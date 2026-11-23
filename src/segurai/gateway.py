"""The enforcing gateway: nothing reaches the real systems without passing through it.

Everything else in Segurai sees what agents REPORT. An agent that calls the
CRM's API directly, with a credential of its own, is invisible to it. The
gateway closes that gap by standing in front of the real systems:

    agent ──HTTP──> Segurai gateway ──HTTP + real credential──> CRM, billing, ...

  * The gateway holds the upstream credentials - from its environment, or
    fetched from the company's secrets manager as needed (credentials.py).
    Agents never have them, so the only way an agent can reach the CRM is
    through here. Deployment makes that true at the network level too: the CRM
    accepts the gateway's credential, and nothing else can reach it.
  * Every request carries the agent's chain (header ``X-Segurai-Chain``) and a
    proof (``X-Segurai-Proof``): a signature over THIS request - method, path,
    body, time and a one-off nonce - made with the private key of the chain's
    leaf holder. The chain must trace back to a root the organisation signed,
    narrowing at every hop. A stolen chain is useless without the key; a
    captured request can't be replayed, or altered and resent.
  * Each request is turned into an action by the upstream's route table
    (``DELETE /opportunities/{id}`` -> delete, crm.opportunities, 1 record,
    irreversible), checked against the leaf warrant AND the organisation's
    rules, and recorded BEFORE it is forwarded. A request no route describes
    is refused: an action nobody can describe is not one anybody authorized.
  * In enforce mode (the default) a request that breaks anything is refused
    with 403 and never forwarded. In observe mode it is forwarded and flagged.
  * The fast path (``direct``): for routine operations, an agent may ask
    ``POST /_segurai/credentials`` for a short-lived token, scope-matched to
    what its warrant allows, and call the system itself. Only operations no
    check could stop go in it: nothing irreversible, nothing size-limited,
    nothing a company rule or a condition covers - those can only be judged
    one request at a time, here. Each grant is recorded (the token's hash,
    never the token).
  * A request that only needs a person's approval - an organisation rule
    with effect "approve", or (with ``step_up``) an action beyond the request
    but inside the person's ceiling - is HELD instead: 202, an approval id,
    and nothing sent until a person approves it on the dashboard. The agent
    asks ``GET /_segurai/approvals/<id>`` for the outcome. See approvals.py.

The request is matched strictly, because a proxy that interprets a request
differently from the system behind it can be walked around:
  * only canonical paths - no "..", "//", backslashes, or encoded "/", "." or
    "\\" - and only standard methods;
  * method-override headers (X-HTTP-Method-Override and friends) are removed,
    so a POST can't turn into a DELETE behind the gateway's back;
  * JSON bodies with duplicate keys are refused (two parsers could each pick
    a different one), and so are repeated query parameters a route reads;
  * redirects from the upstream are passed back, never followed.

Client side, :class:`GatewayClient` signs requests with the current warrant's
key; :func:`proof_headers` does the same for any HTTP library.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import logging
import re
import secrets
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from http.server import BaseHTTPRequestHandler
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._net import ExclusiveHTTPServer
from .approvals import (
    MAX_HELD_BODY,
    MAX_RESULT_BODY,
    STEP_UP_RULE,
    Approval,
    Need,
    amend_action,
    expire_due,
    load,
    open_approval,
    step_up_finding,
)
from .authority import Authority, ChainError, verify_chain
from .collector.store import Store
from .context import CHAIN_TOKEN_PREFIX, export_chain, import_chain
from .credentials import CredentialError
from .models import NON_MUTATING, ActionRecord, Finding, Warrant, utcnow
from .policy import Policy
from .revocation import revocation_for

__all__ = ["Route", "Upstream", "DirectAccess", "GatewayConfig", "GatewayServer", "GatewayClient", "ApprovalRunner",
           "proof_headers", "CHAIN_HEADER", "PROOF_HEADER", "APPROVAL_HEADER", "GatewayConfigError",
           "ApprovalDenied"]

_log = logging.getLogger("segurai.gateway")

CHAIN_HEADER = "X-Segurai-Chain"
PROOF_HEADER = "X-Segurai-Proof"
ACTION_HEADER = "X-Segurai-Action"
APPROVAL_HEADER = "X-Segurai-Approval"
#: The gateway's own paths. No upstream may live here.
OWN_PREFIX = "/_segurai"
#: Warrant checks a step-up may answer. Never "policy" (no request overrides a
#: rule) and never "spec" (nobody can approve what nobody can describe).
_STEP_UP_CHECKS = frozenset({"operation", "target", "scale", "total", "irreversible", "condition"})
_APPROVAL_PATH = re.compile(r"^/_segurai/approvals/(apr_[0-9a-f]{16})$")
_CREDENTIALS_PATH = OWN_PREFIX + "/credentials"
#: A direct token may outlive its warrant by no more than clock slack.
_CLOCK_SLACK = timedelta(seconds=60)

#: How far a proof's timestamp may be from the gateway's clock, either way.
PROOF_WINDOW_SECONDS = 60
#: Methods the gateway will carry. Anything else is refused outright.
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
#: Never forwarded: they describe one connection, not the request, or they
#: could change what the upstream does (method overrides), or they are ours.
_DROP_REQUEST_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te", "trailer",
    "transfer-encoding", "upgrade", "host", "content-length", "expect",
    "x-http-method-override", "x-http-method", "x-method-override",
    "authorization", "cookie",                         # agents bring no credentials of their own
    CHAIN_HEADER.lower(), PROOF_HEADER.lower(),
}
_DROP_RESPONSE_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "transfer-encoding",
                          "te", "trailer", "upgrade", "content-length"}
_SAFE_PARAM = re.compile(r"^[A-Za-z0-9_\-]+$")
_PROOF = re.compile(r"^v1;t=(\d{1,12});n=([A-Za-z0-9_\-]{16,64});s=([A-Za-z0-9_\-+/=]{40,200})$")


class GatewayConfigError(ValueError):
    """A route or upstream that cannot be used. Raised at start-up, never per request."""


# ---- configuration ---------------------------------------------------------------------

@dataclass(frozen=True)
class Route:
    """How one kind of request becomes an action.

    ``path`` is a template: ``{name}`` matches one path segment, and a final
    ``{name*}`` matches the rest. ``resource`` may use path parameters
    (``crm.{table}``). ``scale`` and ``evidence`` values may be a number, or
    an expression naming where the value comes from:

        "path:id"            a path parameter
        "query:days"         a query parameter (as text; add "|int" for a number)
        "json:ids|len"       how many items a JSON list holds
        "json:filter.days|int"
    """

    method: str
    path: str
    operation: str
    resource: str
    scale: int | str = 1
    irreversible: bool = False
    evidence: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        method = self.method.upper()
        object.__setattr__(self, "method", method)
        if method != "*" and method not in METHODS:
            raise GatewayConfigError(f"route {self.path}: method must be one of {METHODS} or '*'")
        if not self.path.startswith("/"):
            raise GatewayConfigError(f"route {self.path}: path must start with /")
        parts = self.path.strip("/").split("/") if self.path.strip("/") else []
        for i, part in enumerate(parts):
            if part.endswith("*}") and i != len(parts) - 1:
                raise GatewayConfigError(f"route {self.path}: {{name*}} may only end a path")
        if not self.operation or not self.resource:
            raise GatewayConfigError(f"route {self.path}: operation and resource are required")
        for expr in [self.scale, *self.evidence.values()]:
            if isinstance(expr, str):
                _parse_expr(expr, self.path)
            elif isinstance(expr, bool) or not isinstance(expr, int):
                raise GatewayConfigError(f"route {self.path}: {expr!r} is not a number or an expression")

    def match(self, method: str, segments: list[str]) -> dict[str, str] | None:
        if self.method not in ("*", method):
            return None
        template = self.path.strip("/").split("/") if self.path.strip("/") else []
        params: dict[str, str] = {}
        for i, part in enumerate(template):
            if part.startswith("{") and part.endswith("*}"):
                params[part[1:-2]] = "/".join(segments[i:])
                return params if len(segments) > i else None
            if i >= len(segments):
                return None
            if part.startswith("{") and part.endswith("}"):
                params[part[1:-1]] = segments[i]
            elif part != segments[i]:
                return None
        return params if len(segments) == len(template) else None


@dataclass(frozen=True)
class Upstream:
    """One real system behind the gateway."""

    name: str
    prefix: str                                  # requests under this path go to this upstream
    url: str                                     # e.g. https://crm.internal.acme.example
    routes: tuple[Route, ...]
    headers: Mapping[str, str] = field(default_factory=dict)   # injected; the upstream credential
    timeout: float = 30.0
    #: Fetched from a secrets manager or token endpoint per request, cached
    #: for its lease (credentials.py). Added after ``headers``.
    credentials: Any = None
    #: The fast path: scope-matched tokens agents may use directly.
    direct: "DirectAccess | None" = None

    def __post_init__(self) -> None:
        if not self.prefix.startswith("/") or self.prefix != "/" + self.prefix.strip("/"):
            raise GatewayConfigError(f"upstream {self.name}: prefix must look like /crm")
        if self.prefix == OWN_PREFIX or self.prefix.startswith(OWN_PREFIX + "/"):
            raise GatewayConfigError(f"upstream {self.name}: {OWN_PREFIX} is the gateway's own")
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise GatewayConfigError(f"upstream {self.name}: url must be http(s)://host[:port][/base]")
        if parsed.query or parsed.fragment:
            raise GatewayConfigError(f"upstream {self.name}: url must not carry a query or fragment")
        if not self.routes:
            raise GatewayConfigError(f"upstream {self.name}: at least one route is required")
        if self.direct is not None and not hasattr(self.credentials, "token_for"):
            raise GatewayConfigError(f"upstream {self.name}: direct access needs oauth2 credentials - only a "
                                     f"token endpoint can issue a token narrowed to a scope")
        if self.direct is not None:
            unknown = sorted(set(self.direct.scopes) - {r.operation for r in self.routes})
            if unknown:
                raise GatewayConfigError(f"upstream {self.name}: direct scopes name operations no route "
                                         f"performs: {unknown}")


@dataclass(frozen=True)
class DirectAccess:
    """The fast path for one upstream: which provider scope each operation needs.

        [gateway.upstreams.direct]
        scopes = { read = "crm.read", search = "crm.read" }
    """

    scopes: Mapping[str, str]

    def __post_init__(self) -> None:
        if not self.scopes or not all(isinstance(k, str) and k and isinstance(v, str) and v
                                      for k, v in self.scopes.items()):
            raise GatewayConfigError("direct access needs scopes: operation = \"provider scope\"")


@dataclass(frozen=True)
class GatewayConfig:
    upstreams: tuple[Upstream, ...]
    mode: str = "enforce"                        # enforce | observe
    max_body: int = 10 * 1024 * 1024
    max_response: int = 50 * 1024 * 1024
    #: How long a held request waits for a person (never past the agent's warrant).
    approval_minutes: int = 60
    #: Hold, rather than refuse, actions beyond the request but inside the
    #: person's ceiling - and ask the person. Needs the issuer's ceilings.
    step_up: bool = False
    #: Besides the person who asked, who may decide a step-up (glob patterns
    #: over dashboard emails; empty = any dashboard admin).
    step_up_approvers: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if self.mode not in ("enforce", "observe"):
            raise GatewayConfigError("gateway mode must be 'enforce' or 'observe'")
        if isinstance(self.approval_minutes, bool) or not 1 <= self.approval_minutes <= 7 * 24 * 60:
            raise GatewayConfigError("approval_minutes must be between 1 and 10080 (a week)")
        prefixes = [u.prefix for u in self.upstreams]
        if len(set(prefixes)) != len(prefixes):
            raise GatewayConfigError("two upstreams share a prefix")
        if len({u.name for u in self.upstreams}) != len(self.upstreams):
            raise GatewayConfigError("upstream names must be unique")


# ---- expressions -------------------------------------------------------------------------

def _parse_expr(expr: str, where: str) -> tuple[str, str, str]:
    source, sep, rest = expr.partition(":")
    if not sep or source not in ("path", "query", "json") or not rest:
        raise GatewayConfigError(f"route {where}: {expr!r} must look like path:x, query:x or json:a.b")
    name, _, transform = rest.partition("|")
    if transform not in ("", "len", "int"):
        raise GatewayConfigError(f"route {where}: unknown transform |{transform} (use |len or |int)")
    return source, name, transform


class _Undescribable(Exception):
    """The request can't be turned into an action. Recorded as a "spec" violation."""


def _evaluate_expr(expr: int | str, params: Mapping[str, str], query: Mapping[str, list[str]],
                   body: Any) -> Any:
    if isinstance(expr, int):
        return expr
    source, name, transform = _parse_expr(expr, "")
    if source == "path":
        if name not in params:
            raise _Undescribable(f"no path parameter {name!r}")
        value: Any = params[name]
    elif source == "query":
        values = query.get(name)
        if not values:
            raise _Undescribable(f"query parameter {name!r} is missing")
        if len(values) > 1:
            raise _Undescribable(f"query parameter {name!r} is repeated")
        value = values[0]
    else:
        if body is _NO_JSON:
            raise _Undescribable("the route reads the JSON body, and there is none")
        value = body
        for part in name.split("."):
            if not isinstance(value, dict) or part not in value:
                raise _Undescribable(f"the JSON body has no {name!r}")
            value = value[part]
    if transform == "len":
        if not isinstance(value, (list, dict)):
            raise _Undescribable(f"{expr}: not a list")
        return len(value)
    if transform == "int":
        if isinstance(value, bool):
            raise _Undescribable(f"{expr}: not a whole number")
        try:
            return int(value)
        except (TypeError, ValueError) as exc:
            raise _Undescribable(f"{expr}: not a whole number") from exc
    return value


_NO_JSON = object()


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate key in JSON object")
    return dict(pairs)


# ---- proofs ------------------------------------------------------------------------------

def _proof_message(method: str, target: str, body: bytes, timestamp: int, nonce: str,
                   warrant_id: str) -> bytes:
    """Exactly what a proof signs. Every field that decides what the request does."""
    return "\n".join([
        "segurai-proof-v1", method.upper(), target, hashlib.sha256(body).hexdigest(),
        str(timestamp), nonce, warrant_id,
    ]).encode("utf-8")


def proof_headers(method: str, target: str, body: bytes = b"", *, leaf: Warrant | None = None,
                  chain: list[Warrant] | None = None, key: Ed25519PrivateKey | None = None) -> dict[str, str]:
    """The two headers a gateway request needs, signed with the leaf holder's key.

    ``target`` is the path and query exactly as sent (``/crm/opportunities/7?force=1``).
    With no arguments beyond the request, the current warrant and the key this
    process holds for it are used.
    """
    from .context import current_warrant
    from .runtime import _rt

    leaf = leaf or current_warrant()
    if key is None:
        _, authority = _rt.ensure()
        key = authority.holder_private_key(leaf.warrant_id)
        if key is None:
            raise ChainError(f"this process holds no key for {leaf.warrant_id}; the gateway "
                             f"needs requests signed by the warrant's holder")
    timestamp = int(time.time())
    nonce = secrets.token_urlsafe(18)
    signature = key.sign(_proof_message(method, target, body, timestamp, nonce, leaf.warrant_id))
    return {
        CHAIN_HEADER: export_chain(leaf, include_key=False, chain=chain),
        PROOF_HEADER: f"v1;t={timestamp};n={nonce};s={base64.urlsafe_b64encode(signature).decode()}",
    }


class _Nonces:
    """Nonces seen recently. A proof can't be used twice inside its time window."""

    def __init__(self) -> None:
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def first_use(self, nonce: str, now: float) -> bool:
        with self._lock:
            if len(self._seen) > 50_000:
                cutoff = now - 2 * PROOF_WINDOW_SECONDS
                self._seen = {n: t for n, t in self._seen.items() if t > cutoff}
            if nonce in self._seen:
                return False
            self._seen[nonce] = now
            return True


# ---- talking to an upstream ------------------------------------------------------------------

def _send_upstream(upstream: Upstream, method: str, rest: str, query_string: str, body: bytes,
                   headers: list[tuple[str, str]], max_response: int) -> tuple[int, list[tuple[str, str]], bytes]:
    """Send one request on, with the upstream's credential, and read the answer.

    http.client never follows redirects, so a 3xx from the upstream goes
    back to the agent as it is - the gateway never ends up talking to a
    system it wasn't configured for.
    """
    base = urllib.parse.urlsplit(upstream.url)
    path = base.path.rstrip("/") + (rest or "/")
    target = path + (f"?{query_string}" if query_string else "")
    out = {k: v for k, v in headers if k.lower() not in _DROP_REQUEST_HEADERS}
    out.update(upstream.headers)
    if upstream.credentials is not None:
        try:
            out.update(upstream.credentials.headers())
        except CredentialError as exc:
            raise _Refusal(502, f"the gateway could not get its credential for {upstream.name}: {exc}") from exc
    out["Host"] = base.netloc
    if body or method in ("POST", "PUT", "PATCH"):
        out["Content-Length"] = str(len(body))
    cls = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
    connection = cls(base.hostname, base.port, timeout=upstream.timeout)
    try:
        connection.request(method, target, body=body or None, headers=out)
        response = connection.getresponse()
        payload = response.read(max_response + 1)
        if len(payload) > max_response:
            raise _Refusal(502, "the upstream's answer is larger than the gateway carries")
        if response.status in (401, 403) and upstream.credentials is not None:
            upstream.credentials.invalidate()       # rotated or revoked: fetch afresh next time
        return response.status, response.getheaders(), payload
    except (OSError, http.client.HTTPException) as exc:
        raise _Refusal(502, f"the upstream {upstream.name} could not be reached: "
                            f"{exc.__class__.__name__}") from exc
    finally:
        connection.close()


class ApprovalRunner:
    """Sends the held requests people approved, and expires the ones nobody decided.

    Runs beside the gateway (started by ``serve_forever``). With several
    gateways on one database each request is claimed before it is sent, so
    exactly one of them sends it.
    """

    def __init__(self, server: "GatewayServer", poll_seconds: float = 0.5):
        self.server = server
        self.poll_seconds = poll_seconds
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()               # start and stop may race (shutdown at start-up)

    def run_once(self) -> int:
        """One pass. Returns how many approved requests were sent (or tried)."""
        store = self.server.store
        expire_due(store)
        sent = 0
        for row in store.approvals(states=("approved",), limit=50):
            claimed = store.transition_approval(row["approval_id"], ("approved",), {"state": "running"})
            if claimed is None:                       # another gateway took it
                continue
            self._send(Approval.from_row(claimed))
            sent += 1
        return sent

    def _send(self, approval: Approval) -> None:
        server, store = self.server, self.server.store
        upstream = next((u for u in server.config.upstreams if u.name == approval.upstream), None)
        error = None if upstream is not None else f"the gateway no longer has an upstream called {approval.upstream}"
        record = store.get_action(approval.action_id)
        if error is None and record is not None:
            # The organisation's rules may have changed while it waited, and the
            # request may have been revoked.
            try:
                chain = store.chain_to(record.warrant_id)
            except ValueError:
                chain = []
            holders = [w.holder for w in chain] or [record.actor]
            revoked = revocation_for(store, chain)
            if revoked is not None:
                error = f"the request was revoked by {revoked['revoked_by']}"
            hard = [f for f in server.policy.evaluate(record.operation, record.resource, record.scale,
                                                      record.irreversible, principal=approval.principal,
                                                      holders=holders)
                    if f.status == "fail" and f.check != "approval"]
            if hard and error is None:
                error = "the organisation's rules changed while it waited: " + "; ".join(f.reason for f in hard)
        changes: dict[str, Any] = {"finished_at": utcnow().isoformat()}
        if error is None:
            try:
                status, headers, payload = _send_upstream(upstream, approval.method, approval.path, approval.query,
                                                          approval.body, list(approval.headers),
                                                          server.config.max_response)
            except _Refusal as refusal:
                error = refusal.message
            else:
                result: dict[str, Any] = {
                    "status": status,
                    "headers": [[k, v] for k, v in headers if k.lower() not in _DROP_RESPONSE_HEADERS]}
                if len(payload) <= MAX_RESULT_BODY:
                    result["body"] = base64.b64encode(payload).decode("ascii")
                else:
                    result["body_omitted"] = len(payload)
                changes.update(state="done", result_status=status, result_json=json.dumps(result, sort_keys=True))
        if error is not None:
            changes.update(state="failed", error=error[:500])
        # The request's new state and its action's record change together, so
        # nobody ever sees one without the other.
        with store._tx():
            row = store.transition_approval(approval.approval_id, ("running",), changes)
            if row is not None:
                amend_action(store, Approval.from_row(row))

    def start(self) -> "ApprovalRunner":
        with self._lock:
            if self._thread is None:
                self._stop.clear()
                thread = threading.Thread(target=self._loop, name="segurai-approvals", daemon=True)
                thread.start()
                self._thread = thread
        return self

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            self._stop.set()
            thread, self._thread = self._thread, None
        if thread is not None:
            thread.join(timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                _log.exception("approval runner pass failed; trying again shortly")
            self._stop.wait(self.poll_seconds)


# ---- the server ----------------------------------------------------------------------------

class _Refusal(Exception):
    def __init__(self, status: int, message: str, action_id: str | None = None,
                 findings: list[Finding] | None = None):
        super().__init__(message)
        self.status, self.message, self.action_id, self.findings = status, message, action_id, findings or []


class GatewayServer(ExclusiveHTTPServer):
    """The gateway's HTTP server. ``address`` is (host, port); port 0 picks a free one."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: GatewayConfig, store: Store,
                 verifier: Authority, policy: Policy | None = None, on_action: Any = None,
                 ceilings: Any = (), run_approvals: bool = True):
        self.config = config
        self.store = store
        self.verifier = verifier.public_only() if verifier.can_sign else verifier
        self.policy = policy or Policy()
        self.nonces = _Nonces()
        self.on_action = on_action                  # e.g. the alert dispatcher
        #: The issuer's ceilings by name: what each person may do at all (step-up).
        self.ceilings = {c.name: c for c in ceilings or ()}
        if config.step_up and not self.ceilings:
            raise GatewayConfigError("step_up needs the issuer's ceilings: without them the gateway can't "
                                     "tell what a person may do beyond the request")
        #: Sends approved requests. ``run_approvals=False`` leaves that to the
        #: caller (``server.approvals.run_once()``), for tests and tools.
        self.approvals = ApprovalRunner(self)
        self.run_approvals = run_approvals
        super().__init__(address, _GatewayHandler)

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        # The approval runner lives exactly as long as the gateway serves.
        if self.run_approvals:
            self.approvals.start()
        try:
            super().serve_forever(poll_interval)
        finally:
            self.approvals.stop()

    def holds_for(self, failures: list[Finding], leaf: Warrant, *, operation: str, resource: str,
                  scale: int, irreversible: bool, evidence: dict[str, Any],
                  body: bytes) -> tuple[list[Need], list[Finding]] | None:
        """Could a person release this, instead of it being refused? (needs, extra findings) or None.

        Only when EVERY failure is something a person may answer: approve
        rules, and - with step_up - warrant checks the person's own ceiling
        would pass. Anything else is refused as it always was.
        """
        if len(body) > MAX_HELD_BODY:
            return None
        needs: list[Need] = []
        extra: list[Finding] = []
        for f in (f for f in failures if f.check == "approval"):
            rule = self.policy.rule(f.clause.split(": ", 1)[1]) if ": " in f.clause else None
            if rule is None:
                return None
            needs.append(Need(rule.name, rule.reason or f.reason, rule.approvers, rule.allow_requester))
        beyond = [f for f in failures if f.check != "approval"]
        if beyond:
            if not self.config.step_up or any(f.check not in _STEP_UP_CHECKS for f in beyond):
                return None
            ceiling = self._ceiling_for(leaf)
            if ceiling is None:
                return None
            changed = (self.store.changed_total(leaf.session_id)
                       if ceiling.scope.max_total is not None else 0)
            under = ceiling.scope.evaluate(operation, resource, scale, irreversible, evidence=evidence,
                                           changed_so_far=changed)
            if any(f.status == "fail" for f in under):
                return None
            principal = leaf.root_principal
            needs.append(Need(STEP_UP_RULE, f"It goes beyond what {principal} asked for, but not beyond what "
                                            f"{principal} may do.", self.config.step_up_approvers, True))
            extra.append(step_up_finding(principal, ceiling.name))
        return (needs, extra) if needs else None

    def direct_operations(self, upstream: Upstream, chain: list[Warrant]) -> tuple[list[str], dict[str, str]]:
        """Which operations a direct token for ``upstream`` may carry: (granted, {excluded: why}).

        An operation goes in only if nothing the gateway checks per request
        could ever stop one of them - because once the agent holds the token,
        the gateway sees none of those requests.
        """
        leaf = chain[-1]
        scope = leaf.scope
        holders = [w.holder for w in chain]
        granted, excluded = [], {}
        for operation in sorted((upstream.direct.scopes if upstream.direct else {})):
            routes = [r for r in upstream.routes if r.operation == operation]
            resources = sorted({re.sub(r"\{[^}]*\}", "*", r.resource) for r in routes})
            mutating = operation not in NON_MUTATING
            rule = next((r for r in self.policy.rules for res in resources
                         if r.applies(operation, res, leaf.root_principal, holders)), None)
            if operation not in scope.operations or not all(scope.covers_target(res) for res in resources):
                excluded[operation] = "not allowed by this request's warrant"
            elif any(r.irreversible for r in routes):
                excluded[operation] = "can't be undone, so each one is checked at the gateway"
            elif mutating and (scope.max_scale is not None or scope.max_total is not None):
                excluded[operation] = "the request limits how much may change, which only the gateway can count"
            elif any(c.applies(operation, res) for c in scope.checks for res in resources):
                excluded[operation] = "a condition must be checked against each request"
            elif rule is not None:
                excluded[operation] = f"the company rule {rule.name!r} covers it"
            else:
                granted.append(operation)
        return granted, excluded

    def _ceiling_for(self, leaf: Warrant) -> Any:
        session = self.store.get_session(leaf.session_id)
        if session is None or not session.identity or not isinstance(session.contract, dict):
            return None                                 # only proven people, issued under a ceiling
        return self.ceilings.get(session.contract.get("issued_under"))

    def upstream_for(self, path: str) -> Upstream | None:
        best = None
        for u in self.config.upstreams:
            if path == u.prefix or path.startswith(u.prefix + "/"):
                if best is None or len(u.prefix) > len(best.prefix):
                    best = u
        return best


class _GatewayHandler(BaseHTTPRequestHandler):
    server: GatewayServer
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002 - name set by the base class
        _log.info("%s - %s", self.address_string(), format % args)

    # Every method goes through one handler.
    def do_GET(self) -> None: self._handle()          # noqa: E704
    def do_HEAD(self) -> None: self._handle()         # noqa: E704
    def do_POST(self) -> None: self._handle()         # noqa: E704
    def do_PUT(self) -> None: self._handle()          # noqa: E704
    def do_PATCH(self) -> None: self._handle()        # noqa: E704
    def do_DELETE(self) -> None: self._handle()       # noqa: E704

    def _reply(self, status: int, payload: dict[str, Any], extra: Mapping[str, str] | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if status >= 400:
            self.close_connection = True
            self.send_header("Connection", "close")
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _body(self) -> bytes:
        if self.headers.get("Transfer-Encoding"):
            raise _Refusal(411, "send a Content-Length; chunked bodies are not accepted")
        raw = self.headers.get("Content-Length")
        if raw is None:
            return b""
        try:
            length = int(raw)
        except ValueError as exc:
            raise _Refusal(400, "bad Content-Length") from exc
        if length < 0 or length > self.server.config.max_body:
            raise _Refusal(413, "request body too large")
        return self.rfile.read(length)

    def _handle(self) -> None:
        try:
            self._process()
        except _Refusal as refusal:
            payload: dict[str, Any] = {"error": refusal.message}
            if refusal.action_id:
                payload["action_id"] = refusal.action_id
            if refusal.findings:
                payload["findings"] = [f.to_dict() for f in refusal.findings]
            extra = {ACTION_HEADER: refusal.action_id} if refusal.action_id else None
            self._reply(refusal.status, payload, extra)
        except Exception:                                  # never leak a traceback to an agent
            _log.exception("gateway failure")
            self._reply(500, {"error": "the gateway failed; nothing was forwarded"})

    # ---- the pipeline --------------------------------------------------------------------

    def _process(self) -> None:
        method = self.command.upper()
        target = self.path
        body = self._body()
        path, _, query_string = target.partition("?")
        _check_canonical(path)
        if path == OWN_PREFIX or path.startswith(OWN_PREFIX + "/"):
            self._own(method, target, path, body)
            return

        upstream = self.server.upstream_for(path)
        if upstream is None:
            raise _Refusal(404, "no upstream is configured for this path")

        chain, leaf = self._authenticate(method, target, body)

        query = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        rest = path[len(upstream.prefix):]
        segments = [urllib.parse.unquote(s) for s in rest.strip("/").split("/")] if rest.strip("/") else []
        record, decision, approval = self._decide(method, upstream, segments, query, body, chain, leaf,
                                                  rest=rest, query_string=query_string)
        if decision == "hold":
            self._reply(202, {
                "state": "pending", "held": True, "approval_id": approval.approval_id,
                "action_id": record.action_id, "expires_at": approval.expires_at.isoformat(),
                "why": [f.reason for f in record.findings if f.status == "fail"],
                "who_decides": approval.who_decides(),
                "check": f"{OWN_PREFIX}/approvals/{approval.approval_id}",
                "message": "Held for a person's approval. Nothing has been sent yet. Ask the check "
                           "address for the outcome.",
            }, {ACTION_HEADER: record.action_id, APPROVAL_HEADER: approval.approval_id})
            return
        if decision == "refuse":
            raise _Refusal(403, f"refused: {record.violation}", record.action_id, list(record.findings))

        status, headers, payload = self._forward(method, upstream, rest, query_string, body)
        self._amend(record, status)
        self.send_response(status)
        for name, value in headers:
            if name.lower() not in _DROP_RESPONSE_HEADERS:
                self.send_header(name, value)
        self.send_header(ACTION_HEADER, record.action_id)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if method != "HEAD":
            self.wfile.write(payload)

    def _authenticate(self, method: str, target: str, body: bytes) -> tuple[list[Warrant], Warrant]:
        token = self.headers.get(CHAIN_HEADER)
        proof = self.headers.get(PROOF_HEADER)
        if not token or not proof:
            raise _Refusal(401, f"every request needs {CHAIN_HEADER} and {PROOF_HEADER} headers")
        if not token.startswith(CHAIN_TOKEN_PREFIX):
            raise _Refusal(401, "the chain header must hold a chain token (export_chain)")
        try:
            chain, key = import_chain(token)
        except ValueError as exc:
            raise _Refusal(401, str(exc)) from exc
        if key is not None:
            raise _Refusal(400, "never send a private key to the gateway: export the chain with "
                                "include_key=False and sign the request instead")
        try:
            verify_chain(chain, self.server.verifier)          # signatures, links, narrowing, expiry
        except ChainError as exc:
            raise _Refusal(401, f"chain refused: {exc}") from exc
        leaf = chain[-1]

        match = _PROOF.match(proof.strip())
        if match is None:
            raise _Refusal(401, "malformed proof")
        timestamp, nonce, signature = int(match.group(1)), match.group(2), match.group(3)
        now = time.time()
        if abs(now - timestamp) > PROOF_WINDOW_SECONDS:
            raise _Refusal(401, "the proof is too old or from the future; check the agent's clock")
        if leaf.holder_key is None:
            raise _Refusal(401, "the leaf warrant names no holder key, so nothing can prove possession")
        try:
            Ed25519PublicKey.from_public_bytes(leaf.holder_key).verify(
                base64.urlsafe_b64decode(signature + "=" * (-len(signature) % 4)),
                _proof_message(method, target, body, timestamp, nonce, leaf.warrant_id))
        except (InvalidSignature, ValueError) as exc:
            raise _Refusal(401, "the proof does not match this request and warrant") from exc
        if not self.server.nonces.first_use(nonce, now):
            raise _Refusal(401, "this proof was already used")
        return chain, leaf

    def _own(self, method: str, target: str, path: str, body: bytes) -> None:
        """The gateway's own endpoints: a held request's outcome, and direct credentials."""
        chain, leaf = self._authenticate(method, target, body)
        if path == _CREDENTIALS_PATH and method == "POST":
            self._grant(chain, leaf, body)
            return
        match = _APPROVAL_PATH.match(path)
        if match is None or method not in ("GET", "HEAD"):
            raise _Refusal(404, f"the gateway's own paths are GET {OWN_PREFIX}/approvals/<id> and "
                                f"POST {_CREDENTIALS_PATH}")
        store = self.server.store
        approval = load(store, match.group(1))
        # Only an agent of the same request may ask: approvals are not a
        # directory of everything waiting in the organisation.
        if approval is None or approval.session_id != leaf.session_id:
            raise _Refusal(404, "no such held request for this session")
        if approval.expired():
            expire_due(store)
            approval = load(store, approval.approval_id) or approval
        self._reply(200, approval.public(), {APPROVAL_HEADER: approval.approval_id})

    def _grant(self, chain: list[Warrant], leaf: Warrant, body: bytes) -> None:
        """The fast path: a short-lived token for the routine operations no check could stop."""
        try:
            asked = json.loads(body or b"{}", object_pairs_hook=_no_duplicate_keys)
            name = asked["upstream"] if isinstance(asked, dict) else None
        except (ValueError, KeyError, UnicodeDecodeError):
            name = None
        if not isinstance(name, str):
            raise _Refusal(400, 'send {"upstream": "<name>"}')
        upstream = next((u for u in self.server.config.upstreams if u.name == name), None)
        if upstream is None or upstream.direct is None:
            raise _Refusal(404, f"{name!r} offers no direct access; send requests through the gateway")
        revoked = revocation_for(self.server.store, chain)
        if revoked is not None:
            raise _Refusal(403, f"{revoked['revoked_by']} revoked this request: {revoked['reason']}")
        granted, excluded = self.server.direct_operations(upstream, chain)
        if not granted:
            self._reply(403, {"error": "nothing this request may do can be done directly; send requests "
                                       "through the gateway", "excluded": excluded})
            return
        provider_scope = " ".join(sorted({upstream.direct.scopes[op] for op in granted}))
        try:
            token, seconds = upstream.credentials.token_for(provider_scope)
        except CredentialError as exc:
            raise _Refusal(502, f"the gateway could not get a token for {name}: {exc}") from exc
        issued = utcnow()
        expires = issued + timedelta(seconds=seconds)
        if expires > leaf.expires_at + _CLOCK_SLACK:
            # The token can't be called back early, so it may not outlive the
            # permission it stands for. (It was minted, but nobody gets it.)
            left = max(0, int((leaf.expires_at - issued).total_seconds() // 60))
            raise _Refusal(409, f"{name}'s tokens last {int(seconds // 60)} min, longer than this request's "
                                f"warrant ({left} min left). Shorten token lifetimes at the provider, or "
                                f"start the request with a longer warrant.")
        grant_id = f"grt_{uuid.uuid4().hex[:16]}"
        with self.server.store._tx():
            self._store_chain(chain)
            self.server.store.put_grant({
                "grant_id": grant_id, "session_id": leaf.session_id, "warrant_id": leaf.warrant_id,
                "holder": leaf.holder, "upstream": name, "operations_json": json.dumps(granted),
                "provider_scope": provider_scope, "excluded_json": json.dumps(excluded, sort_keys=True),
                "issued_at": issued.isoformat(), "expires_at": expires.isoformat(),
                "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            })
        self._reply(200, {
            "grant_id": grant_id, "upstream": name, "base_url": upstream.url, "token_type": "Bearer",
            "access_token": token, "expires_at": expires.isoformat(), "operations": granted,
            "scope": provider_scope, "excluded": excluded,
            "note": "Use this token only for the operations listed. Everything else - and anything after it "
                    "expires - goes through the gateway.",
        })

    def _decide(self, method: str, upstream: Upstream, segments: list[str],
                query: dict[str, list[str]], body: bytes, chain: list[Warrant],
                leaf: Warrant, *, rest: str = "", query_string: str = "",
                ) -> tuple[ActionRecord, str, Approval | None]:
        """Describe the request as an action, check it, record it.

        Returns (record, "forward" | "refuse" | "hold", the approval when held).
        """
        detail: dict[str, Any] = {"via": "gateway", "upstream": upstream.name, "method": method,
                                  "path": "/" + "/".join(segments)}
        parsed_json: Any = _NO_JSON
        try:
            route, params = next(((r, p) for r in upstream.routes
                                  if (p := r.match(method, segments)) is not None), (None, None))
            if route is None:
                raise _Undescribable(f"no route describes {method} {upstream.prefix}{detail['path']}")
            if body and "json" in (self.headers.get("Content-Type") or "").lower():
                try:
                    parsed_json = json.loads(body, object_pairs_hook=_no_duplicate_keys)
                except (ValueError, UnicodeDecodeError) as exc:
                    raise _Undescribable(f"the JSON body can't be read unambiguously: {exc}") from exc
            for name in params:
                if "{" + name + "}" in route.resource and not _SAFE_PARAM.match(params[name]):
                    raise _Undescribable(f"path parameter {name!r} holds characters a resource name "
                                         f"can't contain")
            resource = route.resource.format(**params)
            scale = _evaluate_expr(route.scale, params, query, parsed_json)
            if isinstance(scale, bool) or not isinstance(scale, int) or scale < 0:
                raise _Undescribable(f"scale {scale!r} is not a whole number")
            evidence = {k: _evaluate_expr(v, params, query, parsed_json) for k, v in route.evidence.items()}
            operation, irreversible = route.operation, route.irreversible
            changed = self.server.store.changed_total(leaf.session_id) if leaf.scope.max_total is not None else 0
            findings = leaf.scope.evaluate(operation, resource, scale, irreversible,
                                           evidence=evidence, changed_so_far=changed)
            findings += self.server.policy.evaluate(operation, resource, scale, irreversible,
                                                    principal=leaf.root_principal,
                                                    holders=[w.holder for w in chain])
            detail.update(evidence)
        except _Undescribable as exc:
            operation, resource, scale, irreversible = method.lower(), f"{upstream.name}.undescribed", 1, False
            evidence = {}
            findings = [Finding("spec", "fail", str(exc), "every gateway request must match a route")]

        # A person's explicit "stop" outranks everything, in either mode.
        revoked = revocation_for(self.server.store, chain)
        if revoked is not None:
            findings = [*findings, Finding("revoked", "fail",
                                           f"{revoked['revoked_by']} revoked this request: {revoked['reason']}",
                                           f"revocation {revoked['revocation_id']}")]
        failures = [f for f in findings if f.status == "fail"]
        enforce = self.server.config.mode == "enforce" or revoked is not None
        hold = None
        if failures and enforce:
            hold = self.server.holds_for(failures, leaf, operation=operation, resource=resource, scale=scale,
                                         irreversible=irreversible, evidence=evidence, body=body)
        approval_id = f"apr_{uuid.uuid4().hex[:16]}" if hold else None
        if hold:
            findings = [*findings, *hold[1]]
            failures = [f for f in findings if f.status == "fail"]
            detail["approval"] = {"id": approval_id, "state": "pending"}
        violation = "; ".join(f.reason for f in failures) or None
        if hold and violation:
            violation = "held for a person's approval: " + violation
        record = ActionRecord(
            action_id=f"act_{uuid.uuid4().hex[:16]}", session_id=leaf.session_id,
            warrant_id=leaf.warrant_id, actor=leaf.holder, operation=operation, resource=resource,
            scale=scale, irreversible=irreversible, at=utcnow(), allowed=not failures,
            violation=violation, blocked=bool(failures) and enforce, findings=tuple(findings), detail=detail,
        )
        # Written BEFORE anything is forwarded: if the gateway dies mid-request,
        # the attempt is still on the record. A held request and its record
        # are written together, so neither exists without the other.
        store = self.server.store
        approval = None
        with store._tx():
            self._store_chain(chain)
            store.put_action(record)
            if hold:
                expires = min(utcnow() + timedelta(minutes=self.server.config.approval_minutes), leaf.expires_at)
                forwardable = [(k, v) for k, v in self.headers.items()
                               if k.lower() not in _DROP_REQUEST_HEADERS][:50]
                approval = open_approval(store, record, principal=leaf.root_principal, upstream=upstream.name,
                                         method=method, path=rest or "/", query=query_string,
                                         headers=forwardable, body=body, needs=hold[0], expires_at=expires,
                                         approval_id=approval_id)
        if self.server.on_action is not None:
            try:
                self.server.on_action(record)
            except Exception:
                _log.warning("gateway on_action hook failed", exc_info=True)
        if hold:
            return record, "hold", approval
        return record, ("refuse" if record.blocked else "forward"), None

    def _store_chain(self, chain: list[Warrant]) -> None:
        store = self.server.store
        root = chain[0]
        if store.get_session(root.session_id) is None:
            store.put_session(root.session_id, root.root_principal,
                              "(request not seen by this server)", None, root.issued_at)
        for w in chain:
            store.put_warrant(w)

    def _forward(self, method: str, upstream: Upstream, rest: str, query_string: str,
                 body: bytes) -> tuple[int, list[tuple[str, str]], bytes]:
        return _send_upstream(upstream, method, rest, query_string, body, list(self.headers.items()),
                              self.server.config.max_response)

    def _amend(self, record: ActionRecord, status: int) -> None:
        """Note what the upstream answered. The log keeps the original entry too."""
        from dataclasses import replace

        try:
            self.server.store.put_action(replace(record, detail={**record.detail, "upstream_status": status}))
        except Exception:
            _log.warning("could not record the upstream status for %s", record.action_id, exc_info=True)


def _check_canonical(path: str) -> None:
    """Refuse any path two HTTP servers could read differently."""
    lowered = path.lower()
    if (not path.startswith("/") or "//" in path or "\\" in path
            or any(seg in (".", "..") for seg in path.split("/"))
            or any(enc in lowered for enc in ("%2f", "%2e", "%5c", "%00"))
            or any(ord(c) < 0x21 or ord(c) == 0x7f for c in path)):
        raise _Refusal(400, "the path is not in canonical form")


# ---- the client ------------------------------------------------------------------------------

class ApprovalDenied(Exception):
    """A held request that a person denied, that expired, or that could not be sent."""

    def __init__(self, state: str, detail: dict[str, Any]):
        super().__init__(f"the request was {state}" + (f": {detail.get('note') or detail.get('error')}"
                                                        if detail.get("note") or detail.get("error") else ""))
        self.state, self.detail = state, detail


class GatewayClient:
    """Call systems through the gateway, signing each request with the current warrant's key.

        client = GatewayClient("http://gateway.internal:8800")
        status, headers, body = client.request("DELETE", "/crm/opportunities/7")
    """

    def __init__(self, base_url: str, timeout: float = 30.0):
        parsed = urllib.parse.urlsplit(base_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise ValueError("base_url must be http(s)://host[:port]")
        self._parsed = parsed
        self.timeout = timeout

    def request(self, method: str, target: str, body: bytes | Mapping[str, Any] | list | None = None,
                headers: Mapping[str, str] | None = None,
                wait: float | None = None) -> tuple[int, dict[str, str], bytes]:
        """Send one request. A held one comes back 202 - or, with ``wait`` (seconds),
        the system's answer once a person approves it (see :meth:`wait`)."""
        status, out_headers, payload = self._send(method, target, body, headers)
        held = {k.lower(): v for k, v in out_headers.items()}.get(APPROVAL_HEADER.lower())
        if status == 202 and held and wait:
            return self.wait(held, timeout=wait)
        return status, out_headers, payload

    def direct(self, upstream: str) -> dict[str, Any]:
        """Ask for a short-lived token to call ``upstream`` directly (the fast path).

        The answer lists the operations it may be used for, the system's
        ``base_url``, and what was left out and why. Raises PermissionError
        when nothing this request may do can be done directly.
        """
        status, _, payload = self._send("POST", _CREDENTIALS_PATH, {"upstream": upstream}, None)
        data = json.loads(payload or b"{}")
        if status != 200:
            raise PermissionError(data.get("error") or f"the gateway answered {status}")
        return data

    def status(self, approval_id: str) -> dict[str, Any]:
        """Where a held request stands: its state, and the system's answer once sent."""
        status, _, payload = self._send("GET", f"{OWN_PREFIX}/approvals/{approval_id}", None, None)
        data = json.loads(payload or b"{}")
        if status != 200:
            raise ApprovalDenied("unknown", data)
        return data

    def wait(self, approval_id: str, timeout: float = 600.0, poll: float = 1.0) -> tuple[int, dict[str, str], bytes]:
        """Wait for a person to decide. Returns the system's answer, as :meth:`request` would.

        Raises :class:`ApprovalDenied` if it was denied, expired or could not
        be sent, and TimeoutError if nobody decided within ``timeout``.
        """
        deadline = time.monotonic() + timeout
        while True:
            data = self.status(approval_id)
            state = data.get("state")
            if state == "done":
                result = data.get("result") or {}
                body = base64.b64decode(result.get("body", "")) if "body" in result else b""
                return int(result.get("status", 0)), {k: v for k, v in result.get("headers", [])}, body
            if state in ("denied", "expired", "failed"):
                raise ApprovalDenied(state, data)
            if time.monotonic() >= deadline:
                raise TimeoutError(f"nobody decided {approval_id} within {timeout:.0f} s")
            time.sleep(poll)

    def _send(self, method: str, target: str, body: bytes | Mapping[str, Any] | list | None,
              headers: Mapping[str, str] | None) -> tuple[int, dict[str, str], bytes]:
        if not target.startswith("/"):
            raise ValueError("target must be a path like /crm/opportunities/7")
        out_headers = dict(headers or {})
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode("utf-8")
            out_headers.setdefault("Content-Type", "application/json")
        body = body or b""
        out_headers.update(proof_headers(method, target, body))
        cls = http.client.HTTPSConnection if self._parsed.scheme == "https" else http.client.HTTPConnection
        connection = cls(self._parsed.hostname, self._parsed.port, timeout=self.timeout)
        try:
            connection.request(method.upper(), target, body=body or None, headers=out_headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()
