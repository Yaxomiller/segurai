"""The enforcing gateway: nothing reaches the real systems without passing through it.

Everything else in Segurai sees what agents REPORT. An agent that calls the
CRM's API directly, with a credential of its own, is invisible to it. The
gateway closes that gap by standing in front of the real systems:

    agent ──HTTP──> Segurai gateway ──HTTP + real credential──> CRM, billing, ...

  * The gateway holds the upstream credentials (from its environment). Agents
    never have them, so the only way an agent can reach the CRM is through
    here. Deployment makes that true at the network level too: the CRM
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
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .authority import Authority, ChainError, verify_chain
from .collector.store import Store
from .context import CHAIN_TOKEN_PREFIX, export_chain, import_chain
from .models import ActionRecord, Finding, Warrant, utcnow
from .policy import Policy

__all__ = ["Route", "Upstream", "GatewayConfig", "GatewayServer", "GatewayClient",
           "proof_headers", "CHAIN_HEADER", "PROOF_HEADER", "GatewayConfigError"]

_log = logging.getLogger("segurai.gateway")

CHAIN_HEADER = "X-Segurai-Chain"
PROOF_HEADER = "X-Segurai-Proof"
ACTION_HEADER = "X-Segurai-Action"

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

    def __post_init__(self) -> None:
        if not self.prefix.startswith("/") or self.prefix != "/" + self.prefix.strip("/"):
            raise GatewayConfigError(f"upstream {self.name}: prefix must look like /crm")
        parsed = urllib.parse.urlsplit(self.url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            raise GatewayConfigError(f"upstream {self.name}: url must be http(s)://host[:port][/base]")
        if parsed.query or parsed.fragment:
            raise GatewayConfigError(f"upstream {self.name}: url must not carry a query or fragment")
        if not self.routes:
            raise GatewayConfigError(f"upstream {self.name}: at least one route is required")


@dataclass(frozen=True)
class GatewayConfig:
    upstreams: tuple[Upstream, ...]
    mode: str = "enforce"                        # enforce | observe
    max_body: int = 10 * 1024 * 1024
    max_response: int = 50 * 1024 * 1024

    def __post_init__(self) -> None:
        if self.mode not in ("enforce", "observe"):
            raise GatewayConfigError("gateway mode must be 'enforce' or 'observe'")
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


# ---- the server ----------------------------------------------------------------------------

class _Refusal(Exception):
    def __init__(self, status: int, message: str, action_id: str | None = None,
                 findings: list[Finding] | None = None):
        super().__init__(message)
        self.status, self.message, self.action_id, self.findings = status, message, action_id, findings or []


class GatewayServer(ThreadingHTTPServer):
    """The gateway's HTTP server. ``address`` is (host, port); port 0 picks a free one."""

    daemon_threads = True

    def __init__(self, address: tuple[str, int], config: GatewayConfig, store: Store,
                 verifier: Authority, policy: Policy | None = None, on_action: Any = None):
        self.config = config
        self.store = store
        self.verifier = verifier.public_only() if verifier.can_sign else verifier
        self.policy = policy or Policy()
        self.nonces = _Nonces()
        self.on_action = on_action                  # e.g. the alert dispatcher
        super().__init__(address, _GatewayHandler)

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

        upstream = self.server.upstream_for(path)
        if upstream is None:
            raise _Refusal(404, "no upstream is configured for this path")

        chain, leaf = self._authenticate(method, target, body)

        query = urllib.parse.parse_qs(query_string, keep_blank_values=True)
        rest = path[len(upstream.prefix):]
        segments = [urllib.parse.unquote(s) for s in rest.strip("/").split("/")] if rest.strip("/") else []
        record, forward = self._decide(method, upstream, segments, query, body, chain, leaf)
        if not forward:
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

    def _decide(self, method: str, upstream: Upstream, segments: list[str],
                query: dict[str, list[str]], body: bytes, chain: list[Warrant],
                leaf: Warrant) -> tuple[ActionRecord, bool]:
        """Describe the request as an action, check it, record it. Returns (record, forward?)."""
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
            findings = [Finding("spec", "fail", str(exc), "every gateway request must match a route")]

        failures = [f for f in findings if f.status == "fail"]
        enforce = self.server.config.mode == "enforce"
        record = ActionRecord(
            action_id=f"act_{uuid.uuid4().hex[:16]}", session_id=leaf.session_id,
            warrant_id=leaf.warrant_id, actor=leaf.holder, operation=operation, resource=resource,
            scale=scale, irreversible=irreversible, at=utcnow(), allowed=not failures,
            violation="; ".join(f.reason for f in failures) or None,
            blocked=bool(failures) and enforce, findings=tuple(findings), detail=detail,
        )
        # Written BEFORE anything is forwarded: if the gateway dies mid-request,
        # the attempt is still on the record.
        self._store_chain(chain)
        self.server.store.put_action(record)
        if self.server.on_action is not None:
            try:
                self.server.on_action(record)
            except Exception:
                _log.warning("gateway on_action hook failed", exc_info=True)
        return record, not record.blocked

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
        """Send the request on, with the upstream's credential, and read the answer.

        http.client never follows redirects, so a 3xx from the upstream goes
        back to the agent as it is - the gateway never ends up talking to a
        system it wasn't configured for.
        """
        base = urllib.parse.urlsplit(upstream.url)
        path = base.path.rstrip("/") + (rest or "/")
        target = path + (f"?{query_string}" if query_string else "")
        headers = {k: v for k, v in self.headers.items() if k.lower() not in _DROP_REQUEST_HEADERS}
        headers.update(upstream.headers)
        headers["Host"] = base.netloc
        if body or method in ("POST", "PUT", "PATCH"):
            headers["Content-Length"] = str(len(body))
        cls = http.client.HTTPSConnection if base.scheme == "https" else http.client.HTTPConnection
        connection = cls(base.hostname, base.port, timeout=upstream.timeout)
        try:
            connection.request(method, target, body=body or None, headers=headers)
            response = connection.getresponse()
            payload = response.read(self.server.config.max_response + 1)
            if len(payload) > self.server.config.max_response:
                raise _Refusal(502, "the upstream's answer is larger than the gateway carries")
            return response.status, response.getheaders(), payload
        except (OSError, http.client.HTTPException) as exc:
            raise _Refusal(502, f"the upstream {upstream.name} could not be reached: "
                                f"{exc.__class__.__name__}") from exc
        finally:
            connection.close()

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
                headers: Mapping[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
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
