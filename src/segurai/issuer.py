"""The issuer: the only place a root warrant is minted, and only for a proven person.

    POST /v1/sessions
    Authorization: Bearer <the person's ID token from the company login system>
    {"request": "clean up our old sales records",
     "scope": {"operations": ["search", "archive"], "targets": ["crm.opportunities"]},
     "ttl_minutes": 30}

    -> 201 {"session_id": "...", "principal": "sarah@acme.example",
            "chain_token": "sgc1....", "scope": {...}, "expires_at": "..."}

This is what makes the rest trustworthy end to end:

  * agents never hold the organisation's key, so they can't mint a root - the
    gateway only accepts chains that start at a root minted HERE;
  * a root is minted only for a person whose ID token the login system signed
    (identity.py), and records how they were proven;
  * what anyone can be granted is capped by CEILINGS configured centrally -
    the first ceiling whose people and groups match applies. A requested
    scope is clamped inside it (it can only lose, never gain); no matching
    ceiling means nothing is issued.

Jobs nobody types - a nightly clean-up, a webhook, a queue consumer - start
sessions through TRIGGERS registered here in advance:

    POST /v1/sessions
    Authorization: Bearer <the job's own token from its platform: Kubernetes, CI, cloud>
    {"trigger": "nightly-crm-hygiene", "request": "nightly run, 23 Nov"}

The token must come from a trusted issuer of kind "workloads", and its
subject must match the trigger's. The root's scope is the one registered
with the trigger - no model call, nothing decided at run time - and the
session names the trigger's OWNER, the person accountable for the job, with
the job's proven identity beside it. A workload token can never start a
person's session, and a person's token can never fire a trigger.

The agent application then continues the chain with
``segurai.resume(chain_token, holder="assistant")`` and calls systems through
the gateway. The chain token carries the root holder's private key, so the
response must travel only over TLS, to the application that asked.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import timedelta
from fnmatch import fnmatchcase
from typing import Any, Mapping

from .authority import Authority
from .collector.store import Store
from .context import export_chain
from .identity import Identity, IdentityError, IdentityVerifier
from .models import Scope, utcnow

__all__ = ["Ceiling", "Trigger", "Issuer", "IssueError"]


class IssueError(Exception):
    """A request the issuer refuses. ``status`` is the HTTP status to answer with."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


@dataclass(frozen=True)
class Ceiling:
    """The most a group of people can ever be granted."""

    name: str
    scope: Scope
    principals: tuple[str, ...] = ()       # glob patterns, e.g. "*@acme.example"; empty = anyone
    groups: tuple[str, ...] = ()           # any one of these groups; empty = no group needed

    def matches(self, identity: Identity) -> bool:
        if self.principals and not any(fnmatchcase(identity.principal, p.lower()) for p in self.principals):
            return False
        if self.groups and not set(self.groups) & set(identity.groups):
            return False
        return True


@dataclass(frozen=True)
class Trigger:
    """A job that may start sessions on its own, with a scope registered in advance."""

    name: str
    owner: str                             # the person accountable for it; becomes the principal
    scope: Scope
    subjects: tuple[str, ...]              # glob patterns over the job token's "sub"
    issuers: tuple[str, ...] = ()          # which workload issuers; empty = any trusted one
    ttl: timedelta = timedelta(hours=1)

    def __post_init__(self) -> None:
        if not self.name or not self.owner or "@" not in self.owner:
            raise ValueError("a trigger needs a name and an owner (the accountable person's email)")
        if not self.subjects:
            raise ValueError(f"trigger {self.name}: say which job may fire it (subjects)")

    def fired_by(self, identity: Identity) -> bool:
        if self.issuers and identity.issuer not in self.issuers:
            return False
        return any(fnmatchcase(identity.subject, p) for p in self.subjects)


_SCOPE_FIELDS = {"operations", "targets", "max_scale", "max_total", "irreversible_allowed",
                 "constraints", "checks"}


def _scope_from_request(d: Any) -> Scope:
    if not isinstance(d, Mapping):
        raise IssueError(400, "scope must be an object")
    unknown = sorted(set(d) - _SCOPE_FIELDS)
    if unknown:
        raise IssueError(400, f"scope has unknown fields {unknown}")
    try:
        return Scope.of(**{k: d[k] for k in d})
    except (TypeError, ValueError) as exc:
        raise IssueError(400, f"scope is not valid: {exc}") from exc


class Issuer:
    """Mints roots for proven people, inside central ceilings."""

    def __init__(self, authority: Authority, store: Store, verifier: IdentityVerifier,
                 ceilings: list[Ceiling], *, default_ttl: timedelta = timedelta(hours=1),
                 max_ttl: timedelta = timedelta(hours=8), triggers: list[Trigger] | None = None):
        if not authority.can_sign:
            raise ValueError("the issuer needs the organisation's private key")
        if not ceilings and not triggers:
            raise ValueError("the issuer needs at least one ceiling or trigger; without one nobody can be "
                             "granted anything")
        self.authority = authority
        self.store = store
        self.verifier = verifier
        self.ceilings = ceilings
        self.triggers = {t.name: t for t in triggers or ()}
        self.default_ttl = default_ttl
        self.max_ttl = max_ttl

    def issue(self, id_token: str, body: Mapping[str, Any]) -> dict[str, Any]:
        try:
            identity = self.verifier.verify(id_token)
        except IdentityError as exc:
            raise IssueError(401, f"who is asking could not be proven: {exc}") from exc

        request = body.get("request")
        if not isinstance(request, str) or not request.strip():
            raise IssueError(400, "say what the person asked for, in their words ('request')")
        if len(request) > 4000:
            raise IssueError(400, "the request is longer than 4000 characters")
        unknown = sorted(set(body) - {"request", "scope", "ttl_minutes", "trigger"})
        if unknown:
            raise IssueError(400, f"unknown fields {unknown}")
        if "trigger" in body or identity.method == "workload":
            return self._fire(identity, body, request.strip())

        ceiling = next((c for c in self.ceilings if c.matches(identity)), None)
        if ceiling is None:
            raise IssueError(403, f"no ceiling grants {identity.principal} anything")
        scope = ceiling.scope if body.get("scope") is None else _scope_from_request(body["scope"]).clamped_to(ceiling.scope)

        ttl = self.default_ttl
        if body.get("ttl_minutes") is not None:
            minutes = body["ttl_minutes"]
            if isinstance(minutes, bool) or not isinstance(minutes, int) or minutes <= 0:
                raise IssueError(400, "ttl_minutes must be a whole number above zero")
            ttl = min(timedelta(minutes=minutes), self.max_ttl)

        session_id = f"ses_{uuid.uuid4().hex[:16]}"
        started = utcnow()
        root = self.authority.issue_root(session_id=session_id, principal=identity.principal,
                                         scope=scope, ttl=ttl, now=started)
        self.store.put_session(session_id, identity.principal, request.strip(),
                               {"issued_under": ceiling.name}, started, identity=identity.to_dict())
        self.store.put_warrant(root)
        return {
            "session_id": session_id,
            "principal": identity.principal,
            "ceiling": ceiling.name,
            "scope": scope.to_dict(),
            "expires_at": root.expires_at.isoformat(),
            "chain_token": export_chain(root, chain=[root], include_key=True, authority=self.authority),
        }

    def _fire(self, identity: Identity, body: Mapping[str, Any], request: str) -> dict[str, Any]:
        """A job starting a session under a registered trigger."""
        if identity.method != "workload":
            raise IssueError(403, "triggers are fired by jobs, with a token from a workload issuer - "
                                  "not by a person's sign-in")
        name = body.get("trigger")
        if not isinstance(name, str) or not name:
            raise IssueError(403, "a job's token starts sessions only for a registered trigger: send "
                                  "{\"trigger\": \"<name>\", ...}")
        trigger = self.triggers.get(name)
        if trigger is None or not trigger.fired_by(identity):
            # One answer for both, so a job can't probe which triggers exist.
            raise IssueError(403, f"{identity.subject} may not fire a trigger called {name!r}")
        if body.get("scope") is not None or body.get("ttl_minutes") is not None:
            raise IssueError(400, "a trigger's scope and lifetime are registered with it; send only "
                                  "trigger and request")
        session_id = f"ses_{uuid.uuid4().hex[:16]}"
        started = utcnow()
        root = self.authority.issue_root(session_id=session_id, principal=trigger.owner, scope=trigger.scope,
                                         ttl=min(trigger.ttl, self.max_ttl), now=started)
        self.store.put_session(session_id, trigger.owner, request,
                               {"trigger": trigger.name, "issued_under": f"trigger {trigger.name}",
                                "run_by": identity.subject}, started, identity=identity.to_dict())
        self.store.put_warrant(root)
        return {
            "session_id": session_id,
            "principal": trigger.owner,
            "trigger": trigger.name,
            "scope": trigger.scope.to_dict(),
            "expires_at": root.expires_at.isoformat(),
            "chain_token": export_chain(root, chain=[root], include_key=True, authority=self.authority),
        }
