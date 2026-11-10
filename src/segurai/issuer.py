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

__all__ = ["Ceiling", "Issuer", "IssueError"]


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
                 max_ttl: timedelta = timedelta(hours=8)):
        if not authority.can_sign:
            raise ValueError("the issuer needs the organisation's private key")
        if not ceilings:
            raise ValueError("the issuer needs at least one ceiling; without one nobody can be granted anything")
        self.authority = authority
        self.store = store
        self.verifier = verifier
        self.ceilings = ceilings
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
        unknown = sorted(set(body) - {"request", "scope", "ttl_minutes"})
        if unknown:
            raise IssueError(400, f"unknown fields {unknown}")

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
