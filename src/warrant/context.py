"""Propagating the current warrant across agent hops.

Uses :mod:`contextvars`, which follows both ordinary calls and ``asyncio``
tasks. That covers most agent frameworks, because they are almost all either
plain function composition or asyncio.

It does *not* survive a process or thread boundary. When a hop crosses one -
a queue, an HTTP call, a worker pool - the warrant has to travel explicitly;
:func:`export_warrant` and :func:`import_warrant` are the serialization path
for that case. Losing propagation is the single most common source of broken
chains in practice, so :func:`current_warrant` is deliberately loud about it.
"""

from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from contextvars import ContextVar, Token
from datetime import datetime
from typing import Iterator

from .models import Scope, Warrant

__all__ = [
    "current_warrant",
    "bind_warrant",
    "export_warrant",
    "import_warrant",
    "NoWarrantError",
]

_current: ContextVar[Warrant | None] = ContextVar("warrant_current", default=None)


class NoWarrantError(RuntimeError):
    """Raised when an action is attempted with no warrant in context."""


def current_warrant(required: bool = True) -> Warrant | None:
    """The warrant in scope right now.

    With ``required=True`` (the default) a missing warrant raises rather than
    returning ``None``. An action recorded without a warrant is an orphan in
    the chain, and silently tolerating it produces exactly the untraceable
    history this library exists to prevent.
    """
    w = _current.get()
    if w is None and required:
        raise NoWarrantError(
            "no warrant in context - the chain would break here. "
            "Start one with warrant.session(...), or if this hop crossed a "
            "thread or process boundary, pass it explicitly with "
            "export_warrant()/import_warrant()."
        )
    return w


@contextmanager
def bind_warrant(w: Warrant) -> Iterator[Warrant]:
    """Make ``w`` the current warrant for the duration of the block."""
    token: Token = _current.set(w)
    try:
        yield w
    finally:
        _current.reset(token)


def export_warrant(w: Warrant | None = None) -> str:
    """Serialize a warrant for transport across a process boundary.

    Returns a compact base64 string suitable for an HTTP header, a queue
    message attribute, or OpenTelemetry baggage.
    """
    w = w or current_warrant()
    payload = w.payload()
    payload["signature"] = base64.b64encode(w.signature or b"").decode("ascii")
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def import_warrant(token: str) -> Warrant:
    """Rebuild a warrant produced by :func:`export_warrant`.

    The signature travels with it, so the receiving side can and should verify
    against the authority's public key before trusting it.
    """
    raw = base64.urlsafe_b64decode(token.encode("ascii"))
    d = json.loads(raw)
    return Warrant(
        warrant_id=d["warrant_id"],
        session_id=d["session_id"],
        root_principal=d["root_principal"],
        holder=d["holder"],
        scope=Scope.from_dict(d["scope"]),
        issued_at=datetime.fromisoformat(d["issued_at"]),
        expires_at=datetime.fromisoformat(d["expires_at"]),
        parent_id=d.get("parent_id"),
        depth=int(d.get("depth", 0)),
        signature=base64.b64decode(d.get("signature", "")) or None,
    )
