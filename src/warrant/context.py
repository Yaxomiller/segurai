"""Propagating the current warrant across agent hops.

"The current warrant" is stored in a :mod:`contextvars` variable. Python
carries context variables through ordinary function calls and into
``asyncio`` tasks, and LangGraph copies them into its worker threads. That
covers most agent frameworks, because they are almost all plain function
composition, asyncio, or both.

It does *not* survive a process boundary, or a thread started without copying
the context. When a hop crosses one - a queue, an HTTP call, a worker pool -
the warrant has to travel explicitly: :func:`export_warrant` turns it into a
string, :func:`import_warrant` turns it back. Losing propagation is the single
most common source of broken chains in practice, so :func:`current_warrant`
is deliberately loud about it.
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
    """Make ``w`` the current warrant for the duration of the block.

    The previous value is restored on exit, even if the block raises, so
    nesting works: an agent's child warrant is unbound when the agent returns
    and its caller's warrant is current again.
    """
    token: Token = _current.set(w)
    try:
        yield w
    finally:
        _current.reset(token)


def export_warrant(w: Warrant | None = None) -> str:
    """Serialize a warrant for transport across a process boundary.

    Returns a compact URL-safe base64 string suitable for an HTTP header, a
    queue message attribute, MCP request metadata, or OpenTelemetry baggage.
    """
    w = w or current_warrant()
    payload = w.payload()
    payload["signature"] = base64.b64encode(w.signature or b"").decode("ascii")
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def import_warrant(token: str) -> Warrant:
    """Rebuild a warrant produced by :func:`export_warrant`.

    The signature travels with it, so the receiving side can and should verify
    it against the authority's public key before trusting it. Nothing here
    verifies anything - it only decodes.
    """
    try:
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
            key_id=d.get("key_id"),
            signature=base64.b64decode(d.get("signature", "")) or None,
        )
    except (ValueError, KeyError, TypeError) as exc:
        # json/base64 errors are ValueError subclasses; a missing field is KeyError.
        raise ValueError(f"not a valid warrant token: {exc}") from exc
