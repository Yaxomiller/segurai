"""Propagating the current warrant across agent hops.

"The current warrant" is stored in a :mod:`contextvars` variable. Python
carries context variables through ordinary function calls and into
``asyncio`` tasks, and LangGraph copies them into its worker threads. That
covers most agent frameworks, because they are almost all plain function
composition, asyncio, or both.

It does *not* survive a process boundary, or a thread started without copying
the context. When a hop crosses one - a queue, an HTTP call, a worker pool -
the warrant has to travel explicitly. Two token formats exist:

  * A CHAIN TOKEN (:func:`export_chain` / :func:`import_chain`) carries the
    whole chain from the root down, and - unless told not to - the private
    key of the last holder. The receiver can verify every hop on its own and
    delegate further, without the organisation's key. This is the format to
    use; it is what the MCP integration, OpenTelemetry baggage and the issuer
    all speak.

  * A WARRANT TOKEN (:func:`export_warrant` / :func:`import_warrant`) carries
    one warrant. It is kept for compatibility: a receiver can verify it only
    if it already trusts the key that signed it.

Losing propagation is the single most common source of broken chains in
practice, so :func:`current_warrant` is deliberately loud about it.

A chain token that includes a private key is a CAPABILITY: whoever holds it
can act and delegate within that warrant's scope until it expires. Send it
only over encrypted connections, and pass ``include_key=False`` when the
receiver only needs to verify (the gateway, for instance, never needs it).
"""

from __future__ import annotations

import base64
import json
import zlib
from contextlib import contextmanager
from contextvars import ContextVar, Token
from typing import Iterator

from .models import Warrant

__all__ = [
    "current_warrant",
    "bind_warrant",
    "export_warrant",
    "import_warrant",
    "export_chain",
    "import_chain",
    "NoWarrantError",
    "CHAIN_TOKEN_PREFIX",
]

_current: ContextVar[Warrant | None] = ContextVar("warrant_current", default=None)

#: Every chain token starts with this, so it can't be mistaken for anything else.
CHAIN_TOKEN_PREFIX = "sgc1."

#: Refuse tokens bigger than this before decompressing (a zip bomb defence).
_MAX_TOKEN_CHARS = 64 * 1024
_MAX_DECOMPRESSED = 1024 * 1024


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
            "Start one with segurai.session(...), or if this hop crossed a "
            "thread or process boundary, pass it explicitly with "
            "export_chain()/segurai.resume()."
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


# ---- single-warrant tokens (compatibility) --------------------------------------

def export_warrant(w: Warrant | None = None) -> str:
    """Serialize one warrant for transport across a process boundary.

    Returns a compact URL-safe base64 string. Prefer :func:`export_chain`,
    which a receiver can verify on its own.
    """
    w = w or current_warrant()
    raw = json.dumps(w.to_dict(), separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def import_warrant(token: str) -> Warrant:
    """Rebuild a warrant produced by :func:`export_warrant`.

    The signature travels with it, so the receiving side can and should verify
    it before trusting it. Nothing here verifies anything - it only decodes.
    """
    try:
        if len(token) > _MAX_TOKEN_CHARS:
            raise ValueError("token too large")
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
        d = json.loads(raw)
        if not isinstance(d, dict):
            raise ValueError("not an object")
        return Warrant.from_dict(d)
    except (ValueError, KeyError, TypeError, UnicodeEncodeError) as exc:
        # json/base64 errors are ValueError subclasses; a missing field is KeyError.
        raise ValueError(f"not a valid warrant token: {exc}") from exc


# ---- chain tokens -------------------------------------------------------------------

def export_chain(leaf: Warrant | None = None, *, include_key: bool = True,
                 chain: list[Warrant] | None = None) -> str:
    """Serialize a whole chain, root first, optionally with the leaf holder's private key.

    ``leaf`` defaults to the current warrant; its ancestors come from the
    runtime's store (where every warrant the runtime minted or adopted is
    kept) unless ``chain`` is given explicitly.
    """
    # Imported here: the runtime imports this module.
    from .runtime import _rt

    leaf = leaf or current_warrant()
    if chain is None:
        store, _ = _rt.ensure()
        if store.get_warrant(leaf.warrant_id) is not None:
            chain = store.chain_to(leaf.warrant_id)
        elif leaf.parent_id is None:
            chain = [leaf]
        else:
            raise ValueError(f"the ancestors of {leaf.warrant_id} are not in this process's store; "
                             f"pass chain=[root, ..., leaf] explicitly")
    if not chain or chain[-1].warrant_id != leaf.warrant_id or chain[0].parent_id is not None:
        raise ValueError("a chain must run from a root warrant down to the leaf being exported")

    key = None
    if include_key:
        _, authority = _rt.ensure()
        private = authority.holder_private_key(leaf.warrant_id)
        if private is not None:
            from cryptography.hazmat.primitives import serialization

            key = base64.b64encode(private.private_bytes(
                serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                serialization.NoEncryption())).decode("ascii")
    body = {"v": 1, "chain": [w.to_dict() for w in chain]}
    if key is not None:
        body["key"] = key
    packed = zlib.compress(json.dumps(body, separators=(",", ":")).encode("utf-8"), 9)
    return CHAIN_TOKEN_PREFIX + base64.urlsafe_b64encode(packed).decode("ascii").rstrip("=")


def import_chain(token: str) -> tuple[list[Warrant], bytes | None]:
    """Decode a chain token into (chain, leaf private key or None). Verifies nothing.

    A single-warrant token from :func:`export_warrant` is accepted too and
    comes back as a chain of one, with no key.
    """
    try:
        if not isinstance(token, str) or len(token) > _MAX_TOKEN_CHARS:
            raise ValueError("token missing or too large")
        if not token.startswith(CHAIN_TOKEN_PREFIX):
            return [import_warrant(token)], None
        data = token[len(CHAIN_TOKEN_PREFIX):]
        packed = base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))
        inflater = zlib.decompressobj()
        raw = inflater.decompress(packed, _MAX_DECOMPRESSED)
        if inflater.unconsumed_tail:
            raise ValueError("token expands beyond the size limit")
        body = json.loads(raw)
        if not isinstance(body, dict) or body.get("v") != 1:
            raise ValueError("unknown chain token version")
        chain = [Warrant.from_dict(d) for d in body["chain"]]
        if not chain:
            raise ValueError("empty chain")
        key = base64.b64decode(body["key"]) if body.get("key") else None
        if key is not None and len(key) != 32:
            raise ValueError("malformed key")
        return chain, key
    except (ValueError, KeyError, TypeError, zlib.error, UnicodeEncodeError) as exc:
        raise ValueError(f"not a valid warrant token: {exc}") from exc
