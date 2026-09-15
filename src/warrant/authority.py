"""Issuing, attenuating and verifying warrants.

Ed25519 over a canonical JSON serialization. The signature covers the parent
link and the depth, so a chain cannot be reordered or re-parented after the
fact without detection.

The property we actually care about is proved by :func:`verify_chain`: given an
ordered root-to-leaf chain, every hop is signed, correctly linked, unexpired,
and no wider than its parent. If that holds, then whatever the leaf did was
within what the root principal granted - which is the question nobody can
currently answer.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import Scope, Warrant, utcnow

__all__ = ["Authority", "ChainError", "verify_chain"]

DEFAULT_TTL = timedelta(hours=1)


class ChainError(Exception):
    """Raised when a warrant or a chain fails verification."""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Authority:
    """Holds the signing key and mints warrants.

    In a deployment this lives in the collector, not in the agent process - an
    agent that could mint its own warrants could grant itself anything. For
    local development the in-process key is fine.
    """

    def __init__(self, private_key: Ed25519PrivateKey | None = None):
        self._key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._key.public_key()

    def issue_root(
        self,
        session_id: str,
        principal: str,
        scope: Scope,
        holder: str = "entrypoint",
        ttl: timedelta = DEFAULT_TTL,
        now: datetime | None = None,
    ) -> Warrant:
        """Mint the root warrant for a session, from a human request."""
        now = now or utcnow()
        w = Warrant(
            warrant_id=_new_id("wrt"),
            session_id=session_id,
            root_principal=principal,
            holder=holder,
            scope=scope,
            issued_at=now,
            expires_at=now + ttl,
            parent_id=None,
            depth=0,
        )
        return self._sign(w)

    def attenuate(
        self,
        parent: Warrant,
        holder: str,
        scope: Scope | None = None,
        ttl: timedelta | None = None,
        now: datetime | None = None,
    ) -> Warrant:
        """Derive a child warrant for the next hop.

        ``scope`` defaults to the parent's scope unchanged. If supplied it must
        be a subset; widening raises :class:`ChainError` rather than silently
        clamping, because a caller trying to widen has a bug worth surfacing.
        """
        now = now or utcnow()
        self.verify(parent)
        if parent.is_expired(now):
            raise ChainError(f"parent warrant {parent.warrant_id} has expired")

        # A declared scope states what it narrows; unstated fields inherit.
        child_scope = parent.scope if scope is None else scope.inherit_unspecified(parent.scope)
        ok, reason = child_scope.is_subset_of(parent.scope)
        if not ok:
            raise ChainError(f"attenuation would widen authority: {reason}")

        # A child may never outlive its parent.
        expires = parent.expires_at if ttl is None else min(now + ttl, parent.expires_at)

        w = Warrant(
            warrant_id=_new_id("wrt"),
            session_id=parent.session_id,
            root_principal=parent.root_principal,
            holder=holder,
            scope=child_scope,
            issued_at=now,
            expires_at=expires,
            parent_id=parent.warrant_id,
            depth=parent.depth + 1,
        )
        return self._sign(w)

    def _sign(self, w: Warrant) -> Warrant:
        return w.with_signature(self._key.sign(w.signing_bytes()))

    def verify(self, w: Warrant) -> None:
        """Raise :class:`ChainError` if the signature does not check out."""
        if w.signature is None:
            raise ChainError(f"warrant {w.warrant_id} is unsigned")
        try:
            self.public_key.verify(w.signature, w.signing_bytes())
        except InvalidSignature as exc:
            raise ChainError(f"warrant {w.warrant_id} has an invalid signature") from exc


def verify_chain(
    chain: list[Warrant],
    authority: Authority,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> None:
    """Validate an ordered root-to-leaf chain. Raises :class:`ChainError`.

    ``allow_expired`` exists because audit runs happen long after the fact -
    when reconstructing history you care that the chain was valid *then*, not
    that the warrants are still live now.
    """
    now = now or utcnow()
    if not chain:
        raise ChainError("empty chain")

    root = chain[0]
    if root.parent_id is not None:
        raise ChainError(f"chain does not start at a root: {root.warrant_id}")
    if root.depth != 0:
        raise ChainError(f"root warrant has non-zero depth: {root.depth}")

    for i, w in enumerate(chain):
        authority.verify(w)

        if not allow_expired and w.is_expired(now):
            raise ChainError(f"warrant {w.warrant_id} expired at {w.expires_at.isoformat()}")

        if i == 0:
            continue

        parent = chain[i - 1]

        if w.parent_id != parent.warrant_id:
            raise ChainError(
                f"broken link at depth {i}: {w.warrant_id} claims parent "
                f"{w.parent_id}, chain has {parent.warrant_id}"
            )
        if w.depth != parent.depth + 1:
            raise ChainError(f"depth mismatch at {w.warrant_id}: {w.depth} after {parent.depth}")
        if w.session_id != parent.session_id:
            raise ChainError(f"session mismatch at {w.warrant_id}")
        if w.root_principal != parent.root_principal:
            raise ChainError(f"principal mismatch at {w.warrant_id}")
        if w.expires_at > parent.expires_at:
            raise ChainError(f"warrant {w.warrant_id} outlives its parent")

        ok, reason = w.scope.is_subset_of(parent.scope)
        if not ok:
            raise ChainError(f"attenuation violated at {w.warrant_id}: {reason}")
