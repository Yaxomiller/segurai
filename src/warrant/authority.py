"""Issuing, attenuating and verifying warrants.

Ed25519 signatures over a canonical JSON serialization. The signature covers
the parent link and the depth, so a chain cannot be reordered or re-parented
after the fact without detection.

The property we actually care about is proved by :func:`verify_chain`: given
an ordered root-to-leaf chain, every hop is signed, correctly linked,
unexpired, and no wider than its parent. If that holds, then whatever the leaf
did was within what the root principal granted - which is the question nobody
can currently answer.

Keys
----
An Authority holds a private key (it can sign and verify) or only a public key
(it can verify, nothing else - what an auditor should hold). Keys can be saved
to and loaded from PEM files, which is what lets ``warrant verify`` check
signatures made in an earlier run:

    Authority.load_or_create("warrant.key")     # private key, created if missing
    Authority.verifier("warrant.pub")           # public key only

Every warrant names the key that signed it (``key_id``), so a failed check can
say "signed by a different key" rather than just "invalid".
"""

from __future__ import annotations

import hashlib
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import Scope, Warrant, utcnow

__all__ = ["Authority", "ChainError", "verify_chain", "DEFAULT_TTL"]

#: How long a warrant stays valid when no ttl is given.
DEFAULT_TTL = timedelta(hours=1)


class ChainError(Exception):
    """Raised when a warrant or a chain fails verification."""


def _new_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:16]}"


class Authority:
    """Holds the signing key and mints warrants.

    In a deployment this lives in the collector, not in the agent process - an
    agent that could mint its own warrants could grant itself anything. For
    local development an in-process key is fine.

    ``Authority()`` generates a fresh key that lives only in memory.
    """

    def __init__(self, private_key: Ed25519PrivateKey | None = None, *,
                 public_key: Ed25519PublicKey | None = None):
        if private_key is None and public_key is None:
            private_key = Ed25519PrivateKey.generate()
        self._key = private_key
        self._public = private_key.public_key() if private_key is not None else public_key
        raw = self._public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        # A short, stable name for this key: the start of its SHA-256 fingerprint.
        self._key_id = "key_" + hashlib.sha256(raw).hexdigest()[:16]

    # ---- identity -------------------------------------------------------

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._public

    @property
    def key_id(self) -> str:
        return self._key_id

    @property
    def can_sign(self) -> bool:
        """False for a verify-only authority built from a public key."""
        return self._key is not None

    # ---- keys on disk ---------------------------------------------------

    @classmethod
    def load(cls, path: str | Path) -> "Authority":
        """Load a private key saved by :meth:`save`."""
        key = serialization.load_pem_private_key(Path(path).read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} does not hold an Ed25519 private key")
        return cls(key)

    @classmethod
    def load_or_create(cls, path: str | Path) -> "Authority":
        """Load the key at ``path``, or create and save a new one if there is none.

        Creation uses an exclusive open, so two processes starting at once
        cannot each write a different key (which would make half the
        warrants unverifiable). The loser of that race loads the winner's key.
        """
        path = Path(path)
        if path.exists():
            return cls.load(path)
        authority = cls()
        try:
            authority._write_private(path, exclusive=True)
        except FileExistsError:
            return cls.load(path)
        return authority

    @classmethod
    def verifier(cls, path: str | Path) -> "Authority":
        """A verify-only authority from a public key file (a private key file also works)."""
        data = Path(path).read_bytes()
        if b"PRIVATE KEY" in data:
            return cls(public_key=cls.load(path).public_key)
        key = serialization.load_pem_public_key(data)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError(f"{path} does not hold an Ed25519 public key")
        return cls(public_key=key)

    def save(self, path: str | Path) -> Path:
        """Write the private key to ``path`` and the public key beside it as ``.pub``."""
        path = Path(path)
        self._write_private(path, exclusive=False)
        return path

    def public_key_pem(self) -> bytes:
        return self._public.public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)

    def _write_private(self, path: Path, exclusive: bool) -> None:
        if self._key is None:
            raise ChainError("a verify-only authority has no private key to save")
        pem = self._key.private_bytes(serialization.Encoding.PEM,
                                      serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | (os.O_EXCL if exclusive else os.O_TRUNC)
        # Mode 0o600 = readable by the owner only. Windows largely ignores the
        # mode, so keep key files out of shared folders there.
        fd = os.open(path, flags | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        path.with_suffix(".pub").write_bytes(self.public_key_pem())

    # ---- minting --------------------------------------------------------

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
            key_id=self.key_id,
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

        ``scope`` defaults to the parent's scope unchanged. If supplied it may
        leave fields unspecified (they inherit) and must otherwise be a subset;
        widening raises :class:`ChainError` rather than silently clamping,
        because a caller trying to widen has a bug worth surfacing.
        """
        now = now or utcnow()
        # Step 1: the parent must be genuine and still valid.
        self.verify(parent)
        if parent.is_expired(now):
            raise ChainError(f"parent warrant {parent.warrant_id} has expired")

        # Step 2: work out the child's scope and prove it is no wider.
        child_scope = parent.scope if scope is None else scope.inherit_unspecified(parent.scope)
        ok, reason = child_scope.is_subset_of(parent.scope)
        if not ok:
            raise ChainError(f"attenuation would widen authority: {reason}")

        # Step 3: a child may never outlive its parent.
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
            key_id=self.key_id,
        )
        return self._sign(w)

    def _sign(self, w: Warrant) -> Warrant:
        if self._key is None:
            raise ChainError("this authority holds only a public key and cannot sign")
        return w.with_signature(self._key.sign(w.signing_bytes()))

    def verify(self, w: Warrant) -> None:
        """Raise :class:`ChainError` if the signature does not check out."""
        if w.signature is None:
            raise ChainError(f"warrant {w.warrant_id} is unsigned")
        try:
            self._public.verify(w.signature, w.signing_bytes())
        except InvalidSignature as exc:
            hint = ""
            if w.key_id and w.key_id != self.key_id:
                hint = f" (it names signing key {w.key_id}; checked against {self.key_id})"
            raise ChainError(f"warrant {w.warrant_id} has an invalid signature{hint}") from exc


def verify_chain(
    chain: list[Warrant],
    authority: Authority | None,
    now: datetime | None = None,
    allow_expired: bool = False,
) -> None:
    """Validate an ordered root-to-leaf chain. Raises :class:`ChainError`.

    ``authority`` is used to check signatures. Pass ``None`` to check only the
    structure (links, depths, attenuation) when no key is available - weaker,
    because a forger can make a structurally perfect chain.

    ``allow_expired`` exists because audits happen long after the fact - when
    reconstructing history you care that the chain was valid *then*, not that
    the warrants are still live now.
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
        if authority is not None:
            authority.verify(w)

        if not allow_expired and w.is_expired(now):
            raise ChainError(f"warrant {w.warrant_id} expired at {w.expires_at.isoformat()}")

        if i == 0:
            continue

        # Every rule below compares this hop with the one above it.
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
