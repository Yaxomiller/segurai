"""Core data model.

Three objects matter:

  Scope        - what an actor is permitted to do.
  Warrant      - a signed grant of a Scope, derived from a parent Warrant.
  ActionRecord - something an agent actually did, under a Warrant.

The central invariant is *attenuation*: a Warrant derived from another may only
ever narrow the Scope, never widen it. That invariant is what makes the chain
meaningful - if it held at every hop, then whatever happened at the leaf was
within what the root principal granted.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from fnmatch import fnmatch
from typing import Any

__all__ = ["Scope", "Warrant", "ActionRecord", "utcnow", "NON_MUTATING"]

#: Operations that read without changing anything. ``max_scale`` does not apply
#: to these: an agent scanning 412 rows to find deletion candidates is doing its
#: job, while deleting 400 of them is the thing worth bounding. Conflating the
#: two makes every table scan a violation and trains people to ignore the alerts.
NON_MUTATING: frozenset[str] = frozenset(
    {"read", "list", "get", "search", "query", "describe", "count", "exists"}
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _canonical(obj: Any) -> bytes:
    """Deterministic bytes for signing. Sorted keys, no incidental whitespace."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass(frozen=True)
class Scope:
    """What an actor may do.

    ``targets`` entries are glob patterns matched against resource names, so
    ``crm.*`` covers ``crm.opportunities``. ``max_scale`` is an upper bound on
    the number of records a single action may affect; ``None`` means unbounded.

    ``constraints`` are natural-language conditions that deterministic checks
    cannot evaluate (for example "only records with no recent activity"). They
    are carried through the chain and handed to the semantic judge later.
    """

    operations: frozenset[str] = frozenset()
    targets: frozenset[str] = frozenset()
    max_scale: int | None = None
    irreversible_allowed: bool = False
    constraints: tuple[str, ...] = ()

    @staticmethod
    def of(
        operations: list[str] | None = None,
        targets: list[str] | None = None,
        max_scale: int | None = None,
        irreversible_allowed: bool = False,
        constraints: list[str] | None = None,
    ) -> "Scope":
        """Ergonomic constructor that takes plain lists."""
        return Scope(
            operations=frozenset(operations or []),
            targets=frozenset(targets or []),
            max_scale=max_scale,
            irreversible_allowed=irreversible_allowed,
            constraints=tuple(constraints or []),
        )

    def covers_target(self, resource: str) -> bool:
        return any(fnmatch(resource, pattern) for pattern in self.targets)

    def permits(self, operation: str, resource: str, scale: int = 1,
                irreversible: bool = False) -> tuple[bool, str | None]:
        """Deterministic admission check. Returns (ok, reason_if_not).

        This is the Tier 1 check from the design: pure comparison, no model
        call, microseconds. Constraints are deliberately *not* evaluated here -
        they are not decidable without semantics.
        """
        if operation not in self.operations:
            return False, f"operation {operation!r} not in scope {sorted(self.operations)}"
        if not self.covers_target(resource):
            return False, f"target {resource!r} not covered by {sorted(self.targets)}"
        mutating = operation not in NON_MUTATING
        if mutating and self.max_scale is not None and scale > self.max_scale:
            return False, f"scale {scale} exceeds limit {self.max_scale}"
        if irreversible and not self.irreversible_allowed:
            return False, "irreversible action not permitted by scope"
        return True, None

    def is_subset_of(self, other: "Scope") -> tuple[bool, str | None]:
        """True when this Scope is no wider than ``other`` in every dimension."""
        extra_ops = self.operations - other.operations
        if extra_ops:
            return False, f"widens operations: {sorted(extra_ops)}"

        uncovered = [t for t in self.targets if not _target_within(t, other.targets)]
        if uncovered:
            return False, f"widens targets: {sorted(uncovered)}"

        if other.max_scale is not None:
            if self.max_scale is None:
                return False, "widens max_scale: unbounded under a bounded parent"
            if self.max_scale > other.max_scale:
                return False, f"widens max_scale: {self.max_scale} > {other.max_scale}"

        if self.irreversible_allowed and not other.irreversible_allowed:
            return False, "widens irreversible_allowed"

        dropped = set(other.constraints) - set(self.constraints)
        if dropped:
            return False, f"drops inherited constraints: {sorted(dropped)}"

        return True, None

    def narrow(
        self,
        operations: list[str] | None = None,
        targets: list[str] | None = None,
        max_scale: int | None = None,
        irreversible_allowed: bool | None = None,
        add_constraints: list[str] | None = None,
    ) -> "Scope":
        """Build a strictly narrower Scope. Inherited constraints are preserved."""
        new_ops = self.operations & frozenset(operations) if operations is not None else self.operations
        new_targets = (
            frozenset(t for t in targets if _target_within(t, self.targets))
            if targets is not None
            else self.targets
        )
        new_scale = self.max_scale
        if max_scale is not None:
            new_scale = max_scale if self.max_scale is None else min(max_scale, self.max_scale)
        new_irrev = self.irreversible_allowed
        if irreversible_allowed is not None:
            new_irrev = irreversible_allowed and self.irreversible_allowed
        new_constraints = self.constraints + tuple(add_constraints or ())
        return Scope(
            operations=new_ops,
            targets=new_targets,
            max_scale=new_scale,
            irreversible_allowed=new_irrev,
            constraints=new_constraints,
        )

    def inherit_unspecified(self, parent: "Scope") -> "Scope":
        """Fill in whatever this scope left unsaid from ``parent``.

        A declared child scope states what it *narrows*; anything it does not
        mention inherits. Without this, writing

            @agent("crm", scope=Scope.of(operations=["read"], targets=["crm.x"]))

        under a parent that has constraints and a scale cap would be rejected
        as a widening, and the developer would have to retype the parent's
        fields verbatim to say "narrower". That is hostile, and it is how you
        train people to copy a wide scope everywhere just to make the error go
        away - which is the over-permissioning problem this library exists to
        expose.

        Inheriting can never widen, so this is safe by construction.
        """
        max_scale = self.max_scale if self.max_scale is not None else parent.max_scale
        inherited = tuple(c for c in parent.constraints if c not in self.constraints)
        return replace(self, max_scale=max_scale, constraints=inherited + self.constraints)

    def to_dict(self) -> dict[str, Any]:
        return {
            "operations": sorted(self.operations),
            "targets": sorted(self.targets),
            "max_scale": self.max_scale,
            "irreversible_allowed": self.irreversible_allowed,
            "constraints": list(self.constraints),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Scope":
        return Scope(
            operations=frozenset(d.get("operations") or []),
            targets=frozenset(d.get("targets") or []),
            max_scale=d.get("max_scale"),
            irreversible_allowed=bool(d.get("irreversible_allowed", False)),
            constraints=tuple(d.get("constraints") or []),
        )


def _target_within(candidate: str, patterns: frozenset[str]) -> bool:
    """A target is within a parent set if some parent pattern covers it.

    Handles the pattern-vs-pattern case too: ``crm.*`` is within ``crm.*`` and
    within ``*``, but not within ``crm.accounts``.
    """
    for p in patterns:
        if candidate == p or fnmatch(candidate, p):
            return True
    return False


@dataclass(frozen=True)
class Warrant:
    """A signed grant of authority, derived from at most one parent."""

    warrant_id: str
    session_id: str
    root_principal: str
    holder: str
    scope: Scope
    issued_at: datetime
    expires_at: datetime
    parent_id: str | None = None
    depth: int = 0
    signature: bytes | None = field(default=None, repr=False)

    def payload(self) -> dict[str, Any]:
        """The signed portion. Excludes the signature itself."""
        return {
            "warrant_id": self.warrant_id,
            "session_id": self.session_id,
            "root_principal": self.root_principal,
            "holder": self.holder,
            "scope": self.scope.to_dict(),
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "parent_id": self.parent_id,
            "depth": self.depth,
        }

    def signing_bytes(self) -> bytes:
        return _canonical(self.payload())

    def with_signature(self, signature: bytes) -> "Warrant":
        return replace(self, signature=signature)

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


@dataclass(frozen=True)
class ActionRecord:
    """Something an agent actually did, recorded under a Warrant."""

    action_id: str
    session_id: str
    warrant_id: str
    actor: str
    operation: str
    resource: str
    scale: int = 1
    irreversible: bool = False
    at: datetime = field(default_factory=utcnow)
    allowed: bool = True
    violation: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
