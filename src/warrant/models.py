"""Core data model - the three objects everything else is built from.

  Scope        - WHAT an actor may do: which operations, on which targets, how
                 many records one action may change, whether irreversible
                 actions are allowed, and plain-English conditions.
  Warrant      - a SIGNED grant of a Scope to one holder (an agent), linked to
                 the warrant it was derived from. Following those links from
                 any agent back to the top reaches the human who started it.
  ActionRecord - something an agent ACTUALLY did, recorded under a Warrant,
                 together with the verdict of the admission check.

The central rule is *attenuation*: a Warrant derived from another may only ever
narrow the Scope, never widen it. That rule is what makes the chain mean
something - if it held at every hop, then whatever happened at the leaf was
within what the root principal granted.

Where this file is used:
    runtime.py    calls Scope.permits() on every action       (Tier 1 check)
    authority.py  calls Scope.is_subset_of() at every hop      (attenuation)
    collector/    stores these objects and rebuilds the tree from them
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import Any, Iterable

__all__ = ["Scope", "Warrant", "ActionRecord", "utcnow", "NON_MUTATING", "pattern_covers"]

#: Operations that read without changing anything. ``max_scale`` does not apply
#: to these: an agent scanning 412 rows to find deletion candidates is doing its
#: job, while deleting 400 of them is the thing worth bounding. Conflating the
#: two makes every table scan a violation and trains people to ignore the alerts.
NON_MUTATING: frozenset[str] = frozenset(
    {"read", "list", "get", "search", "query", "describe", "count", "exists"}
)


def utcnow() -> datetime:
    """Current time, always timezone-aware UTC so timestamps compare safely."""
    return datetime.now(timezone.utc)


def _canonical(obj: Any) -> bytes:
    """Deterministic bytes for signing.

    A signature is over exact bytes, so the same warrant must always serialize
    to the same bytes: keys sorted, no optional whitespace.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# ---------------------------------------------------------------------------
# Target patterns
#
# Targets are glob patterns. "crm.*" means every resource whose name starts
# with "crm.", "crm.?" means "crm." plus exactly one character, and "crm.[ab]"
# means "crm.a" or "crm.b". Two different questions get asked about them:
#
#   1. Does a pattern cover a concrete resource name?  ("crm.*" vs "crm.leads")
#      That is ordinary glob matching.
#
#   2. Is one PATTERN inside another PATTERN?          ("crm.*" inside "crm.?")
#      This is the attenuation question: could a child that asked for "crm.*"
#      reach anything its parent ("crm.?") could not? Ordinary glob matching
#      answers this WRONGLY - it reads the child's "*" as a plain character,
#      so "crm.*" looks like a five-character name that "crm.?" matches, and
#      the child silently gains every crm table. That was a real bug.
#
# For question 2 the patterns are compared token by token instead. The check
# is deliberately conservative: when it cannot PROVE the child is inside the
# parent, it answers no. A wrong "no" costs a developer a clearer error; a
# wrong "yes" would break the one guarantee this library makes.
#
# All matching is case-sensitive (fnmatchcase, not fnmatch). Plain fnmatch
# ignores case on Windows only, so the same scope used to allow "CRM.Leads"
# on a laptop and reject it on a Linux server.
# ---------------------------------------------------------------------------

_GLOB_META = frozenset("*?[")


@lru_cache(maxsize=4096)
def _glob_tokens(pattern: str) -> tuple[tuple[str, str], ...]:
    """Split a glob pattern into tokens, reading it exactly the way fnmatch does.

    Each token is ``(kind, text)``:
      "star"  - ``*``: any run of characters, including none
      "any"   - ``?``: exactly one character
      "class" - ``[...]``: exactly one character from a set
      "lit"   - one ordinary character
    """
    tokens: list[tuple[str, str]] = []
    i, n = 0, len(pattern)
    while i < n:
        ch = pattern[i]
        if ch == "*":
            # "**" matches exactly what "*" matches, so collapse repeats.
            if not tokens or tokens[-1][0] != "star":
                tokens.append(("star", "*"))
            i += 1
        elif ch == "?":
            tokens.append(("any", "?"))
            i += 1
        elif ch == "[":
            # Find the closing bracket using fnmatch's rules: a leading "!"
            # negates the set, and a "]" straight after "[" or "[!" is a
            # member of the set rather than its end.
            j = i + 1
            if j < n and pattern[j] == "!":
                j += 1
            if j < n and pattern[j] == "]":
                j += 1
            while j < n and pattern[j] != "]":
                j += 1
            if j >= n:
                tokens.append(("lit", "["))  # never closed: fnmatch treats it literally
                i += 1
            else:
                tokens.append(("class", pattern[i : j + 1]))
                i = j + 1
        else:
            tokens.append(("lit", ch))
            i += 1
    return tuple(tokens)


def _token_covers(parent_kind: str, parent_text: str, child_kind: str, child_text: str) -> bool:
    """Does one single-character parent token cover one child token?

    Never called with a parent "star" - stars are handled by the caller,
    because they can absorb any number of child tokens.
    """
    if child_kind == "star":
        return False  # a run of characters only fits inside a parent "*"
    if parent_kind == "any":
        return True  # "?" covers any single character, set, or "?"
    if parent_kind == "class":
        if child_kind == "lit":
            return fnmatchcase(child_text, parent_text)
        # Proving one set is inside a different set is possible but fiddly;
        # accept only the identical set. Conservative, never unsafe.
        return child_kind == "class" and child_text == parent_text
    # The parent is a plain character: only the same plain character fits.
    return child_kind == "lit" and child_text == parent_text


@lru_cache(maxsize=8192)
def pattern_covers(parent: str, child: str) -> bool:
    """True only if every name ``child`` can match is also matched by ``parent``.

    ``child`` may be a concrete name ("crm.leads") or a pattern ("crm.l*").

    How it works: walk both token lists with dynamic programming. The table
    entry ``ok[i][j]`` answers "do the parent's tokens from i onward cover the
    child's tokens from j onward?". It is filled in from the end backwards, so
    ``ok[0][0]`` is the answer for the whole of both patterns.
    """
    if not (_GLOB_META & set(child)):
        # Fast path: the child is a plain name, so this is ordinary matching.
        # This is the case on nearly every recorded action, so it stays cheap.
        return fnmatchcase(child, parent)

    p, c = _glob_tokens(parent), _glob_tokens(child)
    P, C = len(p), len(c)
    ok = [[False] * (C + 1) for _ in range(P + 1)]
    ok[P][C] = True  # both patterns used up at the same time: covered

    for i in range(P - 1, -1, -1):
        kind, text = p[i]
        for j in range(C, -1, -1):
            if kind == "star":
                # The parent's "*" either stops here, or swallows the child's
                # next token - whatever that token is, even another "*".
                ok[i][j] = ok[i + 1][j] or (j < C and ok[i][j + 1])
            elif j < C and _token_covers(kind, text, *c[j]):
                ok[i][j] = ok[i + 1][j + 1]
    return ok[0][0]


def _target_within(candidate: str, patterns: Iterable[str]) -> bool:
    """A target (name or pattern) is within a set if one pattern provably covers it."""
    return any(pattern_covers(p, candidate) for p in patterns)


def _require_list(name: str, value: Any) -> None:
    """Catch ``operations="read"`` - a string would silently become {'r','e','a','d'}."""
    if isinstance(value, str):
        raise TypeError(f"{name} must be a list of strings, got the string {value!r}; "
                        f"did you mean [{value!r}]?")


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scope:
    """What an actor may do.

    ``targets`` entries are glob patterns matched against resource names, so
    ``crm.*`` covers ``crm.opportunities``. ``max_scale`` is an upper bound on
    the number of records a single *mutating* action may affect; ``None``
    means unbounded.

    ``constraints`` are natural-language conditions that deterministic checks
    cannot evaluate (for example "only records with no recent activity"). They
    travel down the chain and are handed to the semantic judge later.

    ``unspecified`` remembers which fields the author left out when building
    the scope with :meth:`of`. It is bookkeeping only: it is not signed, not
    stored, and not part of equality. See :meth:`inherit_unspecified`.
    """

    operations: frozenset[str] = frozenset()
    targets: frozenset[str] = frozenset()
    max_scale: int | None = None
    irreversible_allowed: bool = False
    constraints: tuple[str, ...] = ()
    unspecified: frozenset[str] = field(default=frozenset(), compare=False, repr=False)

    @staticmethod
    def of(
        operations: list[str] | None = None,
        targets: list[str] | None = None,
        max_scale: int | None = None,
        irreversible_allowed: bool | None = None,
        constraints: list[str] | None = None,
    ) -> "Scope":
        """Ergonomic constructor that takes plain lists.

        Leaving an argument out (``None``) marks that field *unspecified*.

        * Used as a session's root scope, unspecified just means the empty
          default: no operations, no targets, unbounded scale, no
          irreversible actions.
        * Handed to an agent as a narrowing, unspecified fields are copied
          from the parent - so an agent can say only what it narrows.

        Note the difference: ``targets=None`` means "not narrowing targets",
        while ``targets=[]`` means "this agent may touch no targets at all".
        """
        _require_list("operations", operations)
        _require_list("targets", targets)
        _require_list("constraints", constraints)
        if max_scale is not None and max_scale < 0:
            raise ValueError(f"max_scale must be zero or more, got {max_scale}")

        given = {
            "operations": operations,
            "targets": targets,
            "max_scale": max_scale,
            "irreversible_allowed": irreversible_allowed,
        }
        return Scope(
            operations=frozenset(operations or []),
            targets=frozenset(targets or []),
            max_scale=max_scale,
            irreversible_allowed=bool(irreversible_allowed),
            constraints=tuple(constraints or []),
            unspecified=frozenset(name for name, value in given.items() if value is None),
        )

    def covers_target(self, resource: str) -> bool:
        """Is ``resource`` inside one of this scope's target patterns?

        Uses the pattern-aware check, so an action reported against a
        wildcard resource (say, a bulk job on "crm.*") is judged as the set of
        tables it really touches, not as a strangely-named single table.
        """
        return _target_within(resource, self.targets)

    def permits(self, operation: str, resource: str, scale: int = 1,
                irreversible: bool = False) -> tuple[bool, str | None]:
        """Deterministic admission check. Returns (ok, reason_if_not).

        This is the Tier 1 check from the design: pure comparison, no model
        call, microseconds. The checks run cheapest-first and stop at the first
        failure. Constraints are deliberately *not* evaluated here - they are
        not decidable without understanding the words.
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
        """True when this Scope is no wider than ``other`` in every dimension.

        This is the attenuation test run at every delegation hop. Each block
        below checks one way a child could have gained power.
        """
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

        # Dropping a condition ("must not affect active customers") is a
        # widening too: the child would be free of a rule the parent was bound by.
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
        """Build a scope that is guaranteed no wider than this one.

        Unlike attenuation (which raises when asked to widen), this clamps:
        asking for more than this scope has quietly yields the overlap. Useful
        when code wants "at most X" without having to know the parent exactly.
        """
        _require_list("operations", operations)
        _require_list("targets", targets)
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
        new_constraints = self.constraints + tuple(
            c for c in (add_constraints or ()) if c not in self.constraints
        )
        return Scope(
            operations=new_ops,
            targets=new_targets,
            max_scale=new_scale,
            irreversible_allowed=new_irrev,
            constraints=new_constraints,
        )

    def inherit_unspecified(self, parent: "Scope") -> "Scope":
        """Fill in whatever this scope left unsaid, copying it from ``parent``.

        A declared child scope states what it *narrows*; anything it does not
        mention inherits. Without this, writing

            @agent("crm", scope=Scope.of(operations=["read"]))

        would give the agent no targets at all, and narrowing one field would
        mean retyping every other field of the parent. That is hostile, and it
        is how people end up pasting a wide scope everywhere just to make an
        error go away - the over-permissioning this library exists to expose.

        Inheriting can never widen (a copied field is exactly the parent's),
        so this is safe by construction. The authority still runs the full
        subset check on the result.
        """
        def pick(name: str) -> Any:
            return getattr(parent, name) if name in self.unspecified else getattr(self, name)

        # max_scale=None inherits even on a Scope built directly (not via of()):
        # "unbounded" under a bounded parent would be a widening anyway.
        max_scale = self.max_scale if self.max_scale is not None else parent.max_scale

        # Constraints always accumulate: the parent's first, then the child's new ones.
        constraints = parent.constraints + tuple(
            c for c in self.constraints if c not in parent.constraints
        )
        return Scope(
            operations=pick("operations"),
            targets=pick("targets"),
            max_scale=max_scale,
            irreversible_allowed=pick("irreversible_allowed"),
            constraints=constraints,
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON form. This exact shape is what gets signed and stored."""
        return {
            "operations": sorted(self.operations),
            "targets": sorted(self.targets),
            "max_scale": self.max_scale,
            "irreversible_allowed": self.irreversible_allowed,
            "constraints": list(self.constraints),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Scope":
        """Inverse of :meth:`to_dict`. The result has every field specified."""
        return Scope(
            operations=frozenset(d.get("operations") or []),
            targets=frozenset(d.get("targets") or []),
            max_scale=d.get("max_scale"),
            irreversible_allowed=bool(d.get("irreversible_allowed", False)),
            constraints=tuple(d.get("constraints") or []),
        )


# ---------------------------------------------------------------------------
# Warrant and ActionRecord
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Warrant:
    """A signed grant of authority, derived from at most one parent.

    Think of a purchase order rather than a credit card: it names who holds
    it, exactly what it allows, when it expires, and which warrant it was cut
    from (``parent_id``). The root warrant (``parent_id=None``, ``depth=0``)
    is minted directly from the human's request.
    """

    warrant_id: str
    session_id: str
    root_principal: str          # the human at the top of the chain
    holder: str                  # the agent holding this warrant right now
    scope: Scope
    issued_at: datetime
    expires_at: datetime
    parent_id: str | None = None
    depth: int = 0               # 0 for the root, parent's depth + 1 below it
    key_id: str | None = None    # which signing key signed it (see authority.py)
    signature: bytes | None = field(default=None, repr=False)

    def payload(self) -> dict[str, Any]:
        """The signed portion - everything except the signature itself.

        ``parent_id`` and ``depth`` are included on purpose: signing them means
        a warrant cannot later be re-attached to a different parent or moved
        to a different position in the chain without the signature breaking.
        """
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
            "key_id": self.key_id,
        }

    def signing_bytes(self) -> bytes:
        return _canonical(self.payload())

    def with_signature(self, signature: bytes) -> "Warrant":
        return replace(self, signature=signature)

    def is_expired(self, now: datetime | None = None) -> bool:
        return (now or utcnow()) >= self.expires_at


@dataclass(frozen=True)
class ActionRecord:
    """Something an agent actually did, recorded under a Warrant.

    ``allowed`` and ``violation`` hold the Tier 1 verdict at the moment the
    action was recorded.

    ``blocked`` says what happened next, which an auditor needs to know:
    True means ENFORCE mode stopped the action, so it never took place;
    a violation with ``blocked=False`` was recorded in OBSERVE mode and the
    action went ahead.

    ``detail`` is free-form context from the caller (row counts, filters
    used, a note, the tool name) that later tiers can reason over.
    """

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
    blocked: bool = False
    detail: dict[str, Any] = field(default_factory=dict)
