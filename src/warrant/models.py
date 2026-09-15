"""Core data model - the objects everything else is built from.

  Scope        - WHAT an actor may do: which operations, on which targets, how
                 many records one action (and the whole session) may change,
                 whether irreversible actions are allowed, and conditions.
  Check        - one condition a program can test, such as
                 "days_since_activity >= 180", against evidence an action reports.
  Warrant      - a SIGNED grant of a Scope to one holder (an agent), linked to
                 the warrant it was derived from. Following those links from
                 any agent back to the top reaches the human who started it.
  ActionRecord - something an agent ACTUALLY did, recorded under a Warrant,
                 together with every Finding of the admission check.
  Finding      - one thing the check found: a broken rule, or a rule that
                 could not be tested for lack of evidence.

The central rule is *attenuation*: a Warrant derived from another may only ever
narrow the Scope, never widen it. That rule is what makes the chain mean
something - if it held at every hop, then whatever happened at the leaf was
within what the root principal granted.

Where this file is used:
    runtime.py    calls Scope.evaluate() on every action       (Tier 1 check)
    authority.py  calls Scope.is_subset_of() at every hop       (attenuation)
    collector/    stores these objects and rebuilds the tree from them
"""

from __future__ import annotations

import json
import operator as _operator
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import Any, Iterable, Mapping

__all__ = ["Scope", "Check", "Finding", "Warrant", "ActionRecord", "utcnow",
           "NON_MUTATING", "CHECK_OPS", "pattern_covers"]

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
# Findings and checks - the parts of the Tier 1 check
# ---------------------------------------------------------------------------

#: Comparison operators a Check may use.
CHECK_OPS = ("==", "!=", "<", "<=", ">", ">=", "in", "not_in")

_COMPARE = {
    "==": _operator.eq, "!=": _operator.ne,
    "<": _operator.lt, "<=": _operator.le, ">": _operator.gt, ">=": _operator.ge,
}


@dataclass(frozen=True)
class Finding:
    """One thing the Tier 1 check found about one action.

    ``check`` names the rule it came from:
        operation     the operation is not in the scope
        target        the resource is outside the scope's targets
        scale         one action changes more records than ``max_scale`` allows
        total         the session's running total of changed records passes ``max_total``
        irreversible  an irreversible action the scope does not allow
        condition     a Check (e.g. "no recent activity") is not met
        spec          a tool call could not be described by its ActionSpec

    ``status`` is "fail" - the rule was broken - or "unverifiable": the rule
    could not be tested because the action did not report the evidence it
    needs. Unverifiable is NOT a violation. It is a question for a person, or
    for the semantic judge (Tier 2): calling it a violation would bury real
    alerts in noise, and calling it a pass would be a lie.

    ``clause`` quotes the part of the scope the finding is about, so a report
    can say exactly which promise was broken.
    """

    check: str
    status: str
    reason: str
    clause: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check, "status": self.status, "reason": self.reason, "clause": self.clause}

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Finding":
        return Finding(str(d["check"]), str(d["status"]), str(d["reason"]), str(d.get("clause", "")))


def _fail(check: str, reason: str, clause: str) -> Finding:
    return Finding(check, "fail", reason, clause)


def _compare(item: Any, op: str, value: Any) -> bool:
    """Apply one operator. Raises TypeError when the two sides cannot be compared."""
    if op == "in":
        return item in value
    if op == "not_in":
        return item not in value
    if op in ("<", "<=", ">", ">=") and isinstance(item, bool) != isinstance(value, bool):
        # Python happily compares True with 180; for evidence that is a mistake.
        raise TypeError("cannot order a true/false value against a number")
    return _COMPARE[op](item, value)


@dataclass(frozen=True)
class Check:
    """A condition Tier 1 can test against the evidence an action reports.

    The plain-English condition "only records with no recent activity" cannot
    be checked by a program. This version of it can:

        Check(field="days_since_activity", op=">=", value=180,
              condition="only records with no recent activity",
              targets=("crm.opportunities",))

    The agent reports evidence with the action -

        warrant.act("archive", "crm.opportunities", scale=3,
                    days_since_activity=[200, 12, 400])

    - and the check compares it. The rules:

      * A list of evidence must satisfy the condition for EVERY item: one
        recently active record in a batch of three breaks the rule.
      * Missing evidence, or evidence that cannot be compared (a word where a
        number belongs), makes the result "unverifiable" - never a pass, and
        never a violation.
      * ``on="mutations"`` (the default) applies the check only to actions
        that change something; reads may look at any record. ``on="all"``
        applies it to reads too.
      * ``targets`` limits the check to some resources (glob patterns);
        empty means every resource.
    """

    field: str
    op: str
    value: Any
    condition: str = ""
    targets: tuple[str, ...] = ()
    on: str = "mutations"

    def __post_init__(self) -> None:
        if not self.field:
            raise ValueError("a check needs a field name")
        if self.op not in CHECK_OPS:
            raise ValueError(f"op must be one of {CHECK_OPS}, got {self.op!r}")
        if self.on not in ("mutations", "all"):
            raise ValueError(f"on must be 'mutations' or 'all', got {self.on!r}")
        # A frozen dataclass must be hashable, and lists are not, so list
        # values are stored as tuples.
        if isinstance(self.value, list):
            object.__setattr__(self, "value", tuple(self.value))
        if isinstance(self.targets, (list, str)):
            object.__setattr__(self, "targets",
                               (self.targets,) if isinstance(self.targets, str) else tuple(self.targets))
        if self.op in ("in", "not_in") and not isinstance(self.value, tuple):
            raise ValueError(f"op {self.op!r} needs a list of values")

    @property
    def label(self) -> str:
        """How the check is named in findings: its condition, or the formula itself."""
        return self.condition or f"{self.field} {self.op} {self.value!r}"

    def applies(self, operation: str, resource: str) -> bool:
        """Does this check govern this action at all?"""
        if self.on == "mutations" and operation in NON_MUTATING:
            return False
        return not self.targets or _target_within(resource, self.targets)

    def evaluate(self, evidence: Mapping[str, Any] | None) -> Finding | None:
        """None when the condition holds; otherwise a "fail" or "unverifiable" Finding."""
        label = self.label
        if not evidence or self.field not in evidence:
            return Finding("condition", "unverifiable",
                           f"cannot verify {label!r}: the action reported no {self.field!r}", label)
        reported = evidence[self.field]
        items = list(reported) if isinstance(reported, (list, tuple, set, frozenset)) else [reported]
        if not items:
            return Finding("condition", "unverifiable",
                           f"cannot verify {label!r}: {self.field!r} was empty", label)

        broken = []
        for item in items:
            try:
                if not _compare(item, self.op, self.value):
                    broken.append(item)
            except TypeError:
                return Finding("condition", "unverifiable",
                               f"cannot verify {label!r}: {self.field} = {item!r} cannot be "
                               f"compared with {self.value!r}", label)
        if broken:
            shown = broken[0] if len(broken) == 1 else broken
            return _fail("condition",
                         f"condition not met: {label} ({self.field} = {shown!r}, "
                         f"required {self.op} {self.value!r})", label)
        return None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "field": self.field,
            "op": self.op,
            "value": list(self.value) if isinstance(self.value, tuple) else self.value,
            "condition": self.condition,
        }
        if self.targets:
            d["targets"] = list(self.targets)
        if self.on != "mutations":
            d["on"] = self.on
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Check":
        return Check(field=d["field"], op=d["op"], value=d["value"],
                     condition=d.get("condition", ""), targets=tuple(d.get("targets") or ()),
                     on=d.get("on", "mutations"))


def _as_check(value: Check | Mapping[str, Any]) -> Check:
    return value if isinstance(value, Check) else Check.from_dict(value)


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Scope:
    """What an actor may do.

    ``targets`` entries are glob patterns matched against resource names, so
    ``crm.*`` covers ``crm.opportunities``.

    ``max_scale`` bounds how many records a single *mutating* action may
    change. ``max_total`` bounds how many records all mutating actions in the
    session may change together - without it, 400 one-record deletions would
    each pass a limit of 50. ``None`` means unbounded for either.

    ``constraints`` are natural-language conditions, carried down the chain
    for people and for the semantic judge. ``checks`` are conditions in a form
    a program can test against evidence (see :class:`Check`).

    ``unspecified`` remembers which fields the author left out when building
    the scope with :meth:`of`. It is bookkeeping only: it is not signed, not
    stored, and not part of equality. See :meth:`inherit_unspecified`.
    """

    operations: frozenset[str] = frozenset()
    targets: frozenset[str] = frozenset()
    max_scale: int | None = None
    irreversible_allowed: bool = False
    constraints: tuple[str, ...] = ()
    max_total: int | None = None
    checks: tuple[Check, ...] = ()
    unspecified: frozenset[str] = field(default=frozenset(), compare=False, repr=False)

    @staticmethod
    def of(
        operations: list[str] | None = None,
        targets: list[str] | None = None,
        max_scale: int | None = None,
        irreversible_allowed: bool | None = None,
        constraints: list[str] | None = None,
        max_total: int | None = None,
        checks: list[Check | Mapping[str, Any]] | None = None,
    ) -> "Scope":
        """Ergonomic constructor that takes plain lists.

        Leaving an argument out (``None``) marks that field *unspecified*.

        * Used as a session's root scope, unspecified just means the empty
          default: no operations, no targets, unbounded scale and total, no
          irreversible actions, no conditions.
        * Handed to an agent as a narrowing, unspecified fields are copied
          from the parent - so an agent can say only what it narrows.

        Note the difference: ``targets=None`` means "not narrowing targets",
        while ``targets=[]`` means "this agent may touch no targets at all".
        """
        _require_list("operations", operations)
        _require_list("targets", targets)
        _require_list("constraints", constraints)
        _require_list("checks", checks)
        for name, bound in (("max_scale", max_scale), ("max_total", max_total)):
            if bound is not None and bound < 0:
                raise ValueError(f"{name} must be zero or more, got {bound}")

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
            max_total=max_total,
            checks=tuple(_as_check(c) for c in (checks or [])),
            unspecified=frozenset(name for name, value in given.items() if value is None),
        )

    def covers_target(self, resource: str) -> bool:
        """Is ``resource`` inside one of this scope's target patterns?

        Uses the pattern-aware check, so an action reported against a
        wildcard resource (say, a bulk job on "crm.*") is judged as the set of
        tables it really touches, not as a strangely-named single table.
        """
        return _target_within(resource, self.targets)

    def evaluate(self, operation: str, resource: str, scale: int = 1, irreversible: bool = False,
                 evidence: Mapping[str, Any] | None = None, changed_so_far: int = 0) -> list[Finding]:
        """Run every Tier 1 rule against one action. An empty list means clean.

        This is the deterministic check from the design: pure comparison, no
        model call, microseconds. Unlike :meth:`permits`, it does not stop at
        the first problem - an auditor wants every rule an action broke.

        ``evidence`` is what the action reported about the records it touched
        (used by ``checks``). ``changed_so_far`` is how many records earlier
        actions in the session already changed (used by ``max_total``).
        """
        findings: list[Finding] = []
        if operation not in self.operations:
            findings.append(_fail("operation",
                                  f"operation {operation!r} not in scope {sorted(self.operations)}",
                                  f"operations={sorted(self.operations)}"))
        if not self.covers_target(resource):
            findings.append(_fail("target",
                                  f"target {resource!r} not covered by {sorted(self.targets)}",
                                  f"targets={sorted(self.targets)}"))
        mutating = operation not in NON_MUTATING
        if mutating and self.max_scale is not None and scale > self.max_scale:
            findings.append(_fail("scale", f"scale {scale} exceeds limit {self.max_scale}",
                                  f"max_scale={self.max_scale}"))
        if mutating and self.max_total is not None and changed_so_far + scale > self.max_total:
            findings.append(_fail("total",
                                  f"total changed this session would reach {changed_so_far + scale}, "
                                  f"over the limit of {self.max_total}",
                                  f"max_total={self.max_total}"))
        if irreversible and not self.irreversible_allowed:
            findings.append(_fail("irreversible", "irreversible action not permitted by scope",
                                  "irreversible_allowed=false"))
        for check in self.checks:
            if check.applies(operation, resource):
                finding = check.evaluate(evidence)
                if finding is not None:
                    findings.append(finding)
        return findings

    def permits(self, operation: str, resource: str, scale: int = 1,
                irreversible: bool = False) -> tuple[bool, str | None]:
        """Quick yes/no: (ok, first reason if not).

        Built on :meth:`evaluate`. Conditions are not tested here because no
        evidence is passed - they come back "unverifiable", which is not a
        failure.
        """
        for finding in self.evaluate(operation, resource, scale, irreversible):
            if finding.status == "fail":
                return False, finding.reason
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

        if other.max_total is not None:
            if self.max_total is None:
                return False, "widens max_total: unbounded under a bounded parent"
            if self.max_total > other.max_total:
                return False, f"widens max_total: {self.max_total} > {other.max_total}"

        if self.irreversible_allowed and not other.irreversible_allowed:
            return False, "widens irreversible_allowed"

        # Dropping a condition ("must not affect active customers") is a
        # widening too: the child would be free of a rule the parent was bound by.
        dropped = set(other.constraints) - set(self.constraints)
        if dropped:
            return False, f"drops inherited constraints: {sorted(dropped)}"
        missing = [c.label for c in other.checks if c not in self.checks]
        if missing:
            return False, f"drops inherited checks: {missing}"

        return True, None

    def narrow(
        self,
        operations: list[str] | None = None,
        targets: list[str] | None = None,
        max_scale: int | None = None,
        irreversible_allowed: bool | None = None,
        add_constraints: list[str] | None = None,
        max_total: int | None = None,
        add_checks: list[Check] | None = None,
    ) -> "Scope":
        """Build a scope that is guaranteed no wider than this one.

        Unlike attenuation (which raises when asked to widen), this clamps:
        asking for more than this scope has quietly yields the overlap. Useful
        when code wants "at most X" without having to know the parent exactly.
        """
        _require_list("operations", operations)
        _require_list("targets", targets)
        new_ops = self.operations & frozenset(operations) if operations is not None else self.operations
        new_targets = self.targets
        if targets is not None:
            kept: set[str] = set()
            for t in targets:
                if _target_within(t, self.targets):
                    kept.add(t)  # already inside this scope: keep it as asked
                else:
                    # Asked for more than this scope has (say "crm.*" when only
                    # "crm.opportunities" is allowed): keep the parts of this
                    # scope that fall inside the request, instead of dropping
                    # the request entirely.
                    kept.update(p for p in self.targets if pattern_covers(t, p))
            new_targets = frozenset(kept)

        def lower(requested: int | None, current: int | None) -> int | None:
            if requested is None:
                return current
            return requested if current is None else min(requested, current)

        new_irrev = self.irreversible_allowed
        if irreversible_allowed is not None:
            new_irrev = irreversible_allowed and self.irreversible_allowed
        new_constraints = self.constraints + tuple(
            c for c in (add_constraints or ()) if c not in self.constraints
        )
        new_checks = self.checks + tuple(c for c in (add_checks or ()) if c not in self.checks)
        return Scope(
            operations=new_ops,
            targets=new_targets,
            max_scale=lower(max_scale, self.max_scale),
            irreversible_allowed=new_irrev,
            constraints=new_constraints,
            max_total=lower(max_total, self.max_total),
            checks=new_checks,
        )

    def clamped_to(self, ceiling: "Scope") -> "Scope":
        """This scope, cut down to fit inside ``ceiling``.

        Used when a scope comes from somewhere untrusted - such as a language
        model reading a request - and must not exceed what the person is
        really permitted to do. Anything outside the ceiling is removed;
        nothing is ever added except the ceiling's own conditions.
        """
        return ceiling.narrow(
            operations=sorted(self.operations),
            targets=sorted(self.targets),
            max_scale=self.max_scale,
            irreversible_allowed=self.irreversible_allowed,
            add_constraints=list(self.constraints),
            max_total=self.max_total,
            add_checks=list(self.checks),
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

        # A missing bound inherits even on a Scope built directly (not via
        # of()): "unbounded" under a bounded parent would be a widening anyway.
        max_scale = self.max_scale if self.max_scale is not None else parent.max_scale
        max_total = self.max_total if self.max_total is not None else parent.max_total

        # Conditions always accumulate: the parent's first, then the child's new ones.
        constraints = parent.constraints + tuple(
            c for c in self.constraints if c not in parent.constraints
        )
        checks = parent.checks + tuple(c for c in self.checks if c not in parent.checks)
        return Scope(
            operations=pick("operations"),
            targets=pick("targets"),
            max_scale=max_scale,
            irreversible_allowed=pick("irreversible_allowed"),
            constraints=constraints,
            max_total=max_total,
            checks=checks,
        )

    def to_dict(self) -> dict[str, Any]:
        """Plain-JSON form. This exact shape is what gets signed and stored.

        ``max_total`` and ``checks`` appear only when set, so a scope without
        them serializes exactly as it did before they existed - and warrants
        signed back then still verify.
        """
        d: dict[str, Any] = {
            "operations": sorted(self.operations),
            "targets": sorted(self.targets),
            "max_scale": self.max_scale,
            "irreversible_allowed": self.irreversible_allowed,
            "constraints": list(self.constraints),
        }
        if self.max_total is not None:
            d["max_total"] = self.max_total
        if self.checks:
            d["checks"] = [c.to_dict() for c in self.checks]
        return d

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Scope":
        """Inverse of :meth:`to_dict`. The result has every field specified."""
        return Scope(
            operations=frozenset(d.get("operations") or []),
            targets=frozenset(d.get("targets") or []),
            max_scale=d.get("max_scale"),
            irreversible_allowed=bool(d.get("irreversible_allowed", False)),
            constraints=tuple(d.get("constraints") or []),
            max_total=d.get("max_total"),
            checks=tuple(Check.from_dict(c) for c in d.get("checks") or []),
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

    ``findings`` is everything the Tier 1 check found. ``allowed`` is True
    when none of them is a "fail", and ``violation`` joins the reasons of the
    ones that are.

    ``blocked`` says what happened next, which an auditor needs to know:
    True means ENFORCE mode stopped the action, so it never took place;
    a violation with ``blocked=False`` was recorded in OBSERVE mode and the
    action went ahead.

    ``detail`` is free-form context from the caller (evidence about the
    records touched, the tool name, a note) that later tiers can reason over.
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
    findings: tuple[Finding, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)
