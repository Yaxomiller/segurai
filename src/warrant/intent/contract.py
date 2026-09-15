"""The scope contract: a machine-checkable version of what the person meant.

"clean up our old sales records" is not something a program can check an
action against. The intent compiler turns it into a ScopeContract:

    goal                   remove or archive outdated sales records
    expected_operations    search, archive
    expected_targets       crm.opportunities
    expected_scale         records, typical max 50
    implied_constraints    only records with no recent activity;
                           must not affect active customers
    irreversible_expected  false
    clarifications_needed  (none - the request was clear enough)

and the contract becomes the session's root Scope. The contract comes from a
language model, so it is treated as untrusted, and two rules apply first:

  1. It must use the organisation's vocabulary. Operations and targets are
     checked against a Catalog of what actually exists. Anything else is
     dropped and reported - never silently kept, because a made-up name like
     "sales_db.records" would match nothing and quietly flag every action.

  2. It can only NARROW what the person is really allowed to do. When a
     ``ceiling`` (the principal's actual permissions) is supplied, the
     contract's scope is clamped inside it. A request - or a prompt injection
     hidden inside one - cannot grant anyone more than they already had.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..models import NON_MUTATING, Scope, pattern_covers

__all__ = ["Catalog", "CatalogEntry", "ScopeContract"]


@dataclass(frozen=True)
class CatalogEntry:
    """One name in the vocabulary, with a description the model can read."""

    name: str
    description: str = ""


def _entries(value: Any) -> tuple[CatalogEntry, ...]:
    """Accept {"name": "description"}, [{"name":..., "description":...}] or ["name", ...]."""
    if isinstance(value, Mapping):
        items = [CatalogEntry(str(k), str(v or "")) for k, v in value.items()]
    else:
        items = []
        for item in value or []:
            if isinstance(item, Mapping):
                items.append(CatalogEntry(str(item["name"]), str(item.get("description") or "")))
            else:
                items.append(CatalogEntry(str(item)))
    # Sorted, so the same catalog always renders to the same prompt bytes.
    return tuple(sorted(items, key=lambda e: e.name))


@dataclass(frozen=True)
class Catalog:
    """The operations and resources that exist in one organisation."""

    operations: tuple[CatalogEntry, ...]
    resources: tuple[CatalogEntry, ...]

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Catalog":
        catalog = Catalog(operations=_entries(d.get("operations")),
                          resources=_entries(d.get("resources")))
        if not catalog.operations or not catalog.resources:
            raise ValueError("a catalog needs at least one operation and one resource")
        return catalog

    @staticmethod
    def load(path: str | Path) -> "Catalog":
        return Catalog.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    @property
    def operation_names(self) -> tuple[str, ...]:
        return tuple(e.name for e in self.operations)

    @property
    def resource_names(self) -> tuple[str, ...]:
        return tuple(e.name for e in self.resources)

    def resources_matching(self, patterns: Iterable[str]) -> set[str]:
        """The concrete catalog resources that the given names or patterns reach."""
        patterns = list(patterns)
        return {r for r in self.resource_names if any(pattern_covers(p, r) for p in patterns)}

    def render(self) -> str:
        """The catalog as plain text for the model's instructions."""
        lines = ["Operations:"]
        lines += [f"- {e.name}: {e.description}" if e.description else f"- {e.name}"
                  for e in self.operations]
        lines.append("")
        lines.append("Resources:")
        lines += [f"- {e.name}: {e.description}" if e.description else f"- {e.name}"
                  for e in self.resources]
        return "\n".join(lines)


def _strings(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not all(isinstance(v, str) for v in value):
        raise ValueError(f"{field} must be a list of strings")
    return tuple(value)


@dataclass(frozen=True)
class ScopeContract:
    """What a request is understood to authorize, in checkable form."""

    goal: str
    expected_operations: tuple[str, ...]
    expected_targets: tuple[str, ...]
    scale_unit: str = "records"
    typical_max: int | None = None
    implied_constraints: tuple[str, ...] = ()
    irreversible_expected: bool = False
    clarifications_needed: tuple[str, ...] = ()

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "ScopeContract":
        """Read the JSON shape the compiler produces (``expected_scale`` nested)."""
        scale = d.get("expected_scale") or {}
        typical_max = scale.get("typical_max")
        if typical_max is not None and (isinstance(typical_max, bool) or not isinstance(typical_max, int)):
            raise ValueError(f"expected_scale.typical_max must be a whole number or null, got {typical_max!r}")
        return ScopeContract(
            goal=str(d.get("goal") or ""),
            expected_operations=_strings(d.get("expected_operations"), "expected_operations"),
            expected_targets=_strings(d.get("expected_targets"), "expected_targets"),
            scale_unit=str(scale.get("unit") or "records"),
            typical_max=typical_max,
            implied_constraints=_strings(d.get("implied_constraints"), "implied_constraints"),
            irreversible_expected=bool(d.get("irreversible_expected", False)),
            clarifications_needed=_strings(d.get("clarifications_needed"), "clarifications_needed"),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "goal": self.goal,
            "expected_operations": list(self.expected_operations),
            "expected_targets": list(self.expected_targets),
            "expected_scale": {"unit": self.scale_unit, "typical_max": self.typical_max},
            "implied_constraints": list(self.implied_constraints),
            "irreversible_expected": self.irreversible_expected,
            "clarifications_needed": list(self.clarifications_needed),
        }

    def checked_against(self, catalog: Catalog) -> tuple["ScopeContract", list[str]]:
        """Apply the catalog rule. Returns the cleaned contract and what was wrong.

        Nothing here adds authority: names are only ever removed, and a
        missing scale bound is replaced by the tightest one.
        """
        problems: list[str] = []

        operations: list[str] = []
        for op in self.expected_operations:
            if op not in catalog.operation_names:
                problems.append(f"operation {op!r} is not in the catalog; dropped")
            elif op not in operations:
                operations.append(op)

        targets: list[str] = []
        for t in self.expected_targets:
            if not catalog.resources_matching([t]):
                problems.append(f"target {t!r} matches no catalog resource; dropped")
            elif t not in targets:
                targets.append(t)

        typical_max = self.typical_max
        if typical_max is not None and typical_max < 0:
            problems.append(f"typical_max {typical_max} is negative; ignored")
            typical_max = None

        changes_records = any(op not in NON_MUTATING for op in operations)
        if changes_records and typical_max is None:
            # Fail closed: with no bound, a 10,000-row change would pass
            # unremarked. A bound of 1 means any larger change gets flagged,
            # so a human looks at it.
            problems.append("the work changes records but no typical scale was given; "
                            "defaulted to 1 so larger changes are flagged")
            typical_max = 1

        cleaned = replace(self, expected_operations=tuple(operations),
                          expected_targets=tuple(targets), typical_max=typical_max)
        return cleaned, problems

    def to_scope(self) -> Scope:
        """The contract as a Scope, ready to be a session's root."""
        return Scope.of(
            operations=list(self.expected_operations),
            targets=list(self.expected_targets),
            max_scale=self.typical_max,
            # typical_max is the contract's estimate of the size of the whole
            # job, so it also caps the session's running total. That is what
            # stops 400 one-record deletions slipping under a limit of 50.
            max_total=self.typical_max,
            irreversible_allowed=self.irreversible_expected,
            constraints=list(self.implied_constraints),
        )
