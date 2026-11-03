"""Measuring the intent compiler against hand-labeled cases.

The milestone target (M1): on held-out cases, at least 80% of generated
contracts are acceptable, with accuracy reported per field.

Each labeled case says what a correct contract must contain and what it may
contain, because many requests have more than one reasonable reading:

    operations.required   groups; the contract needs at least one name from EACH group
    operations.allowed    the contract may use only these names
    targets.required / .allowed   the same, for the catalog resources the
                                  contract's targets actually reach
    scale        {"min", "max"} bounds for typical_max; null = not graded
    irreversible true / false, or null when either reading is fair
    constraints  groups of keywords; each group is one condition the contract
                 should mention, matched if ANY keyword in the group appears

A contract is "acceptable" when operations, targets, scale and
irreversibility all pass and it mentions at least half the expected
conditions. That automatic verdict is a stand-in for a person's judgement,
so `write_review_sheet` exports every case for a human to confirm.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .compiler import PROMPT_VERSION, IntentCompiler, IntentError
from .contract import Catalog, ScopeContract

__all__ = ["IntentCase", "CaseResult", "EvalReport", "load_cases", "grade", "run_eval"]

#: Share of expected conditions a contract must mention to be acceptable.
CONSTRAINT_RECALL_NEEDED = 0.5
#: The milestone's pass mark.
MILESTONE_TARGET = 0.8


@dataclass(frozen=True)
class IntentCase:
    id: str
    split: str
    request: str
    operations_required: tuple[tuple[str, ...], ...]
    operations_allowed: frozenset[str]
    targets_required: tuple[tuple[str, ...], ...]
    targets_allowed: frozenset[str]
    scale: tuple[int, int | None] | None
    irreversible: bool | None
    constraints: tuple[tuple[str, ...], ...]
    notes: str = ""

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "IntentCase":
        ops, targets, scale = d["operations"], d["targets"], d.get("scale")
        case = IntentCase(
            id=d["id"],
            split=d["split"],
            request=d["request"],
            operations_required=tuple(tuple(g) for g in ops.get("required", [])),
            operations_allowed=frozenset(ops.get("allowed", [])),
            targets_required=tuple(tuple(g) for g in targets.get("required", [])),
            targets_allowed=frozenset(targets.get("allowed", [])),
            scale=None if scale is None else (int(scale.get("min", 0)), scale.get("max")),
            irreversible=d.get("irreversible"),
            constraints=tuple(tuple(k.lower() for k in g) for g in d.get("constraints", [])),
            notes=d.get("notes", ""),
        )
        for group in case.operations_required:
            if not set(group) <= case.operations_allowed:
                raise ValueError(f"{case.id}: required operations {group} are not all allowed")
        for group in case.targets_required:
            if not set(group) <= case.targets_allowed:
                raise ValueError(f"{case.id}: required targets {group} are not all allowed")
        return case


def load_cases(path: str | Path) -> list[IntentCase]:
    """Read one case per line from a JSONL file (blank lines ignored)."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return [IntentCase.from_dict(json.loads(line)) for line in lines if line.strip()]


@dataclass
class CaseResult:
    case_id: str
    split: str
    request: str
    contract: dict[str, Any] | None
    error: str | None = None
    operations_ok: bool = False
    targets_ok: bool = False
    scale_ok: bool = False
    irreversible_ok: bool = False
    constraint_recall: float = 0.0
    acceptable: bool = False
    failures: list[str] = field(default_factory=list)


def _set_ok(name: str, chosen: set[str], required: tuple[tuple[str, ...], ...],
            allowed: frozenset[str], failures: list[str]) -> bool:
    """Grade a set of names against required groups and an allowed list."""
    if not allowed:
        # The label says "nothing at all" - e.g. a prompt-injection request.
        if chosen:
            failures.append(f"{name}: expected none, got {sorted(chosen)}")
            return False
        return True
    if not chosen:
        failures.append(f"{name}: none given")
        return False
    ok = True
    for group in required:
        if not chosen & set(group):
            failures.append(f"{name}: missing one of {list(group)}")
            ok = False
    extra = chosen - allowed
    if extra:
        failures.append(f"{name}: not expected {sorted(extra)}")
        ok = False
    return ok


def grade(case: IntentCase, contract: ScopeContract, catalog: Catalog) -> CaseResult:
    """Score one contract against its label."""
    failures: list[str] = []
    result = CaseResult(case.id, case.split, case.request, contract.to_dict())

    result.operations_ok = _set_ok("operations", set(contract.expected_operations),
                                   case.operations_required, case.operations_allowed, failures)
    # Targets are graded by what they REACH, so "crm.opportunities" and a
    # wildcard that covers exactly the same resources score the same.
    reached = catalog.resources_matching(contract.expected_targets)
    result.targets_ok = _set_ok("targets", reached, case.targets_required, case.targets_allowed, failures)

    if case.scale is None:
        result.scale_ok = True
    else:
        low, high = case.scale
        t = contract.typical_max
        result.scale_ok = t is not None and t >= low and (high is None or t <= high)
        if not result.scale_ok:
            failures.append(f"scale: typical_max {t} outside {low}..{high if high is not None else 'any'}")

    result.irreversible_ok = case.irreversible is None or contract.irreversible_expected == case.irreversible
    if not result.irreversible_ok:
        failures.append(f"irreversible: expected {case.irreversible}, got {contract.irreversible_expected}")

    if case.constraints:
        text = " ".join(contract.implied_constraints).lower()
        missed = [g for g in case.constraints if not any(k in text for k in g)]
        result.constraint_recall = 1 - len(missed) / len(case.constraints)
        for g in missed:
            failures.append(f"constraints: nothing about {list(g)}")
    else:
        result.constraint_recall = 1.0

    result.acceptable = (result.operations_ok and result.targets_ok and result.scale_ok
                         and result.irreversible_ok
                         and result.constraint_recall >= CONSTRAINT_RECALL_NEEDED)
    result.failures = failures
    return result


@dataclass
class EvalReport:
    results: list[CaseResult]
    model: str | None = None
    prompt_version: str = PROMPT_VERSION

    @property
    def total(self) -> int:
        return len(self.results)

    @property
    def acceptable_rate(self) -> float:
        return sum(r.acceptable for r in self.results) / self.total if self.total else 0.0

    def field_accuracy(self) -> dict[str, float]:
        n = self.total or 1
        return {
            "operations": sum(r.operations_ok for r in self.results) / n,
            "targets": sum(r.targets_ok for r in self.results) / n,
            "scale": sum(r.scale_ok for r in self.results) / n,
            "irreversible": sum(r.irreversible_ok for r in self.results) / n,
            "constraint_recall": sum(r.constraint_recall for r in self.results) / n,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "prompt_version": self.prompt_version,
            "cases": self.total,
            "acceptable_rate": self.acceptable_rate,
            "meets_milestone": self.acceptable_rate >= MILESTONE_TARGET,
            "field_accuracy": self.field_accuracy(),
            "errors": sum(1 for r in self.results if r.error),
            "results": [asdict(r) for r in self.results],
        }

    def to_markdown(self) -> str:
        acc = self.field_accuracy()
        good = sum(r.acceptable for r in self.results)
        lines = [
            "# Intent compiler eval",
            "",
            f"Prompt `{self.prompt_version}` - model `{self.model or 'unknown'}` - {self.total} cases",
            "",
            f"**Acceptable: {good}/{self.total} ({self.acceptable_rate:.1%})** - "
            f"milestone target {MILESTONE_TARGET:.0%} "
            f"({'met' if self.acceptable_rate >= MILESTONE_TARGET else 'not met'})",
            "",
            "| Field | Accuracy |",
            "|---|---|",
            f"| Operations | {acc['operations']:.1%} |",
            f"| Targets | {acc['targets']:.1%} |",
            f"| Scale | {acc['scale']:.1%} |",
            f"| Irreversibility | {acc['irreversible']:.1%} |",
            f"| Constraint recall (average) | {acc['constraint_recall']:.1%} |",
        ]
        misses = [r for r in self.results if not r.acceptable]
        if misses:
            lines += ["", "## Not acceptable", ""]
            for r in misses:
                why = r.error or "; ".join(r.failures)
                lines.append(f"- `{r.case_id}` {r.request!r} - {why}")
        return "\n".join(lines)

    def write_review_sheet(self, path: str | Path) -> None:
        """A CSV for a person to confirm or overturn each automatic verdict."""
        columns = ["case_id", "split", "request", "operations", "targets", "typical_max",
                   "irreversible", "constraints", "clarifications", "auto_verdict",
                   "auto_failures", "human_verdict", "human_notes"]
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(columns)
            for r in self.results:
                c = r.contract or {}
                writer.writerow([
                    r.case_id, r.split, r.request,
                    ", ".join(c.get("expected_operations", [])),
                    ", ".join(c.get("expected_targets", [])),
                    (c.get("expected_scale") or {}).get("typical_max"),
                    c.get("irreversible_expected"),
                    " | ".join(c.get("implied_constraints", [])),
                    " | ".join(c.get("clarifications_needed", [])),
                    "acceptable" if r.acceptable else "not acceptable",
                    r.error or "; ".join(r.failures),
                    "", "",
                ])


def run_eval(compiler: IntentCompiler, cases: Iterable[IntentCase],
             progress: Callable[[int, int, CaseResult], None] | None = None) -> EvalReport:
    """Compile and grade every case. A failed compile counts as not acceptable."""
    cases = list(cases)
    results: list[CaseResult] = []
    model = None
    for i, case in enumerate(cases, start=1):
        try:
            compiled = compiler.compile(case.request)
            model = compiled.model or model
            result = grade(case, compiled.contract, compiler.catalog)
        except IntentError as exc:
            result = CaseResult(case.id, case.split, case.request, None, error=str(exc))
        results.append(result)
        if progress is not None:
            progress(i, len(cases), result)
    return EvalReport(results=results, model=model)
