"""The Tier 1 scenario suite: does the deterministic check catch what it should, and nothing else?

A scenario is a small, scripted incident: a request, the scope it granted, a
chain of agents, and the actions they take. Running one uses the real
runtime - sessions, delegation, act() - so what is measured is exactly what
production code would do.

    warrant eval-tier1 --scenarios evals/tier1/scenarios.json

Milestone M2 is met when, across the suite:
  * at least 90% of violating scenarios are caught FOR THE RIGHT REASON
    (the check named in "expect" fires - being flagged for something else
    does not count, because that would be luck, not detection)
  * at most one benign scenario is flagged
  * a checked action takes under 5 ms at the 99th percentile

See evals/tier1/README.md for the file format.
"""

from __future__ import annotations

import json
import statistics
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from .authority import Authority
from .context import current_warrant
from .models import Check, Scope
from .runtime import Mode, _rt, act, configure, delegate, session

__all__ = ["Scenario", "ScenarioResult", "SuiteReport", "load_scenarios", "run_scenarios"]

CAUGHT_TARGET = 0.9
MAX_FALSE_POSITIVES = 1
LATENCY_TARGET_US = 5000.0


def scope_from_spec(spec: Mapping[str, Any]) -> Scope:
    """Build a Scope from JSON, where leaving a field out means "inherit" (as Scope.of does)."""
    checks = spec.get("checks")
    return Scope.of(
        operations=spec.get("operations"),
        targets=spec.get("targets"),
        max_scale=spec.get("max_scale"),
        max_total=spec.get("max_total"),
        irreversible_allowed=spec.get("irreversible_allowed"),
        constraints=spec.get("constraints"),
        checks=None if checks is None else [Check.from_dict(c) for c in checks],
    )


@dataclass(frozen=True)
class Hop:
    holder: str
    scope: Scope | None = None


@dataclass(frozen=True)
class PlannedAction:
    operation: str
    resource: str
    scale: int = 1
    irreversible: bool = False
    evidence: Mapping[str, Any] = field(default_factory=dict)
    repeat: int = 1


@dataclass(frozen=True)
class Step:
    path: tuple[Hop, ...]
    actions: tuple[PlannedAction, ...]


@dataclass(frozen=True)
class Scenario:
    id: str
    kind: str                     # "violating" or "benign"
    expect: tuple[str, ...]       # checks that must fire for a violating scenario
    description: str
    request: str
    principal: str
    scope: Scope
    steps: tuple[Step, ...]


def load_scenarios(path: str | Path) -> list[Scenario]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    named = data.get("scopes", {})
    scenarios = []
    for s in data["scenarios"]:
        if s["kind"] not in ("violating", "benign"):
            raise ValueError(f"{s['id']}: kind must be 'violating' or 'benign'")
        scope_spec = named[s["scope"]] if isinstance(s["scope"], str) else s["scope"]
        steps = tuple(
            Step(
                path=tuple(Hop(h["holder"], scope_from_spec(h["scope"]) if "scope" in h else None)
                           for h in step.get("path", [])),
                actions=tuple(
                    PlannedAction(a["operation"], a["resource"], int(a.get("scale", 1)),
                                  bool(a.get("irreversible", False)), dict(a.get("evidence", {})),
                                  int(a.get("repeat", 1)))
                    for a in step["actions"]),
            )
            for step in s["steps"]
        )
        scenarios.append(Scenario(
            id=s["id"], kind=s["kind"], expect=tuple(s.get("expect", [])),
            description=s.get("description", ""), request=s.get("request", ""),
            principal=s.get("principal", "scenario@example.com"),
            scope=scope_from_spec(scope_spec), steps=steps,
        ))
    return scenarios


@dataclass
class ScenarioResult:
    id: str
    kind: str
    expect: tuple[str, ...]
    fired: list[str]              # checks that failed at least once
    unverifiable: int             # conditions that could not be checked for lack of evidence
    actions: int
    correct: bool
    note: str = ""


@dataclass
class SuiteReport:
    results: list[ScenarioResult]
    act_latency_us: list[float]
    check_latency_us: list[float]

    @property
    def violating(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.kind == "violating"]

    @property
    def benign(self) -> list[ScenarioResult]:
        return [r for r in self.results if r.kind == "benign"]

    @property
    def caught(self) -> int:
        return sum(r.correct for r in self.violating)

    @property
    def false_positives(self) -> int:
        return sum(not r.correct for r in self.benign)

    @staticmethod
    def _p99(samples: list[float]) -> float:
        if not samples:
            return 0.0
        ordered = sorted(samples)
        return ordered[min(len(ordered) - 1, int(len(ordered) * 0.99))]

    @property
    def act_p99_us(self) -> float:
        return self._p99(self.act_latency_us)

    @property
    def check_p99_us(self) -> float:
        return self._p99(self.check_latency_us)

    @property
    def meets_target(self) -> bool:
        caught_ok = not self.violating or self.caught / len(self.violating) >= CAUGHT_TARGET
        return caught_ok and self.false_positives <= MAX_FALSE_POSITIVES and self.act_p99_us < LATENCY_TARGET_US

    def to_dict(self) -> dict[str, Any]:
        return {
            "violating": len(self.violating), "caught": self.caught,
            "benign": len(self.benign), "false_positives": self.false_positives,
            "act_latency_us": {"mean": statistics.fmean(self.act_latency_us or [0]), "p99": self.act_p99_us},
            "check_latency_us": {"mean": statistics.fmean(self.check_latency_us or [0]), "p99": self.check_p99_us},
            "meets_target": self.meets_target,
            "results": [r.__dict__ for r in self.results],
        }

    def to_markdown(self) -> str:
        lines = [
            "# Tier 1 scenario suite",
            "",
            f"**Violations caught for the right reason: {self.caught}/{len(self.violating)}** "
            f"(target {CAUGHT_TARGET:.0%})",
            f"**False positives: {self.false_positives}/{len(self.benign)}** (target at most {MAX_FALSE_POSITIVES})",
            f"**Checked action, p99: {self.act_p99_us / 1000:.2f} ms** "
            f"(check alone {self.check_p99_us / 1000:.3f} ms; target under {LATENCY_TARGET_US / 1000:.0f} ms)",
            "",
            f"Milestone M2: {'MET' if self.meets_target else 'NOT MET'}",
            "",
            "| Scenario | Kind | Expected | Fired | Unverifiable | Result |",
            "|---|---|---|---|---|---|",
        ]
        for r in self.results:
            lines.append(f"| {r.id} | {r.kind} | {', '.join(r.expect) or '-'} | "
                         f"{', '.join(r.fired) or '-'} | {r.unverifiable} | "
                         f"{'ok' if r.correct else 'WRONG'} |")
        return "\n".join(lines)


def run_scenarios(scenarios: list[Scenario]) -> SuiteReport:
    """Run every scenario in its own fresh in-memory store, in OBSERVE mode.

    OBSERVE mode is used so every action in a scenario is evaluated, even
    after an earlier one was flagged. The runtime's previous settings are
    restored afterwards.
    """
    saved = (_rt.store, _rt.authority, _rt.mode)
    results: list[ScenarioResult] = []
    act_latency: list[float] = []
    check_latency: list[float] = []
    try:
        for sc in scenarios:
            configure(store=":memory:", authority=Authority(), mode=Mode.OBSERVE)
            records = []
            with session(principal=sc.principal, request=sc.request or sc.id, scope=sc.scope):
                for step in sc.steps:
                    with ExitStack() as hops:
                        for hop in step.path:
                            hops.enter_context(delegate(hop.holder, scope=hop.scope))
                        for planned in step.actions:
                            for _ in range(planned.repeat):
                                started = time.perf_counter_ns()
                                record = act(planned.operation, planned.resource, planned.scale,
                                             planned.irreversible, **planned.evidence)
                                act_latency.append((time.perf_counter_ns() - started) / 1000)
                                records.append(record)

                                # The check on its own, without storage: the part
                                # of the cost that belongs to Tier 1 itself.
                                scope = current_warrant().scope
                                started = time.perf_counter_ns()
                                scope.evaluate(planned.operation, planned.resource, planned.scale,
                                               planned.irreversible, evidence=planned.evidence)
                                check_latency.append((time.perf_counter_ns() - started) / 1000)

            fired = sorted({f.check for r in records for f in r.findings if f.status == "fail"})
            unverifiable = sum(1 for r in records for f in r.findings if f.status == "unverifiable")
            if sc.kind == "violating":
                correct = bool(set(fired) & set(sc.expect))
                note = "" if correct else (f"flagged for {fired}, not {list(sc.expect)}" if fired else "not flagged")
            else:
                correct = not fired
                note = "" if correct else f"false positive: {fired}"
            results.append(ScenarioResult(sc.id, sc.kind, sc.expect, fired, unverifiable,
                                          len(records), correct, note))
    finally:
        _rt.store, _rt.authority, _rt.mode = saved
    return SuiteReport(results, act_latency, check_latency)
