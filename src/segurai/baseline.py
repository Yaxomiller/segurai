"""Tier 3: what this organisation's agents normally do, learned from its own record.

Tier 1 checks an action against limits a person wrote. Tier 2 asks a model
whether a flagged action fits the request. Both start from someone's guess at
what "normal" is - "50 per action" is a number a person or a model made up.
Every recorded action is evidence of what normal actually is, here, for this
agent, on this system. This module reads that evidence:

    segurai baseline --days 30                  what each agent usually does
    segurai baseline --days 30 --rules          company rules proposed from it (TOML)
    segurai baseline --check ses_7a1e98629d674cde
                                                anything in one request far outside it

It learns only from CLEAN history: actions that were allowed and happened.
Blocked attempts and flagged actions are not "normal", whatever their
number, and observed (unchecked) telemetry is left out unless asked for.

For each (agent, operation, resource) it keeps how many times it happened, in
how many requests, the sizes (median, 95th and 99th percentile, largest),
and whether anything irreversible was done. From that:

  * PROPOSALS - limit rules at a readable number above what really happens
    (the 99th percentile times ``headroom``, never below the largest seen),
    and "never anything irreversible" where nothing irreversible ever was.
    Only patterns with at least ``min_samples`` actions get one: a limit
    learned from five actions is a guess with extra steps. Proposals are
    for a person to read and adopt; nothing is applied by itself.
  * UNUSUAL - an action far above its pattern's usual size, a first
    irreversible action, an operation or resource the agent never used, or
    an agent never seen. Advice for the dashboard, alerts or the judge; like
    Tier 2, it never changes what Tier 1 decided.

This is statistics, not a trained model, and it says so. With little history
it proposes little, by design.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

from .collector.store import Store
from .models import NON_MUTATING, ActionRecord, utcnow
from .report import _nice_ceiling

__all__ = ["Pattern", "Baseline", "learn", "Unusual"]


def _percentile(sorted_values: list[int], fraction: float) -> int:
    """Nearest-rank percentile of an already sorted list."""
    if not sorted_values:
        return 0
    rank = max(1, math.ceil(fraction * len(sorted_values)))
    return sorted_values[min(rank, len(sorted_values)) - 1]


@dataclass
class Pattern:
    """What one agent does with one operation on one resource, as recorded."""

    actor: str
    operation: str
    resource: str
    scales: list[int] = field(default_factory=list)
    sessions: set[str] = field(default_factory=set)
    irreversible: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None

    def add(self, a: ActionRecord) -> None:
        self.scales.append(a.scale)
        self.sessions.add(a.session_id)
        self.irreversible += int(a.irreversible)
        self.first_seen = a.at if self.first_seen is None or a.at < self.first_seen else self.first_seen
        self.last_seen = a.at if self.last_seen is None or a.at > self.last_seen else self.last_seen

    @property
    def samples(self) -> int:
        return len(self.scales)

    @property
    def mutating(self) -> bool:
        return self.operation not in NON_MUTATING

    def stats(self) -> dict[str, int]:
        ordered = sorted(self.scales)
        return {"p50": _percentile(ordered, 0.5), "p95": _percentile(ordered, 0.95),
                "p99": _percentile(ordered, 0.99), "max": ordered[-1] if ordered else 0}


@dataclass(frozen=True)
class Unusual:
    action_id: str
    actor: str
    reason: str


@dataclass
class Baseline:
    since: datetime
    until: datetime
    patterns: dict[tuple[str, str, str], Pattern]
    actions: int
    min_samples: int = 20

    def for_actor(self, actor: str) -> list[Pattern]:
        return [p for (a, _, _), p in self.patterns.items() if a == actor]

    # ---- proposals ------------------------------------------------------------------------

    def proposals(self, *, headroom: float = 1.5) -> list[dict[str, Any]]:
        """Company rules a person may adopt, each with the evidence behind it."""
        rules = []
        for (actor, operation, resource), p in sorted(self.patterns.items()):
            if p.samples < self.min_samples or not p.mutating:
                continue
            s = p.stats()
            limit = max(_nice_ceiling(s["p99"] * headroom), s["max"])
            evidence = (f"learned from {p.samples} actions in {len(p.sessions)} requests between "
                        f"{self.since:%Y-%m-%d} and {self.until:%Y-%m-%d}: median {s['p50']}, "
                        f"99th percentile {s['p99']}, largest {s['max']}")
            rules.append({"name": f"{actor}: {operation} on {resource}, at most {limit} at once (learned)",
                          "effect": "limit", "agents": [actor], "operations": [operation],
                          "targets": [resource], "max_scale": limit, "reason": evidence})
            if p.irreversible == 0:
                rules.append({"name": f"{actor}: nothing irreversible on {resource} (learned)",
                              "effect": "limit", "agents": [actor], "operations": [operation],
                              "targets": [resource], "irreversible": False,
                              "reason": f"none of {p.samples} recorded {operation} actions was irreversible"})
        return rules

    # ---- unusual actions ------------------------------------------------------------------------

    def unusual(self, actions: Iterable[ActionRecord], *, factor: float = 2.0) -> list[Unusual]:
        """Actions far outside this organisation's usual - advice, never a verdict."""
        known_actors = {a for (a, _, _) in self.patterns}
        found = []
        for a in actions:
            p = self.patterns.get((a.actor, a.operation, a.resource))
            if a.actor not in known_actors:
                reason = f"{a.actor} has no history here yet"
                if self.actions < self.min_samples:
                    continue                                 # too little history to call anything new
            elif p is None:
                did_operation = any(x == a.actor and o == a.operation for (x, o, _) in self.patterns)
                if a.operation in NON_MUTATING and did_operation:
                    continue                                 # reading a new table is everyday work
                reason = f"{a.actor} has never been seen to {a.operation} {a.resource} before"
            elif p.samples < self.min_samples:
                continue
            else:
                s = p.stats()
                if p.mutating and a.scale > max(s["p99"] * factor, s["max"]):
                    reason = (f"changes {a.scale} records; {a.actor}'s usual is {s['p50']} and its largest "
                              f"ever {s['max']} (over {p.samples} actions)")
                elif a.irreversible and p.irreversible == 0:
                    reason = f"the first irreversible {a.operation} by {a.actor} on {a.resource}"
                else:
                    continue
            found.append(Unusual(a.action_id, a.actor, reason))
        return found


def learn(store: Store, *, days: int = 30, until: datetime | None = None, min_samples: int = 20,
          include_observed: bool = False) -> Baseline:
    """Learn the baseline from the clean actions recorded in the ``days`` before ``until``."""
    until = until or utcnow()
    since = until - timedelta(days=days)
    patterns: dict[tuple[str, str, str], Pattern] = {}
    count = 0
    for a in store.actions_between(since, until):
        if a.blocked or not a.allowed:
            continue                                         # only what was allowed AND happened
        if not include_observed and a.session_id.startswith("otel_"):
            continue                                         # unchecked telemetry is not "normal"
        key = (a.actor, a.operation, a.resource)
        if key not in patterns:
            patterns[key] = Pattern(*key)
        patterns[key].add(a)
        count += 1
    return Baseline(since=since, until=until, patterns=patterns, actions=count, min_samples=min_samples)


def summary(baseline: Baseline) -> list[str]:
    """The baseline as lines a person can read."""
    lines = [f"Learned from {baseline.actions} clean actions, {baseline.since:%Y-%m-%d} to "
             f"{baseline.until:%Y-%m-%d} (patterns need {baseline.min_samples} actions before they "
             f"propose anything)."]
    by_actor: dict[str, list[Pattern]] = defaultdict(list)
    for p in baseline.patterns.values():
        by_actor[p.actor].append(p)
    for actor in sorted(by_actor):
        lines.append(f"  {actor}")
        for p in sorted(by_actor[actor], key=lambda x: (x.resource, x.operation)):
            s = p.stats()
            size = f"median {s['p50']}, p99 {s['p99']}, largest {s['max']}" if p.mutating else "reads"
            enough = "" if p.samples >= baseline.min_samples else "  (too few to learn from)"
            lines.append(f"    {p.operation:<10} {p.resource:<28} {p.samples:>5} actions in "
                         f"{len(p.sessions)} requests - {size}{enough}")
    return lines
