"""The scope-creep report: what agents were allowed to do, versus what they did.

Over an observation window (say the last 30 days), for every agent - and for
each person's sessions as a whole - it answers:

  * which granted OPERATIONS were never used         ("delete" granted, never exercised)
  * which granted TARGETS were never touched          ("billing.*" granted, never touched)
  * which WILDCARDS could shrink to what was used     ("crm.*" -> crm.opportunities, crm.accounts)
  * how the SIZE LIMITS compare with the largest real change
  * whether IRREVERSIBLE actions were allowed but never needed

and proposes a tightened scope built only from observed use, with the
evidence behind it: sessions, actions, when first and last seen, and example
action ids an auditor can look up. Least privilege, backed by data instead
of guesses - this is the report a security team pays for.

What counts as "use": an action that happened AND stayed within its limits.
A change that broke the rules still shows up (as activity, and as "used
outside the limits"), but it is not evidence that the permission is needed.
Otherwise a single violation would turn into a recommendation to keep the
very permission that was abused. Blocked attempts never happened, so they are
not use either; they are listed separately.

Grants come from two places:

  1. The warrants themselves: what each agent was handed in each session.
  2. An optional grants file: an agent's standing permissions exported from
     an identity provider or an MCP server's token configuration (see
     load_grants). Actions in observed chains - built from plain
     OpenTelemetry spans, with no Segurai code at all - count as use here,
     which is how a team can get this report before adopting warrants.

The caution printed on every report: a permission unused in the window may
still be needed by work that runs rarely (quarter end, the annual audit).
The confidence rating reflects how much activity was observed, not certainty.
"""

from __future__ import annotations

import csv
import io
import json
import math
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

from .collector.store import Store
from .models import (
    NON_MUTATING,
    ActionRecord,
    Check,
    Scope,
    Warrant,
    pattern_covers,
    utcnow,
)

__all__ = ["Grant", "IdentityReport", "ScopeCreepReport", "load_grants", "build_report"]

CAUTION = ("A permission unused in this window may still be needed by work that runs rarely, "
           "such as quarter-end or annual jobs. Review before removing.")

#: How much room to leave above the largest change actually seen.
SCALE_HEADROOM = 1.2


@dataclass(frozen=True)
class Grant:
    """Standing permissions for one identity, from outside warrant."""

    identity: str
    source: str                          # e.g. "okta", "entra", "mcp-token", "manual"
    scope: Scope
    reference: str = ""                  # where to find it in the source system


def load_grants(path: str | Path) -> list[Grant]:
    """Read a grants file:

        {"grants": [
          {"identity": "crm_agent", "source": "okta", "reference": "app 0oa1...",
           "operations": ["read", "update", "delete", "export"],
           "targets": ["crm.*", "billing.invoices"],
           "max_scale": null, "irreversible_allowed": true}
        ]}
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    grants = []
    for g in data.get("grants", []):
        scope = Scope(
            operations=frozenset(g.get("operations") or []),
            targets=frozenset(g.get("targets") or []),
            max_scale=g.get("max_scale"),
            irreversible_allowed=bool(g.get("irreversible_allowed", False)),
            max_total=g.get("max_total"),
        )
        grants.append(Grant(str(g["identity"]), str(g.get("source") or "manual"), scope,
                            str(g.get("reference") or "")))
    return grants


def _nice_ceiling(value: float) -> int:
    """The next 'round' number at or above value: 1, 2, 5, 10, 20, 50, 100..."""
    if value <= 1:
        return 1
    magnitude = 10 ** math.floor(math.log10(value))
    for step in (1, 2, 5, 10):
        if step * magnitude >= value:
            return int(step * magnitude)
    return int(10 * magnitude)  # pragma: no cover - unreachable, the loop always returns


def _is_wildcard(pattern: str) -> bool:
    return any(ch in pattern for ch in "*?[")


@dataclass
class IdentityReport:
    """Granted versus used, for one identity and one source of grants."""

    identity: str
    source: str
    references: list[str]
    sessions: int
    actions: int
    first_seen: datetime | None
    last_seen: datetime | None
    granted_operations: list[str]
    used_operations: dict[str, int]
    unused_operations: list[str]
    granted_targets: list[str]
    used_resources: dict[str, int]
    unused_targets: list[str]
    wildcard_narrowing: dict[str, list[str]]
    granted_max_scale: int | None
    largest_change: int
    irreversible_granted: bool
    irreversible_used: int
    violations: int
    used_outside_limits: dict[str, int]   # operation -> changes that broke the rules
    blocked_attempts: int
    examples: dict[str, str]              # operation -> an action id showing it
    recommended: Scope
    confidence: str                       # none | low | medium | high

    @property
    def granted_count(self) -> int:
        return len(self.granted_operations) + len(self.granted_targets)

    @property
    def unused_count(self) -> int:
        return len(self.unused_operations) + len(self.unused_targets)

    @property
    def unused_share(self) -> float:
        return self.unused_count / self.granted_count if self.granted_count else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity": self.identity, "source": self.source, "references": self.references,
            "sessions": self.sessions, "actions": self.actions,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "granted_operations": self.granted_operations, "used_operations": self.used_operations,
            "unused_operations": self.unused_operations, "granted_targets": self.granted_targets,
            "used_resources": self.used_resources, "unused_targets": self.unused_targets,
            "wildcard_narrowing": self.wildcard_narrowing, "granted_max_scale": self.granted_max_scale,
            "largest_change": self.largest_change, "irreversible_granted": self.irreversible_granted,
            "irreversible_used": self.irreversible_used, "violations": self.violations,
            "used_outside_limits": self.used_outside_limits, "blocked_attempts": self.blocked_attempts,
            "examples": self.examples, "unused_share": round(self.unused_share, 3),
            "confidence": self.confidence, "recommended_scope": self.recommended.to_dict(),
        }


class _Tally:
    """Collects grants and uses for one (identity, source) while the report is built."""

    def __init__(self, identity: str, source: str):
        self.identity, self.source = identity, source
        self.references: list[str] = []
        self.ops: set[str] = set()
        self.targets: set[str] = set()
        self.scale_unbounded = False
        self.scale_max: int | None = None
        self.irreversible_granted = False
        self.constraints: list[str] = []
        self.checks: list[Check] = []
        self.used_ops: Counter = Counter()
        self.used_resources: Counter = Counter()
        self.outside: Counter = Counter()
        self.sessions: set[str] = set()
        self.session_totals: Counter = Counter()
        self.largest_change = 0
        self.irreversible_used = 0
        self.violations = 0
        self.blocked = 0
        self.actions = 0
        self.first: datetime | None = None
        self.last: datetime | None = None
        self.examples: dict[str, str] = {}

    def grant(self, scope: Scope, reference: str = "") -> None:
        self.ops |= scope.operations
        self.targets |= scope.targets
        if scope.max_scale is None:
            self.scale_unbounded = True
        else:
            self.scale_max = max(self.scale_max or 0, scope.max_scale)
        self.irreversible_granted |= scope.irreversible_allowed
        self.constraints += [c for c in scope.constraints if c not in self.constraints]
        self.checks += [c for c in scope.checks if c not in self.checks]
        if reference and reference not in self.references:
            self.references.append(reference)

    def use(self, a: ActionRecord) -> None:
        self.sessions.add(a.session_id)
        if a.blocked:
            # A blocked attempt never happened, so it is not "use" - but it is
            # worth showing: something tried to go beyond its grant.
            self.blocked += 1
            return

        # Everything from here on happened, so it counts as activity...
        self.actions += 1
        self.first = a.at if self.first is None or a.at < self.first else self.first
        self.last = a.at if self.last is None or a.at > self.last else self.last

        if not a.allowed:
            # ...but a change that broke the rules is not evidence the
            # permission is needed. Counting it as use would turn a violation
            # into a recommendation to keep the permission that was abused.
            self.violations += 1
            self.outside[a.operation] += 1
            self.examples.setdefault(f"{a.operation} (outside the limits)", a.action_id)
            return

        self.used_ops[a.operation] += 1
        self.used_resources[a.resource] += 1
        self.examples.setdefault(a.operation, a.action_id)
        if a.operation not in NON_MUTATING:
            self.largest_change = max(self.largest_change, a.scale)
            self.session_totals[a.session_id] += a.scale
        if a.irreversible:
            self.irreversible_used += 1

    def finish(self) -> IdentityReport:
        used = set(self.used_ops)
        unused_ops = sorted(self.ops - used)
        unused_targets = sorted(p for p in self.targets
                                if not any(pattern_covers(p, r) for r in self.used_resources))
        narrowing = {p: sorted(r for r in self.used_resources if pattern_covers(p, r))
                     for p in sorted(self.targets) if _is_wildcard(p)}
        narrowing = {p: rs for p, rs in narrowing.items() if rs}

        # The proposal only ever REMOVES: operations and resources that were
        # both granted and used within limits, and size limits no larger than
        # the grant.
        kept_ops = frozenset(op for op in used if op in self.ops)
        kept_targets = frozenset(r for r in self.used_resources if any(pattern_covers(p, r) for p in self.targets))
        changes = any(op not in NON_MUTATING for op in kept_ops)
        granted_scale = None if self.scale_unbounded else self.scale_max

        def limit(observed: int, granted: int | None) -> int | None:
            if not changes:
                return None if granted is None else min(granted, 1)
            proposal = _nice_ceiling(observed * SCALE_HEADROOM)
            return proposal if granted is None else min(proposal, granted)

        biggest_session = max(self.session_totals.values(), default=0)
        recommended = Scope(
            operations=kept_ops,
            targets=kept_targets,
            max_scale=limit(self.largest_change, granted_scale),
            irreversible_allowed=self.irreversible_granted and self.irreversible_used > 0,
            constraints=tuple(self.constraints),
            max_total=limit(biggest_session, None),
            checks=tuple(self.checks),
        )
        n = len(self.sessions)
        confidence = "none" if n == 0 else "low" if n < 5 else "medium" if n < 20 else "high"
        return IdentityReport(
            identity=self.identity, source=self.source, references=self.references,
            sessions=n, actions=self.actions, first_seen=self.first, last_seen=self.last,
            granted_operations=sorted(self.ops), used_operations=dict(sorted(self.used_ops.items())),
            unused_operations=unused_ops, granted_targets=sorted(self.targets),
            used_resources=dict(sorted(self.used_resources.items())), unused_targets=unused_targets,
            wildcard_narrowing=narrowing, granted_max_scale=granted_scale,
            largest_change=self.largest_change, irreversible_granted=self.irreversible_granted,
            irreversible_used=self.irreversible_used, violations=self.violations,
            used_outside_limits=dict(sorted(self.outside.items())), blocked_attempts=self.blocked,
            examples=dict(sorted(self.examples.items())), recommended=recommended, confidence=confidence,
        )


def _identity(w: Warrant, principal: str) -> str:
    """Agents are reported by name; a session's root grant is reported per person."""
    return f"{principal} (session root)" if w.parent_id is None else w.holder


def build_report(store: Store, since: datetime, until: datetime | None = None,
                 grants: Iterable[Grant] = ()) -> "ScopeCreepReport":
    """Compare grants with use for every session that started in [since, until]."""
    until = until or utcnow()
    tallies: dict[tuple[str, str], _Tally] = {}

    def tally(identity: str, source: str) -> _Tally:
        key = (identity, source)
        if key not in tallies:
            tallies[key] = _Tally(identity, source)
        return tallies[key]

    grants = list(grants)
    external: dict[str, list[Grant]] = {}
    for g in grants:
        # Every external grant is reported, even for an agent never seen at
        # all - a dormant identity with standing permissions is itself a finding.
        tally(g.identity, g.source).grant(g.scope, g.reference)
        external.setdefault(g.identity, []).append(g)

    for sess in store.sessions_since(since):
        if sess.started_at > until:
            continue
        observed = isinstance(sess.contract, dict) and bool(sess.contract.get("observed"))
        warrants = {w.warrant_id: w for w in store.warrants_for_session(sess.session_id)}
        actions = [a for a in store.actions_for_session(sess.session_id) if since <= a.at <= until]

        if not observed:
            # Observed chains carry empty, unsigned scopes: they grant nothing,
            # so only real warrants contribute grants.
            for w in warrants.values():
                tally(_identity(w, sess.principal), "warrants").grant(w.scope)
                tally(_identity(w, sess.principal), "warrants").sessions.add(sess.session_id)

        for a in actions:
            w = warrants.get(a.warrant_id)
            if not observed and w is not None:
                # Credit the agent that acted AND every hop above it, up to the
                # person. A delegating agent uses its permission by passing it
                # on: take the assistant's CRM access away and the CRM agent
                # below it can no longer receive any. Crediting only the actor
                # (as this once did) reported a pure delegator as using nothing,
                # and recommended removing access the chain depends on.
                credited: set[str] = set()
                hop: Warrant | None = w
                while hop is not None and hop.warrant_id not in credited:
                    credited.add(hop.warrant_id)
                    identity = _identity(hop, sess.principal)
                    if identity not in credited:          # an agent recursing into itself
                        credited.add(identity)
                        tally(identity, "warrants").use(a)
                    hop = warrants.get(hop.parent_id) if hop.parent_id else None
            for g in external.get(a.actor, []):
                tally(a.actor, g.source).use(a)

    identities = sorted((t.finish() for t in tallies.values()),
                        key=lambda r: (-r.unused_count, r.identity, r.source))
    return ScopeCreepReport(window_start=since, window_end=until, identities=identities)


@dataclass
class ScopeCreepReport:
    window_start: datetime
    window_end: datetime
    identities: list[IdentityReport]
    generated_at: datetime = field(default_factory=utcnow)

    @property
    def granted_permissions(self) -> int:
        return sum(r.granted_count for r in self.identities)

    @property
    def unused_permissions(self) -> int:
        return sum(r.unused_count for r in self.identities)

    def _window(self) -> str:
        days = max(1, round((self.window_end - self.window_start).total_seconds() / 86400))
        return (f"{self.window_start.date().isoformat()} to {self.window_end.date().isoformat()} "
                f"({days} day{'s' if days != 1 else ''})")

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_start": self.window_start.isoformat(), "window_end": self.window_end.isoformat(),
            "generated_at": self.generated_at.isoformat(), "caution": CAUTION,
            "granted_permissions": self.granted_permissions, "unused_permissions": self.unused_permissions,
            "identities": [r.to_dict() for r in self.identities],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    def to_markdown(self) -> str:
        share = self.unused_permissions / self.granted_permissions if self.granted_permissions else 0
        lines = [
            "# Scope-creep report",
            "",
            f"Window: {self._window()} - generated {self.generated_at.isoformat(timespec='seconds')}",
            "",
            f"**{self.unused_permissions} of {self.granted_permissions} granted permissions "
            f"({share:.0%}) were never used within their limits.**",
            "",
            f"> {CAUTION}",
            "",
            "| Identity | Granted by | Sessions | Actions | Unused operations | Unused targets | "
            "Size limit: granted / largest used / proposed | Confidence |",
            "|---|---|---|---|---|---|---|---|",
        ]
        for r in self.identities:
            granted = "unbounded" if r.granted_max_scale is None else r.granted_max_scale
            proposed = "-" if r.recommended.max_scale is None else r.recommended.max_scale
            lines.append(
                f"| {r.identity} | {r.source} | {r.sessions} | {r.actions} | "
                f"{', '.join(r.unused_operations) or '-'} | {', '.join(r.unused_targets) or '-'} | "
                f"{granted} / {r.largest_change} / {proposed} | {r.confidence} |")
        for r in self.identities:
            lines += ["", f"## {r.identity} - granted by {r.source}", ""]
            if r.references:
                lines.append(f"Reference: {', '.join(r.references)}")
            seen = (f"first {r.first_seen.isoformat(timespec='seconds')}, last {r.last_seen.isoformat(timespec='seconds')}"
                    if r.first_seen and r.last_seen else "never seen in this window")
            lines += [
                f"- Activity: {r.actions} actions in {r.sessions} sessions ({seen})",
                f"- Operations used within limits: {_counts(r.used_operations)}",
                f"- Operations never used within limits: {', '.join(r.unused_operations) or 'none'}",
                f"- Resources touched: {_counts(r.used_resources)}",
                f"- Targets never touched: {', '.join(r.unused_targets) or 'none'}",
            ]
            for pattern, used in r.wildcard_narrowing.items():
                lines.append(f"- Wildcard `{pattern}` was only used for: {', '.join(used)}")
            lines.append(f"- Irreversible actions: {'allowed' if r.irreversible_granted else 'not allowed'}, "
                         f"used {r.irreversible_used} time(s)")
            if r.violations or r.blocked_attempts:
                lines.append(f"- Outside the limits: {r.violations} change(s) that went ahead "
                             f"({_counts(r.used_outside_limits)}) and {r.blocked_attempts} blocked "
                             f"attempt(s). Neither counts as use.")
            if r.examples:
                lines.append("- Example actions: " + ", ".join(f"{op} `{aid}`" for op, aid in r.examples.items()))
            lines += ["", "Proposed scope:", "", "```json",
                      json.dumps(r.recommended.to_dict(), indent=2), "```"]
        return "\n".join(lines)

    def to_csv(self) -> str:
        """One row per unused permission - the list a security team works through."""
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(["identity", "granted_by", "reference", "kind", "permission", "sessions_observed",
                         "actions_observed", "window_start", "window_end", "confidence", "recommendation"])

        def row(r: IdentityReport, kind: str, permission: str, recommendation: str) -> None:
            writer.writerow([r.identity, r.source, "; ".join(r.references), kind, permission, r.sessions,
                             r.actions, self.window_start.isoformat(), self.window_end.isoformat(),
                             r.confidence, recommendation])

        for r in self.identities:
            for op in r.unused_operations:
                note = " - only used outside the limits" if op in r.used_outside_limits else ""
                row(r, "operation", op, "remove" + note)
            for target in r.unused_targets:
                row(r, "target", target, "remove")
            for pattern, used in r.wildcard_narrowing.items():
                row(r, "wildcard", pattern, "narrow to " + ", ".join(used))
            if r.irreversible_granted and not r.irreversible_used:
                row(r, "irreversible", "irreversible actions", "disallow")
            if r.recommended.max_scale is not None and (r.granted_max_scale is None
                                                        or r.recommended.max_scale < r.granted_max_scale):
                granted = "unbounded" if r.granted_max_scale is None else r.granted_max_scale
                row(r, "size limit", f"per action: {granted}", f"lower to {r.recommended.max_scale}")
        return out.getvalue()

    def to_html(self) -> str:
        """A standalone page in the same style as the web view, safe to email."""
        from .collector.web import _e, _page

        share = self.unused_permissions / self.granted_permissions if self.granted_permissions else 0
        rows = []
        for r in self.identities:
            granted = "unbounded" if r.granted_max_scale is None else r.granted_max_scale
            proposed = "-" if r.recommended.max_scale is None else r.recommended.max_scale
            rows.append(
                f"<tr><td><strong>{_e(r.identity)}</strong></td><td>{_e(r.source)}</td>"
                f"<td>{r.sessions}</td><td>{r.actions}</td>"
                f"<td class='fail'>{_e(', '.join(r.unused_operations) or '-')}</td>"
                f"<td class='fail'>{_e(', '.join(r.unused_targets) or '-')}</td>"
                f"<td class='mono'>{_e(granted)} / {r.largest_change} / {_e(proposed)}</td>"
                f"<td>{_e(r.confidence)}</td></tr>")
        details = []
        for r in self.identities:
            narrowing = "".join(f"<li>Wildcard <code>{_e(p)}</code> was only used for {_e(', '.join(u))}</li>"
                                for p, u in r.wildcard_narrowing.items())
            outside = (f"<li class='fail'>Outside the limits: {r.violations} change(s) that went ahead "
                       f"({_e(_counts(r.used_outside_limits))}), {r.blocked_attempts} blocked - not counted "
                       f"as use</li>" if r.violations or r.blocked_attempts else "")
            details.append(
                f"<div class='card'><h2>{_e(r.identity)} &middot; granted by {_e(r.source)}</h2><ul class='plain'>"
                f"<li>{r.actions} actions in {r.sessions} sessions</li>"
                f"<li>Operations used within limits: {_e(_counts(r.used_operations))}</li>"
                f"<li>Resources touched: {_e(_counts(r.used_resources))}</li>{narrowing}{outside}"
                f"<li>Irreversible actions used {r.irreversible_used} time(s)</li></ul>"
                f"<p class='muted'>Proposed scope</p><pre class='mono'>"
                f"{_e(json.dumps(r.recommended.to_dict(), indent=2))}</pre></div>")
        body = (
            "<h1>Scope-creep report</h1>"
            f"<p class='muted'>Window: {_e(self._window())}</p>"
            f"<div class='card'><p><strong>{self.unused_permissions} of {self.granted_permissions} granted "
            f"permissions ({share:.0%}) were never used within their limits.</strong></p>"
            f"<p class='unk'>{_e(CAUTION)}</p></div>"
            "<div class='card table-wrap'><table><thead><tr><th>Identity</th><th>Granted by</th>"
            "<th>Sessions</th><th>Actions</th><th>Unused operations</th><th>Unused targets</th>"
            "<th>Size: granted / used / proposed</th><th>Confidence</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>{''.join(details)}"
        )
        return _page("Segurai - scope-creep report", body)


def _counts(counter: dict[str, int]) -> str:
    return ", ".join(f"{name} ({n})" for name, n in counter.items()) or "none"
