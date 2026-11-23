"""Organisation-wide rules that no warrant can override.

A warrant says what one request was granted. A policy says what nobody is
ever granted, whatever a request or a person's permissions say:

    [[policy.rules]]
    name       = "support agents never delete"
    agents     = ["support_*"]                 # any hop in the chain
    operations = ["delete", "export"]
    effect     = "deny"
    reason     = "Support work never needs to remove or export records."

    [[policy.rules]]
    name        = "billing changes stay small"
    targets     = ["billing.*"]
    effect      = "limit"
    max_scale   = 20
    irreversible = false                       # nothing that can't be undone

    [[policy.rules]]
    name              = "permanent CRM changes need a second person"
    targets           = ["crm.*"]
    effect            = "approve"
    only_irreversible = true                   # only what can't be undone...
    above_scale       = 100                    # ...and only above 100 records (both must hold)
    approvers         = ["*@acme.example"]     # who may decide; empty = any dashboard admin
    reason            = "A big permanent change is a decision for a person."

Deny and approve rules can also depend on what the action reports about
itself - its evidence, such as a refund's amount:

    [[policy.rules]]
    name       = "refunds over $50 need a person"
    operations = ["refund"]
    effect     = "approve"
    when_above = { amount_cents = 5000 }      # applies only above this

``when_below`` is the other way round - "never archive deals active in the
last 180 days" is a deny rule with ``when_below = { days_since_activity =
180 }``. For a list of values (one per record), the rule applies if ANY
record crosses the line. When the evidence is missing or isn't a number,
the rule applies: a rule about large amounts can't be dodged by not saying
the amount.

Rules only ever TAKE AWAY. A rule can deny an action, cap it, or hold it for
a person's approval; there is no "allow" rule, so a policy can never widen
what a warrant granted. That keeps the two easy to reason about together: an
action must fit its warrant AND every rule.

An "approve" rule is a step-up: the action is not refused, it waits. Only
the gateway can hold a request (approvals.py) - it has the request, and the
credential to send it later. Everywhere else an approval rule simply counts
as broken, because there is nobody to ask: the safe reading of "needs a
person's yes" when no person can be asked is "no".

Where rules are checked:
  * the runtime, on every ``act()`` and guarded tool call (a finding with
    ``check="policy"``, blocked in enforce mode like any other violation);
  * the gateway, before a request is forwarded (always enforced);
  * the issuer, which refuses to mint a root that a rule makes pointless.

Every policy has a version - a hash of its rules - recorded in the
tamper-evident log, and each finding names the version it came from. So an
audit can say not just "this broke a rule" but exactly which rules were in
force at the time.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any, Iterable, Mapping

from .models import NON_MUTATING, Finding, pattern_covers

__all__ = ["Rule", "Policy", "PolicyError", "EFFECTS"]

#: What a rule can do. Deliberately no "allow".
EFFECTS = ("deny", "limit", "approve")


class PolicyError(ValueError):
    """A rule that cannot be understood. Raised at load time, never at action time."""


def _strings(value: Any, field_name: str, rule: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str) or not isinstance(value, Iterable):
        raise PolicyError(f"rule {rule!r}: {field_name} must be a list of strings")
    items = tuple(value)
    if not all(isinstance(v, str) and v for v in items):
        raise PolicyError(f"rule {rule!r}: {field_name} must be a list of non-empty strings")
    return items


def _target_overlaps(resource: str, pattern: str) -> bool:
    """Could ``resource`` (itself possibly a pattern) touch anything ``pattern`` names?

    For a rule that takes power away, the cautious answer is the right one:
    an action reported against "crm.*" overlaps a rule about "crm.accounts",
    and one against "*" overlaps every rule.
    """
    if fnmatchcase(resource, pattern):
        return True
    if any(c in resource for c in "*?["):
        return (pattern_covers(resource, pattern) or pattern_covers(pattern, resource)
                or fnmatchcase(pattern, resource))
    return False


@dataclass(frozen=True)
class Rule:
    """One organisation rule. Empty selectors mean "any"."""

    name: str
    effect: str
    agents: tuple[str, ...] = ()        # glob patterns; matched against EVERY hop's holder
    principals: tuple[str, ...] = ()    # glob patterns; matched against the person, case-insensitively
    operations: tuple[str, ...] = ()    # glob patterns
    targets: tuple[str, ...] = ()       # glob patterns over resource names
    max_scale: int | None = None        # limit: records one changing action may touch
    irreversible: bool | None = None    # limit: False forbids anything irreversible
    reason: str = ""
    # approve rules only: when the rule applies, and who may say yes.
    above_scale: int | None = None      # only changes touching more than this many records
    only_irreversible: bool = False     # only actions that can't be undone
    approvers: tuple[str, ...] = ()     # glob patterns over dashboard emails; empty = any admin
    allow_requester: bool = False       # may the person who asked approve it themselves?
    # deny and approve rules: apply only when these evidence fields are above these numbers.
    when_above: tuple[tuple[str, float], ...] = ()
    when_below: tuple[tuple[str, float], ...] = ()

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise PolicyError("every rule needs a name")
        if self.effect not in EFFECTS:
            raise PolicyError(f"rule {self.name!r}: effect must be one of {EFFECTS}, got {self.effect!r}")
        if self.effect == "limit" and self.max_scale is None and self.irreversible is None:
            raise PolicyError(f"rule {self.name!r}: a limit rule needs max_scale or irreversible = false")
        if self.effect != "limit" and (self.max_scale is not None or self.irreversible is not None):
            raise PolicyError(f"rule {self.name!r}: max_scale and irreversible belong to limit rules")
        if self.effect != "approve" and (self.above_scale is not None or self.only_irreversible
                                         or self.approvers or self.allow_requester):
            raise PolicyError(f"rule {self.name!r}: above_scale, only_irreversible, approvers and "
                              f"allow_requester belong to approve rules")
        if (self.when_above or self.when_below) and self.effect == "limit":
            raise PolicyError(f"rule {self.name!r}: when_above and when_below belong to deny and approve rules")
        for name, threshold in (*self.when_above, *self.when_below):
            if not name or isinstance(threshold, bool) or not isinstance(threshold, (int, float)):
                raise PolicyError(f"rule {self.name!r}: when_above and when_below need field = number pairs")
        if self.above_scale is not None and (isinstance(self.above_scale, bool)
                                             or not isinstance(self.above_scale, int) or self.above_scale < 0):
            raise PolicyError(f"rule {self.name!r}: above_scale must be a whole number, zero or more")
        if self.max_scale is not None and (isinstance(self.max_scale, bool) or not isinstance(self.max_scale, int)
                                           or self.max_scale < 0):
            raise PolicyError(f"rule {self.name!r}: max_scale must be a whole number, zero or more")
        if self.irreversible is True:
            raise PolicyError(f"rule {self.name!r}: irreversible = true would grant something; "
                              f"rules only take away (use false, or leave it out)")

    # ---- matching ---------------------------------------------------------

    def applies(self, operation: str, resource: str, principal: str, holders: Iterable[str]) -> bool:
        if self.operations and not any(fnmatchcase(operation, p) for p in self.operations):
            return False
        if self.targets and not any(_target_overlaps(resource, p) for p in self.targets):
            return False
        if self.principals and not any(fnmatchcase(principal.lower(), p.lower()) for p in self.principals):
            return False
        if self.agents and not any(fnmatchcase(h, p) for h in holders for p in self.agents):
            return False
        return True

    def crosses(self, evidence: Mapping[str, Any] | None) -> bool:
        """Does the evidence cross every when_above / when_below line? Missing or unreadable counts as crossing."""
        def numbers(name: str) -> list[float] | None:
            value = (evidence or {}).get(name)
            values = value if isinstance(value, (list, tuple)) else [value]
            found = [v for v in values if isinstance(v, (int, float)) and not isinstance(v, bool)]
            return found if found and len(found) == len(values) else None

        for name, threshold in self.when_above:
            found = numbers(name)
            if found is not None and max(found) <= threshold:
                return False
        for name, threshold in self.when_below:
            found = numbers(name)
            if found is not None and min(found) >= threshold:
                return False
        return True

    def evaluate(self, operation: str, resource: str, scale: int, irreversible: bool,
                 principal: str, holders: Iterable[str], version: str,
                 evidence: Mapping[str, Any] | None = None) -> Finding | None:
        """None when the action is fine under this rule; otherwise a failing finding."""
        holders = tuple(holders)
        if not self.applies(operation, resource, principal, holders):
            return None
        if (self.when_above or self.when_below) and not self.crosses(evidence):
            return None
        why = f" - {self.reason}" if self.reason else ""
        clause = f"policy {version}: {self.name}"
        if self.effect == "deny":
            return Finding("policy", "fail", f"organisation rule {self.name!r} forbids this{why}", clause)
        if self.effect == "approve":
            if self.only_irreversible and not irreversible:
                return None
            if self.above_scale is not None and (operation in NON_MUTATING or scale <= self.above_scale):
                return None
            # "fail" until a person says yes: anything that doesn't know about
            # approvals treats it as broken, which is the safe default.
            return Finding("approval", "fail",
                           f"organisation rule {self.name!r} needs a person to approve this first{why}",
                           clause)
        if (self.max_scale is not None and operation not in NON_MUTATING and scale > self.max_scale):
            return Finding("policy", "fail",
                           f"organisation rule {self.name!r} caps changes at {self.max_scale}, "
                           f"this changes {scale}{why}", clause)
        if self.irreversible is False and irreversible:
            return Finding("policy", "fail",
                           f"organisation rule {self.name!r} forbids irreversible actions{why}", clause)
        return None

    # ---- serialization ------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"name": self.name, "effect": self.effect}
        for key in ("agents", "principals", "operations", "targets"):
            if getattr(self, key):
                d[key] = list(getattr(self, key))
        if self.max_scale is not None:
            d["max_scale"] = self.max_scale
        if self.irreversible is not None:
            d["irreversible"] = self.irreversible
        if self.reason:
            d["reason"] = self.reason
        if self.above_scale is not None:
            d["above_scale"] = self.above_scale
        if self.only_irreversible:
            d["only_irreversible"] = True
        if self.approvers:
            d["approvers"] = list(self.approvers)
        if self.allow_requester:
            d["allow_requester"] = True
        if self.when_above:
            d["when_above"] = dict(self.when_above)
        if self.when_below:
            d["when_below"] = dict(self.when_below)
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Rule":
        known = {"name", "effect", "agents", "principals", "operations", "targets",
                 "max_scale", "irreversible", "reason",
                 "above_scale", "only_irreversible", "approvers", "allow_requester", "when_above",
                 "when_below"}
        name = str(d.get("name") or "")
        unknown = sorted(set(d) - known)
        if unknown:
            raise PolicyError(f"rule {name or '(unnamed)'!r}: unknown setting(s) {unknown}; "
                              f"expected some of {sorted(known)}")
        irreversible = d.get("irreversible")
        if irreversible is not None and not isinstance(irreversible, bool):
            raise PolicyError(f"rule {name!r}: irreversible must be true or false")
        reason = d.get("reason", "")
        if not isinstance(reason, str):
            raise PolicyError(f"rule {name!r}: reason must be text")
        for flag in ("only_irreversible", "allow_requester"):
            if not isinstance(d.get(flag, False), bool):
                raise PolicyError(f"rule {name!r}: {flag} must be true or false")
        when_above, when_below = d.get("when_above") or {}, d.get("when_below") or {}
        if not isinstance(when_above, Mapping) or not isinstance(when_below, Mapping):
            raise PolicyError(f"rule {name!r}: when_above and when_below must be tables of field = number")
        return Rule(
            name=name, effect=str(d.get("effect") or ""),
            agents=_strings(d.get("agents"), "agents", name),
            principals=_strings(d.get("principals"), "principals", name),
            operations=_strings(d.get("operations"), "operations", name),
            targets=_strings(d.get("targets"), "targets", name),
            max_scale=d.get("max_scale"), irreversible=irreversible, reason=reason,
            above_scale=d.get("above_scale"), only_irreversible=d.get("only_irreversible", False),
            approvers=_strings(d.get("approvers"), "approvers", name),
            allow_requester=d.get("allow_requester", False),
            when_above=tuple(sorted((str(k), v) for k, v in when_above.items())),
            when_below=tuple(sorted((str(k), v) for k, v in when_below.items())),
        )


@dataclass(frozen=True)
class Policy:
    """A set of rules. The empty policy changes nothing."""

    rules: tuple[Rule, ...] = ()
    _version: str = field(default="", compare=False, repr=False)

    def __post_init__(self) -> None:
        names = [r.name for r in self.rules]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise PolicyError(f"rule names must be unique; repeated: {duplicates}")
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        object.__setattr__(self, "_version", "pol_" + hashlib.sha256(canonical.encode()).hexdigest()[:12])

    @property
    def version(self) -> str:
        """A short hash of the rules: two policies with the same rules share it."""
        return self._version

    def __bool__(self) -> bool:
        return bool(self.rules)

    def rule(self, name: str) -> Rule | None:
        """The rule called ``name``, or None."""
        return next((r for r in self.rules if r.name == name), None)

    def evaluate(self, operation: str, resource: str, scale: int = 1, irreversible: bool = False,
                 principal: str = "", holders: Iterable[str] = (),
                 evidence: Mapping[str, Any] | None = None) -> list[Finding]:
        """Every rule this action breaks (empty when none).

        An approve rule that applies shows up as a failing finding with
        ``check="approval"``: broken until a person says yes.
        """
        holders = tuple(holders)
        findings = []
        for rule in self.rules:
            finding = rule.evaluate(operation, resource, scale, irreversible, principal, holders,
                                    self.version, evidence)
            if finding is not None:
                findings.append(finding)
        return findings

    def to_dict(self) -> dict[str, Any]:
        return {"rules": [r.to_dict() for r in self.rules]}

    @staticmethod
    def from_dict(d: Mapping[str, Any] | None) -> "Policy":
        if not d:
            return Policy()
        unknown = sorted(set(d) - {"rules"})
        if unknown:
            raise PolicyError(f"policy: unknown setting(s) {unknown}; expected 'rules'")
        rules = d.get("rules") or []
        if not isinstance(rules, list) or not all(isinstance(r, Mapping) for r in rules):
            raise PolicyError("policy.rules must be a list of tables ([[policy.rules]])")
        return Policy(tuple(Rule.from_dict(r) for r in rules))
