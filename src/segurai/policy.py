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

Rules only ever TAKE AWAY. A rule can deny an action or cap it; there is no
"allow" rule, so a policy can never widen what a warrant granted. That keeps
the two easy to reason about together: an action must fit its warrant AND
every rule.

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
EFFECTS = ("deny", "limit")


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

    def __post_init__(self) -> None:
        if not self.name or not isinstance(self.name, str):
            raise PolicyError("every rule needs a name")
        if self.effect not in EFFECTS:
            raise PolicyError(f"rule {self.name!r}: effect must be one of {EFFECTS}, got {self.effect!r}")
        if self.effect == "limit" and self.max_scale is None and self.irreversible is None:
            raise PolicyError(f"rule {self.name!r}: a limit rule needs max_scale or irreversible = false")
        if self.effect == "deny" and (self.max_scale is not None or self.irreversible is not None):
            raise PolicyError(f"rule {self.name!r}: max_scale and irreversible belong to limit rules")
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

    def evaluate(self, operation: str, resource: str, scale: int, irreversible: bool,
                 principal: str, holders: Iterable[str], version: str) -> Finding | None:
        """None when the action is fine under this rule; otherwise a failing finding."""
        holders = tuple(holders)
        if not self.applies(operation, resource, principal, holders):
            return None
        why = f" - {self.reason}" if self.reason else ""
        clause = f"policy {version}: {self.name}"
        if self.effect == "deny":
            return Finding("policy", "fail", f"organisation rule {self.name!r} forbids this{why}", clause)
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
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Rule":
        known = {"name", "effect", "agents", "principals", "operations", "targets",
                 "max_scale", "irreversible", "reason"}
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
        return Rule(
            name=name, effect=str(d.get("effect") or ""),
            agents=_strings(d.get("agents"), "agents", name),
            principals=_strings(d.get("principals"), "principals", name),
            operations=_strings(d.get("operations"), "operations", name),
            targets=_strings(d.get("targets"), "targets", name),
            max_scale=d.get("max_scale"), irreversible=irreversible, reason=reason,
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

    def evaluate(self, operation: str, resource: str, scale: int = 1, irreversible: bool = False,
                 principal: str = "", holders: Iterable[str] = ()) -> list[Finding]:
        """Every rule this action breaks (empty when none)."""
        holders = tuple(holders)
        findings = []
        for rule in self.rules:
            finding = rule.evaluate(operation, resource, scale, irreversible, principal, holders,
                                    self.version)
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
