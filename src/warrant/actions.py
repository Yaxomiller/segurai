"""Describing a tool call as an action.

A tool call arrives as a name plus arguments:

    delete_records(table="opportunities", ids=[... 400 ids ...])

The admission check needs four facts about it instead:

    operation     "delete"
    resource      "crm.opportunities"
    scale         400          (how many records it changes)
    irreversible  True

An ActionSpec is the small recipe that turns the first into the second. Each
field is either a fixed value or a rule computed from the call's arguments:

    ActionSpec(
        operation="delete",
        resource="crm.{table}",      # filled in from the 'table' argument
        scale=count("ids"),          # len(arguments["ids"])
        irreversible=True,
    )

The same ActionSpec type is used everywhere a tool call is intercepted - the
@warrant.tool decorator, the LangGraph ToolGuard and the MCP client - so a
team describes each tool once and it is judged the same way everywhere.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping

__all__ = ["ActionSpec", "ResolvedAction", "ActionSpecError", "count", "arg"]

#: A rule is any function that takes the call's arguments (a name -> value
#: mapping) and returns the field's value.
ArgRule = Callable[[Mapping[str, Any]], Any]

_MISSING = object()


class ActionSpecError(ValueError):
    """A tool call could not be turned into an action - e.g. a missing argument."""


@dataclass(frozen=True)
class ResolvedAction:
    """The four facts about one concrete call, after the spec was applied."""

    operation: str
    resource: str
    scale: int
    irreversible: bool


def count(name: str) -> ArgRule:
    """Scale rule: the number of items in argument ``name`` (a list of ids, rows...)."""

    def rule(arguments: Mapping[str, Any]) -> int:
        return len(arguments[name])

    rule.__name__ = f"count({name!r})"
    return rule


def arg(name: str, default: Any = _MISSING) -> ArgRule:
    """Rule that uses an argument's value as-is, e.g. ``scale=arg("limit", 1)``."""

    def rule(arguments: Mapping[str, Any]) -> Any:
        if name in arguments:
            return arguments[name]
        if default is _MISSING:
            raise KeyError(name)
        return default

    rule.__name__ = f"arg({name!r})"
    return rule


@dataclass(frozen=True)
class ActionSpec:
    """How to read operation, resource, scale and irreversibility off a tool call.

    Each field accepts:
      * a fixed value                        operation="delete"
      * a template filled from arguments     resource="crm.{table}"
      * a function of the arguments          scale=count("ids")

    Use ``{{`` and ``}}`` in a template for literal braces.
    """

    operation: str | ArgRule
    resource: str | ArgRule
    scale: int | ArgRule = 1
    irreversible: bool | ArgRule = False

    def resolve(self, arguments: Mapping[str, Any]) -> ResolvedAction:
        """Apply the spec to one call's arguments.

        Raises :class:`ActionSpecError` when the call cannot be described -
        a missing argument, a template that does not fit, or a value of the
        wrong type. Callers treat that as a violation: an action nobody can
        describe is not an action anybody authorized.
        """
        try:
            operation = _apply(self.operation, arguments)
            resource = _apply(self.resource, arguments)
            scale = _apply(self.scale, arguments)
            irreversible = _apply(self.irreversible, arguments)
        except Exception as exc:
            raise ActionSpecError(
                f"could not map tool call to an action: {type(exc).__name__}: {exc}"
            ) from exc

        if not isinstance(operation, str) or not operation:
            raise ActionSpecError(f"operation must be a non-empty string, got {operation!r}")
        if not isinstance(resource, str) or not resource:
            raise ActionSpecError(f"resource must be a non-empty string, got {resource!r}")
        # bool is a subclass of int in Python, so rule it out explicitly.
        if isinstance(scale, bool) or not isinstance(scale, int) or scale < 0:
            raise ActionSpecError(f"scale must be a whole number of zero or more, got {scale!r}")
        return ResolvedAction(operation, resource, scale, bool(irreversible))


def _apply(rule: Any, arguments: Mapping[str, Any]) -> Any:
    """Evaluate one spec field against the arguments."""
    if callable(rule):
        return rule(arguments)
    if isinstance(rule, str) and "{" in rule:
        return rule.format_map(arguments)
    return rule
