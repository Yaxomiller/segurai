"""CrewAI integration: every tool call checked before it runs.

    import segurai
    from segurai.actions import ActionSpec, count
    from segurai.instrument.crewai import govern

    govern(rules={                                   # once, at start-up
        "delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True),
    })
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=granted):
        crew.kickoff()

``govern`` registers a hook with CrewAI that runs before any agent in the
process uses a tool. Each call is then:

  * recorded under a warrant for the agent making it (one hop per agent role,
    delegated from the warrant in force - the session's), so the chain reads
    person -> agent -> action. CrewAI copies context into the threads it runs
    tasks on, so asynchronous tasks inherit the session too;
  * checked against that warrant and the organisation's rules;
  * in ENFORCE mode, refused when it breaks anything: the tool never runs and
    the agent is told why ("Refused by Segurai: ..."), so it can tell the
    person or try something within bounds, instead of the crew crashing.

Two cases need care, because CrewAI lets a call through when a hook fails:

  * A call made outside any Segurai session has nothing to be checked
    against. In ENFORCE mode it is refused; in OBSERVE mode it goes ahead
    unrecorded and a warning is logged.
  * If checking a call fails unexpectedly, ENFORCE mode refuses the call and
    OBSERVE mode lets it through. Both log the error. A guard that fails
    open in enforce mode would be no guard.

Rules are looked up by the tool's name as written ("Delete records") or as
CrewAI normalises it ("delete_records"). A tool without a rule is recorded as
operation "call" on resource ``tool.<normalised name>``, so a scope can grant
it explicitly. Give important tools a rule: a rule is what lets Segurai see
WHAT a call touches and how much.

Tested against crewai 1.15, with a scripted model standing in for a real one.
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Mapping

try:
    from crewai.hooks import (
        register_after_tool_call_hook,
        register_before_tool_call_hook,
        unregister_after_tool_call_hook,
        unregister_before_tool_call_hook,
    )
except ImportError as exc:  # pragma: no cover - only without the optional package
    raise ImportError("segurai.instrument.crewai needs: pip install crewai") from exc

from ..actions import ActionSpec
from ..context import bind_warrant, current_warrant
from ..runtime import Mode, ViolationError, _rt, check_tool_call
from ._hops import hop

__all__ = ["govern", "ungovern", "REFUSED"]

_log = logging.getLogger("segurai.crewai")

REFUSED = "Refused by Segurai"
_BLOCKED_BY_HOOK = "Tool execution blocked by hook"    # what CrewAI tells the agent by default

_installed: tuple[Any, Any] | None = None
_install_lock = threading.Lock()

# Why a call was refused, from the before-hook to the after-hook that replaces
# CrewAI's generic message. Keyed by the call's arguments dict, which CrewAI
# passes to both; a dict rather than a context variable so it works whichever
# thread or task each hook runs on.
_reasons: dict[int, str] = {}
_reasons_lock = threading.Lock()


def _refuse(arguments: Any, message: str) -> bool:
    with _reasons_lock:
        if len(_reasons) > 1000:          # after-hooks that never ran: don't grow forever
            _reasons.clear()
        _reasons[id(arguments)] = message
    return False                          # CrewAI's signal to block the call


def _before(rules: Mapping[str, ActionSpec]):
    def before_tool_call(context: Any) -> bool | None:
        name = str(getattr(context, "tool_name", "") or "unknown")
        arguments = context.tool_input if isinstance(context.tool_input, dict) else {}
        enforcing = _rt.mode is Mode.ENFORCE
        parent = current_warrant(required=False)
        if parent is None:
            if enforcing:
                return _refuse(context.tool_input, f"{REFUSED}: no Segurai session is active, so this call "
                                                   f"cannot be checked. This call was not made.")
            _log.warning("CrewAI tool %r ran outside any Segurai session, so it was not recorded", name)
            return None
        try:
            tool = getattr(context, "tool", None)
            spec = rules.get(str(getattr(tool, "name", ""))) or rules.get(name) or ActionSpec("call", f"tool.{name}")
            agent = getattr(getattr(context, "agent", None), "role", None) or "crewai_agent"
            with bind_warrant(hop(parent, str(agent))):
                check_tool_call(name, spec, dict(arguments), framework="crewai")
        except ViolationError as refused:
            return _refuse(context.tool_input, f"{REFUSED}: {refused.record.violation}. This call was not made.")
        except Exception as exc:                                          # noqa: BLE001 - see the module notes
            _log.exception("Segurai could not check CrewAI tool %r", name)
            if enforcing:
                return _refuse(context.tool_input, f"{REFUSED}: the call could not be checked ({exc}). "
                                                   f"This call was not made.")
        return None

    return before_tool_call


def _after_tool_call(context: Any) -> str | None:
    """Tell the agent why Segurai refused, instead of CrewAI's generic "blocked" message."""
    with _reasons_lock:
        reason = _reasons.pop(id(context.tool_input), None)
    if reason and str(context.tool_result or "").startswith(_BLOCKED_BY_HOOK):
        return reason
    return None


def govern(rules: Mapping[str, ActionSpec] | None = None) -> None:
    """Check every CrewAI tool call in this process from now on.

    Calling it again replaces the rules; it never registers the hooks twice.
    """
    global _installed
    with _install_lock:
        _remove_locked()
        before = _before(dict(rules or {}))
        register_before_tool_call_hook(before)
        register_after_tool_call_hook(_after_tool_call)
        _installed = (before, _after_tool_call)


def ungovern() -> None:
    """Stop checking CrewAI tool calls."""
    with _install_lock:
        _remove_locked()


def _remove_locked() -> None:
    global _installed
    if _installed is not None:
        before, after = _installed
        unregister_before_tool_call_hook(before)
        unregister_after_tool_call_hook(after)
        _installed = None
