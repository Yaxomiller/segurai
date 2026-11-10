"""OpenAI Agents SDK integration: every tool call checked before it runs.

    from agents import Agent, Runner
    from segurai.instrument.openai_agents import govern

    crm_agent = govern(Agent(name="crm_agent", tools=[delete_records, find_stale]), rules={
        "delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True),
    })
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=granted):
        await Runner.run(crm_agent, "clean up our old sales records")

``govern`` adds a tool input guardrail - the SDK's own hook for vetting a
call before the tool runs - to every function tool of the agent and of every
agent it can hand off to. Each call is then:

  * recorded under a warrant for the agent making it (one hop per agent,
    delegated from the warrant in force when the run started), so the chain
    reads person -> agent -> action exactly as it did elsewhere;
  * checked against that warrant and the organisation's rules;
  * in ENFORCE mode, refused when it breaks anything: the tool never runs and
    the model is told why ("Refused by Segurai: ..."), so it can tell the
    person or try something within bounds, instead of the run crashing.

Tools without a rule are recorded as operation "call" on resource
``tool.<name>``, so a scope can grant them explicitly. Give important tools a
rule: a rule is what lets Segurai see WHAT a call touches and how much.

Tested against openai-agents 0.24, with a scripted model standing in for a real one.
"""

from __future__ import annotations

import json
import threading
from typing import Any, Mapping

try:
    from agents import (
        Agent,
        FunctionTool,
        ToolGuardrailFunctionOutput,
        ToolInputGuardrail,
    )
except ImportError as exc:  # pragma: no cover - only without the optional package
    raise ImportError("segurai.instrument.openai_agents needs: pip install openai-agents") from exc

from ..actions import ActionSpec
from ..context import bind_warrant, current_warrant
from ..models import Warrant
from ..runtime import ViolationError, _rt, check_tool_call

__all__ = ["govern", "GUARDRAIL_NAME"]

GUARDRAIL_NAME = "segurai"
_hops: dict[tuple[str, str], Warrant] = {}
_hops_lock = threading.Lock()


def _hop(parent: Warrant, agent_name: str) -> Warrant:
    """One delegated warrant per (warrant in force, agent): the agent's hop in the chain."""
    if parent.holder == agent_name:
        return parent
    key = (parent.warrant_id, agent_name)
    with _hops_lock:
        child = _hops.get(key)
        if child is None or child.is_expired():
            store, authority = _rt.ensure()
            child = authority.attenuate(parent, holder=agent_name)
            store.put_warrant(child)
            if len(_hops) > 10_000:
                _hops.clear()
            _hops[key] = child
        return child


def _guardrail(rules: Mapping[str, ActionSpec]) -> ToolInputGuardrail:
    def check(data: Any) -> ToolGuardrailFunctionOutput:
        context = data.context
        name = context.tool_name
        try:
            arguments = json.loads(context.tool_arguments or "{}")
            if not isinstance(arguments, dict):
                arguments = {"value": arguments}
        except ValueError:
            arguments = {}
        spec = rules.get(name) or ActionSpec("call", f"tool.{name}")
        warrant = _hop(current_warrant(), data.agent.name)
        try:
            with bind_warrant(warrant):
                record = check_tool_call(name, spec, arguments, tool_call_id=context.tool_call_id,
                                         framework="openai-agents")
        except ViolationError as refused:
            return ToolGuardrailFunctionOutput.reject_content(
                message=f"Refused by Segurai: {refused.record.violation}. This call was not made.",
                output_info={"action_id": refused.record.action_id})
        return ToolGuardrailFunctionOutput.allow(output_info={"action_id": record.action_id})

    return ToolInputGuardrail(guardrail_function=check, name=GUARDRAIL_NAME)


def govern(agent: Agent, rules: Mapping[str, ActionSpec] | None = None) -> Agent:
    """Check every tool call of ``agent`` and of every agent it can hand off to. Returns ``agent``.

    Safe to call twice: a tool already governed is left as it is.
    """
    guardrail = _guardrail(dict(rules or {}))
    seen: set[int] = set()

    def visit(a: Any) -> None:
        if id(a) in seen or not isinstance(a, Agent):
            return
        seen.add(id(a))
        for tool in a.tools:
            if isinstance(tool, FunctionTool):
                existing = list(tool.tool_input_guardrails or [])
                if not any(getattr(g, "name", None) == GUARDRAIL_NAME for g in existing):
                    tool.tool_input_guardrails = [guardrail, *existing]
        for handoff in a.handoffs:
            visit(getattr(handoff, "agent", handoff))

    visit(agent)
    return agent
