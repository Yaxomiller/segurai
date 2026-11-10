"""OpenAI Agents SDK: tool calls checked before they run, through the real SDK loop.

A scripted model stands in for OpenAI: it asks for the tool calls each test
needs, then answers. Everything else - the runner, the guardrails, the tools -
is the real openai-agents package.
"""

import asyncio
import json

import pytest

agents = pytest.importorskip("agents")
from agents import Agent, ModelSettings, Runner, function_tool  # noqa: E402
from agents.items import ModelResponse  # noqa: E402
from agents.models.interface import Model  # noqa: E402
from agents.usage import Usage  # noqa: E402
from openai.types.responses import (  # noqa: E402
    ResponseFunctionToolCall,
    ResponseOutputMessage,
    ResponseOutputText,
)

import segurai  # noqa: E402
from segurai import ActionSpec, Scope, count  # noqa: E402
from segurai.instrument.openai_agents import govern  # noqa: E402

GRANTED = Scope.of(operations=["search", "archive", "call"], targets=["crm.*", "tool.*"], max_scale=50)
RULES = {
    "archive_deals": ActionSpec("archive", "crm.opportunities", scale=count("ids")),
    "delete_deals": ActionSpec("delete", "crm.opportunities", scale=count("ids"), irreversible=True),
}


class Scripted(Model):
    """Asks for each tool call in turn, then gives a final answer. Records what the tools returned."""

    def __init__(self, calls):
        self.calls, self.seen = list(calls), []

    async def get_response(self, system_instructions, input, model_settings, tools, output_schema,
                           handoffs, tracing, *, previous_response_id=None, conversation_id=None, prompt=None):
        if isinstance(input, list):
            self.seen += [i.get("output") for i in input if isinstance(i, dict) and i.get("type") ==
                          "function_call_output"]
        if self.calls:
            name, args = self.calls.pop(0)
            item = ResponseFunctionToolCall(type="function_call", id=f"fc_{name}", call_id=f"call_{name}",
                                            name=name, arguments=json.dumps(args), status="completed")
        else:
            item = ResponseOutputMessage(type="message", id="msg", role="assistant", status="completed",
                                         content=[ResponseOutputText(type="output_text", text="done",
                                                                     annotations=[])])
        return ModelResponse(output=[item], usage=Usage(), response_id=None)

    def stream_response(self, *args, **kwargs):  # pragma: no cover - not used
        raise NotImplementedError


ran = []


@function_tool
def archive_deals(ids: list[int]) -> str:
    """Archive deals by id."""
    ran.append(("archive", len(ids)))
    return f"archived {len(ids)}"


@function_tool
def delete_deals(ids: list[int]) -> str:
    """Permanently delete deals by id."""
    ran.append(("delete", len(ids)))
    return f"deleted {len(ids)}"


@function_tool
def find_stale() -> str:
    """Find stale deals."""
    ran.append(("find", 0))
    return "[1, 2, 3]"


def _agent(model):
    return govern(Agent(name="crm_agent", model=model, model_settings=ModelSettings(),
                        tools=[archive_deals, delete_deals, find_stale]), rules=RULES)


def _run(model, mode=segurai.Mode.OBSERVE):
    ran.clear()
    segurai.configure(mode=mode)
    with segurai.session(principal="sarah@acme.example", request="tidy stale deals", scope=GRANTED) as s:
        asyncio.run(Runner.run(_agent(model), "tidy stale deals"))
    return s


def test_every_tool_call_is_recorded_under_the_agents_own_hop():
    s = _run(Scripted([("find_stale", {}), ("archive_deals", {"ids": [1, 2, 3]})]))
    records = s.actions()
    assert [(r.actor, r.operation, r.resource, r.scale) for r in records] == [
        ("crm_agent", "call", "tool.find_stale", 1), ("crm_agent", "archive", "crm.opportunities", 3)]
    assert all(r.allowed for r in records) and ran == [("find", 0), ("archive", 3)]
    assert [w.holder for w in s.chain()] == ["entrypoint", "crm_agent"]       # one hop, reused
    assert records[1].detail["framework"] == "openai-agents"
    assert segurai.verify_session(s.session_id) == []


def test_enforce_mode_refuses_the_call_and_tells_the_model_why():
    model = Scripted([("delete_deals", {"ids": list(range(400))})])
    s = _run(model, mode=segurai.Mode.ENFORCE)
    assert ran == []                                                            # the tool never ran
    (record,) = s.actions()
    assert record.blocked and "operation 'delete' not in scope" in record.violation
    assert any("Refused by Segurai" in str(out) for out in model.seen)


def test_observe_mode_records_the_violation_and_lets_the_call_through():
    s = _run(Scripted([("archive_deals", {"ids": list(range(80))})]))
    (record,) = s.actions()
    assert not record.allowed and not record.blocked and "scale 80 exceeds limit 50" in record.violation
    assert ran == [("archive", 80)]


def test_governing_twice_adds_one_guardrail():
    agent = _agent(Scripted([]))
    govern(agent, rules=RULES)
    assert all(len(t.tool_input_guardrails) == 1 for t in agent.tools)


def test_handoff_agents_are_governed_too():
    helper = Agent(name="helper", tools=[delete_deals])
    govern(Agent(name="lead", handoffs=[helper]), rules=RULES)
    assert helper.tools[0].tool_input_guardrails[0].name == "segurai"
