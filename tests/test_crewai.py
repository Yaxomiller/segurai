"""CrewAI: tool calls checked before they run, through a real crew.

A scripted model stands in for the LLM: it asks for the tool calls each test
needs, in CrewAI's text format, then answers. Everything else - the crew, the
agents, the tool hooks - is the real crewai package. CrewAI is a large
install, so CI runs these in a job of their own.
"""

import json
import os

import pytest

os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
os.environ.setdefault("CREWAI_TRACING_ENABLED", "false")
crewai = pytest.importorskip("crewai")

from typing import Any  # noqa: E402

from crewai import Agent, Crew, Task  # noqa: E402
from crewai.hooks import ToolCallHookContext  # noqa: E402
from crewai.hooks.tool_hooks import (  # noqa: E402
    run_after_tool_call_hooks,
    run_before_tool_call_hooks,
)
from crewai.llms.base_llm import BaseLLM  # noqa: E402
from crewai.tools import tool  # noqa: E402

import segurai  # noqa: E402
from segurai import ActionSpec, Scope, count  # noqa: E402
from segurai.instrument import crewai as segurai_crewai  # noqa: E402
from segurai.instrument.crewai import REFUSED, govern, ungovern  # noqa: E402

GRANTED = Scope.of(operations=["search", "archive", "call"], targets=["crm.*", "tool.*"], max_scale=50)
RULES = {
    "Archive deals": ActionSpec("archive", "crm.opportunities", scale=count("ids")),
    "delete_deals": ActionSpec("delete", "crm.opportunities", scale=count("ids"), irreversible=True),
}
ran: list[tuple[str, int]] = []


class Scripted(BaseLLM):
    """Replies in turn; keeps every message it was sent."""

    replies: list = []
    seen: list = []

    def call(self, messages, tools=None, callbacks=None, available_functions=None,
             from_task=None, from_agent=None, response_model=None) -> Any:
        self.seen.append(messages)
        return self.replies.pop(0) if self.replies else "Thought: done\nFinal Answer: done"

    def supports_function_calling(self) -> bool:
        return False

    def text(self) -> str:
        return "\n".join(str(m) for batch in self.seen for m in (batch if isinstance(batch, list) else [batch]))


def _use(tool_name, args):
    return f"Thought: I will use a tool\nAction: {tool_name}\nAction Input: {json.dumps(args)}"


@tool("Archive deals")
def archive_deals(ids: list[int]) -> str:
    """Archive deals by id."""
    ran.append(("archive", len(ids)))
    return f"archived {len(ids)}"


@tool("Delete deals")
def delete_deals(ids: list[int]) -> str:
    """Permanently delete deals by id."""
    ran.append(("delete", len(ids)))
    return f"deleted {len(ids)}"


@tool("Find stale")
def find_stale() -> str:
    """Find stale deals."""
    ran.append(("find", 0))
    return "[1, 2, 3]"


@pytest.fixture(autouse=True)
def _governed():
    ran.clear()
    govern(rules=RULES)
    yield
    ungovern()


def _crew(*agents_and_replies, async_first=False):
    agents, tasks = [], []
    for i, (role, replies) in enumerate(agents_and_replies):
        llm = Scripted(model="scripted", replies=list(replies), seen=[])
        agent = Agent(role=role, goal="tidy the CRM", backstory="a careful assistant",
                      tools=[archive_deals, delete_deals, find_stale], llm=llm, verbose=False)
        agents.append(agent)
        tasks.append(Task(description=f"step {i + 1} of tidying stale deals", expected_output="a summary",
                          agent=agent, async_execution=async_first and i == 0))
    return Crew(agents=agents, tasks=tasks, verbose=False), [a.llm for a in agents]


def _run(*agents_and_replies, mode=segurai.Mode.OBSERVE, async_first=False):
    segurai.configure(mode=mode)
    crew, llms = _crew(*agents_and_replies, async_first=async_first)
    with segurai.session(principal="sarah@acme.example", request="tidy stale deals", scope=GRANTED) as s:
        crew.kickoff()
    return s, llms


# ---- through a real crew ------------------------------------------------------------

def test_every_tool_call_is_recorded_under_the_agents_own_hop():
    s, _ = _run(("crm_agent", [_use("Find stale", {}), _use("Archive deals", {"ids": [1, 2, 3]})]))
    records = s.actions()
    assert [(r.actor, r.operation, r.resource, r.scale) for r in records] == [
        ("crm_agent", "call", "tool.find_stale", 1), ("crm_agent", "archive", "crm.opportunities", 3)]
    assert all(r.allowed for r in records) and ran == [("find", 0), ("archive", 3)]
    assert [w.holder for w in s.chain()] == ["entrypoint", "crm_agent"]       # one hop, reused
    assert records[1].detail["framework"] == "crewai"
    assert segurai.verify_session(s.session_id) == []


def test_enforce_mode_refuses_the_call_and_tells_the_agent_why():
    s, (llm,) = _run(("crm_agent", [_use("Delete deals", {"ids": list(range(400))})]), mode=segurai.Mode.ENFORCE)
    assert ran == []                                                            # the tool never ran
    (record,) = s.actions()
    assert record.blocked and "operation 'delete' not in scope" in record.violation
    assert f"{REFUSED}: " in llm.text() and "This call was not made" in llm.text()
    assert segurai_crewai._reasons == {}                                       # nothing left behind


def test_observe_mode_records_the_violation_and_lets_the_call_through():
    s, _ = _run(("crm_agent", [_use("Archive deals", {"ids": list(range(80))})]))
    (record,) = s.actions()
    assert not record.allowed and not record.blocked and "scale 80 exceeds limit 50" in record.violation
    assert ran == [("archive", 80)]


def test_each_agent_in_a_crew_gets_its_own_hop_even_on_another_thread():
    s, _ = _run(("researcher", [_use("Find stale", {})]),
                ("crm_agent", [_use("Archive deals", {"ids": [1, 2]})]), async_first=True)
    assert [(r.actor, r.operation) for r in s.actions()] == [("researcher", "call"), ("crm_agent", "archive")]
    assert sorted(w.holder for w in s.chain()) == ["crm_agent", "entrypoint", "researcher"]


# ---- the edges -------------------------------------------------------------------------

def _context(tool_name="delete_deals", args=None, role="crm_agent"):
    return ToolCallHookContext(tool_name=tool_name, tool_input=args if args is not None else {"ids": [1]},
                               tool=delete_deals, agent=type("A", (), {"role": role})())


def test_outside_a_session_enforce_refuses_and_observe_lets_it_run_unrecorded(caplog):
    segurai.configure(mode=segurai.Mode.ENFORCE)
    ctx = _context()
    assert run_before_tool_call_hooks(ctx) is True                              # blocked
    ctx.tool_result = "Tool execution blocked by hook. Tool: delete_deals"
    assert "no Segurai session is active" in run_after_tool_call_hooks(ctx)

    segurai.configure(mode=segurai.Mode.OBSERVE)
    assert run_before_tool_call_hooks(_context()) is False                      # allowed
    assert "outside any Segurai session" in caplog.text


def test_a_failure_inside_the_check_fails_closed_in_enforce_mode(monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("store unavailable")

    monkeypatch.setattr(segurai_crewai, "check_tool_call", broken)
    with segurai.session(principal="sarah@acme.example", request="tidy", scope=GRANTED):
        segurai.configure(mode=segurai.Mode.ENFORCE)
        ctx = _context()
        assert run_before_tool_call_hooks(ctx) is True
        ctx.tool_result = "Tool execution blocked by hook. Tool: delete_deals"
        assert "could not be checked (store unavailable)" in run_after_tool_call_hooks(ctx)
        segurai.configure(mode=segurai.Mode.OBSERVE)
        assert run_before_tool_call_hooks(_context()) is False                  # observe: let through


def test_another_hooks_block_keeps_its_own_message():
    with segurai.session(principal="sarah@acme.example", request="tidy", scope=GRANTED):
        ctx = _context(args={"ids": [1]})
        assert run_before_tool_call_hooks(ctx) is False                         # Segurai allows it
        ctx.tool_result = "Tool execution blocked by hook. Tool: delete_deals"  # ...someone else blocks it
        assert run_after_tool_call_hooks(ctx) == ctx.tool_result


def test_governing_twice_registers_once_and_ungovern_removes_it():
    from crewai.hooks import get_before_tool_call_hooks

    before = len(get_before_tool_call_hooks())
    govern(rules=RULES)
    govern(rules={})
    assert len(get_before_tool_call_hooks()) == before
    ungovern()
    assert len(get_before_tool_call_hooks()) == before - 1
    govern(rules=RULES)                                                         # for the fixture to remove
