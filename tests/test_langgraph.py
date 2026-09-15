"""LangGraph: agent nodes, subgraphs, parallel branches, async, and ToolGuard."""

import asyncio
import operator
from typing import Annotated, TypedDict

from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.tools import tool as lc_tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

import warrant
from warrant import ActionSpec, Scope, count
from warrant.instrument.langgraph import ToolGuard, agent_node

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


class State(TypedDict):
    log: Annotated[list, operator.add]


def _session():
    return warrant.session(principal="sarah@company.com",
                           request="clean up our old sales records", scope=GRANTED)


def test_nodes_become_agent_hops_including_parallel_branches():
    def planner(state):
        warrant.act("read", "crm.accounts")
        return {"log": ["planner"]}

    def leads(state):
        warrant.act("read", "crm.leads")
        return {"log": ["leads"]}

    def opps(state):
        warrant.act("read", "crm.opportunities")
        return {"log": ["opps"]}

    b = StateGraph(State)
    b.add_node("planner", agent_node("planner", planner))
    b.add_node("leads", agent_node("leads_agent", leads))
    b.add_node("opps", agent_node("opps_agent", opps, scope=Scope.of(targets=["crm.opportunities"])))
    b.add_edge(START, "planner")
    b.add_edge("planner", "leads")   # leads and opps run in parallel,
    b.add_edge("planner", "opps")    # on LangGraph's worker threads
    b.add_edge("leads", END)
    b.add_edge("opps", END)

    with _session() as s:
        b.compile().invoke({"log": []})
        actors = {a.resource: a.actor for a in s.actions()}
        chain = {w.holder: w for w in s.chain()}

    assert actors == {"crm.accounts": "planner", "crm.leads": "leads_agent",
                      "crm.opportunities": "opps_agent"}
    assert chain["opps_agent"].scope.targets == frozenset({"crm.opportunities"})
    # Nodes do not call each other - the graph runner calls each of them - so
    # every agent's warrant is delegated from the session's root.
    root_id = chain["entrypoint"].warrant_id
    assert {chain[n].parent_id for n in ("planner", "leads_agent", "opps_agent")} == {root_id}


def test_a_compiled_subgraph_can_be_an_agent():
    def delete_step(state):
        warrant.act("delete", "crm.opportunities", scale=400, irreversible=True)
        return {"log": ["deleted"]}

    sub = StateGraph(State)
    sub.add_node("delete_step", delete_step)
    sub.add_edge(START, "delete_step")
    sub.add_edge("delete_step", END)

    outer = StateGraph(State)
    outer.add_node("crm_agent", agent_node(
        "crm_agent", sub.compile(),
        scope=Scope.of(operations=["read", "delete"], targets=["crm.opportunities"])))
    outer.add_edge(START, "crm_agent")
    outer.add_edge("crm_agent", END)

    with _session() as s:
        result = outer.compile().invoke({"log": []})
        (rec,) = s.actions()
    assert "deleted" in result["log"]
    assert rec.actor == "crm_agent"
    assert not rec.allowed and "exceeds limit 50" in rec.violation


def test_async_graph_nodes():
    async def reader(state):
        await asyncio.sleep(0)
        warrant.act("read", "crm.leads")
        return {"log": ["read"]}

    b = StateGraph(State)
    b.add_node("reader", agent_node("reader", reader))
    b.add_edge(START, "reader")
    b.add_edge("reader", END)

    async def main():
        with _session() as s:
            await b.compile().ainvoke({"log": []})
            return s.actions()

    (rec,) = asyncio.run(main())
    assert rec.actor == "reader"


# ---- ToolGuard ----------------------------------------------------------

deleted: list = []


@lc_tool
def delete_records(table: str, ids: list[int]) -> str:
    """Delete records by id."""
    deleted.append((table, len(ids)))
    return f"deleted {len(ids)}"


@lc_tool
def send_email(to: str) -> str:
    """Send an email."""
    return "sent"


RULES = {"delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True)}


def _tool_graph(guard):
    b = StateGraph(MessagesState)
    b.add_node("tools", ToolNode([delete_records, send_email],
                                 wrap_tool_call=guard.wrap, awrap_tool_call=guard.awrap))
    b.add_edge(START, "tools")
    b.add_edge("tools", END)
    return b.compile()


def _model_asks_for(name, args, call_id="call_1"):
    """The state a graph is in right after the model requested a tool call."""
    return {"messages": [AIMessage(content="", tool_calls=[{"name": name, "args": args, "id": call_id}])]}


def test_toolguard_records_tool_calls_in_observe_mode():
    deleted.clear()
    with _session() as s:
        _tool_graph(ToolGuard(RULES)).invoke(
            _model_asks_for("delete_records", {"table": "opportunities", "ids": list(range(400))}))
        (rec,) = s.actions()
    assert rec.resource == "crm.opportunities" and rec.scale == 400 and not rec.allowed
    assert rec.detail["tool_call_id"] == "call_1"
    assert deleted == [("opportunities", 400)]


def test_toolguard_blocks_before_the_tool_runs_in_enforce_mode():
    deleted.clear()
    warrant.configure(mode=warrant.Mode.ENFORCE)
    with _session():
        out = _tool_graph(ToolGuard(RULES)).invoke(
            _model_asks_for("delete_records", {"table": "opportunities", "ids": list(range(400))}))
    reply = out["messages"][-1]
    assert isinstance(reply, ToolMessage) and reply.status == "error"
    assert "Blocked by warrant" in reply.content and "exceeds limit 50" in reply.content
    assert deleted == []


def test_an_unmapped_tool_is_flagged_by_default():
    with _session() as s:
        _tool_graph(ToolGuard(RULES)).invoke(_model_asks_for("send_email", {"to": "x@example.com"}))
        (rec,) = s.actions()
    assert (rec.operation, rec.resource) == ("send_email", "tool.send_email")
    assert not rec.allowed and "not in scope" in rec.violation


def test_async_toolnode_path():
    deleted.clear()

    async def main():
        with _session() as s:
            await _tool_graph(ToolGuard(RULES)).ainvoke(
                _model_asks_for("delete_records", {"table": "opportunities", "ids": [1, 2]}))
            return s.actions()

    (rec,) = asyncio.run(main())
    assert rec.allowed is False and "irreversible" in rec.violation
