"""The Sarah scenario, built the way real LangGraph apps are built.

A supervisor graph hands the cleanup to a CRM sub-agent. The sub-agent is its
own compiled graph: a "model" step that decides which tool to call, then a
ToolNode that runs it, round and round until the model is done.

No LLM or API key is needed: the model step is scripted to make the same bad
decision a real model might - delete all 400 stale records at once.

The graph is ordinary LangGraph. Warrant adds three things:
    segurai.session(...)  the human request the whole run hangs from
    agent_node(...)       each sub-agent becomes a hop in the delegation chain
    ToolGuard(...)        every tool call is checked before the tool runs

The run happens twice: once in OBSERVE mode (the delete goes through and is
flagged) and once in ENFORCE mode (the delete is stopped and the model is told
why).

Run:  python examples/langgraph_demo.py
"""

from langchain_core.messages import AIMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph import END, START, MessagesState, StateGraph
from langgraph.prebuilt import ToolNode

import segurai
from segurai import ActionSpec, Scope, count
from segurai.instrument.langgraph import ToolGuard, agent_node

# ---- tools: stand-ins for a real CRM API ---------------------------------

@tool
def find_stale_opportunities(days_inactive: int) -> str:
    """Find opportunities with no activity for `days_inactive` days."""
    return "412 stale opportunities found (ids 1000-1411)"


@tool
def delete_records(table: str, ids: list[int]) -> str:
    """Permanently delete records from a CRM table."""
    return f"deleted {len(ids)} rows from {table}"


# ---- describe each tool once, so Segurai knows what a call touches ----

guard = ToolGuard({
    "find_stale_opportunities": ActionSpec("read", "crm.opportunities"),
    "delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True),
})


# ---- the CRM sub-agent: a scripted "model" plus a ToolNode ---------------

def crm_model(state: MessagesState) -> dict:
    """Stands in for an LLM: find stale rows, then delete 400 of them, then report."""
    tool_results = [m for m in state["messages"] if m.type == "tool"]
    if len(tool_results) == 0:
        call = {"name": "find_stale_opportunities", "args": {"days_inactive": 180}, "id": "call_find"}
    elif len(tool_results) == 1:
        call = {"name": "delete_records",
                "args": {"table": "opportunities", "ids": list(range(1000, 1400))},
                "id": "call_delete"}
    else:
        return {"messages": [AIMessage(content=f"CRM agent finished: {tool_results[-1].content}")]}
    return {"messages": [AIMessage(content="", tool_calls=[call])]}


def needs_tool(state: MessagesState) -> str:
    return "tools" if state["messages"][-1].tool_calls else END


crm = StateGraph(MessagesState)
crm.add_node("model", crm_model)
crm.add_node("tools", ToolNode([find_stale_opportunities, delete_records],
                               wrap_tool_call=guard.wrap, awrap_tool_call=guard.awrap))
crm.add_edge(START, "model")
crm.add_conditional_edges("model", needs_tool, ["tools", END])
crm.add_edge("tools", "model")


# ---- the supervisor graph --------------------------------------------------

def assistant(state: MessagesState) -> dict:
    segurai.act("read", "crm.accounts", note="checking which customers are active")
    return {"messages": [AIMessage(content="Handing the cleanup to the CRM agent.")]}


app = StateGraph(MessagesState)
app.add_node("assistant", agent_node("assistant", assistant))
# The CRM agent is handed a narrower warrant: opportunities only.
app.add_node("crm_agent", agent_node("crm_agent", crm.compile(),
                                     scope=Scope.of(targets=["crm.opportunities"])))
app.add_edge(START, "assistant")
app.add_edge("assistant", "crm_agent")
app.add_edge("crm_agent", END)
graph = app.compile()


GRANTED = Scope.of(
    operations=["read", "update", "delete"],
    targets=["crm.*"],
    max_scale=50,
    constraints=["only records with no recent activity", "must not affect active customers"],
)


def run(mode: segurai.Mode) -> None:
    segurai.configure(store=":memory:", mode=mode)
    request = "clean up our old sales records"
    with segurai.session(principal="sarah@company.com", request=request, scope=GRANTED) as s:
        result = graph.invoke({"messages": [HumanMessage(request)]})

    print(f"=== {mode.value.upper()} mode " + "=" * 50)
    print(f"Final message: {result['messages'][-1].content}")
    print()
    print(segurai.render(s.session_id))
    problems = segurai.verify_session(s.session_id)
    print("\nChain verification:", "OK" if not problems else problems)
    print()


if __name__ == "__main__":
    run(segurai.Mode.OBSERVE)
    run(segurai.Mode.ENFORCE)
