"""LangGraph integration.

LangGraph already carries Python's context into every node: sequential nodes,
parallel branches (it copies the context into its worker threads) and async
nodes all see the warrant that was current when the graph was invoked. That
was checked against langgraph 1.2. So the core API works inside a graph with
no changes, and this module adds two conveniences.

1. agent_node(name, node, scope=None)

   Marks a graph node as an agent hop, so everything it does is attributed to
   that agent and bounded by its (optionally narrower) scope. ``node`` can be
   a plain function, an async function, or any Runnable - a compiled subgraph
   or a prebuilt ReAct agent, which is how multi-agent LangGraph apps are
   usually assembled.

       builder.add_node("crm_agent", agent_node(
           "crm_agent", crm_subgraph, scope=Scope.of(targets=["crm.opportunities"])))

2. ToolGuard(rules)

   Checks every tool call that goes through LangGraph's ToolNode BEFORE the
   tool runs, using one ActionSpec per tool to say what a call touches.

       guard = ToolGuard({
           "delete_records": ActionSpec("delete", "crm.{table}",
                                        scale=count("ids"), irreversible=True),
       })
       ToolNode(tools, wrap_tool_call=guard.wrap, awrap_tool_call=guard.awrap)

   A tool with no rule is recorded with the tool's own name as the operation,
   on resource "tool.<name>". Unless the scope lists that name, the call shows
   up as a violation. That is the right default: a tool nobody has described
   is a tool nobody can have authorized.

Invoke the graph inside ``segurai.session(...)`` so there is a warrant to
delegate from.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, Awaitable, Callable, Mapping

try:
    from langchain_core.messages import ToolMessage
    from langchain_core.runnables import Runnable, RunnableConfig, RunnableLambda
except ImportError as exc:  # pragma: no cover - only without the optional extra
    raise ImportError(
        "segurai.instrument.langgraph needs LangGraph: pip install 'segurai[langgraph]'"
    ) from exc

from ..actions import ActionSpec
from ..models import Scope
from ..runtime import ViolationError, agent, check_tool_call, tool_span

__all__ = ["agent_node", "ToolGuard"]


def agent_node(name: str, node: Any, scope: Scope | None = None,
               ttl: timedelta | None = None) -> Any:
    """Wrap a LangGraph node so each run of it is an agent hop named ``name``."""
    hop = agent(name, scope=scope, ttl=ttl)

    if isinstance(node, Runnable):
        runnable = node

        # A Runnable is an object, not a function we can decorate, so wrap its
        # invoke/ainvoke in small functions that are. Passing ``config`` on
        # keeps LangGraph's checkpointing, streaming and callbacks working for
        # the subgraph exactly as if it had been added to the graph directly.
        def invoke(state: Any, config: RunnableConfig) -> Any:
            return runnable.invoke(state, config)

        async def ainvoke(state: Any, config: RunnableConfig) -> Any:
            return await runnable.ainvoke(state, config)

        return RunnableLambda(hop(invoke), afunc=hop(ainvoke), name=name)

    if callable(node):
        return hop(node)
    raise TypeError(f"agent_node({name!r}) needs a function or a Runnable, got {type(node).__name__}")


class ToolGuard:
    """Checks and records ToolNode tool calls before they run.

    ``rules``    - tool name -> ActionSpec describing what a call touches.
    ``default``  - spec for tools without a rule (see the module notes).
    ``return_blocked_as_message`` - in ENFORCE mode, answer a blocked call
        with an error ToolMessage (the model sees why and can change course)
        instead of raising ViolationError and stopping the whole graph.
    """

    def __init__(self, rules: Mapping[str, ActionSpec] | None = None, *,
                 default: ActionSpec | None = None,
                 return_blocked_as_message: bool = True):
        self.rules = dict(rules or {})
        self.default = default
        self.return_blocked_as_message = return_blocked_as_message

    def spec_for(self, tool_name: str) -> ActionSpec:
        """The ActionSpec that describes calls to ``tool_name``."""
        if tool_name in self.rules:
            return self.rules[tool_name]
        if self.default is not None:
            return self.default
        return ActionSpec(operation=tool_name, resource=f"tool.{tool_name}")

    def _check(self, call: Mapping[str, Any]) -> ToolMessage | None:
        """Record one call. Returns a refusal message if it was blocked, else None."""
        name = call["name"]
        try:
            check_tool_call(name, self.spec_for(name), call.get("args") or {},
                            tool_call_id=call.get("id"))
        except ViolationError as exc:
            if not self.return_blocked_as_message:
                raise
            return ToolMessage(
                content=f"Blocked by warrant: {exc.record.violation}",
                tool_call_id=call.get("id") or "",
                name=name,
                status="error",
            )
        return None

    def wrap(self, request: Any, execute: Callable[[Any], Any]) -> Any:
        """For ``ToolNode(wrap_tool_call=...)`` - the synchronous path."""
        with tool_span(request.tool_call["name"]):
            blocked = self._check(request.tool_call)
            return blocked if blocked is not None else execute(request)

    async def awrap(self, request: Any, execute: Callable[[Any], Awaitable[Any]]) -> Any:
        """For ``ToolNode(awrap_tool_call=...)`` - the async path."""
        with tool_span(request.tool_call["name"]):
            blocked = self._check(request.tool_call)
            return blocked if blocked is not None else await execute(request)
