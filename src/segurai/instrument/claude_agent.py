"""Claude Agent SDK integration: a PreToolUse hook that checks every tool call.

    from claude_agent_sdk import ClaudeAgentOptions, HookMatcher, query
    from segurai.instrument.claude_agent import pre_tool_use

    with segurai.session(principal="sarah@acme.example", request="tidy the repo", scope=granted):
        options = ClaudeAgentOptions(hooks={"PreToolUse": [HookMatcher(hooks=[pre_tool_use("assistant")])]})
        async for message in query(prompt="tidy the repo", options=options):
            ...

The hook runs before Claude uses any tool. Each call is recorded under a
warrant for the agent making it - the main agent, or the sub-agent named in
the hook's ``agent_type`` when a Task sub-agent is working - checked against
the warrant and the organisation's rules, and in ENFORCE mode denied with the
reason, which Claude sees. The warrant is captured when the hook is created,
so it holds even though the SDK runs hooks on its own tasks.

Built-in tools are described sensibly by default (Read/Grep/Glob read files,
Write/Edit write them, Bash executes - irreversibly, since its effects are
unknown - and Web* reads the web; MCP tools are calls to ``mcp.<server>.<tool>``).
Pass ``rules`` to describe a tool more precisely.

Tested against claude-agent-sdk 0.2 with recorded hook inputs (running the
SDK needs the Claude Code CLI, which the tests don't).
"""

from __future__ import annotations

import threading
from typing import Any, Awaitable, Callable, Mapping

from ..actions import ActionSpec
from ..context import bind_warrant, current_warrant
from ..models import Warrant
from ..runtime import ViolationError, _rt, check_tool_call

__all__ = ["pre_tool_use", "default_spec"]

_READ = {"Read", "Glob", "Grep", "LS", "NotebookRead", "TodoRead"}
_WRITE = {"Write", "Edit", "MultiEdit", "NotebookEdit", "TodoWrite"}
_WEB = {"WebFetch", "WebSearch"}


def default_spec(tool_name: str) -> ActionSpec:
    """How a tool is described when no rule is given."""
    if tool_name in _READ:
        return ActionSpec("read", "files")
    if tool_name in _WRITE:
        return ActionSpec("write", "files")
    if tool_name == "Bash":
        return ActionSpec("execute", "shell", irreversible=True)
    if tool_name in _WEB:
        return ActionSpec("read", "web")
    if tool_name.startswith("mcp__"):
        parts = tool_name.split("__")
        server, tool = (parts[1], "__".join(parts[2:])) if len(parts) >= 3 else ("unknown", tool_name)
        return ActionSpec("call", f"mcp.{server}.{tool}", irreversible=True)
    return ActionSpec("call", f"tool.{tool_name}")


def pre_tool_use(agent: str = "assistant", rules: Mapping[str, ActionSpec] | None = None,
                 parent: Warrant | None = None) -> Callable[..., Awaitable[dict[str, Any]]]:
    """A PreToolUse hook for ``ClaudeAgentOptions(hooks=...)``.

    ``agent`` names the main agent's hop. ``parent`` defaults to the warrant
    in force when this is called (inside ``segurai.session`` or ``resume``).
    """
    root = parent or current_warrant()
    rules = dict(rules or {})
    hops: dict[str, Warrant] = {}
    lock = threading.Lock()

    def hop(name: str, above: Warrant) -> Warrant:
        with lock:
            w = hops.get(name)
            if w is None or w.is_expired():
                store, authority = _rt.ensure()
                w = authority.attenuate(above, holder=name)
                store.put_warrant(w)
                hops[name] = w
            return w

    async def hook(input_data: Mapping[str, Any], tool_use_id: str | None, context: Any) -> dict[str, Any]:
        if input_data.get("hook_event_name") != "PreToolUse":
            return {}
        name = str(input_data.get("tool_name") or "unknown")
        arguments = input_data.get("tool_input") or {}
        warrant = root if root.holder == agent else hop(agent, root)
        sub_agent = input_data.get("agent_type") if input_data.get("agent_id") else None
        if sub_agent:
            warrant = hop(f"{agent}/{sub_agent}", warrant)
        spec = rules.get(name) or default_spec(name)
        try:
            with bind_warrant(warrant):
                check_tool_call(name, spec, dict(arguments), tool_use_id=tool_use_id or input_data.get("tool_use_id"),
                                framework="claude-agent-sdk")
        except ViolationError as refused:
            return {"hookSpecificOutput": {
                "hookEventName": "PreToolUse", "permissionDecision": "deny",
                "permissionDecisionReason": f"Refused by Segurai: {refused.record.violation}",
            }}
        return {}          # no opinion: the SDK's own permission settings still apply

    return hook
