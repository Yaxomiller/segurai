"""Claude Agent SDK: the PreToolUse hook, fed hook inputs shaped exactly like the SDK's."""

import asyncio

import pytest

pytest.importorskip("claude_agent_sdk")
from claude_agent_sdk import HookMatcher  # noqa: E402

import segurai  # noqa: E402
from segurai import ActionSpec, Scope, count  # noqa: E402
from segurai.instrument.claude_agent import default_spec, pre_tool_use  # noqa: E402

GRANTED = Scope.of(operations=["read", "write", "call"], targets=["files", "web", "mcp.crm.*"], max_scale=50)


def _input(tool, args, **extra):
    return {"hook_event_name": "PreToolUse", "session_id": "s", "transcript_path": "t", "cwd": ".",
            "tool_name": tool, "tool_input": args, "tool_use_id": f"tu_{tool}", **extra}


def _call(hook, tool, args, **extra):
    return asyncio.run(hook(_input(tool, args, **extra), f"tu_{tool}", None))


def test_tool_calls_are_recorded_under_the_agent_and_its_sub_agents():
    with segurai.session(principal="sarah@acme.example", request="tidy the repo", scope=GRANTED) as s:
        hook = pre_tool_use("assistant")
    assert HookMatcher(hooks=[hook]).hooks == [hook]                          # it fits the SDK's slot
    assert _call(hook, "Read", {"file_path": "README.md"}) == {}
    assert _call(hook, "Edit", {"file_path": "a.py"}, agent_id="ag1", agent_type="code-reviewer") == {}
    records = s.actions()
    assert [(r.actor, r.operation, r.resource) for r in records] == [
        ("assistant", "read", "files"), ("assistant/code-reviewer", "write", "files")]
    assert [w.holder for w in s.chain()] == ["entrypoint", "assistant", "assistant/code-reviewer"]
    assert segurai.verify_session(s.session_id) == []


def test_enforce_mode_denies_with_the_reason():
    segurai.configure(mode=segurai.Mode.ENFORCE)
    with segurai.session(principal="p", request="r", scope=GRANTED) as s:
        hook = pre_tool_use("assistant")
    result = _call(hook, "Bash", {"command": "rm -rf build"})
    decision = result["hookSpecificOutput"]
    assert decision["permissionDecision"] == "deny"
    assert "operation 'execute' not in scope" in decision["permissionDecisionReason"]
    assert s.actions()[0].blocked


def test_rules_describe_mcp_tools_precisely():
    rules = {"mcp__crm__delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"),
                                                    irreversible=True)}
    with segurai.session(principal="p", request="r", scope=GRANTED) as s:
        hook = pre_tool_use("assistant", rules=rules)
    _call(hook, "mcp__crm__delete_records", {"table": "opportunities", "ids": list(range(10))})
    _call(hook, "mcp__crm__list_records", {})
    deleted, listed = s.actions()
    assert (deleted.operation, deleted.resource, deleted.scale) == ("delete", "crm.opportunities", 10)
    assert (listed.operation, listed.resource, listed.irreversible) == ("call", "mcp.crm.list_records", True)


def test_default_descriptions():
    assert default_spec("Grep").resolve({}).operation == "read"
    assert default_spec("Bash").resolve({}).irreversible is True
    assert default_spec("WebFetch").resolve({}).resource == "web"
    assert default_spec("SomethingNew").resolve({}).resource == "tool.SomethingNew"


def test_other_hook_events_are_ignored():
    with segurai.session(principal="p", request="r", scope=GRANTED) as s:
        hook = pre_tool_use()
    assert asyncio.run(hook({"hook_event_name": "PostToolUse"}, None, None)) == {}
    assert s.actions() == []
