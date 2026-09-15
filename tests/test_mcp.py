"""MCP: client-side checks and warrant forwarding, server-side chain continuation.

Uses the official MCP SDK with the server running in-process. The client is
opened BEFORE the session starts, so the server's tasks do not inherit the
warrant through Python's context - it can only arrive the real way, inside
the request's _meta.
"""

import asyncio

import pytest
from mcp import Client, types
from mcp.server.mcpserver import Context, MCPServer

import warrant
from warrant import ActionSpec, Scope, count
from warrant.instrument.mcp import (
    META_KEY,
    WarrantedClient,
    bind_from_meta,
    spec_from_annotations,
)

GRANTED = Scope.of(operations=["read", "write", "delete"], targets=["crm.*", "mcp.crm.*"],
                   max_scale=50, irreversible_allowed=True)
DELETE_RULE = {"delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"),
                                            irreversible=True)}


def make_server(received: list) -> MCPServer:
    server = MCPServer("crm")

    @server.tool(annotations=types.ToolAnnotations(read_only_hint=True))
    def list_records(table: str) -> str:
        return "ok"

    @server.tool(annotations=types.ToolAnnotations(destructive_hint=True))
    async def delete_records(table: str, ids: list[int], ctx: Context) -> str:
        meta = ctx.request_context.meta or {}
        received.append(meta.get(META_KEY))
        with bind_from_meta(ctx, holder="crm_server"):
            warrant.act("delete", f"crm.{table}", scale=len(ids), irreversible=True)
        return f"deleted {len(ids)}"

    @server.tool()
    def untraced(ctx: Context) -> str:
        with bind_from_meta(ctx, holder="crm_server", required=False) as w:
            return "no warrant" if w is None else "warrant"

    return server


def test_annotations_decide_the_default_description():
    read = spec_from_annotations("crm", "list", types.ToolAnnotations(read_only_hint=True)).resolve({})
    assert read.operation == "read" and not read.irreversible

    unknown = spec_from_annotations("crm", "wipe", None).resolve({})
    assert (unknown.operation, unknown.resource, unknown.irreversible) == ("write", "mcp.crm.wipe", True)

    safe = spec_from_annotations("crm", "tag", types.ToolAnnotations(destructive_hint=False)).resolve({})
    assert safe.irreversible is False


def test_client_records_calls_and_the_server_continues_the_chain():
    received: list = []

    async def main():
        async with Client(make_server(received)) as raw:
            crm = WarrantedClient(raw, server="crm", rules=DELETE_RULE)

            @warrant.agent("crm_agent")
            async def crm_agent():
                await crm.call_tool("list_records", {"table": "opportunities"})
                return await crm.call_tool("delete_records", {"table": "opportunities", "ids": [1, 2, 3]})

            with warrant.session(principal="sarah@company.com", request="clean up", scope=GRANTED) as s:
                return await crm_agent(), s

    result, s = asyncio.run(main())
    assert not result.is_error
    assert received and received[0]

    done = {(a.actor, a.operation, a.resource) for a in s.actions()}
    assert ("crm_agent", "read", "mcp.crm.list_records") in done     # from annotations
    assert ("crm_agent", "delete", "crm.opportunities") in done      # from the rule
    assert ("crm_server", "delete", "crm.opportunities") in done     # inside the server

    chain = {w.holder: w for w in s.chain()}
    assert chain["crm_server"].parent_id == chain["crm_agent"].warrant_id
    assert warrant.verify_session(s.session_id) == []


def test_enforce_mode_stops_the_call_before_it_is_sent():
    received: list = []
    warrant.configure(mode=warrant.Mode.ENFORCE)
    read_only = Scope.of(operations=["read"], targets=["mcp.crm.*"])

    async def main():
        async with Client(make_server(received)) as raw:
            crm = WarrantedClient(raw, server="crm")
            with warrant.session(principal="p", request="r", scope=read_only) as s:
                with pytest.raises(warrant.ViolationError):
                    await crm.call_tool("delete_records", {"table": "opportunities", "ids": [1]})
                return s

    s = asyncio.run(main())
    assert received == []  # the server never saw the call
    (rec,) = s.violations()
    assert (rec.operation, rec.resource) == ("write", "mcp.crm.delete_records")


def test_server_refuses_a_call_that_carries_no_warrant():
    async def main():
        async with Client(make_server([])) as raw:
            crm = WarrantedClient(raw, server="crm", rules=DELETE_RULE, send_warrant=False)
            with warrant.session(principal="p", request="r", scope=GRANTED):
                return await crm.call_tool("delete_records", {"table": "opportunities", "ids": [1]})

    result = asyncio.run(main())
    assert result.is_error
    assert "carried no warrant" in result.content[0].text


def test_server_rejects_a_warrant_signed_by_someone_else():
    mallory = warrant.Authority().issue_root(
        session_id="ses_forged", principal="mallory",
        scope=Scope.of(operations=["delete"], targets=["*"], irreversible_allowed=True))

    async def main():
        async with Client(make_server([])) as raw:
            return await raw.call_tool("delete_records", {"table": "opportunities", "ids": [1]},
                                       meta={META_KEY: warrant.export_warrant(mallory)})

    result = asyncio.run(main())
    assert result.is_error
    assert "invalid signature" in result.content[0].text


def test_untraced_calls_are_allowed_when_not_required():
    async def main():
        async with Client(make_server([])) as raw:
            return await raw.call_tool("untraced", {})

    result = asyncio.run(main())
    assert result.content[0].text == "no warrant"


def test_refusals_are_still_ordinary_warrant_errors_outside_mcp():
    from warrant.instrument.mcp import WarrantMissing, WarrantRefused

    assert issubclass(WarrantRefused, warrant.ChainError)
    assert issubclass(WarrantMissing, warrant.NoWarrantError)
    with pytest.raises(warrant.NoWarrantError):
        with bind_from_meta({}, holder="crm_server"):
            pass
    with pytest.raises(warrant.ChainError, match="not a valid warrant token"):
        with bind_from_meta({META_KEY: "garbage"}, holder="crm_server"):
            pass


def test_errors_from_the_tool_body_are_not_relabelled():
    with warrant.session(principal="p", request="r", scope=GRANTED):
        meta = {META_KEY: warrant.export_warrant()}
    with pytest.raises(warrant.ChainError) as info:
        with bind_from_meta(meta, holder="crm_server"):
            raise warrant.ChainError("raised by the tool itself")
    assert type(info.value) is warrant.ChainError
