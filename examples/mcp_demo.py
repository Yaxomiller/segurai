"""The Sarah scenario across a service boundary, over MCP.

The CRM sits behind an MCP server - as it would when another team or the CRM
vendor runs it. The agent reaches it through WarrantedClient; the server
continues the chain with bind_from_meta.

The server runs in-process so the demo needs nothing else installed or
running, but the warrant travels exactly as it would over the network: inside
each request's _meta field, checked by the server's signature verification.

Run:  python examples/mcp_demo.py
"""

import asyncio

from mcp import Client, types
from mcp.server.mcpserver import Context, MCPServer

import segurai
from segurai import ActionSpec, Scope, count
from segurai.instrument.mcp import WarrantedClient, bind_from_meta

# ---- the CRM's MCP server ------------------------------------------------

server = MCPServer("crm")


@server.tool(annotations=types.ToolAnnotations(read_only_hint=True))
def find_stale_opportunities(days_inactive: int) -> str:
    """Find opportunities with no activity for `days_inactive` days."""
    return "412 stale opportunities found (ids 1000-1411)"


@server.tool(annotations=types.ToolAnnotations(destructive_hint=True))
async def delete_records(table: str, ids: list[int], ctx: Context) -> str:
    """Permanently delete records from a CRM table."""
    # Continue the caller's chain: verify the warrant it sent, then act under
    # a child warrant held by this server. What the server records joins the
    # same session as the agent that called it.
    with bind_from_meta(ctx, holder="crm_server"):
        segurai.act("delete", f"crm.{table}", scale=len(ids), irreversible=True)
        return f"deleted {len(ids)} rows from {table}"


# ---- the agent side --------------------------------------------------------

GRANTED = Scope.of(
    operations=["read", "delete"],
    targets=["crm.*", "mcp.crm.*"],
    max_scale=50,
    constraints=["only records with no recent activity", "must not affect active customers"],
)


async def main() -> None:
    segurai.configure(store=":memory:")

    async with Client(server) as raw:
        crm = WarrantedClient(raw, server="crm", rules={
            "delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True),
            # find_stale_opportunities has no rule: its readOnlyHint makes it a "read".
        })

        @segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities", "mcp.crm.*"]))
        async def crm_agent() -> str:
            await crm.call_tool("find_stale_opportunities", {"days_inactive": 180})
            result = await crm.call_tool("delete_records",
                                         {"table": "opportunities", "ids": list(range(1000, 1400))})
            return result.content[0].text

        @segurai.agent("assistant")
        async def assistant() -> str:
            return await crm_agent()

        request = "clean up our old sales records"
        with segurai.session(principal="sarah@company.com", request=request, scope=GRANTED) as s:
            print("Server replied:", await assistant())

    print()
    print(segurai.render(s.session_id))
    problems = segurai.verify_session(s.session_id)
    print("\nChain verification:", "OK" if not problems else problems)


if __name__ == "__main__":
    asyncio.run(main())
