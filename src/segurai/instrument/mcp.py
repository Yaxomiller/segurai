"""MCP integration - checks tool calls at the Model Context Protocol boundary.

MCP is how agents reach tools that live in other processes, often on other
teams' or other companies' servers. That makes it the boundary most worth
watching: a call that leaves the process is where "my agent did something
odd" becomes "my agent did something odd to someone else's system".

CLIENT SIDE - wrap the client an agent uses:

    async with Client(url) as raw:
        crm = WarrantedClient(raw, server="crm", rules={
            "delete_records": ActionSpec("delete", "crm.{table}",
                                         scale=count("ids"), irreversible=True),
        })
        await crm.call_tool("delete_records", {"table": "opportunities", "ids": ids})

  Each call is checked and recorded BEFORE it is sent, so ENFORCE mode stops a
  bad call from ever leaving the process. The current warrant travels to the
  server inside the request's ``_meta`` field.

  Tools without a rule are described from the server's own tool annotations:
      readOnlyHint = true   -> operation "read"
      otherwise             -> operation "write", irreversible unless the
                               server says destructiveHint = false (the MCP
                               spec says to assume destructive when unstated)
      resource              -> "mcp.<server>.<tool>"

SERVER SIDE - continue the chain inside a tool:

    @server.tool()
    async def delete_records(table: str, ids: list[int], ctx: Context) -> str:
        with bind_from_meta(ctx, holder="crm_server"):
            segurai.act("delete", f"crm.{table}", scale=len(ids), irreversible=True)
            ...

  The client sends its whole chain plus its delegation key (a chain token -
  see context.py). The server verifies every hop against the organisation's
  PUBLIC key, derives a child warrant for itself with the key it was handed,
  and everything it records joins the same chain. The server never needs the
  organisation's private key. Trust across organisations (two different
  organisation keys) is a later milestone.

Tested against the official ``mcp`` Python SDK 2.x, but nothing here imports
it: any client object with ``call_tool`` and ``list_tools`` works.
"""

from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import timedelta
from typing import Any, Iterator, Mapping

from ..actions import ActionSpec
from ..authority import ChainError
from ..context import CHAIN_TOKEN_PREFIX, NoWarrantError, export_chain, import_chain
from ..models import Scope, Warrant
from ..runtime import _rt, check_tool_call, delegate, tool_span

try:
    from mcp.server.mcpserver.exceptions import ToolError as _ToolError
except ImportError:  # the SDK is optional; without it these are ordinary errors
    class _ToolError(Exception):  # type: ignore[no-redef]
        pass

__all__ = ["WarrantedClient", "bind_from_meta", "warrant_from_meta",
           "spec_from_annotations", "META_KEY", "WarrantRefused", "WarrantMissing"]

#: The ``_meta`` key the warrant travels under. MCP asks custom keys to carry
#: a prefix so they cannot collide with the protocol's own.
META_KEY = "warrant/token"


# Why these two errors have two parents each: an MCP server hides the text of
# unexpected errors from the caller - it just says "Error executing tool
# delete_records" - which would leave the calling agent, and whoever reads its
# logs, guessing why it was turned away. An MCP ToolError is shown to the
# caller WITH its reason. Being ChainError / NoWarrantError as well means code
# outside MCP still catches them the usual way.

class WarrantRefused(_ToolError, ChainError):
    """An incoming warrant was forged, altered, expired, or unreadable."""


class WarrantMissing(_ToolError, NoWarrantError):
    """A request that had to carry a warrant arrived without one."""


def spec_from_annotations(server: str, tool_name: str, annotations: Any) -> ActionSpec:
    """Describe a tool from the hints its MCP server publishes about it."""
    resource = f"mcp.{server}.{tool_name}"
    if annotations is not None and getattr(annotations, "read_only_hint", None):
        return ActionSpec("read", resource)
    destructive = getattr(annotations, "destructive_hint", None) if annotations is not None else None
    return ActionSpec("write", resource, irreversible=True if destructive is None else bool(destructive))


class WarrantedClient:
    """An MCP client wrapper that checks, records and forwards the warrant.

    Every attribute other than ``call_tool`` passes straight through to the
    wrapped client, so it can be used anywhere the original was.
    """

    def __init__(self, client: Any, server: str, rules: Mapping[str, ActionSpec] | None = None,
                 *, send_warrant: bool = True, send_key: bool = True):
        self._client = client
        self.server = server
        self.rules = dict(rules or {})
        self.send_warrant = send_warrant
        # Without the key the server can verify the chain but not continue
        # it in another process (it would need to hold the org key itself).
        self.send_key = send_key
        self._annotations: dict[str, Any] | None = None  # filled on first use

    def __getattr__(self, name: str) -> Any:
        return getattr(self._client, name)

    async def spec_for(self, tool_name: str) -> ActionSpec:
        """A rule if one was given, otherwise a spec built from the tool's annotations."""
        if tool_name in self.rules:
            return self.rules[tool_name]
        if self._annotations is None:
            self._annotations = {}
            try:
                listing = await self._client.list_tools()
                for t in listing.tools:
                    self._annotations[t.name] = t.annotations
            except Exception:
                # A server that cannot list its tools gets the cautious
                # default for every tool: a write that cannot be undone.
                pass
        return spec_from_annotations(self.server, tool_name, self._annotations.get(tool_name))

    async def call_tool(self, name: str, arguments: dict[str, Any] | None = None,
                        *args: Any, meta: dict[str, Any] | None = None, **kwargs: Any) -> Any:
        """Check and record the call, attach the warrant, then send it."""
        spec = await self.spec_for(name)
        with tool_span(name):
            # In ENFORCE mode this raises ViolationError, and the request is
            # never sent.
            check_tool_call(name, spec, arguments or {}, mcp_server=self.server)
            if self.send_warrant:
                meta = {**(meta or {}), META_KEY: export_chain(include_key=self.send_key)}
            return await self._client.call_tool(name, arguments, *args, meta=meta, **kwargs)


def _meta_of(source: Any) -> Mapping[str, Any] | None:
    """Find the request ``_meta`` in whatever the server code has to hand.

    Accepts the meta dict itself, an MCP ``Context`` (``ctx``), or a request
    context object.
    """
    if source is None:
        return None
    if isinstance(source, Mapping):
        return source
    request_context = getattr(source, "request_context", None)
    if request_context is not None:
        return getattr(request_context, "meta", None)
    return getattr(source, "meta", None)


def _token_of(source: Any) -> str | None:
    meta = _meta_of(source)
    token = meta.get(META_KEY) if meta else None
    return str(token) if token else None


def warrant_from_meta(source: Any) -> Warrant | None:
    """The (leaf) warrant a client sent with this request, if any. NOT verified yet."""
    token = _token_of(source)
    return import_chain(token)[0][-1] if token else None


@contextmanager
def bind_from_meta(source: Any, holder: str, scope: Scope | None = None,
                   ttl: timedelta | None = None, *, required: bool = True) -> Iterator[Warrant | None]:
    """Continue the caller's chain inside an MCP server tool.

    Verifies the incoming warrant, derives a child for ``holder`` (optionally
    narrowed by ``scope``), and binds it for the duration of the block.

    With ``required=False`` a request that carried no warrant runs with no
    warrant bound (and yields None) instead of raising.
    """
    token = _token_of(source)
    try:
        chain, key = import_chain(token) if token else ([], None)
    except ValueError as exc:
        raise WarrantRefused(f"warrant refused: {exc}") from exc
    parent = chain[-1] if chain else None
    if parent is None:
        if required:
            raise WarrantMissing(
                "this MCP request carried no warrant. Send it through WarrantedClient, "
                "or pass required=False to accept calls that are not traced."
            )
        yield None
        return

    store, authority = _rt.ensure()
    with ExitStack() as stack:
        try:
            # Never trust a warrant just because it arrived. A chain token is
            # verified hop by hop against the organisation's public key; an
            # old single-warrant token only verifies if we already trust the
            # key that signed it.
            if token.startswith(CHAIN_TOKEN_PREFIX):
                parent = authority.adopt(chain, key)
            else:
                authority.verify(parent)
            # Keep the caller's chain in this server's store too, so the chain
            # can be walked from here.
            for w in chain:
                store.put_warrant(w)
            child = stack.enter_context(delegate(holder, scope=scope, ttl=ttl, parent=parent))
        except ChainError as exc:
            raise WarrantRefused(f"warrant refused: {exc}") from exc
        # Only the setup above is relabelled. Errors raised by the tool's own
        # code inside the block pass through exactly as they were.
        yield child
