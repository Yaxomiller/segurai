# warrant

**Provenance and authority for AI agent chains.** Records what a human asked for, records what the agents actually did, and links the two — so "who authorized this?" has an answer.

> A manager types *"clean up our old sales records."* An assistant passes the job to a CRM agent, which deletes 400 customer records. A month later an auditor asks who authorized it. Every log says: *the service account did it.*
>
> The trail from the action back to the human is broken. That is what this fixes.

New here? [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) explains how everything fits together in plain language.

---

## Status

**M0 — chain capture: complete.**

- Signed, attenuation-only delegation (Ed25519), with keys that persist so old chains can be re-verified
- Tier 1 admission checks on every action, in about a microsecond
- Observe mode (record and flag) and enforce mode (stop before it happens)
- Integrations: **LangGraph** (nodes, subgraphs, ToolNode), **MCP** (client and server), **OpenTelemetry** (GenAI semantic conventions)
- SQLite storage, chain reconstruction, CLI
- A collector that receives spans from many processes and re-checks every signature

**M1 — intent compiler: built, first live eval pending.**

- One Claude call turns a request into a scope contract (structured output, cached instructions, refusal fallbacks)
- Contracts are checked against the organisation's catalog and clamped to the person's real permissions
- 50 labeled eval cases and a grading harness; running them needs an Anthropic API key

Next: the Tier 1 check suite (M2).

## Install

```bash
pip install -e .                 # core: needs only `cryptography`
pip install -e ".[langgraph]"    # + LangGraph integration
pip install -e ".[mcp]"          # + MCP integration
pip install -e ".[otel]"         # + OpenTelemetry spans
pip install -e ".[intent]"       # + intent compiler (Anthropic SDK)
pip install -e ".[collector]"    # + collector protobuf support
pip install -e ".[dev]"          # everything, plus pytest
```

## Quick start

```python
import warrant
from warrant import Scope

warrant.configure(store="warrant.db")      # signing key kept beside it as warrant.key

granted = Scope.of(
    operations=["read", "update", "delete"],
    targets=["crm.*"],
    max_scale=50,
    constraints=["only records with no recent activity"],
)

# An agent says only what it narrows; everything else is inherited.
@warrant.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
def crm_agent():
    warrant.act("read", "crm.opportunities", scale=412)
    warrant.act("delete", "crm.opportunities", scale=400, irreversible=True)

@warrant.agent("assistant")
def assistant():
    crm_agent()

with warrant.session(
    principal="sarah@company.com",
    request="clean up our old sales records",
    scope=granted,
) as s:
    assistant()

print(warrant.render(s.session_id))
```

```
Delegation chain
  └─ entrypoint  [wrt_7a07522323244bb1]
        ops={delete,read,update} targets={crm.*} max_scale=50
     └─ assistant  [wrt_3f22fd11d57f4d91]
           ops={delete,read,update} targets={crm.*} max_scale=50
        └─ crm_agent  [wrt_ba50b4faee524582]
              ops={delete,read,update} targets={crm.opportunities} max_scale=50
              [ok     ] read crm.opportunities scale=412
              [FAIL   ] delete crm.opportunities scale=400
                        -> scale 400 exceeds limit 50

Summary: 3 warrants, 2 actions, 1 violation(s)
  ! crm_agent: delete crm.opportunities (scale=400) - scale 400 exceeds limit 50 [went ahead]
```

`[FAIL   ]` means the action was outside the warrant and went ahead (observe mode). With `warrant.configure(mode="enforce")` it is stopped before it happens and shows as `[BLOCKED]`.

## Guarding tools

Describe a tool once with an `ActionSpec` — what operation it performs, on which resource, at what scale — and every call is checked *before* the tool body runs:

```python
from warrant import ActionSpec, count

@warrant.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True))
def delete_records(table: str, ids: list[int]) -> int:
    ...
```

## LangGraph

```python
from warrant.instrument.langgraph import ToolGuard, agent_node

guard = ToolGuard({
    "delete_records": ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True),
})

crm = StateGraph(MessagesState)
crm.add_node("model", call_model)
crm.add_node("tools", ToolNode(tools, wrap_tool_call=guard.wrap, awrap_tool_call=guard.awrap))
...

app = StateGraph(MessagesState)
app.add_node("crm_agent", agent_node("crm_agent", crm.compile(),
                                     scope=Scope.of(targets=["crm.opportunities"])))

with warrant.session(principal="sarah@company.com", request=request, scope=granted):
    app.invoke({"messages": [HumanMessage(request)]})
```

Works for plain, async and parallel nodes, and for compiled subgraphs. In enforce mode a blocked tool call comes back to the model as an error message saying why, so the agent can change course instead of the graph crashing. Full example: [examples/langgraph_demo.py](examples/langgraph_demo.py).

## MCP

```python
from warrant.instrument.mcp import WarrantedClient, bind_from_meta

# Agent side: calls are checked before they are sent, and carry the warrant.
crm = WarrantedClient(mcp_client, server="crm", rules={...})
await crm.call_tool("delete_records", {"table": "opportunities", "ids": ids})

# Server side: verify the incoming warrant and continue the same chain.
@server.tool()
async def delete_records(table: str, ids: list[int], ctx: Context) -> str:
    with bind_from_meta(ctx, holder="crm_server"):
        warrant.act("delete", f"crm.{table}", scale=len(ids), irreversible=True)
        ...
```

Tools without a rule are described from the server's own `readOnlyHint` / `destructiveHint` annotations. Full example: [examples/mcp_demo.py](examples/mcp_demo.py).

## OpenTelemetry

```python
from warrant.instrument import otel
otel.enable()
```

Sessions, agent hops and tool calls become spans named per the OpenTelemetry GenAI conventions (`invoke_workflow`, `invoke_agent`, `execute_tool`), carrying the full signed warrant as `warrant.*` attributes. The chain shows up in whatever tracing backend a team already uses. Full example: [examples/otel_demo.py](examples/otel_demo.py).

## Scopes from requests

Instead of writing the scope by hand, let the intent compiler read the request. One Claude call produces a structured contract, which is checked against your catalog of real operations and resources and clamped to the person's actual permissions — so a request can never grant more than the person already has.

```python
from warrant.intent import Catalog, IntentCompiler

warrant.configure(store="warrant.db", intent=IntentCompiler(Catalog.load("catalog.json")))

with warrant.session(principal="sarah@company.com",
                     request="clean up our old sales records",
                     ceiling=sarahs_permissions) as s:
    ...
```

Needs `pip install -e ".[intent]"` and `ANTHROPIC_API_KEY`. Try one request with `warrant intent "clean up our old sales records" --catalog evals/intent/catalog.json`; measure the compiler on 50 labeled cases with `warrant eval-intent` (see [evals/intent/](evals/intent/README.md)).

## Collector

Agents on many machines send spans to one place with the standard OpenTelemetry OTLP exporter:

```bash
warrant collect --db central.db --key org.pub --port 4318
```

The collector rebuilds every chain and re-checks every signature with the organisation's public key, refusing anything forged.

## CLI

```bash
warrant sessions              # list recent sessions
warrant show <session_id>     # render the delegation tree (--json, --ascii)
warrant verify <session_id>   # re-check every signature, link and narrowing
warrant creep <session_id>    # granted vs exercised scope
warrant keygen                # create a signing key
warrant collect               # receive spans from agents (OTLP/HTTP)
warrant intent "<request>"    # compile a request into a scope contract
warrant eval-intent ...       # grade the intent compiler on labeled cases
```

`--db` picks the database (default `warrant.db`); the key is found beside it.

## Design

**Warrants attenuate, never widen.** Each hop derives a child warrant from its parent. A child may narrow operations, targets, scale, or reversibility — never broaden them. Attempting to widen raises rather than silently clamping, because a caller trying to widen has a bug worth seeing. The signature covers the parent link and depth, so a chain cannot be re-parented or reordered after the fact.

If that invariant held at every hop, then whatever happened at the leaf was inside what the root principal granted. That is the whole claim.

**Patterns are compared as patterns.** A child asking for `crm.*` under a parent limited to `crm.?` must be refused, even though plain glob matching would read the child's `*` as an ordinary character and say yes. Containment is checked token by token and errs toward refusing: it may reject a scope that was technically safe, but never accepts one that isn't. Matching is case-sensitive on every platform.

**Unspecified fields inherit.** A declared child scope says what it *narrows*; anything it doesn't mention comes from the parent. Without this, narrowing one field would mean retyping every other — which trains people to paste a wide scope everywhere just to silence the error, producing exactly the over-permissioning this is meant to expose. Leaving a field out (`targets=None`) inherits it; an explicit empty list (`targets=[]`) means *none*.

**Scale bounds mutations, not reads.** An agent scanning 412 rows to find deletion candidates is doing its job; deleting 400 of them is the concern. Conflating them makes every table scan a violation and teaches people to ignore alerts.

**An action nobody can describe is not one anybody authorized.** A tool call whose arguments don't fit its `ActionSpec`, or a tool nobody wrote a spec for, is recorded as a violation rather than waved through.

**Observe by default.** Violations are recorded, nothing is blocked. Nobody lets an unproven library block production traffic — but they will let it watch, and watching produces the evidence that earns the right to enforce later.

**Observability never breaks the agent.** A failing listener or exporter is logged and ignored.

## What's next

| Milestone | |
|---|---|
| M1 | Intent compiler — built; first live eval run pending |
| M2 | Tier 1 check suite, 20 seeded scenarios |
| M3 | Public release; ingest existing OpenTelemetry spans with no code changes |
| M4 | Tier 2 semantic judge for flagged actions |
| M5 | Design-partner pilots |
| M6 | Scope-creep report |

Known limits are listed honestly at the end of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#honest-limits-what-is-not-done-yet).

## Tests

```bash
python -m pytest -q
```

## License

Apache-2.0
