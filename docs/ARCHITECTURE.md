# How warrant works

A plain-language guide to the codebase: what each part does, how a request flows through it, what it guarantees, and what it does not do yet. The source files carry detailed comments; this document is the map that ties them together.

---

## The problem in one paragraph

A manager types *"clean up our old sales records."* An assistant agent passes the job to a CRM agent, which deletes 400 customer records. A month later an auditor asks who authorized it. Every existing log says *"the service account did it"* — because agents today act with one shared API key that works for everything. The trail from the action back to the human is broken. warrant rebuilds that trail and checks each action against what the human actually asked for.

---

## The three objects

Everything is built from three small pieces of data, all in [`src/warrant/models.py`](../src/warrant/models.py).

| Object | Plain meaning | Example |
|---|---|---|
| **Scope** | What someone is allowed to do | read and delete, on `crm.*`, at most 50 records per action, nothing irreversible |
| **Warrant** | A *signed* grant of a Scope to one agent, linked to the warrant it came from | "crm_agent may read/delete `crm.opportunities`, derived from the assistant's warrant, which came from Sarah" |
| **ActionRecord** | Something an agent actually did, and whether it was within its warrant | "crm_agent deleted 400 rows from `crm.opportunities` — outside the warrant (limit 50) — blocked" |

Think of a warrant as a purchase order rather than a credit card: it names who holds it, exactly what it covers, when it expires, and which larger order it was cut from.

---

## The one rule: attenuation

**A child warrant can only ever be narrower than its parent. Never wider.**

If that rule held at every hop, then whatever the last agent did was inside what the human at the top authorized. That is the whole claim, and most of the code exists to make it hold and to prove it held.

It is checked in [`Scope.is_subset_of`](../src/warrant/models.py) along every dimension a child could gain power:

- **operations** — no operation the parent lacked
- **targets** — every child pattern must fit inside a parent pattern (see *Patterns* below)
- **max_scale** — no higher, and never unbounded under a bounded parent
- **irreversible_allowed** — cannot switch on
- **constraints** — cannot drop a condition the parent carried

An agent that asks for more than it was given gets a `ChainError`, not a silent trim. A caller trying to widen has a bug worth seeing.

### Saying only what you narrow

A child scope only needs to mention what it narrows; everything it leaves out is copied from the parent ([`Scope.inherit_unspecified`](../src/warrant/models.py)). So `Scope.of(operations=["read"])` means "same as my parent, but read-only". Leaving a field out (`targets=None`) inherits it; an explicit empty list (`targets=[]`) means *none*.

### Patterns

Targets are glob patterns: `crm.*`, `crm.?`, `crm.[ab]*`. Checking whether one **pattern** fits inside another is subtle — ordinary glob matching reads a `*` in the child as a plain character, so it wrongly says `crm.*` fits inside `crm.?`. [`pattern_covers`](../src/warrant/models.py) compares the patterns token by token and answers "no" whenever it cannot prove "yes". A brute-force test ([`tests/test_patterns.py`](../tests/test_patterns.py)) checks that it never says yes wrongly.

---

## The life of one request

```
 Sarah: "clean up our old sales records"
   │
   ▼
 warrant.session(principal, request, scope)
   │  Authority signs a ROOT warrant (holder "entrypoint", depth 0)
   │  saved to the store, bound as the "current" warrant
   │
   ├─▶ @warrant.agent("assistant")
   │      current warrant is ATTENUATED into a child for "assistant" (depth 1)
   │      signed, saved, bound while the assistant runs
   │
   │      └─▶ @warrant.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
   │             attenuated again, narrower (depth 2)
   │
   │             warrant.act("delete", "crm.opportunities", scale=400)
   │               Tier 1 check against crm_agent's scope → scale 400 > 50
   │               ActionRecord saved: allowed=False
   │               OBSERVE mode: returned, action goes ahead   ("FAIL")
   │               ENFORCE mode: ViolationError raised, stopped ("BLOCKED")
   ▼
 warrant.render(session_id)  → the tree, with every action under its agent
 warrant verify <session_id> → every signature, link and narrowing re-checked
```

The code for this flow is [`src/warrant/runtime.py`](../src/warrant/runtime.py); its opening comment walks through the same steps.

### How "the current warrant" travels

The current warrant lives in a Python *context variable* ([`context.py`](../src/warrant/context.py)). Python carries context variables through normal function calls and into `asyncio` tasks, and LangGraph copies them into its worker threads, so most agent code needs nothing extra.

When work crosses a **process** boundary, the warrant must travel explicitly:

| Boundary | How the warrant travels |
|---|---|
| Queue, HTTP call, subprocess | `export_warrant()` → string → `import_warrant()` → `warrant.delegate(..., parent=w)` |
| MCP tool call | automatically inside the request's `_meta` (see [`instrument/mcp.py`](../src/warrant/instrument/mcp.py)) |
| Services with OpenTelemetry | optionally in OpenTelemetry baggage (see [`instrument/otel.py`](../src/warrant/instrument/otel.py)) |

The receiving side always **verifies the signature** before building on a warrant.

---

## Signatures and keys

[`authority.py`](../src/warrant/authority.py) signs each warrant with Ed25519. The signature covers every field, including the parent link and the depth, so nobody can later widen a scope, re-attach a warrant to a different parent, or reorder the chain without breaking it.

- `warrant.configure(store="warrant.db")` keeps the signing key beside the database as `warrant.key` (private) and `warrant.pub` (public), created on first use.
- `warrant verify <session>` finds that key and re-checks every signature. Without a key it checks structure only, and says so.
- Every warrant records a `key_id`, so a failure can say "signed by a different key" instead of just "invalid".
- An `Authority.verifier("warrant.pub")` can check but never sign — what an auditor should hold.

---

## Describing tool calls: ActionSpec

A tool call is a name plus arguments: `delete_records(table="opportunities", ids=[...400...])`. The check needs *operation, resource, scale, irreversible*. An [`ActionSpec`](../src/warrant/actions.py) is the recipe between the two:

```python
ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True)
```

The same spec type is used by `@warrant.tool`, the LangGraph `ToolGuard` and the MCP `WarrantedClient`, so each tool is described once. A call the spec cannot describe (a missing argument, say) is recorded as a violation: an action nobody can describe is not one anybody authorized.

---

## Modes: observe first, enforce later

| Mode | Out-of-bounds action | Record shows |
|---|---|---|
| `OBSERVE` (default) | recorded, then allowed to proceed | `[FAIL   ]` … `[went ahead]` |
| `ENFORCE` | recorded, then stopped with `ViolationError` | `[BLOCKED]` |

Observe is the default on purpose. Nobody lets an unproven library block production traffic, but they will let it watch — and watching produces the evidence that earns the right to enforce.

---

## Integrations

All optional; `import warrant` pulls in none of them.

| File | What it does |
|---|---|
| [`instrument/otel.py`](../src/warrant/instrument/otel.py) | Emits OpenTelemetry spans (`invoke_workflow`, `invoke_agent`, `execute_tool`) carrying the full signed warrant, so the chain appears in any tracing backend. |
| [`instrument/langgraph.py`](../src/warrant/instrument/langgraph.py) | `agent_node` makes a graph node (function, async function, or compiled subgraph) an agent hop. `ToolGuard` checks every `ToolNode` call before the tool runs. |
| [`instrument/mcp.py`](../src/warrant/instrument/mcp.py) | `WarrantedClient` checks and records MCP tool calls before they are sent and attaches the warrant. `bind_from_meta` continues the chain inside the MCP server. |

Integrations talk to the runtime through **listeners** ([`runtime.Listener`](../src/warrant/runtime.py)): small hooks called around each session, agent hop and tool call. A listener that crashes is logged and ignored — observability must never break the agent it watches.

---

## Storage

[`collector/store.py`](../src/warrant/collector/store.py) — SQLite, one file, three tables: `sessions`, `warrants`, `actions`. Chosen because a file anyone can open beats infrastructure anyone must run. Older database files are upgraded automatically when new columns are added. [`collector/chain.py`](../src/warrant/collector/chain.py) rebuilds and draws the delegation tree.

---

## File map

```
src/warrant/
  __init__.py          public API; render(), summary(), verify_session()
  models.py            Scope, Warrant, ActionRecord; pattern containment
  authority.py         keys; minting, attenuating, verifying warrants
  context.py           the current warrant; export/import across processes
  actions.py           ActionSpec: tool call → operation/resource/scale
  runtime.py           session, agent, delegate, act, tool, configure, listeners
  cli.py               the `warrant` command
  collector/
    store.py           SQLite storage and migrations
    chain.py           tree reconstruction and rendering
  instrument/
    otel.py            OpenTelemetry spans
    langgraph.py       LangGraph nodes and ToolNode
    mcp.py             MCP client and server
examples/              runnable demos (no API keys needed)
tests/                 one file per area; see below
```

## What the tests prove

| Test file | Proves |
|---|---|
| `test_scope.py`, `test_inheritance.py` | the admission check and the narrowing rules |
| `test_patterns.py` | a child pattern can never reach past its parent (brute-force checked) |
| `test_authority.py`, `test_keys.py` | tampering, re-parenting, reordering and foreign keys are all detected; keys survive restarts |
| `test_runtime.py`, `test_tools_async.py` | the developer API, async agents, tools, listeners, delegation across boundaries |
| `test_chain.py`, `test_render.py`, `test_store.py` | reconstruction, output on any terminal, blocked vs went-ahead, old database files |
| `test_otel.py`, `test_langgraph.py`, `test_mcp.py` | each integration against the real library |
| `test_examples.py` | every example still runs |

---

## Honest limits (what is not done yet)

- **The signing key sits with the agent process.** Fine for development; in production an agent that holds the key could mint itself anything. Moving signing into a separate collector is a later milestone.
- **The database is not tamper-evident.** Warrants are signed, so editing one is caught; but a deleted *action* row leaves no trace. A hash-chained, append-only log is planned (M7).
- **Scopes are written by hand.** Deriving them from the request text automatically is M1 (the intent compiler).
- **Constraints are carried, not checked.** "Must not affect active customers" travels down the chain but nothing evaluates it yet (M2 heuristics, M4 semantic judge).
- **LangGraph nodes are children of the session, not of each other**, because the graph runner — not the previous node — calls each node. That is accurate, but a supervisor's routing decision is not yet shown as delegation.
- **Generator functions cannot be agents or tools yet** — the warrant would leak between yields. Clear error if tried.
- **MCP trust is single-organisation.** A server must hold the same key as the client.
