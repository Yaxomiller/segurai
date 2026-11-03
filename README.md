# Segurai

**Provenance and authority for AI agent chains.** Records what a human asked for, records what the agents actually did, and links the two — so "who authorized this?" has an answer.

> A manager types *"clean up our old sales records."* An assistant passes the job to a CRM agent, which deletes 400 customer records. A month later an auditor asks who authorized it. Every log says: *the service account did it.*
>
> The trail from the action back to the human is broken. That is what this fixes.

Install it and import it as `segurai`. The signed grant that each agent hop carries is called a **warrant** — a narrow, written-down, traceable permission, like a search warrant — and that word is used throughout the code and the docs.

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
- Conditions that the catalog's evidence can test are written as Checks automatically
- A read-only web view: the request and contract beside the chain, findings inline, signatures re-verified on every load
- 50 labeled eval cases and a grading harness; running them needs an Anthropic API key

**M2 — Tier 1 check suite: complete.**

- Every rule an action breaks is reported: operation, target, per-action scale, session total, irreversibility, and conditions
- Conditions become testable Checks (e.g. `days_since_activity >= 180`), evaluated against evidence the agent reports; missing evidence is "unverifiable", never a false alarm
- 20 seeded scenarios: 10/10 violations caught for the right reason, 0/10 false positives, 0.15 ms per checked action (p99)

**M3 — public release: in progress.**

- Zero-integration path: existing OpenTelemetry GenAI spans become an observed chain with no code changes
- CI on Linux, Windows and macOS across Python 3.10–3.13, plus packaging checks
- Still to do: publishing to PyPI and a public repository (both need the maintainer's accounts)

**M4 — Tier 2 semantic judge: built, first live eval pending.**

- Reviews only the actions Tier 1 flagged, one narrow question each: within intent, outside intent, or needs a human
- Verdicts sit beside Tier 1's record — advice, never authority — and agent-written text is treated as untrusted data
- 50 labeled cases (27 ambiguous, 3 with planted prompt injection); approving a bad action counts as a dangerous miss

**M6 — scope-creep report: built.**

- Per agent and per person, over any window: operations never used, targets never touched, wildcards that could shrink, size limits against the largest real change
- A proposed tightened scope built only from observed use, with the evidence behind it
- Grants from segurais or from an identity-provider export; Markdown, HTML, JSON, and a CSV of every unused permission

**M5 — design-partner pilots: kit ready.**

- A hardened container for the collector and web view, and a Compose file that won't start without a token
- A pilot runbook: day-0 setup, the weekly review, the day-30 wrap-up, data handling ([docs/PILOT_RUNBOOK.md](docs/PILOT_RUNBOOK.md))
- The pilots themselves need partners — that part is people, not code

## Install

```bash
pip install -e .                 # core: needs only `cryptography`
pip install -e ".[langgraph]"    # + LangGraph integration
pip install -e ".[mcp]"          # + MCP integration
pip install -e ".[otel]"         # + OpenTelemetry spans
pip install -e ".[intent]"       # + intent compiler (Anthropic SDK)
pip install -e ".[judge]"        # + Tier 2 judge (Anthropic SDK)
pip install -e ".[collector]"    # + collector protobuf support
pip install -e ".[dev]"          # everything, plus pytest
```

## Quick start

```python
import segurai
from segurai import Scope

segurai.configure(store="segurai.db")      # signing key kept beside it as segurai.key

granted = Scope.of(
    operations=["read", "update", "delete"],
    targets=["crm.*"],
    max_scale=50,
    constraints=["only records with no recent activity"],
)

# An agent says only what it narrows; everything else is inherited.
@segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
def crm_agent():
    segurai.act("read", "crm.opportunities", scale=412)
    segurai.act("delete", "crm.opportunities", scale=400, irreversible=True)

@segurai.agent("assistant")
def assistant():
    crm_agent()

with segurai.session(
    principal="sarah@company.com",
    request="clean up our old sales records",
    scope=granted,
) as s:
    assistant()

print(segurai.render(s.session_id))
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
                        -> irreversible action not permitted by scope

Summary: 3 warrants, 2 actions, 1 violation(s)
  ! crm_agent: delete crm.opportunities (scale=400) - scale 400 exceeds limit 50; irreversible action not permitted by scope [went ahead]
```

`[FAIL   ]` means the action was outside the warrant and went ahead (observe mode). With `segurai.configure(mode="enforce")` it is stopped before it happens and shows as `[BLOCKED]`.

## Guarding tools

Describe a tool once with an `ActionSpec` — what operation it performs, on which resource, at what scale — and every call is checked *before* the tool body runs:

```python
from segurai import ActionSpec, count

@segurai.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True))
def delete_records(table: str, ids: list[int]) -> int:
    ...
```

## Conditions

A plain-English condition can't be checked by a program; a `Check` can. The agent reports evidence about the records it touches, and every item must satisfy the condition:

```python
from segurai import Check

granted = Scope.of(
    operations=["read", "archive"], targets=["crm.*"], max_scale=50, max_total=50,
    checks=[Check(field="days_since_activity", op=">=", value=180,
                  condition="only records with no recent activity")],
)

segurai.act("archive", "crm.opportunities", scale=3, days_since_activity=[200, 12, 400])
# -> condition not met: only records with no recent activity (days_since_activity = 12, required >= 180)
```

`max_total` caps the records changed across the whole session, so 400 one-record deletions can't slip under a per-action limit of 50. An action that reports no evidence for a check is marked unverifiable (`?` in the tree) rather than treated as a violation. Run the 20-scenario suite with `segurai eval-tier1`.

## LangGraph

```python
from segurai.instrument.langgraph import ToolGuard, agent_node

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

with segurai.session(principal="sarah@company.com", request=request, scope=granted):
    app.invoke({"messages": [HumanMessage(request)]})
```

Works for plain, async and parallel nodes, and for compiled subgraphs. In enforce mode a blocked tool call comes back to the model as an error message saying why, so the agent can change course instead of the graph crashing. Full example: [examples/langgraph_demo.py](examples/langgraph_demo.py).

## MCP

```python
from segurai.instrument.mcp import WarrantedClient, bind_from_meta

# Agent side: calls are checked before they are sent, and carry the warrant.
crm = WarrantedClient(mcp_client, server="crm", rules={...})
await crm.call_tool("delete_records", {"table": "opportunities", "ids": ids})

# Server side: verify the incoming warrant and continue the same chain.
@server.tool()
async def delete_records(table: str, ids: list[int], ctx: Context) -> str:
    with bind_from_meta(ctx, holder="crm_server"):
        segurai.act("delete", f"crm.{table}", scale=len(ids), irreversible=True)
        ...
```

Tools without a rule are described from the server's own `readOnlyHint` / `destructiveHint` annotations. Full example: [examples/mcp_demo.py](examples/mcp_demo.py).

## OpenTelemetry

```python
from segurai.instrument import otel
otel.enable()
```

Sessions, agent hops and tool calls become spans named per the OpenTelemetry GenAI conventions (`invoke_workflow`, `invoke_agent`, `execute_tool`), carrying the full signed warrant as `warrant.*` attributes. The chain shows up in whatever tracing backend a team already uses. Full example: [examples/otel_demo.py](examples/otel_demo.py).

## Scopes from requests

Instead of writing the scope by hand, let the intent compiler read the request. One Claude call produces a structured contract, which is checked against your catalog of real operations and resources and clamped to the person's actual permissions — so a request can never grant more than the person already has.

```python
from segurai.intent import Catalog, IntentCompiler

segurai.configure(store="segurai.db", intent=IntentCompiler(Catalog.load("catalog.json")))

with segurai.session(principal="sarah@company.com",
                     request="clean up our old sales records",
                     ceiling=sarahs_permissions) as s:
    ...
```

Needs `pip install -e ".[intent]"` and `ANTHROPIC_API_KEY`. Try one request with `segurai intent "clean up our old sales records" --catalog evals/intent/catalog.json`; measure the compiler on 50 labeled cases with `segurai eval-intent` (see [evals/intent/](evals/intent/README.md)).

## Collector

Agents on many machines send spans to one place with the standard OpenTelemetry OTLP exporter:

```bash
segurai collect --db central.db --key org.pub --port 4318
```

The collector rebuilds every chain and re-checks every signature with the organisation's public key, refusing anything forged.

**Already using OpenTelemetry? Try it with no code changes.** Point your existing exporter at the collector. Standard GenAI spans (`invoke_agent`, `execute_tool`) from any framework are rebuilt into an *observed* chain: which agent called which tool, and for whom. Observed chains are clearly labeled — nothing in them was authorized, signed or checked — so they show where warrants would go before you adopt them.

## Scope-creep report

Which permissions did we give agents that they never used?

```bash
segurai report --days 30                                   # Markdown to the terminal
segurai report --days 30 --format csv --out unused.csv     # one row per unused permission
segurai report --grants okta-export.json --format html --out report.html
```

For every agent, and for each person's sessions as a whole, it lists operations never used, targets never touched, wildcards that were only used for a few resources, and size limits against the largest change actually made. It then proposes a tightened scope built only from observed use (it never adds anything), with the evidence behind it. Pass `--grants` with standing permissions exported from an identity provider ([format](examples/grants.example.json)) to compare those too, including against observed chains from plain OpenTelemetry. Rarely-run work may need permissions a short window doesn't show, so every report says so and rates its confidence by how much activity it saw.

## Semantic judge (Tier 2)

Tier 1 is exact but can only compare. For the actions it flags, the judge asks Claude one narrow question: given what this person asked for, is this action within intent, outside it, or does a person need to decide?

```bash
segurai judge <session_id> --yes      # judge the session's flagged actions
```

Verdicts are stored beside Tier 1's findings and shown in `segurai show` and the web view; they never change Tier 1's record. Everything the judge reads from agents and tools is treated as untrusted data, so "this was pre-approved" written by an agent grants nothing. Measure it with `segurai eval-judge` on 50 labeled cases (see [evals/tier2/](evals/tier2/README.md)).

## Web view

```bash
segurai ui --db segurai.db        # then open http://127.0.0.1:8700/
```

One page per session: the request and its contract beside the delegation chain, every action's findings inline, and the signatures re-checked each time the page loads. It is plain HTML with no scripts; everything from a request is escaped, and pages carry a strict Content-Security-Policy. With `SEGURAI_COLLECTOR_TOKEN` set, the browser asks for the token as a password. The collector serves the same pages at `/`.

## Deploying a pilot

```bash
export SEGURAI_COLLECTOR_TOKEN="$(python -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose -f deploy/compose.yaml up -d --build
```

The container runs as an unprivileged user on a read-only filesystem, keeps everything in one volume, listens only on localhost (put your TLS proxy in front), and refuses traffic from other machines without a token. Settings come from `SEGURAI_DB`, `SEGURAI_KEY`, `SEGURAI_HOST`, `SEGURAI_PORT` and `SEGURAI_COLLECTOR_TOKEN`. The [pilot runbook](docs/PILOT_RUNBOOK.md) covers the rest: keys, connecting agents, the weekly review and the final report.

## CLI

```bash
segurai sessions              # list recent sessions
segurai show <session_id>     # render the delegation tree (--json, --ascii)
segurai verify <session_id>   # re-check every signature, link and narrowing
segurai creep <session_id>    # granted vs exercised scope
segurai report --days 30      # scope-creep report across sessions
segurai keygen                # create a signing key
segurai collect               # receive spans from agents (OTLP/HTTP)
segurai ui                    # browse sessions in a web page
segurai backup --out copy.db  # consistent copy of the database, safe while running
segurai intent "<request>"    # compile a request into a scope contract
segurai eval-intent ...       # grade the intent compiler on labeled cases
segurai eval-tier1            # run the Tier 1 scenario suite (no API calls)
segurai judge <session_id>    # Tier 2: judge a session's flagged actions
segurai eval-judge            # grade the judge on labeled cases
```

`--db` picks the database (default `segurai.db`); the key is found beside it.

## Design

**Warrants attenuate, never widen.** Each hop derives a child warrant from its parent. A child may narrow operations, targets, scale, or reversibility — never broaden them. Attempting to widen raises rather than silently clamping, because a caller trying to widen has a bug worth seeing. The signature covers the parent link and depth, so a chain cannot be re-parented or reordered after the fact.

If that invariant held at every hop, then whatever happened at the leaf was inside what the root principal granted. That is the whole claim.

**Patterns are compared as patterns.** A child asking for `crm.*` under a parent limited to `crm.?` must be refused, even though plain glob matching would read the child's `*` as an ordinary character and say yes. Containment is checked token by token and errs toward refusing: it may reject a scope that was technically safe, but never accepts one that isn't. Matching is case-sensitive on every platform.

**Unspecified fields inherit.** A declared child scope says what it *narrows*; anything it doesn't mention comes from the parent. Without this, narrowing one field would mean retyping every other — which trains people to paste a wide scope everywhere just to silence the error, producing exactly the over-permissioning this is meant to expose. Leaving a field out (`targets=None`) inherits it; an explicit empty list (`targets=[]`) means *none*.

**Scale bounds mutations, not reads.** An agent scanning 412 rows to find deletion candidates is doing its job; deleting 400 of them is the concern. Conflating them makes every table scan a violation and teaches people to ignore alerts.

**Unverifiable is not a violation.** When an action doesn't report the evidence a condition needs, the finding says so plainly. Treating it as a violation would bury real alerts in noise; treating it as a pass would be untrue.

**An action nobody can describe is not one anybody authorized.** A tool call whose arguments don't fit its `ActionSpec`, or a tool nobody wrote a spec for, is recorded as a violation rather than waved through.

**Observe by default.** Violations are recorded, nothing is blocked. Nobody lets an unproven library block production traffic — but they will let it watch, and watching produces the evidence that earns the right to enforce later.

**Observability never breaks the agent.** A failing listener or exporter is logged and ignored.

## What's next

| Milestone | |
|---|---|
| M1 | Intent compiler — built; first live eval run pending |
| M2 | Tier 1 check suite — complete: 10/10 caught, 0 false positives |
| M3 | Public release; ingest existing OpenTelemetry spans with no code changes |
| M4 | Tier 2 semantic judge — built; first live eval pending |
| M5 | Design-partner pilots — deployment kit and runbook ready |
| M6 | Scope-creep report — built |

Known limits are listed honestly at the end of [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#honest-limits-what-is-not-done-yet).

## Tests

```bash
python -m pytest -q
```

## License

Apache-2.0
