# warrant

**Provenance and authority for AI agent chains.** Records what a human asked for, records what the agents actually did, and links the two — so "who authorized this?" has an answer.

> A manager types *"clean up our old sales records."* An assistant passes the job to a CRM agent, which deletes 400 customer records. A month later an auditor asks who authorized it. Every log says: *the service account did it.*
>
> The trail from the action back to the human is broken. That is what this fixes.

---

## Status

**M0 — chain capture.** The core model, signed attenuation-only delegation, context propagation, storage, chain reconstruction, and deterministic (Tier 1) admission checks all work and are tested. Framework instrumentation, the intent compiler, and semantic judgment are the next milestones.

## Install

```bash
pip install -e ".[dev]"
```

## Use

```python
import warrant
from warrant import Scope

warrant.configure(store="warrant.db")

granted = Scope.of(
    operations=["read", "update", "delete"],
    targets=["crm.*"],
    max_scale=50,
    constraints=["only records with no recent activity"],
)

@warrant.agent("crm_agent", scope=Scope.of(
    operations=["read", "delete"], targets=["crm.opportunities"]))
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
Session ses_5d1dff8d65fc482d
  Principal : sarah@company.com
  Request   : 'clean up our old sales records'

Delegation chain
  └─ entrypoint  [wrt_7a07522323244bb1]
        ops={delete,read,update} targets={crm.*} max_scale=50
     └─ assistant  [wrt_3f22fd11d57f4d91]
           ops={delete,read,update} targets={crm.*} max_scale=50
        └─ crm_agent  [wrt_ba50b4faee524582]
              ops={delete,read} targets={crm.opportunities} max_scale=50
              [ok  ] read crm.opportunities scale=412
              [FAIL] delete crm.opportunities scale=400
                     -> scale 400 exceeds limit 50

Summary: 3 warrants, 3 actions, 1 violation(s)
```

## CLI

```bash
warrant sessions              # list recent sessions
warrant show <session_id>     # render the delegation tree
warrant verify <session_id>   # check structure and attenuation
warrant creep <session_id>    # granted vs exercised scope
```

## Design

**Warrants attenuate, never widen.** Each hop derives a child warrant from its parent. A child may narrow operations, targets, scale, or reversibility — never broaden them. Attempting to widen raises rather than silently clamping, because a caller trying to widen has a bug worth seeing. The signature covers the parent link and depth, so a chain cannot be re-parented or reordered after the fact.

If that invariant held at every hop, then whatever happened at the leaf was inside what the root principal granted. That is the whole claim.

**Patterns are compared as patterns.** A child asking for `crm.*` under a parent limited to `crm.?` must be refused, even though plain glob matching would read the child's `*` as an ordinary character and say yes. Containment is checked token by token and errs toward refusing: it may reject a scope that was technically safe, but never accepts one that isn't. Matching is case-sensitive on every platform.

**Unspecified fields inherit.** A declared child scope says what it *narrows*; anything it doesn't mention comes from the parent. Without this, narrowing one field would mean retyping every other — which trains people to paste a wide scope everywhere just to silence the error, producing exactly the over-permissioning this is meant to expose. Leaving a field out (`targets=None`) inherits it; an explicit empty list (`targets=[]`) means *none*.

**Scale bounds mutations, not reads.** An agent scanning 412 rows to find deletion candidates is doing its job; deleting 400 of them is the concern. Conflating them makes every table scan a violation and teaches people to ignore alerts.

**Observe by default.** Violations are recorded, nothing is blocked. Nobody lets an unproven library block production traffic — but they will let it watch, and watching produces the evidence that earns the right to enforce later.

## What's next

| Milestone | |
|---|---|
| M1 | Intent compiler — derive the scope contract from the request automatically |
| M2 | Tier 1 check suite, 20 seeded scenarios |
| M3 | OpenTelemetry ingest, LangGraph + MCP instrumentation, open source release |
| M4 | Tier 2 semantic judge for flagged actions |
| M5 | Design-partner pilots |
| M6 | Scope-creep report |

## Tests

```bash
python -m pytest -q
```

## License

Apache-2.0
