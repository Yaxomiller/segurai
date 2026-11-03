# Who authorized this?

Your agent deleted 400 customer records. Every log you have says the same thing: *the service account did it.*

That gap — between an action a system took and the person whose request set it in motion — is what [Segurai](https://github.com/Yaxomiller/segurai) exists to close. This is the engineering write-up: the problem, the designs that don't work, the one that seems to, and the parts that are still open.

## The problem, concretely

A manager types *"clean up our old sales records."* An assistant agent reads it, decides the CRM is involved, and hands the job to a CRM agent. That agent searches for stale opportunities, finds 412, and deletes 400 of them.

Some of those 400 belonged to customers who are still active. A month later someone asks who approved it.

Here is what you can actually find out:

- **Your application logs** show `delete_records(table="opportunities", ids=[...])` — 400 ids, no reason, no requester.
- **Your traces**, if you emit OpenTelemetry GenAI spans, show `invoke_agent` → `invoke_agent` → `execute_tool`, nested correctly. They tell you the shape of the call, not who was entitled to make it.
- **Your identity provider** shows one service account with CRM write access, used by everything. It has no notion of "this request, for this person, for this purpose."
- **The CRM's audit log** shows 400 deletions by an API key that is shared by every agent you run.

Nothing in that pile answers "who authorized this?", because nothing in it ever knew. The authority was ambient: a long-lived credential that works for all requests equally, and therefore distinguishes none of them.

It gets worse with delegation. The manager asked the *assistant*. The assistant asked the *CRM agent*. If the CRM agent also calls an MCP server on another team's infrastructure, there is a fourth party acting, several hops from anyone who consented to anything. Each hop is a place where the work can drift from what was asked, and none of them records what it was allowed to do.

## Four designs that don't hold

**Scoped credentials per agent.** Give the CRM agent its own key, limited to the CRM. Better than one shared key, and worth doing — but a static credential can't express "up to 50 records, only ones with no recent activity, for this request." The same key that legitimately archives 30 stale deals on Tuesday deletes 400 live ones on Wednesday. Permissions sized for the widest thing an agent might ever do are the thing you're trying to stop.

**Instructions in the prompt.** "Only archive records with no activity for 180 days." This is advice, not a control. It is also the layer an attacker reaches first: a request, a tool result, or a row of data can all contain text that argues for more.

**Ask a model before every action.** Correct in principle, unaffordable in practice: a judgement call per tool call, at hundreds of milliseconds and real money each. A ransomware-style agent loop can destroy a lot in the seconds you spend deliberating. You also can't block on a model call in a hot path and still call the system fast.

**Read it all afterwards.** Logs plus a human. This is what everyone actually does, and it fails for the dull reason that nobody reads 40,000 tool calls, and the interesting ones look exactly like the boring ones until you check them against intent.

## The design

Four pieces. The first is the only novel one; the rest are standard engineering applied carefully.

### 1. A warrant per hop, narrowing only

Borrowing from search warrants: a narrow, written-down, traceable permission. Each agent hop gets one, derived from its caller's, and **it can only ever be narrower**:

```
sarah@company.com  "clean up our old sales records"
  └─ entrypoint        read, update, delete on crm.*            max 50/action
     └─ assistant      read, update, delete on crm.*            max 50/action
        └─ crm_agent   read, delete on crm.opportunities        max 50/action
```

Each warrant is signed (Ed25519) over its scope, its parent's id, and its depth. So the chain can't be re-parented, reordered, or widened after the fact without the signature breaking. If narrowing held at every hop — and verifying that is a walk up the chain — then whatever the last agent did was inside what the human granted. That is the whole claim, and it's checkable rather than assumed.

The attenuation rule also makes the "an agent cannot grant itself more" property structural instead of aspirational: the code raises when a child asks for something its parent lacks.

### 2. A scope contract, compiled from the request once

"Clean up our old sales records" isn't checkable. One LLM call at the start of the session turns it into something that is:

```json
{"goal": "Archive outdated sales records",
 "expected_operations": ["search", "archive"],
 "expected_targets": ["crm.opportunities"],
 "expected_scale": {"unit": "records", "typical_max": 50},
 "implied_constraints": ["only records with no recent activity",
                         "must not affect active customers"],
 "irreversible_expected": false}
```

One call per session, not per action. Two rules keep it from being a liability: names are checked against a catalog of what actually exists in the organisation (a model-invented `sales_db.records` would match nothing and silently flag everything), and the result is **clamped** to what the person is really permitted to do. A request can only ever narrow their standing permissions, never grant. A prompt injection in the request text therefore buys nothing.

### 3. Two tiers of checking

**Tier 1 is arithmetic**: is the operation in scope, the target covered, the size within the limit, the session total within its budget, the irreversibility allowed, the conditions met? No model call, about 15 µs. It runs on every action and reports *every* rule broken, not just the first.

**Tier 2 is a model**, and it only sees what Tier 1 flagged. Tier 1 is exact but literal: it flags an archive because one deal had "activity" twelve days ago, when that activity was an automated field sync. So the judge gets the request, the contract, the chain, the action, the findings and the recent history, and answers one narrow question: within intent, outside intent, or does a person need to decide?

The judge **never overrides Tier 1**. A verdict sits beside the finding; a flagged action stays flagged. Advice, not authority. And everything the agents reported is passed to it as data, in a block they cannot close, with instructions that an agent's claim of its own approval is not approval.

### 4. A log that is evidence

Signatures make a warrant unalterable. The record of what agents *did* was ordinary database rows until recently — anyone with write access could turn a 400-record delete into 4. Now every record also appends to a hash chain, each entry's hash covering the one before it, so an edit, a deletion, or a reordering all break the links, and `segurai audit` names what changed.

A hash chain alone has a real limit: someone patient with the database file can rebuild the whole thing so it agrees with itself again. A **checkpoint** — the head hash signed with a key the database doesn't contain — closes that, and the audit says so plainly when none exists rather than implying a guarantee it doesn't have.

## The parts that were actually hard

These are the bugs and judgement calls that took the time. They're also the reasons I think this needs to be a library rather than a pattern you reimplement per project.

**Comparing patterns is not comparing strings.** Scopes use globs: `crm.*`, `crm.?`. Checking whether a child's pattern fits inside its parent's looks like string matching and isn't. Ordinary glob matching says `crm.*` fits inside `crm.?` — it reads the child's `*` as an ordinary character — so a child could ask for every CRM table under a parent limited to one-character names, and be granted it. That bug was live in my first version, and it defeated the single guarantee the library makes. The fix compares the patterns token by token and refuses whenever it cannot *prove* containment; a brute-force test over every pattern pair checks that it never says yes wrongly.

**Size limits must bound changes, not reads.** Scanning 412 rows to find deletion candidates is the job. Deleting 400 is the concern. Conflating them makes every table scan a violation and trains people to ignore alerts, which is worse than having no alerts.

**Per-action limits don't stop salami slicing.** Sixty one-record archives each pass a limit of 50. The session needs a running total as well, and blocked attempts must not count toward it.

**Unspecified means inherit.** My first version required a child scope to restate everything it wasn't changing, so narrowing one field meant retyping five. That is how you train developers to paste the widest scope everywhere to silence the error — manufacturing the over-permissioning the tool exists to expose. Unstated fields now inherit, which can't widen anything and is therefore safe by construction.

**"Unverifiable" is a third answer.** When an action reports no evidence for a condition, the honest result is neither pass nor violation. Calling it a violation buries real findings in noise; calling it a pass is a lie. It's recorded as a question, shown differently, and left for the judge or a person.

**Observe by default.** Nobody lets an unproven library block production traffic. They will let it watch — and watching is what earns the right to enforce later. So violations are recorded and the action proceeds, unless you turn enforcement on; and the record distinguishes "flagged, went ahead" from "blocked, never happened", because those are different facts in an audit.

## Numbers

- **317 tests**, green on Linux, macOS and Windows across Python 3.10–3.13.
- **Tier 1: ~15 µs** per check. A fully recorded and hash-chained action is **0.04 ms** median, **0.4 ms** at the 99th percentile under test load. The budget was 5 ms.
- **20 seeded scenarios** — ten violations, ten legitimate tasks that a noisy checker would flag. Ten of ten caught for the right reason, zero false positives. The scenarios are in the repo; `segurai eval-tier1` runs them in a second and costs nothing.

## What isn't done

- **The two LLM-dependent pieces have not been measured live.** The intent compiler and the judge are built and tested offline against mock transports, and each has a 50-case labeled eval — but those evals haven't been run against the API yet, and the labels were drafted by the same model that would be graded. Until a person reviews them, treat any score as unverified. I'd rather say that than quote a number I can't stand behind.
- **No learned baseline.** The interesting version of this compares an action against what *this* organisation's cleanup jobs have historically looked like, rather than a model's guess at a typical size. That needs a thousand real chains, which needs people to run the boring recorder first. Building the model before the data would be the wrong order.
- **MCP trust is single-organisation.** Continuing a chain inside an MCP server requires it to hold the same signing key. Cross-organisation delegation needs a key-distribution story that doesn't exist yet.
- **Checkpoints aren't published anywhere external.** Until they are, a key-holder can still rewrite history that was never witnessed outside the database.
- **One process, SQLite.** Right for a pilot, wrong for a busy multi-team deployment.

## Trying it

```bash
pip install segurai
```

If you already emit OpenTelemetry GenAI spans, there's a path with **no code changes**: point your exporter at the collector and standard `invoke_agent` / `execute_tool` spans are rebuilt into an agent chain — which agent called which tool, and for whom. Nothing in that view is signed or checked, and it says so on every page, but it shows you the shape of what your agents are doing, and where warrants would go.

The thing I most want is wrong answers from real systems: a scenario where Tier 1 flags work that was obviously fine, or waves through something that obviously wasn't. Those are in [the issues](https://github.com/Yaxomiller/segurai/issues).

Apache-2.0. The design document is [docs/ARCHITECTURE.md](ARCHITECTURE.md), written to be read by someone who has never seen the code.
