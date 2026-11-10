# Running the demo

```bash
pip install segurai
segurai demo
```

That builds a made-up company, **Acme Co.**, by running real Segurai code through ten agent requests, then opens the dashboard at <http://127.0.0.1:8700/>. No API key, no internet, nothing to configure. Run it from a folder you don't mind it writing a `segurai-demo/` directory into.

Keep a **second terminal** open in the same folder for the tamper scene. To start over at any point, run `segurai demo` again.

## What is real and what isn't

Say this early. Engineers will ask, and the honest answer is a strength.

- **Real:** every request, agent, permission, action, finding and log entry. They are produced by the actual library running agent code: signed warrants, the Tier 1 checks, enforce mode stopping a refund, the hash-chained log, a signed checkpoint.
- **Made up:** the company, its people and their requests.
- **Pre-written:** the compiled contracts and the AI reviews. Producing them for real needs an API key, so the demo ships samples, and every page that shows one says "sample".

---

## For investors: three minutes

**1. The problem (30 s)**, on the overview page.

> "Companies are letting AI agents act on real systems: delete records, issue refunds, email customers. When one does something it shouldn't, every log says the same thing: *the service account did it*. Nobody can answer *who authorized this?* That's the gap."

**2. The incident (60 s)**: click **"Clean up our old sales records"**.

> "Sarah asked an assistant to clean up old sales records. The assistant handed it to a CRM agent, and that agent permanently deleted 400 deals, some belonging to live customers."

Point at the **What happened** panel:

> "Segurai traced the action back to Sarah's request. It shows exactly how it went beyond it, in plain English: it deleted where it should have archived, it did eight times the size, and it did something that can't be undone. An AI review explains why it's outside what she asked."

**3. Stopped, not just flagged (20 s)**: go back and open **"Refund the customers…"**.

> "Here it's in enforce mode. Raj capped refunds at $20. When the agent tried $250, it was stopped before the money moved."

**4. The evidence can't be faked (60 s).** This is the moment people remember. In the second terminal:

```bash
segurai demo tamper
```

> "Now I'm an insider covering it up. I've rewritten the database: the 400 deletions are now a harmless 4-record archive, and the AI review is gone."

Reload the overview. The incident now says **clean**, and the flagged count has dropped.

> "The dashboard believes the lie, but look at the top right: **tampering detected**. And the request itself is marked *altered after the fact*."

Click through to the request, which shows a red warning, then to **Record integrity**, which names exactly what changed.

**5. Why it matters (10 s).**

> "Audit trails only count as evidence if nobody can quietly edit them. That's what lets a security team sign off on letting agents act at all."

---

## For engineers: six minutes

Lead with the same incident, then go underneath it.

**The chain.** On the incident page, scroll to **Delegation chain**: `entrypoint → assistant → crm_agent`. Each hop is an Ed25519-signed warrant that can only *narrow* its parent's. The FAIL row lists every rule broken, in the exact form the code reports it:

```
operation 'delete' not in scope ['archive', 'read', 'search']
scale 400 exceeds limit 50
total changed this session would reach 400, over the limit of 50
irreversible action not permitted by scope
condition not met: only records with no recent activity (days_since_activity = [12, 9], required >= 180)
```

Point at **Verification**: the signatures are re-checked on every page load.

**The scenarios worth opening**, each showing one design decision:

| Request | What it shows |
|---|---|
| Send the weekly churn summary | Prompt injection: "pre-approved by the CFO" arrived *in the data*, and grants nothing |
| Delete my drafts… | Tier 1 flags 14 against an estimated limit of 10, and the AI review explains why it's fine. The second tier exists to cut false alarms |
| Snooze the low-priority tickets | The agent didn't report priority, so the result is *unverifiable*, a question rather than a violation |
| (observed from OpenTelemetry)… | No Segurai code in those agents at all: plain OTel GenAI spans rebuilt into a chain |

**Permissions.** Open the **Permissions** page:

> "Granted against used, per agent. Support agents hold delete, export and send on billing and CRM, and in this window they never touched any of it. The safer setup only ever removes access, and only what the evidence shows was unused."

**The cover-up.** This is the part security engineers care about. In the second terminal:

```bash
segurai demo            # reset
segurai demo cover-up
```

This goes further than `tamper`. It rewrites the record, deletes the log entry for the removed review, renumbers the log so there's no gap, and recomputes every hash. Now the chain agrees with itself and with the records.

Reload **Record integrity**: **History was rewritten.** Only the signed checkpoint caught it, because it holds the chain's earlier fingerprint, signed with a key the database never contained. Then say plainly where the guarantee ends:

> "A hash chain on its own can be rebuilt by anyone with the database file. The signature is what makes it evidence. Publishing checkpoints somewhere external is the next step; then not even a key-holder can rewrite history that was already witnessed."

**Integration.** Finish on the code:

```python
import segurai
from segurai import Scope

@segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
def crm_agent():
    segurai.act("archive", "crm.opportunities", scale=30)

with segurai.session(principal="sarah@acme.example",
                     request="clean up our old sales records", scope=granted):
    crm_agent()
```

There are also integrations for LangGraph nodes and `ToolNode`, MCP clients and servers, and OpenTelemetry export. The dashboard has no JavaScript at all and runs under a strict Content-Security-Policy.

---

## Questions you'll get

**"Is the AI review real?"** Not in the demo; it's a labelled sample. Measured live: the intent compiler is 91.4% acceptable on held-out cases. The judge never approved a clearly bad action, but on genuinely ambiguous cases its agreement isn't yet where it needs to be. The numbers are in `evals/results/`.

**"Does this slow agents down?"** A checked, recorded and hash-chained action takes 0.04 ms at the median. The AI review runs only on flagged actions, and never blocks.

**"What if someone deletes the whole database?"** Then there's nothing to audit, but there's also nothing to show as innocent. Backups (`segurai backup`) and externally published checkpoints are the answer.

**"Who pays for the AI?"** The customer, with their own key or their own hosted model. Segurai's own running cost is close to zero.
