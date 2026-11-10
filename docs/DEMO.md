# Running the demo

```bash
pip install segurai
segurai demo
```

That builds a made-up company, **Acme Co.**, by running real Segurai code through twelve agent requests, then opens the dashboard at <http://127.0.0.1:8700/>. No API key, no internet, nothing to configure. Run it from a folder you don't mind it writing a `segurai-demo/` directory into.

Keep a **second terminal** open in the same folder for the tamper scene. To start over at any point, run `segurai demo` again.

## What is real and what isn't

Say this early. Engineers will ask, and the honest answer is a strength.

- **Real:** every request, agent, permission, action, finding and log entry. The actual library produces them by running agent code. That covers:
  - signed warrants and the Tier 1 checks;
  - enforce mode stopping a refund, and a company rule stopping a payroll change;
  - the hash-chained log and a signed checkpoint;
  - Priya's ID token, signed by a stand-in for Acme's login system and verified by the issuer;
  - the gateway refusing a delete before the CRM saw it.

  The login system and the CRM run on your machine only while the demo is built.
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

**4. Proven, and no way around it (30 s)**: open **"Archive the deals that went quiet…"**.

> "Two questions every security team asks. First, how do you know who asked? Priya signed in to Acme's login system, and Segurai checked that token itself. That's the green tick: *identity verified*, not just a name someone typed. Second, can't an agent just skip the checks? Not here. Her agent can only reach the CRM through Segurai's gateway, which holds the CRM's password. When it tried to delete a deal, the gateway refused, and the CRM never saw the request."

**5. The evidence can't be faked (60 s).** This is the moment people remember. In the second terminal:

```bash
segurai demo tamper
```

> "Now I'm an insider covering it up. I've rewritten the database: the 400 deletions are now a harmless 4-record archive, and the AI review is gone."

Reload the overview. The incident now says **clean**, and the flagged count has dropped.

> "The dashboard believes the lie, but look at the top right: **tampering detected**. And the request itself is marked *altered after the fact*."

Click through to the request, which shows a red warning, then to **Record integrity**, which names exactly what changed.

**6. Why it matters (10 s).**

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
| Remove the duplicate payroll entries… | Dana's grant allowed deletes in `hr.*`. The company rule "nobody deletes payroll" still blocked it. The AI review says the agent did exactly what was asked, so the rule and the intent check stay separate |
| Archive the deals that went quiet… | Started from a verified ID token, inside the *sales* ceiling. Every action went through the gateway, and each is marked so. The delete was refused before it reached the CRM |

**Permissions.** Open the **Permissions** page:

> "Granted against used, per agent. Support agents hold delete, export and send on billing and CRM, and in this window they never touched any of it. The safer setup only ever removes access, and only what the evidence shows was unused."

**The cover-up.** This is the part security engineers care about. In the second terminal:

```bash
segurai demo            # reset
segurai demo cover-up
```

This goes further than `tamper`. It rewrites the record, deletes the log entry for the removed review, renumbers the log so there's no gap, and recomputes every hash. Now the chain agrees with itself and with the records.

Reload **Record integrity**: **History was rewritten.** Only the signed checkpoint caught it, because it holds the chain's earlier fingerprint, signed with a key the database never contained. Then say plainly where the guarantee ends:

> "A hash chain on its own can be rebuilt by anyone with the database file. The signature is what makes it evidence. In a real deployment, `segurai serve` also publishes each checkpoint outside the database, to an append-only file or a webhook. Then not even someone holding the key can rewrite history that was already witnessed."

For an auditor, `segurai evidence <session>` packs one request into a zip they can check with only the public key: `segurai evidence-verify pack.zip --key org.pub`.

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

There are also integrations for LangGraph, MCP, the OpenAI Agents SDK, the Claude Agent SDK, CrewAI and OpenTelemetry. Each hooks the framework's own "before a tool runs" point. The dashboard has no JavaScript at all and runs under a strict Content-Security-Policy.

**The real deployment.** If they want to see it run as it would in production, show the Docker smoke test (`deploy/smoke-test.sh`, a couple of minutes on a machine with Docker), or this:

```bash
pip install "segurai[server]"
segurai init && segurai users add --email you@acme.example --role admin
segurai serve
```

That gives you sign-in with roles, an access log, the issuer, the gateway, alerts and witnessed checkpoints, all from one checked `segurai.toml`. It runs on SQLite or PostgreSQL, and CI runs the whole test suite and a Docker deployment on both.

---

## Questions you'll get

**"Is the AI review real?"** Not in the demo; it's a labelled sample. Measured live, the intent compiler is 91.4% acceptable on held-out cases. The judge never approved a clearly bad action. On genuinely ambiguous cases, though, its agreement isn't yet where it needs to be: 47% against an 85% target. Two changes respond to that:
- it can now ask twice and hand any disagreement to a person;
- two people can label the hard cases blind (`segurai label`), so the score is measured against human judgement rather than a model's.

The numbers are in `evals/results/`.

**"Can't an agent just skip your SDK?"** If it can reach the system directly, yes. That's why there's a gateway. The agent is given the gateway's address, not the system's, and the gateway holds the system's credentials. Every request is checked against the agent's warrant and signed by that agent's own key, so a stolen token isn't enough.

**"How do you know who asked?"** For requests started through the issuer, Segurai checks the person's ID token from the company's login system (any OIDC provider: Okta, Entra ID, Google). They get no more than their group's ceiling. Requests that only claim a name are labelled "claimed, not verified" on every page.

**"Where does it run? Our database?"** It runs in your environment, from one Docker image, on SQLite or PostgreSQL, including managed PostgreSQL. Nothing leaves your network. The only outside calls are the optional AI review, using your key, and any alerts you configure.

**"Does this slow agents down?"** A checked, recorded and hash-chained action takes 0.04 ms at the median. The AI review runs only on flagged actions, and never blocks.

**"What if someone deletes the whole database?"** Then there's nothing to audit, but there's also nothing to show as innocent. Backups (`segurai backup`) and externally published checkpoints are the answer.

**"Who pays for the AI?"** The customer, with their own key or their own hosted model. Segurai's own running cost is close to zero.
