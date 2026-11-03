# Pilot runbook

How to run a 30-day design-partner pilot, from first call to final report. Written for whoever runs the pilot on both sides; no prior knowledge of Segurai is assumed.

---

## What a pilot is

- **30 days, observe mode.** Segurai records and flags what the partner's agents do. It blocks nothing. Nobody has to trust a new tool with production traffic on day one.
- **One collector, one database, run by the partner.** Their data never leaves their infrastructure unless they choose to share a report.
- **A weekly 30-minute review**, and a final report at day 30.
- **Success looks like** at least one real finding the partner didn't know about, and a clear answer to "would you pay for the scope-creep report?"

## Before day 0: agree these in writing

| Question | Why it matters |
|---|---|
| Who owns the pilot on their side (engineer + security contact)? | Someone has to deploy it and someone has to act on findings. |
| Which agents, in which environment? | Start with one workflow that touches real systems, not a toy. |
| Which way to connect: zero-integration or the SDK? | See step 4. Zero-integration is live the same day; the SDK adds signed chains and checks. |
| Is request text allowed to be stored? | If not, turn it off (step 4). Prompts and model responses are never stored. |
| Where the collector runs, who can reach it, and how long data is kept | Settles the security review before it becomes a blocker. |
| What happens to the data at the end | Default: the partner deletes the volume after the final report. |

---

## Day 0: set up (about an hour)

### 1. Create the organisation's signing key

On a trusted machine:

```bash
pip install segurai
segurai keygen --key org.key
```

This writes `org.key` (private) and `org.pub` (public).
- **`org.key`** goes wherever the agents run, as a secret (secrets manager or deployment secret). It is what signs warrants.
- **`org.pub`** goes to the collector, which uses it to check that every warrant it receives is genuine.
- Never put `org.key` on the collector.

### 2. Choose a token

```bash
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Keep it in the same secrets store. Agents send it to the collector, and people type it as the password for the web view.

### 3. Run the collector

On the host that will run it:

```bash
git clone <this repository> segurai && cd segurai
mkdir -p deploy/keys && cp /secure/place/org.pub deploy/keys/org.pub
export SEGURAI_COLLECTOR_TOKEN='<the token>'
docker compose -f deploy/compose.yaml up -d --build
```

It listens on `127.0.0.1:4318` only. Put the partner's usual TLS reverse proxy in front of it. With Caddy that is two lines:

```
segurai.partner-internal.example {
    reverse_proxy 127.0.0.1:4318
}
```

Check it is up: `https://segurai.partner-internal.example/healthz` should say `ok`.

### 4. Connect the agents

**Option A: zero-integration** (same day, no code changes). If the agents already emit OpenTelemetry, point the exporter at the collector with the token:

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://segurai.partner-internal.example/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer%20<the token>"
```

Standard GenAI spans (`invoke_agent`, `execute_tool`) become **observed chains**: which agent called which tool, and for whom. Nothing is checked or signed in this mode, and every page says so. It is still enough for the scope-creep report when combined with a grants export (step 5).

**Option B: the SDK** (signed chains, Tier 1 checks, the judge). In the agent service:

```python
import segurai
from segurai.instrument import otel
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

segurai.configure(key="/run/secrets/org.key")   # observe mode is the default
provider = TracerProvider()
provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))  # reads the OTEL_* variables above
otel.enable(provider, capture_request=True)      # False if request text must not be stored
```

Then wrap each request in `segurai.session(...)`, mark agents with `@segurai.agent` or `agent_node`, and describe tools with `ActionSpec`. See the README.

### 5. (Optional) Export standing permissions

To compare what agents *can* do with what they *did*, export their permissions from the identity provider or MCP server configuration into a grants file ([format](../examples/grants.example.json)).

### 6. Confirm it works

Run one real agent task, then open `https://segurai.partner-internal.example/`. Log in with any user name and the token as the password. The session should be listed; open it and check the chain looks right.

---

## Every week: the 30-minute review

Before the call, the partner's engineer runs these (any machine with access to the database, or inside the container):

```bash
segurai report --days 7 --format csv --out week-N-unused.csv
segurai report --days 7 --format html --out week-N-report.html
```

Then take the week's evidence snapshot — one line to paste into the weekly notes, and the thing that makes the records provable later:

```bash
segurai audit
segurai checkpoint
```

If an Anthropic API key is available, judge the week's flagged actions (each flagged action is one paid call):

```bash
segurai judge <session_id> --yes
```

On the call, go through three questions in order:

1. **What was flagged?** Open the web view and sort sessions by violations. For each one: was it a real problem, a scope that was written too tightly, or missing evidence?
2. **What went unused?** Walk the CSV. Agree which permissions can be removed now, and which are needed by rare jobs.
3. **What changes this week?** Decide scope fixes, evidence the agents should start reporting, and any agent behaviour to fix.

Record the outcome in this template, one per week:

```
Week N (dates)
Sessions: __   Actions: __   Flagged: __   Judged: __
Real findings (what, impact, action, owner):
  -
False alarms (why, fix to scope or evidence):
  -
Permissions removed:
  -
Next week:
  -
```

---

## Day 30: wrap up

```bash
segurai report --days 30 --format html --out pilot-final-report.html
segurai report --days 30 --format csv  --out pilot-unused-permissions.csv
```

In the final meeting:

1. **Findings.** The real ones, from the weekly notes. A single well-documented near miss is worth more than a long list.
2. **Least privilege.** How many granted permissions went unused, and which were removed during the pilot.
3. **The question that decides everything.** Would they pay for this report every month? If not, what would it have to show?
4. **Next step.** Enforce mode on one agent, a paid continuation, or a clean stop.

Then delete the data unless agreed otherwise: `docker compose -f deploy/compose.yaml down -v` removes the collector and its volume.

---

## Data handling, in plain terms

| Stored | Not stored |
|---|---|
| Who made each request (the principal), and the request text unless turned off | Prompts sent to models, and model responses |
| Each agent hop's signed warrant: what it was allowed to do | Tool outputs |
| A hash-chain entry per record, so an edit or deletion is detectable | |
| Each action: operation, resource, size, findings, and the evidence the agent reported | Anything from spans that aren't agent or tool spans, beyond their ids and names |
| Tool-call arguments, for observed chains (if the framework records them) | |

Everything sits in one SQLite file in the `segurai-data` volume.

To back it up while running:

```bash
docker compose -f deploy/compose.yaml exec segurai segurai backup --out /data/backup.db
```

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Agents get `401 unauthorized` | The token is missing or wrong in `OTEL_EXPORTER_OTLP_TRACES_HEADERS`. The value must be `Authorization=Bearer%20<token>`. |
| No sessions appear | Wrong endpoint (it must end in `/v1/traces`), or the exporter uses gRPC. Use the HTTP exporter (`http/protobuf`). |
| Pages say "signatures not checked" | The collector has no public key. Check that `deploy/keys/org.pub` exists and `SEGURAI_KEY` points to it. |
| Sessions show "Observed, not authorized" | Expected with zero-integration. Only the SDK produces signed, checked chains. |
| "Verification FAILED: invalid signature" | The agents sign with a different key than the collector checks against, or a record was altered. Compare the key ids in the message. |
| The collector won't start: "refusing to listen beyond this machine without a token" | Set `SEGURAI_COLLECTOR_TOKEN`. |
