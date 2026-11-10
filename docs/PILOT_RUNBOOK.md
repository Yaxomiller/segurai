# Pilot runbook

How to run a 30-day design-partner pilot, from first call to final report. Written for whoever runs the pilot on both sides; no prior knowledge of Segurai is assumed.

---

## What a pilot is

- **30 days, observe mode.** Segurai records and flags what the partner's agents do. It blocks nothing. Nobody has to trust a new tool with production traffic on day one.
- **One Segurai server, one database, run by the partner.** Their data never leaves their infrastructure unless they choose to share a report.
- **A weekly 30-minute review**, and a final report at day 30.
- **Success looks like** at least one real finding the partner didn't know about, and a clear answer to "would you pay for the scope-creep report?"

## Before day 0: agree these in writing

| Question | Why it matters |
|---|---|
| Who owns the pilot on their side (engineer + security contact)? | Someone has to deploy it and someone has to act on findings. |
| Which agents, in which environment? | Start with one workflow that touches real systems, not a toy. |
| Which way to connect: zero-integration, the SDK, or the gateway? | See step 3. Zero-integration is live the same day; the SDK adds signed chains and checks; the gateway makes the checks impossible to skip. |
| Is request text allowed to be stored? | If not, turn it off (step 3). Prompts and model responses are never stored. |
| Where Segurai runs, who can sign in to it, and how long data is kept | Settles the security review before it becomes a blocker. |
| What happens to the data at the end | Default: the partner deletes the volume after the final report. |

---

## Day 0: set up (about an hour)

### 1. Start Segurai

On the host that will run it, with Docker. [deploy/README.md](../deploy/README.md) explains each line, and how to use PostgreSQL instead of a SQLite file:

```bash
git clone https://github.com/Yaxomiller/segurai && cd segurai
export SEGURAI_INGEST_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
docker compose -f deploy/compose.yaml run --rm segurai init --dir /data --for-docker
docker compose -f deploy/compose.yaml run --rm segurai users add --config /data/segurai.toml \
    --email security-lead@partner.example --role admin
docker compose -f deploy/compose.yaml up -d
```

Keep the ingest token in the partner's secrets store: agents send it with their spans. `init` creates the organisation's signing key on the volume (`/data/segurai.key`). Back it up. It never needs to leave the server if agents start their sessions through the issuer (step 3).

It listens on `127.0.0.1` only. Put the partner's usual TLS reverse proxy in front, then set `public_url` in `segurai.toml`. With Caddy:

```
segurai.partner-internal.example {
    reverse_proxy 127.0.0.1:8700
}
```

Check it is up: `https://segurai.partner-internal.example/healthz` should say `ok`. Before going further, `deploy/smoke-test.sh` proves the whole setup works on that host in a couple of minutes.

### 2. Decide what's in `segurai.toml`

Edit `/data/segurai.toml` on the volume. Every setting is commented. Check it, then restart:

```bash
docker compose -f deploy/compose.yaml run --rm segurai config check --config /data/segurai.toml
docker compose -f deploy/compose.yaml restart
```

For a pilot, decide these:

- **`[dashboard.oidc]`**: let people sign in with the company login. Otherwise, admins add accounts from the dashboard's People page.
- **`[[policy.rules]]`**: the company's own lines that no request can cross (for example, "nobody deletes payroll").
- **`[alerts]`**: a Slack channel or webhook for violations, blocked actions and tampering.
- **`[witness]`**: where checkpoints are published outside the database. Use storage the server can append to but not rewrite.

### 3. Connect the agents

**Option A: zero-integration** (same day, no code changes). If the agents already emit OpenTelemetry, point the exporter at Segurai with the ingest token:

```bash
export OTEL_EXPORTER_OTLP_TRACES_ENDPOINT=https://segurai.partner-internal.example/v1/traces
export OTEL_EXPORTER_OTLP_TRACES_HEADERS="Authorization=Bearer%20<the ingest token>"
```

Standard GenAI spans (`invoke_agent`, `execute_tool`) become **observed chains**: which agent called which tool, and for whom. Nothing is checked or signed in this mode, and every page says so. It is still enough for the scope-creep report when combined with a grants export (step 4).

**Option B: the SDK** (signed chains, Tier 1 checks, company rules, the judge). There are integrations for LangGraph, MCP, the OpenAI Agents SDK, the Claude Agent SDK and CrewAI; the README shows each. Sessions start one of two ways:

- **Through the issuer** (recommended where the partner has OIDC). The partner's app sends the person's ID token to `POST /v1/sessions` and passes the returned chain token to the agents (`segurai.resume`). The person is proven, the grant stays inside their group's ceiling, and agent processes never hold the organisation's key. Configure `[issuer]` in `segurai.toml`.
- **Directly** (`segurai.session(...)`). The agent service holds a copy of `segurai.key` as a secret. This is quicker to set up, but the person is only claimed, and the agent process could mint itself anything.

**Option C: the gateway** (agents can't go around it). Configure `[gateway]` with the systems the agents act on and their routes, and give the agents the gateway's address (port 8800) instead of the systems'. The gateway holds the real credentials, so the checks can't be skipped. This can come later in the pilot, one system at a time.

### 4. (Optional) Export standing permissions

To compare what agents *can* do with what they *did*, export their permissions from the identity provider or MCP server configuration into a grants file ([format](../examples/grants.example.json)).

### 5. Confirm it works

Run one real agent task, then open `https://segurai.partner-internal.example/` and sign in. The request should be listed. Open it and check that the chain looks right, and that it says "identity verified" if it came through the issuer.

---

## Every week: the 30-minute review

Before the call, the partner's engineer runs these inside the container (`docker compose -f deploy/compose.yaml exec segurai sh`, then `cd /data`):

```bash
segurai report --days 7 --format csv --out week-N-unused.csv
segurai report --days 7 --format html --out week-N-report.html
```

Then check the evidence. The server signs and publishes checkpoints on its own (`[witness]`), so this is one line to paste into the weekly notes:

```bash
segurai audit --witness witness/checkpoints.log
```

For any finding worth escalating, `segurai evidence <session_id>` produces a pack the partner's auditor can check alone.

If an Anthropic API key is available, judge the week's flagged actions (each flagged action is one paid call):

```bash
segurai judge <session_id> --yes
```

On the call, go through three questions in order:

1. **What was flagged?** Open the dashboard and filter by *went beyond the request* and *stopped*. For each one: was it a real problem, a scope that was written too tightly, or missing evidence?
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

Then delete the data unless agreed otherwise: `docker compose -f deploy/compose.yaml down -v` removes Segurai and its volume (add `-f deploy/compose.postgres.yaml` if PostgreSQL was used).

---

## Data handling, in plain terms

| Stored | Not stored |
|---|---|
| Who made each request (the principal), and the request text unless turned off | Prompts sent to models, and model responses |
| Each agent hop's signed warrant: what it was allowed to do | Tool outputs |
| A hash-chain entry per record, so an edit or deletion is detectable | |
| Each action: operation, resource, size, findings, and the evidence the agent reported | Anything from spans that aren't agent or tool spans, beyond their ids and names |
| Tool-call arguments, for observed chains (if the framework records them) | |
| Dashboard accounts (passwords only as scrypt hashes), and who opened which page | Session cookies (only their hashes) |
| For issuer sessions: who the login system said the person was, and their groups | The ID token itself |

Everything sits in the `segurai-data` volume, in one SQLite file, or in PostgreSQL if that was chosen.

To back up a SQLite file while running:

```bash
docker compose -f deploy/compose.yaml exec segurai segurai --db /data/segurai.db backup --out /data/backup.db
```

For PostgreSQL, use `pg_dump` or the provider's backups. Either way, keep a copy of `/data/segurai.key`.

---

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| Agents get `401 unauthorized` | The ingest token is missing or wrong in `OTEL_EXPORTER_OTLP_TRACES_HEADERS`. The value must be `Authorization=Bearer%20<token>`. |
| No sessions appear | Wrong endpoint (it must end in `/v1/traces`), or the exporter uses gRPC. Use the HTTP exporter (`http/protobuf`). |
| "Verification FAILED: signed by a different key" | The agents start sessions with a different key from the server's. Use the issuer, or give the agents a copy of `/data/segurai.key`. |
| Sessions show "Observed, not authorized" | Expected with zero-integration. Only the SDK produces signed, checked chains. |
| "Verification FAILED: invalid signature" | A record was altered, or signed by a key the server doesn't know. Compare the key ids in the message. |
| Compose stops: "set SEGURAI_INGEST_TOKEN" | Export the ingest token in the shell before every `docker compose` command. |
| "port 8700 is already in use" | Another program, perhaps an earlier Segurai, holds the port. Stop it, or change `port` in `segurai.toml` and the published port in `compose.yaml`. |
| The issuer answers 401 | The ID token failed a check; the message names which (issuer, audience, expiry, email domain, or signature). |
