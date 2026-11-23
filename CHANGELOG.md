# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- **The chain survives a queue** ([`queues.py`](src/segurai/queues.py)). `segurai.queues.handoff("invoice_worker", scope=..., seal_to=WORKER_PUBLIC_KEY)` delegates a hop for the consumer and returns message headers. `with segurai.queues.received(headers, holder="invoice_worker", key=WORKER_PRIVATE_KEY):` takes it up in the other service.
  - The chain is verified against the organisation's public key, so the consumer, and later an auditor, can prove who asked and through whom.
  - The hop's private key travels sealed to the consumer's public key (X25519, HKDF-SHA256, ChaCha20-Poly1305, bound to the warrant id). Anyone else who reads the queue sees the chain but can't act on it. A message read after its hop expired is refused.
  - Helpers for SQS message attributes, Kafka headers and Celery task headers. `consumer_keypair()` makes a consumer service's key pair.
- **Inferred links across queues.** When work crossed a queue without those headers, standard OpenTelemetry span links still connect the consumer's observed chain to the producer's. The dashboard shows it as *inferred*: a probable cause for investigating, never evidence.
- **Triggers: jobs nobody types start sessions with a scope registered in advance** (`[[issuer.triggers]]`).
  - A nightly clean-up, a webhook or a queue consumer sends `POST /v1/sessions {"trigger": "...", "request": "..."}` with its own token from its platform (a Kubernetes service account, a CI system, a cloud's workload identity). The token's issuer is trusted with `kind = "workloads"`.
  - The token's subject must match the trigger's `subjects`. The root's scope is the one registered with the trigger, so there is no model call and nothing decided at run time. The session names the trigger's `owner`, the person accountable for the job, beside the job's proven identity.
  - A job's token can never start a person's session, and a person's sign-in can never fire a trigger.
- **The intent compiler caches contracts** by who asked and what they asked (ignoring case, spacing and final punctuation), for 24 hours by default (`cache_ttl`). The same person asking the same thing again costs no model call, and the session's contract says it was cached. The CLI's `intent` and `eval-intent` never use the cache.
- **Revocation: stop a request now** (`segurai revoke <session> --reason ... --by ...`, or *Revoke this request* on its dashboard page, for an admin or the person who made it).
  - The gateway refuses everything further under it, in observe mode too, and records each attempt. No new direct token is handed out under it. Requests waiting for approval are denied, and an approved one not yet sent is never sent.
  - One warrant can be revoked instead (`--warrant`): it and every hop delegated from it stop, and their siblings carry on.
  - Who revoked it, when and why are in the tamper-evident log and the evidence pack. A direct token already handed out can't be called back; it expires on its own.
- **The gateway gets credentials from the company's secrets manager instead of keeping copies** ([`credentials.py`](src/segurai/credentials.py)).
  - `[gateway.upstreams.credentials]` fills headers from a secret's fields (`Authorization = "Bearer {api_key}"`), read from HashiCorp Vault (KV or any dynamic secrets engine), AWS Secrets Manager (`segurai[aws]`), GCP Secret Manager, or the environment. Or it exchanges a client secret for a short-lived OAuth2 access token (`type = "oauth2"`).
  - The gateway proves who it is with the platform's workload identity: a Kubernetes service account token for Vault, the instance or task role on AWS, the metadata server on GCP. With those it holds no long-lived secret at all.
  - Secrets live only in memory, for their lease, and are fetched again a minute before it lapses. If the secrets manager is down, a credential still inside its lease keeps working; after that, requests fail with 502 and nothing is forwarded. A 401 or 403 from the system drops the cached copy, so a rotated key is picked up on the next request. Secrets never appear in errors or in the record.
- **The fast path: direct, scope-matched tokens for routine work.** With `[gateway.upstreams.direct]` (and OAuth2 credentials), an agent can ask the gateway (`POST /_segurai/credentials`, or `GatewayClient.direct("crm")`) for a short-lived token scoped to what its warrant allows, and call the system itself.
  - Only operations no per-request check could stop are included. Anything that can't be undone, anything size-limited by the request, anything under a condition, and anything a company rule covers stays on the gated path. The answer says what was left out and why.
  - A token may not outlive its warrant: if the provider's tokens last longer than the warrant has left, none is handed out.
  - Each grant is recorded in the tamper-evident log and the evidence pack, with the token's SHA-256 (never the token), so the system's own logs can be matched against it. The request's dashboard page lists the grants.
- **Step-up approvals: an action can wait for a person's yes instead of being refused** ([`approvals.py`](src/segurai/approvals.py)).
  - A company rule with `effect = "approve"` holds matching requests at the gateway. It can be limited to actions that can't be undone (`only_irreversible`) and to changes above a size (`above_scale`). It can name who may decide (`approvers`, glob patterns over dashboard emails; empty means any admin). By default the person who asked may not approve their own request (`allow_requester`).
  - With `[gateway] step_up = true`, an action beyond what the request's warrant allows, but within the ceiling the person's session was issued under, is held and the person is asked. A deny rule, a limit rule, anything past the ceiling, an unproven person, or a request no route describes is still refused.
  - A held request gets a 202 and an approval id; nothing is sent. The gateway keeps exactly the request it received, and the approval page shows those bytes. Approved, the gateway sends them once with the system's credential and keeps the answer for the agent (`GET /_segurai/approvals/<id>`, or `GatewayClient.request(..., wait=600)`).
  - Exactly once: each approved request is claimed under the log's lock before it is sent, so two gateways or a double click can never send it twice. The company's rules are checked again just before sending. A held request expires after `approval_minutes` (default 60), or when the agent's warrant does, whichever comes first.
  - A new **Approvals** page on the dashboard, with Approve and Deny buttons (CSRF-protected), the decider's name and an optional note. Each decision goes into the access log.
  - Every held request, decision and outcome is in the tamper-evident log and in the request's evidence pack. A new alert event, `approval`, links straight to the request waiting for a decision.
  - In the runtime (outside the gateway) an approve rule counts as broken, because there is no one to ask.

- **The live stage** (`segurai stage`, extra `segurai[stage]`): real Claude agents at work in a simulated company, with Segurai deciding what they may do, on one screen made for people who don't read code.
  - Two scenes. An eager agent tries to delete $1.7M of live deals, and an obedient agent is asked by an intern who isn't allowed. Both are stopped by the gateway before the CRM sees the request.
  - A person signs in to a stand-in login system, the issuer grants a slip within their group's ceiling, and each agent hop narrows it. Every CRM request goes through the gateway. Nothing on the Segurai side is simulated.
  - *Who did this?* traces any action back to the person. Each run also appears in the ordinary dashboard.
  - Every live run is recorded and can be played back without the internet or an API key, labelled as a replay.
  - Scene 3, the impostor: an email signed like a real customer's, from a look-alike address, asks for a copy of an email holding the customer's account number. The inbox agent helpfully replies; Segurai stops it, because the slip for a summary only lets the agent read (the issuer grants a request-specific slip within the person's ceiling). An earlier version used an obvious "forward the whole inbox" injection, which Claude refused every time.
  - Scene 4, your turn: anyone at Acme, asking anything.
  - The Segurai switch: the same agents with the systems' passwords and nothing in between, so the audience sees the damage Segurai prevents. Nothing is recorded with it off, and the page says so.
  - The receipt: the request's evidence pack, built from the real record, verified on the spot, and offered as a download with Acme's public key.
  - `segurai stage --rehearse N` runs scenes 1-3 N times with real Claude and reports how each went, recording every run for replay.
  - The assistant routes the person's own words to a specialist instead of rewording them, and each specialist sees only the fields its developer chose (the CRM agent can't see a deal's value or activity; the inbox agent can't see sender addresses). The page shows both, so the audience sees what the agent can't.

### Fixed

- A held request's new state and its action's record are now written in one transaction. For a moment the dashboard could show a request as sent while its action still read "held" (seen once in CI).
- The stage server answered some refused requests before reading them, which on Windows could reset the connection before the browser saw the refusal.

## [0.4.0] — 2026-11-10

From a library to something a company can deploy: agents can't go around it, the person who asked is proven, and one command runs the whole thing.

### Agents can't go around it

- **The gateway** (`gateway.py`) is a reverse proxy in front of the systems agents act on. It holds their credentials, so agents can reach those systems only through it.
  - Every request carries the agent's chain and a fresh signature from that agent's own key, over the method, target, body hash, time and a one-time nonce.
  - A route table describes what each request does. The gateway checks the request against the warrant and the company's rules, and records it before forwarding.
  - A refused request never reaches the system. Ambiguous paths, duplicate JSON keys and method-override headers are refused or dropped, and redirects are not followed.
- **Each hop holds its own key.** A warrant names its holder's public key, and children are signed with the parent holder's key, so agents can delegate without the organisation's key.
- **Chain tokens** (`export_chain` / `segurai.resume`) carry a whole chain across processes.

### Who asked, proven

- **ID tokens from the company's login system** (`identity.py`): any OIDC provider.
  - Asymmetric signatures only, and keys are never fetched over plain HTTP.
  - Issuer, audience, expiry and email domain are all checked.
- **The issuer** (`POST /v1/sessions`) mints a root only for a proven person, and only inside their group's **ceiling**. The session records how the person was proven, and every page says "identity verified" or "claimed, not verified".

### Company rules, alerts, witnesses, evidence

- **Company rules** (`policy.py`): deny and limit rules no grant can override. They are versioned and written into the tamper-evident log, and each finding names the version in force.
- **Alerts** (`alerts.py`) go to Slack, a signed webhook or email, for violations, blocked actions and failed audits.
  - Each alert is queued once, and delivery is retried with backoff.
  - With several servers on one database, each alert is claimed just before it is sent, so exactly one server sends it.
- **Witnesses** (`witness.py`): checkpoints are also published outside the database, to an append-only file or a webhook. `segurai audit --witness` then catches a rewrite even by someone holding the key.
- **Evidence packs** (`segurai evidence`, `segurai evidence-verify`): one request as a zip that an auditor can verify with only the public key.

### A product you can run

- **`segurai serve`** runs the whole deployment from one `segurai.toml`: dashboard, span ingest, issuer, gateway, alerts and checkpoints.
  - The file is read strictly: a typo or an inline secret is an error.
  - `segurai init` writes a commented starting file, and `segurai config check` validates one, even while the server runs.
- **Dashboard sign-in.**
  - Local accounts with scrypt passwords and throttled sign-in, or the company login (OIDC with PKCE).
  - Three roles: viewer, auditor and admin.
  - CSRF-protected forms, and an access log written into the tamper-evident log.
  - Search and filters on the overview.
- **PostgreSQL** (`segurai[postgres]`): give the store a `postgresql://` URL, or `database_env` in `segurai.toml`.
  - The SQL is written once, with the differences in `collector/db.py`.
  - An advisory lock stops several servers from forking the log.
  - A dropped connection is replaced, but never half-way through a write.
  - CI runs the whole suite on PostgreSQL 16.
- **Docker.** The image runs `segurai serve` as an unprivileged user, on a read-only filesystem, with no capabilities.
  - `deploy/compose.yaml` runs it with SQLite, and `deploy/compose.postgres.yaml` adds PostgreSQL.
  - `deploy/smoke-test.sh` proves a deployment end to end, and CI runs it with both.
  - Releases publish the image to `ghcr.io/yaxomiller/segurai` for amd64 and arm64.
- **More frameworks:** the OpenAI Agents SDK (a tool input guardrail), the Claude Agent SDK (a PreToolUse hook) and CrewAI (a before-tool-call hook that fails closed in enforce mode). Each is tested against the real framework.

### The judge

- `--votes 2` asks twice. Agreeing answers give the verdict, and disagreeing ones become "a person must decide".
- `segurai label` lets a person label the eval cases without seeing the existing labels. `segurai label-agreement` reports Cohen's kappa and the disputed cases, and writes the labels both people agree on.

### The demo

- Two new scenes, built by running the real code:
  - a company rule that outranks a manager's grant;
  - a request proven by Acme's login system, whose agent reaches the CRM only through the gateway, which refuses a delete before the CRM sees it.
- Pages name the issuer's ceiling, and mark actions that came through the gateway.

### Fixed

- **Two servers could share a port on Windows.** `http.server` sets SO_REUSEADDR, which on Windows lets a second process bind a port already in use, so `segurai serve` could start while another program answered its requests. Servers now bind exclusively, and a busy port is refused with a plain message.
- **A write that failed half-way could be committed by the next write**, leaving a record without its log entry. Every write is now one transaction.
- **The dashboard's integrity cache** was keyed by `id(store)`, so a reopened database could inherit an old "all clear". It is now keyed by the store itself and by whether the database has changed.
- **The Tier 1 speed gate** was flaky on shared CI machines. Timing is now pooled over repeated passes.

### Changed

- **PyJWT** is now a core dependency, because checking who asked is part of the core promise.
- `segurai[server]` installs what `segurai serve` needs; `segurai[crewai]` is its own extra (CrewAI is large).
- The container runs `segurai serve` on ports 8700 (dashboard) and 8800 (gateway). `SEGURAI_INGEST_TOKEN` replaces `SEGURAI_COLLECTOR_TOKEN` in the Compose files.

## [0.3.0] — 2026-11-10

The demo, and a dashboard worth showing.

### `segurai demo`

- One command builds **Acme Co.**, a made-up company, by running real Segurai code through ten agent requests, then opens the dashboard. No API key, no internet. Every record is real (signed warrants, Tier 1 checks, enforce mode, the hash-chained log, a signed checkpoint); the company, people, compiled contracts and AI reviews are made up or pre-written, and labelled as such on every page.
- The scenarios each show one thing: a clean job, the 400-record incident, a refund stopped in enforce mode, a prompt injection, a judgement call where the AI review cuts a false alarm, missing evidence, unused standing access, and agents seen through plain OpenTelemetry.
- `segurai demo tamper` rewrites the incident as a careful insider would: the record becomes a harmless archive and its AI review is deleted, so the dashboard calls it clean. The record-integrity check catches it, and the request is marked *altered after the fact*.
- `segurai demo cover-up` also rebuilds the hash chain so it agrees with itself. Only the signed checkpoint still catches it.
- `docs/DEMO.md`: a three-minute talk track for investors, a six-minute one for engineers, and the questions each will ask.

### Dashboard

- A redesigned web view: headline numbers, a plain-English "what happened" for every flagged action above the exact findings, the delegation chain drawn from the person down, and two new pages, **Record integrity** (`/audit`) and **Permissions** (`/permissions`).
- Every page carries the record-integrity status, and a request whose records were changed after the fact says so on its own page.
- Still no JavaScript on any page, under the same strict Content-Security-Policy.

### Fixed

- **The permissions report credited only the agent that acted**, plus the person at the top. An agent that delegated its work, like an assistant handing a job to a CRM agent, was reported as using nothing, and the report recommended removing access the chain depends on. Every hop on the path is now credited. Found while building the demo.

## [0.2.0] — 2026-11-05

The tamper-evident log, and the first live measurements of both model-dependent pieces.

### First live evals, and what they changed

- **Intent compiler: 91.4% of held-out contracts acceptable** (32/35), against an 80% target. All three misses were labelling problems. `intent-v3` now defines `irreversible_expected` by whether the organisation can put the state back, which decides the two cases the old wording left open (a calendar invitation reaches a person; a pay rise effective next period does not move money yet).
- **Tier 2 judge: 48.1% on ambiguous cases** against an 85% target, with one dangerous miss — target not met. The disagreements clustered on size limits (58% of session-total flags, 44% of per-action flags), and the cause was a missing fact: the judge saw `max_scale: 50` with no way to know whether a person stated it or the intent compiler estimated it.
- `judge-v2`: reviews now carry `limits.source`, the instructions say how to weigh a stated limit against an estimated one, and the bar for `needs_human` is stated (genuine doubt, not "someone should look").
- The review payload is 22% smaller — five earlier actions instead of ten, and scopes spelled out only for the top and acting hops — to pull latency toward the 2 s target from a measured 3.9 s.
- Both eval sets now have `dev`/`test` splits, with every case that informed a prompt change moved to `dev`. Seven Tier 2 labels were corrected where the judge's reading was better than mine; each says so in its notes.
- Both evals now report what the run actually used — calls, fresh and cached input tokens, output tokens — and an estimated cost from a small price table, so nobody has to trust an estimate. Unpriced models report tokens without inventing a dollar figure.
- Raw reports kept in `evals/results/2026-11-05/`.

### Tamper-evident log (M7)

- Every record written — session, warrant, action, verdict — also appends an entry to a hash chain, in the same transaction. Each entry's hash covers the entry before it, so editing a row, deleting a row, or removing, reordering or editing an entry all break the links.
- `segurai audit` reports what was done in plain language: which record was edited, which was deleted, where the chain stops lining up. It exits non-zero when anything is wrong.
- `segurai checkpoint` signs the current head of the chain with a key the database does not contain, which is what catches a wholesale rewrite. The checkpoint prints as one short line to keep outside the database; published somewhere external, it stops even a key-holder rewriting witnessed history.
- Writing an identical record twice (the collector re-ingesting a trace that arrived in pieces) appends nothing; a record whose contents really changed is logged as an amendment, and the earlier entry stays — the log only ever grows.
- Records written before the log existed are reported as such rather than blamed as tampering.
- Cost: 0.04 ms per checked action at the median and 0.4 ms at the 99th percentile, of which the append is ~13 µs. Tier 1's budget is 5 ms.

## [0.1.0] — 2026-11-03

The first public release: milestones M0 to M6.

### Name

- The package, CLI command, PyPI name, environment variables (`SEGURAI_*`) and default file names are **segurai**. The signed grant each agent hop carries is still a **warrant** (`segurai.Warrant`, `warrant_id`, `current_warrant()`), and so are the OpenTelemetry and MCP wire keys that describe warrants (`warrant.id`, `warrant.scope`, `warrant/token`), which the collector matches on.

### Chain capture (M0)

- Signed, attenuation-only delegation. Each agent hop gets an Ed25519-signed warrant derived from its parent's, and it can only narrow the parent's scope, never widen it.
- Target patterns are compared as patterns (so `crm.*` can't hide inside `crm.?`), and matching is case-sensitive on every platform.
- Child scopes say only what they narrow; everything else is inherited.
- Signing keys persist beside the database, every warrant names its signing key, and `segurai verify` checks signatures in later runs.
- Actions are recorded with their verdict. The default observe mode records and flags; enforce mode stops the action before it happens and marks it blocked.
- `@segurai.tool` and `ActionSpec` describe tool calls. A call that can't be described counts as a violation.
- Integrations:
  - **LangGraph:** `agent_node` for functions, async nodes and compiled subgraphs, and `ToolGuard` for `ToolNode`.
  - **MCP:** `WarrantedClient` checks calls before they are sent, and `bind_from_meta` continues the chain inside the server.
  - **OpenTelemetry:** spans follow the GenAI conventions and carry the full signed warrant.
- Collector: OTLP/HTTP ingest (protobuf or JSON) that re-verifies every signature, with a bearer token and size limits. Run it with `segurai collect`.
- SQLite storage with automatic migrations, chain reconstruction, and a CLI.

### Intent compiler (M1)

- One Claude call turns a request into a scope contract. It uses structured output, cached instructions, refusal fallbacks, and passes the request in escaped tags.
- Contracts are checked against the organisation's catalog and clamped to the person's real permissions (`ceiling`). If the work changes records but no size is given, the limit fails closed to 1.
- Conditions that the catalog's evidence fields can test are written as Checks.
- 50 labeled eval cases, per-field grading, and a human review sheet: `segurai eval-intent`.

### Tier 1 check suite (M2)

- Every rule an action breaks is reported as a finding: operation, target, per-action scale, session total, irreversibility, and conditions.
- `Check` tests a condition against the evidence an action reports. Missing evidence is "unverifiable", never a violation.
- `max_total` caps the records changed across a whole session.
- 20 seeded scenarios: 10 of 10 violations caught for the right reason, 0 of 10 false positives, 0.15 ms per checked action at p99. Run them with `segurai eval-tier1`.

### Pilot kit (M5)

- Dockerfile for the collector and web view: an unprivileged user, a health check, and everything stored in one volume.
- `deploy/compose.yaml`: refuses to start without a token, binds to localhost only, read-only filesystem, no privilege escalation.
- The CLI reads `SEGURAI_DB`, `SEGURAI_KEY`, `SEGURAI_HOST` and `SEGURAI_PORT`. `collect` and `ui` refuse to listen beyond the local machine without a token unless `--insecure-no-token` is passed.
- `segurai backup` takes a consistent copy of the database using SQLite's online backup.
- `docs/PILOT_RUNBOOK.md`: day-0 setup, the weekly review template, the day-30 wrap-up, data handling and troubleshooting.

### Scope-creep report (M6)

- `segurai report` compares granted with used permissions over a window, per agent and per person's sessions: operations never used, targets never touched, wildcards used for only a few resources, size limits against the largest real change, and irreversible actions never needed.
- Proposes a tightened scope that only ever removes, with evidence (sessions, actions, first and last seen, example action ids) and a confidence rating based on how much activity was observed.
- Grants come from warrants or a grants file exported from an identity provider. Actions in observed chains count as use against those grants.
- Output as Markdown, standalone HTML, JSON, or a CSV with one row per unused permission.

### Tier 2 judge (M4)

- For actions Tier 1 flagged, one Claude call decides `within_intent`, `outside_intent` or `needs_human`, with a confidence, a plain reason and the clause it turns on. It is shown the request, contract, chain, action, findings and recent history.
- Verdicts are stored beside Tier 1's findings and never change them. Agent-written text is passed as data inside tags it cannot close.
- Run it with `segurai judge <session>` (the paid call needs `--yes`), or live with `JudgeListener`.
- 50 labeled cases, 27 of them ambiguous and 3 with planted prompt injection. `segurai eval-judge` scores agreement and dangerous misses against the M4 target.
- The intent compiler and the judge now share one structured Claude call (`_claude.py`).

### Zero-integration path

- The collector rebuilds existing OpenTelemetry GenAI spans (`invoke_agent`, `execute_tool`) from any framework into an observed chain per trace, with no Segurai code involved. Spans may arrive in any order.
- Observed chains are labeled as such everywhere: no scope, no signatures, and every action marked unverifiable. A trace carrying real warrants is never also built as observed.

### Packaging

- Apache-2.0 LICENSE, `py.typed`, PyPI classifiers, and CI across Linux, Windows and macOS on Python 3.10–3.13 with lint, tests, the Tier 1 suite and a strict package check.

### Web view

- `segurai ui`: one page per session with the request and its contract beside the chain, findings inline, and signatures re-verified on each load. The pages have no scripts and use a strict Content-Security-Policy.
