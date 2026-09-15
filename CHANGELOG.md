# Changelog

All notable changes to this project are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/).

## [0.1.0] — unreleased

The first public release: milestones M0 to M2, plus the intent compiler (M1).

### Chain capture (M0)

- Signed, attenuation-only delegation. Each agent hop gets an Ed25519-signed warrant derived from its parent's, and it can only narrow the parent's scope, never widen it.
- Target patterns are compared as patterns (so `crm.*` can't hide inside `crm.?`), and matching is case-sensitive on every platform.
- Child scopes say only what they narrow; everything else is inherited.
- Signing keys persist beside the database, every warrant names its signing key, and `warrant verify` checks signatures in later runs.
- Actions are recorded with their verdict. The default observe mode records and flags; enforce mode stops the action before it happens and marks it blocked.
- `@warrant.tool` and `ActionSpec` describe tool calls. A call that can't be described counts as a violation.
- Integrations:
  - **LangGraph:** `agent_node` for functions, async nodes and compiled subgraphs, and `ToolGuard` for `ToolNode`.
  - **MCP:** `WarrantedClient` checks calls before they are sent, and `bind_from_meta` continues the chain inside the server.
  - **OpenTelemetry:** spans follow the GenAI conventions and carry the full signed warrant.
- Collector: OTLP/HTTP ingest (protobuf or JSON) that re-verifies every signature, with a bearer token and size limits. Run it with `warrant collect`.
- SQLite storage with automatic migrations, chain reconstruction, and a CLI.

### Intent compiler (M1)

- One Claude call turns a request into a scope contract. It uses structured output, cached instructions, refusal fallbacks, and passes the request in escaped tags.
- Contracts are checked against the organisation's catalog and clamped to the person's real permissions (`ceiling`). If the work changes records but no size is given, the limit fails closed to 1.
- Conditions that the catalog's evidence fields can test are written as Checks.
- 50 labeled eval cases, per-field grading, and a human review sheet: `warrant eval-intent`.

### Tier 1 check suite (M2)

- Every rule an action breaks is reported as a finding: operation, target, per-action scale, session total, irreversibility, and conditions.
- `Check` tests a condition against the evidence an action reports. Missing evidence is "unverifiable", never a violation.
- `max_total` caps the records changed across a whole session.
- 20 seeded scenarios: 10 of 10 violations caught for the right reason, 0 of 10 false positives, 0.15 ms per checked action at p99. Run them with `warrant eval-tier1`.

### Scope-creep report (M6)

- `warrant report` compares granted with used permissions over a window, per agent and per person's sessions: operations never used, targets never touched, wildcards used for only a few resources, size limits against the largest real change, and irreversible actions never needed.
- Proposes a tightened scope that only ever removes, with evidence (sessions, actions, first and last seen, example action ids) and a confidence rating based on how much activity was observed.
- Grants come from warrants or a grants file exported from an identity provider. Actions in observed chains count as use against those grants.
- Output as Markdown, standalone HTML, JSON, or a CSV with one row per unused permission.

### Tier 2 judge (M4)

- For actions Tier 1 flagged, one Claude call decides `within_intent`, `outside_intent` or `needs_human`, with a confidence, a plain reason and the clause it turns on. It is shown the request, contract, chain, action, findings and recent history.
- Verdicts are stored beside Tier 1's findings and never change them. Agent-written text is passed as data inside tags it cannot close.
- Run it with `warrant judge <session>` (the paid call needs `--yes`), or live with `JudgeListener`.
- 50 labeled cases, 27 of them ambiguous and 3 with planted prompt injection. `warrant eval-judge` scores agreement and dangerous misses against the M4 target.
- The intent compiler and the judge now share one structured Claude call (`_claude.py`).

### Zero-integration path

- The collector rebuilds existing OpenTelemetry GenAI spans (`invoke_agent`, `execute_tool`) from any framework into an observed chain per trace, with no warrant code involved. Spans may arrive in any order.
- Observed chains are labeled as such everywhere: no scope, no signatures, and every action marked unverifiable. A trace carrying real warrants is never also built as observed.

### Packaging

- Apache-2.0 LICENSE, `py.typed`, PyPI classifiers, and CI across Linux, Windows and macOS on Python 3.10–3.13 with lint, tests, the Tier 1 suite and a strict package check.

### Web view

- `warrant ui`: one page per session with the request and its contract beside the chain, findings inline, and signatures re-verified on each load. The pages have no scripts and use a strict Content-Security-Policy.
