"""Storage.

SQLite, deliberately. At this stage the entire dataset fits in a file, and a
file you can open with any tool beats infrastructure you have to run. The
schema is kept close to what a columnar store would want, so the eventual move
to Postgres and then ClickHouse is a port rather than a redesign.

Three tables:
    sessions  - one row per human request
    warrants  - one row per delegation hop (parent_id links them into a tree)
    actions   - one row per thing an agent did, with the admission verdict

Nothing here is append-only or tamper-evident yet. That is a later milestone
and it matters - a log an engineer can edit is not evidence - but the
signatures already make any edit to a *warrant* detectable.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from datetime import datetime
from pathlib import Path

from ..models import NON_MUTATING, ActionRecord, Finding, Scope, Warrant

__all__ = ["Store", "SessionRow"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id     TEXT PRIMARY KEY,
    principal      TEXT NOT NULL,
    request        TEXT NOT NULL,
    contract_json  TEXT,
    started_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS warrants (
    warrant_id     TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    root_principal TEXT NOT NULL,
    holder         TEXT NOT NULL,
    scope_json     TEXT NOT NULL,
    issued_at      TEXT NOT NULL,
    expires_at     TEXT NOT NULL,
    parent_id      TEXT,
    depth          INTEGER NOT NULL,
    signature      BLOB,
    key_id         TEXT
);
CREATE INDEX IF NOT EXISTS idx_warrants_session ON warrants(session_id);
CREATE INDEX IF NOT EXISTS idx_warrants_parent  ON warrants(parent_id);

CREATE TABLE IF NOT EXISTS actions (
    action_id      TEXT PRIMARY KEY,
    session_id     TEXT NOT NULL,
    warrant_id     TEXT NOT NULL,
    actor          TEXT NOT NULL,
    operation      TEXT NOT NULL,
    resource       TEXT NOT NULL,
    scale          INTEGER NOT NULL,
    irreversible   INTEGER NOT NULL,
    at             TEXT NOT NULL,
    allowed        INTEGER NOT NULL,
    violation      TEXT,
    detail_json    TEXT,
    blocked        INTEGER NOT NULL DEFAULT 0,
    findings_json  TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id);
CREATE INDEX IF NOT EXISTS idx_actions_warrant ON actions(warrant_id);
CREATE INDEX IF NOT EXISTS idx_actions_flagged ON actions(allowed);

-- Spans from existing OpenTelemetry instrumentation, kept so an "observed"
-- chain can be rebuilt as the rest of its trace arrives (see otlp.py).
CREATE TABLE IF NOT EXISTS observed_spans (
    span_id         TEXT PRIMARY KEY,
    trace_id        TEXT NOT NULL,
    parent_span_id  TEXT,
    name            TEXT NOT NULL,
    started_at      TEXT NOT NULL,
    attributes_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_observed_trace ON observed_spans(trace_id);

-- Traces that carried real warrants; those are never rebuilt as observed.
CREATE TABLE IF NOT EXISTS warrant_traces (
    trace_id        TEXT PRIMARY KEY
);

-- Tier 2 verdicts: the judge's view of flagged actions, kept BESIDE the
-- Tier 1 record in the actions table, never instead of it.
CREATE TABLE IF NOT EXISTS verdicts (
    action_id       TEXT PRIMARY KEY,
    session_id      TEXT NOT NULL,
    verdict         TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    reasoning       TEXT NOT NULL,
    clause          TEXT,
    model           TEXT,
    prompt_version  TEXT,
    judged_at       TEXT NOT NULL,
    latency_ms      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_verdicts_session ON verdicts(session_id);
"""

#: Columns added after the first release, as (table, column, SQL type). A
#: database created by an older version gets them added on open, so old files
#: keep working instead of failing with "no such column".
_ADDED_COLUMNS = [
    ("warrants", "key_id", "TEXT"),
    ("actions", "blocked", "INTEGER NOT NULL DEFAULT 0"),
    ("actions", "findings_json", "TEXT"),
]

_WARRANT_COLUMNS = ("warrant_id", "session_id", "root_principal", "holder", "scope_json",
                    "issued_at", "expires_at", "parent_id", "depth", "signature", "key_id")
_ACTION_COLUMNS = ("action_id", "session_id", "warrant_id", "actor", "operation", "resource",
                   "scale", "irreversible", "at", "allowed", "violation", "detail_json",
                   "blocked", "findings_json")


def _insert_sql(table: str, columns: tuple[str, ...]) -> str:
    # Naming the columns (rather than relying on their order) keeps inserts
    # correct on databases whose columns were added by a migration.
    return (f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) "
            f"VALUES ({', '.join('?' for _ in columns)})")


class SessionRow:
    __slots__ = ("session_id", "principal", "request", "contract", "started_at")

    def __init__(self, session_id: str, principal: str, request: str,
                 contract: dict | None, started_at: datetime):
        self.session_id = session_id
        self.principal = principal
        self.request = request
        self.contract = contract
        self.started_at = started_at

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Session {self.session_id} {self.principal!r} {self.request!r}>"


class Store:
    """A SQLite-backed store. Pass ``":memory:"`` for tests."""

    def __init__(self, path: str | Path = "warrant.db"):
        self.path = str(path)
        # check_same_thread=False lets one store serve an agent whose steps run
        # on a thread pool (LangGraph does this for parallel branches). The
        # lock makes each write-and-commit atomic across those threads.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._migrate()
            self._conn.commit()

    def _migrate(self) -> None:
        for table, column, sql_type in _ADDED_COLUMNS:
            existing = {r["name"] for r in self._conn.execute(f"PRAGMA table_info({table})")}
            if column not in existing:
                self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

    def close(self) -> None:
        self._conn.close()

    def _write(self, sql: str, params: tuple) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            self._conn.commit()

    def _read(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # ---- sessions ----------------------------------------------------

    def put_session(self, session_id: str, principal: str, request: str,
                    contract: dict | None, started_at: datetime) -> None:
        self._write(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?)",
            (session_id, principal, request,
             json.dumps(contract) if contract is not None else None,
             started_at.isoformat()),
        )

    def get_session(self, session_id: str) -> SessionRow | None:
        rows = self._read("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        return _row_to_session(rows[0]) if rows else None

    def sessions(self, limit: int = 50) -> list[SessionRow]:
        rows = self._read("SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return [_row_to_session(r) for r in rows]

    # ---- warrants ----------------------------------------------------

    def put_warrant(self, w: Warrant) -> None:
        self._write(
            _insert_sql("warrants", _WARRANT_COLUMNS),
            (w.warrant_id, w.session_id, w.root_principal, w.holder,
             json.dumps(w.scope.to_dict()), w.issued_at.isoformat(),
             w.expires_at.isoformat(), w.parent_id, w.depth, w.signature, w.key_id),
        )

    def get_warrant(self, warrant_id: str) -> Warrant | None:
        rows = self._read("SELECT * FROM warrants WHERE warrant_id = ?", (warrant_id,))
        return _row_to_warrant(rows[0]) if rows else None

    def warrants_for_session(self, session_id: str) -> list[Warrant]:
        rows = self._read(
            "SELECT * FROM warrants WHERE session_id = ? ORDER BY depth, issued_at",
            (session_id,),
        )
        return [_row_to_warrant(r) for r in rows]

    def chain_to(self, warrant_id: str) -> list[Warrant]:
        """Walk parent links from a leaf back to the root. Returns root-to-leaf.

        Detects cycles rather than looping forever - a cycle means someone
        tampered with parent links, which is exactly the thing worth catching.
        """
        chain: list[Warrant] = []
        seen: set[str] = set()
        cursor: str | None = warrant_id
        while cursor is not None:
            if cursor in seen:
                raise ValueError(f"cycle in warrant chain at {cursor}")
            seen.add(cursor)
            w = self.get_warrant(cursor)
            if w is None:
                raise ValueError(f"chain is broken: warrant {cursor} not found")
            chain.append(w)
            cursor = w.parent_id
        chain.reverse()
        return chain

    # ---- actions -----------------------------------------------------

    def put_action(self, a: ActionRecord) -> None:
        self._write(
            _insert_sql("actions", _ACTION_COLUMNS),
            (a.action_id, a.session_id, a.warrant_id, a.actor, a.operation,
             a.resource, a.scale, int(a.irreversible), a.at.isoformat(),
             int(a.allowed), a.violation,
             # default=str: a caller's detail may hold dates or other objects
             # JSON cannot encode; storing their text beats losing the action.
             json.dumps(a.detail or {}, default=str),
             int(a.blocked),
             json.dumps([f.to_dict() for f in a.findings])),
        )

    def actions_for_session(self, session_id: str) -> list[ActionRecord]:
        """A session's actions in the order they were recorded.

        Ties in time (two actions in the same instant) fall back to insertion
        order, so "what came before" is always well defined.
        """
        rows = self._read("SELECT * FROM actions WHERE session_id = ? ORDER BY at, rowid", (session_id,))
        return [_row_to_action(r) for r in rows]

    def violations(self, session_id: str | None = None) -> list[ActionRecord]:
        if session_id:
            rows = self._read(
                "SELECT * FROM actions WHERE allowed = 0 AND session_id = ? ORDER BY at, rowid",
                (session_id,),
            )
        else:
            rows = self._read("SELECT * FROM actions WHERE allowed = 0 ORDER BY at, rowid")
        return [_row_to_action(r) for r in rows]

    # ---- analysis ----------------------------------------------------

    # ---- verdicts (Tier 2) ---------------------------------------------

    def put_verdict(self, verdict) -> None:
        """Store a judge's Verdict. Judging an action again replaces its old verdict."""
        d = verdict.to_dict()
        self._write(
            "INSERT OR REPLACE INTO verdicts VALUES (?,?,?,?,?,?,?,?,?,?)",
            (d["action_id"], d["session_id"], d["verdict"], d["confidence"], d["reasoning"],
             d["clause"], d["model"], d["prompt_version"], d["judged_at"], d["latency_ms"]),
        )

    def verdicts_for_session(self, session_id: str) -> dict:
        """The session's verdicts, keyed by action id."""
        # Imported here, not at the top: the judge module itself imports this one.
        from ..judge.judge import Verdict

        rows = self._read("SELECT * FROM verdicts WHERE session_id = ?", (session_id,))
        return {
            r["action_id"]: Verdict(
                action_id=r["action_id"], session_id=r["session_id"], verdict=r["verdict"],
                confidence=r["confidence"], reasoning=r["reasoning"], clause=r["clause"] or "",
                model=r["model"], prompt_version=r["prompt_version"] or "",
                judged_at=datetime.fromisoformat(r["judged_at"]), latency_ms=r["latency_ms"],
            )
            for r in rows
        }

    # ---- observed spans (zero-integration ingest) ----------------------

    def put_observed_span(self, trace_id: str, span_id: str, parent_span_id: str | None,
                          name: str, started_at: datetime, attributes: dict) -> None:
        self._write(
            "INSERT OR REPLACE INTO observed_spans VALUES (?,?,?,?,?,?)",
            (span_id, trace_id, parent_span_id, name, started_at.isoformat(),
             json.dumps(attributes, sort_keys=True, default=str)),
        )

    def observed_spans(self, trace_id: str) -> list[dict]:
        """Every kept span of one trace, oldest first."""
        rows = self._read("SELECT * FROM observed_spans WHERE trace_id = ? ORDER BY started_at",
                          (trace_id,))
        return [{"span_id": r["span_id"], "parent_span_id": r["parent_span_id"], "name": r["name"],
                 "started_at": datetime.fromisoformat(r["started_at"]),
                 "attributes": json.loads(r["attributes_json"])} for r in rows]

    def mark_warrant_trace(self, trace_id: str) -> None:
        self._write("INSERT OR IGNORE INTO warrant_traces VALUES (?)", (trace_id,))

    def is_warrant_trace(self, trace_id: str) -> bool:
        return bool(self._read("SELECT 1 FROM warrant_traces WHERE trace_id = ?", (trace_id,)))

    def forget_session(self, session_id: str) -> None:
        """Remove a session with its warrants and actions (used to replace an observed chain)."""
        with self._lock:
            for table in ("actions", "warrants", "sessions"):
                self._conn.execute(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))
            self._conn.commit()

    def changed_total(self, session_id: str) -> int:
        """How many records the session's actions have changed so far.

        Reads don't count - scanning 5,000 rows changes nothing - and neither
        do blocked attempts, which never happened. The ``max_total`` rule
        compares each new change against this running total.
        """
        placeholders = ", ".join("?" for _ in NON_MUTATING)
        rows = self._read(
            "SELECT COALESCE(SUM(scale), 0) AS total FROM actions "
            f"WHERE session_id = ? AND blocked = 0 AND operation NOT IN ({placeholders})",
            (session_id, *sorted(NON_MUTATING)),
        )
        return int(rows[0]["total"])

    def exercised_scope(self, session_id: str) -> dict[str, set[str]]:
        """What was actually used, as opposed to what was granted.

        This is the raw material for the scope-creep report: the diff between
        this and the granted scope is the product.
        """
        rows = self._read(
            "SELECT DISTINCT operation, resource FROM actions WHERE session_id = ?",
            (session_id,),
        )
        used: dict[str, set[str]] = {"operations": set(), "targets": set()}
        for r in rows:
            used["operations"].add(r["operation"])
            used["targets"].add(r["resource"])
        return used


def _row_to_session(row: sqlite3.Row) -> SessionRow:
    return SessionRow(
        session_id=row["session_id"],
        principal=row["principal"],
        request=row["request"],
        contract=json.loads(row["contract_json"]) if row["contract_json"] else None,
        started_at=datetime.fromisoformat(row["started_at"]),
    )


def _row_to_warrant(row: sqlite3.Row) -> Warrant:
    return Warrant(
        warrant_id=row["warrant_id"],
        session_id=row["session_id"],
        root_principal=row["root_principal"],
        holder=row["holder"],
        scope=Scope.from_dict(json.loads(row["scope_json"])),
        issued_at=datetime.fromisoformat(row["issued_at"]),
        expires_at=datetime.fromisoformat(row["expires_at"]),
        parent_id=row["parent_id"],
        depth=row["depth"],
        key_id=row["key_id"],
        signature=row["signature"],
    )


def _row_to_action(row: sqlite3.Row) -> ActionRecord:
    return ActionRecord(
        action_id=row["action_id"],
        session_id=row["session_id"],
        warrant_id=row["warrant_id"],
        actor=row["actor"],
        operation=row["operation"],
        resource=row["resource"],
        scale=row["scale"],
        irreversible=bool(row["irreversible"]),
        at=datetime.fromisoformat(row["at"]),
        allowed=bool(row["allowed"]),
        violation=row["violation"],
        blocked=bool(row["blocked"]),
        findings=tuple(Finding.from_dict(f) for f in json.loads(row["findings_json"] or "[]")),
        detail=json.loads(row["detail_json"]) if row["detail_json"] else {},
    )
