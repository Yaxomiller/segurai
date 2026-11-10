"""Storage.

SQLite by default: a pilot's whole dataset fits in a file, and a file you can
open with any tool beats infrastructure you have to run. Give a
``postgresql://`` URL instead and the same store runs on PostgreSQL, for
several servers sharing one database and the backups a company already
manages. The SQL is written once; db.py smooths over the differences.

The tables:
    sessions    - one row per human request
    warrants    - one row per delegation hop (parent_id links them into a tree)
    actions     - one row per thing an agent did, with the admission verdict
    verdicts    - the Tier 2 judge's view of flagged actions
    ledger      - the tamper-evident hash chain over all of the above
    checkpoints - signed statements of what the chain looked like at a moment

Every write goes through :meth:`Store._write_row`, which stores the row AND
appends one entry to the ledger in the same transaction. Editing or deleting
a row afterwards no longer goes unnoticed: see ledger.py for how that works,
and :meth:`Store.audit` for the check.
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from ..models import NON_MUTATING, ActionRecord, Finding, Scope, Warrant, utcnow
from .db import open_database
from .ledger import (
    GENESIS,
    HIDDEN_COLUMNS,
    LOGGED_KINDS,
    AuditProblem,
    AuditReport,
    Checkpoint,
    LedgerEntry,
    entry_hash,
    payload_hash,
    row_payload,
)

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

-- The tamper-evident log: one entry per record written, each hash covering
-- the entry before it. See ledger.py.
CREATE TABLE IF NOT EXISTS ledger (
    seq            INTEGER PRIMARY KEY,
    at             TEXT NOT NULL,
    kind           TEXT NOT NULL,
    ref_id         TEXT NOT NULL,
    payload_hash   TEXT NOT NULL,
    prev_hash      TEXT NOT NULL,
    entry_hash     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ledger_ref ON ledger(kind, ref_id);

-- Signed statements of the head of the chain at a moment. The signing key is
-- not in this database, so rebuilding the chain is not enough to hide a change.
CREATE TABLE IF NOT EXISTS checkpoints (
    seq            INTEGER PRIMARY KEY,
    head           TEXT NOT NULL,
    created_at     TEXT NOT NULL,
    key_id         TEXT,
    signature      BLOB
);

-- Alerts waiting to go out, and what happened to them (alerts.py). Operational,
-- not evidence, so not in the tamper-evident log. The unique key means the
-- same alert can never be queued twice, however many workers run.
CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    kind            TEXT NOT NULL,
    ref             TEXT NOT NULL,
    channel         TEXT NOT NULL,
    body_json       TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at TEXT NOT NULL,
    sent_at         TEXT,
    failed_at       TEXT,
    last_error      TEXT,
    UNIQUE (kind, ref, channel)
);
CREATE INDEX IF NOT EXISTS idx_alerts_due ON alerts(sent_at, failed_at, next_attempt_at);

-- Dashboard accounts (collector/auth.py). In the tamper-evident log: who was
-- made an admin, and by whom, is evidence too.
CREATE TABLE IF NOT EXISTS users (
    email           TEXT PRIMARY KEY,
    name            TEXT NOT NULL,
    role            TEXT NOT NULL,
    password_hash   TEXT,
    source          TEXT NOT NULL,
    disabled        INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT NOT NULL,
    updated_by      TEXT NOT NULL
);

-- Who opened which page, and who signed in (or failed to). Also in the log.
CREATE TABLE IF NOT EXISTS access_log (
    access_id       TEXT PRIMARY KEY,
    at              TEXT NOT NULL,
    email           TEXT NOT NULL,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    status          INTEGER NOT NULL,
    ip              TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_access_at ON access_log(at);

-- Signed-in browsers. Only a hash of each session token is kept. Not logged:
-- operational, short-lived, and the sign-in itself is in the access log.
CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash      TEXT PRIMARY KEY,
    email           TEXT NOT NULL,
    csrf            TEXT NOT NULL,
    created_at      TEXT NOT NULL,
    expires_at      TEXT NOT NULL,
    ip              TEXT NOT NULL
);

-- Company sign-ins in progress: single use, valid for ten minutes.
CREATE TABLE IF NOT EXISTS oidc_pending (
    state           TEXT PRIMARY KEY,
    nonce           TEXT NOT NULL,
    verifier        TEXT NOT NULL,
    next            TEXT NOT NULL,
    binding         TEXT NOT NULL,
    created_at      TEXT NOT NULL
);

-- Small named values the server keeps between runs (the alert worker's cursor...).
CREATE TABLE IF NOT EXISTS state (
    name            TEXT PRIMARY KEY,
    value           TEXT NOT NULL
);

-- Every version of the organisation's rules that was ever in force (policy.py).
-- Findings name the version, so an audit can show exactly which rules applied.
CREATE TABLE IF NOT EXISTS policies (
    version        TEXT PRIMARY KEY,
    created_at     TEXT NOT NULL,
    policy_json    TEXT NOT NULL
);
"""

#: Which table each logged kind lives in, and the column holding its id.
_LOGGED_TABLES = {
    "session": ("sessions", "session_id"),
    "warrant": ("warrants", "warrant_id"),
    "action": ("actions", "action_id"),
    "verdict": ("verdicts", "action_id"),
    "policy": ("policies", "version"),
    "user": ("users", "email"),
    "access": ("access_log", "access_id"),
}

#: Columns added after the first release, as (table, column, SQL type). A
#: database created by an older version gets them added on open, so old files
#: keep working instead of failing with "no such column".
_ADDED_COLUMNS = [
    ("warrants", "key_id", "TEXT"),
    ("actions", "blocked", "INTEGER NOT NULL DEFAULT 0"),
    ("actions", "findings_json", "TEXT"),
    # 0.4: the holder's public key, which signs the warrants it delegates.
    ("warrants", "holder_key", "BLOB"),
    # 0.4: who the person behind a session was proven to be (identity.py).
    ("sessions", "identity_json", "TEXT"),
]

class SessionRow:
    __slots__ = ("session_id", "principal", "request", "contract", "started_at", "identity")

    def __init__(self, session_id: str, principal: str, request: str,
                 contract: dict | None, started_at: datetime, identity: dict | None = None):
        self.session_id = session_id
        self.principal = principal
        self.request = request
        self.contract = contract
        self.started_at = started_at
        #: How the principal was proven (identity.Identity.to_dict()), or None
        #: when the calling code only claimed it.
        self.identity = identity

    @property
    def verified(self) -> bool:
        return bool(self.identity)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<Session {self.session_id} {self.principal!r} {self.request!r}>"


class Store:
    """The evidence store.

    ``path`` is a SQLite file, ``":memory:"`` (for tests), or a
    ``postgresql://`` URL (needs ``pip install 'segurai[postgres]'``).
    """

    def __init__(self, path: str | Path = "segurai.db"):
        self._db = open_database(str(path))
        #: Where the data lives, safe to print: a PostgreSQL password is masked.
        self.path = self._db.where
        # One connection, shared by every thread that records (LangGraph runs
        # parallel branches on a pool); the lock gives each transaction the
        # connection to itself.
        self._lock = threading.RLock()
        self._depth = 0
        with self._tx():
            self._db.script(_SCHEMA)
            self._migrate()
            self._db.prepare()
        # Each logged table's columns, for writes that replace a whole row.
        # Hidden bookkeeping columns are the database's, never the record's.
        with self._lock:
            self._columns = {
                table: [c for c in self._db.columns(table) if c not in HIDDEN_COLUMNS]
                for table, _ in _LOGGED_TABLES.values()
            }
            self._db.end_read()

    @property
    def dialect(self) -> str:
        """"sqlite" or "postgres"."""
        return self._db.dialect

    @property
    def _conn(self) -> Any:
        # Direct SQL, for tests that tamper with the database the way an
        # insider would. Takes the store's own ``?`` SQL on either database.
        return self._db

    def _migrate(self) -> None:
        for table, column, sql_type in _ADDED_COLUMNS:
            if column not in self._db.columns(table):
                self._db.add_column(table, column, sql_type)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def backup(self, path: str | Path) -> None:
        """Copy the whole database to ``path``, safely, even while it is being written.

        SQLite only: it uses SQLite's online backup, which copies a consistent
        snapshot (copying the file directly can catch a write half-way
        through). For PostgreSQL, use pg_dump or managed backups.
        """
        with self._lock:
            self._db.backup(str(path))

    @contextmanager
    def _tx(self) -> Iterator[None]:
        """One write: every statement in it commits together, or none does.

        Without this, a write that failed half-way would leave its first
        statements pending, to be committed by whatever wrote next - a
        record without its log entry, which an audit would call tampering.
        """
        with self._lock:
            if self._depth:                       # already inside a write: join it
                self._depth += 1
                try:
                    yield
                finally:
                    self._depth -= 1
                return
            self._depth = 1
            self._db.begin()
            try:
                yield
            except BaseException:
                self._db.rollback()
                raise
            else:
                self._db.commit()
            finally:
                self._depth = 0

    def _write(self, sql: str, params: tuple) -> Any:
        with self._tx():
            return self._db.execute(sql, params)

    # ---- writing evidence, and logging it -------------------------------

    def _write_row(self, table: str, values: dict[str, Any], kind: str, ref_id: str) -> None:
        """Store one record and append its ledger entry, together or not at all.

        Both happen in a single transaction, so there is no moment where a
        record exists without its entry (which would look like tampering) or
        an entry exists without its record (which would look like a deletion).
        """
        columns = tuple(values)
        key = _LOGGED_TABLES[kind][1]
        # An upsert that sets EVERY column - those not given take their
        # default, exactly as a fresh insert would - so a rewrite replaces the
        # whole record (what the log's hash describes), while the row keeps its
        # place in insertion order (which the alert cursor relies on).
        updates = ", ".join(f"{c} = excluded.{c}" for c in self._columns[table] if c != key)
        sql = (f"INSERT INTO {table} ({', '.join(columns)}) "
               f"VALUES ({', '.join('?' for _ in columns)}) "
               f"ON CONFLICT ({key}) DO UPDATE SET {updates}")
        with self._tx():
            self._db.lock_ledger()                 # before anything else, so writers take turns
            self._db.execute(sql, tuple(values[c] for c in columns))
            self._append_entry(kind, ref_id, row_payload(values))

    def _append_entry(self, kind: str, ref_id: str, payload: dict[str, Any]) -> None:
        """Append one entry. Caller is inside a write (``_tx``) holding the ledger lock.

        Writing the identical record twice appends nothing: the collector
        re-ingests the same spans whenever a trace arrives in pieces, and
        that is not a new fact. Writing a record whose contents CHANGED does
        append - an amendment is a fact, and the earlier entry stays where it
        is, because the log only ever grows.
        """
        body = payload_hash(payload)
        latest = self._db.execute(
            "SELECT payload_hash FROM ledger WHERE kind = ? AND ref_id = ? "
            "ORDER BY seq DESC LIMIT 1", (kind, ref_id)).fetchone()
        if latest is not None and latest["payload_hash"] == body:
            return

        head = self._db.execute(
            "SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1").fetchone()
        seq = (head["seq"] + 1) if head is not None else 1
        prev = head["entry_hash"] if head is not None else GENESIS
        at = utcnow().isoformat()
        self._db.execute(
            "INSERT INTO ledger VALUES (?,?,?,?,?,?,?)",
            (seq, at, kind, ref_id, body, prev, entry_hash(seq, prev, kind, ref_id, body, at)),
        )

    # ---- reading the log ------------------------------------------------

    def ledger_entries(self, since: int = 0) -> list[LedgerEntry]:
        """Every entry from ``since`` onward, oldest first."""
        rows = self._read("SELECT * FROM ledger WHERE seq > ? ORDER BY seq", (since,))
        return [LedgerEntry(seq=r["seq"], at=r["at"], kind=r["kind"], ref_id=r["ref_id"],
                            payload_hash=r["payload_hash"], prev_hash=r["prev_hash"],
                            entry_hash=r["entry_hash"]) for r in rows]

    def change_marker(self) -> tuple[Any, ...] | None:
        """Changes whenever the database does - through this connection or any other.

        Lets a cache prove nothing changed, rather than assume it. None means
        the database can't tell, and nothing should be cached.
        """
        with self._lock:
            return self._db.change_marker()

    def ledger_head(self) -> tuple[int, str]:
        """The newest entry's sequence number and hash; (0, GENESIS) when empty."""
        rows = self._read("SELECT seq, entry_hash FROM ledger ORDER BY seq DESC LIMIT 1")
        return (rows[0]["seq"], rows[0]["entry_hash"]) if rows else (0, GENESIS)

    def _logged_row(self, kind: str, ref_id: str) -> dict[str, Any] | None:
        """One stored record as plain values, for comparing against its entry."""
        table, id_column = _LOGGED_TABLES[kind]
        rows = self._read(f"SELECT * FROM {table} WHERE {id_column} = ?", (ref_id,))
        return row_payload(dict(rows[0])) if rows else None

    # ---- checkpoints ----------------------------------------------------

    def put_checkpoint(self, authority: Any) -> Checkpoint:
        """Sign the current head of the chain and store it.

        ``authority`` must hold a private key. On a collector that only holds
        the organisation's public key, give it its own key for this purpose
        (``segurai keygen --key ledger.key``): it signs statements about the
        log, never warrants.
        """
        seq, head = self.ledger_head()
        if seq == 0:
            raise ValueError("there is nothing in the log to checkpoint yet")
        checkpoint = Checkpoint(seq=seq, head=head, created_at=utcnow(), key_id=authority.key_id)
        checkpoint = replace(checkpoint, signature=authority.sign_bytes(checkpoint.signing_bytes()))
        self._write(
            "INSERT INTO checkpoints VALUES (?,?,?,?,?) ON CONFLICT (seq) DO UPDATE SET "
            "head = excluded.head, created_at = excluded.created_at, key_id = excluded.key_id, "
            "signature = excluded.signature",
            (checkpoint.seq, checkpoint.head, checkpoint.created_at.isoformat(),
             checkpoint.key_id, checkpoint.signature),
        )
        return checkpoint

    def checkpoints(self) -> list[Checkpoint]:
        rows = self._read("SELECT * FROM checkpoints ORDER BY seq")
        return [Checkpoint(seq=r["seq"], head=r["head"],
                           created_at=datetime.fromisoformat(r["created_at"]),
                           key_id=r["key_id"], signature=r["signature"]) for r in rows]

    # ---- the audit ------------------------------------------------------

    def audit(self, verifier: Any = None, witnessed: list[Checkpoint] | None = None) -> AuditReport:
        """Check the log against itself, against the records, and against the checkpoints.

        ``witnessed`` are checkpoints kept OUTSIDE this database (see
        witness.py) - the strongest check: a rewrite of history they already
        cover is caught even if whoever did it held the signing key and
        replaced every checkpoint stored here.

        ``verifier`` is an Authority holding at least the public half of the
        checkpoint-signing key. Without it the chain and the records are still
        checked, but a wholesale rewrite by someone with database access would
        not be caught - and the report says so.
        """
        report = AuditReport(signatures_checked=verifier is not None)
        entries = self.ledger_entries()
        report.entries = len(entries)

        # 1. The chain against itself: no gaps, each entry links to the one
        #    before it, and each entry's hash matches its own contents.
        prev_hash = GENESIS
        expected_seq = 1
        intact = True
        latest_for: dict[tuple[str, str], LedgerEntry] = {}
        for e in entries:
            if e.seq != expected_seq:
                report.problems.append(AuditProblem(
                    "chain", f"entry {expected_seq} is missing (the next one is {e.seq}); "
                             f"entries were removed", seq=expected_seq))
                intact = False
            if e.prev_hash != prev_hash:
                report.problems.append(AuditProblem(
                    "chain", "this entry does not link to the one before it; entries were "
                             "removed, reordered or edited", seq=e.seq))
                intact = False
            if e.entry_hash != e.recomputed_hash():
                report.problems.append(AuditProblem(
                    "chain", "the entry's own hash does not match its contents; the entry "
                             "was edited", seq=e.seq))
                intact = False
            if intact:
                report.verified_to = e.seq
            prev_hash = e.entry_hash
            expected_seq = e.seq + 1

            key = (e.kind, e.ref_id)
            if key in latest_for:
                report.amendments += 1
            latest_for[key] = e
        report.head = prev_hash

        # 2. The records against the log: each logged record must still exist
        #    and still hash to what was logged.
        for (kind, ref_id), e in sorted(latest_for.items(), key=lambda item: item[1].seq):
            stored = self._logged_row(kind, ref_id)
            if stored is None:
                report.problems.append(AuditProblem(
                    "row", f"this {kind} is in the log but its record is gone; the row was "
                           f"deleted", seq=e.seq, ref_id=ref_id))
                continue
            report.rows_checked += 1
            if payload_hash(stored) != e.payload_hash:
                report.problems.append(AuditProblem(
                    "row", f"this {kind} no longer matches what was logged; the row was "
                           f"edited", seq=e.seq, ref_id=ref_id))

        # 3. Records with no entry at all. Not tampering by itself - a database
        #    written before the log existed has plenty - but worth stating.
        for kind in LOGGED_KINDS:
            table, id_column = _LOGGED_TABLES[kind]
            stored_ids = {r[id_column] for r in self._read(f"SELECT {id_column} FROM {table}")}
            logged_ids = {ref for (k, ref) in latest_for if k == kind}
            report.rows_unlogged += len(stored_ids - logged_ids)

        # 4. The checkpoints: the chain's hash at that point must still be what
        #    was signed, and the signature must check out.
        hash_at = {e.seq: e.entry_hash for e in entries}
        checkpoints = self.checkpoints()
        report.checkpoints = len(checkpoints)
        for cp in checkpoints:
            if cp.seq not in hash_at:
                report.problems.append(AuditProblem(
                    "checkpoint", f"covers entry {cp.seq}, which is not in the log any more",
                    seq=cp.seq))
                continue
            if hash_at[cp.seq] != cp.head:
                report.problems.append(AuditProblem(
                    "checkpoint", "the log's hash at that point is not what was signed; "
                                  "history was rewritten", seq=cp.seq))
                continue
            if verifier is not None:
                try:
                    verifier.verify_bytes(cp.signature or b"", cp.signing_bytes())
                except Exception as exc:
                    report.problems.append(AuditProblem(
                        "checkpoint", f"its signature does not check out: {exc}", seq=cp.seq))
                    continue
            report.checkpoints_verified += 1

        # 5. Checkpoints witnessed outside the database. These were published
        #    as they were made, so the database's owner can't take them back.
        for cp in witnessed or []:
            report.witnessed += 1
            if verifier is not None:
                try:
                    verifier.verify_bytes(cp.signature or b"", cp.signing_bytes())
                except Exception:
                    report.problems.append(AuditProblem(
                        "witness", "a witnessed checkpoint's signature does not check out - it was "
                                   "not made with this organisation's key", seq=cp.seq))
                    continue
            if cp.seq not in hash_at:
                report.problems.append(AuditProblem(
                    "witness", f"a checkpoint witnessed outside the database covers entry {cp.seq}, "
                               f"which is no longer in the log - history was cut short", seq=cp.seq))
                continue
            if hash_at[cp.seq] != cp.head:
                report.problems.append(AuditProblem(
                    "witness", "the log no longer matches a checkpoint witnessed outside the "
                               "database - history was rewritten after it was witnessed", seq=cp.seq))
                continue
            report.witnessed_verified += 1
        return report

    def _read(self, sql: str, params: tuple = ()) -> list[Any]:
        with self._lock:
            rows = self._db.execute(sql, params).fetchall()
            if not self._depth:
                self._db.end_read()
            return rows

    # ---- sessions ----------------------------------------------------

    def put_session(self, session_id: str, principal: str, request: str,
                    contract: dict | None, started_at: datetime,
                    identity: dict | None = None) -> None:
        self._write_row("sessions", {
            "session_id": session_id,
            "principal": principal,
            "request": request,
            "contract_json": json.dumps(contract) if contract is not None else None,
            "started_at": started_at.isoformat(),
            # Only written when proven, so sessions hash as they always did
            # otherwise (see ledger.LATER_COLUMNS).
            **({"identity_json": json.dumps(identity, sort_keys=True)} if identity else {}),
        }, kind="session", ref_id=session_id)

    def get_session(self, session_id: str) -> SessionRow | None:
        rows = self._read("SELECT * FROM sessions WHERE session_id = ?", (session_id,))
        return _row_to_session(rows[0]) if rows else None

    def sessions_since(self, since: datetime) -> list[SessionRow]:
        """Every session that started at or after ``since``, oldest first.

        Timestamps are stored as UTC ISO text, which sorts in time order, so
        the database can compare them directly.
        """
        rows = self._read("SELECT * FROM sessions WHERE started_at >= ? ORDER BY started_at",
                          (since.isoformat(),))
        return [_row_to_session(r) for r in rows]

    def search_sessions(self, *, q: str | None = None, agent: str | None = None,
                        outcome: str | None = None, principal: str | None = None,
                        limit: int = 50, offset: int = 0) -> tuple[list[SessionRow], int]:
        """Sessions matching the filters, newest first, and how many match in all.

        Matching happens in the database, so a page costs the same however
        many requests have been recorded.
        """
        def like(text: str) -> str:
            escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            return f"%{escaped}%"

        where, params = [], []
        if q:
            where.append("(s.request LIKE ? ESCAPE '\\' OR s.principal LIKE ? ESCAPE '\\' "
                         "OR s.session_id LIKE ? ESCAPE '\\')")
            params += [like(q)] * 3
        if principal:
            where.append("s.principal LIKE ? ESCAPE '\\'")
            params.append(like(principal))
        if agent:
            where.append("EXISTS (SELECT 1 FROM warrants w WHERE w.session_id = s.session_id "
                         "AND w.holder LIKE ? ESCAPE '\\')")
            params.append(like(agent))
        flagged = "EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.session_id AND a.allowed = 0"
        unverifiable = ("EXISTS (SELECT 1 FROM actions a WHERE a.session_id = s.session_id "
                        "AND a.findings_json LIKE '%\"status\": \"unverifiable\"%' "
                        "AND a.findings_json NOT LIKE '%\"check\": \"warrant\"%')")
        conditions = {
            "flagged": flagged + " AND a.blocked = 0)",
            "blocked": flagged + " AND a.blocked = 1)",
            "review": unverifiable,
            "clean": "NOT " + flagged + ") AND NOT " + unverifiable,
            "verified": "s.identity_json IS NOT NULL",
        }
        if outcome in conditions:
            where.append(conditions[outcome])
        clause = (" WHERE " + " AND ".join(where)) if where else ""
        total = int(self._read(f"SELECT COUNT(*) AS n FROM sessions s{clause}", tuple(params))[0]["n"])
        rows = self._read(f"SELECT s.* FROM sessions s{clause} ORDER BY s.started_at DESC LIMIT ? OFFSET ?",
                          (*params, max(1, min(limit, 500)), max(0, offset)))
        return [_row_to_session(r) for r in rows], total

    def stats(self) -> dict[str, int]:
        """Headline counts across everything recorded."""
        row = self._read(
            "SELECT (SELECT COUNT(*) FROM sessions) AS sessions, COUNT(*) AS actions, "
            "COALESCE(SUM(CASE WHEN allowed = 0 AND blocked = 0 THEN 1 ELSE 0 END), 0) AS flagged, "
            "COALESCE(SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END), 0) AS blocked, "
            "COALESCE(SUM(CASE WHEN findings_json LIKE '%\"status\": \"unverifiable\"%' "
            "AND findings_json NOT LIKE '%\"check\": \"warrant\"%' THEN 1 ELSE 0 END), 0) AS unk "
            "FROM actions")[0]
        return {k: int(row[k]) for k in ("sessions", "actions", "flagged", "blocked", "unk")}

    def sessions(self, limit: int = 50) -> list[SessionRow]:
        rows = self._read("SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,))
        return [_row_to_session(r) for r in rows]

    # ---- warrants ----------------------------------------------------

    def put_warrant(self, w: Warrant) -> None:
        self._write_row("warrants", {
            "warrant_id": w.warrant_id,
            "session_id": w.session_id,
            "root_principal": w.root_principal,
            "holder": w.holder,
            "scope_json": json.dumps(w.scope.to_dict()),
            "issued_at": w.issued_at.isoformat(),
            "expires_at": w.expires_at.isoformat(),
            "parent_id": w.parent_id,
            "depth": w.depth,
            "signature": w.signature,
            "key_id": w.key_id,
            # Left out when absent, so the row hashes as it would have before
            # holder keys existed (see ledger.LATER_COLUMNS).
            **({"holder_key": w.holder_key} if w.holder_key is not None else {}),
        }, kind="warrant", ref_id=w.warrant_id)

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
        self._write_row("actions", {
            "action_id": a.action_id,
            "session_id": a.session_id,
            "warrant_id": a.warrant_id,
            "actor": a.actor,
            "operation": a.operation,
            "resource": a.resource,
            "scale": a.scale,
            "irreversible": int(a.irreversible),
            "at": a.at.isoformat(),
            "allowed": int(a.allowed),
            "violation": a.violation,
            # default=str: a caller's detail may hold dates or other objects
            # JSON cannot encode; storing their text beats losing the action.
            "detail_json": json.dumps(a.detail or {}, default=str),
            "blocked": int(a.blocked),
            "findings_json": json.dumps([f.to_dict() for f in a.findings]),
        }, kind="action", ref_id=a.action_id)

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

    # ---- dashboard accounts (auth.py) ----------------------------------------

    def put_user(self, email: str, name: str, role: str, password_hash: str | None, source: str,
                 *, disabled: bool, by: str) -> None:
        self._write_row("users", {
            "email": email, "name": name, "role": role, "password_hash": password_hash,
            "source": source, "disabled": int(disabled), "updated_at": utcnow().isoformat(),
            "updated_by": by,
        }, kind="user", ref_id=email)

    def get_user(self, email: str) -> dict | None:
        rows = self._read("SELECT * FROM users WHERE email = ?", (email,))
        return dict(rows[0]) if rows else None

    def users(self) -> list[dict]:
        return [dict(r) for r in self._read("SELECT * FROM users ORDER BY email")]

    def put_web_session(self, token_hash: str, email: str, csrf: str, expires_at: datetime, ip: str) -> None:
        now = utcnow().isoformat()
        with self._tx():
            # Expired sessions are swept whenever a new one starts.
            self._db.execute("DELETE FROM web_sessions WHERE expires_at <= ?", (now,))
            self._db.execute("INSERT INTO web_sessions VALUES (?, ?, ?, ?, ?, ?)",
                             (token_hash, email, csrf, now, expires_at.isoformat(), ip))

    def get_web_session(self, token_hash: str) -> dict | None:
        rows = self._read("SELECT * FROM web_sessions WHERE token_hash = ?", (token_hash,))
        return dict(rows[0]) if rows else None

    def end_web_session(self, token_hash: str) -> None:
        self._write("DELETE FROM web_sessions WHERE token_hash = ?", (token_hash,))

    def end_web_sessions(self, email: str) -> None:
        self._write("DELETE FROM web_sessions WHERE email = ?", (email,))

    def put_oidc_pending(self, state: str, nonce: str, verifier: str, next_path: str, binding: str) -> None:
        cutoff = (utcnow() - timedelta(minutes=10)).isoformat()
        with self._tx():
            self._db.execute("DELETE FROM oidc_pending WHERE created_at < ?", (cutoff,))
            self._db.execute("INSERT INTO oidc_pending VALUES (?, ?, ?, ?, ?, ?)",
                             (state, nonce, verifier, next_path, binding, utcnow().isoformat()))

    def take_oidc_pending(self, state: str) -> dict | None:
        """The sign-in started with ``state``, removed as it is read: it can't be used twice.

        Only the caller whose DELETE removed the row gets it. With several
        servers on one database, two racing to finish the same sign-in can
        both read it, but only one can delete it.
        """
        cutoff = (utcnow() - timedelta(minutes=10)).isoformat()
        with self._tx():
            rows = self._db.execute("SELECT * FROM oidc_pending WHERE state = ? AND created_at >= ?",
                                    (state, cutoff)).fetchall()
            taken = self._db.execute("DELETE FROM oidc_pending WHERE state = ?", (state,)).rowcount
        return dict(rows[0]) if rows and taken == 1 else None

    def put_access(self, access_id: str, email: str, method: str, path: str, status: int, ip: str) -> None:
        self._write_row("access_log", {
            "access_id": access_id, "at": utcnow().isoformat(), "email": email, "method": method,
            "path": path, "status": status, "ip": ip,
        }, kind="access", ref_id=access_id)

    def access_log(self, limit: int = 200, email: str | None = None) -> list[dict]:
        if email:
            rows = self._read("SELECT * FROM access_log WHERE email = ? ORDER BY at DESC LIMIT ?",
                              (email, limit))
        else:
            rows = self._read("SELECT * FROM access_log ORDER BY at DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]

    # ---- alerts (alerts.py) -----------------------------------------------

    def get_state(self, name: str, default: str | None = None) -> str | None:
        rows = self._read("SELECT value FROM state WHERE name = ?", (name,))
        return rows[0]["value"] if rows else default

    def set_state(self, name: str, value: str) -> None:
        self._write("INSERT INTO state (name, value) VALUES (?, ?) "
                    "ON CONFLICT (name) DO UPDATE SET value = excluded.value", (name, value))

    def alert_cursor(self) -> int:
        """How far through the actions table the alert worker has read."""
        value = self.get_state("alerts.cursor")
        if value is None:
            # A new deployment starts at the end: alerting on months of
            # history the first time the worker starts would be noise.
            rows = self._read("SELECT COALESCE(MAX(rowid), 0) AS last FROM actions")
            position = int(rows[0]["last"])
            self.set_state("alerts.cursor", str(position))
            return position
        return int(value)

    def set_alert_cursor(self, position: int) -> None:
        self.set_state("alerts.cursor", str(position))

    def actions_after(self, position: int, limit: int = 500) -> list[tuple[int, ActionRecord]]:
        """Actions stored after ``position``, in the order they were stored."""
        rows = self._read("SELECT rowid AS pos, * FROM actions WHERE rowid > ? ORDER BY rowid LIMIT ?",
                          (position, limit))
        return [(int(r["pos"]), _row_to_action(r)) for r in rows]

    def queue_alert(self, kind: str, ref: str, channel: str, body: dict) -> int:
        """Queue one alert; 1 if queued, 0 if that exact alert was queued before."""
        now = utcnow().isoformat()
        cursor = self._write(
            "INSERT INTO alerts (kind, ref, channel, body_json, created_at, next_attempt_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT (kind, ref, channel) DO NOTHING",
            (kind, ref, channel, json.dumps(body), now, now))
        return cursor.rowcount

    def due_alerts(self, limit: int = 50) -> list[dict]:
        rows = self._read(
            "SELECT * FROM alerts WHERE sent_at IS NULL AND failed_at IS NULL AND next_attempt_at <= ? "
            "ORDER BY id LIMIT ?", (utcnow().isoformat(), limit))
        return [{"id": r["id"], "kind": r["kind"], "ref": r["ref"], "channel": r["channel"],
                 "attempts": r["attempts"], "next_attempt_at": r["next_attempt_at"],
                 "body": json.loads(r["body_json"])} for r in rows]

    def claim_alert(self, alert_id: int, seen_next_attempt_at: str, lease: timedelta) -> bool:
        """Take one due alert for delivery, so no other server sends it too.

        A compare-and-set on ``next_attempt_at``: only the caller whose update
        still finds the value it read wins. The winner pushes the alert out of
        reach for ``lease``. If it dies before finishing, the alert falls due
        again then: delivered at least once, and twice only if a send outlives
        its lease.
        """
        until = (utcnow() + lease).isoformat()
        cursor = self._write(
            "UPDATE alerts SET next_attempt_at = ? WHERE id = ? AND next_attempt_at = ? "
            "AND sent_at IS NULL AND failed_at IS NULL", (until, alert_id, seen_next_attempt_at))
        return cursor.rowcount == 1

    def finish_alert(self, alert_id: int, *, error: str | None = None, give_up: bool = False,
                     retry_in: timedelta | None = None) -> None:
        """Record a delivery: sent (no error), retry later, or given up for good."""
        now = utcnow()
        if error is None:
            self._write("UPDATE alerts SET sent_at = ?, attempts = attempts + 1, last_error = NULL "
                        "WHERE id = ?", (now.isoformat(), alert_id))
        elif give_up:
            self._write("UPDATE alerts SET failed_at = ?, attempts = attempts + 1, last_error = ? "
                        "WHERE id = ?", (now.isoformat(), error, alert_id))
        else:
            self._write("UPDATE alerts SET attempts = attempts + 1, last_error = ?, next_attempt_at = ? "
                        "WHERE id = ?", (error, (now + (retry_in or timedelta(seconds=30))).isoformat(), alert_id))

    def alerts(self, limit: int = 100) -> list[dict]:
        """Recent alerts with their delivery state, newest first (for the dashboard)."""
        rows = self._read("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        return [{"id": r["id"], "kind": r["kind"], "ref": r["ref"], "channel": r["channel"],
                 "created_at": r["created_at"], "attempts": r["attempts"], "sent_at": r["sent_at"],
                 "failed_at": r["failed_at"], "last_error": r["last_error"],
                 "headline": json.loads(r["body_json"]).get("headline", "")} for r in rows]

    # ---- organisation rules ---------------------------------------------

    def put_policy(self, policy: Any) -> None:
        """Record a version of the organisation's rules, once per version."""
        if self._read("SELECT 1 FROM policies WHERE version = ?", (policy.version,)):
            return
        self._write_row("policies", {
            "version": policy.version,
            "created_at": utcnow().isoformat(),
            "policy_json": json.dumps(policy.to_dict(), sort_keys=True),
        }, kind="policy", ref_id=policy.version)

    def get_policy(self, version: str) -> dict | None:
        rows = self._read("SELECT * FROM policies WHERE version = ?", (version,))
        return json.loads(rows[0]["policy_json"]) if rows else None

    def policies(self) -> list[tuple[str, str, dict]]:
        """(version, first recorded, rules) for every version, oldest first."""
        rows = self._read("SELECT * FROM policies ORDER BY created_at")
        return [(r["version"], r["created_at"], json.loads(r["policy_json"])) for r in rows]

    # ---- verdicts (Tier 2) ---------------------------------------------

    def put_verdict(self, verdict) -> None:
        """Store a judge's Verdict. Judging an action again replaces its old verdict."""
        d = verdict.to_dict()
        self._write_row("verdicts", {
            "action_id": d["action_id"],
            "session_id": d["session_id"],
            "verdict": d["verdict"],
            "confidence": d["confidence"],
            "reasoning": d["reasoning"],
            "clause": d["clause"],
            "model": d["model"],
            "prompt_version": d["prompt_version"],
            "judged_at": d["judged_at"],
            "latency_ms": d["latency_ms"],
        }, kind="verdict", ref_id=d["action_id"])

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
            "INSERT INTO observed_spans VALUES (?,?,?,?,?,?) ON CONFLICT (span_id) DO UPDATE SET "
            "trace_id = excluded.trace_id, parent_span_id = excluded.parent_span_id, name = excluded.name, "
            "started_at = excluded.started_at, attributes_json = excluded.attributes_json",
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
        self._write("INSERT INTO warrant_traces VALUES (?) ON CONFLICT (trace_id) DO NOTHING", (trace_id,))

    def is_warrant_trace(self, trace_id: str) -> bool:
        return bool(self._read("SELECT 1 FROM warrant_traces WHERE trace_id = ?", (trace_id,)))

    def forget_session(self, session_id: str) -> None:
        """Remove a session with its warrants and actions (used to replace an observed chain)."""
        with self._tx():
            for table in ("actions", "warrants", "sessions"):
                self._db.execute(f"DELETE FROM {table} WHERE session_id = ?", (session_id,))

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


def _row_to_session(row: Any) -> SessionRow:
    return SessionRow(
        session_id=row["session_id"],
        principal=row["principal"],
        request=row["request"],
        contract=json.loads(row["contract_json"]) if row["contract_json"] else None,
        started_at=datetime.fromisoformat(row["started_at"]),
        identity=json.loads(row["identity_json"]) if row["identity_json"] else None,
    )


def _row_to_warrant(row: Any) -> Warrant:
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
        holder_key=bytes(row["holder_key"]) if row["holder_key"] is not None else None,
    )


def _row_to_action(row: Any) -> ActionRecord:
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
