"""Storage.

SQLite, deliberately. At M0 the entire dataset fits in a file, and a file you
can open with any tool beats infrastructure you have to run. The schema is
kept close to what a columnar store would want, so the eventual migration to
Postgres and then ClickHouse is a port rather than a redesign.

Nothing here is append-only or tamper-evident yet. That is a later milestone
and it matters - a log an engineer can edit is not evidence - but it is not
what M0 needs to prove.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Iterable

from ..models import ActionRecord, Scope, Warrant

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
    signature      BLOB
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
    detail_json    TEXT
);
CREATE INDEX IF NOT EXISTS idx_actions_session ON actions(session_id);
CREATE INDEX IF NOT EXISTS idx_actions_warrant ON actions(warrant_id);
CREATE INDEX IF NOT EXISTS idx_actions_flagged ON actions(allowed);
"""


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
        # check_same_thread=False so a single store can serve an agent running
        # across a thread pool; writes are serialized by SQLite itself.
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    # ---- sessions ----------------------------------------------------

    def put_session(self, session_id: str, principal: str, request: str,
                    contract: dict | None, started_at: datetime) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO sessions VALUES (?,?,?,?,?)",
            (session_id, principal, request,
             json.dumps(contract) if contract is not None else None,
             started_at.isoformat()),
        )
        self._conn.commit()

    def get_session(self, session_id: str) -> SessionRow | None:
        row = self._conn.execute(
            "SELECT * FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
        return _row_to_session(row) if row else None

    def sessions(self, limit: int = 50) -> list[SessionRow]:
        rows = self._conn.execute(
            "SELECT * FROM sessions ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [_row_to_session(r) for r in rows]

    # ---- warrants ----------------------------------------------------

    def put_warrant(self, w: Warrant) -> None:
        self._conn.execute(
            "INSERT OR REPLACE INTO warrants VALUES (?,?,?,?,?,?,?,?,?,?)",
            (w.warrant_id, w.session_id, w.root_principal, w.holder,
             json.dumps(w.scope.to_dict()), w.issued_at.isoformat(),
             w.expires_at.isoformat(), w.parent_id, w.depth, w.signature),
        )
        self._conn.commit()

    def get_warrant(self, warrant_id: str) -> Warrant | None:
        row = self._conn.execute(
            "SELECT * FROM warrants WHERE warrant_id = ?", (warrant_id,)
        ).fetchone()
        return _row_to_warrant(row) if row else None

    def warrants_for_session(self, session_id: str) -> list[Warrant]:
        rows = self._conn.execute(
            "SELECT * FROM warrants WHERE session_id = ? ORDER BY depth, issued_at",
            (session_id,),
        ).fetchall()
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
        self._conn.execute(
            "INSERT OR REPLACE INTO actions VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (a.action_id, a.session_id, a.warrant_id, a.actor, a.operation,
             a.resource, a.scale, int(a.irreversible), a.at.isoformat(),
             int(a.allowed), a.violation, json.dumps(a.detail or {})),
        )
        self._conn.commit()

    def actions_for_session(self, session_id: str) -> list[ActionRecord]:
        rows = self._conn.execute(
            "SELECT * FROM actions WHERE session_id = ? ORDER BY at", (session_id,)
        ).fetchall()
        return [_row_to_action(r) for r in rows]

    def violations(self, session_id: str | None = None) -> list[ActionRecord]:
        if session_id:
            rows = self._conn.execute(
                "SELECT * FROM actions WHERE allowed = 0 AND session_id = ? ORDER BY at",
                (session_id,),
            ).fetchall()
        else:
            rows = self._conn.execute(
                "SELECT * FROM actions WHERE allowed = 0 ORDER BY at"
            ).fetchall()
        return [_row_to_action(r) for r in rows]

    # ---- analysis ----------------------------------------------------

    def exercised_scope(self, session_id: str) -> dict[str, set[str]]:
        """What was actually used, as opposed to what was granted.

        This is the raw material for the scope-creep report: the diff between
        this and the granted scope is the product.
        """
        rows = self._conn.execute(
            "SELECT DISTINCT operation, resource FROM actions WHERE session_id = ?",
            (session_id,),
        ).fetchall()
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
        detail=json.loads(row["detail_json"]) if row["detail_json"] else {},
    )
