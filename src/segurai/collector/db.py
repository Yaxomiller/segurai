"""The two databases the store runs on: SQLite (the default) and PostgreSQL.

The store is written once, in the SQL both understand, with ``?`` for
parameters. Each class here opens one kind of database and smooths over the
few places they differ:

=====================  ======================  ==============================
                       SQLite                  PostgreSQL
=====================  ======================  ==============================
parameters             ``?``                   ``%s`` (translated)
insertion order        ``rowid``               a hidden ``ord`` column
text search            ``LIKE`` ignores case   ``ILIKE`` (translated)
column types           INTEGER, BLOB           BIGINT, BYTEA (translated)
"did anything change"  data_version + changes  the write-ahead log position
two writers at once    one writer per file     an advisory lock on the log
backups                ``segurai backup``      ``pg_dump``
=====================  ======================  ==============================

SQLite suits one server and a pilot: nothing to run, a single file to back
up. PostgreSQL suits several servers sharing one database, managed backups,
and the database tooling a company already has. Records, hashes and audits
are identical on both, so a deployment can start on one and move to the
other.
"""

from __future__ import annotations

import re
import sqlite3
from decimal import Decimal
from typing import Any, Iterator, Sequence
from urllib.parse import urlsplit, urlunsplit

__all__ = ["open_database", "is_database_url", "redact_url", "SQLiteDatabase", "PostgresDatabase"]

_URL_SCHEMES = ("postgresql://", "postgres://")

#: Any fixed number works; it only has to be the same for every Segurai server
#: sharing a database. ("SEGU" in ASCII.)
_LEDGER_LOCK = 0x53454755


def is_database_url(target: str) -> bool:
    return str(target).startswith(_URL_SCHEMES)


def redact_url(target: str) -> str:
    """The URL without its password, for logs and screens."""
    if not is_database_url(target):
        return str(target)
    parts = urlsplit(str(target))
    if parts.password is None:
        return str(target)
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    return urlunsplit(parts._replace(netloc=f"{parts.username}:***@{host}"))


def open_database(target: str) -> SQLiteDatabase | PostgresDatabase:
    """A PostgreSQL URL opens PostgreSQL; anything else is a SQLite file (or ``:memory:``)."""
    return PostgresDatabase(target) if is_database_url(target) else SQLiteDatabase(target)


# ---- SQLite ----------------------------------------------------------------------

class SQLiteDatabase:
    dialect = "sqlite"
    order_column = "rowid"

    def __init__(self, path: str):
        self.where = str(path)
        # check_same_thread=False lets one store serve an agent whose steps run
        # on a thread pool (LangGraph does this for parallel branches). The
        # store's lock makes each transaction atomic across those threads.
        self.conn = sqlite3.connect(self.where, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        return self.conn.execute(sql, tuple(params))

    def script(self, sql: str) -> None:
        self.conn.executescript(sql)

    def begin(self) -> None:
        """Nothing to do: SQLite starts the transaction with the first write."""

    def commit(self) -> None:
        self.conn.commit()

    def rollback(self) -> None:
        self.conn.rollback()

    def end_read(self) -> None:
        """Nothing to do: SQLite starts a transaction only for a write."""

    def close(self) -> None:
        self.conn.close()

    def columns(self, table: str) -> list[str]:
        return [r["name"] for r in self.conn.execute(f"PRAGMA table_info({table})")]

    def add_column(self, table: str, column: str, sql_type: str) -> None:
        self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {sql_type}")

    def prepare(self) -> None:
        """Nothing beyond the shared schema."""

    def lock_ledger(self) -> None:
        """Nothing to do: SQLite lets one connection write to a file at a time."""

    def change_marker(self) -> tuple[Any, ...]:
        # data_version moves when ANOTHER connection commits to the file;
        # total_changes counts every row THIS connection changed, including by
        # direct SQL. Together they let a cache prove nothing changed.
        version = self.conn.execute("PRAGMA data_version").fetchone()[0]
        return int(version), int(self.conn.total_changes)

    def backup(self, path: str) -> None:
        # SQLite's online backup copies a consistent snapshot, even mid-write;
        # copying the file directly can catch a write half-way through.
        target = sqlite3.connect(str(path))
        try:
            self.conn.backup(target)
        finally:
            target.close()


# ---- PostgreSQL --------------------------------------------------------------------

class Row:
    """A result row readable by name or by position, like ``sqlite3.Row``."""

    __slots__ = ("_index", "_values")

    def __init__(self, index: dict[str, int], values: Sequence[Any]):
        self._index = index
        self._values = tuple(_plain(v) for v in values)

    def __getitem__(self, key: int | str) -> Any:
        return self._values[key] if isinstance(key, int) else self._values[self._index[key]]

    def keys(self) -> list[str]:
        return list(self._index)

    def __iter__(self) -> Iterator[Any]:
        return iter(self._values)

    def __len__(self) -> int:
        return len(self._values)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"Row({dict(zip(self._index, self._values, strict=True))})"


def _plain(value: Any) -> Any:
    # SUM() of an integer column is NUMERIC in PostgreSQL; SQLite gives an int.
    if isinstance(value, Decimal) and value == value.to_integral_value():
        return int(value)
    if isinstance(value, memoryview):
        return bytes(value)
    return value


def _row_factory(cursor: Any):
    index = {d.name: i for i, d in enumerate(cursor.description or ())}
    return lambda values: Row(index, values)


_ROWID = re.compile(r"\browid\b")
_LIKE = re.compile(r"\bLIKE\b")
_AUTOINCREMENT = re.compile(r"\bINTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT\b", re.IGNORECASE)
_INTEGER = re.compile(r"\bINTEGER\b")
_BLOB = re.compile(r"\bBLOB\b")


def translate_query(sql: str, has_params: bool) -> str:
    """The store's SQL, as PostgreSQL wants it."""
    sql = _ROWID.sub("ord", sql)
    sql = _LIKE.sub("ILIKE", sql)               # SQLite's LIKE ignores case; keep searches the same
    if has_params:
        # psycopg reads % as the start of a placeholder whenever parameters are
        # passed, so a literal % (in a LIKE pattern) must be doubled first.
        sql = sql.replace("%", "%%").replace("?", "%s")
    return sql


def translate_types(sql: str) -> str:
    """SQLite column types as PostgreSQL ones."""
    sql = _AUTOINCREMENT.sub("BIGSERIAL PRIMARY KEY", sql)
    sql = _INTEGER.sub("BIGINT", sql)           # timestamps in ms and counts can pass 2**31
    return _BLOB.sub("BYTEA", sql)


class PostgresDatabase:
    dialect = "postgres"
    order_column = "ord"

    def __init__(self, url: str):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover - only without the optional package
            raise ImportError("a PostgreSQL database needs: pip install 'segurai[postgres]'") from exc
        self._psycopg = psycopg
        self._url = url
        self.where = redact_url(url)
        self._sent = 0              # statements of the current transaction the server has run
        self.conn = self._connect()

    def _connect(self) -> Any:
        return self._psycopg.connect(self._url, row_factory=_row_factory, autocommit=False)

    def _live(self) -> Any:
        # A server restart or a dropped network leaves the connection broken.
        # Reconnect - but never half-way through a transaction: the statements
        # already run were lost with the old connection, and running the rest
        # on a new one would commit half a record.
        if self.conn.broken or self.conn.closed:
            if self._sent:
                raise self._psycopg.OperationalError("the database connection was lost during a write")
            self.conn = self._connect()
        return self.conn

    def begin(self) -> None:
        """A write is starting: its statements must commit together or not at all."""
        self._sent = 0

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
        values = tuple(int(v) if isinstance(v, bool) else v for v in params)
        query = translate_query(sql, bool(values))
        try:
            try:
                cursor = self._live().execute(query, values or None)
            except self._psycopg.OperationalError:
                if self._sent or not self.conn.broken:
                    raise
                # The connection had died before this transaction ran anything
                # (a restarted server, an idle connection cut by a firewall).
                # Nothing is lost, so reconnect and try once more.
                cursor = self._live().execute(query, values or None)
        except self._psycopg.Error:
            # PostgreSQL refuses every later statement of a failed transaction;
            # end it, so the error stays with the call that caused it.
            self.rollback()
            raise
        self._sent += 1
        return cursor

    def script(self, sql: str) -> None:
        self._live().execute(translate_types(sql))

    def commit(self) -> None:
        self._sent = 0
        self.conn.commit()

    def rollback(self) -> None:
        self._sent = 0
        if not self.conn.closed and not self.conn.broken:
            self.conn.rollback()

    def end_read(self) -> None:
        # psycopg opens a transaction even for a SELECT; close it so the
        # connection isn't left "idle in transaction", holding locks.
        self._sent = 0
        if self.conn.info.transaction_status == self._psycopg.pq.TransactionStatus.INTRANS:
            self.conn.commit()

    def close(self) -> None:
        self.conn.close()

    def columns(self, table: str) -> list[str]:
        rows = self.execute("SELECT column_name FROM information_schema.columns "
                            "WHERE table_schema = current_schema() AND table_name = ? "
                            "ORDER BY ordinal_position", (table,)).fetchall()
        return [r[0] for r in rows]

    def add_column(self, table: str, column: str, sql_type: str) -> None:
        self.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {column} {translate_types(sql_type)}")

    def prepare(self) -> None:
        # PostgreSQL has no rowid. Actions get a hidden counter instead, which
        # the alert worker's cursor and same-instant ordering rely on. It is
        # never part of a record's hash (see ledger.HIDDEN_COLUMNS).
        self.execute("ALTER TABLE actions ADD COLUMN IF NOT EXISTS ord BIGSERIAL")
        self.execute("CREATE INDEX IF NOT EXISTS idx_actions_ord ON actions(ord)")

    def lock_ledger(self) -> None:
        # Several servers may share this database. Each log entry names the one
        # before it, so two appending at once would fork the chain; this lock,
        # held until the transaction ends, makes them take turns.
        self.execute(f"SELECT pg_advisory_xact_lock({_LEDGER_LOCK})")

    def change_marker(self) -> tuple[Any, ...] | None:
        # The write-ahead log moves on every committed change, to any table, by
        # anyone. Conservative - unrelated writes count too - but never wrong.
        try:
            row = self.execute("SELECT pg_current_wal_lsn()::text").fetchone()
            self.end_read()
            return ("wal", row[0])
        except self._psycopg.Error:
            return None                  # e.g. a read replica: don't cache at all

    def backup(self, path: str) -> None:
        raise ValueError("segurai backup copies SQLite files; for PostgreSQL use pg_dump "
                         "(or your provider's managed backups)")
