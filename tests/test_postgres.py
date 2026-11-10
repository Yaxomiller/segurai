"""The database layer: SQL translation, safe failure, and PostgreSQL itself.

The whole suite runs on PostgreSQL when SEGURAI_TEST_DATABASE names one (CI
does this on Linux). The tests here cover what only a second database
brings: several servers appending to one log at once, a connection that
drops, and passwords that must never be printed.
"""

import os
import threading
from datetime import datetime, timezone

import pytest

import segurai
from segurai.collector.db import (
    is_database_url,
    redact_url,
    translate_query,
    translate_types,
)
from segurai.collector.store import Store
from segurai.config import ConfigError, load_config

TEST_DATABASE = os.environ.get("SEGURAI_TEST_DATABASE", ":memory:")
ON_POSTGRES = is_database_url(TEST_DATABASE)
postgres_only = pytest.mark.skipif(not ON_POSTGRES, reason="set SEGURAI_TEST_DATABASE to a postgresql:// URL")
NOW = datetime(2026, 11, 10, tzinfo=timezone.utc)


# ---- translation (no database needed) ------------------------------------------------

def test_queries_are_translated_for_postgres():
    assert translate_query("SELECT * FROM actions WHERE session_id = ? ORDER BY at, rowid", True) == (
        "SELECT * FROM actions WHERE session_id = %s ORDER BY at, ord")
    # a literal % must be doubled once parameters are passed, and LIKE keeps ignoring case
    assert translate_query("SELECT 1 WHERE a NOT LIKE '%x%' AND b = ?", True) == (
        "SELECT 1 WHERE a NOT ILIKE '%%x%%' AND b = %s")
    assert translate_query("SELECT '%x%'", False) == "SELECT '%x%'"
    assert translate_query("SELECT rowid_count, arrowid FROM t", False) == "SELECT rowid_count, arrowid FROM t"


def test_column_types_are_translated_for_postgres():
    assert translate_types("id INTEGER PRIMARY KEY AUTOINCREMENT, n INTEGER NOT NULL, sig BLOB") == (
        "id BIGSERIAL PRIMARY KEY, n BIGINT NOT NULL, sig BYTEA")


def test_passwords_are_never_shown():
    assert redact_url("postgresql://segurai:hunter2@db.internal:5432/evidence") == (
        "postgresql://segurai:***@db.internal:5432/evidence")
    assert redact_url("postgresql://segurai@db.internal/evidence") == "postgresql://segurai@db.internal/evidence"
    assert redact_url("segurai.db") == "segurai.db"
    assert is_database_url("postgres://x@y/z") and not is_database_url("C:/data/segurai.db")


def test_a_postgres_store_needs_an_explicit_key():
    with pytest.raises(ValueError, match="pass key="):
        segurai.configure(store="postgresql://segurai@db.internal/evidence")


def test_config_takes_the_database_url_from_the_environment(tmp_path, monkeypatch):
    cfg = tmp_path / "segurai.toml"
    cfg.write_text('[server]\ndatabase = "postgresql://segurai:hunter2@db/evidence"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="contains a password"):
        load_config(cfg)

    cfg.write_text('[server]\ndatabase_env = "SEGURAI_DATABASE_URL"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="SEGURAI_DATABASE_URL is not set"):
        load_config(cfg)
    monkeypatch.setenv("SEGURAI_DATABASE_URL", "postgresql://segurai:hunter2@db/evidence")
    config = load_config(cfg)
    assert config.server.database == "postgresql://segurai:hunter2@db/evidence"
    assert "hunter2" not in "\n".join(config.summary())

    cfg.write_text('[server]\ndatabase = "segurai.db"\ndatabase_env = "SEGURAI_DATABASE_URL"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="not both"):
        load_config(cfg)
    cfg.write_text('[server]\ndatabase = "mysql://db/evidence"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="postgresql://"):
        load_config(cfg)


# ---- failing safely (whichever database is in use) ------------------------------------------

def test_a_write_that_fails_half_way_leaves_nothing_behind(monkeypatch):
    """A record and its log entry are stored together or not at all.

    Before every write had its own transaction, a failure between the two left
    the record pending, to be committed by the next write - a record with no
    log entry, which the audit would report as tampering.
    """
    store = segurai._runtime.store

    def no_room(*args, **kwargs):
        raise OSError("disk full")

    with monkeypatch.context() as m:
        m.setattr(store, "_append_entry", no_room)
        with pytest.raises(OSError):
            store.put_session("s_fail", "sarah@acme.example", "tidy", None, NOW)
    store.put_session("s_ok", "sarah@acme.example", "tidy", None, NOW)       # the next write commits
    assert store.get_session("s_fail") is None
    assert store.get_session("s_ok") is not None
    assert store.audit().ok


def test_a_failed_statement_does_not_poison_the_next_one():
    store = segurai._runtime.store
    with pytest.raises(Exception):                                            # noqa: B017 - either driver's error
        store._write("INSERT INTO no_such_table VALUES (?)", (1,))
    store.put_session("s_after", "sarah@acme.example", "tidy", None, NOW)
    assert store.get_session("s_after") is not None


# ---- PostgreSQL itself ---------------------------------------------------------------------

@postgres_only
def test_servers_sharing_a_database_never_fork_the_log():
    stores = [Store(TEST_DATABASE) for _ in range(3)]          # three servers, three connections
    errors = []

    def record(store, n):
        try:
            for i in range(20):
                store.put_session(f"s_{n}_{i}", "sarah@acme.example", "tidy", None, NOW)
        except Exception as exc:                               # noqa: BLE001 - reported below
            errors.append(exc)

    threads = [threading.Thread(target=record, args=(stores[n % 3], n)) for n in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    entries = stores[0].ledger_entries()
    assert [e.seq for e in entries] == list(range(1, len(entries) + 1))      # one unbroken chain
    assert sum(e.kind == "session" for e in entries) == 120
    assert stores[0].audit().ok
    for s in stores:
        s.close()


@postgres_only
def test_a_dropped_connection_is_replaced_between_writes():
    import psycopg

    store = Store(TEST_DATABASE)
    store.put_session("s_before", "sarah@acme.example", "tidy", None, NOW)
    pid = store._db.conn.info.backend_pid
    with psycopg.connect(TEST_DATABASE, autocommit=True) as admin:
        admin.execute("SELECT pg_terminate_backend(%s)", (pid,))
    store.put_session("s_after", "sarah@acme.example", "tidy", None, NOW)    # reconnects, no error
    assert store._db.conn.info.backend_pid != pid
    assert {s.session_id for s in store.sessions()} >= {"s_before", "s_after"}
    assert store.audit().ok
    store.close()


@postgres_only
def test_a_connection_lost_mid_write_commits_nothing(monkeypatch):
    import psycopg

    store = Store(TEST_DATABASE)

    def cut_then_append(kind, ref_id, payload):
        with psycopg.connect(TEST_DATABASE, autocommit=True) as admin:
            admin.execute("SELECT pg_terminate_backend(%s)", (store._db.conn.info.backend_pid,))
        Store._append_entry(store, kind, ref_id, payload)

    with monkeypatch.context() as m:
        m.setattr(store, "_append_entry", cut_then_append)
        with pytest.raises(psycopg.OperationalError):
            store.put_session("s_cut", "sarah@acme.example", "tidy", None, NOW)
    assert store.get_session("s_cut") is None                                 # and the store still works
    assert store.audit().ok
    store.close()


@postgres_only
def test_postgres_specifics():
    store = segurai._runtime.store
    assert store.dialect == "postgres" and store.path == redact_url(TEST_DATABASE)
    with pytest.raises(ValueError, match="pg_dump"):
        store.backup("copy.db")
    assert store.change_marker() is not None
    # the hidden insertion counter is the database's, never part of a record
    assert "ord" in store._db.columns("actions") and "ord" not in store._columns["actions"]
