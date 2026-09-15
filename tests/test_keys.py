"""Signing keys on disk, and checking signatures in a later run."""

import json
import sqlite3

import pytest

import warrant
from warrant import Authority, ChainError, Scope
from warrant.cli import main as cli_main

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


def test_saved_key_verifies_after_reload(tmp_path):
    a = Authority()
    root = a.issue_root(session_id="s", principal="p", scope=GRANTED)
    a.save(tmp_path / "k.key")
    b = Authority.load(tmp_path / "k.key")
    b.verify(root)
    assert b.key_id == a.key_id == root.key_id


def test_load_or_create_creates_the_key_only_once(tmp_path):
    path = tmp_path / "k.key"
    first = Authority.load_or_create(path)
    second = Authority.load_or_create(path)
    assert first.key_id == second.key_id
    assert path.with_suffix(".pub").exists()


def test_public_key_can_verify_but_not_sign(tmp_path):
    a = Authority()
    a.save(tmp_path / "k.key")
    root = a.issue_root(session_id="s", principal="p", scope=GRANTED)
    auditor = Authority.verifier(tmp_path / "k.pub")
    auditor.verify(root)
    assert not auditor.can_sign
    with pytest.raises(ChainError, match="cannot sign"):
        auditor.issue_root(session_id="s", principal="p", scope=GRANTED)


def test_wrong_key_message_names_both_keys():
    a, b = Authority(), Authority()
    root = a.issue_root(session_id="s", principal="p", scope=GRANTED)
    with pytest.raises(ChainError, match=f"invalid signature.*{a.key_id}.*{b.key_id}"):
        b.verify(root)


def test_configure_with_a_file_store_keeps_the_key_beside_it(tmp_path):
    warrant.configure(store=str(tmp_path / "w.db"))
    assert (tmp_path / "w.key").exists()
    first = warrant._runtime.authority.key_id
    warrant.configure(store=str(tmp_path / "w.db"))
    assert warrant._runtime.authority.key_id == first


def _run_session(db):
    warrant.configure(store=str(db))

    @warrant.agent("crm_agent", scope=Scope.of(operations=["read"]))
    def crm_agent():
        warrant.act("read", "crm.opportunities")

    with warrant.session(principal="sarah@company.com", request="r", scope=GRANTED) as s:
        crm_agent()
    return s.session_id


def test_cli_verify_checks_signatures_in_a_later_run(tmp_path, capsys):
    db = tmp_path / "w.db"
    sid = _run_session(db)
    assert cli_main(["--db", str(db), "verify", sid]) == 0
    assert "signatures valid" in capsys.readouterr().out


def test_cli_verify_catches_a_scope_edited_in_the_database(tmp_path, capsys):
    db = tmp_path / "w.db"
    sid = _run_session(db)
    # Someone with database access quietly widens the CRM agent's scope.
    widened = {"operations": ["read", "delete"], "targets": ["*"], "max_scale": None,
               "irreversible_allowed": True, "constraints": []}
    conn = sqlite3.connect(db)
    conn.execute("UPDATE warrants SET scope_json = ? WHERE holder = 'crm_agent'",
                 (json.dumps(widened),))
    conn.commit()
    conn.close()

    assert cli_main(["--db", str(db), "verify", sid]) == 1
    assert "invalid signature" in capsys.readouterr().out


def test_cli_verify_without_a_key_says_signatures_were_not_checked(tmp_path, capsys):
    db = tmp_path / "w.db"
    sid = _run_session(db)
    (tmp_path / "w.key").unlink()
    (tmp_path / "w.pub").unlink()
    assert cli_main(["--db", str(db), "verify", sid]) == 0
    assert "NOT checked" in capsys.readouterr().out


def test_cli_keygen_refuses_to_overwrite(tmp_path, capsys):
    key = tmp_path / "k.key"
    assert cli_main(["--key", str(key), "keygen"]) == 0
    assert cli_main(["--key", str(key), "keygen"]) == 1
    assert "already exists" in capsys.readouterr().out


def test_database_from_before_key_ids_still_opens(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE warrants (warrant_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
        "root_principal TEXT NOT NULL, holder TEXT NOT NULL, scope_json TEXT NOT NULL, "
        "issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, parent_id TEXT, "
        "depth INTEGER NOT NULL, signature BLOB)"
    )
    conn.commit()
    conn.close()

    store = warrant.Store(db)
    a = Authority()
    w = a.issue_root(session_id="s", principal="p", scope=GRANTED)
    store.put_warrant(w)
    assert store.get_warrant(w.warrant_id).key_id == a.key_id


def test_import_warrant_rejects_garbage():
    with pytest.raises(ValueError, match="not a valid warrant token"):
        warrant.import_warrant("not-a-token")
