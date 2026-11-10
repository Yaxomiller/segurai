"""Deployment: settings from the environment, the no-token refusal, backups, container defaults."""

from pathlib import Path

import pytest

import segurai
from segurai import Scope, Store
from segurai.cli import main as cli_main

ROOT = Path(__file__).resolve().parents[1]


def _record_session(db):
    segurai.configure(store=str(db))
    with segurai.session(principal="p", request="deploy check",
                         scope=Scope.of(operations=["read"], targets=["crm.*"])) as s:
        segurai.act("read", "crm.x")
    return s.session_id


def test_the_database_path_can_come_from_the_environment(tmp_path, monkeypatch, capsys):
    db = tmp_path / "env.db"
    sid = _record_session(db)
    monkeypatch.setenv("SEGURAI_DB", str(db))
    assert cli_main(["sessions"]) == 0
    assert sid in capsys.readouterr().out


def test_the_key_can_come_from_the_environment(tmp_path, monkeypatch, capsys):
    db = tmp_path / "w.db"
    sid = _record_session(db)
    keys = tmp_path / "keys"
    keys.mkdir()
    (tmp_path / "w.pub").rename(keys / "org.pub")
    (tmp_path / "w.key").unlink()   # the collector only ever holds the public key
    monkeypatch.setenv("SEGURAI_KEY", str(keys / "org.pub"))
    assert cli_main(["--db", str(db), "verify", sid]) == 0
    assert "signatures valid" in capsys.readouterr().out


@pytest.mark.parametrize("command", ["collect", "ui"])
def test_listening_beyond_this_machine_without_a_token_is_refused(tmp_path, monkeypatch, capsys, command):
    monkeypatch.delenv("SEGURAI_COLLECTOR_TOKEN", raising=False)
    assert cli_main(["--db", str(tmp_path / "w.db"), command, "--host", "0.0.0.0", "--port", "0"]) == 2
    assert "Refusing to listen beyond this machine without a token" in capsys.readouterr().out


def test_settings_from_the_environment_get_the_same_safety_check(tmp_path, monkeypatch):
    monkeypatch.delenv("SEGURAI_COLLECTOR_TOKEN", raising=False)
    monkeypatch.setenv("SEGURAI_HOST", "0.0.0.0")
    monkeypatch.setenv("SEGURAI_PORT", "0")
    assert cli_main(["--db", str(tmp_path / "w.db"), "collect"]) == 2


def test_backup_makes_a_consistent_copy_and_will_not_overwrite_by_accident(tmp_path):
    db = tmp_path / "w.db"
    sid = _record_session(db)
    out = tmp_path / "backup.db"

    assert cli_main(["--db", str(db), "backup", "--out", str(out)]) == 0
    copy = Store(out)
    assert copy.get_session(sid) is not None
    assert len(copy.actions_for_session(sid)) == 1
    copy.close()

    assert cli_main(["--db", str(db), "backup", "--out", str(out)]) == 1
    assert cli_main(["--db", str(db), "backup", "--out", str(out), "--force"]) == 0


def test_the_container_files_keep_their_safety_defaults():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "USER segurai" in dockerfile
    assert 'CMD ["serve", "--config", "/data/segurai.toml"]' in dockerfile

    compose = (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    assert "${SEGURAI_INGEST_TOKEN:?" in compose            # won't start without a token
    assert '"127.0.0.1:8700:8700"' in compose               # localhost only
    assert '"127.0.0.1:8800:8800"' in compose
    assert "read_only: true" in compose and "no-new-privileges:true" in compose and "- ALL" in compose

    postgres = (ROOT / "deploy" / "compose.postgres.yaml").read_text(encoding="utf-8")
    assert "${SEGURAI_DB_PASSWORD:?" in postgres            # no default database password
    assert "ports:" not in postgres                         # the database is not published

    dockerignore = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "*.key" in dockerignore and "*.db" in dockerignore
