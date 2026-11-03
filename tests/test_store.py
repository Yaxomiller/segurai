"""Storage: blocked vs. went-ahead, and databases created by older versions."""

import sqlite3

import pytest

import segurai
from segurai import Scope

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


def _open():
    return segurai.session(principal="sarah@company.com", request="clean up", scope=GRANTED)


def test_enforced_violation_is_stored_as_blocked_and_rendered_so():
    segurai.configure(mode=segurai.Mode.ENFORCE)
    with _open() as s:
        with pytest.raises(segurai.ViolationError):
            segurai.act("delete", "crm.opportunities", scale=400)
    (rec,) = s.violations()
    assert rec.blocked is True
    out = segurai.render(s.session_id, charset="ascii")
    assert "[BLOCKED] delete crm.opportunities" in out
    assert "1 violation(s), 1 blocked" in out
    assert segurai.summary(s.session_id)["violations"][0]["blocked"] is True


def test_observed_violation_is_stored_as_went_ahead():
    with _open() as s:
        rec = segurai.act("delete", "crm.opportunities", scale=400)
    assert rec.blocked is False
    (stored,) = s.violations()
    assert stored.blocked is False
    out = segurai.render(s.session_id, charset="ascii")
    assert "[FAIL   ] delete crm.opportunities" in out
    assert "[went ahead]" in out


def test_database_from_before_the_blocked_flag_still_opens(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE actions (action_id TEXT PRIMARY KEY, session_id TEXT NOT NULL, "
        "warrant_id TEXT NOT NULL, actor TEXT NOT NULL, operation TEXT NOT NULL, "
        "resource TEXT NOT NULL, scale INTEGER NOT NULL, irreversible INTEGER NOT NULL, "
        "at TEXT NOT NULL, allowed INTEGER NOT NULL, violation TEXT, detail_json TEXT)"
    )
    conn.execute(
        "INSERT INTO actions VALUES ('act_old', 's', 'w', 'agent', 'read', 'crm.x', 1, 0, "
        "'2026-09-01T00:00:00+00:00', 1, NULL, '{}')"
    )
    conn.commit()
    conn.close()

    store = segurai.Store(db)
    (old,) = store.actions_for_session("s")
    assert old.blocked is False  # rows from before the column existed read as not blocked


def test_detail_that_json_cannot_encode_is_stored_as_text():
    from datetime import date

    with _open() as s:
        segurai.act("read", "crm.x", since=date(2026, 1, 1))
        (rec,) = s.actions()
    assert rec.detail["since"] == "2026-01-01"
