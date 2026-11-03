"""Milestone M7: the log must catch anything done to the records behind its back.

Each test tampers with the database the way someone with write access would -
editing a row, deleting one, cutting an entry out of the log, rewriting the
whole chain - and checks that the audit says so, in words a person can act on.
"""

import sqlite3

import pytest

import segurai
from segurai import Authority, Scope, Store
from segurai.cli import main as cli_main
from segurai.collector.ledger import GENESIS, payload_hash

GRANTED = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)


def _run(db=":memory:", principal="sarah@company.com"):
    """A small honest session: one agent, three actions, one of them flagged.

    No explicit authority: a file-backed store creates its signing key beside
    itself, exactly as it does for a real user, so the CLI can checkpoint.
    """
    segurai.configure(store=str(db))

    @segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
    def crm_agent():
        segurai.act("read", "crm.opportunities", scale=412)
        segurai.act("archive", "crm.opportunities", scale=30)
        segurai.act("delete", "crm.opportunities", scale=400, irreversible=True)

    with segurai.session(principal=principal, request="clean up our old sales records",
                         scope=GRANTED) as s:
        crm_agent()
    return s.session_id


def _store():
    return segurai._runtime.store


def _sql(store, statement, params=()):
    """Tamper with the database directly, as someone with write access would."""
    store._conn.execute(statement, params)
    store._conn.commit()


# ---- the honest case ------------------------------------------------------

def test_an_untouched_log_passes_and_counts_what_it_covers():
    _run()
    report = _store().audit(segurai._runtime.authority)
    assert report.ok
    # 1 session + 2 warrants (entrypoint, crm_agent) + 3 actions
    assert report.entries == 6
    assert report.rows_checked == 6
    assert report.verified_to == 6
    assert report.rows_unlogged == 0
    assert report.amendments == 0
    assert report.head != GENESIS
    assert "No sign of tampering" in report.to_text()


def test_every_kind_of_record_is_logged():
    from segurai.judge import Judge

    class FakeJudge:
        last_model = "fake"
        last_latency_ms = 1

        def complete(self, system, review):
            return {"verdict": "outside_intent", "confidence": "high",
                    "reasoning": "Deleting 400 records was not asked for.", "clause": "scale"}

    sid = _run()
    Judge(FakeJudge()).review_session(_store(), sid)
    kinds = {e.kind for e in _store().ledger_entries()}
    assert kinds == {"session", "warrant", "action", "verdict"}
    assert _store().audit(segurai._runtime.authority).ok


# ---- editing a record -----------------------------------------------------

def test_changing_a_scale_in_the_database_is_caught():
    """The quiet edit the whole milestone exists for: 400 deletions become 4."""
    _run()
    store = _store()
    _sql(store, "UPDATE actions SET scale = 4 WHERE scale = 400")

    report = store.audit(segurai._runtime.authority)
    assert not report.ok
    (problem,) = report.problems
    assert problem.kind == "row"
    assert "no longer matches what was logged" in problem.detail
    assert "the row was edited" in problem.detail
    assert problem.ref_id.startswith("act_")


def test_rewriting_a_verdict_is_caught():
    from segurai.judge import Judge

    class FakeJudge:
        last_model = "fake"
        last_latency_ms = 1

        def complete(self, system, review):
            return {"verdict": "outside_intent", "confidence": "high", "reasoning": "No.",
                    "clause": "scale"}

    sid = _run()
    Judge(FakeJudge()).review_session(_store(), sid)
    _sql(_store(), "UPDATE verdicts SET verdict = 'within_intent', reasoning = 'Fine.'")

    report = _store().audit(segurai._runtime.authority)
    assert not report.ok
    assert any(p.kind == "row" and "verdict" in p.detail for p in report.problems)


def test_editing_a_session_request_is_caught():
    _run()
    _sql(_store(), "UPDATE sessions SET request = 'delete everything, as agreed'")
    report = _store().audit(segurai._runtime.authority)
    assert any(p.kind == "row" and "session" in p.detail for p in report.problems)


# ---- deleting a record ----------------------------------------------------

def test_deleting_an_action_leaves_evidence_that_it_existed():
    sid = _run()
    store = _store()
    gone = next(a for a in store.actions_for_session(sid) if a.scale == 400)
    _sql(store, "DELETE FROM actions WHERE action_id = ?", (gone.action_id,))

    report = store.audit(segurai._runtime.authority)
    assert not report.ok
    (problem,) = report.problems
    assert problem.kind == "row"
    assert "its record is gone" in problem.detail and "the row was deleted" in problem.detail
    assert problem.ref_id == gone.action_id


def test_deleting_every_action_of_a_session_is_still_caught():
    sid = _run()
    _sql(_store(), "DELETE FROM actions WHERE session_id = ?", (sid,))
    report = _store().audit(segurai._runtime.authority)
    assert len([p for p in report.problems if "deleted" in p.detail]) == 3


# ---- tampering with the log itself ----------------------------------------

def test_cutting_an_entry_out_of_the_log_is_caught():
    _run()
    store = _store()
    _sql(store, "DELETE FROM ledger WHERE seq = 4")

    report = store.audit(segurai._runtime.authority)
    assert not report.ok
    reasons = " ".join(p.detail for p in report.problems if p.kind == "chain")
    assert "is missing" in reasons or "does not link" in reasons
    assert report.verified_to == 3          # everything up to the gap is still sound


def test_editing_an_entry_in_the_log_is_caught():
    _run()
    store = _store()
    _sql(store, "UPDATE ledger SET payload_hash = ? WHERE seq = 3", ("0" * 64,))

    report = store.audit(segurai._runtime.authority)
    assert not report.ok
    assert any("the entry was edited" in p.detail for p in report.problems)


def test_reordering_the_log_is_caught():
    _run()
    store = _store()
    rows = store._conn.execute("SELECT seq, ref_id FROM ledger ORDER BY seq").fetchall()
    a, b = rows[2]["ref_id"], rows[3]["ref_id"]
    _sql(store, "UPDATE ledger SET ref_id = ? WHERE seq = 3", (b,))
    _sql(store, "UPDATE ledger SET ref_id = ? WHERE seq = 4", (a,))

    report = store.audit(segurai._runtime.authority)
    assert not report.ok


# ---- the forger who rebuilds the whole chain ------------------------------

def _rebuild_chain_without_the_key(store):
    """What a determined editor with database access can do: make the chain
    internally consistent again after changing a record."""
    from segurai.collector.ledger import entry_hash

    prev = GENESIS
    for row in store._conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall():
        stored = store._logged_row(row["kind"], row["ref_id"])
        body = payload_hash(stored) if stored is not None else row["payload_hash"]
        new_hash = entry_hash(row["seq"], prev, row["kind"], row["ref_id"], body, row["at"])
        store._conn.execute(
            "UPDATE ledger SET payload_hash = ?, prev_hash = ?, entry_hash = ? WHERE seq = ?",
            (body, prev, new_hash, row["seq"]))
        prev = new_hash
    store._conn.commit()


def test_without_a_checkpoint_a_full_rebuild_is_not_detectable():
    """Stated plainly because it is the honest limit of a hash chain alone."""
    _run()
    store = _store()
    _sql(store, "UPDATE actions SET scale = 4 WHERE scale = 400")
    _rebuild_chain_without_the_key(store)

    report = store.audit(segurai._runtime.authority)
    assert report.ok                         # the chain agrees with itself again
    assert report.checkpoints == 0
    assert "could rebuild the whole chain" in report.to_text()


def test_a_checkpoint_catches_the_rebuild():
    _run()
    store = _store()
    authority = segurai._runtime.authority
    checkpoint = store.put_checkpoint(authority)
    assert checkpoint.seq == 6 and checkpoint.signature

    _sql(store, "UPDATE actions SET scale = 4 WHERE scale = 400")
    _rebuild_chain_without_the_key(store)

    report = store.audit(authority)
    assert not report.ok
    (problem,) = [p for p in report.problems if p.kind == "checkpoint"]
    assert "history was rewritten" in problem.detail


def test_a_forged_checkpoint_signature_is_caught():
    _run()
    store = _store()
    store.put_checkpoint(Authority())        # signed by a key that is not ours
    report = store.audit(segurai._runtime.authority)
    assert not report.ok
    assert any("signature does not check out" in p.detail for p in report.problems)


def test_checkpoints_can_be_written_down_and_still_mean_something():
    _run()
    text = _store().put_checkpoint(segurai._runtime.authority).to_text()
    assert text.startswith("segurai-checkpoint seq=6 head=")
    assert "sig=" in text and "key=key_" in text


def test_a_checkpoint_needs_something_to_cover():
    store = Store(":memory:")
    with pytest.raises(ValueError, match="nothing in the log"):
        store.put_checkpoint(Authority())


# ---- honest amendments and re-ingest --------------------------------------

def test_storing_the_same_record_twice_adds_no_entry():
    """The collector re-ingests the same spans when a trace arrives in pieces."""
    sid = _run()
    store = _store()
    before = len(store.ledger_entries())
    for w in store.warrants_for_session(sid):
        store.put_warrant(w)
    for a in store.actions_for_session(sid):
        store.put_action(a)
    assert len(store.ledger_entries()) == before
    assert store.audit(segurai._runtime.authority).ok


def test_a_record_that_really_changed_is_logged_as_an_amendment():
    from dataclasses import replace

    sid = _run()
    store = _store()
    before = len(store.ledger_entries())
    action = store.actions_for_session(sid)[0]
    store.put_action(replace(action, violation="corrected after review"))

    report = store.audit(segurai._runtime.authority)
    assert report.ok                              # an amendment is not tampering
    assert len(store.ledger_entries()) == before + 1
    assert report.amendments == 1
    # Both versions remain: the log only ever grows.
    entries = [e for e in store.ledger_entries() if e.ref_id == action.action_id]
    assert len(entries) == 2 and entries[0].payload_hash != entries[1].payload_hash


# ---- older databases ------------------------------------------------------

def test_records_written_before_the_log_existed_are_reported_not_blamed(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE sessions (session_id TEXT PRIMARY KEY, principal TEXT NOT NULL, "
        "request TEXT NOT NULL, contract_json TEXT, started_at TEXT NOT NULL)")
    conn.execute("INSERT INTO sessions VALUES ('ses_old', 'p', 'r', NULL, "
                 "'2026-09-01T00:00:00+00:00')")
    conn.commit()
    conn.close()

    store = Store(db)
    report = store.audit()
    assert report.ok                               # nothing claims to cover that row
    assert report.rows_unlogged == 1
    assert "written before the log existed" in report.to_text()


# ---- the command line -----------------------------------------------------

def test_audit_and_checkpoint_from_the_command_line(tmp_path, capsys):
    db = tmp_path / "w.db"
    _run(db)

    assert cli_main(["--db", str(db), "audit"]) == 0
    assert "No sign of tampering" in capsys.readouterr().out

    assert cli_main(["--db", str(db), "checkpoint"]) == 0
    out = capsys.readouterr().out
    assert "segurai-checkpoint seq=" in out
    assert "outside the database" in out

    # Someone edits a record, then rebuilds the chain to cover it up.
    store = Store(db)
    _sql(store, "UPDATE actions SET scale = 4 WHERE scale = 400")
    _rebuild_chain_without_the_key(store)
    store.close()

    assert cli_main(["--db", str(db), "audit"]) == 1
    report = capsys.readouterr().out
    assert "TAMPERING DETECTED" in report and "history was rewritten" in report

    assert cli_main(["--db", str(db), "audit", "--json"]) == 1
    import json
    assert json.loads(capsys.readouterr().out)["ok"] is False


def test_audit_says_so_when_it_cannot_check_signatures(tmp_path, capsys):
    db = tmp_path / "w.db"
    _run(db)
    cli_main(["--db", str(db), "checkpoint"])
    capsys.readouterr()
    (tmp_path / "w.key").unlink()
    (tmp_path / "w.pub").unlink()

    assert cli_main(["--db", str(db), "audit"]) == 0
    out = capsys.readouterr().out
    assert "signatures NOT checked" in out
    assert "Pass --key" in out


# ---- cost -----------------------------------------------------------------

def test_logging_keeps_a_checked_action_well_inside_its_budget():
    """Tier 1's budget is 5 ms per action; the log must not eat it.

    Medians, not p99s: a single scheduling hiccup on a loaded machine says
    nothing about this code, and a p99 over a few hundred samples catches
    exactly that. Measured on a laptop: 0.04 ms per action, of which the
    ledger append is ~13 us and the hashing ~3 us.
    """
    import statistics
    import time

    segurai.configure(store=":memory:", authority=Authority())
    actions = []
    with segurai.session(principal="p", request="r", scope=GRANTED):
        for _ in range(300):
            started = time.perf_counter_ns()
            segurai.act("archive", "crm.opportunities", scale=1)
            actions.append((time.perf_counter_ns() - started) / 1_000_000)
    assert statistics.median(actions) < 1.0, f"median {statistics.median(actions):.2f} ms"

    # The append on its own, so a regression points at the right place.
    store = Store(":memory:")
    payload = {"action_id": "act_x", "scale": 1, "detail_json": "{}"}
    appends = []
    with store._lock:
        for i in range(500):
            started = time.perf_counter_ns()
            store._append_entry("action", f"act_{i}", payload)
            appends.append((time.perf_counter_ns() - started) / 1000)
        store._conn.commit()
    assert statistics.median(appends) < 200, f"median {statistics.median(appends):.0f} us"
