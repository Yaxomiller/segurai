"""Witnesses: a rewrite is caught even when whoever did it held the signing key."""

import json
from datetime import timedelta

import pytest

import segurai
from segurai import Scope, Store
from segurai.cli import main as cli_main
from segurai.collector.ledger import GENESIS, Checkpoint, entry_hash, payload_hash
from segurai.witness import CheckpointWorker, FileWitness, Witness, read_witness_file

GRANTED = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)


def _record(n=1):
    with segurai.session(principal="p", request="r", scope=GRANTED):
        for _ in range(n):
            segurai.act("archive", "crm.opportunities", scale=3)


def _key_holder_rewrite(store, authority):
    """What a key-holder covering their tracks does: edit, rebuild the chain, re-sign every checkpoint."""
    store._conn.execute("UPDATE actions SET scale = 1")
    prev = GENESIS
    for row in store._conn.execute("SELECT * FROM ledger ORDER BY seq").fetchall():
        stored = store._logged_row(row["kind"], row["ref_id"])
        body = payload_hash(stored) if stored is not None else row["payload_hash"]
        new = entry_hash(row["seq"], prev, row["kind"], row["ref_id"], body, row["at"])
        store._conn.execute("UPDATE ledger SET payload_hash=?, prev_hash=?, entry_hash=? WHERE seq=?",
                            (body, prev, new, row["seq"]))
        prev = new
    store._conn.execute("DELETE FROM checkpoints")
    store._conn.commit()
    store.put_checkpoint(authority)                 # a fresh, validly signed checkpoint


def test_a_key_holder_rewrite_beats_internal_checkpoints_but_not_a_witness(tmp_path):
    store, authority = segurai._runtime.store, segurai._runtime.authority
    witness = FileWitness(tmp_path / "witness.log")
    worker = CheckpointWorker(store, authority, [witness])
    _record(3)
    assert worker.run_once(force=True)["published"] == {"file": 1}

    _key_holder_rewrite(store, authority)
    assert store.audit(authority).ok                                # the inside story is consistent now

    witnessed, bad = read_witness_file(tmp_path / "witness.log")
    report = store.audit(authority, witnessed=witnessed)
    assert not report.ok and bad == []
    (problem,) = report.problems
    assert problem.kind == "witness" and "rewritten after it was witnessed" in problem.detail


def test_a_witness_line_from_another_key_is_refused(tmp_path):
    _record()
    forged = segurai._runtime.store.put_checkpoint(segurai.Authority())
    report = segurai._runtime.store.audit(segurai._runtime.authority, witnessed=[forged])
    assert any("not made with this organisation's key" in p.detail for p in report.problems)


def test_cutting_history_short_is_caught_by_the_witness(tmp_path):
    store, authority = segurai._runtime.store, segurai._runtime.authority
    _record(2)
    witnessed = [store.put_checkpoint(authority)]
    store._conn.execute("DELETE FROM ledger WHERE seq = (SELECT MAX(seq) FROM ledger)")
    store._conn.commit()
    report = store.audit(authority, witnessed=witnessed)
    assert any("history was cut short" in p.detail for p in report.problems)


def test_the_worker_checkpoints_only_when_due_and_catches_up_failed_witnesses():
    store, authority = segurai._runtime.store, segurai._runtime.authority

    class Flaky(Witness):
        name = "flaky"

        def __init__(self):
            self.up, self.seen = False, []

        def publish(self, cp):
            if not self.up:
                raise OSError("witness unreachable")
            self.seen.append(cp.seq)

    flaky = Flaky()
    worker = CheckpointWorker(store, authority, [flaky], every=timedelta(hours=1))
    _record()
    first = worker.run_once()
    assert first["checkpoint"] is not None and first["failures"] == {"flaky": "witness unreachable"}
    assert worker.run_once()["checkpoint"] is None                  # nothing new, interval not passed

    _record()
    assert worker.run_once(force=True)["checkpoint"] is not None
    flaky.up = True
    assert worker.run_once()["published"] == {"flaky": 2}           # both, in order
    assert flaky.seen == sorted(flaky.seen) and len(flaky.seen) == 2
    assert worker.run_once()["published"] == {}


def test_checkpoint_lines_round_trip_and_junk_is_reported(tmp_path):
    _record()
    cp = segurai._runtime.store.put_checkpoint(segurai._runtime.authority)
    assert Checkpoint.from_text(cp.to_text()) == cp
    path = tmp_path / "w.log"
    path.write_text(cp.to_text() + "\nsomething else\nsegurai-checkpoint seq=1 head=zz\n", encoding="utf-8")
    found, bad = read_witness_file(path)
    assert found == [cp] and len(bad) == 2


def test_the_command_line_writes_and_checks_witness_files(tmp_path, capsys):
    db, witness = tmp_path / "w.db", tmp_path / "witness.log"
    segurai.configure(store=str(db))
    _record(2)
    assert cli_main(["--db", str(db), "checkpoint", "--witness", str(witness)]) == 0
    assert "Also appended to the witness file" in capsys.readouterr().out
    assert cli_main(["--db", str(db), "audit", "--witness", str(witness)]) == 0
    assert "1/1 checkpoint(s) held outside the database still match" in capsys.readouterr().out

    store = Store(db)
    _key_holder_rewrite(store, segurai.Authority.load(tmp_path / "w.key"))
    store.close()
    assert cli_main(["--db", str(db), "audit", "--witness", str(witness), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["witnessed"] == 1 and report["witnessed_verified"] == 0


def test_witness_files_only_ever_grow(tmp_path):
    witness = FileWitness(tmp_path / "w.log")
    _record()
    store, authority = segurai._runtime.store, segurai._runtime.authority
    first = store.put_checkpoint(authority)
    witness.publish(first)
    _record()
    witness.publish(store.put_checkpoint(authority))
    lines = (tmp_path / "w.log").read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2 and lines[0] == first.to_text()


def test_unsafe_witness_webhooks_are_refused():
    from segurai.witness import WebhookWitness
    with pytest.raises(ValueError, match="https"):
        WebhookWitness(url="http://siem.example/x", secret="x" * 20)
    with pytest.raises(ValueError, match="16"):
        WebhookWitness(url="https://siem.example/x", secret="short")
