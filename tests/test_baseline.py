"""Tier 3: the organisation's own record decides what "usual" means."""

import random
from datetime import timedelta

import segurai
from segurai import Policy, Scope
from segurai.baseline import learn
from segurai.models import utcnow

SCOPE = Scope.of(operations=["search", "archive", "delete"], targets=["crm.*"], irreversible_allowed=True)


def _history(requests=30, seed=7):
    """A month of routine work: crm_agent searches, then archives 10-40 deals per request."""
    rng = random.Random(seed)
    for _ in range(requests):
        with segurai.session(principal="ops@acme.example", request="weekly tidy", scope=SCOPE):
            with segurai.delegate("crm_agent"):
                segurai.act("search", "crm.deals", scale=500)
                segurai.act("archive", "crm.deals", scale=rng.randint(10, 40))


def test_it_learns_from_clean_history_only():
    _history()
    segurai.configure(mode=segurai.Mode.OBSERVE)
    with segurai.session(principal="ops@acme.example", request="odd", scope=Scope.of(
            operations=["archive"], targets=["crm.*"], max_scale=5)):
        with segurai.delegate("crm_agent"):
            segurai.act("archive", "crm.deals", scale=900)           # flagged: not "normal", whatever happened
    baseline = learn(segurai._runtime.store)
    archive = baseline.patterns[("crm_agent", "archive", "crm.deals")]
    assert archive.samples == 30 and len(archive.sessions) == 30
    stats = archive.stats()
    assert 10 <= stats["p50"] <= 40 and stats["max"] <= 40           # the 900 is not in it


def test_it_proposes_readable_limits_with_their_evidence():
    _history()
    rules = learn(segurai._runtime.store).proposals(headroom=1.5)
    limit, irreversible = rules
    assert limit["agents"] == ["crm_agent"] and limit["operations"] == ["archive"]
    assert limit["max_scale"] in (50, 100) and "learned from 30 actions in 30 requests" in limit["reason"]
    assert irreversible["irreversible"] is False
    # They are real company rules: they load, and they bite.
    policy = Policy.from_dict({"rules": rules})
    assert policy.evaluate("archive", "crm.deals", scale=400, holders=["crm_agent"])
    assert not policy.evaluate("archive", "crm.deals", scale=30, holders=["crm_agent"])


def test_too_little_history_proposes_nothing():
    _history(requests=5)
    assert learn(segurai._runtime.store).proposals() == []


def test_unusual_actions_are_flagged_as_advice():
    _history()
    baseline = learn(segurai._runtime.store, until=utcnow() + timedelta(seconds=1))
    with segurai.session(principal="ops@acme.example", request="big tidy", scope=SCOPE) as s:
        with segurai.delegate("crm_agent"):
            segurai.act("archive", "crm.deals", scale=25)               # usual
            segurai.act("archive", "crm.deals", scale=400)              # far above usual
            segurai.act("delete", "crm.deals", scale=3, irreversible=True)   # never done before
            segurai.act("search", "crm.accounts", scale=10)             # a new table to read: fine
        with segurai.delegate("billing_agent"):
            segurai.act("refund", "billing.refunds", scale=1)           # an agent never seen
    reasons = [u.reason for u in baseline.unusual(segurai._runtime.store.actions_for_session(s.session_id))]
    assert len(reasons) == 3
    assert reasons[0].startswith("changes 400 records; crm_agent's usual is")
    assert reasons[1] == "crm_agent has never been seen to delete crm.deals before"
    assert reasons[2] == "billing_agent has no history here yet"


def test_the_cli_summarises_proposes_and_checks(tmp_path, capsys):
    from segurai.cli import main

    db = tmp_path / "segurai.db"
    segurai.configure(store=str(db))
    _history()
    with segurai.session(principal="ops@acme.example", request="big tidy", scope=SCOPE) as s:
        with segurai.delegate("crm_agent"):
            segurai.act("archive", "crm.deals", scale=400)
    assert main(["--db", str(db), "baseline"]) == 0
    assert "crm_agent" in capsys.readouterr().out
    assert main(["--db", str(db), "baseline", "--rules"]) == 0
    out = capsys.readouterr().out
    assert "[[policy.rules]]" in out and "(learned)" in out
    assert main(["--db", str(db), "baseline", "--check", s.session_id]) == 0
    assert "unusual" in capsys.readouterr().out
