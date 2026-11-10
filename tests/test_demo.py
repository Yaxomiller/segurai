"""`segurai demo`: the made-up company, the tamper scene, and the cover-up scene.

The demo is what people see first, so it is tested like the product: each
scenario must show what it claims to show, the pages must render without a
script in them, and both tampering scenes must be caught - the second one only
by the signed checkpoint, because that is the point it makes.
"""

import segurai
from segurai import Authority, Store, demo
from segurai.cli import main as cli_main
from segurai.collector.web import audit_page, index_page, permissions_page, session_page


def _seed(tmp_path):
    summary = demo.seed(tmp_path / "demo")
    db, _, pub = demo.demo_paths(tmp_path / "demo")
    return summary, Store(db), Authority.verifier(pub)


def _by_request(store, prefix):
    return next(s for s in store.sessions(limit=50) if s.request.startswith(prefix))


# ---- the scenarios ----------------------------------------------------------

def test_the_demo_company_is_built_from_real_records(tmp_path):
    summary, store, verifier = _seed(tmp_path)
    assert summary.sessions == 10 and summary.actions == 25
    assert summary.flagged == 3 and summary.blocked == 1
    report = store.audit(verifier)
    assert report.ok and report.checkpoints == 1 and report.checkpoints_verified == 1


def test_each_scenario_shows_what_it_is_there_to_show(tmp_path):
    _, store, _ = _seed(tmp_path)

    incident = store.actions_for_session(_by_request(store, "Clean up our old").session_id)
    (deleted,) = [a for a in incident if not a.allowed]
    assert {f.check for f in deleted.findings} == {"operation", "scale", "total", "irreversible", "condition"}
    assert not deleted.blocked                                         # observe mode: it went ahead

    refunds = store.actions_for_session(_by_request(store, "Refund").session_id)
    (stopped,) = [a for a in refunds if a.blocked]
    assert stopped.detail["amount"] == 250                             # enforce mode stopped it

    injected = store.actions_for_session(_by_request(store, "Send the weekly").session_id)
    (shared,) = [a for a in injected if not a.allowed]
    assert {f.check for f in shared.findings} == {"operation", "target"}

    snoozed = store.actions_for_session(_by_request(store, "Snooze").session_id)
    assert all(a.allowed for a in snoozed)                             # missing evidence is not a violation
    assert any(f.status == "unverifiable" for a in snoozed for f in a.findings)

    assert all(a.allowed for a in store.actions_for_session(_by_request(store, "Archive our").session_id))
    assert _by_request(store, "(observed").contract["observed"] is True


def test_samples_are_labelled_as_samples(tmp_path):
    _, store, verifier = _seed(tmp_path)
    page = index_page(store, verifier=verifier)
    assert "Sample company." in page and "pre-written samples" in page
    incident = session_page(store, _by_request(store, "Clean up our old").session_id, verifier)
    assert "AI review (sample, pre-written for the demo)" in incident


def test_seeding_leaves_the_callers_runtime_alone(tmp_path):
    before = segurai._runtime.store
    demo.seed(tmp_path / "demo")
    demo.seed(tmp_path / "demo")                  # twice: the file must not stay locked
    assert segurai._runtime.store is before


# ---- the pages ---------------------------------------------------------------

def test_every_page_renders_without_scripts(tmp_path):
    _, store, verifier = _seed(tmp_path)
    pages = [index_page(store, verifier=verifier), audit_page(store, verifier),
             permissions_page(store, verifier)]
    pages += [session_page(store, s.session_id, verifier) for s in store.sessions(limit=50)]
    for page in pages:
        assert "<script" not in page
        assert "&#x2713; Records verified" in page


def test_the_incident_is_told_in_plain_words_and_exact_ones(tmp_path):
    _, store, verifier = _seed(tmp_path)
    page = session_page(store, _by_request(store, "Clean up our old").session_id, verifier)
    # for the investor
    assert "What happened" in page and "it went ahead" in page
    assert "which was never granted" in page and "can't be undone" in page
    # for the engineer
    assert "scale 400 exceeds limit 50" in page
    assert "signatures valid" in page


def test_permissions_page_credits_delegating_agents(tmp_path):
    _, store, verifier = _seed(tmp_path)
    page = permissions_page(store, verifier)
    assert "permissions granted but never used" in page
    assert "may nothing" not in page


# ---- the tamper scenes ---------------------------------------------------------

def test_tamper_makes_the_incident_look_clean_and_the_audit_catches_it(tmp_path):
    _, store, verifier = _seed(tmp_path)
    store.close()
    demo.tamper(tmp_path / "demo")
    store = Store(demo.demo_paths(tmp_path / "demo")[0])

    sid = _by_request(store, "Clean up our old").session_id
    assert all(a.allowed for a in store.actions_for_session(sid))      # the cover story holds...
    assert store.verdicts_for_session(sid) == {}
    report = store.audit(verifier)                                     # ...but not against the log
    assert not report.ok
    assert {p.kind for p in report.problems} == {"row"}

    assert "This record was changed after it was written" in session_page(store, sid, verifier)
    assert "altered after the fact" in index_page(store, verifier=verifier)
    assert "Tampering detected" in audit_page(store, verifier)


def test_cover_up_is_caught_only_by_the_signed_checkpoint(tmp_path):
    _, store, verifier = _seed(tmp_path)
    store.close()
    demo.cover_up(tmp_path / "demo")
    store = Store(demo.demo_paths(tmp_path / "demo")[0])

    report = store.audit(verifier)
    assert not report.ok
    assert {p.kind for p in report.problems} == {"checkpoint"}        # chain and rows agree now
    assert "History was rewritten" in audit_page(store, verifier)


# ---- the command line ------------------------------------------------------------

def test_demo_commands(tmp_path, capsys):
    folder = str(tmp_path / "d")
    assert cli_main(["demo", "tamper", "--dir", folder]) == 1          # nothing to tamper with yet
    assert "Run `segurai demo` first" in capsys.readouterr().out

    assert cli_main(["demo", "--dir", folder, "--no-serve"]) == 0
    out = capsys.readouterr().out
    assert "10 requests, 25 agent actions" in out and "segurai demo tamper" in out

    assert cli_main(["demo", "tamper", "--dir", folder]) == 0
    assert "harmless 4-record" in capsys.readouterr().out
    assert cli_main(["demo", "tamper", "--dir", folder]) == 1          # already rewritten
    assert cli_main(["demo", "cover-up", "--dir", folder]) == 0
    assert "signed checkpoint still disagrees" in capsys.readouterr().out
