"""The scope-creep report: granted versus used, with evidence and a tightened scope."""

import csv
import io
import json
from datetime import timedelta

import pytest

import segurai
from segurai import Authority, Scope, Store
from segurai.models import ActionRecord, utcnow
from segurai.report import Grant, build_report, load_grants

NOW = utcnow()
GRANTED = Scope.of(operations=["read", "update", "archive", "delete", "export"],
                   targets=["crm.*", "billing.invoices"], max_scale=500, irreversible_allowed=True)
AGENT_SCOPE = Scope(operations=frozenset({"read", "archive", "delete"}),
                    targets=frozenset({"crm.*"}), max_scale=500, irreversible_allowed=True)


def _seed(store, sessions=6, days_ago=1, principal="sarah@company.com"):
    """Sessions where crm_agent reads and archives crm.opportunities, and never deletes."""
    authority = Authority()
    for i in range(sessions):
        started = NOW - timedelta(days=days_ago, minutes=i)
        sid = f"ses_{days_ago}_{i}"
        root = authority.issue_root(session_id=sid, principal=principal, scope=GRANTED, now=started)
        agent = authority.attenuate(root, holder="crm_agent", scope=AGENT_SCOPE, now=started)
        store.put_session(sid, principal, "clean up our old sales records", None, started)
        store.put_warrant(root)
        store.put_warrant(agent)
        for n, (op, resource, scale) in enumerate([("read", "crm.opportunities", 400),
                                                   ("archive", "crm.opportunities", 20 + i),
                                                   ("read", "crm.accounts", 30)]):
            store.put_action(ActionRecord(action_id=f"act_{sid}_{n}", session_id=sid,
                                          warrant_id=agent.warrant_id, actor="crm_agent", operation=op,
                                          resource=resource, scale=scale,
                                          at=started + timedelta(seconds=n)))
    return store


def _row(report, identity, source="warrants"):
    return next(r for r in report.identities if r.identity == identity and r.source == source)


def test_unused_operations_and_targets_are_found_with_evidence():
    report = build_report(_seed(Store(":memory:")), since=NOW - timedelta(days=30))
    agent = _row(report, "crm_agent")
    assert agent.sessions == 6 and agent.actions == 18
    assert agent.unused_operations == ["delete"]
    assert agent.used_operations == {"archive": 6, "read": 12}
    assert agent.examples["archive"].startswith("act_")
    assert agent.confidence == "medium"

    root = _row(report, "sarah@company.com (session root)")
    assert root.unused_operations == ["delete", "export", "update"]
    assert root.unused_targets == ["billing.invoices"]


def test_wildcards_shrink_to_what_was_used():
    agent = _row(build_report(_seed(Store(":memory:")), since=NOW - timedelta(days=30)), "crm_agent")
    assert agent.wildcard_narrowing == {"crm.*": ["crm.accounts", "crm.opportunities"]}
    assert agent.recommended.targets == {"crm.accounts", "crm.opportunities"}


def test_the_proposed_scope_only_ever_removes():
    agent = _row(build_report(_seed(Store(":memory:")), since=NOW - timedelta(days=30)), "crm_agent")
    rec = agent.recommended
    assert rec.operations == {"read", "archive"}
    assert rec.irreversible_allowed is False           # allowed, never used
    assert agent.largest_change == 25
    assert rec.max_scale == 50                           # 25 x 1.2 -> the next round number
    assert rec.is_subset_of(AGENT_SCOPE.narrow(max_scale=500))[0]


def test_sessions_outside_the_window_are_ignored():
    store = _seed(Store(":memory:"), sessions=3, days_ago=1)
    _seed(store, sessions=4, days_ago=90)
    agent = _row(build_report(store, since=NOW - timedelta(days=30)), "crm_agent")
    assert agent.sessions == 3 and agent.confidence == "low"


def test_blocked_attempts_are_shown_but_are_not_use():
    store = _seed(Store(":memory:"), sessions=1)
    agent_warrant = next(w for w in store.warrants_for_session("ses_1_0") if w.holder == "crm_agent")
    store.put_action(ActionRecord(action_id="act_blocked", session_id="ses_1_0",
                                  warrant_id=agent_warrant.warrant_id, actor="crm_agent", operation="delete",
                                  resource="crm.opportunities", scale=400, irreversible=True,
                                  allowed=False, blocked=True, at=NOW - timedelta(hours=1)))
    agent = _row(build_report(store, since=NOW - timedelta(days=30)), "crm_agent")
    assert agent.blocked_attempts == 1
    assert "delete" in agent.unused_operations


def test_use_that_broke_the_rules_is_not_evidence_a_permission_is_needed():
    """Regression: a 400-record delete that violated its limits was being counted
    as 'use', so the proposal kept 'delete' and sized the limit from it."""
    store = _seed(Store(":memory:"), sessions=1)
    agent_warrant = next(w for w in store.warrants_for_session("ses_1_0") if w.holder == "crm_agent")
    store.put_action(ActionRecord(action_id="act_violation", session_id="ses_1_0",
                                  warrant_id=agent_warrant.warrant_id, actor="crm_agent", operation="delete",
                                  resource="crm.opportunities", scale=400, irreversible=True,
                                  allowed=False, violation="scale 400 exceeds limit 50",
                                  at=NOW - timedelta(hours=1)))
    report = build_report(store, since=NOW - timedelta(days=30))
    agent = _row(report, "crm_agent")

    assert agent.violations == 1 and agent.used_outside_limits == {"delete": 1}
    assert agent.actions == 4                              # still counted as activity
    assert "delete" in agent.unused_operations
    assert "delete" not in agent.recommended.operations
    assert agent.largest_change == 20                      # the violating delete doesn't set the limit
    assert agent.recommended.irreversible_allowed is False
    assert agent.examples["delete (outside the limits)"] == "act_violation"

    rows = [r for r in csv.DictReader(io.StringIO(report.to_csv())) if r["identity"] == "crm_agent"]
    assert any(r["permission"] == "delete" and "outside the limits" in r["recommendation"] for r in rows)
    assert "Neither counts as use" in report.to_markdown()


def test_external_grants_are_compared_with_observed_use(tmp_path):
    grants_file = tmp_path / "grants.json"
    grants_file.write_text(json.dumps({"grants": [
        {"identity": "crm_agent", "source": "okta", "reference": "app 0oa1",
         "operations": ["read", "archive", "delete", "export"], "targets": ["crm.*", "billing.*"],
         "max_scale": None, "irreversible_allowed": True},
        {"identity": "old_billing_bot", "source": "okta", "operations": ["refund"], "targets": ["billing.*"]},
    ]}))
    grants = load_grants(grants_file)

    # An observed chain: plain OpenTelemetry spans, no warrants at all.
    store = Store(":memory:")
    started = NOW - timedelta(days=2)
    store.put_session("otel_abc", "(unknown)", "(observed from OpenTelemetry) POST /run",
                      {"observed": True}, started)
    store.put_action(ActionRecord(action_id="obs_1", session_id="otel_abc", warrant_id="obs_root_abc",
                                  actor="crm_agent", operation="read", resource="crm.opportunities",
                                  at=started))

    report = build_report(store, since=NOW - timedelta(days=30), grants=grants)
    okta = _row(report, "crm_agent", "okta")
    assert okta.references == ["app 0oa1"]
    assert okta.unused_operations == ["archive", "delete", "export"]
    assert okta.unused_targets == ["billing.*"]
    assert okta.granted_max_scale is None

    dormant = _row(report, "old_billing_bot", "okta")
    assert dormant.actions == 0 and dormant.confidence == "none"
    assert dormant.unused_operations == ["refund"]
    assert not any(r.source == "warrants" for r in report.identities)   # observed chains grant nothing


def test_every_export_format(tmp_path):
    report = build_report(_seed(Store(":memory:")), since=NOW - timedelta(days=30))

    md = report.to_markdown()
    assert "were never used" in md and "may still be needed by work that runs rarely" in md
    assert "Wildcard `crm.*` was only used for: crm.accounts, crm.opportunities" in md

    data = json.loads(report.to_json())
    assert data["unused_permissions"] == report.unused_permissions
    assert data["identities"][0]["recommended_scope"]["operations"]

    rows = list(csv.DictReader(io.StringIO(report.to_csv())))
    kinds = {(r["identity"], r["kind"], r["permission"]) for r in rows}
    assert ("crm_agent", "operation", "delete") in kinds
    assert ("crm_agent", "irreversible", "irreversible actions") in kinds
    assert any(r["kind"] == "size limit" for r in rows)

    html = report.to_html()
    assert "Scope-creep report" in html and "crm_agent" in html


def test_identity_names_are_escaped_in_html():
    store = Store(":memory:")
    report = build_report(store, since=NOW - timedelta(days=1),
                          grants=[Grant("<script>x</script>", "manual", Scope.of(operations=["read"], targets=["a"]))])
    html = report.to_html()
    assert "<script>x" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("value, expected", [(0, 1), (1, 1), (1.2, 2), (24, 50), (30, 50), (60, 100),
                                             (120, 200), (499, 500), (501, 1000)])
def test_proposed_limits_round_up_to_readable_numbers(value, expected):
    from segurai.report import _nice_ceiling

    assert _nice_ceiling(value) == expected


def test_a_delegating_agent_is_credited_with_what_it_passed_on():
    """Found while building the demo: an assistant that only delegates was reported
    as using nothing, and the report recommended removing access the chain needs."""
    segurai.configure(store=":memory:", authority=segurai.Authority())

    @segurai.agent("assistant")
    def assistant():
        crm_agent()

    @segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
    def crm_agent():
        segurai.act("archive", "crm.opportunities", scale=3)

    granted = Scope.of(operations=["read", "archive", "delete"], targets=["crm.*"], max_scale=50)
    with segurai.session(principal="sarah@company.com", request="tidy up", scope=granted):
        assistant()

    report = build_report(segurai._runtime.store, since=utcnow() - timedelta(days=1))
    by_name = {r.identity: r for r in report.identities}
    middle = by_name["assistant"]
    assert middle.used_operations == {"archive": 1}           # used by passing it on
    assert "archive" in middle.recommended.operations         # so the advice keeps it
    assert "delete" in middle.unused_operations               # genuinely unused stays unused
    assert by_name["crm_agent"].used_operations == {"archive": 1}
    assert by_name["sarah@company.com (session root)"].used_operations == {"archive": 1}
