"""Tier 1 conditions (Check), the session total, and findings."""

import pytest

import segurai
from segurai import ActionSpec, Check, Scope, arg, count

STALE = Check(field="days_since_activity", op=">=", value=180,
              condition="only records with no recent activity", targets=("crm.opportunities",))
NOT_ACTIVE = Check(field="account_status", op="not_in", value=("active",),
                   condition="must not affect active customers")


def _eval(check, evidence, operation="archive", resource="crm.opportunities"):
    return Scope.of(operations=[operation], targets=["crm.*"], checks=[check]).evaluate(
        operation, resource, scale=1, evidence=evidence)


# ---- Check -----------------------------------------------------------------

def test_a_numeric_condition_passes_and_fails():
    assert _eval(STALE, {"days_since_activity": 400}) == []
    (finding,) = _eval(STALE, {"days_since_activity": 12})
    assert (finding.check, finding.status) == ("condition", "fail")
    assert finding.clause == "only records with no recent activity"


def test_every_item_in_a_list_of_evidence_must_satisfy_the_condition():
    assert _eval(STALE, {"days_since_activity": [200, 365]}) == []
    (finding,) = _eval(STALE, {"days_since_activity": [200, 12, 400]})
    assert finding.status == "fail" and "12" in finding.reason


def test_in_and_not_in():
    assert _eval(NOT_ACTIVE, {"account_status": ["churned", "prospect"]}) == []
    assert _eval(NOT_ACTIVE, {"account_status": ["churned", "active"]})[0].status == "fail"
    only_qa = Check(field="created_by", op="in", value=("qa-script", "load-test"))
    assert _eval(only_qa, {"created_by": "qa-script"}) == []
    assert _eval(only_qa, {"created_by": "sarah"})[0].status == "fail"


def test_missing_evidence_is_unverifiable_not_a_violation():
    (finding,) = _eval(STALE, {})
    assert finding.status == "unverifiable"
    assert "days_since_activity" in finding.reason


def test_evidence_of_the_wrong_type_is_unverifiable():
    (finding,) = _eval(STALE, {"days_since_activity": "recently"})
    assert finding.status == "unverifiable"


def test_conditions_govern_changes_not_reads_by_default():
    assert _eval(STALE, {"days_since_activity": 1}, operation="read") == []
    everywhere = Check(field="region", op="==", value="eu", on="all")
    assert _eval(everywhere, {"region": "us"}, operation="read")[0].status == "fail"


def test_a_condition_can_be_limited_to_some_resources():
    assert _eval(STALE, {"days_since_activity": 1}, resource="crm.accounts") == []


def test_an_unknown_operator_is_rejected():
    with pytest.raises(ValueError, match="op"):
        Check(field="x", op="~=", value=1)


def test_check_round_trips_through_json():
    assert Check.from_dict(NOT_ACTIVE.to_dict()) == NOT_ACTIVE


# ---- Scope.evaluate --------------------------------------------------------

def test_every_failure_is_reported_not_just_the_first():
    scope = Scope.of(operations=["archive"], targets=["crm.opportunities"], max_scale=50,
                     checks=[STALE])
    findings = scope.evaluate("delete", "crm.accounts", scale=400, irreversible=True,
                              evidence={"days_since_activity": 1})
    assert {f.check for f in findings} >= {"operation", "target", "scale", "irreversible"}


def test_permits_still_answers_with_the_first_reason():
    scope = Scope.of(operations=["read"], targets=["crm.*"])
    ok, reason = scope.permits("delete", "crm.x")
    assert not ok and reason.startswith("operation")


def test_a_scope_without_checks_or_total_signs_exactly_as_before():
    """Existing signed warrants must keep verifying after this change."""
    assert set(Scope.of(operations=["read"], targets=["a"]).to_dict()) == {
        "operations", "targets", "max_scale", "irreversible_allowed", "constraints"}


# ---- attenuation -----------------------------------------------------------

PARENT = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50, max_total=50,
                  checks=[STALE])


def test_a_child_inherits_checks_and_total():
    child = Scope.of(targets=["crm.opportunities"]).inherit_unspecified(PARENT)
    assert child.checks == (STALE,) and child.max_total == 50
    assert child.is_subset_of(PARENT)[0]


def test_a_child_cannot_drop_a_check():
    child = Scope(operations=frozenset({"read"}), targets=frozenset({"crm.*"}), max_scale=10, max_total=10)
    ok, reason = child.is_subset_of(PARENT)
    assert not ok and "checks" in reason


def test_a_child_cannot_raise_or_remove_the_total():
    higher = Scope.of(max_total=500).inherit_unspecified(PARENT)
    assert "max_total" in higher.is_subset_of(PARENT)[1]
    unbounded = Scope(operations=frozenset({"read"}), targets=frozenset({"crm.*"}), max_scale=10,
                      checks=(STALE,))
    assert "max_total" in unbounded.is_subset_of(PARENT)[1]


def test_clamping_to_a_ceiling_keeps_its_checks_and_total():
    wide = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=500)
    clamped = wide.clamped_to(PARENT)
    assert clamped.checks == (STALE,) and clamped.max_total == 50 and clamped.max_scale == 50


# ---- the runtime -----------------------------------------------------------

def _session(scope):
    return segurai.session(principal="p", request="r", scope=scope)


def test_the_total_accumulates_across_agents_in_a_session():
    scope = Scope.of(operations=["archive"], targets=["crm.*"], max_scale=50, max_total=50)

    @segurai.agent("first")
    def first():
        return segurai.act("archive", "crm.opportunities", scale=30)

    @segurai.agent("second")
    def second():
        return segurai.act("archive", "crm.leads", scale=30)

    with _session(scope):
        assert first().allowed
        rec = second()
    assert not rec.allowed and "total" in rec.violation
    assert [f.check for f in rec.findings] == ["total"]


def test_reads_do_not_count_toward_the_total():
    scope = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_total=10)
    with _session(scope):
        segurai.act("read", "crm.opportunities", scale=5000)
        assert segurai.act("archive", "crm.opportunities", scale=10).allowed


def test_blocked_actions_do_not_count_toward_the_total():
    segurai.configure(mode=segurai.Mode.ENFORCE)
    scope = Scope.of(operations=["archive"], targets=["crm.*"], max_scale=100, max_total=50)
    with _session(scope):
        with pytest.raises(segurai.ViolationError):
            segurai.act("archive", "crm.opportunities", scale=60)
        assert segurai.act("archive", "crm.opportunities", scale=40).allowed


def test_action_spec_evidence_reaches_the_conditions():
    @segurai.tool(ActionSpec("archive", "crm.{table}", scale=count("ids"),
                             evidence={"account_status": arg("statuses")}))
    def archive_records(table, ids, statuses):
        return len(ids)

    scope = Scope.of(operations=["archive"], targets=["crm.*"], checks=[NOT_ACTIVE])
    with _session(scope) as s:
        archive_records("opportunities", [1, 2], ["churned", "active"])
        (rec,) = s.actions()
    assert not rec.allowed and rec.findings[0].clause == "must not affect active customers"
    assert rec.detail["account_status"] == ["churned", "active"]


def test_findings_are_stored_and_rendered_including_unverifiable_ones():
    scope = Scope.of(operations=["archive"], targets=["crm.*"], checks=[STALE, NOT_ACTIVE])
    with _session(scope) as s:
        segurai.act("archive", "crm.opportunities", scale=2, account_status=["churned", "active"])
        (stored,) = s.actions()
    assert {(f.check, f.status) for f in stored.findings} == {("condition", "unverifiable"),
                                                             ("condition", "fail")}
    out = segurai.render(s.session_id, charset="ascii")
    assert "-> condition not met" in out
    assert "?  cannot verify" in out
