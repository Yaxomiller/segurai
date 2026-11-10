"""Organisation rules: they apply on top of every warrant, and only ever take away."""

import pytest

import segurai
from segurai import Policy, PolicyError, Rule, Scope
from segurai.collector.web import session_page

WIDE = Scope.of(operations=["read", "update", "delete", "export", "refund"],
                targets=["crm.*", "billing.*", "support.*"], max_scale=1000, irreversible_allowed=True)

NO_SUPPORT_DELETES = Rule(name="support agents never delete", effect="deny", agents=["support_*"],
                          operations=["delete", "export"], reason="support work never needs it")
SMALL_BILLING = Rule(name="billing changes stay small", effect="limit", targets=["billing.*"],
                     max_scale=20, irreversible=False)


def _run(*actions, principal="sarah@company.com", agent="support_bot", policy=None):
    segurai.configure(policy=policy or Policy((NO_SUPPORT_DELETES, SMALL_BILLING)))

    @segurai.agent("assistant")
    def assistant():
        return worker()

    @segurai.agent(agent)
    def worker():
        return [segurai.act(*a[:2], **a[2]) if len(a) > 2 else segurai.act(*a) for a in actions]

    with segurai.session(principal=principal, request="r", scope=WIDE) as s:
        records = assistant()
    return s, records


def test_a_deny_rule_matches_any_hop_in_the_chain():
    _, (rec,) = _run(("delete", "crm.accounts"))
    assert not rec.allowed
    (finding,) = [f for f in rec.findings if f.check == "policy"]
    assert "support agents never delete" in finding.reason and "support work never needs it" in finding.reason
    assert finding.clause.startswith("policy pol_")

    # The same action by an agent no rule names is fine (the warrant allows it).
    _, (ok,) = _run(("delete", "crm.accounts"), agent="crm_agent")
    assert ok.allowed


def test_rules_name_agents_anywhere_above_the_actor():
    """A rule about support_bot covers whatever support_bot delegates to."""
    segurai.configure(policy=Policy((NO_SUPPORT_DELETES,)))

    @segurai.agent("support_bot")
    def support():
        return helper()

    @segurai.agent("helper")
    def helper():
        return segurai.act("delete", "support.tickets")

    with segurai.session(principal="p", request="r", scope=WIDE):
        assert not support().allowed


def test_a_limit_rule_caps_changes_but_not_reads():
    _, (big, read, small, undoable) = _run(
        ("update", "billing.invoices", {"scale": 50}),
        ("read", "billing.invoices", {"scale": 5000}),
        ("update", "billing.invoices", {"scale": 20}),
        ("refund", "billing.refunds", {"scale": 1, "irreversible": True}),
        agent="billing_bot")
    assert "caps changes at 20, this changes 50" in big.violation
    assert read.allowed and small.allowed
    assert "forbids irreversible actions" in undoable.violation


def test_principal_rules_ignore_case_and_targets_overlap_wildcards():
    contractors = Rule(name="contractors read only", effect="deny", principals=["*@contractor.example"],
                       operations=["update", "delete"])
    _, (rec,) = _run(("update", "crm.accounts"), principal="Pat@CONTRACTOR.example",
                     agent="crm_agent", policy=Policy((contractors,)))
    assert not rec.allowed

    # An action reported against a whole family of tables overlaps a rule about one of them.
    billing_only = Rule(name="no billing exports", effect="deny", operations=["export"],
                        targets=["billing.invoices"])
    _, (bulk,) = _run(("export", "billing.*"), agent="crm_agent", policy=Policy((billing_only,)))
    assert not bulk.allowed
    _, (elsewhere,) = _run(("export", "crm.*"), agent="crm_agent", policy=Policy((billing_only,)))
    assert elsewhere.allowed


def test_enforce_mode_blocks_on_a_rule():
    segurai.configure(mode=segurai.Mode.ENFORCE, policy=Policy((NO_SUPPORT_DELETES,)))

    @segurai.agent("support_bot")
    def support():
        segurai.act("delete", "crm.accounts")

    with segurai.session(principal="p", request="r", scope=WIDE) as s:
        with pytest.raises(segurai.ViolationError, match="support agents never delete"):
            support()
    (rec,) = s.violations()
    assert rec.blocked


def test_rules_never_excuse_what_the_warrant_forbids():
    segurai.configure(policy=Policy((SMALL_BILLING,)))
    narrow = Scope.of(operations=["read"], targets=["crm.*"])
    with segurai.session(principal="p", request="r", scope=narrow):
        rec = segurai.act("update", "crm.accounts")
    assert {f.check for f in rec.findings} == {"operation"}


def test_every_policy_version_is_in_the_log():
    store = segurai._runtime.store
    first = Policy((NO_SUPPORT_DELETES,))
    second = Policy((NO_SUPPORT_DELETES, SMALL_BILLING))
    segurai.configure(policy=first)
    segurai.configure(policy=first)                 # same rules: recorded once
    segurai.configure(policy=second)
    versions = [v for v, _, _ in store.policies()]
    assert versions == [first.version, second.version]
    assert store.get_policy(second.version) == second.to_dict()
    assert store.audit(segurai._runtime.authority).ok

    store._conn.execute("UPDATE policies SET policy_json = ?", ('{"rules": []}',))
    store._conn.commit()
    assert not store.audit(segurai._runtime.authority).ok        # quietly dropping rules is caught


def test_the_version_depends_only_on_the_rules():
    a = Policy((NO_SUPPORT_DELETES, SMALL_BILLING))
    b = Policy.from_dict(a.to_dict())
    assert a.version == b.version and a.version.startswith("pol_")
    assert Policy((SMALL_BILLING,)).version != a.version
    assert not Policy() and Policy().evaluate("delete", "anything") == []


@pytest.mark.parametrize("rule, message", [
    ({"name": "x", "effect": "allow"}, "effect must be one of"),
    ({"name": "x", "effect": "limit"}, "needs max_scale"),
    ({"name": "x", "effect": "deny", "max_scale": 5}, "belong to limit rules"),
    ({"name": "x", "effect": "limit", "irreversible": True}, "rules only take away"),
    ({"name": "x", "effect": "limit", "max_scale": True}, "whole number"),
    ({"name": "x", "effect": "limit", "max_scale": -1}, "whole number"),
    ({"name": "x", "effect": "deny", "agents": "support_*"}, "list of strings"),
    ({"name": "x", "effect": "deny", "operation": ["delete"]}, "unknown setting"),
    ({"effect": "deny"}, "needs a name"),
])
def test_rules_that_cannot_be_understood_are_refused_at_load_time(rule, message):
    with pytest.raises(PolicyError, match=message):
        Policy.from_dict({"rules": [rule]})


def test_duplicate_rule_names_are_refused():
    with pytest.raises(PolicyError, match="unique"):
        Policy((NO_SUPPORT_DELETES, NO_SUPPORT_DELETES))


def test_the_dashboard_explains_a_broken_rule():
    s, _ = _run(("delete", "crm.accounts"))
    page = session_page(segurai._runtime.store, s.session_id)
    assert "organisation rule that no request can override" in page
    assert "support agents never delete" in page
