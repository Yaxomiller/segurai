"""Intent compiler: catalog checks, the ceiling, and session integration.

A fake backend stands in for Claude, so these tests make no API calls.
"""

import pytest

import segurai
from segurai import Scope
from segurai.intent import Catalog, IntentCompiler, IntentError

CATALOG = Catalog.from_dict({
    "operations": {"read": "look up", "search": "search", "archive": "hide without deleting",
                   "delete": "remove permanently", "update": "change"},
    "resources": {"crm.opportunities": "deals", "crm.accounts": "customers",
                  "billing.invoices": "invoices"},
})

SARAH = {
    "goal": "Remove or archive outdated sales records",
    "expected_operations": ["search", "archive", "delete"],
    "expected_targets": ["crm.opportunities"],
    "expected_scale": {"unit": "records", "typical_max": 50},
    "implied_constraints": ["only records with no recent activity", "must not affect active customers"],
    "irreversible_expected": False,
    "clarifications_needed": [],
}


class FakeBackend:
    """Returns a canned contract and remembers what it was asked."""

    def __init__(self, reply):
        self.reply = reply
        self.calls = []
        self.last_model = "fake-model"

    def complete(self, system, request, catalog):
        self.calls.append((system, request))
        return self.reply


def _compile(reply, request="clean up our old sales records"):
    return IntentCompiler(CATALOG, FakeBackend(reply)).compile(request)


def test_contract_becomes_the_root_scope():
    compiled = _compile(SARAH)
    scope = compiled.scope()
    assert scope.operations == {"search", "archive", "delete"}
    assert scope.targets == {"crm.opportunities"}
    assert scope.max_scale == 50
    assert scope.irreversible_allowed is False
    assert "must not affect active customers" in scope.constraints
    assert compiled.problems == ()
    assert compiled.model == "fake-model"


def test_names_outside_the_catalog_are_dropped_and_reported():
    compiled = _compile({**SARAH, "expected_operations": ["archive", "purge"],
                         "expected_targets": ["crm.opportunities", "warehouse.orders"]})
    assert compiled.contract.expected_operations == ("archive",)
    assert compiled.contract.expected_targets == ("crm.opportunities",)
    assert any("purge" in p for p in compiled.problems)
    assert any("warehouse.orders" in p for p in compiled.problems)


def test_wildcards_are_kept_only_when_they_reach_real_resources():
    compiled = _compile({**SARAH, "expected_targets": ["crm.*", "nothing.*"]})
    assert compiled.contract.expected_targets == ("crm.*",)
    assert any("nothing.*" in p for p in compiled.problems)


def test_a_change_with_no_scale_fails_closed():
    compiled = _compile({**SARAH, "expected_scale": {"unit": "records", "typical_max": None}})
    assert compiled.contract.typical_max == 1
    assert any("no typical scale" in p for p in compiled.problems)


def test_read_only_work_needs_no_scale():
    compiled = _compile({**SARAH, "expected_operations": ["read", "search"],
                         "expected_scale": {"unit": "records", "typical_max": None}})
    assert compiled.contract.typical_max is None
    assert compiled.problems == ()


def test_the_ceiling_means_a_request_can_never_grant_more_than_the_person_has():
    greedy = {**SARAH, "expected_operations": ["read", "delete", "update"],
              "expected_targets": ["crm.*", "billing.invoices"],
              "expected_scale": {"unit": "records", "typical_max": 10000},
              "irreversible_expected": True}
    ceiling = Scope.of(operations=["read", "search", "archive"], targets=["crm.opportunities"],
                       max_scale=100)
    scope = _compile(greedy, "delete everything").scope(ceiling)
    assert scope.operations == {"read"}
    assert scope.targets == {"crm.opportunities"}
    assert scope.max_scale == 100
    assert scope.irreversible_allowed is False


def test_malformed_model_output_is_an_intent_error():
    with pytest.raises(IntentError, match="malformed"):
        _compile({**SARAH, "expected_scale": {"typical_max": "lots"}})


def test_an_empty_request_is_refused_before_any_call():
    backend = FakeBackend(SARAH)
    with pytest.raises(IntentError, match="empty"):
        IntentCompiler(CATALOG, backend).compile("   ")
    assert backend.calls == []


def test_the_system_prompt_is_identical_on_every_call_so_it_can_be_cached():
    backend = FakeBackend(SARAH)
    compiler = IntentCompiler(CATALOG, backend)
    compiler.compile("first request")
    compiler.compile("second request")
    assert backend.calls[0][0] == backend.calls[1][0]
    assert "crm.opportunities" in backend.calls[0][0]


def test_catalog_renders_the_same_whatever_order_it_was_written_in():
    a = Catalog.from_dict({"operations": {"b": "", "a": ""}, "resources": {"y": "", "x": ""}})
    b = Catalog.from_dict({"operations": {"a": "", "b": ""}, "resources": {"x": "", "y": ""}})
    assert a.render() == b.render()


def test_session_derives_its_scope_from_the_request():
    segurai.configure(intent=IntentCompiler(CATALOG, FakeBackend(SARAH)))
    ceiling = Scope.of(operations=["read", "search", "archive", "delete"], targets=["crm.*"],
                       max_scale=500)
    with segurai.session(principal="sarah@company.com",
                         request="clean up our old sales records", ceiling=ceiling) as s:
        rec = segurai.act("delete", "crm.opportunities", scale=400)

    assert not rec.allowed and "exceeds limit 50" in rec.violation
    stored = segurai._runtime.store.get_session(s.session_id).contract
    assert stored["contract"]["goal"] == SARAH["goal"]
    assert stored["prompt_version"]
    out = segurai.render(s.session_id, charset="ascii")
    assert "Goal      : Remove or archive outdated sales records" in out
    assert "Condition : must not affect active customers" in out


def test_session_without_a_scope_or_compiler_says_what_to_do():
    with pytest.raises(ValueError, match="intent compiler"):
        with segurai.session(principal="p", request="r"):
            pass


def test_the_ceiling_also_clamps_a_hand_written_scope():
    with segurai.session(principal="p", request="r",
                         scope=Scope.of(operations=["read", "delete"], targets=["crm.*"]),
                         ceiling=Scope.of(operations=["read"], targets=["crm.accounts"])) as s:
        assert s.root_warrant.scope.operations == {"read"}
        assert s.root_warrant.scope.targets == {"crm.accounts"}


def test_narrow_keeps_the_overlap_when_asked_for_a_wider_pattern():
    ceiling = Scope.of(operations=["read"], targets=["crm.opportunities", "billing.invoices"])
    assert ceiling.narrow(targets=["crm.*"]).targets == {"crm.opportunities"}
