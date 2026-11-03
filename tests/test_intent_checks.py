"""The intent compiler writing Checks: catalog evidence, validation, and end to end."""

import json

import httpx2
from anthropic import Anthropic, DefaultHttpxClient

import segurai
from segurai.intent import Catalog, ClaudeBackend, IntentCompiler, ScopeContract

CATALOG = Catalog.from_dict({
    "operations": {"read": "look up", "search": "search", "archive": "hide", "delete": "remove"},
    "resources": {
        "crm.opportunities": {
            "description": "deals",
            "evidence": {"days_since_activity": "number: days since activity",
                         "account_status": "active, churned or prospect"},
        },
        "crm.accounts": "customers",
    },
})

STALE = {"field": "days_since_activity", "op": ">=", "number": 180.0, "text": None, "values": [],
         "condition": "only records with no recent activity", "targets": ["crm.opportunities"]}
NOT_ACTIVE = {"field": "account_status", "op": "not_in", "number": None, "text": None,
              "values": ["active"], "condition": "must not affect active customers",
              "targets": ["crm.opportunities"]}

CONTRACT = {
    "goal": "Archive outdated sales records",
    "expected_operations": ["search", "archive"],
    "expected_targets": ["crm.opportunities"],
    "expected_scale": {"unit": "records", "typical_max": 50},
    "implied_constraints": ["only records with no recent activity", "must not affect active customers"],
    "checks": [STALE, NOT_ACTIVE],
    "irreversible_expected": False,
    "clarifications_needed": [],
}


class FakeBackend:
    last_model = "fake-model"

    def __init__(self, reply):
        self.reply = reply

    def complete(self, system, request, catalog):
        return self.reply


def _compile(reply):
    return IntentCompiler(CATALOG, FakeBackend(reply)).compile("clean up our old sales records")


def test_the_catalog_shows_evidence_to_the_model():
    text = CATALOG.render()
    assert "evidence: account_status (active, churned or prospect); days_since_activity" in text
    assert CATALOG.evidence_for(["crm.*"]) == {"days_since_activity", "account_status"}
    assert CATALOG.evidence_for(["crm.accounts"]) == set()


def test_checks_from_the_model_become_scope_checks():
    compiled = _compile(CONTRACT)
    checks = compiled.scope().checks
    assert [(c.field, c.op, c.value) for c in checks] == [
        ("days_since_activity", ">=", 180), ("account_status", "not_in", ("active",))]
    assert compiled.problems == ()


def test_a_check_on_evidence_the_catalog_lacks_is_dropped_but_its_condition_kept():
    reply = {**CONTRACT, "implied_constraints": [], "checks": [
        {**STALE, "field": "lifetime_value", "op": "<", "number": 1000.0,
         "condition": "only low-value deals"}]}
    compiled = _compile(reply)
    assert compiled.contract.checks == ()
    assert "only low-value deals" in compiled.contract.implied_constraints
    assert any("lifetime_value" in p for p in compiled.problems)


def test_a_check_aimed_at_a_resource_that_does_not_exist_is_dropped():
    compiled = _compile({**CONTRACT, "checks": [{**STALE, "targets": ["warehouse.orders"]}]})
    assert compiled.contract.checks == ()
    assert any("warehouse.orders" in p for p in compiled.problems)


def test_an_unreadable_check_is_reported_not_fatal():
    compiled = _compile({**CONTRACT, "checks": [{**STALE, "op": "~"}, NOT_ACTIVE]})
    assert [c.field for c in compiled.contract.checks] == ["account_status"]
    assert any("could not be read" in p for p in compiled.problems)


def test_a_stored_contract_round_trips_with_its_checks():
    contract = _compile(CONTRACT).contract
    assert ScopeContract.from_dict(contract.to_dict()).checks == contract.checks


def test_compiled_checks_catch_a_violating_action_end_to_end():
    segurai.configure(intent=IntentCompiler(CATALOG, FakeBackend(CONTRACT)))
    with segurai.session(principal="sarah@company.com", request="clean up our old sales records"):
        rec = segurai.act("archive", "crm.opportunities", scale=2,
                          days_since_activity=[400, 9], account_status=["churned"])
    assert not rec.allowed
    assert [f.clause for f in rec.findings] == ["only records with no recent activity"]


def test_the_api_request_asks_for_checks_and_shows_the_evidence():
    captured = []

    def handler(request):
        captured.append(json.loads(request.content))
        return httpx2.Response(200, json={
            "id": "msg_test", "type": "message", "role": "assistant", "model": "claude-opus-5",
            "content": [{"type": "text", "text": json.dumps(CONTRACT)}],
            "stop_reason": "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        })

    client = Anthropic(api_key="test-key", max_retries=0,
                       http_client=DefaultHttpxClient(transport=httpx2.MockTransport(handler)))
    compiled = IntentCompiler(CATALOG, ClaudeBackend(client)).compile("clean up our old sales records")

    assert len(compiled.contract.checks) == 2
    body = captured[0]
    schema = json.dumps(body["output_config"]["format"]["schema"])
    assert '"checks"' in schema and '"not_in"' in schema and '">="' in schema
    assert "evidence: account_status" in body["system"][0]["text"]
