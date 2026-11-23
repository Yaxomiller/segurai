"""Governed templates: the rendered configuration loads, and the agent stays inside it.

The agents run for real through a real gateway, with Claude played from a
script, so every test shows what each tool call actually reached.
"""

import json
import py_compile
import threading

import pytest
from test_gateway import FakeCRM

import segurai
from segurai.config import load_config
from segurai.gateway import GatewayServer
from segurai.templates import TEMPLATES, TemplateError, get

anthropic_types = pytest.importorskip("anthropic.types.beta")

BASE = """
[server]
database = "segurai.db"

[issuer]
[[issuer.trusted]]
issuer = "https://login.acme.example"
audience = "segurai"

"""


def _config(tmp_path, name, **params):
    path = tmp_path / "segurai.toml"
    path.write_text(BASE + get(name).render(params), encoding="utf-8")
    return load_config(path)


def reply(stop, *blocks):
    return anthropic_types.BetaMessage.model_validate({
        "id": "m", "type": "message", "role": "assistant", "model": "scripted", "content": list(blocks),
        "stop_reason": stop, "stop_sequence": None, "usage": {"input_tokens": 10, "output_tokens": 10}})


def use(name, given, i):
    return {"type": "tool_use", "id": i, "name": name, "input": given}


class Script:
    def __init__(self, *turns):
        self.turns = list(turns)
        self.seen_system = None

    def turn(self, system, messages, tools):
        self.seen_system = system
        return self.turns.pop(0)


@pytest.fixture
def crm():
    upstream = FakeCRM()
    yield upstream
    upstream.close()


def _serve(config):
    server = GatewayServer(("127.0.0.1", 0), config.gateway, segurai._runtime.store,
                           segurai._runtime.authority.public_only(), policy=config.policy)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.mark.parametrize("name", sorted(TEMPLATES))
def test_every_template_renders_a_configuration_that_loads(tmp_path, monkeypatch, name):
    template = get(name)
    monkeypatch.setenv(template.values()["credential_env"], "Bearer test")
    config = _config(tmp_path, name)
    (upstream,) = config.gateway.upstreams
    assert [r.operation for r in upstream.routes] == [t.operation for t in template.tools]
    assert config.policy.rules and config.issuer.ceilings[0].name == name
    # The tools Claude sees are exactly the routes, strictly described.
    for tool in template.tools:
        schema = tool.schema()
        assert schema["strict"] and schema["input_schema"]["additionalProperties"] is False


def test_parameters_are_checked():
    with pytest.raises(TemplateError, match="no parameter"):
        get("refunds").values({"auto_limit": 5})
    with pytest.raises(TemplateError, match="whole number"):
        get("refunds").values({"auto_limit_cents": "lots"})
    with pytest.raises(TemplateError, match="URL"):
        get("crm-hygiene").values({"crm_url": "crm.internal"})
    with pytest.raises(TemplateError, match="start with /"):
        get("crm-hygiene").values({"delete_path": "deals/delete"})
    with pytest.raises(TemplateError, match="no template"):
        get("payroll")
    assert get("crm-hygiene").values({"approvers": "a@x.example, b@x.example"})["approvers"] == ["a@x.example",
                                                                                               "b@x.example"]


def test_the_crm_agent_archives_stale_deals_and_nothing_else(tmp_path, monkeypatch, crm):
    monkeypatch.setenv("CRM_AUTHORIZATION", "Bearer crm")
    config = _config(tmp_path, "crm-hygiene", crm_url=crm.url, stale_days=180)
    server, url = _serve(config)
    brain = Script(
        reply("tool_use", use("find_stale_deals", {"inactive_days": 180}, "t1")),
        reply("tool_use", use("archive_deals", {"ids": ["D-1", "D-2"], "days_since_activity": [400, 300],
                                                "reason": "stale"}, "t2")),
        reply("tool_use", use("archive_deals", {"ids": ["D-3", "D-4"], "days_since_activity": [500, 12],
                                                "reason": "stale"}, "t3")),
        reply("tool_use", use("delete_deals", {"ids": ["D-1"], "days_since_activity": [400],
                                               "reason": "duplicate"}, "t4")),
        reply("end_turn", {"type": "text", "text": "Archived 2 deals; one batch refused; a deletion waits."}),
    )
    scope = config.issuer.ceilings[0].scope
    try:
        with segurai.session(principal="ops@acme.example", request="tidy the CRM", scope=scope):
            with segurai.delegate("crm_hygiene_agent"):
                agent = get("crm-hygiene").agent(url, {"crm_url": crm.url}, brain=brain)
                answer = agent.run("Tidy up the CRM.")
        assert answer.startswith("Archived 2 deals")
        assert "180 days" in brain.seen_system
        assert [e["status"] for e in agent.log] == [200, 200, 403, 202]
        assert "active in the last 180 days" in agent.log[2]["refused"]
        assert agent.log[3]["approval_id"].startswith("apr_")
        assert [r["path"] for r in crm.requests] == ["/api/deals?inactive_days=180", "/api/deals/archive"]
        assert json.loads(crm.requests[1]["body"])["ids"] == ["D-1", "D-2"]
    finally:
        server.shutdown()
        server.server_close()


def test_the_refunds_agent_refunds_small_waits_on_large_and_never_on_huge(tmp_path, monkeypatch, crm):
    monkeypatch.setenv("BILLING_AUTHORIZATION", "Bearer billing")
    config = _config(tmp_path, "refunds", billing_url=crm.url, auto_limit_cents=5000, max_refund_cents=50000)
    server, url = _serve(config)
    brain = Script(
        reply("tool_use", use("look_up_order", {"order_id": "O-17"}, "t1")),
        reply("tool_use", use("issue_refund", {"order_id": "O-17", "amount_cents": 2000, "reason": "late"}, "t2")),
        reply("tool_use", use("issue_refund", {"order_id": "O-18", "amount_cents": 20000, "reason": "broken"},
                              "t3")),
        reply("tool_use", use("issue_refund", {"order_id": "O-19", "amount_cents": 90000, "reason": "?"}, "t4")),
        reply("end_turn", {"type": "text", "text": "One refund done, one waiting, one refused."}),
    )
    scope = config.issuer.ceilings[0].scope
    try:
        with segurai.session(principal="support@acme.example", request="handle today's refund tickets",
                             scope=scope):
            with segurai.delegate("refunds_agent"):
                agent = get("refunds").agent(url, {"billing_url": crm.url}, brain=brain)
                agent.run("Handle today's refund tickets.")
        assert [e["status"] for e in agent.log] == [200, 200, 202, 403]
        assert "no refund over $500" in agent.log[3]["refused"]
        assert [r["path"] for r in crm.requests] == ["/api/orders/O-17", "/api/refunds"]
    finally:
        server.shutdown()
        server.server_close()


def test_init_writes_the_configuration_and_a_runnable_agent(tmp_path, capsys):
    from segurai.cli import main

    out = tmp_path / "job"
    assert main(["template", "init", "refunds", "--out", str(out), "--set", "auto_limit_cents=2500"]) == 0
    assert "refunds over $25 need a person" in (out / "refunds.toml").read_text(encoding="utf-8")
    script = out / "refunds_agent.py"
    py_compile.compile(str(script), doraise=True)
    assert "'auto_limit_cents': 2500" in script.read_text(encoding="utf-8")
    assert main(["template", "init", "refunds", "--out", str(out)]) == 1         # won't overwrite
    assert "exists" in capsys.readouterr().out
    assert main(["template", "show", "crm-hygiene"]) == 0
    assert "deleting deals needs a second person" in capsys.readouterr().out
