"""Step-up approvals: requests the gateway holds until a person says yes.

Every test that holds a request also checks the CRM never saw it before the
decision - a "held" request that had in fact been sent would be worse than a
refusal - and every approval test checks the CRM saw it exactly once.
"""

import base64
import http.client
import json
import re
import threading
import time
import urllib.parse
from datetime import timedelta

import pytest
from test_gateway import SECRET, FakeCRM

import segurai
from segurai import Policy, Rule, Scope
from segurai.alerts import AlertWorker, Channel
from segurai.approvals import ApprovalError, Need, decide, expire_due, load
from segurai.collector.auth import WebAuth
from segurai.collector.server import CollectorServer
from segurai.evidence import build_pack, verify_pack
from segurai.gateway import (
    APPROVAL_HEADER,
    ApprovalDenied,
    ApprovalRunner,
    GatewayClient,
    GatewayConfig,
    GatewayConfigError,
    GatewayServer,
    Route,
    Upstream,
)
from segurai.issuer import Ceiling
from segurai.models import utcnow
from segurai.policy import PolicyError

PASSWORD = "correct horse battery"
ROUTES = (
    Route("GET", "/opportunities", "search", "crm.opportunities"),
    Route("POST", "/opportunities/bulk_delete", "delete", "crm.opportunities", scale="json:ids|len",
          irreversible=True),
    Route("POST", "/opportunities/bulk_archive", "archive", "crm.opportunities", scale="json:ids|len"),
    Route("GET", "/payroll", "read", "hr.payroll"),
)
GRANTED = Scope.of(operations=["search", "archive", "delete"], targets=["crm.*"], max_scale=500,
                   irreversible_allowed=True)
#: A big permanent change needs a second person (any admin, never the requester).
SECOND_PERSON = Rule(name="big deletes need a second person", effect="approve", targets=["crm.*"],
                     only_irreversible=True, above_scale=100,
                     reason="A permanent change to more than 100 records is a decision for a person.")
IDS = [f"D-{i}" for i in range(150)]


@pytest.fixture
def crm():
    upstream = FakeCRM()
    yield upstream
    upstream.close()


RULES = Policy((SECOND_PERSON,))


def _start(crm, *, policy=RULES, ceilings=(), run_approvals=True, **config):
    store = segurai._runtime.store
    cfg = GatewayConfig(upstreams=(Upstream(name="crm", prefix="/crm", url=crm.url, routes=ROUTES,
                                            headers={"Authorization": SECRET}),), **{"mode": "enforce", **config})
    server = GatewayServer(("127.0.0.1", 0), cfg, store, segurai._runtime.authority.public_only(),
                           policy=policy, ceilings=ceilings, run_approvals=run_approvals)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, GatewayClient(f"http://127.0.0.1:{server.server_address[1]}")


@pytest.fixture
def gateway(crm):
    server, client = _start(crm)
    yield server, client
    server.shutdown()
    server.server_close()


@pytest.fixture
def manual(crm):
    """A gateway whose approved requests are sent only when the test says so."""
    server, client = _start(crm, run_approvals=False)
    yield server, client
    server.shutdown()
    server.server_close()


def _until(check, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if check():
            return True
        time.sleep(0.02)
    raise AssertionError("timed out")


def _hold(client, ids=IDS):
    """Sarah's crm_agent asks to delete 150 deals; returns (session id, approval id, 202 body)."""
    with segurai.session(principal="sarah@acme.example", request="clean up our old sales records",
                         scope=GRANTED) as s:
        with segurai.delegate("crm_agent"):
            status, headers, body = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": ids})
    assert status == 202, body
    return s.session_id, headers[APPROVAL_HEADER], json.loads(body)


def _deletes(crm):
    return [r for r in crm.requests if r["path"].endswith("/bulk_delete")]


# ---- the rule ------------------------------------------------------------------------------

def test_an_approve_rule_applies_only_where_it_says():
    policy = Policy((SECOND_PERSON,))
    assert policy.evaluate("delete", "crm.deals", scale=150, irreversible=True)[0].check == "approval"
    assert policy.evaluate("delete", "crm.deals", scale=100, irreversible=True) == []    # not above 100
    assert policy.evaluate("archive", "crm.deals", scale=150, irreversible=False) == []  # can be undone
    assert policy.evaluate("delete", "hr.payroll", scale=150, irreversible=True) == []   # another system
    again = Policy.from_dict(policy.to_dict())
    assert again.version == policy.version and again.rules[0].to_dict() == SECOND_PERSON.to_dict()


@pytest.mark.parametrize("rule, message", [
    (dict(name="x", effect="deny", approvers=["a@b"]), "belong to approve rules"),
    (dict(name="x", effect="limit", max_scale=5, above_scale=3), "belong to approve rules"),
    (dict(name="x", effect="approve", max_scale=5), "belong to limit rules"),
    (dict(name="x", effect="approve", above_scale=-1), "whole number"),
    (dict(name="x", effect="approve", allow_requester="yes"), "true or false"),
])
def test_approve_rules_are_checked_when_loaded(rule, message):
    with pytest.raises(PolicyError, match=message):
        Rule.from_dict(rule)


def test_outside_the_gateway_an_approval_rule_counts_as_broken():
    # The runtime has nobody to ask, so "needs a yes" reads as "no".
    segurai.configure(mode=segurai.Mode.ENFORCE, policy=Policy((SECOND_PERSON,)))
    with segurai.session(principal="sarah@acme.example", request="tidy up", scope=GRANTED):
        with segurai.delegate("crm_agent"):
            with pytest.raises(segurai.ViolationError, match="needs a person to approve"):
                segurai.act("delete", "crm.opportunities", scale=150, irreversible=True)


# ---- holding --------------------------------------------------------------------------------

def test_a_request_that_needs_approval_is_held_not_sent(crm, gateway):
    server, client = gateway
    session_id, approval_id, reply = _hold(client)
    assert reply["state"] == "pending" and reply["approval_id"] == approval_id
    assert "needs a person to approve" in reply["why"][0]
    assert "not sarah@acme.example" in reply["who_decides"]
    assert _deletes(crm) == []                                     # nothing reached the CRM

    store = server.store
    approval = load(store, approval_id)
    assert approval.state == "pending" and approval.principal == "sarah@acme.example"
    assert json.loads(approval.body) == {"ids": IDS}              # exactly what was asked
    assert all(k.lower() != "authorization" for k, _ in approval.headers)
    (record,) = store.actions_for_session(session_id)
    assert record.blocked and not record.allowed and record.violation.startswith("held for a person's approval")
    assert record.detail["approval"] == {"id": approval_id, "state": "pending"}
    assert store.audit().ok


def test_the_agent_can_ask_how_its_request_stands_but_nobody_else_can(crm, gateway):
    _, client = gateway
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=GRANTED):
        with segurai.delegate("crm_agent"):
            status, headers, _ = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": IDS})
            approval_id = headers[APPROVAL_HEADER]
            assert client.status(approval_id)["state"] == "pending"
    # Another request's agent can't see it: approvals are not a directory.
    with segurai.session(principal="ivan@acme.example", request="look around", scope=GRANTED):
        with segurai.delegate("crm_agent"):
            with pytest.raises(ApprovalDenied):
                client.status(approval_id)
            status, _, body = client.request("GET", "/_segurai/approvals/not-an-id")
            assert status == 404


def test_an_admin_approves_and_the_held_bytes_are_sent_once(crm, gateway):
    server, client = gateway
    session_id, approval_id, _ = _hold(client)
    store = server.store

    with pytest.raises(ApprovalError, match="not sarah"):         # the requester can't release it
        decide(store, approval_id, email="sarah@acme.example", is_admin=True, approve=True)
    with pytest.raises(ApprovalError, match="dashboard admin"):   # nor can someone who isn't an admin
        decide(store, approval_id, email="viewer@acme.example", is_admin=False, approve=True)
    decide(store, approval_id, email="admin@acme.example", is_admin=True, approve=True, note="checked the list")
    _until(lambda: load(store, approval_id).state == "done")

    (sent,) = _deletes(crm)
    assert json.loads(sent["body"]) == {"ids": IDS} and sent["headers"]["Authorization"] == SECRET
    approval = load(store, approval_id)
    assert approval.decided_by == "admin@acme.example" and approval.note == "checked the list"
    assert approval.result_status == 200

    (record,) = store.actions_for_session(session_id)
    assert record.allowed and not record.blocked and record.violation is None
    assert [f.status for f in record.findings] == ["approved"]
    assert "approved by admin@acme.example" in record.findings[0].reason
    assert record.detail["approval"]["state"] == "done" and record.detail["upstream_status"] == 200
    assert store.changed_total(session_id) == 150                 # now it counts: it happened

    with pytest.raises(ApprovalError, match="already"):
        decide(store, approval_id, email="admin@acme.example", is_admin=True, approve=True)
    time.sleep(0.6)                                                # a runner pass later: still once
    assert len(_deletes(crm)) == 1
    assert store.audit().ok and store.audit().amendments >= 2     # every step is in the log


def test_the_agent_can_wait_for_the_answer(crm, gateway):
    server, client = gateway
    results = {}

    def approve_when_held():
        _until(lambda: server.store.approvals(states=("pending",)))
        row = server.store.approvals(states=("pending",))[0]
        decide(server.store, row["approval_id"], email="admin@acme.example", is_admin=True, approve=True)

    helper = threading.Thread(target=approve_when_held)
    helper.start()
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=GRANTED):
        with segurai.delegate("crm_agent"):
            results["answer"] = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": IDS}, wait=10)
    helper.join()
    status, _, body = results["answer"]
    assert status == 200 and json.loads(body)["ok"] is True       # the CRM's own answer


def test_a_denied_request_is_never_sent(crm, gateway):
    server, client = gateway
    session_id, approval_id, _ = _hold(client)
    decide(server.store, approval_id, email="admin@acme.example", is_admin=True, approve=False,
           note="some of these are live customers")
    time.sleep(0.6)
    assert _deletes(crm) == []
    (record,) = server.store.actions_for_session(session_id)
    assert record.blocked and "denied by admin@acme.example: some of these are live customers" in record.violation
    with segurai.session(principal="x@acme.example", request="x", scope=GRANTED):
        pass
    status = load(server.store, approval_id).public()
    assert status["state"] == "denied" and status["note"] == "some of these are live customers"


def test_a_request_nobody_decides_expires(crm, gateway):
    server, client = gateway
    session_id, approval_id, _ = _hold(client)
    later = utcnow() + timedelta(minutes=61)                       # past the 60-minute window
    (expired,) = expire_due(server.store, later)
    assert expired.approval_id == approval_id and expired.state == "expired"
    with pytest.raises(ApprovalError, match="already expired"):
        decide(server.store, approval_id, email="admin@acme.example", is_admin=True, approve=True)
    (record,) = server.store.actions_for_session(session_id)
    assert "nobody approved it in time" in record.violation
    assert _deletes(crm) == []


def test_an_approval_never_outlives_the_agents_warrant(crm, gateway):
    _, client = gateway
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=GRANTED,
                         ttl=timedelta(minutes=5)):
        with segurai.delegate("crm_agent"):
            _, headers, _ = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": IDS})
    approval = load(segurai._runtime.store, headers[APPROVAL_HEADER])
    assert approval.expires_at - approval.created_at <= timedelta(minutes=5, seconds=1)


def test_two_runners_never_send_the_same_request_twice(crm, manual):
    server, client = manual
    _, approval_id, _ = _hold(client)
    decide(server.store, approval_id, email="admin@acme.example", is_admin=True, approve=True)
    runners = [ApprovalRunner(server), ApprovalRunner(server), ApprovalRunner(server)]
    threads = [threading.Thread(target=r.run_once) for r in runners]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(_deletes(crm)) == 1 and load(server.store, approval_id).state == "done"


def test_if_the_rules_change_while_it_waits_it_is_not_sent(crm, manual):
    server, client = manual
    session_id, approval_id, _ = _hold(client)
    decide(server.store, approval_id, email="admin@acme.example", is_admin=True, approve=True)
    server.policy = Policy((SECOND_PERSON, Rule(name="freeze", effect="deny", targets=["crm.*"],
                                                 operations=["delete"], reason="quarter-end freeze")))
    ApprovalRunner(server).run_once()
    approval = load(server.store, approval_id)
    assert approval.state == "failed" and "quarter-end freeze" in approval.error
    assert _deletes(crm) == []
    (record,) = server.store.actions_for_session(session_id)
    assert record.blocked and "but not sent" in record.violation


def test_observe_mode_holds_nothing(crm):
    server, client = _start(crm, mode="observe")
    try:
        with segurai.session(principal="sarah@acme.example", request="clean up", scope=GRANTED):
            with segurai.delegate("crm_agent"):
                status, _, _ = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": IDS})
        assert status == 200 and len(_deletes(crm)) == 1
        assert server.store.approvals() == []
    finally:
        server.shutdown()
        server.server_close()


def test_a_body_too_big_to_hold_is_refused(crm, gateway, monkeypatch):
    monkeypatch.setattr("segurai.gateway.MAX_HELD_BODY", 100)
    _, client = gateway
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=GRANTED):
        with segurai.delegate("crm_agent"):
            status, _, _ = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": IDS})
    assert status == 403 and _deletes(crm) == []


# ---- step-up: beyond the request, inside the person's ceiling --------------------------------

SALES = Ceiling(name="sales", scope=Scope.of(operations=["search", "archive", "delete"], targets=["crm.*"],
                                              max_scale=500, irreversible_allowed=True))


def _proven(session_id, principal="sarah@acme.example", ceiling="sales"):
    """Make a session look issued by the issuer: a proven person, under a ceiling."""
    store = segurai._runtime.store
    row = store.get_session(session_id)
    store.put_session(session_id, principal, row.request, {"issued_under": ceiling}, row.started_at,
                      identity={"principal": principal, "issuer": "https://login.acme.example"})


def _ask(client, target, body=None, *, scope, proven=True):
    with segurai.session(principal="sarah@acme.example", request="how is the pipeline looking?",
                         scope=scope) as s:
        if proven:
            _proven(s.session_id)
        with segurai.delegate("crm_agent"):
            status, headers, payload = client.request("POST" if body is not None else "GET", target, body)
    return s.session_id, status, headers, json.loads(payload or b"{}")


def test_step_up_asks_the_person_when_an_agent_goes_beyond_the_request(crm):
    server, client = _start(crm, policy=Policy(), step_up=True, ceilings=[SALES])
    try:
        read_only = Scope.of(operations=["search"], targets=["crm.*"], max_scale=50)
        session_id, status, headers, reply = _ask(client, "/crm/opportunities/bulk_archive",
                                                  {"ids": IDS[:10]}, scope=read_only)
        assert status == 202 and "beyond what the request asked for" in " ".join(reply["why"])
        assert reply["who_decides"].startswith("sarah@acme.example, or")
        approval_id = headers[APPROVAL_HEADER]
        # Here the person who asked decides: it is within their own authority.
        decide(server.store, approval_id, email="sarah@acme.example", is_admin=False, approve=True)
        _until(lambda: load(server.store, approval_id).state == "done")
        assert len([r for r in crm.requests if r["path"].endswith("/bulk_archive")]) == 1
        (record,) = server.store.actions_for_session(session_id)
        assert record.allowed and {f.status for f in record.findings} == {"approved"}
    finally:
        server.shutdown()
        server.server_close()


def test_step_up_never_reaches_past_the_ceiling_a_rule_or_an_unproven_person(crm):
    deny = Rule(name="never payroll", effect="deny", targets=["hr.*"])
    server, client = _start(crm, policy=Policy((deny,)), step_up=True, ceilings=[SALES])
    try:
        read_only = Scope.of(operations=["search"], targets=["crm.*"], max_scale=50)
        # Beyond the ceiling itself (sales may never touch HR): refused.
        _, status, _, _ = _ask(client, "/crm/payroll", scope=read_only)
        assert status == 403
        # Beyond the ceiling's size limit: refused.
        _, status, _, _ = _ask(client, "/crm/opportunities/bulk_archive", {"ids": [f"D-{i}" for i in range(600)]},
                               scope=read_only)
        assert status == 403
        # A session nobody proved, so no ceiling to ask under: refused.
        _, status, _, _ = _ask(client, "/crm/opportunities/bulk_archive", {"ids": IDS[:5]}, scope=read_only,
                               proven=False)
        assert status == 403
        assert server.store.approvals() == [] and crm.requests == []
    finally:
        server.shutdown()
        server.server_close()


def test_step_up_needs_the_ceilings(crm):
    with pytest.raises(GatewayConfigError, match="ceilings"):
        _start(crm, step_up=True)
    with pytest.raises(GatewayConfigError, match="_segurai"):
        Upstream(name="x", prefix="/_segurai", url="http://127.0.0.1:1", routes=ROUTES)


# ---- who may decide ---------------------------------------------------------------------------

def test_who_may_decide():
    named = Need("r", "why", approvers=("*@security.acme.example",))
    assert named.allows("ana@security.acme.example", is_admin=False, principal="sarah@acme.example")
    assert not named.allows("admin@acme.example", is_admin=True, principal="sarah@acme.example")
    admins = Need("r", "why")
    assert admins.allows("admin@acme.example", is_admin=True, principal="sarah@acme.example")
    assert not admins.allows("SARAH@acme.example", is_admin=True, principal="sarah@acme.example")
    own = Need("r", "why", requester=True)
    assert own.allows("sarah@acme.example", is_admin=False, principal="sarah@acme.example")


# ---- the dashboard ------------------------------------------------------------------------------

class Browser:
    def __init__(self, port):
        self.port, self.cookies = port, {}

    def request(self, method, path, form=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        h = dict(headers or {})
        if self.cookies:
            h["Cookie"] = "; ".join(f"{k}={v}" for k, v in self.cookies.items())
        body = urllib.parse.urlencode(form).encode() if form is not None else None
        if body is not None:
            h["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            payload = r.read()
            for name, value in r.getheaders():
                if name.lower() == "set-cookie":
                    key, _, rest = value.partition("=")
                    self.cookies[key] = rest.split(";")[0]
            return r.status, dict(r.getheaders()), payload.decode("utf-8", "replace")
        finally:
            conn.close()

    def sign_in(self, email):
        _, _, page = self.request("GET", "/login")
        csrf = re.search(r"name='csrf' value='([^']+)'", page).group(1)
        assert self.request("POST", "/login", {"csrf": csrf, "email": email, "password": PASSWORD,
                                               "next": "/"})[0] == 303


@pytest.fixture
def dashboard():
    store = segurai._runtime.store
    auth = WebAuth(store, cookie_secure=False)
    auth.add_user("admin@acme.example", "admin", password=PASSWORD)
    auth.add_user("sarah@acme.example", "viewer", password=PASSWORD)
    server = CollectorServer(("127.0.0.1", 0), store, verifier=segurai._runtime.authority.public_only(),
                             auth=auth, signer=segurai._runtime.authority)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


def test_a_person_approves_on_the_dashboard(crm, gateway, dashboard):
    server, client = gateway
    session_id, approval_id, _ = _hold(client)
    port = dashboard.server_address[1]

    sarah = Browser(port)
    sarah.sign_in("sarah@acme.example")
    status, _, page = sarah.request("GET", "/approvals")
    assert status == 200 and "Waiting for someone else" in page and "Approve and send" not in page
    assert "D-149" in page or "D-1" in page                        # the held body is shown

    admin = Browser(port)
    admin.sign_in("admin@acme.example")
    status, _, page = admin.request("GET", f"/approvals/{approval_id}")
    assert status == 200 and "Approve and send" in page and "t be undone" in page
    csrf = re.search(r"name='csrf' value='([^']+)'", page).group(1)
    # A forged form (no CSRF token) and a post from another site are both refused.
    assert admin.request("POST", f"/approvals/{approval_id}", {"decision": "approve"})[0] == 403
    assert admin.request("POST", f"/approvals/{approval_id}", {"csrf": csrf, "decision": "approve"},
                         headers={"Origin": "http://evil.example"})[0] == 403
    assert load(server.store, approval_id).state == "pending" and _deletes(crm) == []

    status, headers, _ = admin.request("POST", f"/approvals/{approval_id}",
                                       {"csrf": csrf, "decision": "approve", "note": "ok"})
    assert status == 303 and "Approved" in urllib.parse.unquote_plus(headers["Location"])
    _until(lambda: load(server.store, approval_id).state == "done")
    assert len(_deletes(crm)) == 1
    log = server.store.access_log(email="admin@acme.example")
    assert any(e["method"] == "APPROVE" and e["path"] == f"/approvals/{approval_id}" for e in log)
    status, _, page = admin.request("GET", f"/sessions/{session_id}")
    assert "APPROVED" in page and "approved by admin@acme.example" in page


def test_alerts_ask_for_an_approval_with_a_link_to_it(crm, gateway):
    server, client = gateway
    sent = []

    class Inbox(Channel):
        def send(self, headline, lines, payload):
            sent.append((headline, lines, payload))

    worker = AlertWorker(store=server.store, channels=[Inbox(name="ops")], public_url="https://segurai.acme.example")
    worker.run_once()                                              # start the cursor at the end
    _, approval_id, _ = _hold(client)
    worker.run_once()
    ((headline, lines, payload),) = sent
    assert headline.startswith("Needs your approval: crm_agent wants to delete 150 records")
    assert lines[-1] == f"https://segurai.acme.example/approvals/{approval_id}"
    assert payload["event"] == "approval" and payload["approval_id"] == approval_id


# ---- evidence ---------------------------------------------------------------------------------

def test_the_evidence_pack_carries_the_decision_and_tampering_shows(crm, gateway):
    server, client = gateway
    session_id, approval_id, _ = _hold(client)
    decide(server.store, approval_id, email="admin@acme.example", is_admin=True, approve=True)
    _until(lambda: load(server.store, approval_id).state == "done")

    authority = segurai._runtime.authority
    pack = build_pack(server.store, session_id, authority)
    report = verify_pack(pack, trusted_key=authority.public_key_pem())
    assert report.ok, report.problems
    import io
    import zipfile
    records = json.loads(zipfile.ZipFile(io.BytesIO(pack)).read("records.json"))
    (held,) = records["approval"]
    assert held["decided_by"] == "admin@acme.example" and held["state"] == "done"
    assert base64.b64decode(held["body"]) == json.dumps({"ids": IDS}).encode()

    # Rewriting who approved it is caught.
    server.store._conn.execute("UPDATE approvals SET decided_by = ? WHERE approval_id = ?",
                               ("someone-else@acme.example", approval_id))
    server.store._conn.commit()
    problems = [p for p in server.store.audit().problems if p.ref_id == approval_id]
    assert problems and "edited" in str(problems[0])


# ---- configuration ------------------------------------------------------------------------------

_CONFIG = '''
[server]
database = "segurai.db"
key = "segurai.key"

[[policy.rules]]
name = "big deletes need a second person"
targets = ["crm.*"]
effect = "approve"
only_irreversible = true
above_scale = 100
approvers = ["*@security.acme.example"]

[gateway]
approval_minutes = 30
{extra}
[[gateway.upstreams]]
name = "crm"
prefix = "/crm"
url = "https://crm.internal.acme.example"
[[gateway.upstreams.routes]]
method = "POST"
path = "/opportunities/bulk_delete"
operation = "delete"
resource = "crm.opportunities"
scale = "json:ids|len"
irreversible = true
'''


def test_the_configuration_file_sets_up_approvals(tmp_path):
    from segurai.config import ConfigError, load_config

    path = tmp_path / "segurai.toml"
    path.write_text(_CONFIG.format(extra=""), encoding="utf-8")
    config = load_config(path)
    assert config.gateway.approval_minutes == 30 and not config.gateway.step_up
    (rule,) = config.policy.rules
    assert rule.effect == "approve" and rule.approvers == ("*@security.acme.example",)

    path.write_text(_CONFIG.format(extra="step_up = true"), encoding="utf-8")
    with pytest.raises(ConfigError, match=r"needs \[issuer\]"):
        load_config(path)
    path.write_text(_CONFIG.format(extra="approval_minutes_typo = 5"), encoding="utf-8")
    with pytest.raises(ConfigError, match="unknown setting"):
        load_config(path)
