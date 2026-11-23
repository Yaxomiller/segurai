"""Triggers for jobs nobody types, the intent cache, and revocation."""

import json
import threading
import time
from datetime import timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from test_gateway import SECRET, FakeCRM

import segurai
from segurai import IdentityVerifier, Policy, Rule, Scope, TrustedIssuer
from segurai.approvals import decide, load
from segurai.evidence import build_pack, verify_pack
from segurai.gateway import (
    APPROVAL_HEADER,
    GatewayClient,
    GatewayConfig,
    GatewayServer,
    Route,
    Upstream,
)
from segurai.intent import Catalog, IntentCompiler
from segurai.issuer import Ceiling, IssueError, Issuer, Trigger
from segurai.revocation import RevocationError, revoke

PEOPLE = "https://login.acme.example"
JOBS = "https://kubernetes.default.svc"


class Signer:
    """Two token issuers: the company login (people) and the cluster (jobs)."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def fetch(self, url):
        for issuer in (PEOPLE, JOBS):
            if url == issuer + "/.well-known/openid-configuration":
                return {"issuer": issuer, "jwks_uri": issuer + "/keys"}
        public = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [dict(public, kid="k1", use="sig")]}

    def token(self, iss, sub, aud="segurai", **claims):
        now = int(time.time())
        body = {"iss": iss, "sub": sub, "aud": aud, "iat": now, "exp": now + 300, **claims}
        return jwt.encode(body, self.key, algorithm="RS256", headers={"kid": "k1"})

    def person(self, email="sarah@acme.example"):
        return self.token(PEOPLE, "u-" + email, email=email, email_verified=True, groups=["sales"])

    def job(self, sub="system:serviceaccount:jobs:crm-hygiene"):
        return self.token(JOBS, sub)


NIGHTLY = Trigger(name="nightly-crm-hygiene", owner="ops-lead@acme.example",
                  subjects=("system:serviceaccount:jobs:crm-hygiene",),
                  scope=Scope.of(operations=["search", "archive"], targets=["crm.deals"], max_scale=50),
                  ttl=timedelta(minutes=30))


@pytest.fixture
def issuer():
    signer = Signer()
    verifier = IdentityVerifier([TrustedIssuer(issuer=PEOPLE, audience="segurai"),
                                 TrustedIssuer(issuer=JOBS, audience="segurai", kind="workloads",
                                               principal_claim="sub")], fetch=signer.fetch)
    issuer = Issuer(segurai._runtime.authority, segurai._runtime.store, verifier,
                    [Ceiling(name="anyone", scope=Scope.of(operations=["read", "search", "archive"],
                                                          targets=["crm.*"]))], triggers=[NIGHTLY])
    return issuer, signer


# ---- triggers ---------------------------------------------------------------------------------

def test_a_job_starts_a_session_with_its_registered_scope(issuer):
    issuer, signer = issuer
    issued = issuer.issue(signer.job(), {"trigger": "nightly-crm-hygiene", "request": "nightly run, 23 Nov"})
    assert issued["principal"] == "ops-lead@acme.example" and issued["trigger"] == "nightly-crm-hygiene"
    assert issued["scope"] == NIGHTLY.scope.to_dict()
    session = segurai._runtime.store.get_session(issued["session_id"])
    assert session.verified and session.identity["method"] == "workload"
    assert session.contract == {"trigger": "nightly-crm-hygiene", "issued_under": "trigger nightly-crm-hygiene",
                                "run_by": "system:serviceaccount:jobs:crm-hygiene"}
    with segurai.resume(issued["chain_token"], holder="hygiene_agent") as hop:
        assert hop.scope.max_scale == 50


@pytest.mark.parametrize("who, body, message", [
    ("other-job", {"trigger": "nightly-crm-hygiene", "request": "x"}, "may not fire"),
    ("job", {"trigger": "no-such-trigger", "request": "x"}, "may not fire"),
    ("job", {"request": "x"}, "only for a registered trigger"),
    ("job", {"trigger": "nightly-crm-hygiene", "request": "x", "scope": {"operations": ["delete"]}},
     "registered with it"),
    ("person", {"trigger": "nightly-crm-hygiene", "request": "x"}, "not by a person"),
])
def test_triggers_fire_only_for_the_job_they_name(issuer, who, body, message):
    issuer, signer = issuer
    token = {"job": signer.job(), "other-job": signer.job("system:serviceaccount:jobs:other"),
             "person": signer.person()}[who]
    with pytest.raises(IssueError, match=message):
        issuer.issue(token, body)


def test_a_person_still_gets_their_ceiling_and_a_job_never_does(issuer):
    issuer, signer = issuer
    assert issuer.issue(signer.person(), {"request": "tidy up"})["ceiling"] == "anyone"


def test_the_configuration_needs_a_workload_issuer_for_triggers(tmp_path):
    from segurai.config import ConfigError, load_config

    base = """
[server]
database = "segurai.db"
[issuer]
[[issuer.trusted]]
issuer = "https://login.acme.example"
audience = "segurai"
{jobs}
[[issuer.triggers]]
name = "nightly"
owner = "Ops-Lead@acme.example"
subjects = ["system:serviceaccount:jobs:crm-hygiene"]
operations = ["search"]
targets = ["crm.deals"]
"""
    path = tmp_path / "segurai.toml"
    path.write_text(base.format(jobs=""), encoding="utf-8")
    with pytest.raises(ConfigError, match="workloads"):
        load_config(path)
    path.write_text(base.format(jobs='[[issuer.trusted]]\nissuer = "https://k8s"\naudience = "segurai"\n'
                                     'kind = "workloads"'), encoding="utf-8")
    config = load_config(path)
    (trigger,) = config.issuer.triggers
    assert trigger.owner == "ops-lead@acme.example" and config.issuer.trusted[1].principal_claim == "sub"


# ---- the intent cache -------------------------------------------------------------------------------

class CountingBackend:
    last_model = "counting"

    def __init__(self):
        self.calls = 0

    def complete(self, system, request, catalog):
        self.calls += 1
        return {"goal": "Archive old deals", "expected_operations": ["search", "archive"],
                "expected_targets": ["crm.opportunities"], "expected_scale": {"unit": "records", "typical_max": 50},
                "implied_constraints": [], "irreversible_expected": False}


def _catalog():
    return Catalog.from_dict({"operations": ["search", "archive", "delete"],
                              "resources": [{"name": "crm.opportunities"}]})


def test_the_same_person_asking_the_same_thing_costs_one_model_call():
    backend = CountingBackend()
    compiler = IntentCompiler(_catalog(), backend)
    first = compiler.compile("Clean up our old sales records.", principal="sarah@acme.example")
    again = compiler.compile("  clean up our OLD sales records ", principal="Sarah@acme.example")
    assert backend.calls == 1 and again.cached and not first.cached
    assert again.contract == first.contract and again.request == "  clean up our OLD sales records "
    assert again.to_record()["cached"] is True and "cached" not in first.to_record()
    compiler.compile("Clean up our old sales records.", principal="ivan@acme.example")   # someone else
    compiler.compile("Clean up our old support records.", principal="sarah@acme.example")
    assert backend.calls == 3 and (compiler.hits, compiler.misses) == (1, 3)


def test_the_cache_expires_and_can_be_turned_off():
    backend = CountingBackend()
    compiler = IntentCompiler(_catalog(), backend, cache_ttl=timedelta(seconds=0))
    compiler.compile("tidy", principal="a@b")
    compiler.compile("tidy", principal="a@b")
    off = IntentCompiler(_catalog(), backend, cache_ttl=None)
    off.compile("tidy", principal="a@b")
    off.compile("tidy", principal="a@b")
    assert backend.calls == 4


def test_sessions_use_the_cache_through_the_runtime():
    backend = CountingBackend()
    segurai.configure(intent=IntentCompiler(_catalog(), backend))
    for _ in range(3):
        with segurai.session(principal="sarah@acme.example", request="Clean up our old sales records."):
            pass
    assert backend.calls == 1


# ---- revocation ---------------------------------------------------------------------------------------

ROUTES = (Route("GET", "/opportunities", "search", "crm.opportunities"),
          Route("POST", "/opportunities/bulk_delete", "delete", "crm.opportunities", scale="json:ids|len",
                irreversible=True))
GRANTED = Scope.of(operations=["search", "delete"], targets=["crm.*"], irreversible_allowed=True)


@pytest.fixture
def gateway():
    crm = FakeCRM()
    rule = Rule(name="deletes need a person", effect="approve", operations=["delete"])
    server = GatewayServer(("127.0.0.1", 0), GatewayConfig(upstreams=(Upstream(
        "crm", "/crm", crm.url, ROUTES, {"Authorization": SECRET}),), mode="observe"),
        segurai._runtime.store, segurai._runtime.authority.public_only(), policy=Policy((rule,)))
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield server, GatewayClient(f"http://127.0.0.1:{server.server_address[1]}"), crm
    server.shutdown()
    server.server_close()
    crm.close()


def test_revoking_a_request_stops_its_agents_even_in_observe_mode(gateway):
    server, client, crm = gateway
    store = server.store
    with segurai.session(principal="sarah@acme.example", request="tidy the pipeline", scope=GRANTED) as s:
        with segurai.delegate("crm_agent"):
            assert client.request("GET", "/crm/opportunities")[0] == 200
            revoke(store, s.session_id, by="Sarah@acme.example", reason="wrong customer list")
            status, _, body = client.request("GET", "/crm/opportunities")
    assert status == 403 and "sarah@acme.example revoked this request: wrong customer list" in body.decode()
    assert len(crm.requests) == 1                                   # the second never reached the CRM
    attempt = store.actions_for_session(s.session_id)[-1]          # and the attempt is on the record
    assert attempt.blocked and attempt.findings[-1].check == "revoked"
    with pytest.raises(RevocationError, match="already revoked"):
        revoke(store, s.session_id, by="admin@acme.example", reason="again")
    authority = segurai._runtime.authority
    assert verify_pack(build_pack(store, s.session_id, authority), trusted_key=authority.public_key_pem()).ok


def test_revoking_one_warrant_stops_it_and_what_it_delegated_not_its_siblings(gateway):
    server, client, crm = gateway
    with segurai.session(principal="sarah@acme.example", request="tidy", scope=GRANTED) as s:
        with segurai.delegate("assistant") as assistant:
            with segurai.delegate("crm_agent"):
                revoke(server.store, s.session_id, by="sarah@acme.example", reason="odd behaviour",
                       warrant_id=assistant.warrant_id)
                assert client.request("GET", "/crm/opportunities")[0] == 403
        with segurai.delegate("billing_agent"):
            assert client.request("GET", "/crm/opportunities")[0] == 200


def test_revoking_denies_what_is_waiting_for_approval():
    crm = FakeCRM()
    rule = Rule(name="deletes need a person", effect="approve", operations=["delete"])
    server = GatewayServer(("127.0.0.1", 0), GatewayConfig(upstreams=(Upstream(
        "crm", "/crm", crm.url, ROUTES, {"Authorization": SECRET}),)), segurai._runtime.store,
        segurai._runtime.authority.public_only(), policy=Policy((rule,)), run_approvals=False)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    client = GatewayClient(f"http://127.0.0.1:{server.server_address[1]}")
    try:
        with segurai.session(principal="sarah@acme.example", request="tidy", scope=GRANTED) as s:
            with segurai.delegate("crm_agent"):
                _, h1, _ = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": ["a"]})
                _, h2, _ = client.request("POST", "/crm/opportunities/bulk_delete", {"ids": ["b"]})
        decide(server.store, h2[APPROVAL_HEADER], email="admin@acme.example", is_admin=True, approve=True)
        revoke(server.store, s.session_id, by="sarah@acme.example", reason="stop everything")
        assert load(server.store, h1[APPROVAL_HEADER]).state == "denied"
        assert load(server.store, h2[APPROVAL_HEADER]).state == "failed"
        server.approvals.run_once()
        assert crm.requests == []                                   # neither was ever sent
    finally:
        server.shutdown()
        server.server_close()
        crm.close()


def test_revocation_needs_a_reason_a_person_and_a_real_request():
    with segurai.session(principal="sarah@acme.example", request="tidy", scope=GRANTED) as s:
        pass
    store = segurai._runtime.store
    with pytest.raises(RevocationError, match="why"):
        revoke(store, s.session_id, by="sarah@acme.example", reason="  ")
    with pytest.raises(RevocationError, match="no request"):
        revoke(store, "ses_nope", by="sarah@acme.example", reason="x")
    with pytest.raises(RevocationError, match="not a warrant"):
        revoke(store, s.session_id, by="sarah@acme.example", reason="x", warrant_id="wrt_other")


def test_the_cli_revokes(tmp_path, capsys):
    from segurai.cli import main

    db = tmp_path / "segurai.db"
    segurai.configure(store=str(db))
    with segurai.session(principal="sarah@acme.example", request="tidy", scope=GRANTED) as s:
        pass
    assert main(["--db", str(db), "revoke", s.session_id, "--reason", "test", "--by", "ops@acme.example"]) == 0
    assert "Revoked the whole request" in capsys.readouterr().out
    assert main(["--db", str(db), "revoke", s.session_id, "--reason", "x", "--by", "ops@acme.example"]) == 1


def test_the_person_who_asked_or_an_admin_revokes_from_the_dashboard():
    import re

    from test_approvals import PASSWORD, Browser

    from segurai.collector.auth import WebAuth
    from segurai.collector.server import CollectorServer

    store = segurai._runtime.store
    auth = WebAuth(store, cookie_secure=False)
    for email, role in (("sarah@acme.example", "viewer"), ("ivan@acme.example", "viewer")):
        auth.add_user(email, role, password=PASSWORD)
    server = CollectorServer(("127.0.0.1", 0), store, verifier=segurai._runtime.authority.public_only(), auth=auth)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        with segurai.session(principal="sarah@acme.example", request="tidy the pipeline", scope=GRANTED) as s:
            pass
        page_path = f"/sessions/{s.session_id}"
        ivan = Browser(server.server_address[1])
        ivan.sign_in("ivan@acme.example")
        _, _, page = ivan.request("GET", page_path)
        assert "Revoke this request" not in page                     # not his request, not an admin
        csrf = re.search(r"name='csrf' value='([^']+)'", page).group(1)
        assert ivan.request("POST", page_path + "/revoke", {"csrf": csrf, "reason": "x"})[0] == 403

        sarah = Browser(server.server_address[1])
        sarah.sign_in("sarah@acme.example")
        _, _, page = sarah.request("GET", page_path)
        assert "Revoke this request" in page
        csrf = re.search(r"name='csrf' value='([^']+)'", page).group(1)
        status, _, _ = sarah.request("POST", page_path + "/revoke", {"csrf": csrf, "reason": "wrong list"})
        assert status == 303
        _, _, page = sarah.request("GET", page_path)
        assert "Revoked" in page and "wrong list" in page and "Revoke this request" not in page
        assert any(e["method"] == "REVOKE" for e in store.access_log(email="sarah@acme.example"))
    finally:
        server.shutdown()
        server.server_close()
