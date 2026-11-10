"""The enforcing gateway, against a fake CRM that records exactly what reaches it.

Every refusal test also checks the upstream never saw the request: a 403 that
still forwarded would be worse than no gateway at all.
"""

import base64
import json
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import segurai
from segurai import Authority, Policy, Rule, Scope
from segurai.authority import key_id_of
from segurai.context import export_chain
from segurai.gateway import (
    CHAIN_HEADER,
    PROOF_HEADER,
    GatewayClient,
    GatewayConfig,
    GatewayConfigError,
    GatewayServer,
    Route,
    Upstream,
    proof_headers,
)

SECRET = "Bearer crm-service-credential"


class FakeCRM:
    """Records every request it receives; answers 200, or 302 for /redirect."""

    def __init__(self):
        self.requests = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                outer.requests.append({"method": self.command, "path": self.path,
                                       "headers": dict(self.headers), "body": body})
                if self.path.startswith("/api/redirect"):
                    self.send_response(302)
                    self.send_header("Location", "http://evil.example/steal")
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                payload = json.dumps({"ok": True, "path": self.path}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_POST = do_DELETE = do_PUT = do_PATCH = _any

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


ROUTES = (
    Route("GET", "/opportunities", "search", "crm.opportunities"),
    Route("GET", "/opportunities/{id}", "read", "crm.opportunities"),
    Route("DELETE", "/opportunities/{id}", "delete", "crm.opportunities", irreversible=True),
    Route("POST", "/opportunities/bulk_archive", "archive", "crm.opportunities",
          scale="json:ids|len", evidence={"days_since_activity": "json:days_since_activity"}),
    Route("GET", "/tables/{table}", "read", "crm.{table}"),
    Route("GET", "/search", "search", "crm.opportunities", evidence={"owner": "query:owner"}),
    Route("GET", "/redirect", "read", "crm.opportunities"),
)
GRANTED = Scope.of(operations=["read", "search", "archive", "delete"], targets=["crm.*"],
                   max_scale=50, irreversible_allowed=True)


@pytest.fixture
def crm():
    upstream = FakeCRM()
    yield upstream
    upstream.close()


@pytest.fixture
def org():
    authority = Authority()
    segurai.configure(store=":memory:", authority=authority)
    return authority


def _gateway(crm, org, mode="enforce", policy=None):
    store = segurai._runtime.store
    config = GatewayConfig(upstreams=(Upstream(name="crm", prefix="/crm", url=crm.url, routes=ROUTES,
                                               headers={"Authorization": SECRET}),), mode=mode)
    server = GatewayServer(("127.0.0.1", 0), config, store, org.public_only(), policy=policy)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


@pytest.fixture
def gateway(crm, org):
    server, url = _gateway(crm, org)
    yield url
    server.shutdown()
    server.server_close()


def _as_agent(scope=GRANTED, agent_scope=None):
    """Open a session and an agent hop; return the context managers to use."""
    s = segurai.session(principal="sarah@company.com", request="tidy the pipeline", scope=scope)
    return s, segurai.delegate("crm_agent", scope=agent_scope)


def _raw(url, method, target, headers=None, body=b""):
    import http.client
    parts = urllib.parse.urlsplit(url)
    conn = http.client.HTTPConnection(parts.hostname, parts.port, timeout=10)
    try:
        conn.request(method, target, body=body or None, headers=headers or {})
        response = conn.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        conn.close()


# ---- the honest path ------------------------------------------------------------------

def test_an_allowed_request_reaches_the_crm_with_the_gateways_credential(crm, gateway):
    sess, hop = _as_agent()
    with sess as s, hop:
        status, headers, body = GatewayClient(gateway).request("DELETE", "/crm/opportunities/7")
    assert status == 200 and json.loads(body)["path"] == "/api/opportunities/7"
    (seen,) = crm.requests
    assert seen["method"] == "DELETE" and seen["headers"]["Authorization"] == SECRET
    assert CHAIN_HEADER not in seen["headers"] and PROOF_HEADER not in seen["headers"]

    store = segurai._runtime.store
    (record,) = store.actions_for_session(s.session_id)
    assert record.action_id == headers["X-Segurai-Action"]
    assert (record.actor, record.operation, record.resource) == ("crm_agent", "delete", "crm.opportunities")
    assert record.allowed and record.detail["via"] == "gateway" and record.detail["upstream_status"] == 200
    assert store.audit(segurai._runtime.authority).ok


def test_scale_and_evidence_come_from_the_request(crm, gateway):
    sess, hop = _as_agent()
    with sess as s, hop:
        status, _, body = GatewayClient(gateway).request(
            "POST", "/crm/opportunities/bulk_archive",
            {"ids": list(range(400)), "days_since_activity": [200, 12]})
    assert status == 403 and len(crm.requests) == 0
    refusal = json.loads(body)
    assert "scale 400 exceeds limit 50" in refusal["error"]
    (record,) = segurai._runtime.store.actions_for_session(s.session_id)
    assert record.blocked and record.scale == 400 and record.detail["days_since_activity"] == [200, 12]


# ---- what the gateway refuses, and never forwards --------------------------------------------

def test_out_of_scope_and_against_policy_requests_are_refused(crm, org):
    rules = Policy((Rule(name="no deletes through the gateway", effect="deny", operations=["delete"]),))
    server, url = _gateway(crm, org, policy=rules)
    try:
        sess, hop = _as_agent(agent_scope=Scope.of(operations=["read", "delete"]))
        with sess, hop:
            client = GatewayClient(url)
            assert client.request("GET", "/crm/opportunities")[0] == 403          # search not granted
            status, _, body = client.request("DELETE", "/crm/opportunities/7")    # granted, but a rule
        assert status == 403 and "no deletes through the gateway" in json.loads(body)["error"]
        assert crm.requests == []
    finally:
        server.shutdown()
        server.server_close()


def test_a_request_no_route_describes_is_refused_and_recorded(crm, gateway):
    sess, hop = _as_agent()
    with sess as s, hop:
        status, _, body = GatewayClient(gateway).request("DELETE", "/crm/everything")
    assert status == 403 and "no route describes" in json.loads(body)["error"]
    (record,) = segurai._runtime.store.actions_for_session(s.session_id)
    assert record.findings[0].check == "spec" and record.blocked
    assert crm.requests == []


@pytest.mark.parametrize("target", [
    "/crm/../admin", "/crm//opportunities", "/crm/%2e%2e/admin", "/crm/opportunities%2F7",
    "/crm/opportunities/7%00", "/crm/./opportunities", "/crm\\opportunities",
])
def test_paths_two_servers_could_read_differently_are_refused(crm, gateway, target):
    sess, hop = _as_agent()
    with sess, hop:
        headers = proof_headers("GET", target)
    assert _raw(gateway, "GET", target, headers)[0] == 400
    assert crm.requests == []


def test_requests_without_valid_credentials_are_refused(crm, gateway, org):
    assert _raw(gateway, "GET", "/crm/opportunities")[0] == 401                   # no headers

    sess, hop = _as_agent()
    with sess, hop:
        good = proof_headers("GET", "/crm/opportunities/1")
        with_key = dict(good, **{CHAIN_HEADER: export_chain(include_key=True)})
        other_path = proof_headers("GET", "/crm/opportunities/2")
    assert _raw(gateway, "GET", "/crm/opportunities/1", with_key)[0] == 400      # a key in transit
    assert _raw(gateway, "GET", "/crm/opportunities/1", other_path)[0] == 401    # proof for another request
    assert _raw(gateway, "GET", "/crm/opportunities/1", good)[0] == 200
    assert _raw(gateway, "GET", "/crm/opportunities/1", good)[0] == 401          # replay
    assert len(crm.requests) == 1


def test_the_proof_covers_the_body(crm, gateway):
    sess, hop = _as_agent()
    with sess, hop:
        body = json.dumps({"ids": [1], "days_since_activity": [300]}).encode()
        headers = proof_headers("POST", "/crm/opportunities/bulk_archive", body)
    altered = json.dumps({"ids": list(range(40)), "days_since_activity": [300]}).encode()
    headers["Content-Type"] = "application/json"
    assert _raw(gateway, "POST", "/crm/opportunities/bulk_archive", headers, altered)[0] == 401
    assert crm.requests == []


def test_old_proofs_and_foreign_chains_are_refused(crm, gateway, monkeypatch):
    sess, hop = _as_agent()
    with sess, hop:
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() - 600)
        stale = proof_headers("GET", "/crm/opportunities/1")
        monkeypatch.setattr(time, "time", real)
    assert _raw(gateway, "GET", "/crm/opportunities/1", stale)[0] == 401

    # A chain signed by another organisation's key, perfectly formed otherwise.
    segurai.configure(authority=Authority())
    sess, hop = _as_agent()
    with sess, hop:
        foreign = proof_headers("GET", "/crm/opportunities/1")
    status, _, body = _raw(gateway, "GET", "/crm/opportunities/1", foreign)
    assert status == 401 and "invalid signature" in json.loads(body)["error"]
    assert crm.requests == []


def test_a_proof_signed_with_the_parents_key_is_refused(crm, gateway, org):
    sess, hop = _as_agent()
    with sess as s, hop as leaf:
        parent_key = org.holder_private_key(s.root_warrant.warrant_id)
        headers = proof_headers("GET", "/crm/opportunities/1", leaf=leaf, key=parent_key)
    assert _raw(gateway, "GET", "/crm/opportunities/1", headers)[0] == 401


def test_a_widened_chain_is_refused_even_when_validly_signed(crm, gateway, org):
    """The holder key signs anything; the gateway's chain check is what refuses a widening."""
    with segurai.session(principal="p", request="r", scope=Scope.of(operations=["read"], targets=["crm.x"])) as s:
        root = s.root_warrant
        holder = org.holder_private_key(root.warrant_id)
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    leaf_key = Ed25519PrivateKey.generate()
    wider = segurai.Warrant(
        warrant_id="wrt_wide", session_id=root.session_id, root_principal="p", holder="rogue",
        scope=Scope.of(operations=["read", "delete"], targets=["crm.*"], irreversible_allowed=True),
        issued_at=root.issued_at, expires_at=root.expires_at, parent_id=root.warrant_id, depth=1,
        key_id=key_id_of(root.holder_key),
        holder_key=leaf_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    wider = wider.with_signature(holder.sign(wider.signing_bytes()))
    headers = proof_headers("DELETE", "/crm/opportunities/1", leaf=wider, chain=[root, wider], key=leaf_key)
    status, _, body = _raw(gateway, "DELETE", "/crm/opportunities/1", headers)
    assert status == 401 and "attenuation violated" in json.loads(body)["error"]
    assert crm.requests == []


# ---- what the gateway strips and refuses to interpret --------------------------------------------

def test_method_overrides_and_agent_credentials_never_reach_the_crm(crm, gateway):
    sess, hop = _as_agent()
    with sess, hop:
        headers = proof_headers("GET", "/crm/opportunities/1")
    headers.update({"X-HTTP-Method-Override": "DELETE", "Authorization": "Bearer agent-own-token",
                    "Cookie": "session=agent"})
    assert _raw(gateway, "GET", "/crm/opportunities/1", headers)[0] == 200
    (seen,) = crm.requests
    assert seen["method"] == "GET"
    lowered = {k.lower(): v for k, v in seen["headers"].items()}
    assert "x-http-method-override" not in lowered and "cookie" not in lowered
    assert lowered["authorization"] == SECRET


def test_ambiguous_requests_are_refused(crm, gateway):
    sess, hop = _as_agent()
    with sess, hop:
        dup = b'{"ids": [1], "ids": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,52]}'
        headers = proof_headers("POST", "/crm/opportunities/bulk_archive", dup)
        headers["Content-Type"] = "application/json"
        assert _raw(gateway, "POST", "/crm/opportunities/bulk_archive", headers, dup)[0] == 403
        twice = "/crm/search?owner=sarah&owner=raj"
        assert _raw(gateway, "GET", twice, proof_headers("GET", twice))[0] == 403
        glob = "/crm/tables/*"
        assert _raw(gateway, "GET", glob, proof_headers("GET", glob))[0] == 403
    assert crm.requests == []


def test_redirects_are_passed_back_not_followed(crm, gateway):
    sess, hop = _as_agent()
    with sess, hop:
        status, headers, _ = GatewayClient(gateway).request("GET", "/crm/redirect")
    assert status == 302 and headers["Location"] == "http://evil.example/steal"
    assert len(crm.requests) == 1


def test_an_unreachable_upstream_is_a_502_and_still_on_the_record(org):
    dead = Upstream(name="crm", prefix="/crm", url="http://127.0.0.1:9", routes=ROUTES)
    server = GatewayServer(("127.0.0.1", 0), GatewayConfig(upstreams=(dead,)),
                           segurai._runtime.store, org.public_only())
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        sess, hop = _as_agent()
        with sess as s, hop:
            status, _, body = GatewayClient(f"http://127.0.0.1:{server.server_address[1]}").request(
                "GET", "/crm/opportunities/1")
        assert status == 502 and "could not be reached" in json.loads(body)["error"]
        (record,) = segurai._runtime.store.actions_for_session(s.session_id)
        assert record.allowed and "upstream_status" not in record.detail
    finally:
        server.shutdown()
        server.server_close()


def test_observe_mode_forwards_and_flags(crm, org):
    server, url = _gateway(crm, org, mode="observe")
    try:
        sess, hop = _as_agent(agent_scope=Scope.of(operations=["read"]))
        with sess as s, hop:
            assert GatewayClient(url).request("DELETE", "/crm/opportunities/7")[0] == 200
        (record,) = segurai._runtime.store.actions_for_session(s.session_id)
        assert not record.allowed and not record.blocked and len(crm.requests) == 1
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("make, message", [
    (lambda: Route("BREW", "/x", "read", "a"), "method"),
    (lambda: Route("GET", "x", "read", "a"), "start with /"),
    (lambda: Route("GET", "/{rest*}/x", "read", "a"), "may only end"),
    (lambda: Route("GET", "/x", "read", "a", scale="body:ids"), "must look like"),
    (lambda: Route("GET", "/x", "read", "a", scale="json:ids|sum"), "unknown transform"),
    (lambda: Upstream(name="u", prefix="crm", url="http://x", routes=ROUTES), "prefix"),
    (lambda: Upstream(name="u", prefix="/crm", url="ftp://x", routes=ROUTES), "url"),
    (lambda: Upstream(name="u", prefix="/crm", url="http://x", routes=()), "at least one route"),
    (lambda: GatewayConfig(upstreams=(), mode="lenient"), "mode"),
])
def test_bad_configuration_is_refused_at_start_up(make, message):
    with pytest.raises(GatewayConfigError, match=message):
        make()


def test_tokens_are_never_written_to_a_key_header(crm, gateway):
    """The chain header is the public chain only; check the encoding agrees."""
    sess, hop = _as_agent()
    with sess, hop:
        headers = proof_headers("GET", "/crm/opportunities/1")
    from segurai.context import import_chain
    chain, key = import_chain(headers[CHAIN_HEADER])
    assert key is None and [w.holder for w in chain] == ["entrypoint", "crm_agent"]
    assert base64.urlsafe_b64decode(headers[PROOF_HEADER].split("s=")[1] + "==")
