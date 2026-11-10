"""Dashboard accounts, roles, company sign-in, search, and the issuer - over real HTTP.

A small browser stand-in keeps cookies and never follows redirects, so every
step of a sign-in can be checked.
"""

import base64
import hashlib
import http.client
import json
import re
import threading
import time
import urllib.parse

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import segurai
from segurai import IdentityVerifier, Scope, TrustedIssuer
from segurai.collector.auth import OidcLogin, WebAuth, check_password, hash_password
from segurai.collector.server import CollectorServer
from segurai.evidence import verify_pack
from segurai.issuer import Ceiling, Issuer

ISSUER = "https://login.acme.example"
CLIENT = "segurai-dashboard"
PASSWORD = "correct horse battery"


# ---- a fake login system ------------------------------------------------------------

class FakeIdP:
    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.codes = {}

    def fetch(self, url):
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": ISSUER, "jwks_uri": ISSUER + "/keys",
                    "authorization_endpoint": ISSUER + "/authorize", "token_endpoint": ISSUER + "/token"}
        jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(self.key.public_key()))
        return {"keys": [dict(jwk, kid="k1", use="sig")]}

    def id_token(self, email="sarah@acme.example", groups=("sales",), aud=CLIENT, **extra):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": aud, "sub": "u-" + email, "iat": now, "exp": now + 300,
                  "email": email, "email_verified": True, "groups": list(groups), **extra}
        return jwt.encode(claims, self.key, algorithm="RS256", headers={"kid": "k1"})

    def authorize(self, location, email="sarah@acme.example", groups=("sales",), nonce=None):
        """Play the person approving the sign-in: return the callback query the browser comes back with."""
        query = dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(location).query))
        code = "code-" + query["state"][:8]
        self.codes[code] = {"challenge": query["code_challenge"], "nonce": nonce or query["nonce"],
                            "email": email, "groups": groups}
        return {"state": query["state"], "code": code}

    def post(self, url, form):
        grant = self.codes.pop(form["code"], None)          # codes are single use
        if grant is None:
            raise AssertionError("unknown or reused code")
        expected = base64.urlsafe_b64encode(hashlib.sha256(form["code_verifier"].encode()).digest()).rstrip(b"=")
        assert expected.decode() == grant["challenge"], "PKCE verifier does not match"
        return {"id_token": self.id_token(grant["email"], grant["groups"], nonce=grant["nonce"])}


# ---- a browser stand-in -------------------------------------------------------------------

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
                    val = rest.split(";")[0]
                    if "Max-Age=0" in value:
                        self.cookies.pop(key, None)
                    else:
                        self.cookies[key] = val
            return r.status, dict(r.getheaders()), payload.decode("utf-8", "replace")
        finally:
            conn.close()

    def csrf_from(self, page):
        return re.search(r"name='csrf' value='([^']+)'", page).group(1)

    def sign_in(self, email, password=PASSWORD):
        _, _, page = self.request("GET", "/login")
        return self.request("POST", "/login", {"csrf": self.csrf_from(page), "email": email,
                                               "password": password, "next": "/"})


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def server(idp):
    store = segurai._runtime.store
    oidc = OidcLogin(issuer=ISSUER, client_id=CLIENT, client_secret="s3cret",
                     redirect_url="http://127.0.0.1/auth/callback",
                     role_map={"auditor": ("security",), "admin": ("segurai-admins",)},
                     default_role="viewer", allowed_domains=("acme.example",),
                     fetch=idp.fetch, post=idp.post)
    auth = WebAuth(store, oidc=oidc, cookie_secure=False)
    auth.add_user("admin@acme.example", "admin", password=PASSWORD)
    auth.add_user("auditor@acme.example", "auditor", password=PASSWORD)
    auth.add_user("viewer@acme.example", "viewer", password=PASSWORD)
    verifier = IdentityVerifier([TrustedIssuer(issuer=ISSUER, audience="segurai-agents")], fetch=idp.fetch)
    issuer = Issuer(segurai._runtime.authority, store, verifier, [
        Ceiling(name="sales", groups=("sales",),
                scope=Scope.of(operations=["read", "search", "archive"], targets=["crm.*"], max_scale=50)),
    ])
    srv = CollectorServer(("127.0.0.1", 0), store, verifier=segurai._runtime.authority.public_only(),
                          auth=auth, issuer=issuer, ingest_tokens=["ingest-token"],
                          signer=segurai._runtime.authority)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _record(request="clean up our old sales records", agent="crm_agent", **act):
    with segurai.session(principal="sarah@acme.example", request=request,
                         scope=Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)) as s:
        with segurai.delegate(agent):
            segurai.act(**({"operation": "read", "resource": "crm.accounts"} | act))
    return s.session_id


# ---- passwords and sessions ---------------------------------------------------------------

def test_passwords_are_stored_as_salted_scrypt_hashes():
    stored = hash_password(PASSWORD)
    assert stored.startswith("scrypt$") and PASSWORD not in stored
    assert stored != hash_password(PASSWORD)                     # a fresh salt every time
    assert check_password(PASSWORD, stored) and not check_password("wrong password!", stored)
    assert not check_password(PASSWORD, None) and not check_password(PASSWORD, "garbage")
    with pytest.raises(segurai.collector.auth.AuthError, match="12"):
        hash_password("short")


def test_signing_in_and_out(server):
    b = Browser(server.server_address[1])
    status, headers, _ = b.request("GET", "/sessions/x?y=1")
    assert status == 303 and headers["Location"] == "/login?next=%2Fsessions%2Fx%3Fy%3D1"

    status, _, page = b.sign_in("viewer@acme.example", "not the password")
    assert status == 401 and "match an account" in page
    status, headers, _ = b.sign_in("viewer@acme.example")
    assert status == 303 and "segurai_session" in b.cookies
    assert "HttpOnly" in headers["Set-Cookie"] and "SameSite=Lax" in headers["Set-Cookie"]

    status, _, page = b.request("GET", "/")
    assert status == 200 and "viewer@acme.example" in page and "Sign out" in page
    # Only a hash of the session token is stored.
    raw = b.cookies["segurai_session"]
    assert segurai._runtime.store.get_web_session(raw) is None

    b.request("POST", "/logout", {"csrf": b.csrf_from(page)})
    assert b.request("GET", "/")[0] == 303


def test_roles_decide_what_each_person_sees(server):
    viewer, auditor, admin = (Browser(server.server_address[1]) for _ in range(3))
    viewer.sign_in("viewer@acme.example")
    auditor.sign_in("auditor@acme.example")
    admin.sign_in("admin@acme.example")
    for path in ("/audit", "/access", "/admin/users"):
        assert viewer.request("GET", path)[0] == 403
    assert auditor.request("GET", "/audit")[0] == 200 and auditor.request("GET", "/access")[0] == 200
    assert auditor.request("GET", "/admin/users")[0] == 403
    assert admin.request("GET", "/admin/users")[0] == 200
    assert "Record integrity" not in viewer.request("GET", "/")[2]
    assert "People" in admin.request("GET", "/")[2]


def test_an_admin_manages_people_and_every_change_is_logged(server):
    admin = Browser(server.server_address[1])
    admin.sign_in("admin@acme.example")
    csrf = admin.csrf_from(admin.request("GET", "/admin/users")[2])
    status, headers, _ = admin.request("POST", "/admin/users", {
        "csrf": csrf, "action": "create", "email": "New@Acme.example", "role": "auditor",
        "password": "a long enough password"})
    assert status == 303 and "done=" in headers["Location"]
    newcomer = Browser(server.server_address[1])
    assert newcomer.sign_in("new@acme.example", "a long enough password")[0] == 303

    # Disabling someone ends their sessions at once.
    admin.request("POST", "/admin/users", {"csrf": csrf, "action": "update", "email": "new@acme.example",
                                           "role": "auditor", "disabled": "1"})
    assert newcomer.request("GET", "/")[0] == 303

    # The last admin can't remove themselves.
    status, headers, _ = admin.request("POST", "/admin/users", {
        "csrf": csrf, "action": "update", "email": "admin@acme.example", "role": "viewer", "disabled": "0"})
    assert "last+admin" in headers["Location"]

    store = segurai._runtime.store
    assert store.audit(segurai._runtime.authority).ok
    store._conn.execute("UPDATE users SET role = 'admin' WHERE email = 'viewer@acme.example'")
    store._conn.commit()
    assert not store.audit(segurai._runtime.authority).ok          # a quiet promotion is caught


def test_forms_are_protected_against_forgery(server):
    b = Browser(server.server_address[1])
    assert b.request("POST", "/login", {"csrf": "x", "email": "viewer@acme.example",
                                        "password": PASSWORD})[0] == 400         # no matching cookie
    b.sign_in("admin@acme.example")
    assert b.request("POST", "/admin/users", {"csrf": "wrong", "action": "create", "email": "x@acme.example",
                                              "role": "admin", "password": PASSWORD})[0] == 403
    page = b.request("GET", "/admin/users")[2]
    assert b.request("POST", "/admin/users", {"csrf": b.csrf_from(page), "action": "create",
                                              "email": "x@acme.example", "role": "admin", "password": PASSWORD},
                     headers={"Origin": "https://evil.example"})[0] == 403
    assert segurai._runtime.store.get_user("x@acme.example") is None


def test_repeated_failures_lock_the_account(server):
    b = Browser(server.server_address[1])
    for _ in range(5):
        b.sign_in("viewer@acme.example", "wrong password!!")
    status, _, page = b.sign_in("viewer@acme.example")
    assert status == 401 and "too many failed attempts" in page


def test_sign_in_never_redirects_off_site(server):
    b = Browser(server.server_address[1])
    _, _, page = b.request("GET", "/login?next=//evil.example/x")
    status, headers, _ = b.request("POST", "/login", {"csrf": b.csrf_from(page), "email": "viewer@acme.example",
                                                      "password": PASSWORD, "next": "//evil.example/x"})
    assert status == 303 and headers["Location"] == "/"


def test_every_page_view_and_sign_in_is_in_the_access_log(server):
    b = Browser(server.server_address[1])
    b.sign_in("viewer@acme.example", "wrong password!!")
    b.sign_in("auditor@acme.example")
    b.request("GET", "/permissions")
    entries = segurai._runtime.store.access_log()
    seen = {(e["email"], e["method"], e["path"], e["status"]) for e in entries}
    assert ("viewer@acme.example", "SIGN-IN", "/login", 401) in seen
    assert ("auditor@acme.example", "GET", "/permissions", 200) in seen
    assert "auditor@acme.example" in b.request("GET", "/access")[2]


# ---- company sign-in -----------------------------------------------------------------------

def _company_sign_in(server, idp, groups=("security",), **kw):
    b = Browser(server.server_address[1])
    _, headers, _ = b.request("GET", "/auth/start?next=/permissions")
    location = headers["Location"]
    assert location.startswith(ISSUER + "/authorize?") and "code_challenge_method=S256" in location
    callback = idp.authorize(location, groups=groups, **kw)
    return b, b.request("GET", "/auth/callback?" + urllib.parse.urlencode(callback)), callback


def test_company_sign_in_maps_groups_to_roles(server, idp):
    b, (status, headers, _), _ = _company_sign_in(server, idp, groups=("security",))
    assert status == 303 and headers["Location"] == "/permissions"
    user = segurai._runtime.store.get_user("sarah@acme.example")
    assert user["role"] == "auditor" and user["source"] == "oidc" and user["password_hash"] is None
    assert b.request("GET", "/audit")[0] == 200


def test_company_sign_in_refuses_reuse_swaps_and_strangers(server, idp):
    b, (status, _, _), callback = _company_sign_in(server, idp)
    assert status == 303
    assert b.request("GET", "/auth/callback?" + urllib.parse.urlencode(callback))[0] == 401   # state reused

    # A callback opened in a browser that didn't start the sign-in.
    other = Browser(server.server_address[1])
    _, headers, _ = Browser(server.server_address[1]).request("GET", "/auth/start")
    stolen = idp.authorize(headers["Location"])
    assert other.request("GET", "/auth/callback?" + urllib.parse.urlencode(stolen))[0] == 401

    # A token minted for a different sign-in (wrong nonce).
    _, (status, _, page), _ = _company_sign_in(server, idp, nonce="someone-elses-nonce")
    assert status == 401 and "nonce" in page


# ---- search ---------------------------------------------------------------------------------

def test_the_overview_searches_filters_and_pages(server):
    for i in range(3):
        _record(request=f"routine read {i}")
    _record(request="clean up our old sales records", agent="cleanup_bot", operation="delete",
            resource="crm.opportunities", scale=400)
    store = segurai._runtime.store
    assert store.search_sessions(q="sales records")[1] == 1
    assert store.search_sessions(agent="cleanup")[1] == 1
    assert store.search_sessions(outcome="flagged")[1] == 1 and store.search_sessions(outcome="clean")[1] == 3
    assert store.search_sessions(q="100%")[1] == 0                        # LIKE wildcards are escaped
    rows, total = store.search_sessions(limit=2, offset=2)
    assert total == 4 and len(rows) == 2

    b = Browser(server.server_address[1])
    b.sign_in("viewer@acme.example")
    page = b.request("GET", "/?outcome=flagged")[2]
    assert "clean up our old sales records" in page and "routine read" not in page


# ---- evidence and the issuer ---------------------------------------------------------------

def test_auditors_download_evidence_packs_that_verify(server):
    sid = _record()
    auditor, viewer = Browser(server.server_address[1]), Browser(server.server_address[1])
    auditor.sign_in("auditor@acme.example")
    viewer.sign_in("viewer@acme.example")
    assert viewer.request("GET", f"/sessions/{sid}/evidence.zip")[0] == 403
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("GET", f"/sessions/{sid}/evidence.zip",
                 headers={"Cookie": f"segurai_session={auditor.cookies['segurai_session']}"})
    response = conn.getresponse()
    data = response.read()
    assert response.status == 200 and response.getheader("Content-Type") == "application/zip"
    assert verify_pack(data, segurai._runtime.authority.public_key_pem()).ok


def _issue(server, token, body):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("POST", "/v1/sessions", body=json.dumps(body),
                 headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    r = conn.getresponse()
    return r.status, json.loads(r.read())


def test_the_issuer_mints_roots_only_for_proven_people_inside_their_ceiling(server, idp):
    token = idp.id_token(aud="segurai-agents")
    status, result = _issue(server, token, {"request": "archive stale deals",
                                            "scope": {"operations": ["archive", "delete"], "targets": ["crm.*"],
                                                      "max_scale": 500}})
    assert status == 201 and result["principal"] == "sarah@acme.example"
    assert result["scope"]["operations"] == ["archive"] and result["scope"]["max_scale"] == 50   # clamped

    # The application continues the chain without the organisation's key.
    segurai.configure(store=":memory:", authority=segurai._runtime.authority.public_only())
    with segurai.resume(result["chain_token"], holder="assistant") as w:
        assert w.root_principal == "sarah@acme.example"

    row = server.store.get_session(result["session_id"])
    assert row.verified and row.identity["issuer"] == ISSUER

    assert _issue(server, "not-a-token", {"request": "x"})[0] == 401
    assert _issue(server, idp.id_token(aud="segurai-agents", groups=("finance",)), {"request": "x"})[0] == 403
    assert _issue(server, token, {"request": "x", "admin": True})[0] == 400
    assert _issue(server, idp.id_token(aud="some-other-app"), {"request": "x"})[0] == 401


def test_exporters_need_the_ingest_token(server):
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("POST", "/v1/traces", body=b"{}", headers={"Content-Type": "application/json"})
    assert conn.getresponse().status == 401
    conn = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=10)
    conn.request("POST", "/v1/traces", body=b"{}", headers={"Content-Type": "application/json",
                                                           "Authorization": "Bearer ingest-token"})
    assert conn.getresponse().status == 200
