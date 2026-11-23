"""Credentials fetched from a secrets manager, against fakes that behave like the real ones.

The secret value is checked to appear where it must (the upstream's header)
and nowhere else: not in an error, not in the record.
"""

import base64
import hashlib
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import segurai
from segurai import Scope
from segurai.credentials import (
    AwsSecretsManagerSource,
    CredentialError,
    EnvSource,
    GcpSecretManagerSource,
    OAuth2Credentials,
    TemplateCredentials,
    VaultAuth,
    VaultSource,
)
from segurai.evidence import build_pack, verify_pack
from segurai.gateway import GatewayClient, GatewayConfig, GatewayServer, Route, Upstream

GRANTED = Scope.of(operations=["read"], targets=["crm.*"])


class FakeVault:
    """Kubernetes and AppRole logins, KV v2 and a dynamic secret, like Vault's HTTP API."""

    def __init__(self, jwt="the-pods-service-account-jwt"):
        self.jwt, self.api_key, self.logins, self.reads = jwt, "key-one", 0, 0
        self.tokens: set[str] = set()
        self.lease = 3600
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _json(self, status, payload=None):
                body = json.dumps(payload or {"errors": ["no"]}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                if self.path == "/v1/auth/kubernetes/login" and data == {"role": "segurai-gateway", "jwt": outer.jwt}:
                    ok = True
                elif self.path == "/v1/auth/approle/login" and data == {"role_id": "r-1", "secret_id": "s-1"}:
                    ok = True
                else:
                    ok = False
                if not ok:
                    return self._json(400)
                outer.logins += 1
                token = f"hvs.token-{outer.logins}"
                outer.tokens.add(token)
                self._json(200, {"auth": {"client_token": token, "lease_duration": 3600}})

            def do_GET(self):
                if self.headers.get("X-Vault-Token") not in outer.tokens:
                    return self._json(403)
                outer.reads += 1
                if self.path == "/v1/secret/data/crm-api":
                    return self._json(200, {"data": {"data": {"api_key": outer.api_key}, "metadata": {"version": 3}}})
                if self.path == "/v1/database/creds/crm":
                    return self._json(200, {"lease_duration": outer.lease,
                                            "data": {"username": "v-crm-x1", "password": "p-" + outer.api_key}})
                self._json(404)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def vault():
    fake = FakeVault()
    yield fake
    fake.close()


@pytest.fixture
def jwt_file(tmp_path, vault):
    path = tmp_path / "token"
    path.write_text(vault.jwt, encoding="utf-8")
    return str(path)


def _kubernetes(jwt_file):
    return VaultAuth(method="kubernetes", role="segurai-gateway", jwt_path=jwt_file)


# ---- Vault ----------------------------------------------------------------------------------------

def test_vault_kv_with_the_pods_own_identity(vault, jwt_file):
    source = VaultSource(vault.url, "secret/data/crm-api", _kubernetes(jwt_file))
    assert source.values() == {"api_key": "key-one"}
    assert source.values() == {"api_key": "key-one"}
    assert (vault.logins, vault.reads) == (1, 1)                  # cached for its lease
    vault.api_key = "key-two"                                      # rotated
    source.invalidate()                                            # e.g. the upstream said 401
    assert source.values() == {"api_key": "key-two"} and vault.logins == 1


def test_vault_dynamic_secrets_keep_their_own_lease(vault, monkeypatch):
    monkeypatch.setenv("VAULT_ROLE_ID", "r-1")
    monkeypatch.setenv("VAULT_SECRET_ID", "s-1")
    source = VaultSource(vault.url, "database/creds/crm", VaultAuth(method="approle"))
    vault.lease = 30                                               # shorter than the refresh margin
    assert source.values()["username"] == "v-crm-x1"
    source.values()
    assert vault.reads == 2                                        # so it is fetched again each time


def test_a_lapsed_vault_login_logs_in_again(vault, jwt_file):
    source = VaultSource(vault.url, "secret/data/crm-api", _kubernetes(jwt_file))
    source.values()
    vault.tokens.clear()                                           # Vault forgot the gateway's token
    source.invalidate()
    with pytest.raises(CredentialError, match="403"):
        source.values()
    assert source.values() == {"api_key": "key-one"} and vault.logins == 2


def test_an_unreachable_vault_is_survived_only_inside_the_lease(vault, jwt_file):
    source = VaultSource(vault.url, "database/creds/crm", _kubernetes(jwt_file))
    vault.lease = 30
    first = source.values()
    vault.close()
    assert source.values() == first                                # still inside its 30 s
    source.invalidate()
    with pytest.raises(CredentialError, match="could not reach"):
        source.values()


def test_vault_refuses_bad_configuration(jwt_file):
    with pytest.raises(ValueError, match="https"):
        VaultSource("http://vault.example:8200", "secret/data/x", _kubernetes(jwt_file))
    with pytest.raises(ValueError, match="path"):
        VaultSource("https://vault.example", "../sys/raw", _kubernetes(jwt_file))
    with pytest.raises(ValueError, match="role"):
        VaultAuth(method="kubernetes")
    with pytest.raises(ValueError, match="kubernetes, approle or token"):
        VaultAuth(method="password")


# ---- the clouds ---------------------------------------------------------------------------------

def test_aws_secrets_manager_with_the_instance_role():
    class Client:
        calls = 0

        def get_secret_value(self, SecretId):
            Client.calls += 1
            assert SecretId == "prod/crm"
            return {"SecretString": json.dumps({"api_key": "aws-key"})}

    source = AwsSecretsManagerSource("prod/crm", client=Client())
    assert source.values() == {"api_key": "aws-key"} and source.values() and Client.calls == 1

    class Broken:
        def get_secret_value(self, SecretId):
            raise RuntimeError("AccessDeniedException")

    with pytest.raises(CredentialError, match="RuntimeError"):
        AwsSecretsManagerSource("prod/crm", client=Broken()).values()


def test_gcp_secret_manager_with_the_metadata_servers_token():
    seen = []

    def http(method, url, headers, body):
        seen.append((method, url, dict(headers)))
        if "metadata.google.internal" in url:
            assert headers == {"Metadata-Flavor": "Google"}
            return 200, {"access_token": "ya29.token", "expires_in": 3599}
        assert headers == {"Authorization": "Bearer ya29.token"}
        return 200, {"payload": {"data": base64.b64encode(b"plain-text-key").decode()}}

    source = GcpSecretManagerSource("acme-prod", "crm-api", http=http)
    assert source.values() == {"value": "plain-text-key"}
    assert seen[1][1] == ("https://secretmanager.googleapis.com/v1/projects/acme-prod/secrets/crm-api/"
                          "versions/latest:access")


# ---- turning a secret into headers ------------------------------------------------------------------

def test_templates_fill_headers_and_errors_never_show_the_secret(monkeypatch):
    monkeypatch.setenv("CRM_API_KEY", "s3cr3t-value")
    creds = TemplateCredentials(EnvSource({"api_key": "CRM_API_KEY"}), {"Authorization": "Bearer {api_key}"})
    assert creds.headers() == {"Authorization": "Bearer s3cr3t-value"}
    wrong = TemplateCredentials(EnvSource({"api_key": "CRM_API_KEY"}), {"X-Key": "{token}"})
    with pytest.raises(CredentialError) as info:
        wrong.headers()
    assert "no field token" in str(info.value) and "s3cr3t" not in str(info.value)
    with pytest.raises(ValueError, match="not set"):
        EnvSource({"api_key": "NOT_SET_ANYWHERE"})


def test_oauth2_tokens_are_short_lived_and_cached(monkeypatch):
    monkeypatch.setenv("CRM_CLIENT_SECRET", "client-secret")
    issued = []

    def http(method, url, headers, body):
        form = dict(p.split("=", 1) for p in body.decode().split("&"))
        if form["client_secret"] != "client-secret":
            return 401, None
        issued.append(form.get("scope"))
        return 200, {"access_token": f"at-{len(issued)}", "expires_in": 900}

    creds = OAuth2Credentials("https://login.crm.example/token", "segurai-gateway",
                              EnvSource({"client_secret": "CRM_CLIENT_SECRET"}), scope="api", http=http)
    assert creds.headers() == {"Authorization": "Bearer at-1"} and creds.headers() == {"Authorization": "Bearer at-1"}
    assert issued == ["api"]
    token, seconds = creds.token_for("crm.read")                  # a narrower, fresh token
    assert token == "at-2" and seconds == 900 and issued[-1] == "crm.read"
    creds.invalidate()
    assert creds.headers() == {"Authorization": "Bearer at-3"}
    monkeypatch.setenv("CRM_CLIENT_SECRET", "wrong")
    bad = OAuth2Credentials("https://login.crm.example/token", "segurai-gateway",
                            EnvSource({"client_secret": "CRM_CLIENT_SECRET"}), http=http)
    with pytest.raises(CredentialError, match="401"):
        bad.headers()


# ---- through the gateway ----------------------------------------------------------------------------

class KeyCheckingCRM:
    """Answers 200 only for the current key; 401 for anything else."""

    def __init__(self, key):
        self.key, self.seen = key, []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                outer.seen.append(self.headers.get("Authorization"))
                ok = self.headers.get("Authorization") == f"Bearer {outer.key}"
                body = b'{"ok": true}' if ok else b'{"error": "bad key"}'
                self.send_response(200 if ok else 401)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def test_the_gateway_uses_the_vault_secret_and_picks_up_a_rotation(vault, jwt_file):
    crm = KeyCheckingCRM("key-one")
    creds = TemplateCredentials(VaultSource(vault.url, "secret/data/crm-api", _kubernetes(jwt_file)),
                                {"Authorization": "Bearer {api_key}"})
    upstream = Upstream("crm", "/crm", crm.url, (Route("GET", "/deals", "read", "crm.deals"),), credentials=creds)
    server = GatewayServer(("127.0.0.1", 0), GatewayConfig(upstreams=(upstream,)), segurai._runtime.store,
                           segurai._runtime.authority.public_only())
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    client = GatewayClient(f"http://127.0.0.1:{server.server_address[1]}")
    try:
        with segurai.session(principal="sarah@acme.example", request="look", scope=GRANTED) as s:
            with segurai.delegate("crm_agent"):
                assert client.request("GET", "/crm/deals")[0] == 200
                # The key is rotated in Vault and at the CRM: the old one is refused once...
                vault.api_key = crm.key = "key-two"
                assert client.request("GET", "/crm/deals")[0] == 401
                # ...which drops the cached copy, so the next request carries the new one.
                assert client.request("GET", "/crm/deals")[0] == 200
                vault.close()
                creds.invalidate()
                status, _, body = client.request("GET", "/crm/deals")
        assert crm.seen == ["Bearer key-one", "Bearer key-one", "Bearer key-two"]
        assert status == 502 and b"could not get its credential for crm" in body
        # The secret is never in the record.
        stored = json.dumps([a.detail for a in segurai._runtime.store.actions_for_session(s.session_id)])
        assert "key-one" not in stored and "key-two" not in stored
    finally:
        server.shutdown()
        server.server_close()
        crm.close()


# ---- configuration -------------------------------------------------------------------------------

_CONFIG = """
[server]
database = "segurai.db"

[gateway]
[[gateway.upstreams]]
name = "crm"
prefix = "/crm"
url = "https://crm.internal.acme.example"
[gateway.upstreams.credentials]
{credentials}
[gateway.upstreams.credentials.source]
{source}
[[gateway.upstreams.routes]]
method = "GET"
path = "/deals"
operation = "read"
resource = "crm.deals"
"""


def _load(tmp_path, credentials, source):
    from segurai.config import load_config

    path = tmp_path / "segurai.toml"
    path.write_text(_CONFIG.format(credentials=credentials, source=source), encoding="utf-8")
    return load_config(path)


def test_the_configuration_names_where_each_credential_comes_from(tmp_path):
    from segurai.config import ConfigError

    config = _load(tmp_path, 'headers = { Authorization = "Bearer {api_key}" }',
                   'type = "vault"\nurl = "https://vault.internal:8200"\npath = "secret/data/crm-api"\n'
                   'role = "segurai-gateway"')
    assert any("credentials from Authorization from vault secret/data/crm-api (kubernetes)" in line
               for line in config.summary())
    config = _load(tmp_path, 'type = "oauth2"\ntoken_url = "https://login.crm.example/token"\nclient_id = "gw"',
                   'type = "gcp-secret-manager"\nproject = "acme"\nsecret = "crm-oauth"')
    assert isinstance(config.gateway.upstreams[0].credentials, OAuth2Credentials)

    with pytest.raises(ConfigError, match="unknown setting"):          # no inline secrets, no typos
        _load(tmp_path, 'headers = { Authorization = "Bearer {api_key}" }',
              'type = "vault"\nurl = "https://vault.internal"\npath = "secret/data/x"\nrole = "r"\ntoken = "hvs.x"')
    with pytest.raises(ConfigError, match="type must be"):
        _load(tmp_path, 'headers = { A = "{x}" }', 'type = "keychain"')
    with pytest.raises(ConfigError, match="https"):
        _load(tmp_path, 'headers = { A = "{x}" }', 'type = "vault"\nurl = "http://vault.example"\npath = "a/b"\n'
                                                     'role = "r"')


# ---- the fast path: direct, scope-matched tokens ------------------------------------------------------

def _token_endpoint(lifetime=900):
    minted = []

    def http(method, url, headers, body):
        form = dict(p.split("=", 1) for p in body.decode().split("&"))
        minted.append(urllib.parse.unquote_plus(form.get("scope", "")))
        return 200, {"access_token": f"direct-token-{len(minted)}", "expires_in": lifetime}
    return http, minted


DIRECT_ROUTES = (
    Route("GET", "/deals", "read", "crm.deals"),
    Route("GET", "/search", "search", "crm.deals"),
    Route("POST", "/deals/archive", "archive", "crm.deals", scale="json:ids|len"),
    Route("DELETE", "/deals/{id}", "delete", "crm.deals", irreversible=True),
)
EVERYTHING = Scope.of(operations=["read", "search", "archive", "delete"], targets=["crm.*"], irreversible_allowed=True)


def _direct_gateway(monkeypatch, *, lifetime=900, policy=None):
    from segurai.gateway import DirectAccess

    monkeypatch.setenv("CRM_CLIENT_SECRET", "client-secret")
    http, minted = _token_endpoint(lifetime)
    creds = OAuth2Credentials("https://login.crm.example/token", "segurai-gateway",
                              EnvSource({"client_secret": "CRM_CLIENT_SECRET"}), http=http)
    upstream = Upstream("crm", "/crm", "https://crm.example/api", DIRECT_ROUTES, credentials=creds,
                        direct=DirectAccess({"read": "crm.read", "search": "crm.read", "archive": "crm.write",
                                             "delete": "crm.delete"}))
    server = GatewayServer(("127.0.0.1", 0), GatewayConfig(upstreams=(upstream,)), segurai._runtime.store,
                           segurai._runtime.authority.public_only(), policy=policy)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server, GatewayClient(f"http://127.0.0.1:{server.server_address[1]}"), minted


def _ask_direct(client, scope, ttl=None):
    with segurai.session(principal="sarah@acme.example", request="review the pipeline", scope=scope,
                         **({"ttl": ttl} if ttl else {})) as s:
        with segurai.delegate("crm_agent"):
            try:
                return s.session_id, client.direct("crm")
            except PermissionError as exc:
                return s.session_id, exc


def test_a_direct_token_carries_only_what_no_check_could_stop(monkeypatch):
    server, client, minted = _direct_gateway(monkeypatch)
    try:
        session_id, grant = _ask_direct(client, EVERYTHING)
        assert grant["operations"] == ["archive", "read", "search"]
        assert grant["excluded"] == {"delete": "can't be undone, so each one is checked at the gateway"}
        assert grant["scope"] == "crm.read crm.write" and minted == ["crm.read crm.write"]
        assert grant["access_token"] == "direct-token-1" and grant["base_url"] == "https://crm.example/api"

        (row,) = server.store.grants_for_session(session_id)
        assert row["holder"] == "crm_agent" and row["operations"] == ["archive", "read", "search"]
        assert row["token_sha256"] == hashlib.sha256(b"direct-token-1").hexdigest()
        assert "direct-token-1" not in json.dumps(row)                    # never the token itself
        authority = segurai._runtime.authority
        pack = build_pack(server.store, session_id, authority)
        assert verify_pack(pack, trusted_key=authority.public_key_pem()).ok
    finally:
        server.shutdown()
        server.server_close()


def test_limits_conditions_and_rules_keep_operations_on_the_gated_path(monkeypatch):
    from segurai import Policy, Rule

    rule = Rule(name="archives need a second person", effect="approve", operations=["archive"], targets=["crm.*"])
    server, client, _ = _direct_gateway(monkeypatch, policy=Policy((rule,)))
    try:
        _, grant = _ask_direct(client, EVERYTHING)
        assert grant["operations"] == ["read", "search"]
        assert "archives need a second person" in grant["excluded"]["archive"]

        _, grant = _ask_direct(client, Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50))
        assert "only the gateway can count" in grant["excluded"]["archive"]
        assert grant["excluded"]["search"] == "not allowed by this request's warrant"

        _, refused = _ask_direct(client, Scope.of(operations=["read"], targets=["crm.accounts"]))
        assert isinstance(refused, PermissionError) and "through the gateway" in str(refused)
    finally:
        server.shutdown()
        server.server_close()


def test_a_direct_token_may_not_outlive_its_warrant(monkeypatch):
    from datetime import timedelta

    server, client, minted = _direct_gateway(monkeypatch, lifetime=3600)
    try:
        session_id, refused = _ask_direct(client, EVERYTHING, ttl=timedelta(minutes=10))
        assert isinstance(refused, PermissionError) and "longer than this request's warrant" in str(refused)
        assert server.store.grants_for_session(session_id) == []
    finally:
        server.shutdown()
        server.server_close()


def test_direct_access_needs_a_token_endpoint_and_real_operations():
    from segurai.gateway import DirectAccess, GatewayConfigError

    with pytest.raises(GatewayConfigError, match="oauth2"):
        Upstream("crm", "/crm", "https://crm.example", DIRECT_ROUTES, direct=DirectAccess({"read": "crm.read"}))
    creds = OAuth2Credentials("https://login.crm.example/token", "gw", EnvSource({}), http=lambda *a: (500, None))
    with pytest.raises(GatewayConfigError, match="no route performs"):
        Upstream("crm", "/crm", "https://crm.example", DIRECT_ROUTES, credentials=creds,
                 direct=DirectAccess({"export": "crm.export"}))


def test_the_configuration_turns_on_direct_access(tmp_path):
    from segurai.config import ConfigError, load_config

    text = _CONFIG.format(
        credentials='type = "oauth2"\ntoken_url = "https://login.crm.example/token"\nclient_id = "gw"',
        source='type = "gcp-secret-manager"\nproject = "acme"\nsecret = "crm-oauth"')
    path = tmp_path / "segurai.toml"
    path.write_text(text + '\n[gateway.upstreams.direct]\nscopes = { read = "crm.read" }\n', encoding="utf-8")
    (upstream,) = load_config(path).gateway.upstreams
    assert upstream.direct.scopes == {"read": "crm.read"}
    path.write_text(text + '\n[gateway.upstreams.direct]\nscopes = { export = "crm.export" }\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="no route performs"):
        load_config(path)
