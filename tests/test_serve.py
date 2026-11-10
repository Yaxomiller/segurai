"""A whole deployment from one segurai.toml: issue -> resume -> gateway -> alert -> witness.

Everything the README promises, end to end, with only the outside world faked:
a login system, a CRM and a Slack webhook, each a real local HTTP server.
"""

import http.client
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

import segurai
from segurai.config import ConfigError, load_config
from segurai.gateway import GatewayClient
from segurai.serve import build
from segurai.witness import read_witness_file


def _http_server(handler_factory):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory)
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    return server


class World:
    """The fake outside world: a login system, a CRM, Slack."""

    def __init__(self):
        self.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.crm_seen, self.slack = [], []
        world = self

        class IdP(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                if self.path == "/.well-known/openid-configuration":
                    body = {"issuer": world.issuer, "jwks_uri": world.issuer + "/keys",
                            "authorization_endpoint": world.issuer + "/authorize",
                            "token_endpoint": world.issuer + "/token"}
                else:
                    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(world.key.public_key()))
                    body = {"keys": [dict(jwk, kid="k1", use="sig")]}
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        class CRM(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _any(self):
                world.crm_seen.append((self.command, self.path, self.headers.get("Authorization")))
                self.send_response(200)
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")

            do_GET = do_DELETE = do_POST = _any

        class Slack(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                world.slack.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.servers = [_http_server(IdP), _http_server(CRM), _http_server(Slack)]
        self.issuer = f"http://127.0.0.1:{self.servers[0].server_address[1]}"
        self.crm_url = f"http://127.0.0.1:{self.servers[1].server_address[1]}"
        self.slack_url = f"http://127.0.0.1:{self.servers[2].server_address[1]}/hook"

    def id_token(self, email="sarah@acme.example", groups=("sales",), aud="segurai-agents"):
        now = int(time.time())
        return jwt.encode({"iss": self.issuer, "aud": aud, "sub": email, "iat": now, "exp": now + 300,
                           "email": email, "email_verified": True, "groups": list(groups)},
                          self.key, algorithm="RS256", headers={"kid": "k1"})

    def close(self):
        for s in self.servers:
            s.shutdown()
            s.server_close()


@pytest.fixture
def world():
    w = World()
    yield w
    w.close()


def _config(tmp_path, world, monkeypatch, extra=""):
    monkeypatch.setenv("TEST_INGEST_TOKEN", "an-ingest-token-of-length")
    monkeypatch.setenv("TEST_CRM_AUTH", "Bearer the-crm-credential")
    monkeypatch.setenv("TEST_SLACK_URL", world.slack_url)
    text = f'''
[server]
database = "segurai.db"
key = "org.key"
port = 0
ingest_tokens_env = ["TEST_INGEST_TOKEN"]

[dashboard]
local_accounts = true

[issuer]
[[issuer.trusted]]
issuer = "{world.issuer}"
audience = "segurai-agents"
allowed_domains = ["acme.example"]
[[issuer.ceilings]]
name = "sales"
groups = ["sales"]
operations = ["read", "search", "archive"]
targets = ["crm.*"]
max_scale = 50

[[policy.rules]]
name = "nobody deletes payroll"
targets = ["hr.payroll"]
effect = "deny"

[gateway]
port = 0
[[gateway.upstreams]]
name = "crm"
prefix = "/crm"
url = "{world.crm_url}"
[gateway.upstreams.headers_env]
Authorization = "TEST_CRM_AUTH"
[[gateway.upstreams.routes]]
method = "GET"
path = "/opportunities/{{id}}"
operation = "read"
resource = "crm.opportunities"
[[gateway.upstreams.routes]]
method = "DELETE"
path = "/opportunities/{{id}}"
operation = "delete"
resource = "crm.opportunities"
irreversible = true

[alerts]
[[alerts.channels]]
name = "security"
type = "slack"
url_env = "TEST_SLACK_URL"

[witness]
[[witness.sinks]]
type = "file"
path = "witness/checkpoints.log"
{extra}'''
    path = tmp_path / "segurai.toml"
    path.write_text(text, encoding="utf-8")
    return path


def test_a_whole_deployment_from_one_file(tmp_path, world, monkeypatch):
    deployment = build(load_config(_config(tmp_path, world, monkeypatch))).start()
    try:
        port = deployment.server.server_address[1]

        # 1. The agent application asks the issuer for a session, with Sarah's ID token.
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        conn.request("POST", "/v1/sessions", body=json.dumps({"request": "tidy the stale deals"}),
                     headers={"Authorization": "Bearer " + world.id_token(),
                              "Content-Type": "application/json"})
        response = conn.getresponse()
        issued = json.loads(response.read())
        assert response.status == 201, issued

        # 2. It continues the chain in its own process, holding only the public key...
        segurai.configure(store=":memory:", authority=deployment.authority.public_only())
        with segurai.resume(issued["chain_token"], holder="crm_agent"):
            client = GatewayClient(deployment.gateway_url)
            # 3. ...and reaches the CRM only through the gateway.
            assert client.request("GET", "/crm/opportunities/7")[0] == 200
            status, _, body = client.request("DELETE", "/crm/opportunities/7")
        assert status == 403 and "operation 'delete' not in scope" in json.loads(body)["error"]
        assert world.crm_seen == [("GET", "/opportunities/7", "Bearer the-crm-credential")]

        # 4. The refusal reaches Slack.
        deployment.alerts.run_once()
        assert any("tried to delete 1 record in crm.opportunities" in m["text"] for m in world.slack)

        # 5. A checkpoint is witnessed outside the database, and the record matches it.
        deployment.checkpoints.run_once(force=True)
        witnessed, _ = read_witness_file(tmp_path / "witness" / "checkpoints.log")
        assert witnessed and deployment.store.audit(deployment.authority, witnessed=witnessed).ok

        # 6. The request is in the dashboard, with Sarah's identity proven.
        row = deployment.store.get_session(issued["session_id"])
        assert row.verified and row.principal == "sarah@acme.example"
        actions = deployment.store.actions_for_session(issued["session_id"])
        assert [(a.operation, a.blocked) for a in actions] == [("read", False), ("delete", True)]
    finally:
        deployment.stop()


@pytest.mark.parametrize("extra, message", [
    ("[surprise]\nx = 1", "unknown setting"),
    ("[[alerts.channels]]\nname = 'x'\ntype = 'slack'\nurl = 'https://hooks.slack.com/x'", "never in this file"),
    ("[[alerts.channels]]\nname = 'x'\ntype = 'pager'", "slack, webhook or email"),
])
def test_configuration_mistakes_are_named(tmp_path, world, monkeypatch, extra, message):
    with pytest.raises(ConfigError, match=message):
        load_config(_config(tmp_path, world, monkeypatch, extra))


def test_missing_secrets_and_unsafe_exposure_are_refused(tmp_path, world, monkeypatch):
    path = _config(tmp_path, world, monkeypatch)
    monkeypatch.delenv("TEST_SLACK_URL")
    with pytest.raises(ConfigError, match="TEST_SLACK_URL, which is not set"):
        load_config(path)

    exposed = tmp_path / "exposed.toml"
    exposed.write_text('[server]\nhost = "0.0.0.0"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="anyone could read every request"):
        load_config(exposed)


def test_typos_in_types_are_refused(tmp_path):
    path = tmp_path / "t.toml"
    path.write_text('[server]\nport = "8700"\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="server.port must be int"):
        load_config(path)
    path.write_text('[dashboard]\nlocal_accounts = false\n', encoding="utf-8")
    with pytest.raises(ConfigError, match="nobody can sign in"):
        load_config(path)


def test_the_example_configuration_is_valid(tmp_path):
    from segurai.config import EXAMPLE
    path = tmp_path / "segurai.toml"
    path.write_text(EXAMPLE, encoding="utf-8")
    config = load_config(path)
    assert config.dashboard.local_accounts and len(config.policy.rules) == 1 and config.witnesses


def test_the_first_admin_is_added_from_the_command_line(tmp_path, capsys, monkeypatch):
    from segurai.cli import main as cli_main
    assert cli_main(["init", "--dir", str(tmp_path)]) == 0
    config = str(tmp_path / "segurai.toml")
    monkeypatch.setenv("FIRST_ADMIN_PASSWORD", "a long admin password")
    assert cli_main(["users", "add", "--config", config, "--email", "Ops@Acme.example", "--role", "admin",
                     "--password-env", "FIRST_ADMIN_PASSWORD"]) == 0
    assert cli_main(["users", "set", "--config", config, "--email", "ops@acme.example",
                     "--role", "viewer"]) == 1                       # the last admin can't step down
    capsys.readouterr()
    assert cli_main(["users", "list", "--config", config]) == 0
    listing = capsys.readouterr().out
    assert "ops@acme.example" in listing and "admin" in listing
    assert cli_main(["config", "check", "--config", config]) == 0
    assert "is valid" in capsys.readouterr().out
