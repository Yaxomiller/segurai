"""The read-only web view: pages, escaping, verification, and serving them safely."""

import base64
import json
import threading
import urllib.error
import urllib.request

import pytest

import warrant
from warrant import Check, Scope
from warrant.collector.server import CollectorServer
from warrant.collector.web import CSP, index_page, session_page

GRANTED = Scope.of(
    operations=["read", "archive", "delete"], targets=["crm.*"], max_scale=50, max_total=50,
    checks=[Check(field="days_since_activity", op=">=", value=180,
                  condition="only records with no recent activity", targets=("crm.opportunities",))],
)


def _run(request="clean up our old sales records", contract=None):
    @warrant.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
    def crm_agent():
        warrant.act("read", "crm.opportunities", scale=412)
        warrant.act("archive", "crm.opportunities", scale=3, days_since_activity=[200, 12, 400])
        warrant.act("archive", "crm.opportunities", scale=2)  # reports no evidence

    with warrant.session(principal="sarah@company.com", request=request, scope=GRANTED,
                         contract=contract) as s:
        crm_agent()
    return s.session_id


def _store():
    return warrant._runtime.store


# ---- the pages ---------------------------------------------------------

def test_index_lists_sessions_and_their_verdicts():
    sid = _run()
    page = index_page(_store())
    assert "clean up our old sales records" in page
    assert f"/sessions/{sid}" in page
    assert "sarah@company.com" in page and "1 violation(s)" in page


def test_session_page_shows_chain_findings_scope_and_verification():
    sid = _run()
    page = session_page(_store(), sid, verifier=warrant._runtime.authority)
    assert "crm_agent" in page and "FAIL" in page
    assert "condition not met: only records with no recent activity" in page
    assert "cannot verify" in page
    assert "Session total" in page and "days_since_activity" in page
    assert "signatures valid" in page


def test_without_a_key_the_page_says_signatures_were_not_checked():
    sid = _run()
    assert "Signatures not checked" in session_page(_store(), sid)


def test_text_from_requests_is_escaped_not_executed():
    sid = _run(request="<script>alert('hi')</script>")
    for page in (session_page(_store(), sid), index_page(_store())):
        assert "<script>" not in page
        assert "&lt;script&gt;" in page


def test_a_compiled_contract_is_shown_beside_the_chain():
    record = {
        "contract": {
            "goal": "Archive outdated sales records",
            "expected_operations": ["archive"], "expected_targets": ["crm.opportunities"],
            "expected_scale": {"unit": "records", "typical_max": 50},
            "implied_constraints": ["must not affect active customers"],
            "irreversible_expected": False,
            "clarifications_needed": ["Which date counts as old?"],
            "checks": [],
        },
        "problems": ["operation 'purge' is not in the catalog; dropped"],
        "model": "claude-opus-5", "prompt_version": "intent-v2",
    }
    page = session_page(_store(), _run(contract=record))
    assert "Archive outdated sales records" in page
    assert "Which date counts as old?" in page
    assert "purge" in page and "claude-opus-5" in page


def test_a_tampered_chain_fails_verification_on_the_page():
    sid = _run()
    store = _store()
    widened = json.dumps({"operations": ["delete"], "targets": ["*"], "max_scale": None,
                          "irreversible_allowed": True, "constraints": []})
    store._conn.execute("UPDATE warrants SET scope_json = ? WHERE holder = 'crm_agent'", (widened,))
    store._conn.commit()
    page = session_page(store, sid, verifier=warrant._runtime.authority)
    assert "Verification FAILED" in page and "invalid signature" in page


def test_an_unknown_session_has_no_page():
    assert session_page(_store(), "ses_nope") is None


# ---- serving -------------------------------------------------------------

@pytest.fixture
def serve(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    started = []

    def start(**kwargs):
        server = CollectorServer(("127.0.0.1", 0), _store(), **kwargs)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        started.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in started:
        server.shutdown()
        server.server_close()


def _get(url, headers=None):
    try:
        with urllib.request.urlopen(urllib.request.Request(url, headers=headers or {}), timeout=10) as r:
            return r.status, dict(r.headers), r.read().decode("utf-8")
    except urllib.error.HTTPError as err:
        return err.code, dict(err.headers), err.read().decode("utf-8", "replace")


def test_pages_are_served_with_a_strict_content_security_policy(serve):
    sid = _run()
    base = serve(verifier=warrant._runtime.authority)

    status, headers, body = _get(base + "/")
    assert status == 200 and "text/html" in headers["Content-Type"]
    assert headers["Content-Security-Policy"] == CSP
    assert headers["X-Content-Type-Options"] == "nosniff"
    assert sid in body

    status, _, body = _get(base + f"/sessions/{sid}")
    assert status == 200 and "signatures valid" in body
    assert _get(base + "/sessions/ses_nope")[0] == 404


def test_with_a_token_the_browser_is_asked_to_log_in(serve):
    _run()
    base = serve(token="s3cret")

    status, headers, _ = _get(base + "/")
    assert status == 401 and headers["WWW-Authenticate"].startswith("Basic")

    wrong = base64.b64encode(b"anyone:guess").decode()
    assert _get(base + "/", {"Authorization": f"Basic {wrong}"})[0] == 401

    right = base64.b64encode(b"anyone:s3cret").decode()
    assert _get(base + "/", {"Authorization": f"Basic {right}"})[0] == 200
    assert _get(base + "/", {"Authorization": "Bearer s3cret"})[0] == 200
