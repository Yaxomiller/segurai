"""The collector: spans in, verified chain out."""

import gzip
import json
import threading
import urllib.error
import urllib.request

import pytest
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

import segurai
from segurai import ActionSpec, Authority, Scope, Store, count, verify_chain
from segurai.collector.chain import render_session
from segurai.collector.otlp import ingest
from segurai.collector.server import CollectorServer
from segurai.instrument import otel
from segurai.instrument.otel import warrant_attributes

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


@pytest.fixture
def signer():
    """The organisation's signing key, shared by agents; the collector gets only its public half."""
    return Authority()


def _start(store, **kwargs):
    server = CollectorServer(("127.0.0.1", 0), store, **kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture
def collector(signer, monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    store = Store(":memory:")
    server = _start(store, verifier=Authority(public_key=signer.public_key))
    yield server, store
    server.shutdown()
    server.server_close()


def _url(server, path="/v1/traces"):
    return f"http://127.0.0.1:{server.server_address[1]}{path}"


def _post(url, body: bytes, content_type="application/json", headers=None):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": content_type, **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


def _otlp_json(*attribute_sets):
    """Build an OTLP/JSON request holding one span per attribute dict."""
    def value(v):
        if isinstance(v, bool):
            return {"boolValue": v}
        if isinstance(v, int):
            return {"intValue": str(v)}
        return {"stringValue": str(v)}

    spans = [{"name": "span", "attributes": [{"key": k, "value": value(v)} for k, v in attrs.items()]}
             for attrs in attribute_sets]
    return {"resourceSpans": [{"scopeSpans": [{"spans": spans}]}]}


# ---- end to end with the real OpenTelemetry exporter --------------------

def test_spans_from_an_agent_process_rebuild_the_verified_chain(collector, signer):
    server, central = collector

    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=_url(server))))
    # The "agent process": its own local store, the organisation's signing key.
    segurai.configure(store=":memory:", authority=signer)
    otel.enable(provider)
    try:
        @segurai.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True))
        def delete_records(table, ids):
            return len(ids)

        @segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
        def crm_agent():
            segurai.act("read", "crm.opportunities", scale=412)
            delete_records("opportunities", list(range(400)))

        @segurai.agent("assistant")
        def assistant():
            crm_agent()

        with segurai.session(principal="sarah@company.com",
                             request="clean up our old sales records", scope=GRANTED) as s:
            assistant()
    finally:
        otel.disable()
        provider.shutdown()

    sid = s.session_id
    warrants = central.warrants_for_session(sid)
    assert [w.holder for w in warrants] == ["entrypoint", "assistant", "crm_agent"]
    leaf = warrants[-1]
    verify_chain(central.chain_to(leaf.warrant_id), Authority(public_key=signer.public_key))

    assert central.get_session(sid).request == "clean up our old sales records"
    out = render_session(central, sid, charset="ascii")
    assert "sarah@company.com" in out
    assert "[FAIL   ] delete crm.opportunities scale=400" in out


# ---- ingest rules --------------------------------------------------------

def test_forged_warrants_are_refused_and_foreign_spans_ignored(signer):
    genuine = signer.issue_root(session_id="ses_1", principal="sarah@company.com", scope=GRANTED)
    mallory = Authority()
    forged = mallory.attenuate(mallory.issue_root(session_id="ses_1", principal="sarah@company.com",
                                                  scope=GRANTED), holder="exfiltrator")
    llm_call = {"gen_ai.operation.name": "chat", "gen_ai.request.model": "some-model"}

    store = Store(":memory:")
    report = ingest(store, _otlp_json(warrant_attributes(genuine), warrant_attributes(forged), llm_call),
                    verifier=Authority(public_key=signer.public_key))

    assert report.verified and report.warrants == 1 and report.ignored == 1
    assert len(report.rejected) == 1 and "invalid signature" in report.rejected[0]
    assert store.get_warrant(genuine.warrant_id) is not None
    assert store.get_warrant(forged.warrant_id) is None


def test_without_a_verifier_warrants_are_stored_as_received(signer):
    w = signer.issue_root(session_id="ses_1", principal="p", scope=GRANTED)
    store = Store(":memory:")
    report = ingest(store, _otlp_json(warrant_attributes(w)))
    assert not report.verified and report.warrants == 1


def test_a_malformed_warrant_span_is_reported_not_dropped_silently(signer):
    attrs = warrant_attributes(signer.issue_root(session_id="s", principal="p", scope=GRANTED))
    attrs["warrant.scope"] = "{not json"
    report = ingest(Store(":memory:"), _otlp_json(attrs))
    assert report.warrants == 0 and "malformed" in report.rejected[0]


def test_ingesting_the_same_spans_twice_changes_nothing(signer):
    w = signer.issue_root(session_id="ses_1", principal="p", scope=GRANTED)
    store = Store(":memory:")
    request = _otlp_json(warrant_attributes(w))
    ingest(store, request)
    ingest(store, request)
    assert len(store.warrants_for_session("ses_1")) == 1


# ---- HTTP behaviour ------------------------------------------------------

def test_json_over_http_reports_partial_success_for_refused_spans(collector, signer):
    server, _ = collector
    forged = Authority().issue_root(session_id="s", principal="p", scope=GRANTED)
    status, body = _post(_url(server), json.dumps(_otlp_json(warrant_attributes(forged))).encode())
    assert status == 200
    assert json.loads(body)["partialSuccess"]["rejectedSpans"] == "1"


def test_gzip_bodies_are_accepted(collector, signer):
    server, store = collector
    w = signer.issue_root(session_id="ses_gz", principal="p", scope=GRANTED)
    body = gzip.compress(json.dumps(_otlp_json(warrant_attributes(w))).encode())
    status, _ = _post(_url(server), body, headers={"Content-Encoding": "gzip"})
    assert status == 200
    assert store.get_warrant(w.warrant_id) is not None


def test_token_is_required_when_configured(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    server = _start(Store(":memory:"), token="s3cret")
    try:
        body = json.dumps(_otlp_json()).encode()
        assert _post(_url(server), body)[0] == 401
        assert _post(_url(server), body, headers={"Authorization": "Bearer wrong"})[0] == 401
        assert _post(_url(server), body, headers={"Authorization": "Bearer s3cret"})[0] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_oversized_and_zip_bomb_bodies_are_refused(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    server = _start(Store(":memory:"), max_body=1000)
    try:
        assert _post(_url(server), b"x" * 2000)[0] == 413
        bomb = gzip.compress(b"{" + b" " * 100_000 + b"}")   # small on the wire, huge inflated
        assert len(bomb) < 1000
        assert _post(_url(server), bomb, headers={"Content-Encoding": "gzip"})[0] == 413
    finally:
        server.shutdown()
        server.server_close()


def test_bad_requests_get_clear_errors(collector):
    server, _ = collector
    assert _post(_url(server), b"{not json")[0] == 400
    assert _post(_url(server), b"<xml/>", content_type="text/xml")[0] == 415
    assert _post(_url(server, "/elsewhere"), b"{}")[0] == 404
    with urllib.request.urlopen(_url(server, "/healthz"), timeout=10) as resp:
        assert resp.read() == b"ok"
