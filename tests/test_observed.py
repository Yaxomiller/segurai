"""Zero-integration ingest: existing OpenTelemetry GenAI spans become an observed chain.

A team that already emits standard GenAI spans (invoke_agent / execute_tool)
can point them at the collector and see its agent chain with no code change.
Nothing in such a chain is signed or checked, and it must say so.
"""

import json
import threading

import pytest
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from warrant import Authority, Scope, Store
from warrant.collector.chain import render_session
from warrant.collector.otlp import ingest
from warrant.collector.server import CollectorServer
from warrant.collector.web import session_page
from warrant.instrument.otel import warrant_attributes

TRACE = "5b8efff798038103d269b633813fc60c"
ROOT, SUPERVISOR, CRM, CHAT, TOOL = ("1000000000000001", "2000000000000002", "3000000000000003",
                                     "4000000000000004", "5000000000000005")
BASE_NS = 1_760_000_000_000_000_000


def _request(span_id, parent, name, offset, attrs, trace=TRACE):
    """One OTLP/JSON export request holding a single span."""
    def value(v):
        return {"intValue": str(v)} if isinstance(v, int) and not isinstance(v, bool) else {"stringValue": str(v)}

    span = {"traceId": trace, "spanId": span_id, "name": name,
            "startTimeUnixNano": str(BASE_NS + offset),
            "attributes": [{"key": k, "value": value(v)} for k, v in attrs.items()]}
    if parent:
        span["parentSpanId"] = parent
    return {"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}


SPANS = [  # (span, parent, name, offset, attributes) - listed parents first
    (ROOT, None, "POST /run", 0, {"enduser.id": "sarah@company.com"}),
    (SUPERVISOR, ROOT, "invoke_agent supervisor", 10,
     {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "supervisor"}),
    (CRM, SUPERVISOR, "invoke_agent crm_agent", 20,
     {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "crm_agent"}),
    (CHAT, CRM, "chat claude-opus-5", 30, {"gen_ai.operation.name": "chat"}),
    (TOOL, CHAT, "execute_tool delete_records", 40,
     {"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "delete_records",
      "gen_ai.tool.call.id": "call_1",
      "gen_ai.tool.call.arguments": json.dumps({"table": "opportunities", "ids": [1, 2, 3]})}),
]


def _ingest_all(store, order):
    for span in order:
        ingest(store, _request(*span))


def _check_chain(store):
    session_id = f"otel_{TRACE}"
    sess = store.get_session(session_id)
    assert sess is not None and sess.principal == "sarah@company.com"
    assert sess.contract["observed"] is True

    warrants = store.warrants_for_session(session_id)
    assert [w.holder for w in warrants] == ["entrypoint", "supervisor", "crm_agent"]
    crm = warrants[-1]
    assert [w.holder for w in store.chain_to(crm.warrant_id)] == ["entrypoint", "supervisor", "crm_agent"]

    (action,) = store.actions_for_session(session_id)
    assert (action.actor, action.operation, action.resource) == ("crm_agent", "delete_records",
                                                                 "tool.delete_records")
    assert action.allowed and not action.blocked
    assert [f.status for f in action.findings] == ["unverifiable"]
    assert action.detail["arguments"] == {"table": "opportunities", "ids": [1, 2, 3]}
    return session_id


def test_spans_arriving_child_first_rebuild_the_chain():
    """The OTLP exporter sends each span when it ends - children before parents."""
    store = Store(":memory:")
    _ingest_all(store, reversed(SPANS))
    _check_chain(store)


def test_spans_arriving_parents_first_rebuild_the_same_chain():
    store = Store(":memory:")
    _ingest_all(store, SPANS)
    _check_chain(store)


def test_sending_the_same_spans_again_changes_nothing():
    store = Store(":memory:")
    _ingest_all(store, SPANS)
    _ingest_all(store, SPANS)
    session_id = _check_chain(store)
    assert len(store.warrants_for_session(session_id)) == 3


def test_the_chain_says_it_was_observed_not_authorized():
    store = Store(":memory:")
    _ingest_all(store, SPANS)
    session_id = f"otel_{TRACE}"
    text = render_session(store, session_id, charset="ascii")
    assert "Observed" in text and "?  observed from existing telemetry" in text
    page = session_page(store, session_id)
    assert "Observed, not authorized" in page


def test_a_trace_with_real_warrants_is_never_also_built_as_observed():
    signer = Authority()
    root = signer.issue_root(session_id="ses_real", principal="p",
                             scope=Scope.of(operations=["read"], targets=["crm.*"]))
    warrant_span = (ROOT, None, "invoke_workflow warrant.session", 0, warrant_attributes(root))

    # Observed spans first, then the warrant span: the observed chain is replaced.
    store = Store(":memory:")
    _ingest_all(store, SPANS[1:])
    assert store.get_session(f"otel_{TRACE}") is not None
    ingest(store, _request(*warrant_span))
    assert store.get_session(f"otel_{TRACE}") is None

    # Warrant span first: GenAI spans in that trace are left to the warrant path.
    store = Store(":memory:")
    ingest(store, _request(*warrant_span))
    _ingest_all(store, SPANS[1:])
    assert store.get_session(f"otel_{TRACE}") is None


def test_ordinary_spans_with_no_agents_create_nothing():
    store = Store(":memory:")
    report = ingest(store, _request("9000000000000009", None, "GET /health", 0, {"http.method": "GET"},
                                    trace="0af7651916cd43dd8448eb211c80319c"))
    assert report.ignored == 1
    assert store.sessions() == []


@pytest.fixture
def collector(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    store = Store(":memory:")
    server = CollectorServer(("127.0.0.1", 0), store)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server, store
    server.shutdown()
    server.server_close()


def test_real_exporter_with_no_warrant_code_at_all(collector):
    """Five-minute try: ordinary OpenTelemetry code, pointed at the collector."""
    server, store = collector
    provider = TracerProvider()
    endpoint = f"http://127.0.0.1:{server.server_address[1]}/v1/traces"
    provider.add_span_processor(SimpleSpanProcessor(OTLPSpanExporter(endpoint=endpoint)))
    tracer = provider.get_tracer("some-agent-framework")

    with tracer.start_as_current_span("invoke_agent crm_agent", attributes={
            "gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "crm_agent"}) as agent_span:
        with tracer.start_as_current_span("execute_tool archive_records", attributes={
                "gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "archive_records"}):
            pass
    provider.shutdown()

    trace_id = format(agent_span.get_span_context().trace_id, "032x")
    session_id = f"otel_{trace_id}"
    assert [w.holder for w in store.warrants_for_session(session_id)] == ["entrypoint", "crm_agent"]
    (action,) = store.actions_for_session(session_id)
    assert (action.actor, action.operation) == ("crm_agent", "archive_records")
