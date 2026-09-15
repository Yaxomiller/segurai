"""OpenTelemetry spans: names, nesting, attributes, and baggage."""

import base64
import json

import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

import warrant
from warrant import ActionSpec, Scope, count
from warrant.instrument import otel

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


def _provider():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return exporter, provider


@pytest.fixture
def spans():
    exporter, provider = _provider()
    otel.enable(provider)
    yield exporter
    otel.disable()


def _by_name(exporter):
    return {s.name: s for s in exporter.get_finished_spans()}


def _run():
    @warrant.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True))
    def delete_records(table, ids):
        return len(ids)

    @warrant.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
    def crm_agent():
        warrant.act("read", "crm.opportunities", scale=412)
        delete_records("opportunities", list(range(400)))

    @warrant.agent("assistant")
    def assistant():
        crm_agent()

    with warrant.session(principal="sarah@company.com",
                         request="clean up our old sales records", scope=GRANTED) as s:
        assistant()
    return s


def test_span_names_follow_the_genai_conventions(spans):
    _run()
    names = {s.name for s in spans.get_finished_spans()}
    assert {"invoke_workflow warrant.session", "invoke_agent assistant",
            "invoke_agent crm_agent", "execute_tool delete_records",
            "execute_tool read"} <= names


def test_spans_nest_like_the_delegation_chain(spans):
    _run()
    by = _by_name(spans)
    session = by["invoke_workflow warrant.session"]
    assistant = by["invoke_agent assistant"]
    crm = by["invoke_agent crm_agent"]
    tool = by["execute_tool delete_records"]
    assert assistant.parent.span_id == session.context.span_id
    assert crm.parent.span_id == assistant.context.span_id
    assert tool.parent.span_id == crm.context.span_id
    assert len({s.context.trace_id for s in (session, assistant, crm, tool)}) == 1


def test_agent_span_carries_the_whole_signed_warrant(spans):
    s = _run()
    attrs = _by_name(spans)["invoke_agent crm_agent"].attributes
    assert attrs["gen_ai.operation.name"] == "invoke_agent"
    assert attrs["gen_ai.agent.name"] == "crm_agent"
    assert attrs["gen_ai.conversation.id"] == s.session_id

    stored = {w.warrant_id: w for w in s.chain()}[attrs["warrant.id"]]
    assert attrs["warrant.parent_id"] == stored.parent_id
    assert json.loads(attrs["warrant.scope"]) == stored.scope.to_dict()
    assert base64.b64decode(attrs["warrant.signature"]) == stored.signature
    assert attrs["warrant.key_id"] == stored.key_id


def test_violation_is_an_event_not_an_error_status(spans):
    _run()
    tool = _by_name(spans)["execute_tool delete_records"]
    assert tool.attributes["warrant.action.allowed"] is False
    assert tool.attributes["warrant.action.scale"] == 400
    assert [e.name for e in tool.events] == ["warrant.violation"]
    assert tool.status.status_code is not StatusCode.ERROR


def test_session_span_includes_the_request_unless_told_not_to():
    exporter, provider = _provider()
    otel.enable(provider, capture_request=False)
    try:
        with warrant.session(principal="p", request="secret request", scope=GRANTED):
            pass
    finally:
        otel.disable()
    (span,) = exporter.get_finished_spans()
    assert "warrant.request" not in span.attributes
    assert span.attributes["warrant.principal"] == "p"


def test_baggage_carries_the_warrant_when_enabled():
    _, provider = _provider()
    otel.enable(provider, propagate_baggage=True)
    try:
        @warrant.agent("crm_agent")
        def crm_agent():
            return otel.warrant_from_baggage()

        with warrant.session(principal="p", request="r", scope=GRANTED):
            carried = crm_agent()
    finally:
        otel.disable()
    assert carried.holder == "crm_agent"
    warrant._runtime.authority.verify(carried)


def test_baggage_is_off_by_default(spans):
    with warrant.session(principal="p", request="r", scope=GRANTED):
        assert otel.warrant_from_baggage() is None


def test_disable_stops_spans(spans):
    otel.disable()
    with warrant.session(principal="p", request="r", scope=GRANTED):
        warrant.act("read", "crm.x")
    assert spans.get_finished_spans() == ()
