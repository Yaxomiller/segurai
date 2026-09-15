"""Receiving spans: rebuilding warrants and actions from OpenTelemetry data.

When agents run in several processes or on several machines, each one sends
its spans to one collector. Two kinds of span are understood:

  1. WARRANT SPANS - emitted by warrant's own instrumentation
     (instrument/otel.py). They carry every field of every signed warrant and
     every action, so the collector rebuilds the chain exactly - and re-checks
     every signature itself, trusting nothing the senders claim.

  2. PLAIN GENAI SPANS - emitted by any framework that follows the
     OpenTelemetry GenAI conventions ("invoke_agent ...", "execute_tool ...").
     No warrant code was involved, so nothing was authorized or checked. The
     collector still rebuilds an OBSERVED chain from them - which agent called
     which tool, under whom - and labels it clearly as observed. This is the
     zero-integration path: a team already sending OpenTelemetry can see its
     agent chains in five minutes, before adopting anything.

Why observed chains are rebuilt rather than built once: the standard exporter
sends each span when it ENDS, so children arrive before their parents and in
separate requests. The collector keeps the spans of each trace and rebuilds
that trace's chain every time more of it arrives.

A trace that carries warrant spans is never also built as observed.

Two wire encodings of the same OTLP "ExportTraceServiceRequest" are accepted:

  * protobuf  - what OpenTelemetry's standard OTLP/HTTP exporter sends
                (needs: pip install 'warrant-provenance[collector]')
  * JSON      - OTLP/JSON, what the OpenTelemetry Collector and curl send

The shape of an OTLP request, reduced to what matters here:

    {"resourceSpans": [
        {"scopeSpans": [
            {"spans": [
                {"traceId": "...", "spanId": "...", "parentSpanId": "...",
                 "name": "invoke_agent crm_agent", "startTimeUnixNano": "...",
                 "attributes": [{"key": "gen_ai.agent.name", "value": {"stringValue": "crm_agent"}}]}
            ]}
        ]}
    ]}
"""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Iterator, Mapping

from ..authority import Authority, ChainError
from ..models import ActionRecord, Finding, Scope, Warrant, utcnow
from .store import Store

__all__ = ["decode_request", "ingest", "IngestReport", "UnsupportedEncoding", "OBSERVED_FINDING"]

# The attributes a span must have to carry a complete warrant.
_WARRANT_KEYS = ("warrant.id", "warrant.session_id", "warrant.holder", "warrant.root_principal",
                 "warrant.depth", "warrant.scope", "warrant.issued_at", "warrant.expires_at")

# From plain spans only these attributes are kept: enough to rebuild an
# observed chain, and nothing else (prompts and responses are not stored).
_OBSERVED_KEYS = ("gen_ai.operation.name", "gen_ai.agent.name", "gen_ai.tool.name",
                  "gen_ai.tool.call.id", "gen_ai.tool.call.arguments", "enduser.id", "user.id")

#: Attached to every action in an observed chain.
OBSERVED_FINDING = Finding(
    "warrant", "unverifiable",
    "observed from existing telemetry: no warrant was issued, so this action was not checked",
    "no warrant",
)


class UnsupportedEncoding(ValueError):
    """The request body is in an encoding this collector cannot read."""


@dataclass
class IngestReport:
    """What one batch of spans contributed."""

    spans: int = 0
    sessions: int = 0
    warrants: int = 0
    actions: int = 0
    observed_traces: int = 0                             # observed chains (re)built
    ignored: int = 0                                     # spans with nothing for warrant
    rejected: list[str] = field(default_factory=list)    # why each refused warrant was refused
    verified: bool = False                               # were signatures checked?


def decode_request(body: bytes, content_type: str) -> dict[str, Any]:
    """Turn an OTLP/HTTP request body into the OTLP/JSON dictionary shape."""
    ctype = (content_type or "").split(";")[0].strip().lower()
    if ctype == "application/json":
        try:
            decoded = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"not valid JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise ValueError("an OTLP/JSON body must be a JSON object")
        return decoded
    if ctype in ("application/x-protobuf", "application/protobuf"):
        try:
            from google.protobuf.json_format import MessageToDict
            from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
                ExportTraceServiceRequest,
            )
        except ImportError as exc:
            raise UnsupportedEncoding(
                "reading protobuf needs: pip install 'warrant-provenance[collector]'"
            ) from exc
        try:
            message = ExportTraceServiceRequest.FromString(body)
        except Exception as exc:  # protobuf raises its own DecodeError type
            raise ValueError(f"not a valid OTLP protobuf body: {exc}") from exc
        # MessageToDict produces the OTLP/JSON shape (camelCase keys, 64-bit
        # integers as strings), so one code path handles both encodings.
        # The one difference - ids come out base64 rather than hex - is
        # handled by _hex_id below.
        return MessageToDict(message)
    raise UnsupportedEncoding(f"unsupported content type {content_type!r}; "
                              f"send application/json or application/x-protobuf")


# ---- reading spans ----------------------------------------------------------

@dataclass
class _Span:
    trace_id: str | None
    span_id: str | None
    parent_span_id: str | None
    name: str
    started_at: datetime | None
    attrs: dict[str, Any]


def _value(v: Mapping[str, Any]) -> Any:
    """Unwrap one OTLP AnyValue, e.g. {"intValue": "400"} -> 400."""
    if "stringValue" in v:
        return v["stringValue"]
    if "boolValue" in v:
        return bool(v["boolValue"])
    if "intValue" in v:
        return int(v["intValue"])      # JSON encodes 64-bit ints as strings
    if "doubleValue" in v:
        return float(v["doubleValue"])
    if "arrayValue" in v:
        return [_value(item) for item in v["arrayValue"].get("values", [])]
    return None


def _hex_id(value: Any, hex_length: int) -> str | None:
    """A trace or span id as lowercase hex, whichever way it arrived.

    OTLP/JSON writes ids in hex; protobuf converted with MessageToDict writes
    them in base64. The lengths never overlap (a 16-hex-digit span id is 12
    base64 characters), so the two can be told apart safely. An all-zero id
    means "no id" in OpenTelemetry.
    """
    if not value:
        return None
    text = str(value)
    if len(text) == hex_length and all(c in "0123456789abcdefABCDEF" for c in text):
        result = text.lower()
    else:
        try:
            raw = base64.b64decode(text, validate=True)
        except (binascii.Error, ValueError):
            return None
        if len(raw) * 2 != hex_length:
            return None
        result = raw.hex()
    return None if set(result) == {"0"} else result


def _time(nanos: Any) -> datetime | None:
    try:
        ns = int(nanos)
    except (TypeError, ValueError):
        return None
    if ns <= 0:
        return None
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc) + timedelta(
        microseconds=(ns % 1_000_000_000) // 1000)


def _spans(request: Mapping[str, Any]) -> Iterator[_Span]:
    """Every span in the request, with its attributes flattened into a plain dict."""
    for resource_spans in request.get("resourceSpans") or []:
        for scope_spans in resource_spans.get("scopeSpans") or []:
            for span in scope_spans.get("spans") or []:
                yield _Span(
                    trace_id=_hex_id(span.get("traceId"), 32),
                    span_id=_hex_id(span.get("spanId"), 16),
                    parent_span_id=_hex_id(span.get("parentSpanId"), 16),
                    name=str(span.get("name") or ""),
                    started_at=_time(span.get("startTimeUnixNano")),
                    attrs={a["key"]: _value(a.get("value") or {}) for a in span.get("attributes") or []},
                )


# ---- warrant spans ------------------------------------------------------------

def _warrant(a: Mapping[str, Any]) -> Warrant:
    signature = a.get("warrant.signature")
    return Warrant(
        warrant_id=a["warrant.id"],
        session_id=a["warrant.session_id"],
        root_principal=a["warrant.root_principal"],
        holder=a["warrant.holder"],
        scope=Scope.from_dict(json.loads(a["warrant.scope"])),
        issued_at=datetime.fromisoformat(a["warrant.issued_at"]),
        expires_at=datetime.fromisoformat(a["warrant.expires_at"]),
        parent_id=a.get("warrant.parent_id") or None,
        depth=int(a["warrant.depth"]),
        key_id=a.get("warrant.key_id") or None,
        signature=base64.b64decode(signature) if signature else None,
    )


def _action(a: Mapping[str, Any]) -> ActionRecord:
    return ActionRecord(
        action_id=a["warrant.action.id"],
        session_id=a["warrant.session_id"],
        warrant_id=a["warrant.id"],
        actor=a["warrant.action.actor"],
        operation=a["warrant.action.operation"],
        resource=a["warrant.action.resource"],
        scale=int(a["warrant.action.scale"]),
        irreversible=bool(a["warrant.action.irreversible"]),
        at=datetime.fromisoformat(a["warrant.action.at"]),
        allowed=bool(a["warrant.action.allowed"]),
        violation=a.get("warrant.action.violation") or None,
        blocked=bool(a.get("warrant.action.blocked", False)),
        findings=tuple(Finding.from_dict(f) for f in json.loads(a.get("warrant.action.findings") or "[]")),
        detail=json.loads(a.get("warrant.action.detail") or "{}"),
    )


def _ingest_warrant_span(store: Store, attrs: Mapping[str, Any], verifier: Authority | None,
                         report: IngestReport) -> None:
    used = False
    try:
        if all(k in attrs for k in _WARRANT_KEYS):
            w = _warrant(attrs)
            if verifier is not None:
                verifier.verify(w)      # raises ChainError if forged or altered
            store.put_warrant(w)
            report.warrants += 1
            used = True
            # The session span is the one that also names the principal.
            if "warrant.principal" in attrs and w.parent_id is None:
                store.put_session(w.session_id, attrs["warrant.principal"],
                                  attrs.get("warrant.request", "(request not captured)"),
                                  None, w.issued_at)
                report.sessions += 1
        if "warrant.action.id" in attrs:
            store.put_action(_action(attrs))
            report.actions += 1
            used = True
    except ChainError as exc:
        report.rejected.append(f"{attrs.get('warrant.id', '?')}: {exc}")
        return
    except (KeyError, ValueError, TypeError) as exc:
        # A span that looks like ours but is malformed - say so rather than
        # dropping it silently.
        report.rejected.append(f"{attrs.get('warrant.id', '?')}: malformed span ({exc})")
        return
    if not used:
        report.ignored += 1


# ---- observed chains from plain GenAI spans ----------------------------------------

def _operation(span: Mapping[str, Any]) -> Any:
    return span["attributes"].get("gen_ai.operation.name")


def _rebuild_observed(store: Store, trace_id: str) -> bool:
    """Rebuild one trace's observed chain from every span of it seen so far.

    Returns False when the trace has no agent or tool spans (nothing to build).
    Every row written uses an id derived from the trace or span id, so a
    rebuild replaces the previous one instead of adding to it.
    """
    spans = store.observed_spans(trace_id)            # oldest first
    by_id = {s["span_id"]: s for s in spans}
    agents = [s for s in spans if _operation(s) == "invoke_agent"]
    tools = [s for s in spans if _operation(s) == "execute_tool"]
    if not agents and not tools:
        return False

    session_id = f"otel_{trace_id}"
    started = spans[0]["started_at"]
    principal = next((str(s["attributes"][k]) for s in spans for k in ("enduser.id", "user.id")
                      if s["attributes"].get(k)), "(unknown)")
    top = next((s for s in spans if not s["parent_span_id"] or s["parent_span_id"] not in by_id), spans[0])
    store.put_session(session_id, principal, f"(observed from OpenTelemetry) {top['name']}",
                      {"observed": True, "source": "opentelemetry", "trace_id": trace_id}, started)

    # Observed warrants grant nothing and are signed by no one: an empty
    # scope, no signature, and key_id "observed" say so to anyone who looks.
    root = Warrant(warrant_id=f"obs_root_{trace_id}", session_id=session_id, root_principal=principal,
                   holder="entrypoint", scope=Scope(), issued_at=started, expires_at=started,
                   parent_id=None, depth=0, key_id="observed")
    store.put_warrant(root)

    def agent_above(span: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """The nearest invoke_agent span above this one (skipping LLM calls, HTTP spans...)."""
        seen: set[str] = set()
        parent = span["parent_span_id"]
        while parent and parent in by_id and parent not in seen:
            seen.add(parent)
            candidate = by_id[parent]
            if _operation(candidate) == "invoke_agent":
                return candidate
            parent = candidate["parent_span_id"]
        return None

    warrants: dict[str, Warrant] = {}
    building: set[str] = set()

    def warrant_for(agent: Mapping[str, Any]) -> Warrant:
        wid = f"obs_{agent['span_id']}"
        if wid in warrants:
            return warrants[wid]
        building.add(wid)
        above = agent_above(agent)
        # A parent already being built means the span parents loop - bad data;
        # hang the agent off the root rather than recursing forever.
        parent = root if above is None or f"obs_{above['span_id']}" in building else warrant_for(above)
        holder = (agent["attributes"].get("gen_ai.agent.name")
                  or agent["name"].removeprefix("invoke_agent").strip() or "agent")
        w = Warrant(warrant_id=wid, session_id=session_id, root_principal=principal, holder=str(holder),
                    scope=Scope(), issued_at=agent["started_at"], expires_at=agent["started_at"],
                    parent_id=parent.warrant_id, depth=parent.depth + 1, key_id="observed")
        building.discard(wid)
        warrants[wid] = w
        return w

    for agent in agents:
        store.put_warrant(warrant_for(agent))

    for tool in tools:
        above = agent_above(tool)
        holder = warrant_for(above) if above is not None else root
        attrs = tool["attributes"]
        name = str(attrs.get("gen_ai.tool.name") or tool["name"].removeprefix("execute_tool").strip() or "tool")
        detail: dict[str, Any] = {"tool": name, "observed": True}
        if attrs.get("gen_ai.tool.call.id"):
            detail["tool_call_id"] = attrs["gen_ai.tool.call.id"]
        arguments = attrs.get("gen_ai.tool.call.arguments")
        if arguments is not None:
            try:
                detail["arguments"] = json.loads(arguments) if isinstance(arguments, str) else arguments
            except ValueError:
                detail["arguments"] = arguments
        store.put_action(ActionRecord(
            action_id=f"obs_{tool['span_id']}", session_id=session_id, warrant_id=holder.warrant_id,
            actor=holder.holder, operation=name, resource=f"tool.{name}", scale=1, irreversible=False,
            at=tool["started_at"], allowed=True, violation=None, blocked=False,
            findings=(OBSERVED_FINDING,), detail=detail,
        ))
    return True


# ---- the entry point -------------------------------------------------------------

def ingest(store: Store, request: Mapping[str, Any], verifier: Authority | None = None) -> IngestReport:
    """Store every session, warrant and action found in an OTLP request.

    Warrant spans: with a ``verifier`` (the organisation's public key), each
    warrant's signature is checked and a warrant that fails is NOT stored -
    its id and the reason go into ``report.rejected``. Without one, warrants
    are stored as received, and ``warrant verify`` can check them later.

    Plain GenAI spans: kept, and their trace's observed chain rebuilt.

    Storing is idempotent: the same span sent twice changes nothing.
    """
    report = IngestReport(verified=verifier is not None)
    touched: set[str] = set()

    for span in _spans(request):
        report.spans += 1
        if any(key.startswith("warrant.") for key in span.attrs):
            if span.trace_id and not store.is_warrant_trace(span.trace_id):
                # This trace has real warrants: it must never also appear as
                # an observed chain. Remove one built from earlier spans.
                store.mark_warrant_trace(span.trace_id)
                store.forget_session(f"otel_{span.trace_id}")
            _ingest_warrant_span(store, span.attrs, verifier, report)
            continue

        if span.trace_id and span.span_id:
            # Keep every plain span with ids, even ones that are not agents or
            # tools: an LLM or HTTP span may be what links a tool call to the
            # agent above it.
            store.put_observed_span(span.trace_id, span.span_id, span.parent_span_id, span.name,
                                    span.started_at or utcnow(),
                                    {k: span.attrs[k] for k in _OBSERVED_KEYS if k in span.attrs})
            touched.add(span.trace_id)
        if span.attrs.get("gen_ai.operation.name") not in ("invoke_agent", "execute_tool"):
            report.ignored += 1

    for trace_id in sorted(touched):
        if not store.is_warrant_trace(trace_id) and _rebuild_observed(store, trace_id):
            report.observed_traces += 1
    return report
