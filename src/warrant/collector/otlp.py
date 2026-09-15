"""Receiving spans: rebuilding warrants and actions from OpenTelemetry data.

When agents run in several processes or on several machines, each one sends
its spans (see instrument/otel.py) to one collector. Those spans carry every
field of every signed warrant and every action, so the collector can rebuild
the whole delegation chain in its own store - and re-check every signature
itself, trusting nothing the senders claim.

Two wire encodings of the same OTLP "ExportTraceServiceRequest" are accepted:

  * protobuf  - what OpenTelemetry's standard OTLP/HTTP exporter sends
                (needs: pip install 'warrant-provenance[collector]')
  * JSON      - OTLP/JSON, what the OpenTelemetry Collector and curl send

Spans that carry no warrant attributes - LLM calls, HTTP requests, database
queries from other instrumentation - are counted and ignored.

The shape of an OTLP request, reduced to what matters here:

    {"resourceSpans": [
        {"scopeSpans": [
            {"spans": [
                {"name": "invoke_agent crm_agent",
                 "attributes": [{"key": "warrant.id", "value": {"stringValue": "wrt_..."}}, ...]}
            ]}
        ]}
    ]}
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterator, Mapping

from ..authority import Authority, ChainError
from ..models import ActionRecord, Scope, Warrant
from .store import Store

__all__ = ["decode_request", "ingest", "IngestReport", "UnsupportedEncoding"]

# The attributes a span must have to carry a complete warrant.
_WARRANT_KEYS = ("warrant.id", "warrant.session_id", "warrant.holder", "warrant.root_principal",
                 "warrant.depth", "warrant.scope", "warrant.issued_at", "warrant.expires_at")


class UnsupportedEncoding(ValueError):
    """The request body is in an encoding this collector cannot read."""


@dataclass
class IngestReport:
    """What one batch of spans contributed."""

    spans: int = 0
    sessions: int = 0
    warrants: int = 0
    actions: int = 0
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
        # MessageToDict produces exactly the OTLP/JSON shape (camelCase keys,
        # 64-bit integers as strings), so one code path handles both.
        return MessageToDict(message)
    raise UnsupportedEncoding(f"unsupported content type {content_type!r}; "
                              f"send application/json or application/x-protobuf")


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


def _spans(request: Mapping[str, Any]) -> Iterator[dict[str, Any]]:
    """Every span in the request, with its attributes flattened into a plain dict."""
    for resource_spans in request.get("resourceSpans") or []:
        for scope_spans in resource_spans.get("scopeSpans") or []:
            for span in scope_spans.get("spans") or []:
                yield {a["key"]: _value(a.get("value") or {}) for a in span.get("attributes") or []}


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
        detail=json.loads(a.get("warrant.action.detail") or "{}"),
    )


def ingest(store: Store, request: Mapping[str, Any], verifier: Authority | None = None) -> IngestReport:
    """Store every session, warrant and action found in an OTLP request.

    With a ``verifier`` (the organisation's public key), each warrant's
    signature is checked and a warrant that fails is NOT stored - its id and
    the reason go into ``report.rejected``. Without one, warrants are stored
    as received, and ``warrant verify`` can check them later.

    Storing is idempotent: the same span sent twice changes nothing.
    """
    report = IngestReport(verified=verifier is not None)
    for attrs in _spans(request):
        report.spans += 1
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
            continue
        except (KeyError, ValueError, TypeError) as exc:
            # A span that looks like ours but is malformed - say so rather than
            # dropping it silently.
            report.rejected.append(f"{attrs.get('warrant.id', '?')}: malformed span ({exc})")
            continue
        if not used:
            report.ignored += 1
    return report
