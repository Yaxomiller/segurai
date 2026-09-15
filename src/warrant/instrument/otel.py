"""OpenTelemetry output: every session, agent hop and action becomes a span.

Why this exists: teams running agents in production already collect traces
(Datadog, Honeycomb, Grafana, Jaeger...). Emitting standard spans puts the
delegation chain inside the tools they already look at, next to their LLM
calls and HTTP requests, with no new dashboard to adopt.

Span names follow the OpenTelemetry GenAI semantic conventions:

    warrant.session(...)   ->  "invoke_workflow warrant.session"
    @warrant.agent(name)   ->  "invoke_agent <name>"
    tool call / act()      ->  "execute_tool <tool name>"

Each span also carries warrant's own attributes under the "warrant." prefix.
Together they hold the whole signed warrant - id, parent, depth, scope, key
id and signature - so a collector that receives only the spans can rebuild
the chain and re-check every signature itself.

Usage:

    from warrant.instrument import otel
    otel.enable()            # uses the global TracerProvider

Spans nest correctly because each one is opened as the *current* span while
the agent or tool runs: an LLM call or HTTP request made inside an agent
appears underneath that agent's span.
"""

from __future__ import annotations

import base64
import json
from contextlib import contextmanager
from contextvars import ContextVar
from typing import Any, Iterator

try:
    from opentelemetry import baggage, trace
    from opentelemetry import context as otel_context
except ImportError as exc:  # pragma: no cover - only without the optional extra
    raise ImportError(
        "warrant.instrument.otel needs OpenTelemetry: pip install 'warrant-provenance[otel]'"
    ) from exc

from .._version import __version__
from ..context import export_warrant, import_warrant
from ..models import ActionRecord, Warrant
from ..runtime import Listener, Session, add_listener, remove_listener

__all__ = [
    "enable", "disable", "OtelListener", "warrant_attributes", "action_attributes",
    "warrant_from_baggage", "BAGGAGE_KEY",
]

#: Baggage entry that carries the exported warrant to downstream services.
BAGGAGE_KEY = "warrant.token"

# Attribute names from the OpenTelemetry GenAI semantic conventions
# (https://opentelemetry.io/docs/specs/semconv/gen-ai/). Written out as plain
# strings because the conventions package keeps them in an "incubating"
# module whose import path is not stable yet.
GEN_AI_OPERATION_NAME = "gen_ai.operation.name"
GEN_AI_CONVERSATION_ID = "gen_ai.conversation.id"
GEN_AI_AGENT_NAME = "gen_ai.agent.name"
GEN_AI_TOOL_NAME = "gen_ai.tool.name"
GEN_AI_TOOL_CALL_ID = "gen_ai.tool.call.id"

# When a tool call opens its own span, the action recorded inside it should
# land on THAT span instead of creating a second one. This holds
# [span, already_used] for the tool span that is currently open.
_open_tool_span: ContextVar[list | None] = ContextVar("warrant_open_tool_span", default=None)


def warrant_attributes(w: Warrant) -> dict[str, Any]:
    """Every field of a warrant as span attributes.

    OpenTelemetry does not allow ``None`` attribute values, so optional
    fields are left out rather than sent empty.
    """
    attrs: dict[str, Any] = {
        GEN_AI_CONVERSATION_ID: w.session_id,
        "warrant.id": w.warrant_id,
        "warrant.session_id": w.session_id,
        "warrant.holder": w.holder,
        "warrant.root_principal": w.root_principal,
        "warrant.depth": w.depth,
        "warrant.scope": json.dumps(w.scope.to_dict(), sort_keys=True),
        "warrant.issued_at": w.issued_at.isoformat(),
        "warrant.expires_at": w.expires_at.isoformat(),
    }
    if w.parent_id:
        attrs["warrant.parent_id"] = w.parent_id
    if w.key_id:
        attrs["warrant.key_id"] = w.key_id
    if w.signature:
        attrs["warrant.signature"] = base64.b64encode(w.signature).decode("ascii")
    return attrs


def action_attributes(r: ActionRecord) -> dict[str, Any]:
    """Every field of an action record as span attributes."""
    attrs: dict[str, Any] = {
        "warrant.id": r.warrant_id,
        "warrant.session_id": r.session_id,
        "warrant.action.id": r.action_id,
        "warrant.action.actor": r.actor,
        "warrant.action.operation": r.operation,
        "warrant.action.resource": r.resource,
        "warrant.action.scale": r.scale,
        "warrant.action.irreversible": r.irreversible,
        "warrant.action.allowed": r.allowed,
        "warrant.action.blocked": r.blocked,
        "warrant.action.at": r.at.isoformat(),
    }
    if r.violation:
        attrs["warrant.action.violation"] = r.violation
    if r.detail:
        attrs["warrant.action.detail"] = json.dumps(r.detail, sort_keys=True, default=str)
    return attrs


class OtelListener(Listener):
    """Turns runtime events into OpenTelemetry spans.

    ``capture_request`` - include the human's request text on the session span.
    Turn it off if requests may contain data your tracing backend must not hold.

    ``propagate_baggage`` - also put the exported warrant into OpenTelemetry
    baggage, so instrumented HTTP clients forward it to downstream services
    automatically. Off by default: baggage is sent on EVERY outgoing request,
    including to third-party APIs, and the warrant names the principal and
    the scope.
    """

    def __init__(self, tracer_provider: Any = None, *, capture_request: bool = True,
                 propagate_baggage: bool = False):
        self._tracer = trace.get_tracer("warrant", __version__, tracer_provider=tracer_provider)
        self.capture_request = capture_request
        self.propagate_baggage = propagate_baggage

    @contextmanager
    def session_scope(self, session: Session) -> Iterator[None]:
        attrs = {
            GEN_AI_OPERATION_NAME: "invoke_workflow",
            "warrant.principal": session.principal,
            **warrant_attributes(session.root_warrant),
        }
        if self.capture_request:
            attrs["warrant.request"] = session.request
        with self._tracer.start_as_current_span("invoke_workflow warrant.session", attributes=attrs):
            with self._baggage(session.root_warrant):
                yield

    @contextmanager
    def agent_scope(self, warrant: Warrant) -> Iterator[None]:
        attrs = {
            GEN_AI_OPERATION_NAME: "invoke_agent",
            GEN_AI_AGENT_NAME: warrant.holder,
            **warrant_attributes(warrant),
        }
        with self._tracer.start_as_current_span(f"invoke_agent {warrant.holder}", attributes=attrs):
            with self._baggage(warrant):
                yield

    @contextmanager
    def tool_scope(self, tool_name: str, warrant: Warrant) -> Iterator[None]:
        attrs = {
            GEN_AI_OPERATION_NAME: "execute_tool",
            GEN_AI_TOOL_NAME: tool_name,
            GEN_AI_CONVERSATION_ID: warrant.session_id,
            "warrant.id": warrant.warrant_id,
        }
        with self._tracer.start_as_current_span(f"execute_tool {tool_name}", attributes=attrs) as span:
            token = _open_tool_span.set([span, False])
            try:
                yield
            finally:
                _open_tool_span.reset(token)

    def on_action(self, record: ActionRecord, warrant: Warrant) -> None:
        holder = _open_tool_span.get()
        if holder is not None and not holder[1]:
            # The action belongs to the tool span that is already open.
            span = holder[0]
            holder[1] = True
            span.set_attributes(action_attributes(record))
            _flag_violation(span, record)
            return

        # A bare warrant.act() with no tool span around it: record it as a
        # short span of its own, so it still shows up in the trace.
        tool_name = str(record.detail.get("tool") or record.operation)
        attrs = {
            GEN_AI_OPERATION_NAME: "execute_tool",
            GEN_AI_TOOL_NAME: tool_name,
            GEN_AI_CONVERSATION_ID: record.session_id,
            **action_attributes(record),
        }
        if record.detail.get("tool_call_id"):
            attrs[GEN_AI_TOOL_CALL_ID] = str(record.detail["tool_call_id"])
        with self._tracer.start_as_current_span(f"execute_tool {tool_name}", attributes=attrs) as span:
            _flag_violation(span, record)

    @contextmanager
    def _baggage(self, warrant: Warrant) -> Iterator[None]:
        if not self.propagate_baggage:
            yield
            return
        token = otel_context.attach(baggage.set_baggage(BAGGAGE_KEY, export_warrant(warrant)))
        try:
            yield
        finally:
            otel_context.detach(token)


def _flag_violation(span: Any, record: ActionRecord) -> None:
    """Mark a violation as a span event.

    Deliberately NOT an error status: in OBSERVE mode the action still went
    ahead and may have succeeded, and marking it failed would be untrue.
    """
    if not record.allowed:
        span.add_event("warrant.violation", {"warrant.violation.reason": record.violation or ""})


def warrant_from_baggage(ctx: Any = None) -> Warrant | None:
    """On a receiving service: the warrant a caller put in baggage, if any.

    The result is NOT verified yet - check it with your Authority before
    delegating from it (``warrant.delegate(..., parent=w)`` does that).
    """
    token = baggage.get_baggage(BAGGAGE_KEY, ctx)
    return import_warrant(str(token)) if token else None


_listener: OtelListener | None = None


def enable(tracer_provider: Any = None, *, capture_request: bool = True,
           propagate_baggage: bool = False) -> OtelListener:
    """Start emitting spans. Calling it again replaces the previous settings."""
    global _listener
    disable()
    _listener = OtelListener(tracer_provider, capture_request=capture_request,
                             propagate_baggage=propagate_baggage)
    add_listener(_listener)
    return _listener


def disable() -> None:
    """Stop emitting spans."""
    global _listener
    if _listener is not None:
        remove_listener(_listener)
        _listener = None
