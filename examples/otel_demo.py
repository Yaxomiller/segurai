"""What Segurai's OpenTelemetry output looks like.

Runs the Sarah scenario with span export switched on, then prints the spans
as an indented tree with their most useful attributes. In a real deployment
the same spans go to your tracing backend (Jaeger, Honeycomb, Datadog,
Grafana Tempo...) through a normal OTLP exporter - nothing Segurai-specific
is needed on that side.

Run:  python examples/otel_demo.py
"""

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

import segurai
from segurai import ActionSpec, Scope, count
from segurai.instrument import otel

# Collect spans in memory so this script can print them. A real app would add
# an OTLP exporter to its TracerProvider instead.
exporter = InMemorySpanExporter()
provider = TracerProvider()
provider.add_span_processor(SimpleSpanProcessor(exporter))
otel.enable(provider)


@segurai.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True))
def delete_records(table: str, ids: list[int]) -> int:
    return len(ids)


@segurai.agent("crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
def crm_agent() -> None:
    segurai.act("read", "crm.opportunities", scale=412)
    delete_records("opportunities", list(range(400)))


@segurai.agent("assistant")
def assistant() -> None:
    crm_agent()


GRANTED = Scope.of(operations=["read", "update", "delete"], targets=["crm.*"], max_scale=50)

with segurai.session(principal="sarah@company.com",
                     request="clean up our old sales records", scope=GRANTED):
    assistant()


# ---- print the spans as a tree ---------------------------------------------

SHOWN = (
    "gen_ai.operation.name", "gen_ai.agent.name", "gen_ai.tool.name",
    "warrant.root_principal", "warrant.id", "warrant.parent_id",
    "warrant.action.operation", "warrant.action.resource", "warrant.action.scale",
    "warrant.action.allowed", "warrant.action.violation",
)

spans = exporter.get_finished_spans()
children: dict = {}
for span in spans:
    children.setdefault(span.parent.span_id if span.parent else None, []).append(span)


def show(span, depth: int) -> None:
    pad = "    " * depth
    print(f"{pad}{span.name}")
    for key in SHOWN:
        if key in span.attributes:
            print(f"{pad}  | {key} = {span.attributes[key]}")
    for event in span.events:
        print(f"{pad}  ! event {event.name}: {event.attributes.get('warrant.violation.reason')}")
    for child in sorted(children.get(span.context.span_id, []), key=lambda s: s.start_time):
        show(child, depth + 1)


for root in children.get(None, []):
    show(root, 0)
