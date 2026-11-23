"""The chain across a queue: proven when the message carries it, inferred when only span links do.

The consumer side runs as another process would: a fresh store, and only the
organisation's PUBLIC key - so nothing it does can lean on keys the producer
happened to leave in memory.
"""

import threading
from datetime import timedelta
from types import SimpleNamespace

import pytest
from test_gateway import SECRET, FakeCRM

import segurai
from segurai import Authority, ChainError, Scope, Store
from segurai.collector.otlp import ingest
from segurai.collector.web import session_page
from segurai.gateway import GatewayClient, GatewayConfig, GatewayServer, Route, Upstream
from segurai.queues import (
    CHAIN_HEADER,
    KEY_HEADER,
    consumer_keypair,
    from_celery,
    from_kafka,
    from_sqs,
    handoff,
    kafka_headers,
    received,
    sqs_attributes,
)

GRANTED = Scope.of(operations=["read", "refund"], targets=["billing.*"], max_scale=10)


READ_ONLY = Scope.of(operations=["read"])


def _produce(seal_to=None, consumer="invoice_worker", scope=READ_ONLY, ttl=None):
    """Sarah's assistant hands invoice work to a worker; returns (session id, message headers, org key)."""
    org = segurai._runtime.authority
    with segurai.session(principal="sarah@acme.example", request="check last month's invoices",
                         scope=GRANTED) as s:
        with segurai.delegate("assistant"):
            headers = handoff(consumer, scope=scope, seal_to=seal_to, **({"ttl": ttl} if ttl else {}))
    return s.session_id, headers, org


def _as_consumer(org):
    """Become another process: an empty store and only the organisation's public key."""
    segurai.configure(store=":memory:", authority=org.public_only())
    return segurai._runtime.store


def test_a_sealed_handoff_lets_only_that_worker_act_and_proves_who_asked():
    private, public = consumer_keypair()
    session_id, headers, org = _produce(seal_to=public)
    assert set(headers) == {CHAIN_HEADER, KEY_HEADER}
    store = _as_consumer(org)

    crm = FakeCRM()
    routes = (Route("GET", "/invoices", "read", "billing.invoices"),)
    gateway = GatewayServer(("127.0.0.1", 0), GatewayConfig(upstreams=(Upstream(
        "billing", "/billing", crm.url, routes, {"Authorization": SECRET}),)), store, org.public_only())
    threading.Thread(target=gateway.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    try:
        with received(headers, holder="invoice_worker", key=private) as hop:
            assert hop.holder == "invoice_worker" and hop.session_id == session_id
            assert hop.scope.operations == frozenset({"read"})          # narrowed by the producer
            client = GatewayClient(f"http://127.0.0.1:{gateway.server_address[1]}")
            assert client.request("GET", "/billing/invoices")[0] == 200
            with segurai.delegate("pdf_reader"):                         # and it can delegate further
                assert client.request("GET", "/billing/invoices")[0] == 200
        (first, second) = store.actions_for_session(session_id)
        chain = store.chain_to(second.warrant_id)
        assert [w.holder for w in chain] == ["entrypoint", "assistant", "invoice_worker", "pdf_reader"]
        assert chain[0].root_principal == "sarah@acme.example"
    finally:
        gateway.shutdown()
        gateway.server_close()
        crm.close()


def test_without_its_key_a_worker_can_prove_the_chain_but_not_act():
    session_id, headers, org = _produce()
    assert KEY_HEADER not in headers
    _as_consumer(org)
    with received(headers, holder="invoice_worker") as hop:
        assert hop.session_id == session_id
        with pytest.raises(ChainError):
            segurai.gateway.proof_headers("GET", "/billing/invoices")


def test_the_wrong_worker_gets_nothing():
    private, public = consumer_keypair()
    other_private, _ = consumer_keypair()
    _, headers, org = _produce(seal_to=public)
    _as_consumer(org)
    with pytest.raises(ChainError, match="not sealed for this consumer"):
        with received(headers, holder="invoice_worker", key=other_private):
            pass
    with pytest.raises(ChainError, match="handed to 'invoice_worker', not 'refund_worker'"):
        with received(headers, holder="refund_worker", key=private):
            pass
    with pytest.raises(ChainError, match="pass key="):
        with received(headers, holder="invoice_worker"):
            pass


def test_a_sealed_key_moved_to_another_message_does_not_open():
    private, public = consumer_keypair()
    _, first, org = _produce(seal_to=public)
    _, second, _ = _produce(seal_to=public)
    _as_consumer(org)
    swapped = {CHAIN_HEADER: second[CHAIN_HEADER], KEY_HEADER: first[KEY_HEADER]}
    with pytest.raises(ChainError, match="not sealed for this consumer"):
        with received(swapped, holder="invoice_worker", key=private):
            pass


def test_forged_widened_stale_or_plain_keyed_messages_are_refused():
    private, public = consumer_keypair()
    _, headers, org = _produce(seal_to=public, ttl=timedelta(seconds=1))
    # A chain token with the key in the clear is refused outright.
    with segurai.session(principal="sarah@acme.example", request="x", scope=GRANTED):
        with segurai.delegate("invoice_worker"):
            plain = {CHAIN_HEADER: segurai.export_chain(include_key=True)}
    # A chain signed by some other organisation is refused.
    segurai.configure(store=":memory:", authority=Authority())
    with segurai.session(principal="mallory@evil.example", request="x", scope=GRANTED):
        with segurai.delegate("assistant"):
            foreign = handoff("invoice_worker", seal_to=public)
    _as_consumer(org)
    with pytest.raises(ChainError, match="in the clear"):
        with received(plain, holder="invoice_worker"):
            pass
    with pytest.raises(ChainError):
        with received(foreign, holder="invoice_worker", key=private):
            pass
    with pytest.raises(ChainError, match="no segurai-chain"):
        with received({}, holder="invoice_worker"):
            pass
    import time
    time.sleep(1.2)                                           # the hop's one second runs out
    with pytest.raises(ChainError, match="expired"):
        with received(headers, holder="invoice_worker", key=private):
            pass


def test_the_headers_survive_each_queues_shape():
    private, public = consumer_keypair()
    _, headers, _ = _produce(seal_to=public)
    assert from_sqs({"MessageAttributes": sqs_attributes(headers)}) == headers
    assert from_kafka(kafka_headers(headers)) == headers
    celery_request = SimpleNamespace(headers=dict(headers))
    assert from_celery(celery_request) == headers
    # Header names are matched without regard to case (HTTP lowercases, some brokers don't).
    shouted = {k.upper(): v for k, v in headers.items()}
    with received(shouted, holder="invoice_worker", key=private) as hop:
        assert hop.holder == "invoice_worker"


# ---- inferred: span links, when the message carried nothing ------------------------------------

PRODUCER, CONSUMER = "a" * 32, "b" * 32


def _span(trace, span_id, name, attrs, links=()):
    def value(v):
        return {"stringValue": str(v)}
    span = {"traceId": trace, "spanId": span_id, "name": name, "startTimeUnixNano": "1760000000000000000",
            "attributes": [{"key": k, "value": value(v)} for k, v in attrs.items()],
            "links": [{"traceId": t, "spanId": s} for t, s in links]}
    return {"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}


def test_span_links_are_shown_as_a_probable_cause_never_as_proof():
    store = Store(":memory:")
    ingest(store, _span(PRODUCER, "1" * 16, "invoke_agent assistant",
                        {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "assistant",
                         "enduser.id": "sarah@acme.example"}))
    ingest(store, _span(CONSUMER, "2" * 16, "invoke_agent invoice_worker",
                        {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "invoice_worker"},
                        links=[(PRODUCER, "1" * 16)]))
    consumer = store.get_session(f"otel_{CONSUMER}")
    assert consumer.contract["follows_from"] == [{"trace_id": PRODUCER, "span_id": "1" * 16,
                                                  "session_id": f"otel_{PRODUCER}"}]
    assert "not evidence" in consumer.contract["link"]
    page = session_page(store, f"otel_{CONSUMER}")
    assert "inferred" in page and f"otel_{PRODUCER}" in page and "not evidence" in page
    assert "follows_from" not in store.get_session(f"otel_{PRODUCER}").contract
