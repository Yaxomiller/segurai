"""Carrying a request's authority through a queue, so the chain doesn't break there.

Inside one process the current warrant travels by itself, and across an HTTP
call or an MCP request it rides along with the call. A queue is different:
the message is written now and read later, by another service, perhaps
hours later. Without help the chain stops at the queue, and the worker's
actions belong to nobody.

So the producing agent hands the work over explicitly:

    # producer: an agent with work for the invoice worker
    headers = segurai.queues.handoff("invoice_worker",
                                     scope=Scope.of(operations=["read", "refund"]),
                                     seal_to=INVOICE_WORKER_PUBLIC_KEY)
    sqs.send_message(QueueUrl=url, MessageBody=body,
                     MessageAttributes=segurai.queues.sqs_attributes(headers))

    # consumer: the invoice worker, in another service
    headers = segurai.queues.from_sqs(message)
    with segurai.queues.received(headers, holder="invoice_worker", key=INVOICE_WORKER_PRIVATE_KEY):
        ...   # act, delegate, call the gateway - all under the request that started it

What travels in the message:

  * ``segurai-chain``: the chain from the person's root down to a hop the
    producer delegated for the consumer, by name, narrowed as it chose. It
    is signed all the way, so the consumer (and later an auditor) can PROVE
    who asked, through whom, for what. This is the "instrumented" path:
    audit evidence.
  * ``segurai-key`` (optional): that hop's private key, SEALED to the
    consumer's public key (X25519, HKDF-SHA256, ChaCha20-Poly1305, bound to
    the warrant id). Only the intended consumer can open it, and only with
    it can the consumer act at the gateway or delegate further. Anyone else
    who reads the queue - another consumer, a dead-letter tool, a backup -
    sees who authorized the work, but can't act on it.

Things to know:

  * The hop can't outlive the request that made it (it is a child warrant),
    so a message read after its warrant expired is refused. Work that must
    outlive the person's request is a job of its own: start it from a
    trigger (issuer.py).
  * Queues deliver at least once. Taking up the same hop twice is allowed -
    it is the same authority - and both runs' actions are recorded under it.
  * Each consumer service needs its own key pair: :func:`consumer_keypair`.
    Keep the private half like any service secret; give the public half to
    the producers.

For work that crosses a queue WITHOUT these headers, Segurai can still link
the two sides when OpenTelemetry span links connect them (the standard way
messaging is traced). Those links are shown as inferred - a probable cause,
for investigating - and never as evidence (collector/otlp.py).
"""

from __future__ import annotations

import base64
from contextlib import contextmanager
from datetime import timedelta
from typing import Any, Iterator, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .authority import ChainError
from .context import bind_warrant, current_warrant, export_chain, import_chain
from .models import Scope, Warrant

__all__ = ["CHAIN_HEADER", "KEY_HEADER", "handoff", "received", "consumer_keypair", "seal", "unseal",
           "sqs_attributes", "from_sqs", "kafka_headers", "from_kafka", "from_celery"]

CHAIN_HEADER = "segurai-chain"
KEY_HEADER = "segurai-key"
_SEAL_INFO = b"segurai-seal-v1"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# ---- keys and sealing -----------------------------------------------------------------------

def consumer_keypair() -> tuple[str, str]:
    """A new key pair for one consumer service: (private, public), as text."""
    private = X25519PrivateKey.generate()
    raw_private = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                        serialization.NoEncryption())
    raw_public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64(raw_private), _b64(raw_public)


def _derive(shared: bytes, ephemeral: bytes, recipient: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_SEAL_INFO + ephemeral + recipient).derive(shared)


def seal(secret: bytes, recipient_public: str, *, context: bytes) -> str:
    """Encrypt ``secret`` so only the holder of the matching private key can read it.

    ``context`` (the warrant id) is bound in: a sealed key moved onto another
    warrant's message won't open.
    """
    try:
        recipient = _unb64(recipient_public)
        public = X25519PublicKey.from_public_bytes(recipient)
    except ValueError as exc:
        raise ValueError("not a consumer public key (from consumer_keypair())") from exc
    ephemeral = X25519PrivateKey.generate()
    ephemeral_public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw,
                                                           serialization.PublicFormat.Raw)
    key = _derive(ephemeral.exchange(public), ephemeral_public, recipient)
    # A fresh key per message, so a fixed nonce is safe.
    return _b64(ephemeral_public + ChaCha20Poly1305(key).encrypt(b"\0" * 12, secret, context))


def unseal(sealed: str, private: str, *, context: bytes) -> bytes:
    """Open what :func:`seal` sealed. Raises ChainError if it wasn't sealed for this key and context."""
    try:
        raw = _unb64(sealed)
        own = X25519PrivateKey.from_private_bytes(_unb64(private))
        recipient = own.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        ephemeral_public, ciphertext = raw[:32], raw[32:]
        key = _derive(own.exchange(X25519PublicKey.from_public_bytes(ephemeral_public)), ephemeral_public, recipient)
        return ChaCha20Poly1305(key).decrypt(b"\0" * 12, ciphertext, context)
    except (InvalidTag, ValueError) as exc:
        raise ChainError("the sealed key in this message was not sealed for this consumer") from exc


# ---- handing over, and taking up -------------------------------------------------------------

def handoff(consumer: str, *, scope: Scope | None = None, ttl: timedelta | None = None,
            seal_to: str | None = None) -> dict[str, str]:
    """Delegate a hop for ``consumer`` from the current warrant; return the message headers.

    ``scope`` narrows what the consumer may do (fields left out inherit).
    ``seal_to`` is the consumer's public key: without it the consumer gets a
    proven chain but no key, so it can't act at the gateway or delegate.
    """
    from .runtime import _rt

    store, authority = _rt.ensure()
    parent = current_warrant()
    hop = authority.attenuate(parent, holder=consumer, scope=scope, ttl=ttl)
    store.put_warrant(hop)
    headers = {CHAIN_HEADER: export_chain(hop, include_key=False)}
    if seal_to is not None:
        private = authority.holder_private_key(hop.warrant_id)
        if private is None:
            raise ChainError("this process holds no key for the new hop (holder keys are off)")
        raw = private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())
        headers[KEY_HEADER] = seal(raw, seal_to, context=hop.warrant_id.encode("utf-8"))
    return headers


def _header(headers: Mapping[str, Any], name: str) -> str | None:
    for key, value in headers.items():
        if str(key).lower() == name:
            return value.decode("utf-8") if isinstance(value, (bytes, bytearray)) else str(value)
    return None


@contextmanager
def received(headers: Mapping[str, Any], *, holder: str, key: str | None = None) -> Iterator[Warrant]:
    """Take up the hop a producer handed this consumer, and make it the current warrant.

    The chain is verified against the organisation's public key (signatures,
    links, narrowing, expiry), and must end at a hop for ``holder``. With
    ``key`` (this consumer's private key) the sealed hop key is opened, so
    this process can act at the gateway and delegate further.
    """
    from .runtime import _rt

    store, authority = _rt.ensure()
    token = _header(headers, CHAIN_HEADER)
    if not token:
        raise ChainError(f"the message carries no {CHAIN_HEADER} header: nothing says who authorized it")
    chain, plain_key = import_chain(token)
    if plain_key is not None:
        raise ChainError("a chain on a queue must not carry its key in the clear; seal it to the consumer")
    leaf = chain[-1]
    if leaf.holder != holder:
        raise ChainError(f"this message was handed to {leaf.holder!r}, not {holder!r}")
    sealed = _header(headers, KEY_HEADER)
    private = None
    if sealed:
        if key is None:
            raise ChainError("the message carries a sealed key: pass key=<this consumer's private key>")
        private = unseal(sealed, key, context=leaf.warrant_id.encode("utf-8"))
    leaf = authority.adopt(chain, private)              # verifies every hop, and expiry
    for w in chain:
        store.put_warrant(w)
    with bind_warrant(leaf), _rt.hooks("agent_scope", leaf):
        yield leaf


# ---- the shapes particular queues want ----------------------------------------------------------

def sqs_attributes(headers: Mapping[str, str]) -> dict[str, dict[str, str]]:
    """Amazon SQS MessageAttributes."""
    return {k: {"DataType": "String", "StringValue": v} for k, v in headers.items()}


def from_sqs(message: Mapping[str, Any]) -> dict[str, str]:
    """The headers back out of an SQS message (as boto3 returns it)."""
    attributes = message.get("MessageAttributes") or {}
    return {k: v.get("StringValue", "") for k, v in attributes.items() if isinstance(v, Mapping)}


def kafka_headers(headers: Mapping[str, str]) -> list[tuple[str, bytes]]:
    """Kafka record headers (a list of (name, bytes))."""
    return [(k, v.encode("utf-8")) for k, v in headers.items()]


def from_kafka(headers: Any) -> dict[str, str]:
    """The headers back out of a Kafka record's headers list."""
    return {str(k): (v.decode("utf-8") if isinstance(v, (bytes, bytearray)) else str(v)) for k, v in headers or []}


def from_celery(request: Any) -> dict[str, str]:
    """The headers back out of a Celery task's ``self.request``.

    Send them with ``task.apply_async(args, headers=segurai.queues.handoff(...))``.
    """
    found: dict[str, str] = {}
    sources = [getattr(request, "headers", None) or {}]
    if isinstance(request, Mapping):
        sources.append(request)
    for source in sources:
        for name in (CHAIN_HEADER, KEY_HEADER):
            value = source.get(name) if isinstance(source, Mapping) else None
            if value is None:
                value = getattr(request, name.replace("-", "_"), None)
            if value is not None and name not in found:
                found[name] = str(value)
    for name in (CHAIN_HEADER, KEY_HEADER):
        if name not in found:
            value = getattr(request, name, None)
            if isinstance(value, str):
                found[name] = value
    return found
