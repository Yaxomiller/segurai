"""The collector: a small HTTP service that receives spans from many agents.

    segurai collect --db central.db --key org.pub --port 4318

Agents point a standard OpenTelemetry OTLP/HTTP exporter at it:

    OTLPSpanExporter(endpoint="http://collector-host:4318/v1/traces")

and every session, warrant and action they emit lands in one database, with
every signature re-checked on arrival (see otlp.py for what is rebuilt).

Built on Python's standard-library HTTP server so it runs anywhere with no
extra infrastructure. That is enough for pilots and single-team deployments;
a busy production deployment would put it behind a reverse proxy (for TLS)
or be replaced by a production web stack later.

Endpoints:
    POST /v1/traces   OTLP/HTTP, protobuf or JSON, optional gzip
    GET  /healthz     returns "ok"
    GET  /            the web view of sessions (see web.py)
    GET  /sessions/x  one session: contract, chain, findings, verification

Security defaults:
    * listens on 127.0.0.1 unless told otherwise
    * optional bearer token (``Authorization: Bearer <token>``), compared in
      constant time so the token cannot be guessed by timing responses
    * request bodies are capped, before and after gzip decompression, so one
      oversized or maliciously compressed request cannot exhaust memory
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

from ..authority import Authority
from .otlp import IngestReport, UnsupportedEncoding, decode_request, ingest
from .store import Store
from .web import CSP, audit_page, index_page, permissions_page, session_page

__all__ = ["CollectorServer", "DEFAULT_MAX_BODY"]

_log = logging.getLogger("segurai.collector")

#: Largest accepted request body, in bytes (after decompression).
DEFAULT_MAX_BODY = 16 * 1024 * 1024


class CollectorServer(ThreadingHTTPServer):
    """An HTTP server that stores the spans it receives.

    ``address`` is ``(host, port)``; port 0 picks a free port (used in tests).
    ``verifier`` holds the organisation's public key; without one, warrants
    are stored unverified.
    """

    daemon_threads = True  # don't let a slow client keep the process alive on exit

    def __init__(self, address: tuple[str, int], store: Store, *,
                 verifier: Authority | None = None, token: str | None = None,
                 max_body: int = DEFAULT_MAX_BODY):
        self.store = store
        self.verifier = verifier
        self.token = token
        self.max_body = max_body
        super().__init__(address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    server: CollectorServer
    protocol_version = "HTTP/1.1"   # keep-alive, which the OTLP exporter uses

    # ---- plumbing ------------------------------------------------------

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - name set by the base class
        # Route request logs through logging instead of printing to stderr.
        _log.info("%s - %s", self.address_string(), format % args)

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8",
              extra_headers: dict[str, str] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # After an error, finish with the connection rather than holding it
        # open. The request may have been refused before its body was read,
        # so what is left in the socket belongs to a message nobody handled;
        # reusing the connection then desynchronises client and server, which
        # showed up as the client's connection being aborted at random.
        if status >= 400:
            self.close_connection = True
            self.send_header("Connection", "close")
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)
        self.wfile.flush()

    def _authorized(self) -> bool:
        """Accept the token as "Bearer <token>" (exporters) or as a Basic password (browsers).

        A browser cannot attach a bearer token to a page visit, but it does
        show a login box for Basic auth; the user name is ignored. Comparisons
        run in constant time so the token cannot be guessed from timings.
        """
        if not self.server.token:
            return True
        token = self.server.token.encode("utf-8")
        supplied = self.headers.get("Authorization", "")
        if hmac.compare_digest(supplied.encode("utf-8", "replace"), b"Bearer " + token):
            return True
        if supplied[:6].lower() == "basic ":
            try:
                decoded = base64.b64decode(supplied[6:].strip(), validate=True)
            except (binascii.Error, ValueError):
                return False
            _, _, password = decoded.partition(b":")
            return hmac.compare_digest(password, token)
        return False

    def _read_body(self) -> bytes | None:
        """Read the body within the size limit. Sends the error response and returns None on failure."""
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self._send(411, b"Content-Length required")
            return None
        try:
            length = int(length_header)
        except ValueError:
            self._send(400, b"bad Content-Length")
            return None
        if length < 0 or length > self.server.max_body:
            self._send(413, b"request body too large")
            return None
        body = self.rfile.read(length)

        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            # Decompress with a ceiling: a tiny gzip body can expand to
            # gigabytes (a "zip bomb"), so stop as soon as the limit is passed.
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                body = inflater.decompress(body, self.server.max_body + 1)
            except zlib.error:
                self._send(400, b"invalid gzip body")
                return None
            if len(body) > self.server.max_body or inflater.unconsumed_tail:
                self._send(413, b"request body too large after decompression")
                return None
        return body

    # ---- endpoints -----------------------------------------------------

    def _send_page(self, status: int, page: str) -> None:
        """An HTML page, with headers that stop it being scripted, sniffed, framed or cached."""
        self._send(status, page.encode("utf-8"), "text/html; charset=utf-8", extra_headers={
            "Content-Security-Policy": CSP,
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Cache-Control": "no-store",
        })

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/healthz":
            self._send(200, b"ok")
            return
        # The web view shows who asked for what, so it sits behind the token too.
        if not self._authorized():
            self._send(401, b"unauthorized",
                       extra_headers={"WWW-Authenticate": 'Basic realm="segurai", charset="UTF-8"'})
            return
        if path == "/":
            self._send_page(200, index_page(self.server.store, verifier=self.server.verifier))
        elif path == "/audit":
            self._send_page(200, audit_page(self.server.store, self.server.verifier))
        elif path == "/permissions":
            self._send_page(200, permissions_page(self.server.store, self.server.verifier))
        elif path.startswith("/sessions/"):
            session_id = unquote(path[len("/sessions/"):])
            page = session_page(self.server.store, session_id, self.server.verifier)
            if page is None:
                self._send(404, b"no such session")
            else:
                self._send_page(200, page)
        else:
            self._send(404, b"not found")

    def do_POST(self) -> None:
        if self.path.split("?")[0] != "/v1/traces":
            self._send(404, b"not found")
            return
        if not self._authorized():
            self._send(401, b"unauthorized", extra_headers={"WWW-Authenticate": "Bearer"})
            return
        body = self._read_body()
        if body is None:
            return

        content_type = self.headers.get("Content-Type", "")
        try:
            request = decode_request(body, content_type)
        except UnsupportedEncoding as exc:
            self._send(415, str(exc).encode("utf-8"))
            return
        except ValueError as exc:
            self._send(400, str(exc).encode("utf-8"))
            return

        report = ingest(self.server.store, request, self.server.verifier)
        if report.rejected:
            _log.warning("rejected %d warrant span(s): %s", len(report.rejected), report.rejected)
        self._respond(report, content_type)

    def _respond(self, report: IngestReport, content_type: str) -> None:
        """Answer in the encoding the client used, as OTLP/HTTP requires.

        Refused spans are reported through OTLP's "partial success" field, so
        the sender's exporter logs them instead of retrying forever.
        """
        rejected = len(report.rejected)
        message = "; ".join(report.rejected)[:1000]
        if content_type.split(";")[0].strip().lower() == "application/json":
            payload: dict = {}
            if rejected:
                payload["partialSuccess"] = {"rejectedSpans": str(rejected), "errorMessage": message}
            self._send(200, json.dumps(payload).encode("utf-8"), "application/json")
            return

        from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
            ExportTracePartialSuccess,
            ExportTraceServiceResponse,
        )
        response = ExportTraceServiceResponse()
        if rejected:
            response.partial_success.CopyFrom(
                ExportTracePartialSuccess(rejected_spans=rejected, error_message=message))
        self._send(200, response.SerializeToString(), "application/x-protobuf")
