"""The Segurai server: receives spans, issues roots, and serves the dashboard.

    segurai serve --config segurai.toml          everything, configured in one file
    segurai collect --db central.db --key org.pub --port 4318     just receive spans
    segurai ui --db central.db                                     just the dashboard

Endpoints:
    POST /v1/traces          OTLP/HTTP spans from agents (protobuf or JSON, optional gzip)
    POST /v1/sessions        the issuer: a root warrant for a proven person (issuer.py)
    GET  /healthz            "ok"
    GET  /                   the overview, with search and filters
    GET  /sessions/<id>      one request; /sessions/<id>/evidence.zip its evidence pack
    GET  /permissions        granted versus used
    GET  /audit              record integrity
    GET  /access             who opened what (auditors)
    GET/POST /admin/users    people and roles (admins)
    GET/POST /login, POST /logout, GET /auth/start, GET /auth/callback    signing in

Who may do what:
    * Agents and exporters authenticate with a bearer token (``ingest_tokens``).
    * The issuer authenticates the PERSON from their ID token, not the caller.
    * People sign in to the dashboard (auth.py) and see what their role allows.
      Without accounts configured, the older shared-token mode applies: one
      token for everything, as a bearer token or a Basic-auth password.

Security defaults:
    * listens on 127.0.0.1 unless told otherwise (the CLI refuses to listen
      wider without a token or accounts);
    * tokens compared in constant time; request bodies capped before and after
      gzip; forms protected by CSRF tokens and an Origin check;
    * pages carry a Content-Security-Policy with no scripts at all.

Built on the standard-library HTTP server so it runs anywhere with no extra
infrastructure; put a TLS-terminating reverse proxy in front of it.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import logging
import secrets
import zlib
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler
from typing import Any, Iterable
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

from .._net import ExclusiveHTTPServer
from ..authority import Authority
from . import web
from .auth import COOKIE, PRE_LOGIN_COOKIE, AuthError, WebAuth, safe_next
from .otlp import IngestReport, UnsupportedEncoding, decode_request, ingest
from .store import Store
from .web import CSP

__all__ = ["CollectorServer", "DEFAULT_MAX_BODY"]

_log = logging.getLogger("segurai.collector")

#: Largest accepted request body, in bytes (after decompression).
DEFAULT_MAX_BODY = 16 * 1024 * 1024
#: Largest accepted form body (sign-in, people).
_MAX_FORM = 64 * 1024
CSRF_COOKIE = "segurai_csrf"

#: The least role each dashboard page needs.
_ROLES = (("/access", "auditor"), ("/audit", "auditor"), ("/admin/", "admin"))


class CollectorServer(ExclusiveHTTPServer):
    """The HTTP server. ``address`` is ``(host, port)``; port 0 picks a free port (tests).

    ``verifier`` holds the organisation's public key (warrants are stored
    unverified without it). ``token`` is the older single shared token.
    ``auth`` turns on personal accounts; ``issuer`` the /v1/sessions endpoint;
    ``ingest_tokens`` the bearer tokens exporters may use; ``signer`` the
    organisation's private key, for signing evidence packs; ``witness_files``
    checkpoint files the integrity page checks against.
    """

    daemon_threads = True  # don't let a slow client keep the process alive on exit

    def __init__(self, address: tuple[str, int], store: Store, *,
                 verifier: Authority | None = None, token: str | None = None,
                 max_body: int = DEFAULT_MAX_BODY, auth: WebAuth | None = None, issuer: Any = None,
                 ingest_tokens: Iterable[str] = (), signer: Authority | None = None,
                 witness_files: Iterable[str] = (), trust_proxy: bool = False):
        self.store = store
        self.verifier = verifier
        self.token = token
        self.max_body = max_body
        self.auth = auth
        self.issuer = issuer
        self.ingest_tokens = tuple(t for t in ingest_tokens if t)
        self.signer = signer
        self.witness_files = tuple(witness_files)
        self.trust_proxy = trust_proxy
        super().__init__(address, _Handler)


class _Handler(BaseHTTPRequestHandler):
    server: CollectorServer
    protocol_version = "HTTP/1.1"   # keep-alive, which the OTLP exporter uses

    # ---- plumbing ------------------------------------------------------

    def log_message(self, format: str, *args) -> None:  # noqa: A002 - name set by the base class
        # Route request logs through logging instead of printing to stderr.
        _log.info("%s - %s", self.address_string(), format % args)

    #: The most of an unread request body that is read and thrown away before
    #: an error response (see _drain). Bigger bodies are not worth reading.
    DRAIN_LIMIT = 1024 * 1024

    def _drain(self) -> None:
        """Read and discard a request body nobody is going to use.

        A request refused before its body was read (wrong path, no token)
        still has that body waiting in the socket. Closing a socket with
        unread data in it makes the operating system send a TCP reset rather
        than a normal close, and the client can see the reset before it
        reads our answer - an "aborted connection" instead of a clear 404.
        Reading the body first lets the connection close cleanly.
        """
        if getattr(self, "_body_read", False):
            return
        self._body_read = True
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return
        if 0 < length <= self.DRAIN_LIMIT:
            try:
                self.rfile.read(length)
            except OSError:
                pass

    def _send(self, status: int, body: bytes, content_type: str = "text/plain; charset=utf-8",
              extra_headers: Any = None) -> None:
        # A page view is logged BEFORE the page goes out: a viewer who reads
        # it and disconnects is still on the record, and the entry exists by
        # the time anyone could look for it.
        pending = getattr(self, "_access_pending", None)
        if pending is not None:
            self._access_pending = None
            email, path, ip = pending
            self.server.auth.log(email, self.command, path, status, ip)
        if status >= 400:
            self._drain()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # After an error, finish with the connection rather than holding it
        # open: whatever the client sends next on it belongs to an exchange
        # that already failed.
        if status >= 400:
            self.close_connection = True
            self.send_header("Connection", "close")
        pairs = extra_headers.items() if isinstance(extra_headers, dict) else (extra_headers or [])
        for name, value in pairs:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.wfile.flush()

    def _redirect(self, location: str, cookies: list[str] | None = None) -> None:
        headers = [("Location", location), ("Cache-Control", "no-store")]
        headers += [("Set-Cookie", c) for c in cookies or []]
        self._send(303, b"", extra_headers=headers)

    def _client_ip(self) -> str:
        if self.server.trust_proxy:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip()[:64]
        return self.client_address[0]

    def _cookies(self) -> dict[str, str]:
        try:
            jar = SimpleCookie(self.headers.get("Cookie") or "")
        except CookieError:
            return {}
        return {k: v.value for k, v in jar.items()}

    def _authorized(self) -> bool:
        """The shared token as "Bearer <token>" (exporters) or as a Basic password (browsers)."""
        if not self.server.token:
            return True
        return self._bearer_matches([self.server.token]) or self._basic_matches(self.server.token)

    def _bearer_matches(self, tokens: Iterable[str]) -> bool:
        supplied = self.headers.get("Authorization", "").encode("utf-8", "replace")
        ok = False
        for token in tokens:     # check every token, so timing doesn't say which one matched
            ok |= hmac.compare_digest(supplied, b"Bearer " + token.encode("utf-8"))
        return ok

    def _basic_matches(self, token: str) -> bool:
        supplied = self.headers.get("Authorization", "")
        if supplied[:6].lower() != "basic ":
            return False
        try:
            decoded = base64.b64decode(supplied[6:].strip(), validate=True)
        except (binascii.Error, ValueError):
            return False
        return hmac.compare_digest(decoded.partition(b":")[2], token.encode("utf-8"))

    def _read_body(self, limit: int | None = None) -> bytes | None:
        """Read the body within the size limit. Sends the error response and returns None on failure."""
        limit = limit or self.server.max_body
        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self._send(411, b"Content-Length required")
            return None
        try:
            length = int(length_header)
        except ValueError:
            self._send(400, b"bad Content-Length")
            return None
        if length < 0 or length > limit:
            self._send(413, b"request body too large")
            return None
        self._body_read = True
        body = self.rfile.read(length)

        if self.headers.get("Content-Encoding", "").lower() == "gzip":
            # Decompress with a ceiling: a tiny gzip body can expand to
            # gigabytes (a "zip bomb"), so stop as soon as the limit is passed.
            inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
            try:
                body = inflater.decompress(body, limit + 1)
            except zlib.error:
                self._send(400, b"invalid gzip body")
                return None
            if len(body) > limit or inflater.unconsumed_tail:
                self._send(413, b"request body too large after decompression")
                return None
        return body

    def _send_page(self, status: int, page: str, cookies: list[str] | None = None) -> None:
        """An HTML page, with headers that stop it being scripted, sniffed, framed or cached."""
        headers = [("Content-Security-Policy", CSP), ("X-Content-Type-Options", "nosniff"),
                   ("X-Frame-Options", "DENY"), ("Referrer-Policy", "no-referrer"),
                   ("Cache-Control", "no-store")]
        headers += [("Set-Cookie", c) for c in cookies or []]
        self._send(status, page.encode("utf-8"), "text/html; charset=utf-8", extra_headers=headers)

    def _json(self, status: int, payload: dict) -> None:
        self._send(status, json.dumps(payload).encode("utf-8"), "application/json",
                   extra_headers={"Cache-Control": "no-store"})

    # ---- who is asking ---------------------------------------------------

    def _viewer(self) -> Any:
        auth = self.server.auth
        return auth.session_for(self._cookies().get(COOKIE)) if auth else None

    def _same_origin(self) -> bool:
        """Browsers send Origin on form posts; a post from another site is refused."""
        origin = self.headers.get("Origin")
        if not origin or origin == "null":
            return origin is None
        return urlsplit(origin).netloc == (self.headers.get("Host") or "")

    def _form(self) -> dict[str, str] | None:
        body = self._read_body(_MAX_FORM)
        if body is None:
            return None
        try:
            parsed = parse_qs(body.decode("utf-8"), keep_blank_values=True, max_num_fields=50)
        except (UnicodeDecodeError, ValueError):
            self._send(400, b"unreadable form")
            return None
        return {k: v[0] for k, v in parsed.items()}

    # ---- GET ----------------------------------------------------------------

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_GET(self) -> None:
        split = urlsplit(self.path)
        path, query = split.path, {k: v[0] for k, v in parse_qs(split.query, max_num_fields=20).items()}
        if path == "/healthz":
            self._send(200, b"ok")
            return
        auth = self.server.auth
        if auth is not None and path in ("/login", "/auth/start", "/auth/callback"):
            self._sign_in_pages(path, query)
            return
        if auth is None:
            # Older shared-token mode: one token sees everything.
            if not self._authorized():
                self._send(401, b"unauthorized",
                           extra_headers={"WWW-Authenticate": 'Basic realm="segurai", charset="UTF-8"'})
                return
            self._render(path, query, viewer=None)
            return

        viewer = self._viewer()
        if viewer is None:
            self._redirect("/login?" + urlencode({"next": self.path[:500]}))
            return
        needed = next((role for prefix, role in _ROLES if path.startswith(prefix)), "viewer")
        if path.endswith("/evidence.zip"):
            needed = "auditor"
        self._access_pending = (viewer.user.email, self.path, self._client_ip())
        if not viewer.user.can(needed):
            token = web.current_viewer.set(viewer)
            try:
                self._send_page(403, web.message_page("Not allowed", f"This page needs the {needed} role."))
            finally:
                web.current_viewer.reset(token)
            return
        self._render(path, query, viewer=viewer)

    def _render(self, path: str, query: dict[str, str], viewer: Any) -> int:
        """Draw one dashboard page for ``viewer``. Returns the status sent."""
        store, verifier = self.server.store, self.server.verifier
        token = web.current_viewer.set(viewer)
        try:
            if path == "/":
                self._send_page(200, web.index_page(store, verifier=verifier, filters=query))
            elif path == "/audit":
                self._send_page(200, web.audit_page(store, verifier, witnessed=self._witnessed()))
            elif path == "/permissions":
                self._send_page(200, web.permissions_page(store, verifier))
            elif path == "/access" and viewer is not None:
                self._send_page(200, web.access_page(store, query.get("email")))
            elif path == "/admin/users" and viewer is not None:
                self._send_page(200, web.users_page(store, csrf=viewer.csrf, message=query.get("done", ""),
                                                    error=query.get("error", "")))
            elif path.startswith("/sessions/") and path.endswith("/evidence.zip"):
                return self._evidence(unquote(path[len("/sessions/"):-len("/evidence.zip")]))
            elif path.startswith("/sessions/"):
                page = web.session_page(store, unquote(path[len("/sessions/"):]), verifier)
                if page is None:
                    self._send(404, b"no such session")
                    return 404
                self._send_page(200, page)
            else:
                self._send(404, b"not found")
                return 404
            return 200
        finally:
            web.current_viewer.reset(token)

    def _witnessed(self) -> list | None:
        if not self.server.witness_files:
            return None
        from ..witness import read_witness_file

        found = []
        for path in self.server.witness_files:
            try:
                found += read_witness_file(path)[0]
            except OSError as exc:
                _log.warning("witness file %s unreadable: %s", path, exc)
        return found

    def _evidence(self, session_id: str) -> int:
        from ..evidence import EvidenceError, build_pack

        authority = self.server.signer or self.server.verifier
        if authority is None:
            self._send(409, b"no organisation key is configured, so no pack can be signed")
            return 409
        try:
            html = web.session_page(self.server.store, session_id, self.server.verifier) or ""
            data = build_pack(self.server.store, session_id, authority, report_html=html,
                              witnessed=self._witnessed())
        except EvidenceError as exc:
            self._send(404 if "no session" in str(exc) else 409, str(exc).encode("utf-8"))
            return 404
        safe = "".join(c for c in session_id if c.isalnum() or c in "_-")[:64]
        self._send(200, data, "application/zip", extra_headers={
            "Content-Disposition": f'attachment; filename="{safe}-evidence.zip"',
            "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff"})
        return 200

    def _sign_in_pages(self, path: str, query: dict[str, str]) -> None:
        auth = self.server.auth
        ip = self._client_ip()
        if path == "/login":
            csrf = secrets.token_urlsafe(24)
            self._send_page(200, web.login_page(
                csrf, next_path=safe_next(query.get("next")), local=auth.local_accounts,
                oidc_label=auth.oidc.display_name if auth.oidc else None),
                cookies=[self._pre_cookie(CSRF_COOKIE, csrf)])
            return
        try:
            if path == "/auth/start":
                location, binding = auth.oidc_start(query.get("next", "/"))
                self._redirect(location, [self._pre_cookie(PRE_LOGIN_COOKIE, binding)])
                return
            token, _, next_path = auth.oidc_finish(query.get("state", ""), query.get("code", ""),
                                                   self._cookies().get(PRE_LOGIN_COOKIE), ip)
            self._redirect(next_path, [auth.cookie(token), self._pre_cookie(PRE_LOGIN_COOKIE, "", 0)])
        except AuthError as exc:
            self._send_page(401, web.login_page(secrets.token_urlsafe(24), error=str(exc),
                                                local=auth.local_accounts,
                                                oidc_label=auth.oidc.display_name if auth.oidc else None))

    def _pre_cookie(self, name: str, value: str, max_age: int = 600) -> str:
        secure = "; Secure" if self.server.auth and self.server.auth.cookie_secure else ""
        return f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}{secure}"

    # ---- POST --------------------------------------------------------------------

    def do_POST(self) -> None:
        path = self.path.split("?")[0]
        if path == "/v1/traces":
            self._ingest()
        elif path == "/v1/sessions":
            self._issue()
        elif self.server.auth is not None and path in ("/login", "/logout", "/admin/users"):
            if not self._same_origin():
                self._send(403, b"cross-site form refused")
                return
            {"/login": self._login, "/logout": self._logout, "/admin/users": self._people}[path]()
        else:
            self._send(404, b"not found")

    def _ingest(self) -> None:
        tokens = list(self.server.ingest_tokens) + ([self.server.token] if self.server.token else [])
        if tokens and not self._bearer_matches(tokens) and not (
                self.server.token and self._basic_matches(self.server.token)):
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

    def _issue(self) -> None:
        from ..issuer import IssueError

        issuer = self.server.issuer
        if issuer is None:
            self._send(404, b"this server does not issue sessions")
            return
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer "):
            self._json(401, {"error": "send the person's ID token as Authorization: Bearer <token>"})
            return
        body = self._read_body(_MAX_FORM)
        if body is None:
            return
        try:
            data = json.loads(body or b"{}")
            if not isinstance(data, dict):
                raise ValueError
        except ValueError:
            self._json(400, {"error": "the body must be a JSON object"})
            return
        try:
            result = issuer.issue(supplied[7:].strip(), data)
        except IssueError as exc:
            self._json(exc.status, {"error": str(exc)})
            return
        self._json(201, result)

    def _login(self) -> None:
        auth = self.server.auth
        form = self._form()
        if form is None:
            return
        expected = self._cookies().get(CSRF_COOKIE, "")
        if not expected or not hmac.compare_digest(form.get("csrf", ""), expected):
            self._send_page(400, web.login_page(secrets.token_urlsafe(24), error=(
                "Your sign-in form expired. Please try again."), local=auth.local_accounts,
                oidc_label=auth.oidc.display_name if auth.oidc else None))
            return
        try:
            token, _ = auth.sign_in(form.get("email", ""), form.get("password", ""), self._client_ip())
        except AuthError as exc:
            csrf = secrets.token_urlsafe(24)
            self._send_page(401, web.login_page(csrf, error=str(exc), next_path=safe_next(form.get("next")),
                                                local=auth.local_accounts,
                                                oidc_label=auth.oidc.display_name if auth.oidc else None),
                            cookies=[self._pre_cookie(CSRF_COOKIE, csrf)])
            return
        self._redirect(safe_next(form.get("next")), [auth.cookie(token), self._pre_cookie(CSRF_COOKIE, "", 0)])

    def _logout(self) -> None:
        auth = self.server.auth
        form = self._form()
        if form is None:
            return
        viewer = self._viewer()
        if viewer is not None and hmac.compare_digest(form.get("csrf", ""), viewer.csrf):
            auth.end(self._cookies().get(COOKIE))
            auth.log(viewer.user.email, "SIGN-OUT", "/logout", 200, self._client_ip())
        self._redirect("/login", [auth.cookie("", max_age=0)])

    def _people(self) -> None:
        auth = self.server.auth
        form = self._form()
        if form is None:
            return
        viewer = self._viewer()
        if viewer is None or not viewer.user.can("admin"):
            self._send(403, b"this needs the admin role")
            return
        if not hmac.compare_digest(form.get("csrf", ""), viewer.csrf):
            self._send(403, b"the form expired; reload the page")
            return
        by = viewer.user.email
        try:
            if form.get("action") == "create":
                auth.add_user(form.get("email", ""), form.get("role", ""), password=form.get("password", ""), by=by)
                done = f"Added {form.get('email', '').strip().lower()}."
            elif form.get("action") == "update":
                auth.update_user(form.get("email", ""), role=form.get("role") or None,
                                 disabled=form.get("disabled") == "1", by=by)
                done = f"Saved {form.get('email', '').strip().lower()}."
            else:
                raise AuthError("unknown action")
        except AuthError as exc:
            auth.log(by, "POST", "/admin/users", 400, self._client_ip())
            self._redirect("/admin/users?" + urlencode({"error": str(exc)}))
            return
        auth.log(by, "POST", "/admin/users", 200, self._client_ip())
        self._redirect("/admin/users?" + urlencode({"done": done}))

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
