"""Alerts: tell someone the moment an agent goes beyond a request.

A dashboard only helps if someone opens it. This module watches the record and
sends a message - to Slack, to any webhook, or by email - when:

    violation   an agent did something outside its warrant or the rules, and it went ahead
    blocked     an agent tried, and enforce mode (or the gateway) stopped it
    tamper      the record no longer matches its tamper-evident log

How it works - an "outbox", so nothing is lost and nothing is sent twice:

  1. A background worker reads actions it hasn't seen yet, in the order they
     were stored (a cursor kept in the database). It doesn't matter how an
     action arrived - the runtime, spans from another process, the gateway -
     everything ends up in the same table.
  2. For each one worth telling, it queues one alert per interested channel.
     A unique key (event, record, channel) means a restart or a second
     worker can never queue the same alert twice.
  3. It sends what's due. A failed send is retried with growing gaps
     (30 s, 1 min, 2 min ... up to an hour) and given up after 8 tries, with
     the last error kept so the dashboard can show it.
  4. Every few minutes it re-runs the audit; if the record has been tampered
     with, that is an alert too (once per distinct problem, not every scan).

Messages carry the facts and a link to the request in the dashboard, never
the full detail an agent reported - alert channels are often wider audiences
than the dashboard.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import smtplib
import ssl
import threading
import time
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import timedelta
from email.message import EmailMessage
from typing import Any, Iterable

from .collector.store import Store
from .models import ActionRecord

__all__ = ["Channel", "SlackChannel", "WebhookChannel", "EmailChannel", "AlertWorker",
           "EVENTS", "AlertError", "format_action"]

_log = logging.getLogger("segurai.alerts")

EVENTS = ("violation", "blocked", "tamper")
MAX_ATTEMPTS = 8
#: How long a server holds an alert it is sending before another may try. Far
#: longer than any channel's timeout, so a slow send is never doubled.
CLAIM_LEASE = timedelta(minutes=5)


class AlertError(Exception):
    """A channel that could not deliver. The worker retries it later."""


def _http_allowed(url: str, allow_http: bool) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme == "https" and parsed.hostname:
        return
    if parsed.scheme == "http" and parsed.hostname and (
            allow_http or parsed.hostname in ("127.0.0.1", "localhost", "::1")):
        return
    raise ValueError(f"alert URL must be https (got {url!r})")


def _post_json(url: str, payload: dict[str, Any], headers: dict[str, str] | None = None,
               timeout: float = 10.0) -> None:
    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json",
                                              "User-Agent": "segurai-alerts", **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:     # noqa: S310 - scheme checked
            if not 200 <= response.status < 300:
                raise AlertError(f"{urllib.parse.urlsplit(url).hostname} answered {response.status}")
    except urllib.error.HTTPError as exc:
        raise AlertError(f"{urllib.parse.urlsplit(url).hostname} answered {exc.code}") from exc
    except (OSError, urllib.error.URLError) as exc:
        raise AlertError(f"could not reach {urllib.parse.urlsplit(url).hostname}: {exc}") from exc


# ---- what a message says -------------------------------------------------------------

def format_action(event: str, record: ActionRecord, principal: str, request: str,
                  link: str | None) -> tuple[str, list[str]]:
    """(headline, detail lines) for an action alert, in plain words."""
    noun = "record" if record.scale == 1 else "records"
    if event == "blocked":
        headline = (f"Stopped: {record.actor} tried to {record.operation} {record.scale} {noun} "
                    f"in {record.resource}")
    else:
        headline = (f"Went beyond the request: {record.actor} {record.operation} "
                    f"{record.scale} {noun} in {record.resource}")
    lines = [f"Asked by {principal}: “{request}”"]
    lines += [f"• {f.reason}" for f in record.findings if f.status == "fail"][:6]
    if link:
        lines.append(link)
    return headline, lines


# ---- channels ------------------------------------------------------------------------

@dataclass
class Channel:
    """Somewhere alerts go. ``on`` picks which events it wants."""

    name: str
    on: tuple[str, ...] = EVENTS

    def __post_init__(self) -> None:
        bad = sorted(set(self.on) - set(EVENTS))
        if bad:
            raise ValueError(f"channel {self.name}: unknown events {bad}; choose from {EVENTS}")

    def send(self, headline: str, lines: list[str], payload: dict[str, Any]) -> None:
        raise NotImplementedError


def _slack_escape(text: str) -> str:
    """Slack treats &, < and > as markup; agent-written text must not become links or mentions."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


@dataclass
class SlackChannel(Channel):
    """A Slack incoming webhook (https://api.slack.com/messaging/webhooks)."""

    url: str = ""
    allow_http: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        _http_allowed(self.url, self.allow_http)

    def send(self, headline: str, lines: list[str], payload: dict[str, Any]) -> None:
        text = "*" + _slack_escape(headline) + "*\n" + "\n".join(_slack_escape(x) for x in lines)
        _post_json(self.url, {"text": text, "unfurl_links": False, "unfurl_media": False})


@dataclass
class WebhookChannel(Channel):
    """Any HTTPS endpoint. Each POST is signed, so the receiver can tell it came from here.

    ``X-Segurai-Signature: t=<unix time>,v1=<hex HMAC-SHA256 of "<time>.<body>">``
    with the shared ``secret``. Receivers should reject old timestamps.
    """

    url: str = ""
    secret: str = ""
    allow_http: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        _http_allowed(self.url, self.allow_http)
        if len(self.secret) < 16:
            raise ValueError(f"channel {self.name}: a webhook needs a secret of at least 16 characters")

    def send(self, headline: str, lines: list[str], payload: dict[str, Any]) -> None:
        body = {"headline": headline, "lines": lines, **payload}
        timestamp = str(int(time.time()))
        raw = json.dumps(body).encode("utf-8")
        signature = hmac.new(self.secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        _post_json(self.url, body, headers={"X-Segurai-Signature": f"t={timestamp},v1={signature}"})


@dataclass
class EmailChannel(Channel):
    """Email through an SMTP server, with TLS unless told otherwise."""

    host: str = ""
    port: int = 587
    sender: str = ""
    to: tuple[str, ...] = ()
    username: str | None = None
    password: str | None = None
    security: str = "starttls"          # starttls | tls | none (none only for a local relay)

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.host or not self.sender or not self.to:
            raise ValueError(f"channel {self.name}: email needs host, sender and at least one recipient")
        if self.security not in ("starttls", "tls", "none"):
            raise ValueError(f"channel {self.name}: security must be starttls, tls or none")
        if self.security == "none" and self.host not in ("127.0.0.1", "localhost"):
            raise ValueError(f"channel {self.name}: unencrypted SMTP is only allowed to a local relay")

    def send(self, headline: str, lines: list[str], payload: dict[str, Any]) -> None:
        message = EmailMessage()
        message["Subject"] = "[Segurai] " + headline.replace("\n", " ")[:180]
        message["From"] = self.sender
        message["To"] = ", ".join(self.to)
        message.set_content("\n".join([headline, "", *lines]))
        try:
            if self.security == "tls":
                smtp: smtplib.SMTP = smtplib.SMTP_SSL(self.host, self.port, timeout=15,
                                                      context=ssl.create_default_context())
            else:
                smtp = smtplib.SMTP(self.host, self.port, timeout=15)
            with smtp:
                if self.security == "starttls":
                    smtp.starttls(context=ssl.create_default_context())
                if self.username:
                    smtp.login(self.username, self.password or "")
                smtp.send_message(message)
        except (OSError, smtplib.SMTPException) as exc:
            raise AlertError(f"email via {self.host} failed: {exc}") from exc


# ---- the worker ------------------------------------------------------------------------

@dataclass
class AlertWorker:
    """Finds what's worth telling, queues it once, and delivers it with retries."""

    store: Store
    channels: list[Channel]
    public_url: str = ""                       # for links into the dashboard
    verifier: Any = None                       # checks checkpoint signatures during the audit
    audit_every: timedelta = timedelta(minutes=5)
    poll_seconds: float = 2.0
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)
    _last_audit: float = field(default=0.0, repr=False)

    def _link(self, session_id: str) -> str | None:
        if not self.public_url:
            return None
        return f"{self.public_url.rstrip('/')}/sessions/{urllib.parse.quote(session_id, safe='')}"

    # One pass: everything the worker does, in order. Tests call this directly.
    def run_once(self) -> dict[str, int]:
        queued = self._queue_new_actions()
        if time.monotonic() - self._last_audit >= self.audit_every.total_seconds():
            self._last_audit = time.monotonic()
            queued += self._queue_tamper()
        sent, failed = self._deliver_due()
        return {"queued": queued, "sent": sent, "failed": failed}

    def _wanted(self, event: str) -> list[Channel]:
        return [c for c in self.channels if event in c.on]

    def _queue_new_actions(self) -> int:
        queued = 0
        cursor = self.store.alert_cursor()
        for position, record in self.store.actions_after(cursor, limit=500):
            cursor = position
            if record.allowed:
                continue
            event = "blocked" if record.blocked else "violation"
            channels = self._wanted(event)
            if not channels:
                continue
            session = self.store.get_session(record.session_id)
            principal = session.principal if session else record.actor
            request = session.request if session else "(request unknown)"
            headline, lines = format_action(event, record, principal, request, self._link(record.session_id))
            payload = {"event": event, "action_id": record.action_id, "session_id": record.session_id,
                       "actor": record.actor, "operation": record.operation, "resource": record.resource,
                       "scale": record.scale, "principal": principal}
            for channel in channels:
                queued += self.store.queue_alert(event, record.action_id, channel.name,
                                                 {"headline": headline, "lines": lines, "payload": payload})
        self.store.set_alert_cursor(cursor)
        return queued

    def _queue_tamper(self) -> int:
        channels = self._wanted("tamper")
        if not channels:
            return 0
        report = self.store.audit(self.verifier)
        if report.ok:
            return 0
        problems = sorted(str(p) for p in report.problems)
        ref = "tamper_" + hashlib.sha256("\n".join(problems).encode()).hexdigest()[:16]
        headline = f"Tampering detected: {len(problems)} record(s) changed after they were written"
        lines = [f"• {p}" for p in problems[:8]]
        if self.public_url:
            lines.append(f"{self.public_url.rstrip('/')}/audit")
        return sum(self.store.queue_alert("tamper", ref, c.name,
                                          {"headline": headline, "lines": lines,
                                           "payload": {"event": "tamper", "problems": problems[:50]}})
                   for c in channels)

    def _deliver_due(self) -> tuple[int, int]:
        by_name = {c.name: c for c in self.channels}
        sent = failed = 0
        for alert in self.store.due_alerts(limit=50):
            # Several servers may share one database: claim each alert just
            # before sending it, so exactly one of them does.
            if not self.store.claim_alert(alert["id"], alert["next_attempt_at"], CLAIM_LEASE):
                continue
            channel = by_name.get(alert["channel"])
            if channel is None:          # the channel was removed from the configuration
                self.store.finish_alert(alert["id"], error="channel no longer configured", give_up=True)
                continue
            body = alert["body"]
            try:
                channel.send(body["headline"], body["lines"], body.get("payload", {}))
            except Exception as exc:     # any failure is retried; a bug must not kill the worker
                failed += 1
                attempts = alert["attempts"] + 1
                give_up = attempts >= MAX_ATTEMPTS
                delay = min(30 * 2 ** (attempts - 1), 3600)
                self.store.finish_alert(alert["id"], error=str(exc)[:500], give_up=give_up,
                                        retry_in=timedelta(seconds=delay))
                _log.warning("alert %s via %s failed (attempt %d): %s", alert["id"], channel.name,
                             attempts, exc)
                continue
            sent += 1
            self.store.finish_alert(alert["id"])
        return sent, failed

    # ---- running in the background ---------------------------------------------------

    def start(self) -> "AlertWorker":
        if self._thread is not None:
            return self
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="segurai-alerts", daemon=True)
        self._thread.start()
        return self

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
            self._thread = None

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                _log.exception("alert worker pass failed; trying again shortly")
            self._stop.wait(self.poll_seconds)


def channels_for(event: str, channels: Iterable[Channel]) -> list[str]:
    return [c.name for c in channels if event in c.on]
