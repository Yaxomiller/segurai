"""Alerts: queued once, delivered with retries, never sent twice, never lost."""

import hashlib
import hmac
import json
import threading
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

import segurai
from segurai import Scope
from segurai.alerts import AlertWorker, EmailChannel, SlackChannel, WebhookChannel

GRANTED = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)


class Receiver:
    """A local HTTPS-stand-in that records posts, and can be told to fail."""

    def __init__(self):
        self.posts, self.fail = [], False
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.posts.append({"headers": dict(self.headers), "body": body})
                self.send_response(500 if outer.fail else 200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/hook"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def receiver():
    r = Receiver()
    yield r
    r.close()


def _worker(channels, **kw):
    store = segurai._runtime.store
    worker = AlertWorker(store=store, channels=channels, public_url="https://segurai.acme.example",
                         verifier=segurai._runtime.authority, **kw)
    worker.run_once()               # a new deployment starts its cursor at the end
    return worker


def _incident(request="clean up our old sales records"):
    with segurai.session(principal="sarah@acme.example", request=request, scope=GRANTED) as s:
        segurai.act("read", "crm.accounts")
        segurai.act("delete", "crm.opportunities", scale=400, irreversible=True)
    return s


def test_a_violation_reaches_slack_once(receiver):
    worker = _worker([SlackChannel(name="security", url=receiver.url)])
    s = _incident()
    assert worker.run_once() == {"queued": 1, "sent": 1, "failed": 0}
    assert worker.run_once() == {"queued": 0, "sent": 0, "failed": 0}       # never twice
    (post,) = receiver.posts
    text = json.loads(post["body"])["text"]
    assert "Went beyond the request: crm_agent" not in text                 # no agent here: the root acted
    assert "delete 400 records in crm.opportunities" in text
    assert "sarah@acme.example" in text and "scale 400 exceeds limit 50" in text
    assert f"https://segurai.acme.example/sessions/{s.session_id}" in text
    (alert,) = segurai._runtime.store.alerts()
    assert alert["sent_at"] and alert["kind"] == "violation"


def test_blocked_actions_are_their_own_event(receiver):
    worker = _worker([SlackChannel(name="only-blocked", url=receiver.url, on=("blocked",))])
    _incident()                                                              # observe mode: a violation
    segurai.configure(mode=segurai.Mode.ENFORCE)
    with segurai.session(principal="p", request="r", scope=GRANTED):
        with pytest.raises(segurai.ViolationError):
            segurai.act("delete", "crm.accounts")
    assert worker.run_once()["sent"] == 1
    assert "Stopped: entrypoint tried to delete" in json.loads(receiver.posts[0]["body"])["text"]


def test_history_from_before_the_worker_started_is_not_replayed(receiver):
    _incident()
    worker = _worker([SlackChannel(name="security", url=receiver.url)])
    assert worker.run_once()["queued"] == 0 and receiver.posts == []


def test_failed_deliveries_are_retried_with_backoff_then_given_up(receiver):
    worker = _worker([SlackChannel(name="security", url=receiver.url)])
    receiver.fail = True
    _incident()
    assert worker.run_once()["failed"] == 1
    store = segurai._runtime.store
    (alert,) = store.alerts()
    assert alert["attempts"] == 1 and "answered 500" in alert["last_error"] and not alert["failed_at"]
    assert worker.run_once()["failed"] == 0                                   # not due yet: backing off

    for _ in range(10):                                                      # make every retry due now
        store._conn.execute("UPDATE alerts SET next_attempt_at = '2000-01-01'")
        store._conn.commit()
        worker.run_once()
    (alert,) = store.alerts()
    assert alert["attempts"] == 8 and alert["failed_at"]                      # given up after 8 tries

    receiver.fail = False
    worker.run_once()
    assert store.alerts()[0]["sent_at"] is None                               # a given-up alert stays given up


def test_a_restart_neither_loses_nor_repeats(receiver):
    first = _worker([SlackChannel(name="security", url=receiver.url)])
    receiver.fail = True
    _incident()
    first.run_once()
    receiver.fail = False
    segurai._runtime.store._conn.execute("UPDATE alerts SET next_attempt_at = '2000-01-01'")
    segurai._runtime.store._conn.commit()
    second = AlertWorker(store=segurai._runtime.store, channels=first.channels)   # "after a restart"
    assert second.run_once() == {"queued": 0, "sent": 1, "failed": 0}


def test_tampering_is_alerted_once_per_distinct_problem(receiver):
    worker = _worker([SlackChannel(name="security", url=receiver.url, on=("tamper",))],
                     audit_every=timedelta(0))
    _incident()
    store = segurai._runtime.store
    store._conn.execute("UPDATE actions SET scale = 4 WHERE scale = 400")
    store._conn.commit()
    assert worker.run_once()["sent"] == 1
    assert worker.run_once()["sent"] == 0
    assert "Tampering detected: 1 record(s)" in json.loads(receiver.posts[0]["body"])["text"]


def test_agent_written_text_cannot_ping_everyone_in_slack(receiver):
    worker = _worker([SlackChannel(name="security", url=receiver.url)])
    _incident(request="clean up <!channel> and <https://evil.example|click here>")
    worker.run_once()
    text = json.loads(receiver.posts[0]["body"])["text"]
    assert "<!channel>" not in text and "&lt;!channel&gt;" in text
    assert "<https://evil.example" not in text


def test_webhooks_are_signed(receiver):
    secret = "a-shared-secret-of-some-length"
    worker = _worker([WebhookChannel(name="siem", url=receiver.url, secret=secret)])
    s = _incident()
    worker.run_once()
    (post,) = receiver.posts
    stamp, signature = post["headers"]["X-Segurai-Signature"].split(",")
    timestamp = stamp.split("=")[1]
    expected = hmac.new(secret.encode(), timestamp.encode() + b"." + post["body"], hashlib.sha256).hexdigest()
    assert signature == "v1=" + expected
    payload = json.loads(post["body"])
    assert payload["event"] == "violation" and payload["session_id"] == s.session_id


def test_email_goes_through_smtp_with_tls(monkeypatch):
    sent = []

    class FakeSMTP:
        def __init__(self, host, port, timeout):
            self.calls = [("connect", host, port)]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            sent.append(self.calls)

        def starttls(self, context):
            self.calls.append(("starttls",))

        def login(self, user, password):
            self.calls.append(("login", user))

        def send_message(self, message):
            self.calls.append(("send", message["Subject"], message["To"], message.get_content()))

    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    worker = _worker([EmailChannel(name="mail", host="smtp.acme.example", sender="segurai@acme.example",
                                   to=("security@acme.example",), username="segurai", password="pw")])
    _incident()
    assert worker.run_once()["sent"] == 1
    (calls,) = sent
    assert calls[0] == ("connect", "smtp.acme.example", 587) and calls[1] == ("starttls",)
    subject, to, content = calls[3][1:]
    assert subject.startswith("[Segurai] Went beyond the request") and to == "security@acme.example"
    assert "scale 400 exceeds limit 50" in content


@pytest.mark.parametrize("make, message", [
    (lambda: SlackChannel(name="s", url="http://hooks.slack.com/x"), "must be https"),
    (lambda: WebhookChannel(name="w", url="https://siem.example/x", secret="short"), "at least 16"),
    (lambda: SlackChannel(name="s", url="https://hooks.slack.com/x", on=("everything",)), "unknown events"),
    (lambda: EmailChannel(name="e", host="smtp.example", sender="a@b", to=()), "recipient"),
    (lambda: EmailChannel(name="e", host="smtp.example", sender="a@b", to=("c@d",), security="none"),
     "local relay"),
])
def test_unsafe_channels_are_refused(make, message):
    with pytest.raises(ValueError, match=message):
        make()


def test_the_background_worker_starts_and_stops(receiver):
    worker = _worker([SlackChannel(name="security", url=receiver.url)], poll_seconds=0.05)
    worker.start()
    try:
        _incident()
        for _ in range(100):
            if receiver.posts:
                break
            threading.Event().wait(0.05)
        assert len(receiver.posts) == 1
    finally:
        worker.stop()


class _Slow:
    """A channel that takes a moment to send, so two servers overlap."""

    def __init__(self):
        self.name, self.sent, self._lock = "security", [], threading.Lock()

    def send(self, headline, lines, payload):
        import time

        time.sleep(0.1)
        with self._lock:
            self.sent.append(headline)


def test_servers_sharing_a_database_send_each_alert_once(monkeypatch):
    """Both servers see the alert due; only the one that claims it sends it."""
    store = segurai._runtime.store
    channel = _Slow()
    workers = [AlertWorker(store=store, channels=[channel], public_url="https://segurai.acme.example",
                           verifier=segurai._runtime.authority) for _ in range(2)]
    store.queue_alert("violation", "act_1", "security", {"headline": "one alert", "lines": [], "payload": {}})

    real, both_read = store.due_alerts, threading.Barrier(2)

    def due_for_both(limit=50):
        rows = real(limit=limit)
        both_read.wait(timeout=5)              # neither claims until both have read it
        return rows

    monkeypatch.setattr(store, "due_alerts", due_for_both)
    threads = [threading.Thread(target=w._deliver_due) for w in workers]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)
    assert channel.sent == ["one alert"]
    assert store.alerts()[0]["sent_at"] is not None
