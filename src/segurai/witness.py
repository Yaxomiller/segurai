"""Witnesses: checkpoints published somewhere the database's owner can't take back.

A checkpoint signs the log's state with the organisation's key, which stops
anyone WITHOUT the key from rewriting history unnoticed. But whoever holds the
key - an administrator, or an attacker who stole it - could rewrite the log,
re-sign every checkpoint, and leave nothing to see.

Witnesses close that. Each checkpoint is also published OUTSIDE the
database, the moment it is made:

  * ``FileWitness`` appends one line per checkpoint to a file - put it on
    storage the Segurai server can write to but not rewrite: a different
    machine, an append-only mount, or object storage with retention locks;
  * ``WebhookWitness`` posts each checkpoint to another system (a SIEM, a
    ticketing system, another team's service), signed so it can tell the
    post is genuine.

An audit given the witnessed lines (``segurai audit --witness FILE``) then
compares the log with what was witnessed. History rewritten after a
checkpoint went out no longer matches it, whoever did the rewriting.

:class:`CheckpointWorker` makes a checkpoint whenever the log has grown and
the interval has passed, publishes it to every witness, and retries any that
failed - a witness that is down for an hour receives that hour's checkpoints
when it comes back.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any, Iterable

from .alerts import _http_allowed, _post_json
from .collector.ledger import Checkpoint
from .collector.store import Store

__all__ = ["Witness", "FileWitness", "WebhookWitness", "CheckpointWorker", "read_witness_file"]

_log = logging.getLogger("segurai.witness")


class Witness:
    """Somewhere a checkpoint is published. ``publish`` raises on failure."""

    name: str = "witness"

    def publish(self, checkpoint: Checkpoint) -> None:
        raise NotImplementedError


@dataclass
class FileWitness(Witness):
    """Append each checkpoint as one line to a file, flushed to disk before returning."""

    path: Path
    name: str = "file"

    def __post_init__(self) -> None:
        self.path = Path(self.path)

    def publish(self, checkpoint: Checkpoint) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        line = checkpoint.to_text() + "\n"
        # O_APPEND: every write lands at the end, even with several writers.
        fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o640)
        try:
            os.write(fd, line.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)


@dataclass
class WebhookWitness(Witness):
    """Post each checkpoint to another system, HMAC-signed like alert webhooks."""

    url: str
    secret: str
    name: str = "webhook"
    allow_http: bool = False

    def __post_init__(self) -> None:
        _http_allowed(self.url, self.allow_http)
        if len(self.secret) < 16:
            raise ValueError(f"witness {self.name}: a webhook needs a secret of at least 16 characters")

    def publish(self, checkpoint: Checkpoint) -> None:
        body = {"checkpoint": checkpoint.to_text(), "seq": checkpoint.seq, "head": checkpoint.head,
                "created_at": checkpoint.created_at.isoformat(), "key_id": checkpoint.key_id}
        timestamp = str(int(time.time()))
        raw = json.dumps(body).encode("utf-8")
        signature = hmac.new(self.secret.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
        _post_json(self.url, body, headers={"X-Segurai-Signature": f"t={timestamp},v1={signature}"})


def read_witness_file(path: str | Path) -> tuple[list[Checkpoint], list[str]]:
    """Every checkpoint in a witness file, plus a note for each line that isn't one."""
    checkpoints, bad = [], []
    for number, line in enumerate(Path(path).read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            checkpoints.append(Checkpoint.from_text(line))
        except (ValueError, TypeError) as exc:
            bad.append(f"line {number}: {exc}")
    return checkpoints, bad


@dataclass
class CheckpointWorker:
    """Checkpoint the log on a schedule and publish every checkpoint to every witness."""

    store: Store
    authority: Any                                   # holds the organisation's private key
    witnesses: list[Witness]
    every: timedelta = timedelta(hours=1)
    poll_seconds: float = 30.0
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)
    _thread: threading.Thread | None = field(default=None, repr=False)

    def _published(self, witness: Witness) -> int:
        return int(self.store.get_state(f"witness.{witness.name}.seq", "0") or 0)

    def run_once(self, force: bool = False) -> dict[str, Any]:
        """Make a checkpoint if one is due, then catch every witness up. Returns what happened."""
        made = None
        seq, _ = self.store.ledger_head()
        latest = self.store.checkpoints()[-1:] or [None]
        last = latest[0]
        due = last is None or (seq > last.seq and (
            force or (time.time() - last.created_at.timestamp()) >= self.every.total_seconds()))
        if seq and due:
            made = self.store.put_checkpoint(self.authority)
        published: dict[str, int] = {}
        failures: dict[str, str] = {}
        for witness in self.witnesses:
            done = self._published(witness)
            for cp in (c for c in self.store.checkpoints() if c.seq > done):
                try:
                    witness.publish(cp)
                except Exception as exc:       # retried on the next pass, from the same checkpoint
                    failures[witness.name] = str(exc)[:300]
                    _log.warning("witness %s failed at checkpoint %d: %s", witness.name, cp.seq, exc)
                    break
                self.store.set_state(f"witness.{witness.name}.seq", str(cp.seq))
                published[witness.name] = published.get(witness.name, 0) + 1
        return {"checkpoint": made.seq if made else None, "published": published, "failures": failures}

    def start(self) -> "CheckpointWorker":
        if self._thread is None:
            self._stop.clear()
            self._thread = threading.Thread(target=self._loop, name="segurai-witness", daemon=True)
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
                _log.exception("checkpoint pass failed; trying again shortly")
            self._stop.wait(self.poll_seconds)


def witness_names(witnesses: Iterable[Witness]) -> list[str]:
    return [w.name for w in witnesses]


def _host(url: str) -> str:
    return urllib.parse.urlsplit(url).hostname or url
