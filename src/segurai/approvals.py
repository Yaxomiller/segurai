"""Step-up approvals: an action that waits for a person's yes instead of being refused.

Some actions are fine, some are never fine, and some are fine *if a person
agrees*: a permanent change to 400 records, an email outside the company, a
payment above a threshold. Refusing those breaks legitimate work; allowing
them silently is what this whole project exists to stop. So the gateway
holds them:

    agent ──request──> gateway: "this needs a person's approval"
                          │  records the action (blocked, for now) and holds
                          │  EXACTLY this request: method, path, body
                          │  answers the agent 202, with an approval id
                          ▼
    a person opens the dashboard's Approvals page, sees who asked, what the
    agent wants to send, and why it was held - and approves or denies it
                          │
                          ▼
    gateway: sends the held request once, with the system's credential, and
    keeps the answer for the agent to collect (GET /_segurai/approvals/<id>)

Two things can hold a request:

  * an organisation rule with ``effect = "approve"`` (policy.py) - a written
    guardrail, such as "deleting more than 100 CRM records needs a second
    person". By default the person who made the request may NOT approve it
    themselves; that is the point of a second person.
  * with ``[gateway] step_up = true``: an action outside what this request's
    warrant allows, but inside what the person is allowed to do at all (the
    ceiling their session was issued under). The agent went beyond what was
    asked, not beyond what the person may do - so the person is asked. Here
    the requester may decide, since it is within their own authority.

What it never does: a deny rule, a limit rule, an action outside the
person's ceiling, or a request no route describes is refused outright, as
before. Approval can only release what a person is entitled to release.

The rules the code keeps:

  * What is approved is what runs. The held bytes are sent, not a retry the
    agent might change; the approval page shows those same bytes.
  * At most once. Approving moves the request to "approved"; the gateway's
    runner claims it ("running") under the log's lock before sending, so two
    servers, or a double click, can never send it twice. If the gateway dies
    mid-send, the request stays "running": better an honest "outcome
    unknown" than a second permanent delete.
  * An approval can't outlive the permission it extends: a held request
    expires at the end of the approval window or when the agent's warrant
    expires, whichever is first.
  * Rules are checked again just before sending. If the organisation's rules
    changed while the request waited, and now forbid it, it is not sent.
  * Everything is evidence: the held request, who decided, when, any note,
    and what the system answered are all in the tamper-evident log, and in
    the request's evidence pack.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime
from fnmatch import fnmatchcase
from typing import Any

from .collector.store import Store
from .models import ActionRecord, Finding, utcnow

__all__ = ["Approval", "Need", "ApprovalError", "STATES", "OPEN_STATES", "decide", "expire_due",
           "open_approval", "load", "STEP_UP_RULE"]

#: pending   waiting for a person
#: approved  a person said yes; the gateway will send it shortly
#: running   the gateway is sending it (or stopped while sending: outcome unknown)
#: done      sent; the system's answer is kept
#: failed    approved, but it could not be sent (rules changed, system unreachable...)
#: denied    a person said no
#: expired   nobody decided in time
STATES = ("pending", "approved", "running", "done", "failed", "denied", "expired")
OPEN_STATES = ("pending", "approved", "running")

#: The name a step-up hold goes by, where a rule's name would be.
STEP_UP_RULE = "outside the request, inside the person's ceiling"

#: The most of a held request's body, or of the system's answer, that is kept.
MAX_HELD_BODY = 1024 * 1024
MAX_RESULT_BODY = 1024 * 1024


class ApprovalError(Exception):
    """A decision that can't be made: not allowed, already decided, or expired."""


@dataclass(frozen=True)
class Need:
    """One reason a request is held, and who may release it."""

    rule: str                               # the rule's name, or STEP_UP_RULE
    reason: str                             # in plain words, for the approval page
    approvers: tuple[str, ...] = ()         # glob patterns over emails; empty = any dashboard admin
    requester: bool = False                 # may the person who asked decide?

    def allows(self, email: str, *, is_admin: bool, principal: str) -> bool:
        email = email.strip().lower()
        if email == principal.strip().lower():
            # Separation of duties: the person who asked decides only where
            # the rule says so - even if they are an admin.
            return self.requester
        if self.approvers:
            return any(fnmatchcase(email, p.lower()) for p in self.approvers)
        return is_admin

    def who(self, principal: str) -> str:
        """Who may decide, as a phrase: "any admin", "anyone matching *@acme.example"..."""
        if self.approvers:
            base = "anyone matching " + ", ".join(self.approvers)
        else:
            base = "a dashboard admin"
        if self.requester:
            return f"{principal}, or {base}"
        return base + f" (not {principal}, who asked)"

    def to_dict(self) -> dict[str, Any]:
        return {"rule": self.rule, "reason": self.reason, "approvers": list(self.approvers),
                "requester": self.requester}

    @staticmethod
    def from_dict(d: dict[str, Any]) -> "Need":
        return Need(rule=d["rule"], reason=d.get("reason", ""), approvers=tuple(d.get("approvers") or ()),
                    requester=bool(d.get("requester")))


@dataclass(frozen=True)
class Approval:
    """A held request and everything that has happened to it."""

    approval_id: str
    action_id: str
    session_id: str
    principal: str                          # who made the request
    actor: str                              # the agent that sent it
    upstream: str                           # which system it is for
    method: str
    path: str                               # within the upstream, e.g. /opportunities/bulk_delete
    query: str                              # the query string, without "?"
    headers: tuple[tuple[str, str], ...]    # what will be forwarded (never credentials)
    body: bytes
    needs: tuple[Need, ...]
    state: str
    created_at: datetime
    expires_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    note: str | None = None
    finished_at: datetime | None = None
    result_status: int | None = None
    result: dict[str, Any] | None = field(default=None, compare=False)
    error: str | None = None

    @property
    def target(self) -> str:
        return self.path + (f"?{self.query}" if self.query else "")

    @property
    def body_sha256(self) -> str:
        return hashlib.sha256(self.body).hexdigest()

    @property
    def is_open(self) -> bool:
        return self.state in OPEN_STATES

    def expired(self, now: datetime | None = None) -> bool:
        return self.state == "pending" and (now or utcnow()) >= self.expires_at

    def may_decide(self, email: str, *, is_admin: bool) -> bool:
        """Can this person approve or deny it? Every reason it is held must allow them."""
        return (self.state == "pending" and not self.expired()
                and all(n.allows(email, is_admin=is_admin, principal=self.principal) for n in self.needs))

    def who_decides(self) -> str:
        return "; and ".join(n.who(self.principal) for n in self.needs)

    def body_text(self, limit: int = 4000) -> str:
        """The body as a person can read it: pretty JSON when it is JSON."""
        if not self.body:
            return ""
        try:
            text = _readable(json.loads(self.body))
        except (ValueError, UnicodeDecodeError):
            text = self.body.decode("utf-8", "replace")
        return text if len(text) <= limit else text[:limit] + f"\n... ({len(text) - limit} more characters)"

    # ---- storage --------------------------------------------------------------------

    def to_row(self) -> dict[str, Any]:
        return {
            "approval_id": self.approval_id, "action_id": self.action_id, "session_id": self.session_id,
            "principal": self.principal, "actor": self.actor, "upstream": self.upstream,
            "method": self.method, "path": self.path, "query": self.query,
            "headers_json": json.dumps([list(h) for h in self.headers]),
            "body": self.body, "body_sha256": self.body_sha256,
            "needs_json": json.dumps([n.to_dict() for n in self.needs], sort_keys=True),
            "state": self.state, "created_at": self.created_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
            "decided_by": self.decided_by,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "note": self.note,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "result_status": self.result_status,
            "result_json": json.dumps(self.result, sort_keys=True) if self.result is not None else None,
            "error": self.error,
        }

    @staticmethod
    def from_row(row: dict[str, Any]) -> "Approval":
        def when(value: Any) -> datetime | None:
            return datetime.fromisoformat(value) if value else None

        return Approval(
            approval_id=row["approval_id"], action_id=row["action_id"], session_id=row["session_id"],
            principal=row["principal"], actor=row["actor"], upstream=row["upstream"],
            method=row["method"], path=row["path"], query=row["query"],
            headers=tuple((str(k), str(v)) for k, v in json.loads(row["headers_json"] or "[]")),
            body=bytes(row["body"]) if row["body"] is not None else b"",
            needs=tuple(Need.from_dict(n) for n in json.loads(row["needs_json"] or "[]")),
            state=row["state"], created_at=when(row["created_at"]), expires_at=when(row["expires_at"]),
            decided_by=row["decided_by"], decided_at=when(row["decided_at"]), note=row["note"],
            finished_at=when(row["finished_at"]), result_status=row["result_status"],
            result=json.loads(row["result_json"]) if row["result_json"] else None, error=row["error"],
        )

    def public(self) -> dict[str, Any]:
        """What the agent that sent it is told when it asks (never who else is involved)."""
        out: dict[str, Any] = {"approval_id": self.approval_id, "action_id": self.action_id,
                               "state": self.state, "expires_at": self.expires_at.isoformat()}
        if self.state in ("denied", "done", "failed", "approved", "running"):
            out["decided_at"] = self.decided_at.isoformat() if self.decided_at else None
        if self.state == "denied":
            out["note"] = self.note or ""
        if self.state == "failed":
            out["error"] = self.error or ""
        if self.state == "done" and self.result is not None:
            out["result"] = self.result
        return out


def _readable(value: Any, level: int = 0) -> str:
    """JSON laid out for a person: one key per line, but a list of plain values on one line."""
    pad = "  " * (level + 1)
    if isinstance(value, dict) and value:
        items = [f"{pad}{json.dumps(k, ensure_ascii=False)}: {_readable(v, level + 1)}" for k, v in value.items()]
        return "{\n" + ",\n".join(items) + "\n" + "  " * level + "}"
    if isinstance(value, list) and any(isinstance(v, (dict, list)) for v in value):
        return "[\n" + ",\n".join(pad + _readable(v, level + 1) for v in value) + "\n" + "  " * level + "]"
    return json.dumps(value, ensure_ascii=False)


def load(store: Store, approval_id: str) -> Approval | None:
    row = store.get_approval(approval_id)
    return Approval.from_row(row) if row else None


# ---- opening, deciding, expiring -----------------------------------------------------------

def open_approval(store: Store, record: ActionRecord, *, principal: str, upstream: str, method: str,
                  path: str, query: str, headers: list[tuple[str, str]], body: bytes,
                  needs: list[Need], expires_at: datetime, approval_id: str | None = None) -> Approval:
    """Hold a request. The caller has already stored ``record`` (blocked, pending)."""
    approval = Approval(
        approval_id=approval_id or f"apr_{uuid.uuid4().hex[:16]}", action_id=record.action_id,
        session_id=record.session_id, principal=principal, actor=record.actor, upstream=upstream,
        method=method, path=path, query=query, headers=tuple(headers), body=body, needs=tuple(needs),
        state="pending", created_at=utcnow(), expires_at=expires_at)
    store.put_approval(approval.to_row())
    return approval


def decide(store: Store, approval_id: str, *, email: str, is_admin: bool, approve: bool,
           note: str = "") -> Approval:
    """A person approves or denies a held request. Raises ApprovalError if they can't."""
    approval = load(store, approval_id)
    if approval is None:
        raise ApprovalError("there is no such request")
    if approval.state != "pending":
        raise ApprovalError(f"this request was already {approval.state}")
    if approval.expired():
        expire_due(store)
        raise ApprovalError("this request expired before anyone decided")
    if not approval.may_decide(email, is_admin=is_admin):
        raise ApprovalError(f"you can't decide this one: it needs {approval.who_decides()}")
    now = utcnow()
    note = (note or "").strip()[:1000]
    changes = {"state": "approved" if approve else "denied", "decided_by": email.strip().lower(),
               "decided_at": now.isoformat(), "note": note or None}
    with store._tx():                     # the decision and the action's record change together
        row = store.transition_approval(approval_id, ("pending",), changes, unexpired_at=now.isoformat())
        if row is None:
            raise ApprovalError("someone else decided this request a moment ago, or it just expired")
        decided = Approval.from_row(row)
        if not approve:
            amend_action(store, decided)
    return decided


def expire_due(store: Store, now: datetime | None = None) -> list[Approval]:
    """Move every pending request past its deadline to "expired". Returns those moved."""
    now = now or utcnow()
    moved = []
    for row in store.approvals(states=("pending",), limit=1000):
        if row["expires_at"] > now.isoformat():
            continue
        with store._tx():
            changed = store.transition_approval(row["approval_id"], ("pending",),
                                                {"state": "expired", "finished_at": now.isoformat()})
            if changed is not None:
                approval = Approval.from_row(changed)
                amend_action(store, approval)
                moved.append(approval)
    return moved


# ---- keeping the action's record in step ------------------------------------------------------

def amend_action(store: Store, approval: Approval) -> None:
    """Update the held action's record to say what happened. The log keeps every version."""
    record = store.get_action(approval.action_id)
    if record is None:
        return
    info = dict(record.detail.get("approval") or {})
    info.update({"id": approval.approval_id, "state": approval.state})
    if approval.decided_by:
        info["decided_by"] = approval.decided_by
        info["decided_at"] = approval.decided_at.isoformat() if approval.decided_at else None
    if approval.note:
        info["note"] = approval.note
    detail = {**record.detail, "approval": info}
    held = record.violation or "held for approval"
    if approval.state == "done":
        # A person released it: every reason it was held is now answered.
        findings = tuple(
            replace(f, status="approved", reason=f"{f.reason} - approved by {approval.decided_by}")
            if f.status == "fail" else f for f in record.findings)
        detail["upstream_status"] = approval.result_status
        store.put_action(replace(record, allowed=True, blocked=False, violation=None,
                                 findings=findings, detail=detail))
        return
    if approval.state == "denied":
        why = f" - denied by {approval.decided_by}" + (f": {approval.note}" if approval.note else "")
    elif approval.state == "expired":
        why = " - nobody approved it in time"
    elif approval.state == "failed":
        why = f" - approved by {approval.decided_by}, but not sent: {approval.error}"
    else:
        why = ""
    store.put_action(replace(record, violation=_strip_outcome(held) + why, detail=detail))


def _strip_outcome(violation: str) -> str:
    # A record is amended at most a couple of times; keep the original reason
    # and replace whatever outcome was appended before.
    for marker in (" - denied by ", " - nobody approved it in time", " - approved by "):
        if marker in violation:
            violation = violation.split(marker, 1)[0]
    return violation


def step_up_finding(principal: str, ceiling: str) -> Finding:
    """The finding that says a request was held because it went beyond what was asked."""
    return Finding("approval", "fail",
                   f"this goes beyond what the request asked for, but not beyond what {principal} may do "
                   f"(the {ceiling} ceiling), so {principal} is asked",
                   f"gateway step-up: {ceiling}")
