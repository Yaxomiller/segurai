"""Revocation: stop a request's agents now, whatever their warrants still allow.

A warrant is valid until it expires. Most of the time that is right - it is
short. But sometimes a person sees an agent doing something odd, or a request
was a mistake, and an hour is too long to wait. Revoking says: from now on,
nothing under this request may act.

    segurai revoke ses_7a1e98629d674cde --reason "wrong customer list" --by sarah@acme.example

or the "Revoke this request" button on the request's dashboard page. One
warrant can be revoked instead of the whole request (``warrant_id``); that
stops it and every hop delegated from it, and leaves the rest alone.

What it does, immediately:

  * the gateway refuses every later request whose chain includes a revoked
    warrant - in enforce AND observe mode, since this is a person's explicit
    "stop" - and records each attempt, so "it kept trying" is on the record;
  * no new direct (fast-path) token is handed out under it;
  * requests held for approval under it are denied, and an approved one not
    yet sent is never sent.

What it can't do: call back a direct token already handed out (the system
honours it until it expires, which is why those are short and never carry
anything a rule could stop), or reach an agent that acts without the gateway.
Revocation is checked where Segurai stands in the path. The revocation itself
- who, when, why - is in the tamper-evident log and the evidence pack.
"""

from __future__ import annotations

import uuid
from typing import Any

from .collector.store import Store
from .models import Warrant, utcnow

__all__ = ["revoke", "revocation_for", "RevocationError"]


class RevocationError(ValueError):
    """A revocation that can't be made: no such request, or no reason given."""


def revocation_for(store: Store, chain: list[Warrant]) -> dict[str, Any] | None:
    """The revocation that stops this chain, if any: of its request, or of any warrant in it."""
    if not chain:
        return None
    return store.revocation_for(chain[-1].session_id, [w.warrant_id for w in chain])


def revoke(store: Store, session_id: str, *, by: str, reason: str, warrant_id: str | None = None,
           how: str = "dashboard") -> dict[str, Any]:
    """Revoke a whole request, or one warrant and everything delegated from it."""
    from .approvals import Approval, amend_action

    if store.get_session(session_id) is None:
        raise RevocationError(f"there is no request {session_id}")
    reason = (reason or "").strip()
    if not reason:
        raise RevocationError("say why: the reason is kept with the revocation")
    if not (by or "").strip():
        raise RevocationError("say who is revoking it")
    if warrant_id is not None:
        warrant = store.get_warrant(warrant_id)
        if warrant is None or warrant.session_id != session_id:
            raise RevocationError(f"{warrant_id} is not a warrant of {session_id}")
    if store.revocation_for(session_id, [warrant_id] if warrant_id else []) is not None and warrant_id is None:
        raise RevocationError("this request is already revoked")
    now = utcnow()
    row = {"revocation_id": f"rev_{uuid.uuid4().hex[:16]}", "session_id": session_id, "warrant_id": warrant_id,
           "revoked_by": by.strip().lower(), "reason": reason[:1000], "at": now.isoformat(), "how": how}
    store.put_revocation(row)

    # Held requests under it are answered now, rather than left to wait.
    for held in store.approvals(session_id=session_id, states=("pending", "approved"), limit=1000):
        if warrant_id is not None:
            record = store.get_action(held["action_id"])
            try:
                chain = store.chain_to(record.warrant_id) if record else []
            except ValueError:
                chain = []
            if warrant_id not in {w.warrant_id for w in chain}:
                continue
        if held["state"] == "pending":
            changes = {"state": "denied", "decided_by": row["revoked_by"], "decided_at": now.isoformat(),
                       "note": f"revoked: {row['reason']}"}
        else:
            changes = {"state": "failed", "finished_at": now.isoformat(),
                       "error": f"the request was revoked by {row['revoked_by']}"}
        with store._tx():
            changed = store.transition_approval(held["approval_id"], (held["state"],), changes)
            if changed is not None:
                amend_action(store, Approval.from_row(changed))
    return row
