"""The tamper-evident log (milestone M7).

Signatures already make it impossible to alter a *warrant* without detection.
But the record of what agents actually DID is ordinary database rows: someone
with write access could change a scale from 400 to 4, or delete the row
altogether, and nothing would show. A log an engineer can quietly edit is not
evidence, and "audit" is not an honest word for it.

This module is the fix. Every record written - session, warrant, action,
verdict - also appends one entry to a **hash chain**:

    seq  kind     ref_id              payload_hash  prev_hash   entry_hash
    ---  -------  ------------------  ------------  ---------   ----------
      1  session  ses_5d1dff8d...     a91f...       000000...   4c7b...
      2  warrant  wrt_7a075223...     77de...       4c7b...     e011...
      3  action   act_3f22fd11...     b3c0...       e011...      91aa...   <- head

Each entry's hash covers its own contents AND the previous entry's hash, so
the newest hash (the "head") depends on every entry that came before it.
That gives three guarantees:

  * **Edit a row** and its payload hash no longer matches the entry -> caught.
  * **Delete a row** and its entry still stands, pointing at nothing -> caught.
  * **Remove or reorder entries** and the chain of hashes stops lining up -> caught.

One gap remains: someone with the database file and enough patience could
rebuild the *whole* chain to be internally consistent again. **Checkpoints**
close it. A checkpoint is the head hash at a point in time, signed with a key
the database does not contain. Rebuilding the chain is then not enough - the
forger would also have to forge a signature. Checkpoints are what make the
log evidence rather than bookkeeping.

For a stronger guarantee still, a checkpoint can be published somewhere
outside the organisation (a transparency log such as Rekor, or simply mailed
to an auditor): then not even someone holding the signing key can rewrite
history that was already witnessed. That is a later milestone; the hook for
it is that a checkpoint is a short, self-contained string.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Mapping

__all__ = ["GENESIS", "LedgerEntry", "Checkpoint", "AuditProblem", "AuditReport",
           "canonical_bytes", "payload_hash", "entry_hash", "row_payload"]

#: What the first entry's "previous hash" is: no entry came before it.
GENESIS = "0" * 64

#: Tables whose rows are evidence and therefore logged. Raw OpenTelemetry
#: spans are deliberately not: they are the raw INPUT, and the sessions,
#: warrants and actions rebuilt from them are logged instead.
LOGGED_KINDS = ("session", "warrant", "action", "verdict", "policy")


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Deterministic bytes for a record: sorted keys, no optional whitespace.

    A hash is over exact bytes, so the same record must always serialise to
    the same bytes, whatever order the columns came back in.
    """
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def payload_hash(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def entry_hash(seq: int, prev_hash: str, kind: str, ref_id: str, body_hash: str,
               at: str) -> str:
    """The hash of one entry, which covers the entry before it.

    Everything that identifies the entry is included - its position, its
    record, and the whole history behind it - so no field can be changed on
    its own.
    """
    material = canonical_bytes({
        "seq": seq, "prev_hash": prev_hash, "kind": kind,
        "ref_id": ref_id, "payload_hash": body_hash, "at": at,
    })
    return hashlib.sha256(material).hexdigest()


#: Columns added to a logged table AFTER the log existed. Rows written before a
#: column existed were hashed without it, so the rule is: a later column is part
#: of a row's hash only when it holds a value. An old row (NULL there) hashes
#: exactly as it did when it was written; a new row with a value is covered.
LATER_COLUMNS = frozenset({"holder_key", "identity_json"})

#: Columns the database adds for its own bookkeeping (PostgreSQL's insertion
#: order). They are not part of the record, so they are never hashed.
HIDDEN_COLUMNS = frozenset({"ord"})


def row_payload(mapping: Mapping[str, Any]) -> dict[str, Any]:
    """A database row as plain JSON-ready values.

    Hashing works on exactly what is STORED, not on the objects in memory.
    That matters: a caller's detail may contain a date, which is stored as
    text, so hashing the in-memory object and hashing the row back would
    disagree. Taking the stored values on both sides makes the comparison
    symmetric by construction.
    """
    payload: dict[str, Any] = {}
    for key, value in mapping.items():
        if key in HIDDEN_COLUMNS or (key in LATER_COLUMNS and value is None):
            continue
        if isinstance(value, (bytes, bytearray, memoryview)):
            payload[key] = base64.b64encode(bytes(value)).decode("ascii")
        else:
            payload[key] = value
    return payload


@dataclass(frozen=True)
class LedgerEntry:
    """One link in the chain."""

    seq: int
    at: str
    kind: str
    ref_id: str
    payload_hash: str
    prev_hash: str
    entry_hash: str

    def recomputed_hash(self) -> str:
        return entry_hash(self.seq, self.prev_hash, self.kind, self.ref_id,
                          self.payload_hash, self.at)


@dataclass(frozen=True)
class Checkpoint:
    """The head of the chain at a moment, signed with a key held outside the database."""

    seq: int
    head: str
    created_at: datetime
    key_id: str | None = None
    signature: bytes | None = None

    def signing_bytes(self) -> bytes:
        return canonical_bytes({"seq": self.seq, "head": self.head,
                                "created_at": self.created_at.isoformat()})

    def to_text(self) -> str:
        """A short self-contained string, for mailing to an auditor or publishing."""
        signature = base64.b64encode(self.signature or b"").decode("ascii")
        return (f"segurai-checkpoint seq={self.seq} head={self.head} "
                f"at={self.created_at.isoformat()} key={self.key_id or 'unsigned'} "
                f"sig={signature}")

    @staticmethod
    def from_text(line: str) -> "Checkpoint":
        """Read a line written by :meth:`to_text`. Raises ValueError if it isn't one."""
        parts = line.strip().split(" ")
        if not parts or parts[0] != "segurai-checkpoint":
            raise ValueError("not a segurai checkpoint line")
        fields = dict(p.split("=", 1) for p in parts[1:] if "=" in p)
        missing = {"seq", "head", "at", "key", "sig"} - set(fields)
        if missing:
            raise ValueError(f"checkpoint line is missing {sorted(missing)}")
        if len(fields["head"]) != 64 or any(c not in "0123456789abcdef" for c in fields["head"]):
            raise ValueError("checkpoint head must be 64 hex characters")
        return Checkpoint(seq=int(fields["seq"]), head=fields["head"],
                          created_at=datetime.fromisoformat(fields["at"]),
                          key_id=None if fields["key"] == "unsigned" else fields["key"],
                          signature=base64.b64decode(fields["sig"], validate=True) or None)


@dataclass(frozen=True)
class AuditProblem:
    """One thing wrong with the log, in plain language."""

    kind: str          # chain | row | checkpoint
    detail: str
    seq: int | None = None
    ref_id: str | None = None

    def __str__(self) -> str:
        where = f" at entry {self.seq}" if self.seq is not None else ""
        what = f" ({self.ref_id})" if self.ref_id else ""
        return f"{self.kind}{where}{what}: {self.detail}"


@dataclass
class AuditReport:
    """What an audit of the log found."""

    entries: int = 0
    head: str = GENESIS
    verified_to: int = 0                               # last entry that checked out
    rows_checked: int = 0
    rows_unlogged: int = 0                             # rows older than the log itself
    amendments: int = 0                                # records written more than once
    checkpoints: int = 0
    checkpoints_verified: int = 0
    signatures_checked: bool = False
    witnessed: int = 0                                 # checkpoints held OUTSIDE the database
    witnessed_verified: int = 0
    problems: list[AuditProblem] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok, "entries": self.entries, "head": self.head,
            "verified_to": self.verified_to, "rows_checked": self.rows_checked,
            "rows_unlogged": self.rows_unlogged, "amendments": self.amendments,
            "checkpoints": self.checkpoints, "checkpoints_verified": self.checkpoints_verified,
            "witnessed": self.witnessed, "witnessed_verified": self.witnessed_verified,
            "signatures_checked": self.signatures_checked,
            "problems": [
                {"kind": p.kind, "seq": p.seq, "ref_id": p.ref_id, "detail": p.detail}
                for p in self.problems
            ],
        }

    def to_text(self) -> str:
        lines = [
            "Tamper-evident log",
            "",
            f"  entries        : {self.entries}",
            f"  head           : {self.head[:16]}...",
            f"  verified to    : entry {self.verified_to}",
            f"  records checked: {self.rows_checked}"
            + (f" ({self.amendments} written more than once)" if self.amendments else ""),
        ]
        if self.rows_unlogged:
            lines.append(f"  not in the log : {self.rows_unlogged} record(s) written before "
                         f"the log existed")
        if self.checkpoints:
            how = "signatures verified" if self.signatures_checked else "signatures NOT checked"
            lines.append(f"  checkpoints    : {self.checkpoints_verified}/{self.checkpoints} "
                         f"({how})")
        else:
            lines.append("  checkpoints    : none - without one, a determined editor with "
                         "database access could rebuild the whole chain")
        if self.witnessed:
            lines.append(f"  witnessed      : {self.witnessed_verified}/{self.witnessed} checkpoint(s) "
                         f"held outside the database still match")
        lines.append("")
        if self.ok:
            lines.append("No sign of tampering: every record hashes to its entry, and every "
                         "entry links to the one before it.")
        else:
            lines.append(f"TAMPERING DETECTED - {len(self.problems)} problem(s):")
            lines += [f"  ! {p}" for p in self.problems]
        return "\n".join(lines)
