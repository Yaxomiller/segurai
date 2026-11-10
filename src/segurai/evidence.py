"""Evidence packs: one file an auditor can check without trusting anyone.

    segurai evidence ses_7a1e98629d674cde --out incident.zip
    segurai evidence-verify incident.zip --key acme-org.pub

A pack holds everything about one request - who asked (and how that was
proven), every permission in the chain, every action and finding, the AI
reviews, the organisation's rules that applied - plus what's needed to check
it all from the pack alone:

    records.json      the stored rows, exactly as stored
    ledger.json       the stretch of the tamper-evident log from this request's
                      first record up to a signed checkpoint
    checkpoint.json   that checkpoint: the log's state, signed
    public_key.pem    the organisation's public key
    witness.txt       checkpoint lines held outside the database, when known
    report.html       the same request as a page a person can read
    manifest.json     every file's SHA-256, signed with the organisation's key
                      when the pack was made by its holder
    README.txt        what all this is, in plain words

:func:`verify_pack` re-derives everything: each file's hash, every warrant's
signature and narrowing, each record's hash against its log entry, every log
entry's hash and link, and the checkpoint's signature over the last one. If a
single byte of a record had been changed - in the database before export, or
in the pack after - the hashes stop lining up.

The auditor should check the public key itself against one published by the
organisation (``--key``): a pack is only as trustworthy as the key it is
checked with, and a forger could ship a pack with their own key inside.
"""

from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization

from ._version import __version__
from .authority import Authority, ChainError, verify_chain
from .collector.ledger import Checkpoint, LedgerEntry, payload_hash
from .collector.store import Store
from .models import Warrant, utcnow

__all__ = ["build_pack", "verify_pack", "PackReport", "EvidenceError"]

_FILES = ("records.json", "ledger.json", "checkpoint.json", "public_key.pem", "report.html", "README.txt")
#: Refuse to unpack anything bigger than this (a zip bomb defence).
_MAX_MEMBER = 200 * 1024 * 1024


class EvidenceError(Exception):
    """A pack that can't be built, or can't be read at all."""


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _json(data: Any) -> bytes:
    return json.dumps(data, indent=2, sort_keys=True, default=str).encode("utf-8")


_README = """SEGURAI EVIDENCE PACK
=====================

This file describes one request made to AI agents: who asked, what each agent
was allowed to do, what each one actually did, and what was found.

It is built so that it can be checked WITHOUT trusting whoever handed it to you:

  * Every permission ("warrant") is signed. The first is signed with the
    organisation's key; each later one with the key of the agent that handed
    the work on, and each can only be narrower than the one before.
  * Every record is also an entry in a tamper-evident log, where each entry's
    hash covers the one before it. ledger.json holds the stretch of that log
    from this request's first record up to a checkpoint - the log's state at a
    moment, signed with the organisation's key.
  * manifest.json lists the SHA-256 hash of every other file here.

To check it, with Segurai installed (pip install segurai):

    segurai evidence-verify THIS_FILE.zip --key <the organisation's public key>

Get the organisation's public key from the organisation itself, not only from
this pack: public_key.pem is included for convenience, but a forger could put
their own key in a pack. The key's id is in manifest.json ("key_id").

report.html shows the same request as a page a person can read.
"""


def build_pack(store: Store, session_id: str, authority: Authority, *,
               witnessed: list[Checkpoint] | None = None, report_html: str | None = None,
               checkpoint: bool = True) -> bytes:
    """Build an evidence pack for one request and return it as zip bytes.

    ``authority`` holds the organisation's key: with the private key the
    manifest is signed, and (``checkpoint=True``) a fresh checkpoint is made
    when none yet covers this request's records. With only the public key the
    pack can still be built if a checkpoint already covers them.
    """
    session = store.get_session(session_id)
    if session is None:
        raise EvidenceError(f"no session {session_id}")

    records: dict[str, list[dict[str, Any]]] = {}
    refs: list[tuple[str, str]] = []
    queries = [
        ("session", "SELECT * FROM sessions WHERE session_id = ?", "session_id"),
        ("warrant", "SELECT * FROM warrants WHERE session_id = ? ORDER BY depth, issued_at", "warrant_id"),
        ("action", "SELECT * FROM actions WHERE session_id = ? ORDER BY at, rowid", "action_id"),
        ("verdict", "SELECT * FROM verdicts WHERE session_id = ?", "action_id"),
    ]
    from .collector.ledger import row_payload

    for kind, sql, key in queries:
        rows = [row_payload(dict(r)) for r in store._read(sql, (session_id,))]
        records[kind] = rows
        refs += [(kind, r[key]) for r in rows]
    # The rule versions any finding in this request names.
    versions = sorted({f["clause"].split(":")[0].removeprefix("policy ").strip()
                       for a in records["action"] for f in json.loads(a.get("findings_json") or "[]")
                       if f.get("check") == "policy" and f.get("clause", "").startswith("policy ")})
    records["policy"] = [row_payload(dict(r)) for v in versions
                         for r in store._read("SELECT * FROM policies WHERE version = ?", (v,))]
    refs += [("policy", r["version"]) for r in records["policy"]]

    # The log entries for these records: the latest entry for each.
    wanted = set(refs)
    latest: dict[tuple[str, str], LedgerEntry] = {}
    for e in store.ledger_entries():
        if (e.kind, e.ref_id) in wanted:
            latest[(e.kind, e.ref_id)] = e
    missing = wanted - set(latest)
    if missing:
        raise EvidenceError(f"{len(missing)} record(s) of this request are not in the log "
                            f"(written before it existed?): {sorted(missing)[:3]}")
    first = min(e.seq for e in latest.values())
    last_needed = max(e.seq for e in latest.values())

    covering = [c for c in store.checkpoints() if c.seq >= last_needed]
    if not covering:
        if not (checkpoint and authority.can_sign):
            raise EvidenceError("no checkpoint covers this request yet, and no private key was given "
                                "to make one")
        covering = [store.put_checkpoint(authority)]
    anchor = covering[0]
    segment = [e for e in store.ledger_entries(since=first - 1) if e.seq <= anchor.seq]

    files: dict[str, bytes] = {
        "records.json": _json(records),
        "ledger.json": _json([e.__dict__ for e in segment]),
        "checkpoint.json": _json({"seq": anchor.seq, "head": anchor.head,
                                  "created_at": anchor.created_at.isoformat(), "key_id": anchor.key_id,
                                  "signature": anchor.to_text().split("sig=", 1)[1]}),
        "public_key.pem": authority.public_key_pem(),
        "report.html": (report_html or "<!doctype html><title>Segurai evidence</title>"
                        "<p>No report was rendered for this pack.</p>").encode("utf-8"),
        "README.txt": _README.encode("utf-8"),
    }
    if witnessed:
        files["witness.txt"] = ("\n".join(c.to_text() for c in witnessed) + "\n").encode("utf-8")

    manifest = {
        "format": "segurai-evidence-1", "generator": f"segurai {__version__}",
        "generated_at": utcnow().isoformat(), "session_id": session_id,
        "principal": session.principal, "identity_verified": bool(session.identity),
        "key_id": authority.key_id, "checkpoint_seq": anchor.seq,
        "files": {name: _sha256(data) for name, data in sorted(files.items())},
    }
    manifest_bytes = _json(manifest)
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as pack:
        for name, data in sorted(files.items()):
            pack.writestr(name, data)
        pack.writestr("manifest.json", manifest_bytes)
        if authority.can_sign:
            pack.writestr("manifest.sig", authority.sign_bytes(manifest_bytes).hex())
    return out.getvalue()


@dataclass
class PackReport:
    """What checking a pack found."""

    session_id: str = ""
    key_id: str = ""
    key_trusted: bool = False                  # checked against a key the auditor supplied
    manifest_signed: bool = False
    warrants: int = 0
    actions: int = 0
    entries: int = 0
    checkpoint_seq: int = 0
    witnessed: int = 0
    problems: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.problems

    def to_text(self) -> str:
        lines = [f"Evidence pack for {self.session_id}",
                 f"  signed by key      : {self.key_id}" + (" (matches the key you supplied)"
                                                           if self.key_trusted else " (NOT checked against "
                                                           "a key you supplied - pass --key)"),
                 f"  manifest signature : {'valid' if self.manifest_signed else 'none'}",
                 f"  warrants checked   : {self.warrants}",
                 f"  actions checked    : {self.actions}",
                 f"  log entries checked: {self.entries}, up to signed checkpoint {self.checkpoint_seq}"]
        if self.witnessed:
            lines.append(f"  witnessed lines    : {self.witnessed}")
        lines += [f"  note: {n}" for n in self.notes]
        lines.append("")
        if self.ok:
            lines.append("VERIFIED: every record matches its log entry, every log entry links to the "
                         "next, and the organisation's key signed the result.")
        else:
            lines.append(f"NOT VERIFIED - {len(self.problems)} problem(s):")
            lines += [f"  ! {p}" for p in self.problems]
        return "\n".join(lines)


def verify_pack(data: bytes | str | Path, trusted_key: bytes | None = None) -> PackReport:
    """Check an evidence pack from the pack alone. ``trusted_key`` is a PEM public key."""
    report = PackReport()
    if isinstance(data, (str, Path)):
        data = Path(data).read_bytes()
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        raise EvidenceError(f"not a zip file: {exc}") from exc
    files: dict[str, bytes] = {}
    for info in archive.infolist():
        if info.file_size > _MAX_MEMBER or "/" in info.filename or "\\" in info.filename:
            raise EvidenceError(f"refusing to read {info.filename!r}")
        files[info.filename] = archive.read(info)

    # 1. The manifest, its signature, and every file's hash.
    if "manifest.json" not in files:
        raise EvidenceError("no manifest.json - not a Segurai evidence pack")
    manifest = json.loads(files["manifest.json"])
    report.session_id = manifest.get("session_id", "")
    report.key_id = manifest.get("key_id", "")
    try:
        pack_key = Authority.from_public_pem(files["public_key.pem"])
    except (KeyError, ValueError) as exc:
        raise EvidenceError(f"the pack's public key can't be read: {exc}") from exc
    authority = pack_key
    if trusted_key is not None:
        trusted = Authority.from_public_pem(trusted_key)
        if trusted.key_id != pack_key.key_id:
            report.problems.append(f"the pack was made with key {pack_key.key_id}, not the key you "
                                   f"supplied ({trusted.key_id})")
        authority = trusted
        report.key_trusted = trusted.key_id == pack_key.key_id
    if pack_key.key_id != report.key_id:
        report.problems.append("the manifest names a different key from the one in the pack")
    if "manifest.sig" in files:
        try:
            authority.verify_bytes(bytes.fromhex(files["manifest.sig"].decode()), files["manifest.json"])
            report.manifest_signed = True
        except (ChainError, ValueError):
            report.problems.append("the manifest's signature does not check out")
    for name, digest in manifest.get("files", {}).items():
        if name not in files:
            report.problems.append(f"{name} is listed in the manifest but missing")
        elif _sha256(files[name]) != digest:
            report.problems.append(f"{name} was changed after the pack was made")
    for name in set(files) - set(manifest.get("files", {})) - {"manifest.json", "manifest.sig"}:
        report.problems.append(f"{name} is in the pack but not in the manifest")
    if any(name not in files for name in _FILES):
        report.problems.append("the pack is missing files it should have")
        return report

    records = json.loads(files["records.json"])
    ledger = [LedgerEntry(**e) for e in json.loads(files["ledger.json"])]
    cp_data = json.loads(files["checkpoint.json"])

    # 2. The chain of permissions: signatures, links and narrowing, hop by hop.
    warrants = {}
    for row in records.get("warrant", []):
        w = _warrant_from_row(row)
        warrants[w.warrant_id] = w
    report.warrants = len(warrants)
    for leaf in [w for w in warrants.values() if w.warrant_id not in {x.parent_id for x in warrants.values()}]:
        chain, cursor = [], leaf
        while cursor is not None:
            chain.append(cursor)
            cursor = warrants.get(cursor.parent_id) if cursor.parent_id else None
        chain.reverse()
        try:
            verify_chain(chain, authority, allow_expired=True)
        except ChainError as exc:
            report.problems.append(f"permission chain to {leaf.holder}: {exc}")

    # 3. Each record against its log entry.
    keys = {"session": "session_id", "warrant": "warrant_id", "action": "action_id",
            "verdict": "action_id", "policy": "version"}
    latest: dict[tuple[str, str], LedgerEntry] = {}
    for e in ledger:
        latest[(e.kind, e.ref_id)] = e
    for kind, rows in records.items():
        for row in rows:
            entry = latest.get((kind, row[keys[kind]]))
            if entry is None:
                report.problems.append(f"{kind} {row[keys[kind]]} has no entry in the log")
            elif payload_hash(row) != entry.payload_hash:
                report.problems.append(f"{kind} {row[keys[kind]]} does not match its log entry - "
                                       f"it was changed after it was written")
    report.actions = len(records.get("action", []))

    # 4. The log itself: each entry's hash and link, ending at the checkpoint.
    report.entries = len(ledger)
    for i, e in enumerate(ledger):
        if e.entry_hash != e.recomputed_hash():
            report.problems.append(f"log entry {e.seq} does not match its own hash")
        if i and (e.seq != ledger[i - 1].seq + 1 or e.prev_hash != ledger[i - 1].entry_hash):
            report.problems.append(f"log entry {e.seq} does not link to the entry before it")
    checkpoint = Checkpoint(seq=int(cp_data["seq"]), head=cp_data["head"],
                            created_at=datetime.fromisoformat(cp_data["created_at"]),
                            key_id=cp_data.get("key_id"),
                            signature=__import__("base64").b64decode(cp_data["signature"]))
    report.checkpoint_seq = checkpoint.seq
    if not ledger or ledger[-1].seq != checkpoint.seq or ledger[-1].entry_hash != checkpoint.head:
        report.problems.append("the log in the pack does not end at the signed checkpoint")
    try:
        authority.verify_bytes(checkpoint.signature or b"", checkpoint.signing_bytes())
    except ChainError:
        report.problems.append("the checkpoint's signature does not check out")

    # 5. Witnessed lines, when the pack carries them.
    if "witness.txt" in files:
        hash_at = {e.seq: e.entry_hash for e in ledger}
        for line in files["witness.txt"].decode("utf-8").splitlines():
            if not line.strip():
                continue
            report.witnessed += 1
            try:
                witnessed = Checkpoint.from_text(line)
                authority.verify_bytes(witnessed.signature or b"", witnessed.signing_bytes())
            except (ValueError, ChainError):
                report.problems.append("a witnessed checkpoint line is unreadable or wrongly signed")
                continue
            if witnessed.seq in hash_at and hash_at[witnessed.seq] != witnessed.head:
                report.problems.append(f"the log disagrees with the checkpoint witnessed at entry "
                                       f"{witnessed.seq}")
    if not report.key_trusted:
        report.notes.append("checked with the key inside the pack; supply the organisation's own "
                            "public key (--key) to rule out a forged pack")
    return report


def _warrant_from_row(row: dict[str, Any]) -> Warrant:
    import base64

    from .models import Scope

    return Warrant(
        warrant_id=row["warrant_id"], session_id=row["session_id"], root_principal=row["root_principal"],
        holder=row["holder"], scope=Scope.from_dict(json.loads(row["scope_json"])),
        issued_at=datetime.fromisoformat(row["issued_at"]), expires_at=datetime.fromisoformat(row["expires_at"]),
        parent_id=row.get("parent_id"), depth=int(row["depth"]), key_id=row.get("key_id"),
        signature=base64.b64decode(row["signature"]) if row.get("signature") else None,
        holder_key=base64.b64decode(row["holder_key"]) if row.get("holder_key") else None,
    )


def public_key_pem_of(authority: Authority) -> bytes:
    return authority.public_key.public_bytes(serialization.Encoding.PEM,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
