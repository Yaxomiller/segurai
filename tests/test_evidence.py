"""Evidence packs: checkable from the pack alone, and any change is caught."""

import io
import json
import zipfile

import pytest

import segurai
from segurai import Scope
from segurai.cli import main as cli_main
from segurai.evidence import EvidenceError, build_pack, verify_pack

GRANTED = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)


def _incident():
    with segurai.session(principal="sarah@acme.example", request="clean up", scope=GRANTED) as s:
        with segurai.delegate("crm_agent"):
            segurai.act("read", "crm.accounts")
            segurai.act("delete", "crm.opportunities", scale=400, irreversible=True)
    return s.session_id


def _rewrite(pack: bytes, name: str, change) -> bytes:
    src = zipfile.ZipFile(io.BytesIO(pack))
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w") as dst:
        for info in src.infolist():
            data = src.read(info)
            dst.writestr(info.filename, change(data) if info.filename == name else data)
    return out.getvalue()


def test_an_honest_pack_verifies_against_the_organisations_key():
    sid = _incident()
    authority = segurai._runtime.authority
    pack = build_pack(segurai._runtime.store, sid, authority)
    report = verify_pack(pack, authority.public_key_pem())
    assert report.ok, report.problems
    assert report.key_trusted and report.manifest_signed
    assert report.warrants == 2 and report.actions == 2 and report.entries >= 5


def test_a_record_changed_before_export_is_caught():
    sid = _incident()
    store = segurai._runtime.store
    store._conn.execute("UPDATE actions SET scale = 4 WHERE scale = 400")
    store._conn.commit()
    report = verify_pack(build_pack(store, sid, segurai._runtime.authority))
    assert any("changed after it was written" in p for p in report.problems)


def test_editing_the_pack_after_export_is_caught():
    sid = _incident()
    pack = build_pack(segurai._runtime.store, sid, segurai._runtime.authority)
    edited = _rewrite(pack, "records.json", lambda d: d.replace(b'"scale": 400', b'"scale": 4'))
    report = verify_pack(edited)
    assert any("records.json was changed" in p for p in report.problems)
    assert any("does not match its log entry" in p for p in report.problems)


def test_a_pack_forged_with_another_key_fails_against_the_real_one():
    sid = _incident()
    real = segurai._runtime.authority
    forged = build_pack(segurai._runtime.store, sid, segurai.Authority())
    assert not verify_pack(forged, real.public_key_pem()).ok


def test_junk_is_refused():
    with pytest.raises(EvidenceError):
        verify_pack(b"not a zip")


def test_the_command_line_builds_and_checks_a_pack(tmp_path, capsys):
    db = tmp_path / "w.db"
    segurai.configure(store=str(db))
    sid = _incident()
    out = tmp_path / "pack.zip"
    assert cli_main(["--db", str(db), "evidence", sid, "--out", str(out)]) == 0
    capsys.readouterr()
    assert cli_main(["--key", str(tmp_path / "w.pub"), "evidence-verify", str(out)]) == 0
    assert "VERIFIED" in capsys.readouterr().out
    manifest = json.loads(zipfile.ZipFile(out).read("manifest.json"))
    assert manifest["session_id"] == sid and "report.html" in manifest["files"]
