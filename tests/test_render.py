"""Output must never crash, whatever the terminal can display.

Regression for 2026-09-15: on Windows, the demo and ``segurai show`` raised
UnicodeEncodeError when stdout used a legacy code page (cp1252), which is what
happens when output is piped or redirected.
"""

import os
import subprocess
import sys
from pathlib import Path

import pytest

import segurai
from segurai import Scope
from segurai.collector.chain import render_session

ROOT = Path(__file__).resolve().parents[1]
LEGACY_CONSOLE = dict(os.environ, PYTHONIOENCODING="cp1252")


def _session(store=":memory:", request="clean up our old sales records"):
    segurai.configure(store=store, authority=segurai.Authority())

    @segurai.agent("crm_agent")
    def crm_agent():
        segurai.act("delete", "crm.opportunities", scale=400)

    granted = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)
    with segurai.session(principal="sarah@company.com", request=request, scope=granted) as s:
        crm_agent()
    return s.session_id


def test_ascii_charset_output_is_pure_ascii():
    sid = _session()
    out = render_session(segurai._runtime.store, sid, charset="ascii")
    out.encode("ascii")  # raises if a non-ASCII character slipped in
    assert "`- crm_agent" in out


def test_unicode_charset_draws_box_lines():
    sid = _session()
    out = render_session(segurai._runtime.store, sid, charset="unicode")
    assert "└─ crm_agent" in out


def test_unknown_charset_is_rejected():
    sid = _session()
    with pytest.raises(ValueError, match="charset"):
        render_session(segurai._runtime.store, sid, charset="emoji")


def test_demo_runs_on_a_legacy_code_page():
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "demo_multiagent.py")],
        capture_output=True, env=LEGACY_CONSOLE, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr.decode("cp1252", "replace")
    assert b"crm_agent" in result.stdout


def test_cli_show_survives_unprintable_request_text(tmp_path):
    sid = _session(store=str(tmp_path / "w.db"), request="nettoyer les données 旧记录")
    result = subprocess.run(
        [sys.executable, "-m", "segurai.cli", "--db", str(tmp_path / "w.db"), "show", sid],
        capture_output=True, env=LEGACY_CONSOLE, cwd=ROOT,
    )
    assert result.returncode == 0, result.stderr.decode("cp1252", "replace")
    assert b"crm_agent" in result.stdout
