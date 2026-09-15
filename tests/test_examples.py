"""Every example must keep running - examples are the first thing a new user tries."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("script, expected", [
    ("demo_multiagent.py", "scale 400 exceeds limit 50"),
    ("langgraph_demo.py", "Blocked by warrant"),
    ("mcp_demo.py", "crm_server"),
    ("otel_demo.py", "invoke_agent crm_agent"),
])
def test_example_runs(script, expected):
    result = subprocess.run(
        [sys.executable, str(ROOT / "examples" / script)],
        capture_output=True, cwd=ROOT, timeout=180,
        env=dict(os.environ, PYTHONIOENCODING="utf-8"),
    )
    out = result.stdout.decode("utf-8", "replace")
    assert result.returncode == 0, result.stderr.decode("utf-8", "replace")[-3000:]
    assert expected in out
