"""Shared test setup."""

import os
import sys

import pytest

import segurai


def pytest_runtest_logreport(report):
    """On GitHub Actions, turn each failure into an error annotation.

    Job logs need admin rights to download, but annotations are public, so
    a failure on a platform nobody has at hand can still be read exactly.
    """
    if os.environ.get("GITHUB_ACTIONS") != "true" or not report.failed:
        return
    text = "\n".join(report.longreprtext.splitlines()[-25:])
    data = text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    title = report.nodeid.replace("%", "%25").replace(",", "%2C").replace(":", "%3A")
    sys.__stdout__.write(f"\n::error title={title}::{data}\n")
    sys.__stdout__.flush()


@pytest.fixture(autouse=True)
def _isolated_runtime():
    """Every test starts clean: in-memory store, fresh key, OBSERVE mode, no listeners, no rules.

    The runtime is process-wide, so without this a test that switches to
    ENFORCE mode or adds a listener would silently change the tests after it.
    """
    segurai.configure(store=":memory:", authority=segurai.Authority(), mode=segurai.Mode.OBSERVE,
                      policy=segurai.Policy())
    segurai._runtime.listeners.clear()
    segurai._runtime.intent = None
    yield
    segurai._runtime.listeners.clear()
