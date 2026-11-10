"""Shared test setup."""

import pytest

import segurai


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
