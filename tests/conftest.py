"""Shared test setup."""

import pytest

import warrant


@pytest.fixture(autouse=True)
def _isolated_runtime():
    """Every test starts clean: in-memory store, fresh key, OBSERVE mode, no listeners.

    The runtime is process-wide, so without this a test that switches to
    ENFORCE mode or adds a listener would silently change the tests after it.
    """
    warrant.configure(store=":memory:", authority=warrant.Authority(), mode=warrant.Mode.OBSERVE)
    warrant._runtime.listeners.clear()
    yield
    warrant._runtime.listeners.clear()
