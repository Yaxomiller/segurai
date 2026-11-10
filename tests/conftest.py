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


#: Set to a postgresql:// URL to run every test that uses the runtime's store
#: on PostgreSQL instead of an in-memory SQLite database. The database is
#: wiped before each test, so point it at one that exists only for this.
TEST_DATABASE = os.environ.get("SEGURAI_TEST_DATABASE", ":memory:")


def _wipe_postgres(url):
    import psycopg

    with psycopg.connect(url, autocommit=True) as conn:
        conn.execute("DROP SCHEMA IF EXISTS public CASCADE")
        conn.execute("CREATE SCHEMA public")


@pytest.fixture(autouse=True)
def _isolated_runtime():
    """Every test starts clean: empty store, fresh key, OBSERVE mode, no listeners, no rules.

    The runtime is process-wide, so without this a test that switches to
    ENFORCE mode or adds a listener would silently change the tests after it.
    """
    if TEST_DATABASE != ":memory:":
        _wipe_postgres(TEST_DATABASE)
    segurai.configure(store=TEST_DATABASE, authority=segurai.Authority(), mode=segurai.Mode.OBSERVE,
                      policy=segurai.Policy())
    store = segurai._runtime.store
    segurai._runtime.listeners.clear()
    segurai._runtime.intent = None
    yield
    segurai._runtime.listeners.clear()
    if TEST_DATABASE != ":memory:":
        store.close()                     # PostgreSQL connections are a limited resource
