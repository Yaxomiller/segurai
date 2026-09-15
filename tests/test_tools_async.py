"""ActionSpec, @warrant.tool, async agents, delegate() and listener safety."""

import asyncio
from contextlib import contextmanager
from dataclasses import replace

import pytest

import warrant
from warrant import ActionSpec, Scope, arg, count

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


def _session():
    return warrant.session(principal="sarah@company.com", request="clean up", scope=GRANTED)


# ---- ActionSpec ---------------------------------------------------------

def test_spec_fills_templates_and_rules():
    spec = ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True)
    a = spec.resolve({"table": "opportunities", "ids": [1, 2, 3]})
    assert (a.operation, a.resource, a.scale, a.irreversible) == ("delete", "crm.opportunities", 3, True)


def test_arg_rule_with_default():
    spec = ActionSpec("read", "crm.leads", scale=arg("limit", 1))
    assert spec.resolve({}).scale == 1
    assert spec.resolve({"limit": 20}).scale == 20


@pytest.mark.parametrize("spec, arguments, message", [
    (ActionSpec("delete", "crm.{table}"), {}, "KeyError"),
    (ActionSpec("delete", "crm.x", scale=count("ids")), {"ids": None}, "TypeError"),
    (ActionSpec("delete", "crm.x", scale=arg("n")), {"n": -5}, "zero or more"),
    (ActionSpec("delete", "crm.x", scale=arg("n")), {"n": True}, "whole number"),
    (ActionSpec("", "crm.x"), {}, "operation"),
])
def test_spec_errors_are_explained(spec, arguments, message):
    with pytest.raises(warrant.ActionSpecError, match=message):
        spec.resolve(arguments)


# ---- @warrant.tool ------------------------------------------------------

calls: list = []


@warrant.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"), irreversible=True))
def delete_records(table: str, ids: list, dry_run: bool = False):
    calls.append((table, len(ids)))
    return len(ids)


def test_tool_records_the_call_and_still_runs_in_observe_mode():
    calls.clear()
    with _session() as s:
        assert delete_records("opportunities", ids=list(range(400))) == 400
        (rec,) = s.actions()
    assert (rec.operation, rec.resource, rec.scale) == ("delete", "crm.opportunities", 400)
    assert rec.allowed is False and "exceeds limit 50" in rec.violation
    assert rec.detail["tool"] == "delete_records"
    assert calls == [("opportunities", 400)]


def test_tool_body_never_runs_when_blocked_in_enforce_mode():
    calls.clear()
    warrant.configure(mode=warrant.Mode.ENFORCE)
    with _session() as s:
        with pytest.raises(warrant.ViolationError):
            delete_records("opportunities", list(range(400)))
        assert len(s.violations()) == 1
    assert calls == []


def test_a_call_that_cannot_be_described_is_a_violation():
    @warrant.tool(ActionSpec("delete", "crm.{table}"))
    def purge(**kwargs):
        return "done"

    with _session() as s:
        purge(schema="x")  # no 'table' argument, so the resource is unknown
        (rec,) = s.actions()
    assert rec.allowed is False and "could not map tool call" in rec.violation
    assert rec.resource == "tool.purge"


def test_async_tool():
    @warrant.tool(ActionSpec("read", "crm.{table}"))
    async def fetch(table):
        return table

    async def main():
        with _session() as s:
            assert await fetch("leads") == "leads"
            return s.actions()

    (rec,) = asyncio.run(main())
    assert rec.allowed and rec.resource == "crm.leads"


# ---- async agents -------------------------------------------------------

def test_async_agent_actions_are_credited_to_the_agent():
    """Regression: the hop used to end before the coroutine ever ran."""
    @warrant.agent("async_agent", scope=Scope.of(operations=["read"]))
    async def async_agent():
        await asyncio.sleep(0)
        return warrant.act("read", "crm.opportunities")

    async def main():
        with _session() as s:
            return await async_agent(), s.chain()

    rec, chain = asyncio.run(main())
    assert rec.actor == "async_agent"
    assert [w.holder for w in chain] == ["entrypoint", "async_agent"]


def test_concurrent_async_agents_keep_their_own_warrants():
    @warrant.agent("a")
    async def a():
        await asyncio.sleep(0.01)
        return warrant.act("read", "crm.a")

    @warrant.agent("b")
    async def b():
        await asyncio.sleep(0)
        return warrant.act("read", "crm.b")

    async def main():
        with _session():
            return await asyncio.gather(a(), b())

    ra, rb = asyncio.run(main())
    assert (ra.actor, rb.actor) == ("a", "b")


def test_generator_agents_are_refused_clearly():
    with pytest.raises(TypeError, match="generator"):
        @warrant.agent("streamer")
        def streamer():
            yield 1


# ---- delegate() across a boundary ---------------------------------------

def test_delegate_with_an_imported_parent_continues_the_chain():
    with _session():
        token = warrant.export_warrant()
    # e.g. a worker process that received the token with a queue message
    parent = warrant.import_warrant(token)
    with warrant.delegate("worker", parent=parent):
        rec = warrant.act("read", "crm.leads")
    assert rec.actor == "worker"
    chain = warrant._runtime.store.chain_to(rec.warrant_id)
    assert [w.holder for w in chain] == ["entrypoint", "worker"]


def test_delegate_refuses_a_tampered_parent():
    with _session():
        token = warrant.export_warrant()
    forged = replace(warrant.import_warrant(token),
                     scope=Scope.of(operations=["delete"], targets=["*"]))
    with pytest.raises(warrant.ChainError, match="invalid signature"):
        with warrant.delegate("worker", parent=forged):
            pass


# ---- listeners ----------------------------------------------------------

class Recorder(warrant.Listener):
    def __init__(self):
        self.events = []

    @contextmanager
    def agent_scope(self, w):
        self.events.append(("enter", w.holder))
        yield
        self.events.append(("exit", w.holder))

    def on_action(self, record, w):
        self.events.append(("action", record.operation))


def test_listener_sees_hops_and_actions_in_order():
    recorder = Recorder()
    warrant.add_listener(recorder)

    @warrant.agent("crm_agent")
    def crm_agent():
        warrant.act("read", "crm.x")

    with _session():
        crm_agent()
    assert recorder.events == [("enter", "crm_agent"), ("action", "read"), ("exit", "crm_agent")]


class Broken(warrant.Listener):
    def agent_scope(self, w):
        raise RuntimeError("listener bug")

    def on_action(self, record, w):
        raise RuntimeError("listener bug")


def test_a_broken_listener_never_breaks_the_agent(caplog):
    warrant.add_listener(Broken())

    @warrant.agent("crm_agent")
    def crm_agent():
        return warrant.act("read", "crm.x")

    with _session():
        assert crm_agent().allowed
    assert "listener" in caplog.text


def test_errors_from_the_agent_itself_still_propagate():
    warrant.add_listener(Recorder())

    @warrant.agent("crm_agent")
    def crm_agent():
        raise KeyError("boom")

    with _session():
        with pytest.raises(KeyError):
            crm_agent()
