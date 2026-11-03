import pytest

import segurai
from segurai import Scope
from segurai.context import NoWarrantError

GRANTED = Scope.of(
    operations=["read", "update", "delete"],
    targets=["crm.*"],
    max_scale=50,
)


@pytest.fixture(autouse=True)
def fresh_runtime():
    segurai.configure(store=":memory:", authority=segurai.Authority(),
                      mode=segurai.Mode.OBSERVE)
    yield


def _open():
    return segurai.session(
        principal="sarah@company.com",
        request="clean up our old sales records",
        scope=GRANTED,
    )


def test_act_outside_a_session_raises():
    with pytest.raises(NoWarrantError, match="no warrant in context"):
        segurai.act("read", "crm.opportunities")


def test_session_records_root_warrant():
    with _open() as s:
        assert s.root_warrant.depth == 0
        assert s.root_warrant.root_principal == "sarah@company.com"
        assert len(s.chain()) == 1


def test_permitted_action_is_recorded_as_allowed():
    with _open() as s:
        rec = segurai.act("read", "crm.opportunities", scale=5)
        assert rec.allowed and rec.violation is None
        assert len(s.actions()) == 1
        assert s.violations() == []


def test_violation_is_recorded_but_not_blocked_in_observe_mode():
    with _open() as s:
        rec = segurai.act("delete", "crm.opportunities", scale=400)
        assert rec.allowed is False
        assert "scale 400 exceeds limit 50" in rec.violation
        assert len(s.violations()) == 1


def test_violation_raises_in_enforce_mode():
    segurai.configure(mode=segurai.Mode.ENFORCE)
    with _open() as s:
        with pytest.raises(segurai.ViolationError, match="exceeds limit"):
            segurai.act("delete", "crm.opportunities", scale=400)
        # still recorded, even though it raised
        assert len(s.violations()) == 1


def test_agent_decorator_attenuates_and_attributes():
    @segurai.agent("crm_agent", scope=Scope.of(
        operations=["read"], targets=["crm.opportunities"], max_scale=10))
    def crm_agent():
        return segurai.act("read", "crm.opportunities", scale=3)

    with _open() as s:
        rec = crm_agent()
        assert rec.actor == "crm_agent"
        chain = s.chain()
        assert len(chain) == 2
        assert chain[1].holder == "crm_agent"
        assert chain[1].parent_id == chain[0].warrant_id


def test_agent_cannot_widen_its_own_scope():
    @segurai.agent("rogue", scope=Scope.of(operations=["read", "purge"], targets=["*"]))
    def rogue():
        pass

    with _open():
        with pytest.raises(segurai.ChainError, match="would widen authority"):
            rogue()


def test_child_scope_constrains_even_when_parent_would_allow():
    """The CRM agent is capped at 10 though Sarah granted 50."""
    @segurai.agent("crm_agent", scope=Scope.of(
        operations=["read", "delete"], targets=["crm.opportunities"], max_scale=10))
    def crm_agent():
        return segurai.act("delete", "crm.opportunities", scale=30)

    with _open():
        rec = crm_agent()
        assert rec.allowed is False
        assert "exceeds limit 10" in rec.violation


def test_nested_agents_build_a_three_hop_chain():
    @segurai.agent("crm_agent")
    def crm_agent():
        return segurai.act("read", "crm.opportunities")

    @segurai.agent("assistant")
    def assistant():
        return crm_agent()

    with _open() as s:
        assistant()
        chain = s.chain()
        assert [w.holder for w in chain] == ["entrypoint", "assistant", "crm_agent"]
        assert [w.depth for w in chain] == [0, 1, 2]


def test_verify_session_passes_for_an_honest_run():
    @segurai.agent("assistant")
    def assistant():
        segurai.act("read", "crm.opportunities")

    with _open() as s:
        assistant()
        assert segurai.verify_session(s.session_id) == []


def test_export_import_round_trip():
    with _open():
        token = segurai.export_warrant()
        restored = segurai.import_warrant(token)
        original = segurai.current_warrant()
        assert restored.warrant_id == original.warrant_id
        assert restored.scope == original.scope
        assert restored.signature == original.signature


def test_imported_warrant_still_verifies():
    with _open():
        token = segurai.export_warrant()
    restored = segurai.import_warrant(token)
    segurai._runtime.authority.verify(restored)  # must not raise


def test_agent_that_only_narrows_operations_can_still_act():
    """Regression: declaring only operations used to leave the agent no targets."""
    @segurai.agent("reader", scope=Scope.of(operations=["read"]))
    def reader():
        return segurai.act("read", "crm.opportunities")

    with _open():
        rec = reader()
        assert rec.allowed, rec.violation
