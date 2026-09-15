from dataclasses import replace
from datetime import timedelta

import pytest

from warrant import Authority, ChainError, Scope, verify_chain
from warrant.models import utcnow


@pytest.fixture
def auth():
    return Authority()


@pytest.fixture
def root(auth):
    return auth.issue_root(
        session_id="ses_test",
        principal="sarah@company.com",
        scope=Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50),
    )


def test_issued_warrant_verifies(auth, root):
    auth.verify(root)  # must not raise
    assert root.depth == 0 and root.parent_id is None


def test_unsigned_warrant_rejected(auth, root):
    naked = replace(root, signature=None)
    with pytest.raises(ChainError, match="unsigned"):
        auth.verify(naked)


def test_tampering_with_scope_is_detected(auth, root):
    widened = replace(root, scope=Scope.of(operations=["read", "delete", "purge"],
                                           targets=["*"], max_scale=None))
    with pytest.raises(ChainError, match="invalid signature"):
        auth.verify(widened)


def test_tampering_with_parent_link_is_detected(auth, root):
    reparented = replace(root, parent_id="wrt_somethingelse")
    with pytest.raises(ChainError, match="invalid signature"):
        auth.verify(reparented)


def test_foreign_key_cannot_verify(root):
    stranger = Authority()
    with pytest.raises(ChainError, match="invalid signature"):
        stranger.verify(root)


def test_attenuate_narrows(auth, root):
    child = auth.attenuate(
        root, holder="crm_agent",
        scope=Scope.of(operations=["read"], targets=["crm.opportunities"], max_scale=10),
    )
    auth.verify(child)
    assert child.parent_id == root.warrant_id
    assert child.depth == 1
    assert child.root_principal == root.root_principal


def test_attenuate_refuses_to_widen(auth, root):
    with pytest.raises(ChainError, match="would widen authority"):
        auth.attenuate(
            root, holder="rogue",
            scope=Scope.of(operations=["read", "delete", "purge"], targets=["*"]),
        )


def test_attenuate_defaults_to_parent_scope(auth, root):
    child = auth.attenuate(root, holder="assistant")
    assert child.scope == root.scope


def test_child_inherits_constraints_without_restating_them(auth):
    parent = auth.issue_root(
        session_id="s", principal="p",
        scope=Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50,
                       constraints=["no active customers"]),
    )
    # The child says only what it narrows and never mentions constraints.
    child = auth.attenuate(
        parent, holder="crm_agent",
        scope=Scope.of(operations=["read"], targets=["crm.opportunities"]),
    )
    assert "no active customers" in child.scope.constraints
    assert child.scope.max_scale == 50          # inherited, not widened to None
    assert child.scope.operations == frozenset({"read"})


def test_child_may_add_its_own_constraints(auth, root):
    child = auth.attenuate(
        root, holder="crm_agent",
        scope=Scope.of(operations=["read"], targets=["crm.*"],
                       constraints=["dry run only"]),
    )
    assert "dry run only" in child.scope.constraints


def test_inheritance_still_refuses_a_genuine_widening(auth):
    parent = auth.issue_root(
        session_id="s", principal="p",
        scope=Scope.of(operations=["read"], targets=["crm.*"], max_scale=10),
    )
    with pytest.raises(ChainError, match="would widen authority"):
        auth.attenuate(parent, holder="rogue",
                       scope=Scope.of(operations=["read"], targets=["crm.*"], max_scale=999))


def test_child_cannot_outlive_parent(auth, root):
    child = auth.attenuate(root, holder="assistant", ttl=timedelta(days=30))
    assert child.expires_at <= root.expires_at


def test_expired_parent_cannot_delegate(auth):
    past = utcnow() - timedelta(hours=2)
    stale = auth.issue_root(
        session_id="ses_x", principal="p", scope=Scope.of(operations=["read"], targets=["a"]),
        ttl=timedelta(minutes=1), now=past,
    )
    with pytest.raises(ChainError, match="expired"):
        auth.attenuate(stale, holder="late")


class TestChainVerification:
    def _chain(self, auth, root):
        a = auth.attenuate(root, holder="assistant")
        b = auth.attenuate(a, holder="crm_agent",
                           scope=Scope.of(operations=["read"], targets=["crm.opportunities"],
                                          max_scale=10))
        return [root, a, b]

    def test_valid_chain_passes(self, auth, root):
        verify_chain(self._chain(auth, root), auth)

    def test_empty_chain_rejected(self, auth):
        with pytest.raises(ChainError, match="empty chain"):
            verify_chain([], auth)

    def test_chain_must_start_at_root(self, auth, root):
        chain = self._chain(auth, root)
        with pytest.raises(ChainError, match="does not start at a root"):
            verify_chain(chain[1:], auth)

    def test_broken_link_detected(self, auth, root):
        chain = self._chain(auth, root)
        other = auth.issue_root(session_id="ses_test", principal="sarah@company.com",
                                scope=root.scope)
        with pytest.raises(ChainError, match="broken link"):
            verify_chain([other, chain[2]], auth)

    def test_reordering_detected(self, auth, root):
        chain = self._chain(auth, root)
        with pytest.raises(ChainError):
            verify_chain([chain[0], chain[2], chain[1]], auth)

    def test_expired_chain_rejected_unless_allowed(self, auth):
        past = utcnow() - timedelta(hours=5)
        r = auth.issue_root(session_id="s", principal="p",
                            scope=Scope.of(operations=["read"], targets=["a"]),
                            ttl=timedelta(minutes=1), now=past)
        with pytest.raises(ChainError, match="expired"):
            verify_chain([r], auth)
        verify_chain([r], auth, allow_expired=True)  # audit path
