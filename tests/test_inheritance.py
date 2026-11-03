"""A declared child scope says only what it narrows; everything else inherits.

Regression for 2026-09-15: an agent declared with only ``operations`` used to
end up with no targets at all, so every action it took was flagged.
"""

import pytest

import segurai
from segurai import Scope

PARENT = Scope.of(
    operations=["read", "delete"],
    targets=["crm.*"],
    max_scale=50,
    irreversible_allowed=True,
    constraints=["no active customers"],
)


def test_unmentioned_targets_are_inherited():
    child = Scope.of(operations=["read"]).inherit_unspecified(PARENT)
    assert child.targets == frozenset({"crm.*"})
    assert child.operations == frozenset({"read"})


def test_unmentioned_operations_are_inherited():
    child = Scope.of(targets=["crm.leads"]).inherit_unspecified(PARENT)
    assert child.operations == frozenset({"read", "delete"})
    assert child.targets == frozenset({"crm.leads"})


def test_unmentioned_irreversible_and_scale_are_inherited():
    child = Scope.of(operations=["delete"]).inherit_unspecified(PARENT)
    assert child.irreversible_allowed is True
    assert child.max_scale == 50


def test_constraints_always_accumulate():
    child = Scope.of(constraints=["dry run only"]).inherit_unspecified(PARENT)
    assert child.constraints == ("no active customers", "dry run only")


def test_explicit_empty_targets_mean_none_not_inherit():
    child = Scope.of(operations=["read"], targets=[]).inherit_unspecified(PARENT)
    assert child.targets == frozenset()


def test_explicit_false_irreversible_narrows():
    child = Scope.of(irreversible_allowed=False).inherit_unspecified(PARENT)
    assert child.irreversible_allowed is False


def test_inherited_scope_passes_the_subset_check():
    child = Scope.of(operations=["read"]).inherit_unspecified(PARENT)
    ok, reason = child.is_subset_of(PARENT)
    assert ok, reason


def test_bookkeeping_does_not_affect_equality():
    built = Scope.of(operations=["read"], targets=["a"])
    direct = Scope(operations=frozenset({"read"}), targets=frozenset({"a"}))
    assert built == direct


def test_a_string_where_a_list_belongs_is_rejected():
    with pytest.raises(TypeError, match="did you mean"):
        Scope.of(operations="read")


def test_negative_max_scale_is_rejected():
    with pytest.raises(ValueError, match="zero or more"):
        Scope.of(max_scale=-1)


def test_agent_that_only_narrows_operations_keeps_parent_targets():
    segurai.configure(store=":memory:", authority=segurai.Authority())

    @segurai.agent("reader", scope=Scope.of(operations=["read"]))
    def reader():
        return segurai.act("read", "crm.opportunities")

    with segurai.session(principal="p", request="r", scope=PARENT):
        rec = reader()
        assert rec.allowed, rec.violation
