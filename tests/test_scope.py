from warrant import Scope


def test_permits_happy_path():
    s = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)
    ok, reason = s.permits("delete", "crm.opportunities", scale=10)
    assert ok and reason is None


def test_permits_rejects_unknown_operation():
    s = Scope.of(operations=["read"], targets=["crm.*"])
    ok, reason = s.permits("delete", "crm.opportunities")
    assert not ok and "operation" in reason


def test_permits_rejects_uncovered_target():
    s = Scope.of(operations=["read"], targets=["crm.*"])
    ok, reason = s.permits("read", "billing.invoices")
    assert not ok and "target" in reason


def test_permits_rejects_scale_overrun():
    s = Scope.of(operations=["delete"], targets=["crm.*"], max_scale=50)
    ok, reason = s.permits("delete", "crm.opportunities", scale=400)
    assert not ok and "scale 400 exceeds limit 50" in reason


def test_scale_limit_does_not_apply_to_reads():
    """Scanning 412 rows to find candidates is the job; deleting 400 is the concern."""
    s = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)
    ok, reason = s.permits("read", "crm.opportunities", scale=412)
    assert ok, reason
    ok, reason = s.permits("delete", "crm.opportunities", scale=412)
    assert not ok and "exceeds limit" in reason


def test_permits_rejects_unexpected_irreversible():
    s = Scope.of(operations=["delete"], targets=["crm.*"], irreversible_allowed=False)
    ok, reason = s.permits("delete", "crm.opportunities", irreversible=True)
    assert not ok and "irreversible" in reason


def test_unbounded_scale_allows_anything():
    s = Scope.of(operations=["delete"], targets=["crm.*"], max_scale=None)
    ok, _ = s.permits("delete", "crm.opportunities", scale=10_000)
    assert ok


def test_glob_matching_is_prefix_scoped():
    s = Scope.of(operations=["read"], targets=["crm.*"])
    assert s.covers_target("crm.opportunities")
    assert not s.covers_target("crmx.opportunities")
    assert not s.covers_target("billing.invoices")


class TestSubset:
    parent = Scope.of(
        operations=["read", "update", "delete"],
        targets=["crm.*"],
        max_scale=50,
        irreversible_allowed=False,
        constraints=["no active customers"],
    )

    def test_identical_is_subset(self):
        ok, _ = self.parent.is_subset_of(self.parent)
        assert ok

    def test_narrower_is_subset(self):
        child = Scope.of(
            operations=["read"],
            targets=["crm.opportunities"],
            max_scale=10,
            constraints=["no active customers"],
        )
        ok, reason = child.is_subset_of(self.parent)
        assert ok, reason

    def test_extra_operation_rejected(self):
        child = Scope.of(operations=["read", "purge"], targets=["crm.*"], max_scale=10,
                         constraints=["no active customers"])
        ok, reason = child.is_subset_of(self.parent)
        assert not ok and "widens operations" in reason

    def test_extra_target_rejected(self):
        child = Scope.of(operations=["read"], targets=["billing.*"], max_scale=10,
                         constraints=["no active customers"])
        ok, reason = child.is_subset_of(self.parent)
        assert not ok and "widens targets" in reason

    def test_larger_scale_rejected(self):
        child = Scope.of(operations=["read"], targets=["crm.*"], max_scale=500,
                         constraints=["no active customers"])
        ok, reason = child.is_subset_of(self.parent)
        assert not ok and "widens max_scale" in reason

    def test_unbounded_under_bounded_rejected(self):
        child = Scope.of(operations=["read"], targets=["crm.*"], max_scale=None,
                         constraints=["no active customers"])
        ok, reason = child.is_subset_of(self.parent)
        assert not ok and "unbounded" in reason

    def test_escalating_irreversible_rejected(self):
        child = Scope.of(operations=["read"], targets=["crm.*"], max_scale=10,
                         irreversible_allowed=True, constraints=["no active customers"])
        ok, reason = child.is_subset_of(self.parent)
        assert not ok and "irreversible" in reason

    def test_dropping_inherited_constraint_rejected(self):
        child = Scope.of(operations=["read"], targets=["crm.*"], max_scale=10)
        ok, reason = child.is_subset_of(self.parent)
        assert not ok and "drops inherited constraints" in reason


def test_narrow_clamps_rather_than_widening():
    parent = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)
    # Asking for more than the parent has should yield the intersection.
    child = parent.narrow(operations=["read", "purge"], max_scale=500)
    assert child.operations == frozenset({"read"})
    assert child.max_scale == 50
    ok, _ = child.is_subset_of(parent)
    assert ok


def test_narrow_preserves_inherited_constraints():
    parent = Scope.of(operations=["read"], targets=["crm.*"], constraints=["a"])
    child = parent.narrow(add_constraints=["b"])
    assert child.constraints == ("a", "b")
