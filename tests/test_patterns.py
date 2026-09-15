"""Target-pattern containment - the guard on the attenuation guarantee.

A child agent's target patterns must never reach a resource its parent could
not. The first "rejected" case below is the exact bug found on 2026-09-15:
a child asking for "crm.*" was accepted under a parent limited to "crm.?",
because plain glob matching read the child's "*" as an ordinary character.
"""

from fnmatch import fnmatchcase
from itertools import product

import pytest

import warrant
from warrant import Scope
from warrant.models import pattern_covers


@pytest.mark.parametrize("parent, child", [
    ("crm.*", "crm.opportunities"),
    ("crm.*", "crm.*"),
    ("crm.*", "crm.opp*"),
    ("crm.*", "crm.?"),
    ("*", "anything.at.all*"),
    ("crm.?", "crm.a"),
    ("crm.?", "crm.[ab]"),
    ("crm.[ab]*", "crm.a*"),
    ("crm.a*", "crm.a[bc]*"),
    ("crm.**", "crm.*"),
])
def test_child_inside_parent_is_accepted(parent, child):
    assert pattern_covers(parent, child)


@pytest.mark.parametrize("parent, child", [
    ("crm.?", "crm.*"),            # the original bug
    ("?", "*"),
    ("crm.opp*", "crm.*"),
    ("crm.[ab]*", "crm.*"),
    ("crm.[ab]", "crm.?"),
    ("crm.a", "crm.?"),
    ("crm.*", "billing.*"),
    ("crm.*", "crmx.opportunities"),
    ("crm.leads", "CRM.leads"),    # case-sensitive on every platform
])
def test_child_reaching_outside_parent_is_rejected(parent, child):
    assert not pattern_covers(parent, child)


def test_soundness_by_brute_force():
    """Whenever pattern_covers says yes, no concrete name escapes the parent.

    Enumerates every name up to four characters over a tiny alphabet and
    checks all pattern pairs. This is what makes the check trustworthy: it may
    sometimes say no when the true answer is yes, but never the reverse.
    """
    patterns = ["*", "?", "a*", "a?", "?b", "[ab]", "[!a]", "a[ab]*", "*b",
                "a.*", "a.?", "**", "?*", "*?", "a", "."]
    names = ["".join(t) for n in range(5) for t in product("ab.", repeat=n)]
    for parent in patterns:
        for child in patterns:
            if pattern_covers(parent, child):
                escaped = [n for n in names if fnmatchcase(n, child) and not fnmatchcase(n, parent)]
                assert not escaped, f"{child!r} accepted inside {parent!r} but {escaped[:3]} escape"


def test_agent_cannot_widen_targets_with_a_wildcard():
    warrant.configure(store=":memory:", authority=warrant.Authority())

    @warrant.agent("rogue", scope=Scope.of(operations=["read"], targets=["crm.*"]))
    def rogue():
        return warrant.act("read", "crm.opportunities")

    parent = Scope.of(operations=["read"], targets=["crm.?"])
    with warrant.session(principal="p", request="r", scope=parent):
        with pytest.raises(warrant.ChainError, match="widens targets"):
            rogue()


def test_wildcard_resource_on_an_action_is_judged_as_a_pattern():
    """A bulk action reported against "crm.*" touches every crm table."""
    s = Scope.of(operations=["delete"], targets=["crm.?"])
    ok, reason = s.permits("delete", "crm.*")
    assert not ok and "not covered" in reason


def test_target_matching_is_case_sensitive():
    s = Scope.of(operations=["read"], targets=["crm.*"])
    assert s.covers_target("crm.Opportunities")
    assert not s.covers_target("CRM.opportunities")
