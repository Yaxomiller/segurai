import pytest

import segurai
from segurai import Scope, Store
from segurai.collector.chain import build_tree

GRANTED = Scope.of(operations=["read", "delete"], targets=["crm.*"], max_scale=50)


@pytest.fixture(autouse=True)
def fresh_runtime():
    segurai.configure(store=":memory:", authority=segurai.Authority(),
                      mode=segurai.Mode.OBSERVE)
    yield


def _run_demo():
    @segurai.agent("crm_agent", scope=Scope.of(
        operations=["read", "delete"], targets=["crm.opportunities"], max_scale=50))
    def crm_agent():
        segurai.act("read", "crm.opportunities", scale=412)
        segurai.act("delete", "crm.opportunities", scale=400, irreversible=True)

    @segurai.agent("assistant")
    def assistant():
        segurai.act("read", "crm.opportunities")
        crm_agent()

    with segurai.session(principal="sarah@company.com",
                         request="clean up our old sales records",
                         scope=GRANTED) as s:
        assistant()
        return s.session_id


def test_store_reconstructs_chain_to_leaf():
    sid = _run_demo()
    store = segurai._runtime.store
    warrants = store.warrants_for_session(sid)
    leaf = max(warrants, key=lambda w: w.depth)
    chain = store.chain_to(leaf.warrant_id)
    assert [w.holder for w in chain] == ["entrypoint", "assistant", "crm_agent"]
    assert chain[0].parent_id is None


def test_chain_to_missing_warrant_raises():
    store = Store(":memory:")
    with pytest.raises(ValueError, match="not found"):
        store.chain_to("wrt_nope")


def test_build_tree_groups_children():
    sid = _run_demo()
    warrants = segurai._runtime.store.warrants_for_session(sid)
    roots, children = build_tree(warrants)
    assert len(roots) == 1
    assert children[roots[0].warrant_id][0].holder == "assistant"


def test_render_contains_the_answer_to_who_authorized_this():
    sid = _run_demo()
    out = segurai.render(sid)
    assert "sarah@company.com" in out
    assert "clean up our old sales records" in out
    assert "entrypoint" in out and "assistant" in out and "crm_agent" in out
    # the violation must be visible, with its reason
    assert "FAIL" in out
    assert "irreversible" in out or "exceeds" in out


def test_summary_reports_violations_and_exercised_scope():
    sid = _run_demo()
    summary = segurai.summary(sid)
    assert summary["principal"] == "sarah@company.com"
    assert summary["max_depth"] == 2
    assert summary["holders"] == ["assistant", "crm_agent", "entrypoint"]
    assert len(summary["violations"]) == 1
    assert summary["violations"][0]["actor"] == "crm_agent"
    assert summary["exercised"]["operations"] == ["delete", "read"]


def test_exercised_scope_is_narrower_than_granted():
    """The seed of the scope-creep report: 'update' was granted, never used."""
    sid = _run_demo()
    used = segurai._runtime.store.exercised_scope(sid)
    assert "update" not in used["operations"]


def test_verify_session_detects_a_forged_warrant():
    sid = _run_demo()
    store = segurai._runtime.store
    # An attacker cannot use attenuate() - it verifies the parent first, and a
    # foreign key cannot verify our warrants. So forge the object directly and
    # splice it into the store, which is the realistic tampering path.
    rogue_auth = segurai.Authority()
    leaf = max(store.warrants_for_session(sid), key=lambda w: w.depth)
    forged = segurai.Warrant(
        warrant_id="wrt_forged",
        session_id=leaf.session_id,
        root_principal=leaf.root_principal,
        holder="exfiltrator",
        scope=Scope.of(operations=["read", "delete"], targets=["*"]),
        issued_at=leaf.issued_at,
        expires_at=leaf.expires_at,
        parent_id=leaf.warrant_id,
        depth=leaf.depth + 1,
    )
    store.put_warrant(rogue_auth._sign(forged))

    problems = segurai.verify_session(sid)
    assert problems and "exfiltrator" in problems[0]
