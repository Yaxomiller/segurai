"""Holder keys: agents delegate without the organisation's key, and still can't widen.

The organisation's key signs roots. Each warrant names a holder key; the
holder signs what it delegates with it. These tests play both honest agents
in other processes and dishonest ones holding a real holder key, and check
that verification accepts exactly the first.
"""

import base64
import sqlite3
import zlib
from dataclasses import replace
from datetime import timedelta

import pytest

import segurai
from segurai import Authority, ChainError, Scope, Store, verify_chain
from segurai.authority import key_id_of
from segurai.context import CHAIN_TOKEN_PREFIX, export_chain, import_chain
from segurai.models import utcnow

GRANTED = Scope.of(operations=["read", "archive"], targets=["crm.*"], max_scale=50)


@pytest.fixture
def org():
    return Authority()


def _root(org, scope=GRANTED, ttl=timedelta(hours=1)):
    return org.issue_root(session_id="ses_d", principal="sarah@company.com", scope=scope, ttl=ttl)


def _key_bytes(private):
    from cryptography.hazmat.primitives import serialization
    return private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                 serialization.NoEncryption())


# ---- the honest path ----------------------------------------------------------

def test_children_are_signed_by_the_parent_holder_not_the_org(org):
    root = _root(org)
    child = org.attenuate(root, "assistant")
    grandchild = org.attenuate(child, "crm_agent", scope=Scope.of(targets=["crm.opportunities"]))
    assert root.key_id == org.key_id
    assert child.key_id == key_id_of(root.holder_key) != org.key_id
    assert grandchild.key_id == key_id_of(child.holder_key)
    verify_chain([root, child, grandchild], org.public_only())


def test_an_agent_without_the_org_key_can_delegate_from_a_handed_over_chain(org):
    root = _root(org)
    child = org.attenuate(root, "assistant")
    key = _key_bytes(org.holder_private_key(child.warrant_id))

    agent_process = org.public_only()               # holds no private key of the org
    assert not agent_process.can_sign
    leaf = agent_process.adopt([root, child], key)
    worker = agent_process.attenuate(leaf, "billing_worker", scope=Scope.of(operations=["read"]))
    verify_chain([root, child, worker], org.public_only())


def test_a_verify_only_authority_cannot_mint_a_root(org):
    with pytest.raises(ChainError, match="cannot sign a root"):
        org.public_only().issue_root(session_id="s", principal="p", scope=GRANTED)


def test_without_the_key_a_chain_can_be_verified_but_not_continued(org):
    root = _root(org)
    agent_process = org.public_only()
    leaf = agent_process.adopt([root], None)
    with pytest.raises(ChainError, match="holds neither its holder key nor the organisation's key"):
        agent_process.attenuate(leaf, "worker")


# ---- the dishonest holder ---------------------------------------------------------

def test_a_holder_signing_a_wider_child_is_caught_by_the_chain_check(org):
    """The holder key signs anything; the chain check is what stops it widening."""
    root = _root(org)
    holder_key = org.holder_private_key(root.warrant_id)
    wider = segurai.Warrant(
        warrant_id="wrt_wider", session_id=root.session_id, root_principal=root.root_principal,
        holder="rogue", scope=Scope.of(operations=["read", "delete"], targets=["*"]),
        issued_at=root.issued_at, expires_at=root.expires_at, parent_id=root.warrant_id,
        depth=1, key_id=key_id_of(root.holder_key))
    wider = wider.with_signature(holder_key.sign(wider.signing_bytes()))
    with pytest.raises(ChainError, match="attenuation violated"):
        verify_chain([root, wider], org.public_only())


def test_a_child_signed_with_a_sibling_holders_key_is_refused(org):
    root = _root(org)
    a = org.attenuate(root, "agent_a")
    b = org.attenuate(root, "agent_b")
    stolen = org.holder_private_key(a.warrant_id)
    fake = segurai.Warrant(
        warrant_id="wrt_fake", session_id=root.session_id, root_principal=root.root_principal,
        holder="impostor", scope=b.scope, issued_at=b.issued_at, expires_at=b.expires_at,
        parent_id=b.warrant_id, depth=2, key_id=key_id_of(a.holder_key))
    fake = fake.with_signature(stolen.sign(fake.signing_bytes()))
    with pytest.raises(ChainError, match="invalid signature"):
        verify_chain([root, b, fake], org.public_only())


def test_another_organisations_chain_is_refused(org):
    mallory = Authority()
    with pytest.raises(ChainError, match="invalid signature"):
        org.public_only().adopt([_root(mallory)], None)


def test_a_key_that_is_not_the_leafs_is_refused(org):
    root = _root(org)
    child = org.attenuate(root, "assistant")
    wrong = _key_bytes(org.holder_private_key(root.warrant_id))     # the parent's key, not the leaf's
    with pytest.raises(ChainError, match="not its leaf holder's key"):
        org.public_only().adopt([root, child], wrong)


def test_an_altered_holder_key_breaks_the_signature(org):
    root = _root(org)
    swapped = replace(root, holder_key=Authority().public_only()._public.public_bytes_raw())
    with pytest.raises(ChainError, match="invalid signature"):
        verify_chain([swapped], org.public_only())


def test_expired_chains_cannot_be_adopted(org):
    root = _root(org, ttl=timedelta(seconds=-1))
    with pytest.raises(ChainError, match="expired"):
        org.public_only().adopt([root], None)


# ---- tokens -----------------------------------------------------------------------

def test_chain_tokens_round_trip_and_reject_tampering(org):
    segurai.configure(store=":memory:", authority=org)
    with segurai.session(principal="sarah@company.com", request="tidy up", scope=GRANTED):
        with segurai.delegate("assistant") as child:
            token = export_chain()
            bare = export_chain(include_key=False)
    assert token.startswith(CHAIN_TOKEN_PREFIX)
    chain, key = import_chain(token)
    assert [w.holder for w in chain] == ["entrypoint", "assistant"] and chain[-1] == child
    assert key is not None and import_chain(bare)[1] is None

    # Change one character of the scope inside the token: the signature catches it.
    body = __import__("json").loads(zlib.decompress(base64.urlsafe_b64decode(
        token[len(CHAIN_TOKEN_PREFIX):] + "==")))
    body["chain"][1]["scope"]["max_scale"] = 5000
    forged = CHAIN_TOKEN_PREFIX + base64.urlsafe_b64encode(
        zlib.compress(__import__("json").dumps(body).encode())).decode().rstrip("=")
    with pytest.raises(ChainError):
        org.public_only().adopt(*import_chain(forged))


@pytest.mark.parametrize("bad", ["", "x" * 70_000, CHAIN_TOKEN_PREFIX + "!!!", CHAIN_TOKEN_PREFIX],
                         ids=["empty", "oversized", "not-base64", "prefix-only"])
def test_unreadable_tokens_are_refused_cleanly(bad):
    with pytest.raises(ValueError, match="not a valid warrant token"):
        import_chain(bad)


def test_a_token_that_inflates_into_a_bomb_is_refused():
    bomb = zlib.compress(b"[" + b" " * 5_000_000 + b"]", 9)
    token = CHAIN_TOKEN_PREFIX + base64.urlsafe_b64encode(bomb).decode().rstrip("=")
    assert len(token) < 64 * 1024
    with pytest.raises(ValueError, match="size limit"):
        import_chain(token)


def test_resume_continues_a_chain_in_a_process_without_the_org_key(org):
    segurai.configure(store=":memory:", authority=org)
    with segurai.session(principal="sarah@company.com", request="tidy up", scope=GRANTED) as s:
        with segurai.delegate("assistant"):
            token = export_chain()

    # "Another process": its own store, and only the organisation's public key.
    segurai.configure(store=":memory:", authority=org.public_only())
    with segurai.resume(token, holder="crm_worker") as w:
        segurai.act("archive", "crm.opportunities", scale=3)
    store = segurai._runtime.store
    assert [x.holder for x in store.chain_to(w.warrant_id)] == ["entrypoint", "assistant", "crm_worker"]
    verify_chain(store.chain_to(w.warrant_id), org.public_only())
    assert store.actions_for_session(s.session_id)[0].actor == "crm_worker"


# ---- storage --------------------------------------------------------------------------

def test_holder_keys_are_stored_and_covered_by_the_log(org, tmp_path):
    segurai.configure(store=str(tmp_path / "w.db"), authority=org)
    with segurai.session(principal="p", request="r", scope=GRANTED) as s:
        with segurai.delegate("assistant"):
            pass
    store = segurai._runtime.store
    chain = store.warrants_for_session(s.session_id)
    assert all(w.holder_key for w in chain)
    verify_chain(chain, org.public_only())
    assert store.audit(org).ok

    # Swapping a stored holder key is an edit the log notices.
    store._conn.execute("UPDATE warrants SET holder_key = ? WHERE depth = 1", (b"\x00" * 32,))
    store._conn.commit()
    assert not store.audit(org).ok


def test_a_log_written_before_holder_keys_still_audits_clean(tmp_path):
    """Rows hashed before the holder_key column existed must not look edited."""
    db = tmp_path / "old.db"
    legacy = Authority(holder_keys=False)
    segurai.configure(store=str(db), authority=legacy)
    with segurai.session(principal="p", request="r", scope=GRANTED):
        with segurai.delegate("assistant"):
            segurai.act("read", "crm.accounts")
    segurai._runtime.store.close()
    segurai.configure(store=":memory:")

    # Simulate the pre-0.4 schema: drop the column the rows never had.
    conn = sqlite3.connect(db)
    conn.execute("ALTER TABLE warrants DROP COLUMN holder_key")
    conn.commit()
    conn.close()

    reopened = Store(db)                                     # migrates the column back in
    assert reopened.audit(legacy).ok
    assert all(w.holder_key is None for w in reopened.warrants_for_session(
        reopened.sessions()[0].session_id))


def test_a_child_signed_by_the_org_key_is_still_accepted(org):
    """Warrants from before holder keys: every hop signed by the org key."""
    legacy = Authority(org._key, holder_keys=False)
    root = legacy.issue_root(session_id="s", principal="p", scope=GRANTED)
    child = legacy.attenuate(root, "assistant")
    assert child.key_id == org.key_id and child.holder_key is None
    verify_chain([root, child], org.public_only())


def test_expired_holder_keys_are_forgotten(org):
    root = _root(org, ttl=timedelta(milliseconds=1))
    assert org.holder_private_key(root.warrant_id) is not None
    org._writes = 255
    import time
    time.sleep(0.01)
    _root(org)                                                # triggers a prune
    assert org.holder_private_key(root.warrant_id) is None
    assert utcnow() > root.expires_at
