"""Proving who asked: ID tokens from a fake login system, honest and forged."""

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

import segurai
from segurai import Identity, IdentityError, IdentityVerifier, Scope, TrustedIssuer
from segurai.collector.web import index_page, session_page

ISSUER = "https://login.acme.example"
AUDIENCE = "segurai-prod"


class FakeIdP:
    """A login system: signing keys, a discovery document, and token minting."""

    def __init__(self):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        self.kids = {"rsa-1": self.rsa}
        self.fetches = []

    def jwks(self):
        keys = []
        for kid, key in self.kids.items():
            jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key())
                             if isinstance(key, rsa.RSAPrivateKey)
                             else jwt.algorithms.ECAlgorithm.to_jwk(key.public_key()))
            jwk.update(kid=kid, use="sig")
            keys.append(jwk)
        return {"keys": keys}

    def fetch(self, url):
        self.fetches.append(url)
        if url == ISSUER + "/.well-known/openid-configuration":
            return {"issuer": ISSUER, "jwks_uri": ISSUER + "/keys"}
        if url == ISSUER + "/keys":
            return self.jwks()
        raise AssertionError(f"unexpected fetch {url}")

    def token(self, kid="rsa-1", alg="RS256", **overrides):
        now = int(time.time())
        claims = {"iss": ISSUER, "aud": AUDIENCE, "sub": "00u123", "iat": now, "exp": now + 300,
                  "email": "Sarah@Acme.example", "email_verified": True, "groups": ["sales", "admins"],
                  "jti": "tok-1"}
        claims.update(overrides)
        claims = {k: v for k, v in claims.items() if v is not None}
        return jwt.encode(claims, self.kids[kid], algorithm=alg, headers={"kid": kid})


@pytest.fixture
def idp():
    return FakeIdP()


@pytest.fixture
def verifier(idp):
    return IdentityVerifier([TrustedIssuer(issuer=ISSUER, audience=AUDIENCE,
                                           allowed_domains=("acme.example",))], fetch=idp.fetch)


# ---- the honest path ----------------------------------------------------------------

def test_a_valid_token_proves_who_asked(idp, verifier):
    who = verifier.verify(idp.token())
    assert who.principal == "sarah@acme.example"            # emails compare lower-case
    assert who.subject == "00u123" and who.issuer == ISSUER
    assert who.groups == ("sales", "admins") and who.token_id == "tok-1"
    assert Identity.from_dict(who.to_dict()) == who


def test_elliptic_curve_keys_work_too(idp, verifier):
    idp.kids["ec-1"] = idp.ec
    assert verifier.verify(idp.token(kid="ec-1", alg="ES256")).principal == "sarah@acme.example"


def test_rotated_keys_are_picked_up_but_refetching_is_throttled(idp, verifier, monkeypatch):
    verifier.verify(idp.token())
    idp.kids["rsa-2"] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rotated = idp.token(kid="rsa-2")

    # Within a minute of the last fetch an unknown key is refused without refetching...
    with pytest.raises(IdentityError, match="does not publish"):
        verifier.verify(rotated)
    fetched = len(idp.fetches)

    # ...after it, one refetch finds the new key.
    import segurai.identity as identity_module
    real = time.monotonic
    monkeypatch.setattr(identity_module.time, "monotonic", lambda: real() + 120)
    assert verifier.verify(rotated).principal == "sarah@acme.example"
    assert len(idp.fetches) == fetched + 1


# ---- the forgeries ------------------------------------------------------------------------

def test_an_unsigned_token_is_refused(idp, verifier):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": "rsa-1"}).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(jwt.decode(idp.token(), options={
        "verify_signature": False})).encode()).rstrip(b"=")
    with pytest.raises(IdentityError, match="not accepted"):
        verifier.verify(f"{header.decode()}.{body.decode()}.")


def test_the_public_key_cannot_be_used_as_a_shared_secret(idp, verifier):
    """The classic algorithm-confusion attack: HS256 signed with the issuer's public key."""
    public_pem = idp.rsa.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo)
    claims = jwt.decode(idp.token(), options={"verify_signature": False})
    import hashlib
    import hmac
    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "kid": "rsa-1"}).encode()).rstrip(b"=")
    body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=")
    signature = base64.urlsafe_b64encode(hmac.new(public_pem, header + b"." + body, hashlib.sha256)
                                         .digest()).rstrip(b"=")
    with pytest.raises(IdentityError, match="not accepted"):
        verifier.verify(b".".join([header, body, signature]).decode())


def test_a_token_signed_by_someone_else_is_refused(idp, verifier):
    impostor = FakeIdP()
    with pytest.raises(IdentityError, match="does not verify"):
        verifier.verify(impostor.token())


def test_an_altered_token_is_refused(idp, verifier):
    head, body, sig = idp.token().split(".")
    claims = json.loads(base64.urlsafe_b64decode(body + "=="))
    claims["email"] = "ceo@acme.example"
    forged_body = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    with pytest.raises(IdentityError, match="does not verify"):
        verifier.verify(f"{head}.{forged_body}.{sig}")


@pytest.mark.parametrize("overrides, message", [
    ({"iss": "https://evil.example"}, "not trusted here"),
    ({"aud": "some-other-app"}, "different application"),
    ({"exp": int(time.time()) - 3600, "iat": int(time.time()) - 7200}, "expired"),
    ({"nbf": int(time.time()) + 3600}, "not valid yet"),
    ({"iat": int(time.time()) + 3600}, "not valid yet|future"),
    ({"email_verified": False}, "not verified this email"),
    ({"email": "sarah@gmail.com"}, "not allowed here"),
    ({"email": None}, "no 'email'"),
    ({"sub": None}, "does not verify"),
    ({"exp": None}, "does not verify"),
])
def test_tokens_that_prove_nothing_are_refused(idp, verifier, overrides, message):
    with pytest.raises(IdentityError, match=message):
        verifier.verify(idp.token(**overrides))


@pytest.mark.parametrize("junk", ["", "a.b", "x" * 20_000 + ".a.b", "not-a-token"])
def test_junk_is_refused_cleanly(verifier, junk):
    with pytest.raises(IdentityError):
        verifier.verify(junk)


def test_a_discovery_document_naming_another_issuer_is_refused(idp):
    def lying(url):
        return {"issuer": "https://evil.example", "jwks_uri": ISSUER + "/keys"} if "well-known" in url \
            else idp.fetch(url)
    verifier = IdentityVerifier([TrustedIssuer(issuer=ISSUER, audience=AUDIENCE)], fetch=lying)
    with pytest.raises(IdentityError, match="different issuer"):
        verifier.verify(idp.token())


def test_shared_secret_algorithms_cannot_even_be_configured():
    with pytest.raises(ValueError, match="only asymmetric"):
        TrustedIssuer(issuer=ISSUER, audience=AUDIENCE, algorithms=("HS256",))


def test_keys_are_never_fetched_over_plain_http():
    from segurai.identity import _http_get_json
    with pytest.raises(IdentityError, match="plain http"):
        _http_get_json("http://login.acme.example/keys")


# ---- sessions remember how the person was proven -----------------------------------------------

GRANTED = Scope.of(operations=["read"], targets=["crm.*"])


def test_a_session_opened_with_an_identity_is_recorded_as_verified(idp, verifier):
    who = verifier.verify(idp.token())
    with segurai.session(identity=who, request="list my accounts", scope=GRANTED) as s:
        segurai.act("read", "crm.accounts")
    store = segurai._runtime.store
    row = store.get_session(s.session_id)
    assert row.principal == "sarah@acme.example" and row.verified
    assert row.identity["issuer"] == ISSUER and row.identity["subject"] == "00u123"
    assert store.audit(segurai._runtime.authority).ok
    assert "identity verified" in session_page(store, s.session_id)


def test_a_claimed_principal_is_labelled_as_claimed():
    with segurai.session(principal="sarah@acme.example", request="r", scope=GRANTED) as s:
        pass
    store = segurai._runtime.store
    assert not store.get_session(s.session_id).verified
    assert "claimed, not verified" in session_page(store, s.session_id)
    assert "identity verified" not in index_page(store)


def test_a_principal_that_disagrees_with_the_identity_is_refused(idp, verifier):
    who = verifier.verify(idp.token())
    with pytest.raises(ValueError, match="does not match the verified identity"):
        with segurai.session(principal="ceo@acme.example", identity=who, request="r", scope=GRANTED):
            pass


def test_editing_a_recorded_identity_is_caught(idp, verifier):
    who = verifier.verify(idp.token())
    with segurai.session(identity=who, request="r", scope=GRANTED):
        pass
    store = segurai._runtime.store
    store._conn.execute("UPDATE sessions SET identity_json = ?", (json.dumps({"principal": "x"}),))
    store._conn.commit()
    assert not store.audit(segurai._runtime.authority).ok
