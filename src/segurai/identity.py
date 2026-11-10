"""Proving who asked.

Until a person's identity is proven, "sarah@company.com" at the top of a
chain is only what the calling code claimed. This module turns a claim into
proof: it accepts the signed ID token that the company's login system issues
(OpenID Connect - Okta, Microsoft Entra ID, Google Workspace, Auth0, Keycloak
and the rest all speak it) and checks it the way a relying party must:

  * the token is signed by a key the configured issuer publishes (its JWKS),
    with an asymmetric algorithm from an allow-list - never "none", never a
    shared-secret algorithm, so a public key can't be abused as an HMAC
    secret;
  * the issuer (``iss``) is one this deployment trusts, exactly;
  * the token was issued for this deployment (``aud``);
  * it has not expired, and was not issued in the future (small clock leeway);
  * the email is verified, and in an allowed domain, when so configured.

The result is an :class:`Identity` - who the person is, which issuer vouched
for it, their groups, and when that was checked. Sessions opened with one
record it, and the dashboard shows "verified" rather than "claimed".

Usage:

    verifier = IdentityVerifier([TrustedIssuer(
        issuer="https://login.acme.example", audience="segurai")])
    identity = verifier.verify(id_token)            # raises IdentityError
    with segurai.session(identity=identity, request="clean up", scope=...):
        ...

Signing keys are fetched from the issuer's published key set and cached;
an unknown key id triggers one refresh (issuers rotate keys), never more
than once a minute, so a stream of junk tokens can't make us hammer the
issuer.
"""

from __future__ import annotations

import json
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .models import utcnow

__all__ = ["Identity", "IdentityError", "IdentityVerifier", "TrustedIssuer", "ASYMMETRIC_ALGORITHMS"]

#: The only signature algorithms accepted. All asymmetric: an attacker who
#: knows the issuer's public key must not be able to sign tokens with it.
ASYMMETRIC_ALGORITHMS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                         "ES256", "ES384", "ES512", "EdDSA")

#: How long fetched signing keys are trusted before they are fetched again.
KEY_CACHE_SECONDS = 3600
#: An unknown key id causes a refetch at most this often.
MIN_REFRESH_SECONDS = 60


class IdentityError(Exception):
    """A token that does not prove who someone is. The message says why."""


def _http_get_json(url: str, timeout: float = 5.0) -> dict[str, Any]:
    if not url.lower().startswith(("https://", "http://localhost", "http://127.0.0.1")):
        raise IdentityError(f"refusing to fetch signing keys over plain http: {url}")
    request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                   "User-Agent": "segurai-identity"})
    with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 - scheme checked above
        if response.status != 200:
            raise IdentityError(f"{url} answered {response.status}")
        body = response.read(1024 * 1024 + 1)
    if len(body) > 1024 * 1024:
        raise IdentityError(f"{url} returned more than 1 MB")
    data = json.loads(body)
    if not isinstance(data, dict):
        raise IdentityError(f"{url} did not return a JSON object")
    return data


@dataclass(frozen=True)
class TrustedIssuer:
    """One login system this deployment accepts tokens from."""

    issuer: str                                   # must equal the token's "iss" exactly
    audience: str | tuple[str, ...]               # the client id the token must be for
    jwks_url: str | None = None                   # discovered from the issuer when not given
    principal_claim: str = "email"                # what becomes the principal
    groups_claim: str = "groups"
    require_verified_email: bool = True           # only applies when principal_claim is "email"
    allowed_domains: tuple[str, ...] = ()         # empty = any domain
    algorithms: tuple[str, ...] = ASYMMETRIC_ALGORITHMS
    leeway_seconds: int = 60

    def __post_init__(self) -> None:
        if not self.issuer:
            raise ValueError("a trusted issuer needs its issuer URL")
        if not self.audience:
            raise ValueError(f"issuer {self.issuer}: an audience (client id) is required")
        bad = sorted(set(self.algorithms) - set(ASYMMETRIC_ALGORITHMS))
        if bad:
            raise ValueError(f"issuer {self.issuer}: refusing algorithms {bad}; only asymmetric "
                             f"signature algorithms are accepted")
        if not 0 <= self.leeway_seconds <= 300:
            raise ValueError(f"issuer {self.issuer}: leeway must be between 0 and 300 seconds")


@dataclass(frozen=True)
class Identity:
    """A person (or service) whose identity a trusted issuer vouched for."""

    principal: str
    subject: str
    issuer: str
    groups: tuple[str, ...] = ()
    verified_at: datetime = field(default_factory=utcnow)
    expires_at: datetime | None = None
    token_id: str | None = None
    method: str = "oidc"

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal, "subject": self.subject, "issuer": self.issuer,
            "groups": list(self.groups), "verified_at": self.verified_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "token_id": self.token_id, "method": self.method,
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Identity":
        return Identity(
            principal=str(d["principal"]), subject=str(d.get("subject") or ""),
            issuer=str(d.get("issuer") or ""), groups=tuple(d.get("groups") or ()),
            verified_at=datetime.fromisoformat(d["verified_at"]),
            expires_at=datetime.fromisoformat(d["expires_at"]) if d.get("expires_at") else None,
            token_id=d.get("token_id"), method=str(d.get("method") or "oidc"),
        )


class _KeySet:
    """One issuer's published signing keys, cached, refreshed on an unknown key id."""

    def __init__(self, url: str, fetch: Callable[[str], dict[str, Any]]):
        self.url = url
        self._fetch = fetch
        self._keys: dict[str, Any] = {}
        self._fetched = 0.0
        self._lock = threading.Lock()

    def _load(self) -> None:
        import jwt

        data = self._fetch(self.url)
        keys: dict[str, Any] = {}
        for jwk in data.get("keys") or []:
            if not isinstance(jwk, dict) or jwk.get("use", "sig") != "sig":
                continue
            try:
                parsed = jwt.PyJWK(jwk)
            except (jwt.PyJWKError, jwt.InvalidKeyError, ValueError, TypeError):
                continue                      # a key type we don't use; skip, don't fail
            keys[str(jwk.get("kid") or "")] = parsed
        if not keys:
            raise IdentityError(f"no usable signing keys at {self.url}")
        self._keys = keys
        self._fetched = time.monotonic()

    def key_for(self, kid: str | None) -> Any:
        kid = kid or ""
        with self._lock:
            age = time.monotonic() - self._fetched
            if not self._keys or age > KEY_CACHE_SECONDS:
                self._load()
            elif kid not in self._keys and age > MIN_REFRESH_SECONDS:
                self._load()                  # the issuer may have rotated its keys
            if kid in self._keys:
                return self._keys[kid]
            if not kid and len(self._keys) == 1:
                return next(iter(self._keys.values()))
        raise IdentityError(f"the token was signed with key {kid!r}, which the issuer does not publish")


class IdentityVerifier:
    """Checks ID tokens from a fixed list of trusted issuers."""

    def __init__(self, issuers: list[TrustedIssuer],
                 fetch: Callable[[str], dict[str, Any]] = _http_get_json):
        try:
            import jwt  # noqa: F401
        except ImportError as exc:      # pragma: no cover - only without the extra
            raise ImportError("verifying identities needs PyJWT: pip install 'segurai[identity]'") from exc
        if not issuers:
            raise ValueError("at least one trusted issuer is required")
        self._issuers = {i.issuer: i for i in issuers}
        self._fetch = fetch
        self._keysets: dict[str, _KeySet] = {}
        self._lock = threading.Lock()

    @property
    def issuers(self) -> list[TrustedIssuer]:
        return list(self._issuers.values())

    def _keyset(self, issuer: TrustedIssuer) -> _KeySet:
        with self._lock:
            keyset = self._keysets.get(issuer.issuer)
            if keyset is None:
                url = issuer.jwks_url
                if not url:
                    discovery = self._fetch(issuer.issuer.rstrip("/") + "/.well-known/openid-configuration")
                    if discovery.get("issuer") != issuer.issuer:
                        raise IdentityError(f"{issuer.issuer} publishes a different issuer "
                                            f"({discovery.get('issuer')!r}) in its discovery document")
                    url = discovery.get("jwks_uri")
                    if not isinstance(url, str) or not url:
                        raise IdentityError(f"{issuer.issuer} publishes no jwks_uri")
                keyset = self._keysets[issuer.issuer] = _KeySet(url, self._fetch)
            return keyset

    def verify(self, token: str, nonce: str | None = None) -> Identity:
        """Prove who ``token`` belongs to, or raise :class:`IdentityError` saying why not.

        ``nonce`` is the value sent when a browser sign-in began; the token
        must carry exactly it, so a token from another sign-in can't be swapped in.
        """
        import jwt

        if not isinstance(token, str) or token.count(".") != 2 or len(token) > 16 * 1024:
            raise IdentityError("not a signed JWT")
        try:
            header = jwt.get_unverified_header(token)
            unverified = jwt.decode(token, options={"verify_signature": False})
        except jwt.PyJWTError as exc:
            raise IdentityError(f"unreadable token: {exc}") from exc

        issuer = self._issuers.get(str(unverified.get("iss") or ""))
        if issuer is None:
            raise IdentityError(f"tokens from {unverified.get('iss')!r} are not trusted here")
        algorithm = header.get("alg")
        if algorithm not in issuer.algorithms:
            raise IdentityError(f"signature algorithm {algorithm!r} is not accepted")

        try:
            key = self._keyset(issuer).key_for(header.get("kid"))
            claims = jwt.decode(
                token, key=key, algorithms=list(issuer.algorithms),
                audience=list(issuer.audience) if isinstance(issuer.audience, tuple) else issuer.audience,
                issuer=issuer.issuer, leeway=issuer.leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except IdentityError:
            raise
        except jwt.ExpiredSignatureError as exc:
            raise IdentityError("the token has expired") from exc
        except jwt.InvalidAudienceError as exc:
            raise IdentityError("the token was issued for a different application") from exc
        except jwt.ImmatureSignatureError as exc:
            raise IdentityError("the token is not valid yet") from exc
        except jwt.PyJWTError as exc:
            raise IdentityError(f"the token does not verify: {exc}") from exc
        except (OSError, ValueError) as exc:
            raise IdentityError(f"could not fetch the issuer's signing keys: {exc}") from exc

        if nonce is not None and not (isinstance(claims.get("nonce"), str)
                                      and __import__("hmac").compare_digest(claims["nonce"], nonce)):
            raise IdentityError("the token was not issued for this sign-in (nonce mismatch)")

        iat = claims.get("iat")
        if isinstance(iat, (int, float)) and iat > time.time() + issuer.leeway_seconds:
            raise IdentityError("the token claims to have been issued in the future")

        principal = claims.get(issuer.principal_claim)
        if not isinstance(principal, str) or not principal.strip():
            raise IdentityError(f"the token has no {issuer.principal_claim!r} to name the person by")
        principal = principal.strip()
        if issuer.principal_claim == "email":
            principal = principal.lower()
            if issuer.require_verified_email and claims.get("email_verified") is not True:
                raise IdentityError("the issuer has not verified this email address")
            domain = principal.rsplit("@", 1)[-1]
            if issuer.allowed_domains and domain not in {d.lower() for d in issuer.allowed_domains}:
                raise IdentityError(f"accounts from {domain} are not allowed here")

        groups = claims.get(issuer.groups_claim) or ()
        if isinstance(groups, str):
            groups = (groups,)
        exp = claims.get("exp")
        return Identity(
            principal=principal,
            subject=str(claims["sub"]),
            issuer=issuer.issuer,
            groups=tuple(str(g) for g in groups if isinstance(g, (str, int))),
            verified_at=utcnow(),
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc) if isinstance(exp, (int, float)) else None,
            token_id=str(claims["jti"]) if claims.get("jti") else None,
        )
