"""Who may see the dashboard, and what they may do there.

Three roles, each including the one before it:

    viewer    the overview, every request, the permissions report
    auditor   + record integrity, evidence packs, the access log
    admin     + adding people, changing roles, disabling accounts

Two ways to sign in, usable together:

  * **The company login system** (OpenID Connect - Okta, Entra ID, Google,
    Keycloak...). The standard authorization-code flow with PKCE, a one-time
    ``state`` and ``nonce``, and the ID token checked by identity.py. Roles
    come from the token's groups through ``role_map``; people the map doesn't
    cover get ``default_role`` (or are turned away when it is empty).
  * **Local accounts**, for a pilot without a login system. Passwords are
    stored only as scrypt hashes with a random salt; repeated failures lock
    the account and the address out for a while.

Once signed in, a person holds a random session cookie (HttpOnly, SameSite,
Secure when served over https). Only a hash of it is stored, so a copy of the
database can't be used to sign in. Every form carries a CSRF token. Every page
anyone opens is written to the access log - itself part of the tamper-evident
log - so "who looked at this incident" has an answer too.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import threading
import time
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Mapping

from ..models import utcnow
from .store import Store

__all__ = ["ROLES", "WebAuth", "OidcLogin", "AuthError", "hash_password", "check_password",
           "User", "WebSession"]

ROLES = ("viewer", "auditor", "admin")
COOKIE = "segurai_session"
PRE_LOGIN_COOKIE = "segurai_prelogin"
MIN_PASSWORD = 12


class AuthError(Exception):
    """Sign-in refused. The message is safe to show to the person signing in."""


# ---- passwords ---------------------------------------------------------------------

_SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1, "dklen": 32}


def hash_password(password: str) -> str:
    """A salted scrypt hash: ``scrypt$n$r$p$salt$hash`` (salt and hash in base64)."""
    if len(password) < MIN_PASSWORD:
        raise AuthError(f"passwords must be at least {MIN_PASSWORD} characters")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode("utf-8"), salt=salt, **_SCRYPT)
    return "scrypt${n}${r}${p}${salt}${hash}".format(
        **_SCRYPT, salt=base64.b64encode(salt).decode(), hash=base64.b64encode(digest).decode())


def check_password(password: str, stored: str | None) -> bool:
    """Constant-time comparison. A missing hash still costs one scrypt, so timing
    doesn't reveal whether an account exists."""
    try:
        scheme, n, r, p, salt, digest = (stored or "").split("$")
        if scheme != "scrypt":
            raise ValueError
        expected = base64.b64decode(digest)
        actual = hashlib.scrypt(password.encode("utf-8"), salt=base64.b64decode(salt),
                                n=int(n), r=int(r), p=int(p), dklen=len(expected))
    except (ValueError, TypeError):
        hashlib.scrypt(b"x", salt=b"0" * 16, **_SCRYPT)
        return False
    return hmac.compare_digest(actual, expected)


# ---- people and sessions -------------------------------------------------------------

@dataclass(frozen=True)
class User:
    email: str
    name: str
    role: str
    source: str                     # local | oidc
    disabled: bool

    def can(self, role: str) -> bool:
        return not self.disabled and ROLES.index(self.role) >= ROLES.index(role)


@dataclass(frozen=True)
class WebSession:
    user: User
    csrf: str
    expires_at: Any


class _Throttle:
    """Failed sign-ins per account and per address. Five in 15 minutes locks for 15."""

    def __init__(self, limit: int = 5, window: float = 900.0):
        self.limit, self.window = limit, window
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def locked(self, *keys: str) -> bool:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                recent = [t for t in self._failures.get(key, []) if now - t < self.window]
                self._failures[key] = recent
                if len(recent) >= self.limit:
                    return True
        return False

    def fail(self, *keys: str) -> None:
        now = time.monotonic()
        with self._lock:
            for key in keys:
                self._failures.setdefault(key, []).append(now)

    def clear(self, *keys: str) -> None:
        with self._lock:
            for key in keys:
                self._failures.pop(key, None)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def safe_next(target: str | None) -> str:
    """Only ever redirect to a path on this server, never somewhere else."""
    if (not target or not target.startswith("/") or target.startswith("//")
            or "\\" in target or any(ord(c) < 0x20 for c in target)):
        return "/"
    return target


# ---- signing in with the company login system ------------------------------------------

@dataclass
class OidcLogin:
    """Settings for signing in to the dashboard with an OpenID Connect provider."""

    issuer: str
    client_id: str
    client_secret: str
    redirect_url: str                                  # https://segurai.acme.example/auth/callback
    role_map: Mapping[str, tuple[str, ...]] = field(default_factory=dict)   # role -> groups
    default_role: str = ""                             # "" = people no group maps are turned away
    allowed_domains: tuple[str, ...] = ()
    groups_claim: str = "groups"
    display_name: str = "your company login"
    fetch: Any = None                                  # for tests: url -> dict
    post: Any = None                                   # for tests: (url, form) -> dict

    def __post_init__(self) -> None:
        if self.default_role and self.default_role not in ROLES:
            raise ValueError(f"default_role must be one of {ROLES} or empty")
        for role in self.role_map:
            if role not in ROLES:
                raise ValueError(f"role_map: unknown role {role!r}; roles are {ROLES}")
        if not (self.redirect_url.startswith("https://")
                or self.redirect_url.startswith(("http://127.0.0.1", "http://localhost"))):
            raise ValueError("the OIDC redirect URL must be https (or a local address while testing)")

    def role_for(self, groups: tuple[str, ...]) -> str | None:
        best = None
        for role in ROLES:                              # viewer, auditor, admin: highest wins
            if set(self.role_map.get(role, ())) & set(groups):
                best = role
        return best or (self.default_role or None)


def _post_form(url: str, form: Mapping[str, str], timeout: float = 10.0) -> dict[str, Any]:
    if not url.startswith(("https://", "http://127.0.0.1", "http://localhost")):
        raise AuthError("the login system's token endpoint must be https")
    data = urllib.parse.urlencode(form).encode()
    request = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:   # noqa: S310 - scheme checked
            return json.loads(response.read(1024 * 1024))
    except urllib.error.HTTPError as exc:
        raise AuthError(f"the login system refused the sign-in ({exc.code})") from exc
    except (OSError, ValueError) as exc:
        raise AuthError("the login system could not be reached") from exc


# ---- the whole thing ---------------------------------------------------------------------

class WebAuth:
    """Accounts, sign-in, sessions, CSRF and the access log, for one dashboard."""

    def __init__(self, store: Store, *, oidc: OidcLogin | None = None, local_accounts: bool = True,
                 session_hours: float = 12.0, cookie_secure: bool = True):
        self.store = store
        self.oidc = oidc
        self.local_accounts = local_accounts
        self.session_lifetime = timedelta(hours=session_hours)
        self.cookie_secure = cookie_secure
        self.throttle = _Throttle()
        self._verifier = None
        self._discovery: dict[str, Any] | None = None
        self._lock = threading.Lock()

    # ---- accounts -------------------------------------------------------------------------

    def add_user(self, email: str, role: str, *, password: str | None = None, name: str = "",
                 source: str = "local", by: str = "system") -> User:
        email = email.strip().lower()
        if "@" not in email or len(email) > 254:
            raise AuthError("an account needs an email address")
        if role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        password_hash = hash_password(password) if password is not None else None
        self.store.put_user(email, name or email, role, password_hash, source, disabled=False, by=by)
        return self.get_user(email)  # type: ignore[return-value]

    def get_user(self, email: str) -> User | None:
        row = self.store.get_user(email.strip().lower())
        if row is None:
            return None
        return User(row["email"], row["name"], row["role"], row["source"], bool(row["disabled"]))

    def update_user(self, email: str, *, role: str | None = None, disabled: bool | None = None,
                    password: str | None = None, by: str) -> User:
        row = self.store.get_user(email.strip().lower())
        if row is None:
            raise AuthError("no such account")
        if role is not None and role not in ROLES:
            raise AuthError(f"role must be one of {ROLES}")
        new_role = role or row["role"]
        new_disabled = row["disabled"] if disabled is None else int(disabled)
        if row["role"] == "admin" and (new_role != "admin" or new_disabled):
            others = [u for u in self.store.users() if u["role"] == "admin" and not u["disabled"]
                      and u["email"] != row["email"]]
            if not others:
                raise AuthError("this is the last admin; make someone else admin first")
        password_hash = hash_password(password) if password else row["password_hash"]
        self.store.put_user(row["email"], row["name"], new_role, password_hash, row["source"],
                            disabled=bool(new_disabled), by=by)
        if new_disabled:
            self.store.end_web_sessions(row["email"])
        return self.get_user(row["email"])  # type: ignore[return-value]

    # ---- sessions -----------------------------------------------------------------------------

    def _start(self, user: User, ip: str) -> tuple[str, WebSession]:
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(24)
        expires = utcnow() + self.session_lifetime
        self.store.put_web_session(_hash_token(token), user.email, csrf, expires, ip)
        self.log(user.email, "SIGN-IN", "/login", 200, ip)
        return token, WebSession(user, csrf, expires)

    def session_for(self, token: str | None) -> WebSession | None:
        """The signed-in person for a session cookie, or None. Roles are re-read every time."""
        if not token or len(token) > 200:
            return None
        row = self.store.get_web_session(_hash_token(token))
        if row is None or row["expires_at"] <= utcnow().isoformat():
            return None
        user = self.get_user(row["email"])
        if user is None or user.disabled:
            return None
        return WebSession(user, row["csrf"], row["expires_at"])

    def end(self, token: str | None) -> None:
        if token:
            self.store.end_web_session(_hash_token(token))

    def cookie(self, token: str, max_age: int | None = None) -> str:
        """The Set-Cookie value for a session token ("" clears it)."""
        age = int(self.session_lifetime.total_seconds()) if max_age is None else max_age
        parts = [f"{COOKIE}={token}", "Path=/", "HttpOnly", "SameSite=Lax", f"Max-Age={age}"]
        if self.cookie_secure:
            parts.append("Secure")
        return "; ".join(parts)

    # ---- local passwords -------------------------------------------------------------------------

    def sign_in(self, email: str, password: str, ip: str) -> tuple[str, WebSession]:
        if not self.local_accounts:
            raise AuthError("sign in with " + (self.oidc.display_name if self.oidc else "the login system"))
        email = (email or "").strip().lower()
        if self.throttle.locked(f"user:{email}", f"ip:{ip}"):
            self.log(email or "?", "SIGN-IN", "/login", 429, ip)
            raise AuthError("too many failed attempts; try again in 15 minutes")
        row = self.store.get_user(email)
        ok = check_password(password or "", row["password_hash"] if row else None)
        if not ok or row is None or row["disabled"] or row["source"] != "local":
            self.throttle.fail(f"user:{email}", f"ip:{ip}")
            self.log(email or "?", "SIGN-IN", "/login", 401, ip)
            raise AuthError("that email and password don't match an account")
        self.throttle.clear(f"user:{email}")
        return self._start(self.get_user(email), ip)  # type: ignore[arg-type]

    # ---- the company login system -------------------------------------------------------------------

    def _oidc_config(self) -> dict[str, Any]:
        from ..identity import IdentityVerifier, TrustedIssuer, _http_get_json

        assert self.oidc is not None
        with self._lock:
            if self._discovery is None:
                fetch = self.oidc.fetch or _http_get_json
                discovery = fetch(self.oidc.issuer.rstrip("/") + "/.well-known/openid-configuration")
                if discovery.get("issuer") != self.oidc.issuer:
                    raise AuthError("the login system's discovery document names another issuer")
                self._discovery = discovery
                self._verifier = IdentityVerifier(
                    [TrustedIssuer(issuer=self.oidc.issuer, audience=self.oidc.client_id,
                                   jwks_url=discovery.get("jwks_uri"), groups_claim=self.oidc.groups_claim,
                                   allowed_domains=self.oidc.allowed_domains)], fetch=fetch)
            return self._discovery

    def oidc_start(self, next_path: str) -> tuple[str, str]:
        """(URL to send the browser to, pre-login cookie value binding this browser to the attempt)."""
        if self.oidc is None:
            raise AuthError("company sign-in is not configured")
        discovery = self._oidc_config()
        state, nonce, verifier = (secrets.token_urlsafe(24) for _ in range(3))
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        binding = secrets.token_urlsafe(24)
        self.store.put_oidc_pending(state, nonce, verifier, safe_next(next_path), _hash_token(binding))
        query = urllib.parse.urlencode({
            "response_type": "code", "client_id": self.oidc.client_id,
            "redirect_uri": self.oidc.redirect_url, "scope": "openid email profile",
            "state": state, "nonce": nonce, "code_challenge": challenge,
            "code_challenge_method": "S256",
        })
        return f"{discovery['authorization_endpoint']}?{query}", binding

    def oidc_finish(self, state: str, code: str, binding: str | None, ip: str) -> tuple[str, WebSession, str]:
        """Complete a company sign-in. Returns (session token, session, where to go next)."""
        if self.oidc is None:
            raise AuthError("company sign-in is not configured")
        pending = self.store.take_oidc_pending(state or "")       # single use
        if pending is None or not binding or not hmac.compare_digest(pending["binding"], _hash_token(binding)):
            raise AuthError("that sign-in link has expired or was not started in this browser; try again")
        discovery = self._oidc_config()
        post = self.oidc.post or _post_form
        tokens = post(discovery["token_endpoint"], {
            "grant_type": "authorization_code", "code": code, "redirect_uri": self.oidc.redirect_url,
            "client_id": self.oidc.client_id, "client_secret": self.oidc.client_secret,
            "code_verifier": pending["verifier"],
        })
        id_token = tokens.get("id_token") if isinstance(tokens, dict) else None
        if not id_token:
            raise AuthError("the login system did not return an ID token")
        from ..identity import IdentityError

        try:
            identity = self._verifier.verify(id_token, nonce=pending["nonce"])   # type: ignore[union-attr]
        except IdentityError as exc:
            self.log("?", "SIGN-IN", "/auth/callback", 401, ip)
            raise AuthError(f"sign-in refused: {exc}") from exc
        user = self.get_user(identity.principal)
        if user is not None and user.disabled:
            raise AuthError("this account has been disabled")
        role = self.oidc.role_for(identity.groups)
        if user is None or user.source == "oidc":
            if role is None:
                self.log(identity.principal, "SIGN-IN", "/auth/callback", 403, ip)
                raise AuthError("your account has no role in Segurai; ask an administrator")
            if user is None or user.role != role:
                self.store.put_user(identity.principal, identity.principal, role, None, "oidc",
                                    disabled=False, by="login system")
            user = self.get_user(identity.principal)
        token, web_session = self._start(user, ip)                # type: ignore[arg-type]
        return token, web_session, pending["next"]

    # ---- the access log -------------------------------------------------------------------------------

    def log(self, email: str, method: str, path: str, status: int, ip: str) -> None:
        self.store.put_access(f"acc_{uuid.uuid4().hex[:16]}", email, method, path[:500], status, ip)
