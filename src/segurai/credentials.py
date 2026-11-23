"""Where the gateway gets each system's credential: from the place the company already keeps it.

The gateway is the only thing that may call the real systems, so it needs
their credentials. The simplest way - an environment variable per system -
makes the gateway a vault: a long-lived copy of every key the agents are
kept away from. A company that already runs a secrets manager should not
have to hand a new component its production keys. So the gateway can ask
for them instead, at the moment it needs them:

    [gateway.upstreams.credentials]
    headers = { Authorization = "Bearer {api_key}" }    # filled from the secret's fields
    [gateway.upstreams.credentials.source]
    type = "vault"                                       # or aws-secrets-manager, gcp-secret-manager, env
    url  = "https://vault.internal:8200"
    path = "secret/data/crm-api"
    auth = "kubernetes"                                  # the gateway's own workload identity
    role = "segurai-gateway"

or, for a system that issues short-lived tokens itself (most SaaS APIs):

    [gateway.upstreams.credentials]
    type      = "oauth2"
    token_url = "https://login.crm.example/oauth2/token"
    client_id = "segurai-gateway"
    scope     = "api"
    client_secret_field = "client_secret"               # the source's field holding it
    [gateway.upstreams.credentials.source]               # where the client secret lives
    type = "vault"
    path = "secret/data/crm-oauth"

The parts:

  * A SOURCE reads a secret - a set of named fields - from somewhere: the
    environment, HashiCorp Vault (KV or any dynamic secrets engine),
    AWS Secrets Manager, or GCP Secret Manager.
  * CREDENTIALS turn a source into the headers the upstream expects: by
    filling a template ({api_key} is the secret's api_key field), or by
    exchanging a client secret for a short-lived OAuth2 access token.

What the gateway keeps, and for how long:

  * Secrets live only in memory, for the lease the secrets manager gives
    (a Vault lease, an access token's expires_in) or ``ttl_seconds``, and
    are fetched again a minute before they lapse. Nothing is written to disk
    or to the record.
  * The gateway proves who IT is with the workload identity the platform
    already gives it - a Kubernetes service account token, an AWS instance
    or task role, a GCP service account on the metadata server - so with
    those there is no long-lived secret for the gateway to hold at all.
    (A Vault token or AppRole secret id in the environment also works, and
    is a long-lived secret; prefer the platform's identity.)
  * If the secrets manager can't be reached, a credential still inside its
    lease keeps working; once it lapses, requests fail with 502 and nothing
    is forwarded. When an upstream answers 401 or 403, the cached credential
    is dropped, so a rotated key is picked up on the next request.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Mapping

__all__ = ["CredentialError", "SecretSource", "EnvSource", "VaultSource", "AwsSecretsManagerSource",
           "GcpSecretManagerSource", "Credentials", "TemplateCredentials", "OAuth2Credentials", "http_json"]

_log = logging.getLogger("segurai.credentials")

#: Fetch again this long before a lease or token lapses.
REFRESH_AHEAD = 60.0
#: How long a secret with no lease of its own is kept, unless configured.
DEFAULT_TTL = 300.0

#: (method, url, headers, body) -> (status, parsed JSON). Injectable for tests.
HttpJson = Callable[[str, str, Mapping[str, str], bytes | None], tuple[int, Any]]


class CredentialError(Exception):
    """A credential that could not be obtained. The message never contains the secret."""


def _https_only(url: str, what: str) -> None:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme == "https" and parts.hostname:
        return
    if parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1",
                                                     "169.254.169.254", "metadata.google.internal"):
        return                       # loopback, or a cloud metadata server (link-local by design)
    raise ValueError(f"{what} must be an https:// URL (got {url!r})")


def http_json(method: str, url: str, headers: Mapping[str, str], body: bytes | None = None,
              timeout: float = 10.0) -> tuple[int, Any]:
    """One HTTP call that expects JSON back. Errors become CredentialError, without bodies."""
    request = urllib.request.Request(url, data=body, method=method,
                                     headers={"Accept": "application/json", "User-Agent": "segurai-gateway",
                                              **headers})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:      # noqa: S310 - scheme checked
            raw = response.read(1024 * 1024)
            return response.status, json.loads(raw or b"null")
    except urllib.error.HTTPError as exc:
        # The body of an error from a secrets manager can echo what was asked
        # for; keep only the status.
        return exc.code, None
    except (OSError, ValueError) as exc:
        raise CredentialError(f"could not reach {urllib.parse.urlsplit(url).hostname}: "
                              f"{exc.__class__.__name__}") from exc


class _Lease:
    """A value with an expiry, refreshed by one caller at a time."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: Any = None
        self._until = 0.0                      # time.monotonic() after which it must not be used

    def get(self, fetch: Callable[[], tuple[Any, float]]) -> Any:
        """The cached value, or a fresh one. ``fetch`` returns (value, seconds it is good for)."""
        with self._lock:
            now = time.monotonic()
            if self._value is not None and now < self._until - REFRESH_AHEAD:
                return self._value
            try:
                value, seconds = fetch()
            except CredentialError:
                if self._value is not None and now < self._until:
                    _log.warning("could not refresh a credential; using the cached one until it lapses",
                                 exc_info=True)
                    return self._value
                raise
            self._value, self._until = value, now + max(1.0, seconds)
            return value

    def drop(self) -> None:
        with self._lock:
            self._value, self._until = None, 0.0


# ---- sources: where a secret's fields come from ----------------------------------------------

class SecretSource:
    """Reads a secret: a dict of named fields. Cached for its lease."""

    kind = "secret"

    def __init__(self, ttl: float = DEFAULT_TTL):
        self.ttl = ttl
        self._lease = _Lease()

    def values(self) -> dict[str, str]:
        return self._lease.get(self._fetch)

    def invalidate(self) -> None:
        self._lease.drop()

    def _fetch(self) -> tuple[dict[str, str], float]:
        raise NotImplementedError

    def describe(self) -> str:
        return self.kind


def _fields(data: Any, what: str) -> dict[str, str]:
    """A secret's fields as strings. A plain-text secret becomes {"value": text}."""
    if isinstance(data, str):
        try:
            parsed = json.loads(data)
        except ValueError:
            return {"value": data}
        data = parsed if isinstance(parsed, dict) else {"value": data}
    if not isinstance(data, dict):
        raise CredentialError(f"{what} is not a set of named fields")
    return {str(k): v if isinstance(v, str) else json.dumps(v) for k, v in data.items()}


class EnvSource(SecretSource):
    """Fields from environment variables: ``vars = { api_key = "CRM_API_KEY" }``. Read at start-up."""

    kind = "env"

    def __init__(self, variables: Mapping[str, str]):
        super().__init__(ttl=float("inf"))
        missing = [name for name in variables.values() if not os.environ.get(name)]
        if missing:
            raise ValueError(f"environment variable(s) {missing} not set")
        self._data = {k: os.environ[v] for k, v in variables.items()}

    def values(self) -> dict[str, str]:
        return dict(self._data)

    def describe(self) -> str:
        return "environment"


@dataclass
class VaultAuth:
    """How the gateway proves itself to Vault.

    kubernetes  the pod's service account token (a short-lived, projected JWT)
    approle     a role id and secret id from the environment
    token       a Vault token from the environment (development)
    """

    method: str = "kubernetes"
    role: str = ""                                   # kubernetes: the Vault role to log in as
    mount: str = ""                                  # the auth mount; default "kubernetes" / "approle"
    jwt_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    token_env: str = "VAULT_TOKEN"
    role_id_env: str = "VAULT_ROLE_ID"
    secret_id_env: str = "VAULT_SECRET_ID"

    def __post_init__(self) -> None:
        if self.method not in ("kubernetes", "approle", "token"):
            raise ValueError("vault auth must be kubernetes, approle or token")
        if self.method == "kubernetes" and not self.role:
            raise ValueError("vault kubernetes auth needs a role")


class VaultSource(SecretSource):
    """A secret read from HashiCorp Vault: KV (v1 or v2), or any dynamic secrets engine.

    ``path`` is the API path after /v1/, e.g. ``secret/data/crm-api`` (KV v2)
    or ``aws/creds/crm-readonly`` (a dynamic secret with its own lease).
    """

    kind = "vault"

    def __init__(self, url: str, path: str, auth: VaultAuth, *, namespace: str = "",
                 ttl: float = DEFAULT_TTL, http: HttpJson = http_json):
        super().__init__(ttl)
        _https_only(url, "vault url")
        if not path or path.startswith("/") or ".." in path.split("/"):
            raise ValueError("vault path must look like secret/data/crm-api")
        self.url, self.path, self.auth, self.namespace = url.rstrip("/"), path, auth, namespace
        self._http = http
        self._token = _Lease()

    def describe(self) -> str:
        return f"vault {self.path} ({self.auth.method})"

    def _headers(self, token: str | None = None) -> dict[str, str]:
        headers = {"X-Vault-Namespace": self.namespace} if self.namespace else {}
        if token:
            headers["X-Vault-Token"] = token
        return headers

    def _login(self) -> tuple[str, float]:
        auth = self.auth
        if auth.method == "token":
            token = os.environ.get(auth.token_env)
            if not token:
                raise CredentialError(f"vault token auth: {auth.token_env} is not set")
            return token, float("inf")
        if auth.method == "kubernetes":
            try:
                jwt = Path(auth.jwt_path).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise CredentialError(f"vault kubernetes auth: can't read the service account token "
                                      f"({auth.jwt_path})") from exc
            mount, body = auth.mount or "kubernetes", {"role": auth.role, "jwt": jwt}
        else:
            role_id, secret_id = os.environ.get(auth.role_id_env), os.environ.get(auth.secret_id_env)
            if not role_id or not secret_id:
                raise CredentialError(f"vault approle auth: {auth.role_id_env} and {auth.secret_id_env} must be set")
            mount, body = auth.mount or "approle", {"role_id": role_id, "secret_id": secret_id}
        status, data = self._http("POST", f"{self.url}/v1/auth/{mount}/login", self._headers(),
                                  json.dumps(body).encode())
        token = ((data or {}).get("auth") or {}).get("client_token") if isinstance(data, dict) else None
        if status != 200 or not token:
            raise CredentialError(f"vault refused the gateway's {auth.method} login ({status})")
        return token, float((data["auth"].get("lease_duration") or 3600))

    def _fetch(self) -> tuple[dict[str, str], float]:
        token = self._token.get(self._login)
        status, data = self._http("GET", f"{self.url}/v1/{self.path}", self._headers(token), None)
        if status == 403:
            self._token.drop()                       # the login may have lapsed; log in again next time
        if status != 200 or not isinstance(data, dict) or not isinstance(data.get("data"), dict):
            raise CredentialError(f"vault answered {status} for {self.path}")
        payload = data["data"]
        if isinstance(payload.get("data"), dict) and "metadata" in payload:
            payload = payload["data"]                # KV version 2 wraps the fields once more
        lease = float(data.get("lease_duration") or 0) or self.ttl
        return _fields(payload, f"vault {self.path}"), lease


class AwsSecretsManagerSource(SecretSource):
    """A secret from AWS Secrets Manager, read with the gateway's own AWS identity.

    Needs boto3 (``pip install boto3``). Credentials come from wherever boto3
    finds them - on AWS, the instance or task role, so no key is stored.
    """

    kind = "aws-secrets-manager"

    def __init__(self, secret_id: str, *, region: str = "", ttl: float = DEFAULT_TTL, client: Any = None):
        super().__init__(ttl)
        if not secret_id:
            raise ValueError("aws-secrets-manager needs secret_id")
        self.secret_id = secret_id
        if client is None:
            try:
                import boto3
            except ImportError as exc:
                raise ValueError("aws-secrets-manager needs boto3: pip install boto3") from exc
            client = boto3.client("secretsmanager", **({"region_name": region} if region else {}))
        self._client = client

    def describe(self) -> str:
        return f"aws-secrets-manager {self.secret_id}"

    def _fetch(self) -> tuple[dict[str, str], float]:
        try:
            answer = self._client.get_secret_value(SecretId=self.secret_id)
        except Exception as exc:                     # botocore raises many kinds; none carry the secret
            raise CredentialError(f"aws-secrets-manager could not read {self.secret_id}: "
                                  f"{exc.__class__.__name__}") from exc
        if answer.get("SecretString") is not None:
            return _fields(answer["SecretString"], self.secret_id), self.ttl
        binary = answer.get("SecretBinary") or b""
        return {"value": base64.b64decode(binary).decode("utf-8") if isinstance(binary, str)
                else bytes(binary).decode("utf-8")}, self.ttl


class GcpSecretManagerSource(SecretSource):
    """A secret from Google Cloud Secret Manager, read with the gateway's service account.

    The access token comes from the metadata server, so on Google Cloud no
    key file is needed.
    """

    kind = "gcp-secret-manager"
    METADATA_TOKEN = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

    def __init__(self, project: str, secret: str, *, version: str = "latest", ttl: float = DEFAULT_TTL,
                 http: HttpJson = http_json, api: str = "https://secretmanager.googleapis.com"):
        super().__init__(ttl)
        if not project or not secret:
            raise ValueError("gcp-secret-manager needs project and secret")
        _https_only(api, "gcp secret manager api")
        self.project, self.secret, self.version, self.api = project, secret, version, api.rstrip("/")
        self._http = http
        self._token = _Lease()

    def describe(self) -> str:
        return f"gcp-secret-manager {self.project}/{self.secret}"

    def _access_token(self) -> tuple[str, float]:
        status, data = self._http("GET", self.METADATA_TOKEN, {"Metadata-Flavor": "Google"}, None)
        if status != 200 or not isinstance(data, dict) or not data.get("access_token"):
            raise CredentialError(f"the GCP metadata server gave no access token ({status})")
        return data["access_token"], float(data.get("expires_in") or 300)

    def _fetch(self) -> tuple[dict[str, str], float]:
        token = self._token.get(self._access_token)
        name = (f"projects/{urllib.parse.quote(self.project, safe='')}/secrets/"
                f"{urllib.parse.quote(self.secret, safe='')}/versions/{urllib.parse.quote(self.version, safe='')}")
        status, data = self._http("GET", f"{self.api}/v1/{name}:access", {"Authorization": f"Bearer {token}"}, None)
        if status in (401, 403):
            self._token.drop()
        try:
            raw = base64.b64decode(data["payload"]["data"]).decode("utf-8")
        except (TypeError, KeyError, ValueError) as exc:
            raise CredentialError(f"gcp-secret-manager answered {status} for {self.secret}") from exc
        return _fields(raw, self.secret), self.ttl


# ---- credentials: a source turned into the headers an upstream expects --------------------------

class Credentials:
    """What the gateway adds to each request for one upstream."""

    def headers(self) -> dict[str, str]:
        raise NotImplementedError

    def invalidate(self) -> None:
        """Forget anything cached (the upstream refused it): fetch afresh next time."""

    def describe(self) -> str:
        return "credentials"


@dataclass
class TemplateCredentials(Credentials):
    """Headers filled from a secret's fields: ``{"Authorization": "Bearer {api_key}"}``."""

    source: SecretSource
    template: Mapping[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.template:
            raise ValueError("credentials need at least one header, e.g. Authorization = \"Bearer {api_key}\"")

    def headers(self) -> dict[str, str]:
        values = self.source.values()
        out = {}
        for header, pattern in self.template.items():
            try:
                out[header] = pattern.format_map(values)
            except (KeyError, IndexError, ValueError) as exc:
                raise CredentialError(f"the secret from {self.source.describe()} has no field "
                                      f"{exc.args[0] if exc.args else '?'} for header {header}") from exc
        return out

    def invalidate(self) -> None:
        self.source.invalidate()

    def describe(self) -> str:
        return f"{', '.join(self.template)} from {self.source.describe()}"


class OAuth2Credentials(Credentials):
    """A short-lived access token from an OAuth2 token endpoint (client credentials).

    The client secret is read from ``source`` (its ``field``), exchanged for a
    token, and the token is used until a minute before it expires. With
    :meth:`token_for` the gateway can also ask for a narrower ``scope`` - the
    basis of direct, scope-matched credentials for agents.
    """

    def __init__(self, token_url: str, client_id: str, source: SecretSource, *, field: str = "client_secret",
                 scope: str = "", audience: str = "", http: HttpJson = http_json):
        _https_only(token_url, "token_url")
        if not client_id:
            raise ValueError("oauth2 credentials need client_id")
        self.token_url, self.client_id, self.source, self.field = token_url, client_id, source, field
        self.scope, self.audience = scope, audience
        self._http = http
        self._lease = _Lease()

    def describe(self) -> str:
        return f"oauth2 token from {urllib.parse.urlsplit(self.token_url).hostname} ({self.source.describe()})"

    def token_for(self, scope: str | None = None) -> tuple[str, float]:
        """A fresh token (not cached) and how many seconds it is good for."""
        secret = self.source.values().get(self.field)
        if not secret:
            raise CredentialError(f"the secret from {self.source.describe()} has no field {self.field}")
        form = {"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": secret}
        chosen = self.scope if scope is None else scope
        if chosen:
            form["scope"] = chosen
        if self.audience:
            form["audience"] = self.audience
        status, data = self._http("POST", self.token_url, {"Content-Type": "application/x-www-form-urlencoded"},
                                  urllib.parse.urlencode(form).encode())
        if status in (400, 401):
            self.source.invalidate()                 # perhaps the client secret was rotated
        if status != 200 or not isinstance(data, dict) or not data.get("access_token"):
            raise CredentialError(f"the token endpoint answered {status}")
        return str(data["access_token"]), float(data.get("expires_in") or 300)

    def headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._lease.get(self.token_for)}"}

    def invalidate(self) -> None:
        self._lease.drop()
