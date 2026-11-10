"""One configuration file for a whole Segurai deployment: ``segurai.toml``.

    segurai init                        writes a commented example and a signing key
    segurai config check                 reads it, checks everything, prints a summary
    segurai serve --config segurai.toml  runs it

Two rules make the file safe to keep in version control:

  * **Secrets never go in it.** Anything secret is named by the environment
    variable that holds it - ``client_secret_env = "SEGURAI_OIDC_SECRET"`` - and
    read when the server starts. A missing variable stops the start with its name.
  * **Nothing is guessed.** An unknown setting, a misspelt one, or a value of
    the wrong type is an error that names the setting, never silently ignored:
    a typo in a security setting must not quietly turn the setting off.

Relative paths are taken relative to the configuration file's own folder.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10
    import tomli as tomllib

from .collector.db import is_database_url, redact_url
from .models import Scope
from .policy import Policy, PolicyError

__all__ = ["Config", "ConfigError", "load_config", "EXAMPLE", "example"]


class ConfigError(ValueError):
    """A configuration that can't be used. The message names the setting."""


_MISSING = object()


class _Table:
    """One TOML table, read strictly: every key must be known, every type right."""

    def __init__(self, data: Any, where: str):
        if not isinstance(data, dict):
            raise ConfigError(f"{where} must be a table")
        self.data, self.where, self.used = data, where, set()

    def get(self, key: str, kind: Any, default: Any = _MISSING) -> Any:
        self.used.add(key)
        if key not in self.data:
            if default is _MISSING:
                raise ConfigError(f"{self.where}.{key} is required")
            return default
        value = self.data[key]
        kinds = kind if isinstance(kind, tuple) else (kind,)
        if bool not in kinds and isinstance(value, bool) and int in kinds:
            raise ConfigError(f"{self.where}.{key} must be a number, not true/false")
        if not isinstance(value, kinds):
            names = " or ".join(k.__name__ for k in kinds)
            raise ConfigError(f"{self.where}.{key} must be {names}, got {type(value).__name__}")
        return value

    def strings(self, key: str, default: tuple = ()) -> tuple[str, ...]:
        value = self.get(key, list, list(default))
        if not all(isinstance(v, str) for v in value):
            raise ConfigError(f"{self.where}.{key} must be a list of strings")
        return tuple(value)

    def table(self, key: str) -> "_Table | None":
        self.used.add(key)
        return _Table(self.data[key], f"{self.where}.{key}") if key in self.data else None

    def tables(self, key: str) -> list["_Table"]:
        self.used.add(key)
        items = self.data.get(key, [])
        if not isinstance(items, list):
            raise ConfigError(f"{self.where}.{key} must be a list of tables ([[{self.where}.{key}]])")
        return [_Table(item, f"{self.where}.{key}[{i}]") for i, item in enumerate(items)]

    def secret(self, key: str, *, required: bool = True) -> str | None:
        """The value of the environment variable named by ``<key>_env``."""
        name = self.get(f"{key}_env", str, None)
        if name is None:
            if f"{key}" in self.data:
                raise ConfigError(f"{self.where}.{key}: put secrets in an environment variable and name it "
                                  f"with {key}_env, never in this file")
            if required:
                raise ConfigError(f"{self.where}.{key}_env is required (the environment variable holding it)")
            return None
        value = os.environ.get(name)
        if not value:
            raise ConfigError(f"{self.where}.{key}_env names {name}, which is not set")
        return value

    def done(self) -> None:
        unknown = sorted(set(self.data) - self.used)
        if unknown:
            raise ConfigError(f"{self.where}: unknown setting(s) {unknown}")


# ---- the parsed configuration --------------------------------------------------------

@dataclass
class ServerConfig:
    database: str
    key: Path
    host: str = "127.0.0.1"
    port: int = 8700
    public_url: str = ""
    trust_proxy: bool = False
    ingest_tokens: tuple[str, ...] = ()


@dataclass
class DashboardConfig:
    local_accounts: bool = True
    session_hours: float = 12.0
    oidc: Any = None                        # collector.auth.OidcLogin


@dataclass
class IssuerConfig:
    trusted: list = field(default_factory=list)       # identity.TrustedIssuer
    ceilings: list = field(default_factory=list)      # issuer.Ceiling
    default_ttl: timedelta = timedelta(hours=1)
    max_ttl: timedelta = timedelta(hours=8)


@dataclass
class Config:
    path: Path
    server: ServerConfig
    dashboard: DashboardConfig | None = None
    issuer: IssuerConfig | None = None
    policy: Policy = field(default_factory=Policy)
    gateway: Any = None                     # gateway.GatewayConfig plus host/port
    gateway_address: tuple[str, int] | None = None
    alert_channels: list = field(default_factory=list)
    audit_every: timedelta = timedelta(minutes=5)
    witnesses: list = field(default_factory=list)
    witness_every: timedelta = timedelta(hours=1)

    def summary(self) -> list[str]:
        s = self.server
        lines = [f"database        : {redact_url(s.database)}",
                 f"organisation key: {s.key}",
                 f"dashboard       : http://{s.host}:{s.port}/" + (f" (public: {s.public_url})" if s.public_url else "")]
        if self.dashboard:
            how = []
            if self.dashboard.local_accounts:
                how.append("local accounts")
            if self.dashboard.oidc:
                how.append(f"company sign-in ({self.dashboard.oidc.issuer})")
            lines.append(f"sign-in         : {', '.join(how) or 'none'}")
        else:
            lines.append("sign-in         : none - the dashboard is open to anyone who can reach it")
        lines.append(f"ingest tokens   : {len(s.ingest_tokens)}")
        if self.issuer:
            lines.append(f"issuer          : {len(self.issuer.trusted)} trusted login system(s), "
                         f"{len(self.issuer.ceilings)} ceiling(s)")
        lines.append(f"policy          : {len(self.policy.rules)} rule(s)"
                     + (f" ({self.policy.version})" if self.policy else ""))
        if self.gateway:
            routes = sum(len(u.routes) for u in self.gateway.upstreams)
            lines.append(f"gateway         : http://{self.gateway_address[0]}:{self.gateway_address[1]}/ - "
                         f"{len(self.gateway.upstreams)} upstream(s), {routes} route(s), {self.gateway.mode}")
        lines.append(f"alerts          : {', '.join(c.name for c in self.alert_channels) or 'none'}")
        lines.append(f"witnesses       : {', '.join(w.name for w in self.witnesses) or 'none'}")
        return lines


def _path(base: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (base / p)


def _scope(t: _Table) -> Scope:
    try:
        return Scope.of(operations=list(t.strings("operations")), targets=list(t.strings("targets")),
                        max_scale=t.get("max_scale", int, None), max_total=t.get("max_total", int, None),
                        irreversible_allowed=t.get("irreversible_allowed", bool, False),
                        constraints=list(t.strings("constraints")))
    except ValueError as exc:
        raise ConfigError(f"{t.where}: {exc}") from exc


def _server(t: _Table, base: Path) -> ServerConfig:
    database = t.get("database", str, "segurai.db")
    database_env = t.get("database_env", str, "")
    if database_env:
        # A PostgreSQL URL usually carries a password, so it comes from the
        # environment like every other secret.
        database = os.environ.get(database_env, "")
        if not database:
            raise ConfigError(f"server.database_env: {database_env} is not set")
        if "database" in t.data:
            raise ConfigError("server: give database or database_env, not both")
    if "://" in database:
        if not is_database_url(database):
            raise ConfigError("server.database must be a file path or a postgresql:// URL")
        if not database_env and urlsplit(database).password:
            raise ConfigError("server.database: this URL contains a password. Put the URL in an "
                              "environment variable and name it with database_env instead.")
    else:
        database = str(_path(base, database))
    tokens = tuple(os.environ.get(name, "") for name in t.strings("ingest_tokens_env"))
    missing = [n for n, v in zip(t.strings("ingest_tokens_env"), tokens, strict=True) if not v]
    if missing:
        raise ConfigError(f"server.ingest_tokens_env: {missing} not set")
    if any(len(tok) < 16 for tok in tokens):
        raise ConfigError("server.ingest_tokens_env: every ingest token must be at least 16 characters")
    port = t.get("port", int, 8700)
    if not 0 <= port <= 65535:
        raise ConfigError("server.port must be between 0 and 65535")
    public_url = t.get("public_url", str, "").rstrip("/")
    if public_url and not public_url.startswith(("https://", "http://")):
        raise ConfigError("server.public_url must start with https://")
    config = ServerConfig(database=database, key=_path(base, t.get("key", str, "segurai.key")),
                          host=t.get("host", str, "127.0.0.1"), port=port, public_url=public_url,
                          trust_proxy=t.get("trust_proxy", bool, False), ingest_tokens=tokens)
    t.done()
    return config


def _dashboard(t: _Table, server: ServerConfig) -> DashboardConfig:
    from .collector.auth import ROLES, OidcLogin

    config = DashboardConfig(local_accounts=t.get("local_accounts", bool, True),
                             session_hours=float(t.get("session_hours", (int, float), 12)))
    if not 0.25 <= config.session_hours <= 24 * 7:
        raise ConfigError("dashboard.session_hours must be between 0.25 and 168")
    o = t.table("oidc")
    if o is not None:
        role_map: dict[str, tuple[str, ...]] = {}
        rm = o.table("role_map")
        if rm is not None:
            for role in list(rm.data):
                if role not in ROLES:
                    raise ConfigError(f"dashboard.oidc.role_map: unknown role {role!r}; roles are {ROLES}")
                role_map[role] = rm.strings(role)
            rm.done()
        if not server.public_url:
            raise ConfigError("dashboard.oidc needs server.public_url (the address people open)")
        try:
            config.oidc = OidcLogin(
                issuer=o.get("issuer", str), client_id=o.get("client_id", str),
                client_secret=o.secret("client_secret"), redirect_url=server.public_url + "/auth/callback",
                role_map=role_map, default_role=o.get("default_role", str, ""),
                allowed_domains=o.strings("allowed_domains"), groups_claim=o.get("groups_claim", str, "groups"),
                display_name=o.get("display_name", str, "your company login"))
        except ValueError as exc:
            raise ConfigError(f"dashboard.oidc: {exc}") from exc
        o.done()
    if not config.local_accounts and config.oidc is None:
        raise ConfigError("dashboard: with local_accounts = false, configure [dashboard.oidc] or nobody can sign in")
    t.done()
    return config


def _issuer(t: _Table) -> IssuerConfig:
    from .identity import TrustedIssuer
    from .issuer import Ceiling

    config = IssuerConfig(default_ttl=timedelta(minutes=t.get("default_ttl_minutes", int, 60)),
                          max_ttl=timedelta(minutes=t.get("max_ttl_minutes", int, 480)))
    if config.default_ttl > config.max_ttl or config.default_ttl.total_seconds() <= 0:
        raise ConfigError("issuer: default_ttl_minutes must be above zero and at most max_ttl_minutes")
    for tt in t.tables("trusted"):
        try:
            audience = tt.get("audience", (str, list))
            config.trusted.append(TrustedIssuer(
                issuer=tt.get("issuer", str), audience=tuple(audience) if isinstance(audience, list) else audience,
                jwks_url=tt.get("jwks_url", str, None), principal_claim=tt.get("principal_claim", str, "email"),
                groups_claim=tt.get("groups_claim", str, "groups"),
                require_verified_email=tt.get("require_verified_email", bool, True),
                allowed_domains=tt.strings("allowed_domains")))
        except ValueError as exc:
            raise ConfigError(f"{tt.where}: {exc}") from exc
        tt.done()
    for ct in t.tables("ceilings"):
        name = ct.get("name", str)
        principals, groups = ct.strings("principals"), ct.strings("groups")
        config.ceilings.append(Ceiling(name=name, principals=principals, groups=groups, scope=_scope(ct)))
        ct.done()
    if not config.trusted:
        raise ConfigError("issuer: at least one [[issuer.trusted]] login system is required")
    if not config.ceilings:
        raise ConfigError("issuer: at least one [[issuer.ceilings]] is required; without one nobody gets anything")
    t.done()
    return config


def _gateway(t: _Table) -> tuple[Any, tuple[str, int]]:
    from .gateway import GatewayConfig, GatewayConfigError, Route, Upstream

    upstreams = []
    for ut in t.tables("upstreams"):
        headers = {}
        ht = ut.table("headers_env")
        if ht is not None:
            for header in list(ht.data):
                env = ht.get(header, str)
                value = os.environ.get(env)
                if not value:
                    raise ConfigError(f"{ht.where}.{header} names {env}, which is not set")
                headers[header] = value
            ht.done()
        routes = []
        for rt in ut.tables("routes"):
            evidence = {}
            et = rt.table("evidence")
            if et is not None:
                for name in list(et.data):
                    evidence[name] = et.get(name, str)
                et.done()
            try:
                routes.append(Route(method=rt.get("method", str), path=rt.get("path", str),
                                    operation=rt.get("operation", str), resource=rt.get("resource", str),
                                    scale=rt.get("scale", (int, str), 1),
                                    irreversible=rt.get("irreversible", bool, False), evidence=evidence))
            except GatewayConfigError as exc:
                raise ConfigError(f"{rt.where}: {exc}") from exc
            rt.done()
        try:
            upstreams.append(Upstream(name=ut.get("name", str), prefix=ut.get("prefix", str), url=ut.get("url", str),
                                      routes=tuple(routes), headers=headers,
                                      timeout=float(ut.get("timeout_seconds", (int, float), 30))))
        except GatewayConfigError as exc:
            raise ConfigError(f"{ut.where}: {exc}") from exc
        ut.done()
    try:
        config = GatewayConfig(upstreams=tuple(upstreams), mode=t.get("mode", str, "enforce"))
    except GatewayConfigError as exc:
        raise ConfigError(f"gateway: {exc}") from exc
    if not upstreams:
        raise ConfigError("gateway: at least one [[gateway.upstreams]] is required")
    address = (t.get("host", str, "127.0.0.1"), t.get("port", int, 8800))
    t.done()
    return config, address


def _alerts(t: _Table) -> tuple[list, timedelta]:
    from .alerts import EmailChannel, SlackChannel, WebhookChannel

    channels = []
    for ct in t.tables("channels"):
        kind = ct.get("type", str)
        common = {"name": ct.get("name", str), "on": ct.strings("on", ("violation", "blocked", "tamper"))}
        try:
            if kind == "slack":
                channels.append(SlackChannel(url=ct.secret("url"), **common))
            elif kind == "webhook":
                channels.append(WebhookChannel(url=ct.get("url", str), secret=ct.secret("secret"), **common))
            elif kind == "email":
                channels.append(EmailChannel(
                    host=ct.get("host", str), port=ct.get("port", int, 587), sender=ct.get("sender", str),
                    to=ct.strings("to"), username=ct.get("username", str, None),
                    password=ct.secret("password", required=False), security=ct.get("security", str, "starttls"),
                    **common))
            else:
                raise ConfigError(f"{ct.where}.type must be slack, webhook or email")
        except ValueError as exc:
            raise ConfigError(f"{ct.where}: {exc}") from exc
        ct.done()
    names = [c.name for c in channels]
    if len(set(names)) != len(names):
        raise ConfigError("alerts.channels: names must be unique")
    every = timedelta(minutes=t.get("audit_every_minutes", int, 5))
    t.done()
    return channels, every


def _witnesses(t: _Table, base: Path) -> tuple[list, timedelta]:
    from .witness import FileWitness, WebhookWitness

    sinks = []
    for st in t.tables("sinks"):
        kind = st.get("type", str)
        name = st.get("name", str, kind)
        try:
            if kind == "file":
                sinks.append(FileWitness(path=_path(base, st.get("path", str)), name=name))
            elif kind == "webhook":
                sinks.append(WebhookWitness(url=st.get("url", str), secret=st.secret("secret"), name=name))
            else:
                raise ConfigError(f"{st.where}.type must be file or webhook")
        except ValueError as exc:
            raise ConfigError(f"{st.where}: {exc}") from exc
        st.done()
    every = timedelta(minutes=t.get("every_minutes", int, 60))
    if every.total_seconds() < 60:
        raise ConfigError("witness.every_minutes must be at least 1")
    t.done()
    return sinks, every


def load_config(path: str | Path) -> Config:
    """Read and check a configuration file. Raises :class:`ConfigError` naming the problem."""
    path = Path(path)
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path} is not valid TOML: {exc}") from exc
    base = path.resolve().parent
    root = _Table(raw, "segurai.toml")
    server = _server(root.table("server") or _Table({}, "server"), base)
    config = Config(path=path, server=server)

    if (t := root.table("dashboard")) is not None:
        config.dashboard = _dashboard(t, server)
    if (t := root.table("issuer")) is not None:
        config.issuer = _issuer(t)
    if (t := root.table("policy")) is not None:
        try:
            config.policy = Policy.from_dict(t.data)
        except PolicyError as exc:
            raise ConfigError(f"policy: {exc}") from exc
    if (t := root.table("gateway")) is not None:
        config.gateway, config.gateway_address = _gateway(t)
    if (t := root.table("alerts")) is not None:
        config.alert_channels, config.audit_every = _alerts(t)
    if (t := root.table("witness")) is not None:
        config.witnesses, config.witness_every = _witnesses(t, base)
    root.done()

    loopback = server.host in ("127.0.0.1", "localhost", "::1")
    if not loopback and config.dashboard is None:
        raise ConfigError("server.host is reachable from other machines, but [dashboard] has no sign-in: "
                          "anyone could read every request. Add [dashboard], or listen on 127.0.0.1.")
    if not loopback and not server.ingest_tokens:
        raise ConfigError("server.host is reachable from other machines, but no ingest token is set: anyone "
                          "could send forged records. Set server.ingest_tokens_env.")
    return config


EXAMPLE = '''# Segurai configuration. Secrets never go in this file: name the environment
# variable that holds them (..._env). Every setting is checked; a typo is an error.
#   segurai config check --config segurai.toml
#   segurai serve        --config segurai.toml

[server]
database = "segurai.db"                 # a SQLite file, or postgresql://user@host/db
# database_env = "SEGURAI_DATABASE_URL" # or: the variable holding a PostgreSQL URL with its password
key = "segurai.key"                     # the organisation's PRIVATE key; created if missing
host = "127.0.0.1"                      # put a TLS reverse proxy in front for anything wider
port = 8700
public_url = ""                         # e.g. "https://segurai.acme.example" (needed for company sign-in)
ingest_tokens_env = []                  # e.g. ["SEGURAI_INGEST_TOKEN"]: tokens agents send spans with

[dashboard]
local_accounts = true                   # add people with: segurai users add --config segurai.toml ...
session_hours = 12

# [dashboard.oidc]                      # sign in with the company login system
# issuer = "https://login.acme.example"
# client_id = "segurai-dashboard"
# client_secret_env = "SEGURAI_OIDC_SECRET"
# allowed_domains = ["acme.example"]
# default_role = "viewer"               # "" turns away anyone no group below maps
# [dashboard.oidc.role_map]
# admin = ["segurai-admins"]
# auditor = ["security"]

# [issuer]                              # POST /v1/sessions: roots only for proven people
# [[issuer.trusted]]
# issuer = "https://login.acme.example"
# audience = "segurai-agents"
# allowed_domains = ["acme.example"]
# [[issuer.ceilings]]                   # the most a group can ever be granted
# name = "sales"
# groups = ["sales"]
# operations = ["read", "search", "archive"]
# targets = ["crm.*"]
# max_scale = 50

[[policy.rules]]                        # organisation rules no request can override
name = "nobody deletes payroll"
targets = ["hr.payroll"]
operations = ["delete"]
effect = "deny"

# [gateway]                             # agents reach real systems only through here
# host = "127.0.0.1"
# port = 8800
# mode = "enforce"
# [[gateway.upstreams]]
# name = "crm"
# prefix = "/crm"
# url = "https://crm.internal.acme.example"
# [gateway.upstreams.headers_env]
# Authorization = "CRM_AUTHORIZATION"   # the CRM credential the gateway adds; agents never see it
# [[gateway.upstreams.routes]]
# method = "DELETE"
# path = "/opportunities/{id}"
# operation = "delete"
# resource = "crm.opportunities"
# irreversible = true

# [alerts]
# [[alerts.channels]]
# name = "security"
# type = "slack"                        # slack | webhook | email
# url_env = "SLACK_WEBHOOK_URL"
# on = ["violation", "blocked", "tamper"]

[witness]                               # checkpoints published outside the database
every_minutes = 60
[[witness.sinks]]
type = "file"
path = "witness/checkpoints.log"        # better: storage this server can append to but not rewrite
'''


def example(*, docker: bool = False, postgres: bool = False) -> str:
    """The commented starting configuration, adjusted for where it will run.

    ``docker``: listen on every interface inside the container (compose
    publishes the ports on 127.0.0.1 only), which needs an ingest token, read
    from SEGURAI_INGEST_TOKEN. ``postgres``: take the database URL from
    SEGURAI_DATABASE_URL instead of using a SQLite file.
    """
    text = EXAMPLE
    replacements = []
    if docker:
        replacements += [
            ('host = "127.0.0.1"                      # put a TLS reverse proxy in front for anything wider',
             'host = "0.0.0.0"                        # inside the container; compose publishes it on 127.0.0.1'),
            ('ingest_tokens_env = []                  # e.g. ["SEGURAI_INGEST_TOKEN"]: tokens agents send spans with',
             'ingest_tokens_env = ["SEGURAI_INGEST_TOKEN"]   # the token agents send spans with'),
            ('# host = "127.0.0.1"\n# port = 8800', '# host = "0.0.0.0"\n# port = 8800'),
        ]
    if postgres:
        replacements += [
            ('database = "segurai.db"                 # a SQLite file, or postgresql://user@host/db\n'
             '# database_env = "SEGURAI_DATABASE_URL" # or: the variable holding a PostgreSQL URL with its password',
             'database_env = "SEGURAI_DATABASE_URL"   # the variable holding the PostgreSQL URL, password included'),
        ]
    for old, new in replacements:
        if text.count(old) != 1:                       # pragma: no cover - caught by the tests
            raise AssertionError(f"example(): {old!r} not found once")
        text = text.replace(old, new)
    return text
