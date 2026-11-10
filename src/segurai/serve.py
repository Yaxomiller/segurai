"""``segurai serve``: run a whole deployment from one configuration file.

One process runs everything a pilot needs, sharing one database:

    the dashboard and span ingest      server.port     (collector/server.py)
    the issuer                         POST /v1/sessions on the same port
    the gateway                        gateway.port    (gateway.py), when configured
    the alert worker                   in the background (alerts.py)
    the checkpoint worker              in the background (witness.py)

:func:`build` assembles everything from a :class:`Config` without starting
anything (so tests and ``segurai config check`` can inspect it); ``start``
and ``stop`` run it.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

from .authority import Authority
from .collector.store import Store
from .config import Config

__all__ = ["Deployment", "build"]

_log = logging.getLogger("segurai.serve")


@dataclass
class Deployment:
    config: Config
    store: Store
    authority: Authority
    server: Any                                     # CollectorServer
    gateway: Any = None                             # GatewayServer
    alerts: Any = None                              # AlertWorker
    checkpoints: Any = None                         # CheckpointWorker
    _threads: list[threading.Thread] = field(default_factory=list)

    @property
    def dashboard_url(self) -> str:
        host, port = self.server.server_address[:2]
        return f"http://{host}:{port}/"

    @property
    def gateway_url(self) -> str | None:
        if self.gateway is None:
            return None
        host, port = self.gateway.server_address[:2]
        return f"http://{host}:{port}/"

    def start(self) -> "Deployment":
        for target, name in ((self.server, "segurai-dashboard"), (self.gateway, "segurai-gateway")):
            if target is not None:
                thread = threading.Thread(target=target.serve_forever, kwargs={"poll_interval": 0.2},
                                          name=name, daemon=True)
                thread.start()
                self._threads.append(thread)
        if self.alerts is not None:
            self.alerts.start()
        if self.checkpoints is not None:
            self.checkpoints.start()
        return self

    def stop(self) -> None:
        if self.checkpoints is not None:
            self.checkpoints.stop()
        if self.alerts is not None:
            self.alerts.stop()
        for target in (self.gateway, self.server):
            if target is not None:
                target.shutdown()
                target.server_close()
        for thread in self._threads:
            thread.join(timeout=5)
        self.store.close()


def build(config: Config) -> Deployment:
    """Assemble a deployment from a checked configuration. Starts nothing."""
    from .alerts import AlertWorker
    from .collector.auth import WebAuth
    from .collector.server import CollectorServer
    from .witness import CheckpointWorker, FileWitness

    s = config.server
    store = Store(s.database)
    authority = Authority.load_or_create(s.key)
    verifier = authority.public_only()
    if config.policy:
        store.put_policy(config.policy)

    auth = None
    if config.dashboard is not None:
        auth = WebAuth(store, oidc=config.dashboard.oidc, local_accounts=config.dashboard.local_accounts,
                       session_hours=config.dashboard.session_hours,
                       cookie_secure=s.public_url.startswith("https://"))

    issuer = None
    if config.issuer is not None:
        from .identity import IdentityVerifier
        from .issuer import Issuer

        issuer = Issuer(authority, store, IdentityVerifier(config.issuer.trusted), config.issuer.ceilings,
                        default_ttl=config.issuer.default_ttl, max_ttl=config.issuer.max_ttl)

    witness_files = [str(w.path) for w in config.witnesses if isinstance(w, FileWitness)]
    server = CollectorServer((s.host, s.port), store, verifier=verifier, auth=auth, issuer=issuer,
                             ingest_tokens=s.ingest_tokens, signer=authority, witness_files=witness_files,
                             trust_proxy=s.trust_proxy)

    gateway = None
    if config.gateway is not None:
        from .gateway import GatewayServer

        gateway = GatewayServer(config.gateway_address, config.gateway, store, verifier, policy=config.policy)

    alerts = None
    if config.alert_channels:
        alerts = AlertWorker(store=store, channels=config.alert_channels, public_url=s.public_url,
                             verifier=verifier, audit_every=config.audit_every)
    checkpoints = None
    if config.witnesses:
        checkpoints = CheckpointWorker(store, authority, config.witnesses, every=config.witness_every)
    return Deployment(config=config, store=store, authority=authority, server=server, gateway=gateway,
                      alerts=alerts, checkpoints=checkpoints)
