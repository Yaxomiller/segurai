"""One delegated warrant per (warrant in force, agent): an agent's hop in the chain.

Framework integrations see tool calls from many agents. Each agent gets its
own warrant, delegated from the one in force when its run started, so the
chain reads person -> agent -> action. The warrant is made the first time
the agent acts and reused after that, until it expires.
"""

from __future__ import annotations

import threading

from ..models import Warrant
from ..runtime import _rt

__all__ = ["hop"]

_MAX = 10_000                     # forget them all past this: they are cheap to remake
_hops: dict[tuple[str, str], Warrant] = {}
_lock = threading.Lock()


def hop(parent: Warrant, agent_name: str) -> Warrant:
    """The warrant ``agent_name`` acts under, delegated from ``parent``."""
    if parent.holder == agent_name:
        return parent
    key = (parent.warrant_id, agent_name)
    with _lock:
        child = _hops.get(key)
        if child is None or child.is_expired():
            store, authority = _rt.ensure()
            child = authority.attenuate(parent, holder=agent_name)
            store.put_warrant(child)
            if len(_hops) >= _MAX:
                _hops.clear()
            _hops[key] = child
        return child
