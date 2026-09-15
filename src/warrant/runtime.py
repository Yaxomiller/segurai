"""The developer-facing API.

Three things to learn, and that is deliberate - adoption dies on surface area:

    with warrant.session(principal=..., request=..., scope=...) as s:
        ...

    @warrant.agent("crm_agent")
    def crm_agent(...): ...

    warrant.act("delete", "crm.opportunities", scale=400)

Default mode is OBSERVE: violations are recorded, nothing is blocked. That is
not timidity, it is the adoption path. Nobody lets an unproven library block
production traffic, but they will happily let it watch - and watching is what
produces the evidence that earns the right to enforce later.
"""

from __future__ import annotations

import functools
import uuid
from contextlib import contextmanager
from datetime import timedelta
from enum import Enum
from typing import Any, Callable, Iterator, TypeVar

from .authority import Authority, DEFAULT_TTL
from .context import bind_warrant, current_warrant
from .collector.store import Store
from .models import ActionRecord, Scope, Warrant, utcnow

__all__ = ["Mode", "configure", "session", "agent", "act", "ViolationError", "Session"]

F = TypeVar("F", bound=Callable[..., Any])


class Mode(str, Enum):
    OBSERVE = "observe"   # record everything, block nothing
    ENFORCE = "enforce"   # raise on violation


class ViolationError(PermissionError):
    """Raised in ENFORCE mode when an action falls outside its warrant."""

    def __init__(self, record: ActionRecord):
        self.record = record
        super().__init__(
            f"{record.actor} attempted {record.operation} on {record.resource} "
            f"(scale={record.scale}): {record.violation}"
        )


class _Runtime:
    def __init__(self) -> None:
        self.store: Store | None = None
        self.authority: Authority | None = None
        self.mode: Mode = Mode.OBSERVE

    def ensure(self) -> tuple[Store, Authority]:
        if self.store is None:
            self.store = Store(":memory:")
        if self.authority is None:
            self.authority = Authority()
        return self.store, self.authority


_rt = _Runtime()


def configure(
    store: Store | str | None = None,
    authority: Authority | None = None,
    mode: Mode | str = Mode.OBSERVE,
) -> None:
    """Point the runtime at a store and an authority.

    Calling this is optional; without it everything runs against an in-memory
    store, which is the right default for a first five-minute try.
    """
    if isinstance(store, str):
        store = Store(store)
    if store is not None:
        _rt.store = store
    if authority is not None:
        _rt.authority = authority
    _rt.mode = Mode(mode)


class Session:
    """Handle for an active session."""

    __slots__ = ("session_id", "principal", "request", "root_warrant")

    def __init__(self, session_id: str, principal: str, request: str, root: Warrant):
        self.session_id = session_id
        self.principal = principal
        self.request = request
        self.root_warrant = root

    def chain(self) -> list[Warrant]:
        store, _ = _rt.ensure()
        return store.warrants_for_session(self.session_id)

    def actions(self) -> list[ActionRecord]:
        store, _ = _rt.ensure()
        return store.actions_for_session(self.session_id)

    def violations(self) -> list[ActionRecord]:
        store, _ = _rt.ensure()
        return store.violations(self.session_id)


@contextmanager
def session(
    principal: str,
    request: str,
    scope: Scope,
    contract: dict | None = None,
    ttl: timedelta = DEFAULT_TTL,
    session_id: str | None = None,
) -> Iterator[Session]:
    """Open a session from a human request.

    ``scope`` is what the principal is understood to have authorized. At this
    milestone you pass it explicitly; the intent compiler that derives it from
    ``request`` automatically arrives in M1, and ``contract`` is where its
    structured output will live.
    """
    store, authority = _rt.ensure()
    sid = session_id or f"ses_{uuid.uuid4().hex[:16]}"
    started = utcnow()

    root = authority.issue_root(
        session_id=sid, principal=principal, scope=scope, ttl=ttl, now=started
    )

    store.put_session(sid, principal, request, contract, started)
    store.put_warrant(root)

    handle = Session(sid, principal, request, root)
    with bind_warrant(root):
        yield handle


def agent(name: str, scope: Scope | None = None, ttl: timedelta | None = None) -> Callable[[F], F]:
    """Mark a function as an agent hop.

    On every call this attenuates the current warrant to a child held by
    ``name``. If ``scope`` is given it must be a subset of the caller's - an
    agent cannot grant itself more than it was handed, and attempting to do so
    raises rather than silently clamping.
    """

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            store, authority = _rt.ensure()
            parent = current_warrant()
            child = authority.attenuate(parent, holder=name, scope=scope, ttl=ttl)
            store.put_warrant(child)
            with bind_warrant(child):
                return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def act(
    operation: str,
    resource: str,
    scale: int = 1,
    irreversible: bool = False,
    **detail: Any,
) -> ActionRecord:
    """Record an action and check it against the warrant in context.

    Returns the record. In OBSERVE mode a violation is recorded and returned
    with ``allowed=False``; in ENFORCE mode it raises :class:`ViolationError`.
    """
    store, _ = _rt.ensure()
    w = current_warrant()

    ok, reason = w.scope.permits(operation, resource, scale=scale, irreversible=irreversible)

    record = ActionRecord(
        action_id=f"act_{uuid.uuid4().hex[:16]}",
        session_id=w.session_id,
        warrant_id=w.warrant_id,
        actor=w.holder,
        operation=operation,
        resource=resource,
        scale=scale,
        irreversible=irreversible,
        at=utcnow(),
        allowed=ok,
        violation=reason,
        detail=detail,
    )
    store.put_action(record)

    if not ok and _rt.mode is Mode.ENFORCE:
        raise ViolationError(record)
    return record
