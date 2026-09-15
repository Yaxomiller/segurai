"""The developer-facing API.

A handful of things to learn, and that is deliberate - adoption dies on
surface area:

    with warrant.session(principal=..., request=..., scope=...) as s:  # a human asks
        ...

    @warrant.agent("crm_agent")                                         # an agent hop
    def crm_agent(...): ...

    warrant.act("delete", "crm.opportunities", scale=400)               # record an action

    @warrant.tool(ActionSpec("delete", "crm.{table}", scale=count("ids")))
    def delete_records(table, ids): ...                                 # or guard a tool

How a call flows through this file:

    session()  The Authority mints a ROOT warrant from the human's request.
               It is saved to the Store and bound as the "current" warrant.
    @agent     Each call ATTENUATES the current warrant into a child for this
               agent, saves it, and binds it while the agent runs.
    act()      Checks the action against the current warrant's scope (Tier 1),
               saves it with the verdict, and - in ENFORCE mode only - raises
               if it was out of bounds.
    @tool      Same check as act(), but made BEFORE the tool body runs, so
               ENFORCE mode stops a bad call before it does any damage.

Listeners (see :class:`Listener`) are told about each step. That is how
OpenTelemetry spans get emitted without this file knowing anything about
OpenTelemetry.

Default mode is OBSERVE: violations are recorded, nothing is blocked. That is
not timidity, it is the adoption path. Nobody lets an unproven library block
production traffic, but they will happily let it watch - and watching is what
produces the evidence that earns the right to enforce later.
"""

from __future__ import annotations

import functools
import inspect
import logging
import uuid
from contextlib import ExitStack, contextmanager, nullcontext
from datetime import timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Callable, ContextManager, Iterator, Mapping, TypeVar

from .actions import ActionSpec, ActionSpecError
from .authority import DEFAULT_TTL, Authority
from .collector.store import Store
from .context import bind_warrant, current_warrant
from .models import ActionRecord, Scope, Warrant, utcnow

__all__ = [
    "Mode", "configure", "session", "agent", "delegate", "act", "tool", "tool_span",
    "check_tool_call", "ViolationError", "Session", "Listener", "add_listener",
    "remove_listener",
]

F = TypeVar("F", bound=Callable[..., Any])
_log = logging.getLogger("warrant")


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


class Listener:
    """Something that wants to know what the runtime is doing.

    Subclass it and override only what you need; every method has a
    do-nothing default. The ``*_scope`` hooks are context managers wrapped
    around the work they describe, so a listener can time it and nest inside
    it - OpenTelemetry uses them to open and close spans.

    A listener that raises is logged and ignored: observability code must
    never break the agent it is observing.
    """

    def session_scope(self, session: "Session") -> ContextManager[Any]:
        return nullcontext()

    def agent_scope(self, warrant: Warrant) -> ContextManager[Any]:
        return nullcontext()

    def tool_scope(self, tool_name: str, warrant: Warrant) -> ContextManager[Any]:
        return nullcontext()

    def on_action(self, record: ActionRecord, warrant: Warrant) -> None:
        pass


@contextmanager
def _guarded(listener: Listener, hook: str, *args: Any) -> Iterator[None]:
    """Run one listener hook around a block, containing any error the LISTENER raises.

    Errors raised by the block itself (the user's code) always propagate
    untouched; only failures inside the listener are swallowed and logged.
    """
    try:
        cm = getattr(listener, hook)(*args)
        cm.__enter__()
    except Exception:
        _log.warning("warrant listener %r failed entering %s", listener, hook, exc_info=True)
        yield
        return
    try:
        yield
    except BaseException as exc:
        try:
            cm.__exit__(type(exc), exc, exc.__traceback__)
        except Exception:
            _log.warning("warrant listener %r failed leaving %s", listener, hook, exc_info=True)
        raise
    else:
        try:
            cm.__exit__(None, None, None)
        except Exception:
            _log.warning("warrant listener %r failed leaving %s", listener, hook, exc_info=True)


class _Runtime:
    """Process-wide settings: where records go, who signs, and the mode."""

    def __init__(self) -> None:
        self.store: Store | None = None
        self.authority: Authority | None = None
        self.mode: Mode = Mode.OBSERVE
        self.listeners: list[Listener] = []

    def ensure(self) -> tuple[Store, Authority]:
        """The store and authority, falling back to in-memory ones if unconfigured."""
        if self.store is None:
            self.store = Store(":memory:")
        if self.authority is None:
            self.authority = Authority()
        return self.store, self.authority

    @contextmanager
    def hooks(self, hook: str, *args: Any) -> Iterator[None]:
        """Enter ``hook`` on every listener around a block (exited in reverse order)."""
        with ExitStack() as stack:
            for listener in list(self.listeners):
                stack.enter_context(_guarded(listener, hook, *args))
            yield

    def notify_action(self, record: ActionRecord, warrant: Warrant) -> None:
        for listener in list(self.listeners):
            try:
                listener.on_action(record, warrant)
            except Exception:
                _log.warning("warrant listener %r failed on_action", listener, exc_info=True)


_rt = _Runtime()


def configure(
    store: Store | str | Path | None = None,
    authority: Authority | None = None,
    mode: Mode | str = Mode.OBSERVE,
    key: str | Path | None = None,
) -> None:
    """Point the runtime at a store and an authority, and set the mode.

    Calling this is optional; without it everything runs against an in-memory
    store and a throwaway key, which is right for a first five-minute try.

    ``key`` is a signing-key file, created if missing. When ``store`` is a
    file path and neither ``authority`` nor ``key`` is given, the key lives
    beside the database (``warrant.db`` -> ``warrant.key``). Keeping the key
    is what lets ``warrant verify`` check signatures in a later run.
    """
    if isinstance(store, (str, Path)):
        path = str(store)
        if authority is None and key is None and path != ":memory:":
            key = Path(path).with_suffix(".key")
        store = Store(path)
    if key is not None and authority is None:
        authority = Authority.load_or_create(key)
    if store is not None:
        _rt.store = store
    if authority is not None:
        _rt.authority = authority
    _rt.mode = Mode(mode)


def add_listener(listener: Listener) -> None:
    """Start telling ``listener`` about sessions, agent hops and actions."""
    if listener not in _rt.listeners:
        _rt.listeners.append(listener)


def remove_listener(listener: Listener) -> None:
    if listener in _rt.listeners:
        _rt.listeners.remove(listener)


class Session:
    """Handle for an active session."""

    __slots__ = ("session_id", "principal", "request", "root_warrant")

    def __init__(self, session_id: str, principal: str, request: str, root: Warrant):
        self.session_id = session_id
        self.principal = principal
        self.request = request
        self.root_warrant = root

    def __repr__(self) -> str:
        return f"<Session {self.session_id} {self.principal!r} {self.request!r}>"

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

    root = authority.issue_root(session_id=sid, principal=principal, scope=scope,
                                ttl=ttl, now=started)
    store.put_session(sid, principal, request, contract, started)
    store.put_warrant(root)

    handle = Session(sid, principal, request, root)
    with _rt.hooks("session_scope", handle), bind_warrant(root):
        yield handle


@contextmanager
def delegate(holder: str, scope: Scope | None = None, ttl: timedelta | None = None,
             parent: Warrant | None = None) -> Iterator[Warrant]:
    """One agent hop as a ``with`` block: derive a child warrant and bind it.

    ``parent`` defaults to the current warrant. Pass one explicitly when the
    hop crossed a thread or process boundary - for example a warrant that
    arrived with a queue message and was rebuilt with ``import_warrant``.
    The authority verifies the parent before deriving from it.
    """
    store, authority = _rt.ensure()
    parent = parent if parent is not None else current_warrant()
    child = authority.attenuate(parent, holder=holder, scope=scope, ttl=ttl)
    store.put_warrant(child)
    with bind_warrant(child), _rt.hooks("agent_scope", child):
        yield child


def _reject_generators(fn: Callable[..., Any], what: str) -> None:
    if inspect.isgeneratorfunction(fn) or inspect.isasyncgenfunction(fn):
        raise TypeError(
            f"{what} cannot wrap a generator function yet: the warrant would leak "
            f"into the caller between yields. Wrap the code that consumes it instead."
        )


def agent(name: str, scope: Scope | None = None, ttl: timedelta | None = None) -> Callable[[F], F]:
    """Mark a function as an agent hop.

    On every call this attenuates the current warrant to a child held by
    ``name``. If ``scope`` is given it may leave fields out (they inherit) and
    must otherwise be a subset of the caller's - an agent cannot grant itself
    more than it was handed, and attempting to do so raises.

    Works on plain and ``async`` functions.
    """

    def decorator(fn: F) -> F:
        _reject_generators(fn, f"@warrant.agent({name!r})")

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                # The hop starts when the coroutine RUNS, not when it is
                # created. Binding at creation time would unbind the child
                # warrant before the agent's first line executed, and every
                # action would be credited to the parent instead.
                with delegate(name, scope=scope, ttl=ttl):
                    return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with delegate(name, scope=scope, ttl=ttl):
                return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator


def _record(w: Warrant, operation: str, resource: str, scale: int, irreversible: bool,
            ok: bool, reason: str | None, detail: dict[str, Any]) -> ActionRecord:
    """Save one action with its verdict, tell listeners, and enforce if configured."""
    store, _ = _rt.ensure()
    # Decide up front whether this action will be stopped, so the stored
    # record says so: "flagged but went ahead" and "stopped" are different
    # facts in an audit.
    blocked = not ok and _rt.mode is Mode.ENFORCE
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
        blocked=blocked,
        detail=detail,
    )
    # Saved BEFORE raising, so a blocked attempt is still on the record.
    store.put_action(record)
    _rt.notify_action(record, w)

    if blocked:
        raise ViolationError(record)
    return record


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
    Extra keyword arguments are kept as free-form ``detail``.
    """
    w = current_warrant()
    ok, reason = w.scope.permits(operation, resource, scale=scale, irreversible=irreversible)
    return _record(w, operation, resource, scale, irreversible, ok, reason, detail)


def check_tool_call(tool_name: str, spec: ActionSpec, arguments: Mapping[str, Any],
                    **detail: Any) -> ActionRecord:
    """Turn one tool call into a checked, recorded action.

    Every integration - the @tool decorator, the LangGraph ToolGuard, the MCP
    client - funnels through here, so a tool call is judged the same way
    wherever it was intercepted.
    """
    w = current_warrant()
    detail = {"tool": tool_name, **detail}
    try:
        action = spec.resolve(arguments)
    except ActionSpecError as exc:
        # We cannot tell what this call would touch - which table, how many
        # rows. An action nobody can describe is not one anybody authorized,
        # so it is recorded as a violation instead of being waved through.
        op = spec.operation if isinstance(spec.operation, str) and "{" not in spec.operation else "unknown"
        return _record(w, op, f"tool.{tool_name}", 1, False, False, str(exc), detail)

    ok, reason = w.scope.permits(action.operation, action.resource,
                                 scale=action.scale, irreversible=action.irreversible)
    return _record(w, action.operation, action.resource, action.scale,
                   action.irreversible, ok, reason, detail)


@contextmanager
def tool_span(tool_name: str) -> Iterator[Warrant]:
    """Wrap one tool call so listeners can measure it (an ``execute_tool`` span)."""
    w = current_warrant()
    with _rt.hooks("tool_scope", tool_name, w):
        yield w


def _call_arguments(signature: inspect.Signature, args: tuple, kwargs: dict) -> dict[str, Any]:
    """Map a call's positional and keyword arguments onto parameter names."""
    bound = signature.bind(*args, **kwargs)
    bound.apply_defaults()
    arguments: dict[str, Any] = {}
    for name, value in bound.arguments.items():
        kind = signature.parameters[name].kind
        if kind is inspect.Parameter.VAR_KEYWORD:
            arguments.update(value)       # **kwargs: flatten into the top level
        else:
            arguments[name] = value
    return arguments


def tool(spec: ActionSpec, name: str | None = None) -> Callable[[F], F]:
    """Guard a tool function: check and record each call before the body runs.

        @warrant.tool(ActionSpec("delete", "crm.{table}", scale=count("ids"),
                                 irreversible=True))
        def delete_records(table: str, ids: list[int]) -> int: ...

    In ENFORCE mode an out-of-bounds call raises :class:`ViolationError` and
    the body never executes. Works on plain and ``async`` functions.
    """

    def decorator(fn: F) -> F:
        _reject_generators(fn, "@warrant.tool")
        tool_name = name or fn.__name__
        signature = inspect.signature(fn)

        if inspect.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                arguments = _call_arguments(signature, args, kwargs)
                with tool_span(tool_name):
                    check_tool_call(tool_name, spec, arguments)
                    return await fn(*args, **kwargs)

            return async_wrapper  # type: ignore[return-value]

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            arguments = _call_arguments(signature, args, kwargs)
            with tool_span(tool_name):
                check_tool_call(tool_name, spec, arguments)
                return fn(*args, **kwargs)

        return wrapper  # type: ignore[return-value]

    return decorator
