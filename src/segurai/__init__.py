"""warrant - provenance and authority for AI agent chains.

Records what a human asked for, records what the agents actually did, and links
the two so the question "who authorized this?" has an answer.

    import segurai
    from segurai import Scope

    segurai.configure(store="segurai.db")

    scope = Scope.of(
        operations=["read", "update", "delete"],
        targets=["crm.*"],
        max_scale=50,
    )

    with segurai.session(
        principal="sarah@company.com",
        request="clean up our old sales records",
        scope=scope,
    ) as s:
        run_assistant()
        print(segurai.render(s.session_id))

Map of the package:

    models.py        Scope, Warrant, ActionRecord - the data
    authority.py     signing keys; minting, attenuating, verifying warrants
    context.py       which warrant is "current"; moving one between processes
    actions.py       ActionSpec - describing a tool call as an action
    runtime.py       the API above: session, agent, act, tool, configure
    scenarios.py     the Tier 1 scenario suite (milestone M2)
    collector/       SQLite storage, the tamper-evident log, chain rendering
    instrument/      optional integrations: OpenTelemetry, LangGraph, MCP
    cli.py           the `segurai` command
"""

from ._version import __version__
from .actions import ActionSpec, ActionSpecError, arg, count
from .authority import Authority, ChainError, verify_chain
from .collector.chain import chain_summary, render_session
from .collector.ledger import AuditReport, Checkpoint
from .collector.store import Store
from .context import (
    NoWarrantError,
    bind_warrant,
    current_warrant,
    export_chain,
    export_warrant,
    import_chain,
    import_warrant,
)
from .models import ActionRecord, Check, Finding, Scope, Warrant
from .runtime import (
    Listener,
    Mode,
    Session,
    ViolationError,
    act,
    add_listener,
    agent,
    check_tool_call,
    configure,
    delegate,
    remove_listener,
    resume,
    session,
    tool,
    tool_span,
)
from .runtime import _rt as _runtime

__all__ = [
    "__version__",
    # runtime
    "configure", "session", "agent", "delegate", "act", "tool", "tool_span",
    "check_tool_call", "Mode", "Session", "ViolationError",
    "Listener", "add_listener", "remove_listener",
    # describing tool calls
    "ActionSpec", "ActionSpecError", "count", "arg",
    # model
    "Scope", "Check", "Finding", "Warrant", "ActionRecord",
    # authority
    "Authority", "ChainError", "verify_chain",
    # context
    "current_warrant", "bind_warrant", "export_warrant", "import_warrant",
    "export_chain", "import_chain", "resume",
    "NoWarrantError",
    # storage and reporting
    "Store", "render", "summary", "verify_session", "audit", "checkpoint",
    "AuditReport", "Checkpoint",
]


def render(session_id: str, show_scopes: bool = True, charset: str = "auto") -> str:
    """Render a session's delegation tree using the configured store.

    ``charset="auto"`` draws the tree with Unicode lines when stdout can show
    them and falls back to plain ASCII when it cannot.
    """
    store, _ = _runtime.ensure()
    return render_session(store, session_id, show_scopes=show_scopes, charset=charset)


def summary(session_id: str) -> dict:
    """Machine-readable summary of a session."""
    store, _ = _runtime.ensure()
    return chain_summary(store, session_id)


def verify_session(session_id: str, allow_expired: bool = True) -> list[str]:
    """Verify every root-to-leaf chain in a session.

    Returns a list of problems; empty means every chain is signed, correctly
    linked, and attenuated at every hop. Expired warrants are tolerated by
    default because audits happen after the fact - what matters is that the
    chain was valid when it was used.
    """
    store, authority = _runtime.ensure()
    warrants = store.warrants_for_session(session_id)
    problems: list[str] = []

    parents = {w.parent_id for w in warrants if w.parent_id}
    leaves = [w for w in warrants if w.warrant_id not in parents]

    for leaf in leaves:
        try:
            chain = store.chain_to(leaf.warrant_id)
            verify_chain(chain, authority, allow_expired=allow_expired)
        except (ChainError, ValueError) as exc:
            problems.append(f"{leaf.holder} [{leaf.warrant_id}]: {exc}")
    return problems


def audit(verify_signatures: bool = True) -> AuditReport:
    """Check the tamper-evident log of the configured store.

    Reports any record that was edited or deleted, any entry removed from the
    log, and whether the signed checkpoints still hold. With
    ``verify_signatures=False`` the checkpoint signatures are not checked -
    useful only when the key is unavailable, and the report says so.
    """
    store, authority = _runtime.ensure()
    return store.audit(authority if verify_signatures else None)


def checkpoint() -> Checkpoint:
    """Sign the current head of the log, so later rewrites of it are detectable."""
    store, authority = _runtime.ensure()
    return store.put_checkpoint(authority)
