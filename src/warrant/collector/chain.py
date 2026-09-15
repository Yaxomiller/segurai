"""Reconstructing and rendering a session's delegation tree.

The warrants of a session form a tree, not a line: one agent may fan out to
several. Reconstruction walks parent links; rendering draws the tree with the
actions attributed to each holder, which is the artefact the whole library
exists to produce.
"""

from __future__ import annotations

from collections import defaultdict

from ..models import ActionRecord, Warrant
from .store import Store

__all__ = ["build_tree", "render_session", "chain_summary"]


def build_tree(warrants: list[Warrant]) -> tuple[list[Warrant], dict[str | None, list[Warrant]]]:
    """Return (roots, children_by_parent_id)."""
    children: dict[str | None, list[Warrant]] = defaultdict(list)
    for w in warrants:
        children[w.parent_id].append(w)
    for group in children.values():
        group.sort(key=lambda w: w.issued_at)
    roots = children.get(None, [])
    return roots, children


def _fmt_scope(w: Warrant) -> str:
    s = w.scope
    ops = ",".join(sorted(s.operations)) or "-"
    tgts = ",".join(sorted(s.targets)) or "-"
    bits = [f"ops={{{ops}}}", f"targets={{{tgts}}}"]
    if s.max_scale is not None:
        bits.append(f"max_scale={s.max_scale}")
    if s.irreversible_allowed:
        bits.append("irreversible=ok")
    return " ".join(bits)


def render_session(store: Store, session_id: str, show_scopes: bool = True) -> str:
    """Human-readable reconstruction of one session."""
    sess = store.get_session(session_id)
    if sess is None:
        return f"No such session: {session_id}"

    warrants = store.warrants_for_session(session_id)
    actions = store.actions_for_session(session_id)
    by_warrant: dict[str, list[ActionRecord]] = defaultdict(list)
    for a in actions:
        by_warrant[a.warrant_id].append(a)

    lines: list[str] = []
    lines.append(f"Session {sess.session_id}")
    lines.append(f"  Principal : {sess.principal}")
    lines.append(f"  Request   : {sess.request!r}")
    lines.append(f"  Started   : {sess.started_at.isoformat()}")
    lines.append("")
    lines.append("Delegation chain")

    roots, children = build_tree(warrants)

    def walk(w: Warrant, prefix: str, is_last: bool) -> None:
        connector = "└─ " if is_last else "├─ "
        lines.append(f"{prefix}{connector}{w.holder}  [{w.warrant_id}]")
        child_prefix = prefix + ("   " if is_last else "│  ")
        if show_scopes:
            lines.append(f"{child_prefix}   {_fmt_scope(w)}")
        for a in by_warrant.get(w.warrant_id, []):
            mark = "ok  " if a.allowed else "FAIL"
            lines.append(
                f"{child_prefix}   [{mark}] {a.operation} {a.resource} scale={a.scale}"
                + ("" if a.allowed else f"\n{child_prefix}          -> {a.violation}")
            )
        kids = children.get(w.warrant_id, [])
        for i, k in enumerate(kids):
            walk(k, child_prefix, i == len(kids) - 1)

    for i, r in enumerate(roots):
        walk(r, "  ", i == len(roots) - 1)

    flagged = [a for a in actions if not a.allowed]
    lines.append("")
    lines.append(
        f"Summary: {len(warrants)} warrants, {len(actions)} actions, "
        f"{len(flagged)} violation(s)"
    )
    for a in flagged:
        lines.append(f"  ! {a.actor}: {a.operation} {a.resource} (scale={a.scale}) - {a.violation}")

    return "\n".join(lines)


def chain_summary(store: Store, session_id: str) -> dict:
    """Machine-readable counterpart to :func:`render_session`."""
    sess = store.get_session(session_id)
    warrants = store.warrants_for_session(session_id)
    actions = store.actions_for_session(session_id)
    return {
        "session_id": session_id,
        "principal": sess.principal if sess else None,
        "request": sess.request if sess else None,
        "warrants": len(warrants),
        "max_depth": max((w.depth for w in warrants), default=0),
        "holders": sorted({w.holder for w in warrants}),
        "actions": len(actions),
        "violations": [
            {
                "actor": a.actor,
                "operation": a.operation,
                "resource": a.resource,
                "scale": a.scale,
                "reason": a.violation,
            }
            for a in actions
            if not a.allowed
        ],
        "exercised": {k: sorted(v) for k, v in store.exercised_scope(session_id).items()},
    }
