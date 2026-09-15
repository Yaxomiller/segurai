"""Reconstructing and rendering a session's delegation tree.

The warrants of one session form a tree, not a line: one agent may hand work
to several others. Reconstruction groups warrants by their parent link;
rendering draws that tree with each agent's actions listed under it. That
printout - who asked, what was granted at each hop, what each agent did - is
the artefact the whole library exists to produce.
"""

from __future__ import annotations

import sys
from collections import defaultdict
from typing import TextIO

from ..models import ActionRecord, Warrant
from .store import Store

__all__ = ["build_tree", "render_session", "chain_summary"]

#: Line-drawing characters for the tree. The Unicode set looks better; the
#: ASCII set is for outputs that cannot show Unicode - a Windows console on a
#: legacy code page, or output piped to a file or another program. Printing
#: Unicode there used to crash the demo with UnicodeEncodeError.
_GLYPHS: dict[str, dict[str, str]] = {
    "unicode": {"branch": "├─ ", "last": "└─ ", "pipe": "│  ", "gap": "   "},
    "ascii":   {"branch": "|- ", "last": "`- ", "pipe": "|  ", "gap": "   "},
}


def _can_print(text: str, stream: TextIO) -> bool:
    """Whether ``stream`` can encode ``text`` without an error."""
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return False
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _glyphs(charset: str) -> dict[str, str]:
    """Pick the tree characters. ``auto`` checks what stdout can display."""
    if charset == "auto":
        sample = "".join(_GLYPHS["unicode"].values())
        charset = "unicode" if _can_print(sample, sys.stdout) else "ascii"
    if charset not in _GLYPHS:
        raise ValueError(f"charset must be 'auto', 'unicode' or 'ascii', got {charset!r}")
    return _GLYPHS[charset]


def build_tree(warrants: list[Warrant]) -> tuple[list[Warrant], dict[str | None, list[Warrant]]]:
    """Return (roots, children_by_parent_id).

    ``children[None]`` holds the roots; ``children[some_id]`` holds the
    warrants delegated from ``some_id``, oldest first.
    """
    children: dict[str | None, list[Warrant]] = defaultdict(list)
    for w in warrants:
        children[w.parent_id].append(w)
    for group in children.values():
        group.sort(key=lambda w: w.issued_at)
    roots = children.get(None, [])
    return roots, children


def _fmt_scope(w: Warrant) -> str:
    """One-line summary of a warrant's scope, e.g. ops={read} targets={crm.*} max_scale=50."""
    s = w.scope
    ops = ",".join(sorted(s.operations)) or "-"
    tgts = ",".join(sorted(s.targets)) or "-"
    bits = [f"ops={{{ops}}}", f"targets={{{tgts}}}"]
    if s.max_scale is not None:
        bits.append(f"max_scale={s.max_scale}")
    if s.irreversible_allowed:
        bits.append("irreversible=ok")
    return " ".join(bits)


def render_session(store: Store, session_id: str, show_scopes: bool = True,
                   charset: str = "auto") -> str:
    """Human-readable reconstruction of one session.

    ``charset`` is "unicode", "ascii", or "auto" (Unicode when stdout can show it).
    """
    sess = store.get_session(session_id)
    if sess is None:
        return f"No such session: {session_id}"

    g = _glyphs(charset)
    warrants = store.warrants_for_session(session_id)
    actions = store.actions_for_session(session_id)

    # Index actions by the warrant they were taken under, so each agent's
    # actions can be printed directly beneath it in the tree.
    by_warrant: dict[str, list[ActionRecord]] = defaultdict(list)
    for a in actions:
        by_warrant[a.warrant_id].append(a)

    lines: list[str] = [
        f"Session {sess.session_id}",
        f"  Principal : {sess.principal}",
        f"  Request   : {sess.request!r}",
        f"  Started   : {sess.started_at.isoformat()}",
        "",
        "Delegation chain",
    ]

    roots, children = build_tree(warrants)

    def walk(w: Warrant, prefix: str, is_last: bool) -> None:
        # Draw this warrant, then its scope and actions, then recurse into the
        # agents it delegated to. ``prefix`` carries the vertical bars of all
        # the ancestors so the branches line up.
        lines.append(f"{prefix}{g['last'] if is_last else g['branch']}{w.holder}  [{w.warrant_id}]")
        child_prefix = prefix + (g["gap"] if is_last else g["pipe"])
        if show_scopes:
            lines.append(f"{child_prefix}   {_fmt_scope(w)}")
        for a in by_warrant.get(w.warrant_id, []):
            # ok      - within the warrant
            # FAIL    - outside it, recorded in OBSERVE mode: it still went ahead
            # BLOCKED - outside it, stopped in ENFORCE mode: it never happened
            mark = "ok     " if a.allowed else ("BLOCKED" if a.blocked else "FAIL   ")
            lines.append(f"{child_prefix}   [{mark}] {a.operation} {a.resource} scale={a.scale}")
            if not a.allowed:
                lines.append(f"{child_prefix}             -> {a.violation}")
        kids = children.get(w.warrant_id, [])
        for i, k in enumerate(kids):
            walk(k, child_prefix, i == len(kids) - 1)

    for i, r in enumerate(roots):
        walk(r, "  ", i == len(roots) - 1)

    flagged = [a for a in actions if not a.allowed]
    blocked = sum(1 for a in flagged if a.blocked)
    lines.append("")
    lines.append(
        f"Summary: {len(warrants)} warrants, {len(actions)} actions, "
        f"{len(flagged)} violation(s)" + (f", {blocked} blocked" if blocked else "")
    )
    for a in flagged:
        outcome = "blocked" if a.blocked else "went ahead"
        lines.append(f"  ! {a.actor}: {a.operation} {a.resource} (scale={a.scale}) - "
                     f"{a.violation} [{outcome}]")

    return "\n".join(lines)


def chain_summary(store: Store, session_id: str) -> dict:
    """Machine-readable counterpart to :func:`render_session` (used by ``--json``)."""
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
                "blocked": a.blocked,
            }
            for a in actions
            if not a.allowed
        ],
        "exercised": {k: sorted(v) for k, v in store.exercised_scope(session_id).items()},
    }
