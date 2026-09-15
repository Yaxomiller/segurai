"""Command line interface.

    warrant sessions                 list recent sessions
    warrant show <session_id>        render the delegation tree
    warrant verify <session_id>      check every chain in a session
    warrant creep <session_id>       granted vs exercised scope

``--db`` selects the store, defaulting to ./warrant.db.
"""

from __future__ import annotations

import argparse
import json
import sys

from .authority import Authority, ChainError, verify_chain
from .collector.chain import chain_summary, render_session
from .collector.store import Store


def _store(args: argparse.Namespace) -> Store:
    return Store(args.db)


def cmd_sessions(args: argparse.Namespace) -> int:
    store = _store(args)
    rows = store.sessions(limit=args.limit)
    if not rows:
        print(f"No sessions in {args.db}")
        return 0
    for r in rows:
        print(f"{r.session_id}  {r.started_at.isoformat()}  {r.principal:<28} {r.request!r}")
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    store = _store(args)
    if args.json:
        print(json.dumps(chain_summary(store, args.session_id), indent=2))
    else:
        print(render_session(store, args.session_id, show_scopes=not args.no_scopes))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify chains against a public key.

    Note the limitation: with an ephemeral in-process Authority there is no
    persisted key to check against, so this is only meaningful once signing
    moves to the collector. Until then it verifies structure, not signatures.
    """
    store = _store(args)
    warrants = store.warrants_for_session(args.session_id)
    if not warrants:
        print(f"No warrants for session {args.session_id}")
        return 1

    parents = {w.parent_id for w in warrants if w.parent_id}
    leaves = [w for w in warrants if w.warrant_id not in parents]

    problems: list[str] = []
    for leaf in leaves:
        try:
            chain = store.chain_to(leaf.warrant_id)
        except ValueError as exc:
            problems.append(f"{leaf.holder}: {exc}")
            continue
        for i, w in enumerate(chain[1:], start=1):
            parent = chain[i - 1]
            ok, reason = w.scope.is_subset_of(parent.scope)
            if not ok:
                problems.append(f"{w.holder} [{w.warrant_id}]: attenuation violated - {reason}")
            if w.depth != parent.depth + 1:
                problems.append(f"{w.holder} [{w.warrant_id}]: depth mismatch")

    if problems:
        print(f"FAILED - {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"OK - {len(leaves)} chain(s), structure and attenuation intact.")
    print("Note: signature verification requires a persisted authority key (M3).")
    return 0


def cmd_creep(args: argparse.Namespace) -> int:
    store = _store(args)
    warrants = store.warrants_for_session(args.session_id)
    if not warrants:
        print(f"No warrants for session {args.session_id}")
        return 1
    root = next(w for w in warrants if w.parent_id is None)
    used = store.exercised_scope(args.session_id)

    granted_ops = set(root.scope.operations)
    unused_ops = sorted(granted_ops - used["operations"])

    print(f"Session {args.session_id}")
    print(f"  granted operations : {sorted(granted_ops)}")
    print(f"  exercised          : {sorted(used['operations'])}")
    print(f"  never used         : {unused_ops or '(none)'}")
    print(f"  targets touched    : {sorted(used['targets'])}")
    if unused_ops:
        pct = 100 * len(unused_ops) / max(len(granted_ops), 1)
        print(f"\n  {len(unused_ops)} of {len(granted_ops)} granted operations "
              f"({pct:.0f}%) went unused in this session.")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="warrant", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="warrant.db", help="store path (default: warrant.db)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sessions", help="list recent sessions")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_sessions)

    s = sub.add_parser("show", help="render a session's delegation tree")
    s.add_argument("session_id")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-scopes", action="store_true")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("verify", help="verify the chains in a session")
    s.add_argument("session_id")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("creep", help="granted vs exercised scope")
    s.add_argument("session_id")
    s.set_defaults(func=cmd_creep)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
