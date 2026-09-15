"""Command line interface.

    warrant sessions                 list recent sessions
    warrant show <session_id>        render the delegation tree
    warrant verify <session_id>      check every chain in a session
    warrant creep <session_id>       granted vs exercised scope
    warrant keygen                   create a signing key

``--db`` selects the store, defaulting to ./warrant.db. The signing key is
looked for beside it (warrant.db -> warrant.key / warrant.pub) unless
``--key`` says otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .authority import Authority, ChainError, verify_chain
from .collector.chain import chain_summary, render_session
from .collector.store import Store


def _store(args: argparse.Namespace) -> Store:
    return Store(args.db)


def _find_key(args: argparse.Namespace) -> Path | None:
    """The key to verify with: --key if given, else a .pub or .key beside the database."""
    if args.key:
        return Path(args.key)
    db = Path(args.db)
    for candidate in (db.with_suffix(".pub"), db.with_suffix(".key")):
        if candidate.exists():
            return candidate
    return None


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
        charset = "ascii" if args.ascii else "auto"
        print(render_session(store, args.session_id, show_scopes=not args.no_scopes,
                             charset=charset))
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify every root-to-leaf chain in a session.

    With a key: signatures, links, depths, expiry ordering and attenuation.
    Without one: everything except signatures - and it says so, because a
    structure-only check can be passed by a careful forger.
    """
    store = _store(args)
    warrants = store.warrants_for_session(args.session_id)
    if not warrants:
        print(f"No warrants for session {args.session_id}")
        return 1

    key_path = _find_key(args)
    verifier = None
    if key_path is not None:
        if not key_path.exists():
            print(f"Key file not found: {key_path}")
            return 1
        verifier = Authority.verifier(key_path)

    # A leaf is a warrant nobody delegated from; checking the chain up from
    # each leaf covers every warrant in the tree.
    parents = {w.parent_id for w in warrants if w.parent_id}
    leaves = [w for w in warrants if w.warrant_id not in parents]

    problems: list[str] = []
    for leaf in leaves:
        try:
            chain = store.chain_to(leaf.warrant_id)
            verify_chain(chain, verifier, allow_expired=True)
        except (ChainError, ValueError) as exc:
            problems.append(f"{leaf.holder} [{leaf.warrant_id}]: {exc}")

    if problems:
        print(f"FAILED - {len(problems)} problem(s):")
        for p in problems:
            print(f"  - {p}")
        return 1

    if verifier is not None:
        print(f"OK - {len(leaves)} chain(s): signatures valid ({verifier.key_id}), "
              f"links and attenuation intact.")
    else:
        print(f"OK - {len(leaves)} chain(s), structure and attenuation intact.")
        print("Signatures NOT checked: no key found. Pass --key, or keep the .key/.pub "
              "file beside the database.")
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


def cmd_keygen(args: argparse.Namespace) -> int:
    path = Path(args.key or Path(args.db).with_suffix(".key"))
    if path.exists() and not args.force:
        print(f"{path} already exists (use --force to replace it; old warrants "
              f"will then fail verification).")
        return 1
    authority = Authority()
    authority.save(path)
    print(f"Wrote private key {path} and public key {path.with_suffix('.pub')}")
    print(f"Key id: {authority.key_id}")
    print("Keep the .key file secret. Share the .pub file with whoever verifies.")
    return 0


def _never_crash_on_unprintable_text() -> None:
    """Replace characters the terminal cannot show instead of raising.

    A Windows console on a legacy code page (cp1252), or output redirected to
    a file, cannot encode every character. Without this, a request typed in
    another language would crash ``warrant show`` halfway through the report.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def main(argv: list[str] | None = None) -> int:
    _never_crash_on_unprintable_text()
    p = argparse.ArgumentParser(prog="warrant", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--db", default="warrant.db", help="store path (default: warrant.db)")
    p.add_argument("--key", default=None,
                   help="signing key file (default: beside the database)")
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("sessions", help="list recent sessions")
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(func=cmd_sessions)

    s = sub.add_parser("show", help="render a session's delegation tree")
    s.add_argument("session_id")
    s.add_argument("--json", action="store_true")
    s.add_argument("--no-scopes", action="store_true")
    s.add_argument("--ascii", action="store_true", help="draw the tree with plain ASCII")
    s.set_defaults(func=cmd_show)

    s = sub.add_parser("verify", help="verify the chains in a session")
    s.add_argument("session_id")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("creep", help="granted vs exercised scope")
    s.add_argument("session_id")
    s.set_defaults(func=cmd_creep)

    s = sub.add_parser("keygen", help="create a signing key")
    s.add_argument("--force", action="store_true", help="replace an existing key")
    s.set_defaults(func=cmd_keygen)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
