"""Command line interface.

    warrant sessions                 list recent sessions
    warrant show <session_id>        render the delegation tree
    warrant verify <session_id>      check every chain in a session
    warrant creep <session_id>       granted vs exercised scope
    warrant keygen                   create a signing key
    warrant collect                  receive spans from agents over OTLP/HTTP
    warrant intent "<request>"       compile a request into a scope contract
    warrant eval-intent              grade the intent compiler on labeled cases

``--db`` selects the store, defaulting to ./warrant.db. The signing key is
looked for beside it (warrant.db -> warrant.key / warrant.pub) unless
``--key`` says otherwise.
"""

from __future__ import annotations

import argparse
import json
import os
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


def cmd_collect(args: argparse.Namespace) -> int:
    from .collector.server import CollectorServer

    store = _store(args)
    key_path = _find_key(args)
    verifier = Authority.verifier(key_path) if key_path is not None and key_path.exists() else None
    # Prefer the environment variable: a token on the command line is visible
    # to anyone who can list the machine's processes.
    token = args.token or os.environ.get("WARRANT_COLLECTOR_TOKEN")

    server = CollectorServer((args.host, args.port), store, verifier=verifier, token=token)
    host, port = server.server_address[:2]
    print(f"warrant collector: http://{host}:{port}/v1/traces -> {args.db}")
    if verifier is not None:
        print(f"  signatures checked with {verifier.key_id}; forged warrants are refused")
    else:
        print("  WARNING: no key found - warrants are stored WITHOUT signature checks (pass --key)")
    if token:
        print("  bearer token required")
    elif args.host not in ("127.0.0.1", "localhost", "::1"):
        print("  WARNING: listening beyond this machine with no token (set WARRANT_COLLECTOR_TOKEN)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        server.server_close()
    return 0


def _compiler(args: argparse.Namespace):
    from .intent import Catalog, ClaudeBackend, IntentCompiler

    return IntentCompiler(Catalog.load(args.catalog),
                          ClaudeBackend(model=args.model, effort=args.effort))


def cmd_intent(args: argparse.Namespace) -> int:
    """Compile one request and print the contract (one API call)."""
    from .intent import IntentError

    try:
        compiled = _compiler(args).compile(args.request)
    except IntentError as exc:
        print(f"Could not compile the request: {exc}")
        return 1
    print(json.dumps(compiled.to_record(), indent=2))
    scope = compiled.scope()
    print(f"\nRoot scope: ops={sorted(scope.operations)} targets={sorted(scope.targets)} "
          f"max_scale={scope.max_scale} irreversible_allowed={scope.irreversible_allowed}")
    return 0


def cmd_eval_intent(args: argparse.Namespace) -> int:
    """Run the labeled intent cases through the compiler and grade them."""
    from .intent.eval import MILESTONE_TARGET, load_cases, run_eval

    cases = load_cases(args.cases)
    if args.split != "all":
        cases = [c for c in cases if c.split == args.split]
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        print("No cases selected.")
        return 1

    # Every case is a paid API call, so running needs an explicit yes.
    if not args.yes:
        print(f"This makes {len(cases)} calls to {args.model} on your Anthropic account, "
              f"which costs money. Re-run with --yes to go ahead.")
        return 2

    def progress(i, n, result):
        verdict = "error" if result.error else ("ok" if result.acceptable else "miss")
        print(f"  [{i}/{n}] {verdict:5} {result.case_id}")

    report = run_eval(_compiler(args), cases, progress=progress)
    print()
    print(report.to_markdown())
    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nFull results: {args.out}")
    if args.review_sheet:
        report.write_review_sheet(args.review_sheet)
        print(f"Human review sheet: {args.review_sheet}")
    return 0 if report.acceptable_rate >= MILESTONE_TARGET else 1


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

    s = sub.add_parser("collect", help="receive spans from agents over OTLP/HTTP")
    s.add_argument("--host", default="127.0.0.1", help="interface to listen on (default: 127.0.0.1)")
    s.add_argument("--port", type=int, default=4318, help="port (default: 4318, the OTLP/HTTP port)")
    s.add_argument("--token", default=None,
                   help="require this bearer token (prefer the WARRANT_COLLECTOR_TOKEN variable)")
    s.set_defaults(func=cmd_collect)

    def add_model_options(parser: argparse.ArgumentParser) -> None:
        parser.add_argument("--catalog", required=True, help="catalog JSON of operations and resources")
        parser.add_argument("--model", default="claude-opus-5", help="Claude model (default: claude-opus-5)")
        parser.add_argument("--effort", default=None, choices=["low", "medium", "high", "xhigh", "max"])

    s = sub.add_parser("intent", help="compile a request into a scope contract (calls Claude)")
    s.add_argument("request")
    add_model_options(s)
    s.set_defaults(func=cmd_intent)

    s = sub.add_parser("eval-intent", help="grade the intent compiler on labeled cases (calls Claude)")
    s.add_argument("--cases", required=True, help="JSONL file of labeled cases")
    s.add_argument("--split", default="test", choices=["dev", "test", "all"])
    s.add_argument("--limit", type=int, default=0, help="only the first N cases")
    s.add_argument("--yes", action="store_true", help="confirm the paid API calls")
    s.add_argument("--out", default=None, help="write full JSON results here")
    s.add_argument("--review-sheet", default=None, help="write a CSV for human review here")
    add_model_options(s)
    s.set_defaults(func=cmd_eval_intent)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
