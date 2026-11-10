"""Command line interface.

    segurai sessions                 list recent sessions
    segurai show <session_id>        render the delegation tree
    segurai verify <session_id>      check every chain in a session
    segurai creep <session_id>       granted vs exercised scope
    segurai report                   scope-creep report across sessions (M6)
    segurai keygen                   create a signing key
    segurai demo                     a made-up company, real records, in the browser
    segurai init                     write segurai.toml and a signing key
    segurai config check             check segurai.toml and print what it sets up
    segurai serve                    run a deployment: dashboard, issuer, gateway, alerts
    segurai users add|list|set       people who can sign in to the dashboard
    segurai audit                    check the tamper-evident log
    segurai checkpoint               sign the log's current state
    segurai collect                  receive spans from agents over OTLP/HTTP
    segurai ui                       browse sessions in a web page
    segurai backup --out copy.db     copy the database safely while it is in use
    segurai intent "<request>"       compile a request into a scope contract
    segurai eval-intent              grade the intent compiler on labeled cases
    segurai eval-tier1               run the Tier 1 scenario suite (no API calls)
    segurai judge <session_id>       Tier 2: judge a session's flagged actions
    segurai eval-judge               grade the Tier 2 judge on labeled cases

``--db`` selects the store, defaulting to ./segurai.db. The signing key is
looked for beside it (segurai.db -> segurai.key / segurai.pub) unless
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
from .collector.db import is_database_url, redact_url
from .collector.store import Store


def _store(args: argparse.Namespace) -> Store:
    return Store(args.db)


def _beside_db(args: argparse.Namespace, suffix: str) -> Path:
    """A file kept next to the database, such as its key: segurai.db -> segurai.key.

    A PostgreSQL database has no folder to sit beside, so its files default
    to the current folder (segurai.key), as in segurai.toml.
    """
    return Path("segurai").with_suffix(suffix) if is_database_url(args.db) else Path(args.db).with_suffix(suffix)


def _shown(db: str) -> str:
    """The database, safe to print: a PostgreSQL password is masked."""
    return redact_url(db)


def _find_key(args: argparse.Namespace) -> Path | None:
    """The key to verify with: --key if given, else a .pub or .key beside the database."""
    if args.key:
        return Path(args.key)
    for candidate in (_beside_db(args, ".pub"), _beside_db(args, ".key")):
        if candidate.exists():
            return candidate
    return None


def cmd_sessions(args: argparse.Namespace) -> int:
    store = _store(args)
    rows = store.sessions(limit=args.limit)
    if not rows:
        print(f"No sessions in {_shown(args.db)}")
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


def cmd_report(args: argparse.Namespace) -> int:
    """Scope-creep report: granted versus used permissions over a window."""
    from datetime import timedelta

    from .models import utcnow
    from .report import build_report, load_grants

    store = _store(args)
    grants = load_grants(args.grants) if args.grants else []
    until = utcnow()
    report = build_report(store, since=until - timedelta(days=args.days), until=until, grants=grants)
    render = {"md": report.to_markdown, "html": report.to_html,
              "json": report.to_json, "csv": report.to_csv}[args.format]
    text = render()
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"Wrote {args.format} report to {args.out}: {report.unused_permissions} of "
              f"{report.granted_permissions} granted permissions unused across "
              f"{len(report.identities)} identities.")
    else:
        print(text)
    return 0


def cmd_audit(args: argparse.Namespace) -> int:
    """Check the tamper-evident log: records edited or deleted, entries removed."""
    from .witness import read_witness_file

    store = _store(args)
    key_path = _find_key(args)
    verifier = Authority.verifier(key_path) if key_path is not None and key_path.exists() else None
    witnessed, unreadable = [], []
    for path in args.witness or []:
        try:
            found, bad = read_witness_file(path)
        except OSError as exc:
            print(f"Cannot read witness file {path}: {exc}")
            return 2
        witnessed += found
        unreadable += [f"{path} {note}" for note in bad]
    report = store.audit(verifier, witnessed=witnessed)
    if args.json:
        print(json.dumps({**report.to_dict(), "unreadable_witness_lines": unreadable}, indent=2))
    else:
        print(report.to_text())
        for note in unreadable:
            print(f"  ! unreadable witness line - {note}")
        if verifier is None and report.checkpoints:
            print()
            print("Checkpoint signatures were not checked: no key found. Pass --key, or keep "
                  "the .key/.pub file beside the database.")
    return 0 if report.ok else 1


def cmd_checkpoint(args: argparse.Namespace) -> int:
    """Sign the current head of the log.

    The signing key must be a private key. On a collector that holds only the
    organisation's public key, give it a key of its own for this purpose -
    it signs statements about the log, never warrants.
    """
    store = _store(args)
    key_path = Path(args.key) if args.key else _beside_db(args, ".key")
    if not key_path.exists():
        print(f"No signing key at {key_path}. Create one with: segurai keygen --key {key_path}")
        return 1
    try:
        checkpoint = store.put_checkpoint(Authority.load(key_path))
    except ValueError as exc:
        print(f"Nothing to checkpoint: {exc}")
        return 1
    print(checkpoint.to_text())
    if args.witness:
        from .witness import FileWitness

        FileWitness(Path(args.witness)).publish(checkpoint)
        print()
        print(f"Also appended to the witness file {args.witness}. Check against it later with:")
        print(f"  segurai --db {_shown(args.db)} audit --witness {args.witness}")
        return 0
    print()
    print("Keep this line somewhere outside the database - a ticket, an email to whoever "
          "audits you, or a transparency log. Then even someone holding the key cannot "
          "rewrite history that was already witnessed.")
    return 0


def cmd_evidence(args: argparse.Namespace) -> int:
    """Build an evidence pack for one request: a zip an auditor can check on its own."""
    from .collector.web import session_page
    from .evidence import EvidenceError, build_pack

    store = _store(args)
    key_path = Path(args.key) if args.key else _beside_db(args, ".key")
    if not key_path.exists():
        key_path = _beside_db(args, ".pub")
    if not key_path.exists():
        print("No key found. Pass --key with the organisation's key (private, to sign the pack).")
        return 1
    authority = Authority.load(key_path) if b"PRIVATE" in key_path.read_bytes() else Authority.verifier(key_path)
    try:
        data = build_pack(store, args.session_id, authority,
                          report_html=session_page(store, args.session_id, authority.public_only()))
    except EvidenceError as exc:
        print(f"Cannot build the pack: {exc}")
        return 1
    out = Path(args.out or f"{args.session_id}-evidence.zip")
    out.write_bytes(data)
    print(f"Wrote {out} ({len(data):,} bytes). Check it with:")
    print(f"  segurai evidence-verify {out} --key <the organisation's public key>")
    return 0


def cmd_evidence_verify(args: argparse.Namespace) -> int:
    from .evidence import EvidenceError, verify_pack

    trusted = Path(args.key).read_bytes() if args.key else None
    if trusted is not None and b"PRIVATE" in trusted:
        trusted = Authority.load(args.key).public_key_pem()
    try:
        report = verify_pack(Path(args.pack), trusted)
    except (EvidenceError, OSError) as exc:
        print(f"Cannot read the pack: {exc}")
        return 2
    print(report.to_text())
    return 0 if report.ok else 1


def cmd_keygen(args: argparse.Namespace) -> int:
    path = Path(args.key) if args.key else _beside_db(args, ".key")
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


_LOOPBACK = ("127.0.0.1", "localhost", "::1")


def _serve(args: argparse.Namespace, what: str) -> int:
    """Start the collector's HTTP server (spans in, web pages out), with the safety checks."""
    from .collector.server import CollectorServer

    # Prefer the environment variable: a token on the command line is visible
    # to anyone who can list the machine's processes.
    token = args.token or os.environ.get("SEGURAI_COLLECTOR_TOKEN")
    if args.host not in _LOOPBACK and not token and not args.insecure_no_token:
        print("Refusing to listen beyond this machine without a token: anyone who could reach the "
              "port could read every session and send forged data. Set SEGURAI_COLLECTOR_TOKEN, or "
              "pass --insecure-no-token if the network is protected some other way.")
        return 2

    store = _store(args)
    key_path = _find_key(args)
    verifier = Authority.verifier(key_path) if key_path is not None and key_path.exists() else None
    server = CollectorServer((args.host, args.port), store, verifier=verifier, token=token)
    host, port = server.server_address[:2]
    print(f"segurai {what}: http://{host}:{port}/  (spans to /v1/traces, database {_shown(args.db)})")
    if verifier is not None:
        print(f"  signatures checked with {verifier.key_id}; forged warrants are refused")
    else:
        print("  WARNING: no key found - signatures are NOT checked (pass --key or set SEGURAI_KEY)")
    if token:
        print("  token required (web browsers: any user name, the token as the password)")
    elif args.host not in _LOOPBACK:
        print("  WARNING: listening beyond this machine with no token (--insecure-no-token)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print()
        print("stopping")
    finally:
        server.server_close()
    return 0


def cmd_collect(args: argparse.Namespace) -> int:
    return _serve(args, "collector")


def cmd_ui(args: argparse.Namespace) -> int:
    return _serve(args, "ui")


def cmd_demo(args: argparse.Namespace) -> int:
    """Build the demo company and open the dashboard, or tamper with it.

    Every record is produced by the real library; the company, people,
    contracts and AI reviews are made up and labelled as such (see demo.py).
    """
    from . import demo

    folder = Path(args.dir)
    db, _, pub = demo.demo_paths(folder)

    if args.action in ("tamper", "cover-up"):
        if not db.exists():
            print(f"No demo in {folder}/ yet. Run `segurai demo` first.")
            return 1
        if args.action == "tamper":
            try:
                action_id = demo.tamper(folder)
            except ValueError as exc:
                print(f"Nothing to tamper with: {exc}")
                return 1
            print(f"Rewrote {action_id}: the 400-record permanent delete is now a harmless 4-record")
            print("archive that broke no rule, and the AI review that flagged it is deleted.")
            print("The dashboard now calls the request clean. Reload any page: the record log disagrees.")
        else:
            action_id = demo.cover_up(folder)
            print(f"Rewrote {action_id}, deleted its review, AND rebuilt the hash chain to match.")
            print("The chain now agrees with itself. Reload /audit: the signed checkpoint still disagrees.")
        return 0

    summary = demo.seed(folder)
    print(f"Built the demo company in {folder}/ by running real agent code:")
    print(f"  {summary.sessions} requests, {summary.actions} agent actions, "
          f"{summary.flagged} went beyond the request, {summary.blocked} stopped")
    print("  every warrant signed, every action checked, every record hash-chained and checkpointed")
    print()
    print("While it runs, in a second terminal (same folder):")
    print("  segurai demo tamper      quietly rewrite the incident")
    print("  segurai demo cover-up    ...and rebuild the chain to hide it")
    print("  segurai demo             start again, untouched")
    print()
    if args.no_serve:
        return 0

    url = f"http://127.0.0.1:{args.port}/"
    if not args.no_browser:
        import threading
        import webbrowser
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    serve_args = argparse.Namespace(db=str(db), key=str(pub), host="127.0.0.1", port=args.port,
                                    token=None, insecure_no_token=False)
    try:
        return _serve(serve_args, "demo")
    except OSError as exc:
        print(f"Could not listen on port {args.port} ({exc}). Try: segurai demo --port 8701")
        return 1


def cmd_init(args: argparse.Namespace) -> int:
    """Write a commented segurai.toml and create the organisation's signing key."""
    from .config import EXAMPLE

    folder = Path(args.dir)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "segurai.toml"
    if path.exists() and not args.force:
        print(f"{path} already exists; pass --force to overwrite it.")
        return 1
    path.write_text(EXAMPLE, encoding="utf-8")
    authority = Authority.load_or_create(folder / "segurai.key")
    print(f"Wrote {path} and the organisation's key {folder / 'segurai.key'} ({authority.key_id}).")
    print("Keep the .key file secret; share the .pub file with auditors. Next:")
    print(f"  segurai config check --config {path}")
    print(f"  segurai users add --config {path} --email you@example.com --role admin")
    print(f"  segurai serve --config {path}")
    return 0


def _load_config(path: str):
    from .config import ConfigError, load_config

    try:
        return load_config(path)
    except ConfigError as exc:
        print(f"Configuration problem: {exc}")
        return None


def cmd_config(args: argparse.Namespace) -> int:
    from .serve import build

    config = _load_config(args.config)
    if config is None:
        return 2
    try:
        deployment = build(config)
    except Exception as exc:          # a port in use, an unreadable key...
        print(f"The configuration reads correctly, but cannot start: {exc}")
        return 2
    try:
        print(f"{args.config} is valid:")
        for line in config.summary():
            print(f"  {line}")
        if config.dashboard and config.dashboard.local_accounts and not deployment.store.users():
            print()
            print("No accounts yet. Add the first admin:")
            print(f"  segurai users add --config {args.config} --email you@example.com --role admin")
    finally:
        for target in (deployment.server, deployment.gateway):
            if target is not None:
                target.server_close()
        deployment.store.close()
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    import signal
    import threading

    from .serve import build

    config = _load_config(args.config)
    if config is None:
        return 2
    try:
        deployment = build(config)
    except OSError as exc:
        print(f"Cannot start: {exc}")
        return 1
    deployment.start()
    print(f"Segurai is running from {args.config}")
    for line in config.summary():
        print(f"  {line}")
    if config.dashboard and config.dashboard.local_accounts and not deployment.store.users():
        print("  ! no accounts yet: segurai users add --config "
              f"{args.config} --email you@example.com --role admin")
    stop = threading.Event()
    for signum in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(signum, lambda *_: stop.set())
        except ValueError:            # not the main thread (tests)
            pass
    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    print("stopping")
    deployment.stop()
    return 0


def cmd_users(args: argparse.Namespace) -> int:
    import getpass
    import os

    from .collector.auth import AuthError, WebAuth

    if args.config:
        config = _load_config(args.config)
        if config is None:
            return 2
        store = Store(config.server.database)
    else:
        store = _store(args)
    auth = WebAuth(store)
    try:
        if args.action == "list":
            users = store.users()
            if not users:
                print("No accounts.")
            for u in users:
                state = "disabled" if u["disabled"] else "active"
                print(f"{u['email']:<36} {u['role']:<8} {u['source']:<6} {state}")
            return 0
        if not args.email:
            print("--email is required")
            return 2
        password = None
        if args.action == "add" or args.password_env or args.reset_password:
            if args.password_env:
                password = os.environ.get(args.password_env) or ""
                if not password:
                    print(f"{args.password_env} is not set")
                    return 2
            elif args.action == "add" or args.reset_password:
                password = getpass.getpass("Password (12+ characters): ")
                if password != getpass.getpass("Again: "):
                    print("The passwords don't match.")
                    return 2
        if args.action == "add":
            user = auth.add_user(args.email, args.role or "viewer", password=password, by="command line")
        else:
            user = auth.update_user(args.email, role=args.role, by="command line", password=password,
                                    disabled={"yes": True, "no": False}.get(args.disabled or ""))
        print(f"{user.email}: {user.role}{' (disabled)' if user.disabled else ''}")
        return 0
    except AuthError as exc:
        print(f"Refused: {exc}")
        return 1
    finally:
        store.close()


def cmd_backup(args: argparse.Namespace) -> int:
    """Copy the database safely, even while the collector is writing to it."""
    out = Path(args.out)
    if out.exists() and not args.force:
        print(f"{out} already exists (use --force to replace it).")
        return 1
    try:
        _store(args).backup(out)
    except ValueError as exc:                     # PostgreSQL: use pg_dump
        print(exc)
        return 1
    print(f"Backed up {_shown(args.db)} to {out}")
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


def cmd_eval_tier1(args: argparse.Namespace) -> int:
    """Run the seeded Tier 1 scenarios and report against the M2 target."""
    from .scenarios import load_scenarios, run_scenarios

    report = run_scenarios(load_scenarios(args.scenarios))
    print(report.to_markdown())
    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        print(f"\nFull results: {args.out}")
    return 0 if report.meets_target else 1


def cmd_judge(args: argparse.Namespace) -> int:
    """Judge every flagged action in a session that has no verdict yet (one API call each)."""
    from .judge import ClaudeJudgeBackend, Judge, JudgeError, needs_review

    store = _store(args)
    if store.get_session(args.session_id) is None:
        print(f"No such session: {args.session_id}")
        return 1
    already = set() if args.rejudge else set(store.verdicts_for_session(args.session_id))
    pending = [a for a in store.actions_for_session(args.session_id)
               if needs_review(a) and a.action_id not in already]
    if not pending:
        print("Nothing to judge: every flagged action already has a verdict (use --rejudge to redo).")
        return 0
    if not args.yes:
        print(f"This makes {len(pending)} call(s) to {args.model} on your Anthropic account, "
              f"which costs money. Re-run with --yes to go ahead.")
        return 2

    judge = Judge(ClaudeJudgeBackend(model=args.model, effort=args.effort), votes=args.votes)
    failures = 0
    for record in pending:
        try:
            verdict = judge.review_action(store, record)
        except JudgeError as exc:
            failures += 1
            print(f"  could not judge {record.actor}: {record.operation} {record.resource} - {exc}")
            continue
        print(f"  {verdict.verdict:<15} ({verdict.confidence}) {record.actor}: "
              f"{record.operation} {record.resource} - {verdict.reasoning}")
    return 1 if failures else 0


def cmd_label(args: argparse.Namespace) -> int:
    """Label the judge's eval cases yourself, without seeing the existing labels."""
    from .judge.eval import load_cases
    from .judge.labelling import label_cases

    cases = load_cases(args.cases)
    if args.split != "all":
        cases = [c for c in cases if c.split == args.split]
    if args.ambiguous_only:
        cases = [c for c in cases if c.ambiguous]
    label_cases(cases, args.out, labeller=args.labeller)
    return 0


def cmd_label_agreement(args: argparse.Namespace) -> int:
    """How far two people's labels agree, and which cases they disagree on."""
    from .judge.eval import load_cases
    from .judge.labelling import agreement, load_labels, merged

    first, second = load_labels(args.first), load_labels(args.second)
    expected = {c.id: c.expected for c in load_cases(args.cases)} if args.cases else None
    result = agreement(first, second, expected, names=(Path(args.first).stem, Path(args.second).stem))
    if not result.shared:
        print("The two files have no cases in common.")
        return 1
    print(result.to_text())
    if args.merged:
        rows = merged(first, second)
        Path(args.merged).write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
        print(f"\nWrote the {len(rows)} label(s) both agree on to {args.merged}.")
    return 0


def cmd_eval_judge(args: argparse.Namespace) -> int:
    """Grade the judge on labeled cases against the M4 target."""
    from .judge import ClaudeJudgeBackend, Judge
    from .judge.eval import load_cases, run_eval

    cases = load_cases(args.cases)
    if args.split != "all":
        cases = [c for c in cases if c.split == args.split]
    if args.limit:
        cases = cases[: args.limit]
    if not cases:
        print("No cases selected.")
        return 1
    if not args.yes:
        print(f"This makes {len(cases)} calls to {args.model} on your Anthropic account, "
              f"which costs money. Re-run with --yes to go ahead.")
        return 2

    def progress(i, n, result):
        mark = "error" if result.error else ("agree" if result.agree else "differ")
        print(f"  [{i}/{n}] {mark:6} {result.case_id}")

    report = run_eval(Judge(ClaudeJudgeBackend(model=args.model, effort=args.effort), votes=args.votes),
                      cases, progress)
    print()
    print(report.to_markdown())
    if args.out:
        Path(args.out).write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return 0 if report.meets_target else 1


def _never_crash_on_unprintable_text() -> None:
    """Replace characters the terminal cannot show instead of raising.

    A Windows console on a legacy code page (cp1252), or output redirected to
    a file, cannot encode every character. Without this, a request typed in
    another language would crash ``segurai show`` halfway through the report.
    """
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")


def main(argv: list[str] | None = None) -> int:
    _never_crash_on_unprintable_text()
    p = argparse.ArgumentParser(prog="segurai", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    # Defaults can come from the environment, which is how containers are configured.
    p.add_argument("--db", default=os.environ.get("SEGURAI_DB", "segurai.db"),
                   help="store path (default: $SEGURAI_DB, else segurai.db)")
    p.add_argument("--key", default=os.environ.get("SEGURAI_KEY"),
                   help="signing key file (default: $SEGURAI_KEY, else beside the database)")
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

    s = sub.add_parser("report", help="scope-creep report: granted versus used permissions")
    s.add_argument("--days", type=int, default=30, help="observation window in days (default: 30)")
    s.add_argument("--grants", default=None,
                   help="JSON file of standing permissions exported from an identity provider")
    s.add_argument("--format", default="md", choices=["md", "html", "json", "csv"])
    s.add_argument("--out", default=None, help="write the report here instead of printing it")
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("audit", help="check the tamper-evident log")
    s.add_argument("--json", action="store_true")
    s.add_argument("--witness", action="append", metavar="FILE",
                   help="a file of checkpoints kept outside the database (repeatable)")
    s.set_defaults(func=cmd_audit)

    s = sub.add_parser("checkpoint", help="sign the log's current state")
    s.add_argument("--witness", metavar="FILE", help="also append the checkpoint to this file")
    s.set_defaults(func=cmd_checkpoint)

    s = sub.add_parser("evidence", help="build an evidence pack for one request")
    s.add_argument("session_id")
    s.add_argument("--out", help="where to write the zip (default: <session>-evidence.zip)")
    s.set_defaults(func=cmd_evidence)

    s = sub.add_parser("evidence-verify", help="check an evidence pack from the pack alone")
    s.add_argument("pack")
    s.set_defaults(func=cmd_evidence_verify)

    s = sub.add_parser("keygen", help="create a signing key")
    s.add_argument("--force", action="store_true", help="replace an existing key")
    s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("collect", help="receive spans from agents over OTLP/HTTP")
    s.add_argument("--host", default=os.environ.get("SEGURAI_HOST", "127.0.0.1"),
                   help="interface to listen on (default: $SEGURAI_HOST, else 127.0.0.1)")
    s.add_argument("--port", type=int, default=int(os.environ.get("SEGURAI_PORT", "4318")),
                   help="port (default: $SEGURAI_PORT, else 4318)")
    s.add_argument("--insecure-no-token", action="store_true",
                   help="allow listening beyond this machine without a token")
    s.add_argument("--token", default=None,
                   help="require this bearer token (prefer the SEGURAI_COLLECTOR_TOKEN variable)")
    s.set_defaults(func=cmd_collect)

    s = sub.add_parser("ui", help="browse sessions in a web page")
    s.add_argument("--host", default=os.environ.get("SEGURAI_HOST", "127.0.0.1"),
                   help="interface to listen on (default: $SEGURAI_HOST, else 127.0.0.1)")
    s.add_argument("--port", type=int, default=int(os.environ.get("SEGURAI_PORT", "8700")),
                   help="port (default: $SEGURAI_PORT, else 8700)")
    s.add_argument("--insecure-no-token", action="store_true",
                   help="allow listening beyond this machine without a token")
    s.add_argument("--token", default=None,
                   help="require this password (prefer the SEGURAI_COLLECTOR_TOKEN variable)")
    s.set_defaults(func=cmd_ui)

    s = sub.add_parser("demo", help="a made-up company with real records, in the browser")
    s.add_argument("action", nargs="?", default="start", choices=["start", "tamper", "cover-up"],
                   help="start (default) builds the demo and opens the dashboard; tamper and "
                        "cover-up rewrite the incident to show the audit catching it")
    s.add_argument("--dir", default="segurai-demo", help="where the demo's files live")
    s.add_argument("--port", type=int, default=8700, help="port for the dashboard (default 8700)")
    s.add_argument("--no-browser", action="store_true", help="don't open a browser window")
    s.add_argument("--no-serve", action="store_true", help="build the demo database and stop")
    s.set_defaults(func=cmd_demo)

    s = sub.add_parser("init", help="write a commented segurai.toml and a signing key")
    s.add_argument("--dir", default=".", help="where to write them (default: here)")
    s.add_argument("--force", action="store_true", help="overwrite an existing segurai.toml")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("config", help="check a configuration file")
    s.add_argument("action", choices=["check"])
    s.add_argument("--config", default="segurai.toml")
    s.set_defaults(func=cmd_config)

    s = sub.add_parser("serve", help="run a deployment from segurai.toml")
    s.add_argument("--config", default="segurai.toml")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("users", help="people who can sign in to the dashboard")
    s.add_argument("action", choices=["add", "list", "set"])
    s.add_argument("--config", default=None, help="take the database from this configuration")
    s.add_argument("--email")
    s.add_argument("--role", choices=["viewer", "auditor", "admin"])
    s.add_argument("--disabled", choices=["yes", "no"])
    s.add_argument("--reset-password", action="store_true", help="with set: prompt for a new password")
    s.add_argument("--password-env", help="read the password from this environment variable")
    s.set_defaults(func=cmd_users)

    s = sub.add_parser("backup", help="copy the database safely while it is in use")
    s.add_argument("--out", required=True, help="where to write the copy")
    s.add_argument("--force", action="store_true", help="replace an existing file")
    s.set_defaults(func=cmd_backup)

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

    s = sub.add_parser("eval-tier1", help="run the Tier 1 scenario suite (no API calls)")
    s.add_argument("--scenarios", default="evals/tier1/scenarios.json")
    s.add_argument("--out", default=None, help="write full JSON results here")
    s.set_defaults(func=cmd_eval_tier1)

    efforts = ["low", "medium", "high", "xhigh", "max"]
    s = sub.add_parser("judge", help="Tier 2: judge a session's flagged actions (calls Claude)")
    s.add_argument("session_id")
    s.add_argument("--rejudge", action="store_true", help="judge again where a verdict exists")
    s.add_argument("--yes", action="store_true", help="confirm the paid API calls")
    s.add_argument("--model", default="claude-opus-5")
    s.add_argument("--effort", default="low", choices=efforts)
    s.add_argument("--votes", type=int, default=1, choices=range(1, 6), metavar="1-5",
                   help="ask this many times; disagreement becomes needs_human")
    s.set_defaults(func=cmd_judge)

    s = sub.add_parser("label", help="label the judge's eval cases yourself, blind to existing labels")
    s.add_argument("--cases", default="evals/tier2/cases.jsonl")
    s.add_argument("--as", dest="labeller", required=True, help="your name, recorded with each label")
    s.add_argument("--out", required=True, help="your labels file (resumes if it exists)")
    s.add_argument("--split", default="all", choices=["dev", "test", "all"])
    s.add_argument("--ambiguous-only", action="store_true", help="only the cases marked ambiguous")
    s.set_defaults(func=cmd_label)

    s = sub.add_parser("label-agreement", help="how far two people's labels agree")
    s.add_argument("first")
    s.add_argument("second")
    s.add_argument("--cases", default=None, help="also compare each person with this answer key")
    s.add_argument("--merged", default=None, help="write the labels both agree on here")
    s.set_defaults(func=cmd_label_agreement)

    s = sub.add_parser("eval-judge", help="grade the Tier 2 judge on labeled cases (calls Claude)")
    s.add_argument("--cases", default="evals/tier2/cases.jsonl")
    s.add_argument("--split", default="test", choices=["dev", "test", "all"],
                   help="dev to tune the prompt against, test to report (default: test)")
    s.add_argument("--limit", type=int, default=0, help="only the first N cases")
    s.add_argument("--yes", action="store_true", help="confirm the paid API calls")
    s.add_argument("--out", default=None, help="write full JSON results here")
    s.add_argument("--model", default="claude-opus-5")
    s.add_argument("--effort", default="low", choices=efforts)
    s.add_argument("--votes", type=int, default=1, choices=range(1, 6), metavar="1-5",
                   help="ask this many times; disagreement becomes needs_human")
    s.set_defaults(func=cmd_eval_judge)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
