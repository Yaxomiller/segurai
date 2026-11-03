"""A read-only web view: what was asked, beside what happened.

    segurai ui --db segurai.db          then open http://127.0.0.1:8700/

Two pages:

  /                  recent sessions, with how many violations each had
  /sessions/<id>     one session: the request and (if one was compiled) its
                     contract and granted scope on the left; the delegation
                     chain on the right, with every action and finding inline;
                     and whether the signatures check out

Deliberately plain: HTML built on the server, a little inline CSS, no
JavaScript. It has to run anywhere the collector runs and be safe to open.

Safety: every piece of text that came from outside - request text, agent
names, resource names, reasons - goes through ``_e`` (HTML escaping), so a
request containing "<script>" is displayed, never run. The server also sends
a Content-Security-Policy (``CSP`` below) that forbids scripts outright, as a
second line of defence.
"""

from __future__ import annotations

import html
from collections import defaultdict
from typing import Any
from urllib.parse import quote

from ..authority import Authority, ChainError, verify_chain
from ..models import ActionRecord, Scope, Warrant
from .chain import build_tree
from .store import Store

__all__ = ["index_page", "session_page", "CSP"]

#: Sent with every page: no scripts, no external anything, only our own inline styles.
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
       "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

_STYLE = """
:root { --bg:#fafaf8; --fg:#1d1d1f; --muted:#6b6b70; --line:#e3e3e0; --card:#ffffff;
        --ok:#1f7a3f; --fail:#b3261e; --blocked:#6f3fb3; --unk:#8a5d00; --code:#f1f1ee; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#161618; --fg:#ececec; --muted:#9a9aa0; --line:#2c2c30; --card:#1e1e21;
          --ok:#5cc27e; --fail:#ff7b72; --blocked:#c89bff; --unk:#e3b341; --code:#26262a; }
}
body { margin:0; background:var(--bg); color:var(--fg);
       font:14px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
header { padding:16px 24px; border-bottom:1px solid var(--line); }
header a { text-decoration:none; }
main { padding:24px; max-width:1240px; margin:0 auto; }
a { color:inherit; }
h1 { font-size:18px; margin:0 0 4px; }
h2 { font-size:13px; text-transform:uppercase; letter-spacing:.05em; color:var(--muted); margin:0 0 12px; }
.muted { color:var(--muted); }
.table-wrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
th { color:var(--muted); font-weight:500; }
.grid { display:grid; grid-template-columns:minmax(280px, 1fr) 2fr; gap:20px; }
@media (max-width: 860px) { .grid { grid-template-columns:1fr; } }
.card { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:16px;
        margin-bottom:20px; overflow-x:auto; }
code, .mono { font-family:ui-monospace, "Cascadia Code", Consolas, monospace; font-size:12.5px; }
code { background:var(--code); padding:1px 4px; border-radius:4px; }
ul.tree, ul.tree ul { list-style:none; margin:0; }
ul.tree { padding:0; }
ul.tree ul { padding-left:18px; border-left:1px solid var(--line); margin-left:4px; }
li.agent { margin:10px 0; }
.action { margin:3px 0; }
.badge { display:inline-block; min-width:62px; text-align:center; font-size:11px; font-weight:600;
         padding:0 6px; border-radius:4px; border:1px solid currentColor; margin-right:6px; }
.ok { color:var(--ok); } .fail { color:var(--fail); } .blocked { color:var(--blocked); } .unk { color:var(--unk); }
.finding { margin:1px 0 1px 76px; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:4px 14px; margin:0; }
dt { color:var(--muted); } dd { margin:0; }
ul.plain { margin:0; padding-left:18px; }
"""


def _e(value: Any) -> str:
    """Escape text for HTML. Everything from outside the program goes through this."""
    return html.escape(str(value), quote=True)


def _page(title: str, body: str) -> str:
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head><body>"
        "<header><a href='/'><strong>Segurai</strong></a> "
        "<span class='muted'>&middot; who authorized what your agents did</span></header>"
        f"<main>{body}</main></body></html>"
    )


def _list(items: list[str], empty: str = "none") -> str:
    if not items:
        return f"<span class='muted'>{_e(empty)}</span>"
    return "<ul class='plain'>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"


def _codes(items: list[str]) -> str:
    return " ".join(f"<code>{_e(i)}</code>" for i in items) or "<span class='muted'>none</span>"


# ---- the index ------------------------------------------------------------

def index_page(store: Store, limit: int = 50) -> str:
    """Recent sessions, newest first."""
    rows = []
    for s in store.sessions(limit=limit):
        actions = store.actions_for_session(s.session_id)
        violations = sum(1 for a in actions if not a.allowed)
        blocked = sum(1 for a in actions if a.blocked)
        unverifiable = sum(1 for a in actions for f in a.findings if f.status == "unverifiable")
        if violations:
            verdict = f"<span class='fail'>{violations} violation(s)</span>"
            if blocked:
                verdict += f" <span class='blocked'>&middot; {blocked} blocked</span>"
        else:
            verdict = "<span class='ok'>clean</span>"
        rows.append(
            "<tr>"
            f"<td><a href='/sessions/{_e(quote(s.session_id, safe=''))}'>{_e(s.request)}</a>"
            f"<div class='muted mono'>{_e(s.session_id)}</div></td>"
            f"<td>{_e(s.principal)}</td>"
            f"<td class='mono'>{_e(s.started_at.strftime('%Y-%m-%d %H:%M:%S %Z'))}</td>"
            f"<td>{len(actions)}</td><td>{verdict}</td>"
            f"<td>{'<span class=unk>' + str(unverifiable) + '</span>' if unverifiable else '0'}</td>"
            "</tr>"
        )
    if rows:
        table = ("<div class='table-wrap'><table><thead><tr><th>Request</th><th>Principal</th>"
                 "<th>Started</th><th>Actions</th><th>Verdict</th><th>Unverifiable</th></tr></thead>"
                 f"<tbody>{''.join(rows)}</tbody></table></div>")
    else:
        table = "<p class='muted'>No sessions recorded yet.</p>"
    return _page("Segurai - sessions", f"<h1>Sessions</h1><div class='card'>{table}</div>")


# ---- one session ------------------------------------------------------------

def _scope_html(scope: Scope) -> str:
    rows = [
        ("Operations", _codes(sorted(scope.operations))),
        ("Targets", _codes(sorted(scope.targets))),
        ("Per action", _e(scope.max_scale) if scope.max_scale is not None else "unbounded"),
        ("Session total", _e(scope.max_total) if scope.max_total is not None else "unbounded"),
        ("Irreversible", "allowed" if scope.irreversible_allowed else "not allowed"),
        ("Conditions", _list(list(scope.constraints))),
        ("Checks", _list([f"{c.field} {c.op} {c.value!r} - {c.label}" for c in scope.checks])),
    ]
    return "<dl>" + "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in rows) + "</dl>"


def _contract_html(record: dict[str, Any]) -> str:
    c = record.get("contract") or {}
    scale = c.get("expected_scale") or {}
    checks = [f"{k.get('field')} {k.get('op')} {k.get('value')!r} - {k.get('condition', '')}"
              for k in c.get("checks") or []]
    rows = [
        ("Goal", _e(c.get("goal", ""))),
        ("Operations", _codes(c.get("expected_operations", []))),
        ("Targets", _codes(c.get("expected_targets", []))),
        ("Typical size", f"{_e(scale.get('typical_max'))} {_e(scale.get('unit', ''))}"),
        ("Irreversible", "expected" if c.get("irreversible_expected") else "not expected"),
        ("Conditions", _list(c.get("implied_constraints", []))),
        ("Checks", _list(checks)),
        ("Needs clarifying", _list(c.get("clarifications_needed", []))),
        ("Corrected", _list(record.get("problems", []), empty="nothing")),
        ("Compiled by", _e(f"{record.get('model') or 'unknown'} - {record.get('prompt_version') or ''}")),
    ]
    return "<dl>" + "".join(f"<dt>{name}</dt><dd>{value}</dd>" for name, value in rows) + "</dl>"


def _verification_html(store: Store, warrants: list[Warrant], verifier: Authority | None) -> str:
    """Re-check every chain in the session, the same way `segurai verify` does."""
    parents = {w.parent_id for w in warrants if w.parent_id}
    leaves = [w for w in warrants if w.warrant_id not in parents]
    problems = []
    for leaf in leaves:
        try:
            verify_chain(store.chain_to(leaf.warrant_id), verifier, allow_expired=True)
        except (ChainError, ValueError) as exc:
            problems.append(f"{leaf.holder}: {exc}")
    if problems:
        return "<p class='fail'>Verification FAILED</p>" + _list(problems)
    if verifier is None:
        return (f"<p class='unk'>{len(leaves)} chain(s): links and narrowing intact. "
                "Signatures not checked - no key configured.</p>")
    return (f"<p class='ok'>{len(leaves)} chain(s) verified: signatures valid "
            f"(<code>{_e(verifier.key_id)}</code>), links and narrowing intact.</p>")


def _action_html(a: ActionRecord, verdict: Any = None) -> str:
    if a.allowed:
        cls, label = "ok", "ok"
    elif a.blocked:
        cls, label = "blocked", "BLOCKED"
    else:
        cls, label = "fail", "FAIL"
    extra = " &middot; irreversible" if a.irreversible else ""
    out = [f"<div class='action mono'><span class='badge {cls}'>{label}</span>"
           f"{_e(a.operation)} {_e(a.resource)} <span class='muted'>scale={a.scale}{extra}</span></div>"]
    for f in a.findings:
        if f.status == "fail":
            out.append(f"<div class='finding mono fail'>&#x2717; {_e(f.reason)}</div>")
        else:
            out.append(f"<div class='finding mono unk'>? {_e(f.reason)}</div>")
    if not a.findings and not a.allowed:
        out.append(f"<div class='finding mono fail'>&#x2717; {_e(a.violation)}</div>")
    if verdict is not None:
        # Tier 2's verdict is shown beside Tier 1's findings, never instead of them.
        tone = {"within_intent": "ok", "outside_intent": "fail"}.get(verdict.verdict, "unk")
        out.append(f"<div class='finding {tone}'><strong>judge: {_e(verdict.verdict)}</strong> "
                   f"({_e(verdict.confidence)}) &mdash; {_e(verdict.reasoning)}</div>")
    return "".join(out)


def _agent_html(w: Warrant, children: dict, by_warrant: dict, verdicts: dict) -> str:
    s = w.scope
    summary = (f"ops {', '.join(sorted(s.operations)) or '-'} &middot; targets "
               f"{_e(', '.join(sorted(s.targets)) or '-')}"
               + (f" &middot; per action {s.max_scale}" if s.max_scale is not None else "")
               + (f" &middot; total {s.max_total}" if s.max_total is not None else ""))
    parts = [f"<li class='agent'><strong>{_e(w.holder)}</strong> "
             f"<span class='muted mono'>{_e(w.warrant_id)}</span>"
             f"<div class='muted mono'>{summary}</div>"]
    parts += [_action_html(a, verdicts.get(a.action_id)) for a in by_warrant.get(w.warrant_id, [])]
    kids = children.get(w.warrant_id, [])
    if kids:
        parts.append("<ul>" + "".join(_agent_html(k, children, by_warrant, verdicts) for k in kids) + "</ul>")
    parts.append("</li>")
    return "".join(parts)


def session_page(store: Store, session_id: str, verifier: Authority | None = None) -> str | None:
    """One session's page, or None when there is no such session."""
    sess = store.get_session(session_id)
    if sess is None:
        return None
    warrants = store.warrants_for_session(session_id)
    actions = store.actions_for_session(session_id)
    by_warrant: dict[str, list[ActionRecord]] = defaultdict(list)
    for a in actions:
        by_warrant[a.warrant_id].append(a)
    roots, children = build_tree(warrants)

    root = roots[0] if roots else None
    left = ["<div class='card'><h2>Granted scope</h2>",
            _scope_html(root.scope) if root else "<p class='muted'>No root warrant.</p>", "</div>"]
    if isinstance(sess.contract, dict) and sess.contract.get("contract"):
        left += ["<div class='card'><h2>Compiled contract</h2>", _contract_html(sess.contract), "</div>"]
    elif isinstance(sess.contract, dict) and sess.contract.get("observed"):
        left.append("<div class='card'><h2>Observed, not authorized</h2><p class='unk'>Rebuilt from "
                    "existing OpenTelemetry spans. No warrants were issued, so actions were recorded "
                    "but not checked, and nothing here is signed.</p></div>")
    else:
        left.append("<div class='card'><h2>Contract</h2><p class='muted'>None - the scope was "
                    "written by hand rather than compiled from the request.</p></div>")
    left += ["<div class='card'><h2>Verification</h2>",
             _verification_html(store, warrants, verifier) if warrants else "<p class='muted'>No warrants.</p>",
             "</div>"]

    violations = sum(1 for a in actions if not a.allowed)
    unverifiable = sum(1 for a in actions for f in a.findings if f.status == "unverifiable")
    verdicts = store.verdicts_for_session(session_id)
    tree = "<ul class='tree'>" + "".join(_agent_html(r, children, by_warrant, verdicts) for r in roots) + "</ul>"
    right = (f"<div class='card'><h2>Delegation chain</h2>"
             f"<p class='muted'>{len(warrants)} warrants &middot; {len(actions)} actions &middot; "
             f"<span class='{'fail' if violations else 'ok'}'>{violations} violation(s)</span>"
             + (f" &middot; <span class='unk'>{unverifiable} unverifiable</span>" if unverifiable else "")
             + f"</p>{tree}</div>")

    body = (f"<h1>{_e(sess.request)}</h1>"
            f"<p class='muted'>{_e(sess.principal)} &middot; "
            f"<span class='mono'>{_e(sess.started_at.isoformat())}</span> &middot; "
            f"<span class='mono'>{_e(sess.session_id)}</span></p>"
            f"<div class='grid'><div>{''.join(left)}</div><div>{right}</div></div>")
    return _page(f"warrant - {sess.request}", body)
