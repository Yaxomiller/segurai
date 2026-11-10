"""The web view: what was asked, beside what happened.

    segurai ui --db segurai.db          then open http://127.0.0.1:8700/
    segurai demo                        the same pages, on a made-up company

Four pages:

  /                  the overview: headline numbers, record integrity, and every
                     request with how it went
  /sessions/<id>     one request: a plain-English account of anything that went
                     wrong, the delegation chain from the person to every agent
                     and action, what was asked and granted, and whether the
                     signatures check out
  /audit             record integrity: whether anything was edited or deleted
                     after it was written (see collector/ledger.py)
  /permissions       granted versus used: the standing access nobody needed

Two audiences read these pages, so each one is written twice over. The top of
a page says what happened in plain words, for someone deciding whether this
matters; the exact findings, ids and limits sit underneath, for the engineer
deciding whether to believe it.

Deliberately simple underneath: HTML built on the server, inline CSS, and no
JavaScript at all. It has to run anywhere the collector runs and be safe to
open.

Safety: every piece of text that came from outside - request text, agent
names, resource names, reasons - goes through ``_e`` (HTML escaping), so a
request containing "<script>" is displayed, never run. The server also sends
a Content-Security-Policy (``CSP`` below) that forbids scripts outright, as a
second line of defence.
"""

from __future__ import annotations

import html
import re
import time
import weakref
from collections import defaultdict
from contextvars import ContextVar
from datetime import timedelta
from typing import Any
from urllib.parse import quote, urlencode

from ..authority import Authority, ChainError, verify_chain
from ..models import ActionRecord, Finding, Scope, Warrant, utcnow
from .chain import build_tree
from .ledger import AuditReport
from .store import Store

__all__ = ["index_page", "session_page", "audit_page", "permissions_page", "login_page",
           "users_page", "access_page", "message_page", "CSP", "current_viewer"]

#: The signed-in person the page is being drawn for (a WebSession), set by the
#: server for each request. None when the dashboard runs without accounts.
current_viewer: ContextVar = ContextVar("segurai_viewer", default=None)


def _can(role: str) -> bool:
    """Whether the current viewer holds ``role``. Without accounts, everything shows."""
    viewer = current_viewer.get()
    return viewer is None or viewer.user.can(role)

#: Sent with every page: no scripts, no external anything, only our own inline styles.
CSP = ("default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

_STYLE = """
:root { --bg:#f6f6f3; --fg:#18181b; --muted:#6b6b72; --line:#e4e4df; --card:#ffffff;
        --soft:#f1f1ec; --accent:#2f4fd8;
        --ok:#18794e; --ok-bg:#e9f6ef; --fail:#b42318; --fail-bg:#fdecea;
        --blocked:#6941c6; --blocked-bg:#f1ecfd; --unk:#935f00; --unk-bg:#fdf3dc;
        --code:#efefea; --shadow:0 1px 2px rgba(0,0,0,.04), 0 1px 1px rgba(0,0,0,.03); }
@media (prefers-color-scheme: dark) {
  :root { --bg:#121214; --fg:#ececee; --muted:#9d9da6; --line:#2a2a2f; --card:#1b1b1f;
          --soft:#222227; --accent:#8ea2ff;
          --ok:#5fd394; --ok-bg:#15291f; --fail:#ff8a80; --fail-bg:#33191a;
          --blocked:#c3a6ff; --blocked-bg:#251d38; --unk:#f0c262; --unk-bg:#30270f;
          --code:#26262b; --shadow:none; }
}
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
       font:15px/1.55 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
a { color:inherit; }
header { background:var(--card); border-bottom:1px solid var(--line); }
.bar { max-width:1240px; margin:0 auto; padding:12px 24px; display:flex; flex-wrap:wrap;
       align-items:center; gap:10px 22px; }
.brand { font-weight:700; font-size:17px; text-decoration:none; letter-spacing:-.01em; }
.tag { color:var(--muted); font-size:13px; }
nav { display:flex; gap:4px; flex-wrap:wrap; }
nav a { text-decoration:none; padding:5px 10px; border-radius:6px; color:var(--muted); font-size:14px; }
nav a:hover { background:var(--soft); color:var(--fg); }
nav a.on { background:var(--soft); color:var(--fg); font-weight:600; }
.spacer { flex:1; }
main { max-width:1240px; margin:0 auto; padding:24px; }
.banner { background:var(--soft); border:1px solid var(--line); border-radius:10px; padding:10px 14px;
          font-size:13.5px; color:var(--muted); margin-bottom:20px; }
.banner strong { color:var(--fg); }
h1 { font-size:24px; line-height:1.25; margin:0 0 6px; letter-spacing:-.015em; }
h2 { font-size:12px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted);
     margin:0 0 12px; font-weight:600; }
h3 { font-size:15px; margin:0 0 6px; }
p { margin:0 0 10px; }
.lede { color:var(--muted); margin-bottom:22px; max-width:760px; }
.muted { color:var(--muted); }
.small { font-size:13px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px;
        margin-bottom:18px; box-shadow:var(--shadow); overflow-x:auto; }
.grid { display:grid; grid-template-columns:minmax(300px, 1fr) 1.6fr; gap:18px; align-items:start; }
@media (max-width: 900px) { .grid { grid-template-columns:1fr; } }
.tiles { display:grid; grid-template-columns:repeat(auto-fit, minmax(150px, 1fr)); gap:12px;
         margin-bottom:22px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:14px 16px;
        box-shadow:var(--shadow); text-decoration:none; display:block; }
.tile .n { font-size:28px; font-weight:700; letter-spacing:-.02em; line-height:1.1; }
.tile .l { color:var(--muted); font-size:13px; margin-top:4px; }
.table-wrap { overflow-x:auto; }
table { border-collapse:collapse; width:100%; }
th, td { text-align:left; padding:10px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
tr:last-child td { border-bottom:none; }
th { color:var(--muted); font-weight:500; font-size:13px; }
td a.req { font-weight:600; text-decoration:none; }
td a.req:hover { text-decoration:underline; }
code, .mono { font-family:ui-monospace, "Cascadia Code", Consolas, monospace; font-size:12.5px; }
code { background:var(--code); padding:1px 5px; border-radius:4px; }
pre { background:var(--code); border-radius:8px; padding:10px 12px; overflow-x:auto; margin:6px 0 0; }
.chip { display:inline-block; font-size:12px; font-weight:600; padding:2px 9px; border-radius:999px;
        white-space:nowrap; }
.chip.ok { background:var(--ok-bg); color:var(--ok); }
.chip.fail { background:var(--fail-bg); color:var(--fail); }
.chip.blocked { background:var(--blocked-bg); color:var(--blocked); }
.chip.unk { background:var(--unk-bg); color:var(--unk); }
.chip.plain { background:var(--soft); color:var(--muted); }
.ok { color:var(--ok); } .fail { color:var(--fail); } .blocked { color:var(--blocked); } .unk { color:var(--unk); }
.quote { font-size:22px; font-weight:650; letter-spacing:-.015em; margin:4px 0 6px; }
.quote::before { content:"\\201C"; color:var(--muted); } .quote::after { content:"\\201D"; color:var(--muted); }
.story { border-left:4px solid var(--fail); }
.story.blocked { border-left-color:var(--blocked); }
.story.unk { border-left-color:var(--unk); }
.story ul { margin:6px 0 10px; padding-left:20px; }
.story li { margin:3px 0; }
.judge { background:var(--soft); border-radius:10px; padding:10px 12px; margin-top:8px; }
.judge .who { font-size:12px; color:var(--muted); }
.person { display:inline-flex; align-items:center; gap:8px; background:var(--soft); border-radius:999px;
          padding:4px 12px; font-weight:600; font-size:14px; }
ul.tree, ul.tree ul { list-style:none; margin:0; }
ul.tree { padding:0; margin-top:10px; }
ul.tree ul { padding-left:20px; border-left:2px solid var(--line); margin-left:10px; }
li.agent { margin:10px 0; }
.node { border:1px solid var(--line); border-radius:10px; padding:10px 12px; background:var(--card); }
.node .name { font-weight:650; }
.node .meta { color:var(--muted); font-size:12.5px; }
.action { display:flex; gap:8px; align-items:baseline; flex-wrap:wrap; padding:6px 8px; margin-top:6px;
          border-radius:8px; background:var(--soft); }
.action.fail { background:var(--fail-bg); } .action.blocked { background:var(--blocked-bg); }
.action.unk { background:var(--unk-bg); }
.badge { display:inline-block; min-width:64px; text-align:center; font-size:11px; font-weight:700;
         padding:1px 6px; border-radius:4px; border:1px solid currentColor; }
.finding { margin:2px 0 2px 76px; font-size:12.5px; }
dl { display:grid; grid-template-columns:max-content 1fr; gap:6px 14px; margin:0; }
dt { color:var(--muted); font-size:13.5px; } dd { margin:0; }
ul.plain { margin:0; padding-left:18px; }
.perm { display:inline-block; font-family:ui-monospace, Consolas, monospace; font-size:12px;
        padding:1px 7px; border-radius:5px; margin:2px 3px 2px 0; }
.perm.used { background:var(--ok-bg); color:var(--ok); }
.perm.unused { background:var(--fail-bg); color:var(--fail); text-decoration:line-through; }
.big { font-size:26px; font-weight:700; letter-spacing:-.02em; }
footer { max-width:1240px; margin:0 auto; padding:8px 24px 32px; color:var(--muted); font-size:12.5px; }
input, select, button { font:inherit; font-size:14px; padding:6px 10px; border:1px solid var(--line);
         border-radius:8px; background:var(--card); color:var(--fg); }
button { cursor:pointer; background:var(--soft); }
button.primary { background:var(--accent); border-color:var(--accent); color:#fff; font-weight:600; }
form.inline { display:inline; margin:0; }
.filters { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom:14px; }
.filters input[type=search] { min-width:240px; flex:1; }
.pager { display:flex; justify-content:space-between; align-items:center; margin-top:12px; }
.who { font-size:13px; color:var(--muted); display:flex; gap:8px; align-items:center; }
.login { max-width:420px; margin:40px auto; }
.login label { display:block; font-size:13px; color:var(--muted); margin:10px 0 4px; }
.login input { width:100%; }
.error { color:var(--fail); background:var(--fail-bg); border-radius:8px; padding:8px 12px; margin-bottom:12px; }
"""


def _e(value: Any) -> str:
    """Escape text for HTML. Everything from outside the program goes through this."""
    return html.escape(str(value), quote=True)


def _link(session_id: str) -> str:
    return f"/sessions/{_e(quote(session_id, safe=''))}"


# ---- what every page shares ------------------------------------------------------

#: Audit results per store, reused only while the database provably hasn't
#: changed. Keyed by the store object itself (weakly) - never by id(), which
#: Python reuses: a reopened database must never inherit an old "all clear".
_AUDIT_CACHE: "weakref.WeakKeyDictionary[Store, tuple[float, Any, Any, AuditReport]]" = weakref.WeakKeyDictionary()
#: An upper bound on reuse even when nothing changed.
AUDIT_CACHE_SECONDS = 20.0


def _integrity(store: Store, verifier: Authority | None, fresh: bool = False) -> AuditReport:
    """The tamper-evident log's audit, reused only while nothing in the database changed."""
    marker = store.change_marker()
    cached = _AUDIT_CACHE.get(store)
    if (not fresh and marker is not None and cached is not None and cached[1] == marker
            and cached[2] is verifier
            and time.monotonic() - cached[0] < AUDIT_CACHE_SECONDS):
        return cached[3]
    report = store.audit(verifier)
    _AUDIT_CACHE[store] = (time.monotonic(), store.change_marker(), verifier, report)
    return report


def _integrity_chip(report: AuditReport) -> str:
    if not report.ok:
        return "<a class='chip fail' href='/audit'>&#x2717; Tampering detected</a>"
    if report.entries == 0:
        return "<span class='chip plain'>No records yet</span>"
    if report.checkpoints and report.signatures_checked:
        return "<a class='chip ok' href='/audit'>&#x2713; Records verified</a>"
    return "<a class='chip unk' href='/audit'>&#x2713; Records intact &middot; not signed</a>"


def _is_sample(store: Store) -> bool:
    return any(isinstance(s.contract, dict) and s.contract.get("sample") for s in store.sessions(limit=50))


def _page(title: str, body: str, *, store: Store | None = None, verifier: Authority | None = None,
          current: str = "", integrity: AuditReport | None = None) -> str:
    chip = ""
    banner = ""
    if store is not None:
        chip = _integrity_chip(integrity if integrity is not None else _integrity(store, verifier))
        if _is_sample(store):
            banner = ("<div class='banner'><strong>Sample company.</strong> Every record here was "
                      "produced by real Segurai code: signed warrants, Tier 1 checks, the hash-chained "
                      "log. The company, people and requests are made up, and the compiled contracts "
                      "and AI reviews are pre-written samples, labelled wherever they appear.</div>")
    viewer = current_viewer.get()
    items = [("overview", "/", "Overview", "viewer"), ("permissions", "/permissions", "Permissions", "viewer"),
             ("audit", "/audit", "Record integrity", "auditor")]
    if viewer is not None:
        items += [("access", "/access", "Access log", "auditor"), ("people", "/admin/users", "People", "admin")]
    nav = "".join(
        f"<a href='{href}'{' class=on' if current == key else ''}>{label}</a>"
        for key, href, label, role in items if _can(role)
    )
    who = ""
    if viewer is not None:
        who = (f"<span class='who'>{_e(viewer.user.email)} &middot; {_e(viewer.user.role)}"
               f"<form class='inline' method='post' action='/logout'>"
               f"<input type='hidden' name='csrf' value='{_e(viewer.csrf)}'>"
               f"<button type='submit'>Sign out</button></form></span>")
    if not _can("auditor"):
        chip = ""          # integrity details are for auditors
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        f"<title>{_e(title)}</title><style>{_STYLE}</style></head><body>"
        "<header><div class='bar'><a class='brand' href='/'>Segurai</a>"
        "<span class='tag'>who authorized what your agents did</span>"
        f"<nav>{nav}</nav><span class='spacer'></span>{chip}{who}</div></header>"
        f"<main>{banner}{body}</main>"
        "<footer>Read-only view &middot; no scripts on any page &middot; "
        "signatures and the record log are re-checked on every load.</footer>"
        "</body></html>"
    )


def _problem_session(store: Store, kind: str | None, ref_id: str | None) -> str | None:
    """The session an audit problem is about, so the page can link to it."""
    if not ref_id:
        return None
    if ref_id.startswith("ses_") or ref_id.startswith("otel_"):
        return ref_id
    for table, column in (("actions", "action_id"), ("verdicts", "action_id"), ("warrants", "warrant_id")):
        rows = store._read(f"SELECT session_id FROM {table} WHERE {column} = ?", (ref_id,))
        if rows:
            return rows[0]["session_id"]
    return None


def _session_problems(store: Store, report: AuditReport, session_id: str) -> list:
    return [p for p in report.problems if _problem_session(store, p.kind, p.ref_id) == session_id]


def _list(items: list[str], empty: str = "none") -> str:
    if not items:
        return f"<span class='muted'>{_e(empty)}</span>"
    return "<ul class='plain'>" + "".join(f"<li>{_e(i)}</li>" for i in items) + "</ul>"


def _codes(items: list[str]) -> str:
    return " ".join(f"<code>{_e(i)}</code>" for i in items) or "<span class='muted'>none</span>"


# ---- plain English -----------------------------------------------------------------

def _limit(clause: str) -> str | None:
    """'max_scale=50' -> '50'."""
    match = re.search(r"=(\S+)$", clause or "")
    return match.group(1) if match else None


def _explain(f: Finding, a: ActionRecord) -> str:
    """One finding as a sentence a non-engineer can read. Returns HTML."""
    if f.status == "unverifiable":
        if f.check == "warrant":
            return "Seen through existing telemetry only: nothing here was authorized or checked."
        return (f"It didn't report enough to check <strong>{_e(f.clause or f.reason)}</strong> "
                "&mdash; a question for a person, not a violation.")
    if f.check == "operation":
        return f"It used <strong>{_e(a.operation)}</strong>, which was never granted."
    if f.check == "target":
        return f"It touched <strong>{_e(a.resource)}</strong>, outside what it was given."
    if f.check == "scale":
        limit = _limit(f.clause)
        return (f"It changed <strong>{_e(a.scale)}</strong> records in one go"
                + (f" &mdash; the limit was {_e(limit)}." if limit else "."))
    if f.check == "total":
        reached = re.search(r"reach (\d+)", f.reason)
        limit = _limit(f.clause)
        return ("It took this request past its overall budget"
                + (f": <strong>{_e(reached.group(1))}</strong> records" if reached else "")
                + (f" against a limit of {_e(limit)}." if limit else "."))
    if f.check == "irreversible":
        return "It did something that <strong>can't be undone</strong>, which wasn't allowed."
    if f.check == "condition":
        return f"It broke a condition of the request: <strong>{_e(f.clause or f.reason)}</strong>."
    if f.check == "spec":
        return "The tool call couldn't be described, so nobody could have authorized it."
    if f.check == "policy":
        rule = f.clause.split(": ", 1)[-1] if f.clause else "an organisation rule"
        return (f"It broke an organisation rule that no request can override: "
                f"<strong>{_e(rule)}</strong>.")
    return _e(f.reason)


def _what_it_did(a: ActionRecord) -> str:
    verb = {"delete": "deleted", "archive": "archived", "update": "updated", "share": "shared",
            "send": "sent", "refund": "refunded", "snooze": "snoozed"}.get(a.operation, a.operation)
    noun = "record" if a.scale == 1 else "records"
    if a.blocked:
        return (f"<strong>{_e(a.actor)}</strong> tried to {_e(a.operation)} {_e(a.scale)} {noun} in "
                f"<code>{_e(a.resource)}</code> &mdash; <span class='blocked'>stopped before it happened</span>")
    if a.allowed:
        return (f"<strong>{_e(a.actor)}</strong> {_e(verb)} {_e(a.scale)} {noun} in "
                f"<code>{_e(a.resource)}</code>")
    return (f"<strong>{_e(a.actor)}</strong> {_e(verb)} {_e(a.scale)} {noun} in "
            f"<code>{_e(a.resource)}</code> &mdash; <span class='fail'>it went ahead</span>")


def _identity_chip(sess: Any) -> str:
    """Whether the person at the top of a request was proven, or only named."""
    identity = getattr(sess, "identity", None)
    if identity:
        issuer = str(identity.get("issuer") or "the login system")
        return (f"<span class='chip ok' title='Signed ID token checked against {_e(issuer)}'>"
                f"&#x2713; identity verified</span>")
    if isinstance(getattr(sess, "contract", None), dict) and sess.contract.get("observed"):
        return ""
    return ("<span class='chip unk' title='Named by the calling code; no login system vouched for it'>"
            "claimed, not verified</span>")


def _session_status(actions: list[ActionRecord]) -> tuple[str, str]:
    """(css class, label) for a whole request."""
    violations = sum(1 for a in actions if not a.allowed)
    blocked = sum(1 for a in actions if a.blocked)
    observed = any(f.check == "warrant" for a in actions for f in a.findings)
    unverifiable = sum(1 for a in actions for f in a.findings if f.status == "unverifiable")
    noun = "violation" if violations == 1 else "violations"
    if violations and blocked == violations:
        return "blocked", f"{violations} {noun} &middot; stopped"
    if violations:
        extra = f" &middot; {blocked} stopped" if blocked else " &middot; went ahead"
        return "fail", f"{violations} {noun}{extra}"
    if observed:
        return "plain", "observed only"
    if unverifiable:
        return "unk", "needs a look"
    return "ok", "clean"


def _judge_html(verdict: Any) -> str:
    if verdict is None:
        return ""
    tone = {"within_intent": "ok", "outside_intent": "fail"}.get(verdict.verdict, "unk")
    label = {"within_intent": "Within what was asked", "outside_intent": "Beyond what was asked",
             "needs_human": "Needs a person to decide"}.get(verdict.verdict, verdict.verdict)
    source = (verdict.model or "").startswith("sample")
    who = "AI review (sample, pre-written for the demo)" if source else f"AI review &middot; {_e(verdict.model or '')}"
    # Tier 2's verdict is shown beside Tier 1's findings, never instead of them.
    return (f"<div class='judge'><div class='who'>{who}</div>"
            f"<strong class='{tone}'>judge: {_e(verdict.verdict)}</strong> "
            f"<span class='muted'>&middot; {label} &middot; {_e(verdict.confidence)} confidence</span>"
            f"<div>{_e(verdict.reasoning)}</div></div>")


# ---- the overview ------------------------------------------------------------------

OUTCOMES = (("", "Any outcome"), ("flagged", "Went beyond the request"), ("blocked", "Stopped"),
            ("review", "Needs a look"), ("clean", "Clean"), ("verified", "Identity verified"))


def _filters_html(filters: dict[str, str]) -> str:
    options = "".join(f"<option value='{v}'{' selected' if filters.get('outcome') == v else ''}>{label}</option>"
                      for v, label in OUTCOMES)
    return ("<form class='filters' method='get' action='/'>"
            f"<input type='search' name='q' placeholder='Search requests, people, session ids' "
            f"value='{_e(filters.get('q', ''))}' maxlength='200'>"
            f"<input type='text' name='agent' placeholder='Agent' value='{_e(filters.get('agent', ''))}' "
            f"maxlength='100'>"
            f"<select name='outcome'>{options}</select>"
            "<button type='submit'>Filter</button>"
            + ("<a href='/' class='small'>Clear</a>" if any(filters.values()) else "")
            + "</form>")


def index_page(store: Store, limit: int = 50, verifier: Authority | None = None,
               filters: dict[str, str] | None = None) -> str:
    """Headline numbers, then every request matching the filters, newest first, a page at a time."""
    filters = {k: v for k, v in (filters or {}).items() if k in ("q", "agent", "outcome", "page") and v}
    try:
        page = max(1, min(int(filters.pop("page", "1")), 10_000))
    except ValueError:
        page = 1
    sessions, total = store.search_sessions(q=filters.get("q"), agent=filters.get("agent"),
                                            outcome=filters.get("outcome"), limit=limit,
                                            offset=(page - 1) * limit)
    integrity = _integrity(store, verifier)
    altered = {_problem_session(store, p.kind, p.ref_id) for p in integrity.problems}
    rows = []
    totals = store.stats()
    for s in sessions:
        actions = store.actions_for_session(s.session_id)
        verdicts = store.verdicts_for_session(s.session_id)
        cls, label = _session_status(actions)
        review = ""
        if verdicts:
            v = next(iter(verdicts.values()))
            tone = {"within_intent": "ok", "outside_intent": "fail"}.get(v.verdict, "unk")
            review = f"<span class='{tone}'>{_e(v.verdict.replace('_', ' '))}</span>"
        rows.append(
            "<tr>"
            f"<td><a class='req' href='{_link(s.session_id)}'>{_e(s.request)}</a>"
            f"<div class='muted mono'>{_e(s.session_id)}</div></td>"
            f"<td>{_e(s.principal)}"
            + (" <span class='ok' title='identity verified'>&#x2713;</span>" if s.verified else "")
            + "</td>"
            f"<td>{len(actions)}</td>"
            f"<td><span class='chip {cls}'>{label}</span>"
            + (" <a class='chip fail' href='/audit'>&#x2717; altered after the fact</a>"
               if s.session_id in altered else "")
            + "</td>"
            f"<td class='small'>{review or '<span class=muted>&mdash;</span>'}</td>"
            f"<td class='mono muted' style='white-space:nowrap'>{_e(s.started_at.strftime('%Y-%m-%d %H:%M'))}</td>"
            "</tr>"
        )

    tile_integrity = ("<a class='tile' href='/audit'><div class='n fail'>&#x2717;</div>"
                      "<div class='l'>Tampering detected</div></a>" if not integrity.ok else
                      "<a class='tile' href='/audit'><div class='n ok'>&#x2713;</div>"
                      f"<div class='l'>{integrity.entries} records, none altered</div></a>")
    tiles = (
        "<div class='tiles'>"
        f"<div class='tile'><div class='n'>{totals['sessions']}</div><div class='l'>Requests from people</div></div>"
        f"<div class='tile'><div class='n'>{totals['actions']}</div><div class='l'>Agent actions recorded</div></div>"
        f"<div class='tile'><div class='n fail'>{totals['flagged']}</div><div class='l'>Went beyond the request</div></div>"
        f"<div class='tile'><div class='n blocked'>{totals['blocked']}</div><div class='l'>Stopped before they happened</div></div>"
        f"<div class='tile'><div class='n unk'>{totals['unk']}</div><div class='l'>Need a person to look</div></div>"
        f"{tile_integrity}"
        "</div>"
    )
    if rows:
        table = ("<div class='table-wrap'><table><thead><tr><th>Request</th><th>Asked by</th>"
                 "<th>Actions</th><th>Outcome</th><th>AI review</th><th>When (UTC)</th></tr></thead>"
                 f"<tbody>{''.join(rows)}</tbody></table></div>")
    else:
        table = ("<p class='muted'>No requests match these filters.</p>" if filters
                 else "<p class='muted'>No sessions recorded yet.</p>")
    pages = max(1, -(-total // limit))
    query = {k: v for k, v in filters.items()}
    prev_link = (f"<a href='/?{_e(urlencode({**query, 'page': page - 1}))}'>&larr; Newer</a>"
                 if page > 1 else "<span></span>")
    next_link = (f"<a href='/?{_e(urlencode({**query, 'page': page + 1}))}'>Older &rarr;</a>"
                 if page < pages else "<span></span>")
    pager = (f"<div class='pager small'>{prev_link}<span class='muted'>{total} request(s) &middot; "
             f"page {page} of {pages}</span>{next_link}</div>")
    body = ("<h1>Every agent action, traced to the person who asked</h1>"
            "<p class='lede'>Each request below is linked to the agents it set in motion and everything "
            "they did. Anything that went beyond the request is flagged, and the record itself is "
            "tamper-evident.</p>"
            f"{tiles}<div class='card'><h2>Sessions</h2>{_filters_html(filters)}{table}{pager}</div>")
    return _page("Segurai - sessions", body, store=store, verifier=verifier, current="overview",
                 integrity=integrity)


# ---- one request -------------------------------------------------------------------

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
            f"(<code>{_e(verifier.key_id)}</code>), links and narrowing intact.</p>"
            "<p class='muted small'>Each agent's permission was signed, and each one is narrower than "
            "the one it came from, so none of them could have given itself more.</p>")


def _action_html(a: ActionRecord, verdict: Any = None) -> str:
    if a.allowed:
        cls, label = "ok", "ok"
    elif a.blocked:
        cls, label = "blocked", "BLOCKED"
    else:
        cls, label = "fail", "FAIL"
    unk = a.allowed and any(f.status == "unverifiable" for f in a.findings)
    extra = " &middot; irreversible" if a.irreversible else ""
    out = [f"<div class='action {('unk' if unk else cls) if cls != 'ok' or unk else ''}'>"
           f"<span class='badge {cls}'>{label}</span>"
           f"<span class='mono'>{_e(a.operation)} {_e(a.resource)}</span> "
           f"<span class='muted mono'>scale={a.scale}{extra}</span></div>"]
    for f in a.findings:
        if f.status == "fail":
            out.append(f"<div class='finding mono fail'>&#x2717; {_e(f.reason)}</div>")
        else:
            out.append(f"<div class='finding mono unk'>? {_e(f.reason)}</div>")
    if not a.findings and not a.allowed:
        out.append(f"<div class='finding mono fail'>&#x2717; {_e(a.violation)}</div>")
    if verdict is not None:
        out.append(f"<div class='finding'>{_judge_html(verdict)}</div>")
    return "".join(out)


def _agent_html(w: Warrant, children: dict, by_warrant: dict, verdicts: dict) -> str:
    s = w.scope
    summary = (f"may {_e(', '.join(sorted(s.operations)) or '-')} on "
               f"{_e(', '.join(sorted(s.targets)) or '-')}"
               + (f" &middot; up to {s.max_scale} per action" if s.max_scale is not None else "")
               + (f" &middot; {s.max_total} in total" if s.max_total is not None else ""))
    parts = [f"<li class='agent'><div class='node'><span class='name'>{_e(w.holder)}</span> "
             f"<span class='muted mono small'>{_e(w.warrant_id)}</span>"
             f"<div class='meta'>{summary}</div>"]
    parts += [_action_html(a, verdicts.get(a.action_id)) for a in by_warrant.get(w.warrant_id, [])]
    parts.append("</div>")
    kids = children.get(w.warrant_id, [])
    if kids:
        parts.append("<ul>" + "".join(_agent_html(k, children, by_warrant, verdicts) for k in kids) + "</ul>")
    parts.append("</li>")
    return "".join(parts)


def _story_html(actions: list[ActionRecord], verdicts: dict) -> str:
    """The plain-English account at the top of a request: only what needs attention."""
    notable = [a for a in actions if not a.allowed
               or any(f.status == "unverifiable" and f.check != "warrant" for f in a.findings)]
    if not notable:
        return ""
    cards = []
    for a in notable:
        tone = "blocked" if a.blocked else ("" if not a.allowed else "unk")
        sentences = "".join(f"<li>{_explain(f, a)}</li>" for f in a.findings)
        cards.append(f"<div class='card story {tone}'><h2>What happened</h2>"
                     f"<p>{_what_it_did(a)}</p><ul>{sentences}</ul>"
                     f"{_judge_html(verdicts.get(a.action_id))}</div>")
    return "".join(cards)


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
    verdicts = store.verdicts_for_session(session_id)

    root = roots[0] if roots else None
    left = []
    if isinstance(sess.contract, dict) and sess.contract.get("contract"):
        left += ["<div class='card'><h2>What was asked, as a contract</h2>", _contract_html(sess.contract), "</div>"]
    elif isinstance(sess.contract, dict) and sess.contract.get("observed"):
        left.append("<div class='card'><h2>Observed, not authorized</h2><p class='unk'>Rebuilt from "
                    "existing OpenTelemetry spans. No warrants were issued, so actions were recorded "
                    "but not checked, and nothing here is signed.</p><p class='muted small'>This is "
                    "the zero-integration path: point an existing OpenTelemetry exporter at the "
                    "collector and the agent chain appears, with no code changes.</p></div>")
    else:
        left.append("<div class='card'><h2>Contract</h2><p class='muted'>None - the scope was "
                    "written by hand rather than compiled from the request.</p></div>")
    left += ["<div class='card'><h2>Granted scope</h2>",
             _scope_html(root.scope) if root else "<p class='muted'>No root warrant.</p>", "</div>"]
    left += ["<div class='card'><h2>Verification</h2>",
             _verification_html(store, warrants, verifier) if warrants else "<p class='muted'>No warrants.</p>",
             "</div>"]

    violations = sum(1 for a in actions if not a.allowed)
    unverifiable = sum(1 for a in actions for f in a.findings if f.status == "unverifiable")
    tree = "<ul class='tree'>" + "".join(_agent_html(r, children, by_warrant, verdicts) for r in roots) + "</ul>"
    right = (f"<div class='card'><h2>Delegation chain</h2>"
             f"<span class='person'>{_e(sess.principal)}</span>"
             f"<p class='muted small' style='margin-top:8px'>{len(warrants)} warrants &middot; "
             f"{len(actions)} actions &middot; "
             f"<span class='{'fail' if violations else 'ok'}'>{violations} violation(s)</span>"
             + (f" &middot; <span class='unk'>{unverifiable} unverifiable</span>" if unverifiable else "")
             + f"</p>{tree}</div>")

    cls, label = _session_status(actions)
    integrity = _integrity(store, verifier)
    changed = _session_problems(store, integrity, session_id)
    warning = ""
    if changed:
        warning = ("<div class='card story'><div class='big fail'>&#x2717; This record was changed "
                   "after it was written</div><p>What you see below is the <em>current</em> data, and it "
                   "no longer matches the tamper-evident log. Treat it as untrustworthy. "
                   "<a href='/audit'>See exactly what changed &rarr;</a></p></div>")
    body = (f"<p class='small'><a href='/'>&larr; All requests</a></p>"
            f"<div class='quote'>{_e(sess.request)}</div>"
            f"<p class='muted'>asked by <strong>{_e(sess.principal)}</strong> "
            f"{_identity_chip(sess)} &middot; "
            f"<span class='mono'>{_e(sess.started_at.isoformat())}</span> &middot; "
            f"<span class='mono'>{_e(sess.session_id)}</span> &middot; "
            f"<span class='chip {cls}'>{label}</span></p>"
            + (f"<p class='small'><a href='{_link(session_id)}/evidence.zip'>Download the evidence pack</a> "
               "<span class='muted'>&middot; a file an auditor can check on its own</span></p>"
               if _can("auditor") and current_viewer.get() is not None else "")
            + f"{warning}{_story_html(actions, verdicts)}"
            f"<div class='grid'><div>{''.join(left)}</div><div>{right}</div></div>")
    return _page(f"Segurai - {sess.request}", body, store=store, verifier=verifier,
                 integrity=integrity)


# ---- record integrity -----------------------------------------------------------------

def audit_page(store: Store, verifier: Authority | None = None, witnessed: list | None = None) -> str:
    """Whether anything was edited or deleted after it was written."""
    report = store.audit(verifier, witnessed=witnessed) if witnessed else _integrity(store, verifier, fresh=True)
    if not report.ok:
        status = ("<div class='card story'><div class='big fail'>&#x2717; Tampering detected</div>"
                  "<p>Records were changed after they were written. The pages elsewhere show the "
                  "<em>current</em> data, which may now tell a different story. What changed:</p><ul>"
                  + "".join(_audit_problem_html(store, p) for p in report.problems)
                  + "</ul></div>")
    else:
        status = ("<div class='card story' style='border-left-color:var(--ok)'>"
                  "<div class='big ok'>&#x2713; Every record is intact</div>"
                  f"<p>All {report.entries} records still match what was written, and each one still "
                  "links to the one before it.</p></div>")

    if report.checkpoints and report.signatures_checked:
        signed = (f"<span class='ok'>{report.checkpoints_verified} of {report.checkpoints} signed "
                  "checkpoint(s) hold</span>")
    elif report.checkpoints:
        signed = f"<span class='unk'>{report.checkpoints} checkpoint(s); signatures not checked (no key)</span>"
    else:
        signed = ("<span class='unk'>none yet &mdash; without one, someone with database access "
                  "could rebuild the whole chain</span>")

    facts = ("<div class='card'><h2>The record log</h2><dl>"
             f"<dt>Records logged</dt><dd>{report.entries}</dd>"
             f"<dt>Checked against the log</dt><dd>{report.rows_checked}</dd>"
             f"<dt>Chain sound up to</dt><dd>entry {report.verified_to}</dd>"
             f"<dt>Signed checkpoints</dt><dd>{signed}</dd>"
             f"<dt>Written before the log</dt><dd>{report.rows_unlogged}</dd>"
             f"<dt>Latest hash</dt><dd class='mono'>{_e(report.head[:32])}&hellip;</dd>"
             "</dl></div>")

    how = ("<div class='card'><h2>How it works</h2>"
           "<p>Every record is also written to a <strong>hash chain</strong>: each entry carries a "
           "fingerprint of its own contents <em>and</em> of the entry before it. Edit a record and its "
           "fingerprint no longer matches; delete one and the chain has a gap; reorder them and the "
           "links break.</p>"
           "<p>A determined insider could rebuild the whole chain so it agrees with itself. A "
           "<strong>checkpoint</strong> stops that: the chain's latest fingerprint, signed with a key "
           "the database never holds. Rewriting history would then mean forging that signature.</p>"
           "</div>")
    try_it = ("<div class='card'><h2>Try it</h2>"
              "<p class='small muted'>From the folder you ran the demo in, in a second terminal. "
              "Then reload this page.</p>"
              "<pre>segurai demo tamper      # quietly rewrite the incident\n"
              "segurai demo cover-up    # ...and rebuild the chain to hide it\n"
              "segurai demo             # start again, untouched</pre>"
              "<p class='small muted' style='margin-top:10px'>Or against any database:</p>"
              "<pre>segurai --db segurai.db audit\nsegurai --db segurai.db checkpoint</pre></div>")
    body = ("<h1>Record integrity</h1>"
            "<p class='lede'>An audit trail is only evidence if nobody can quietly edit it. This page "
            "re-checks the whole record every time it loads.</p>"
            f"{status}<div class='grid'><div>{facts}</div><div>{how}{try_it}</div></div>")
    return _page("Segurai - record integrity", body, store=store, verifier=verifier, current="audit",
                 integrity=report)


def _audit_problem_html(store: Store, p: Any) -> str:
    """One audit problem, linked to the request it affects when that can be found."""
    session_id = _problem_session(store, p.kind, p.ref_id)
    where = ""
    if session_id:
        sess = store.get_session(session_id)
        name = sess.request if sess else session_id
        where = f" &mdash; in <a href='{_link(session_id)}'>&ldquo;{_e(name)}&rdquo;</a>"
    ids = f"{p.ref_id or ''}{' entry ' + str(p.seq) if p.seq is not None else ''}"
    if p.kind == "checkpoint":
        # The cover-up case: the chain agrees with itself, only the signature disagrees.
        return ("<li><strong>History was rewritten.</strong> The log no longer matches a fingerprint "
                "that was signed earlier with a key this database never held, so someone rebuilt the "
                f"record to hide a change. <span class='muted mono'>{_e(p.detail)} &middot; {_e(ids)}</span></li>")
    return f"<li>{_e(p.detail)}{where} <span class='muted mono'>{_e(ids)}</span></li>"


# ---- permissions ----------------------------------------------------------------------

def permissions_page(store: Store, verifier: Authority | None = None, days: int = 30) -> str:
    """Granted versus used: the standing access nobody needed."""
    # Imported here rather than at the top: report imports the store module.
    from ..report import build_report

    report = build_report(store, since=utcnow() - timedelta(days=days))
    identities = sorted(report.identities, key=lambda r: (-r.unused_count, r.identity))
    cards = []
    for r in identities:
        if not r.granted_count:
            continue
        ops = "".join(
            f"<span class='perm {'used' if op in r.used_operations else 'unused'}'>{_e(op)}</span>"
            for op in sorted(r.granted_operations))
        targets = "".join(
            f"<span class='perm {'unused' if t in r.unused_targets else 'used'}'>{_e(t)}</span>"
            for t in sorted(r.granted_targets))
        rec = r.recommended
        if not rec.operations or not rec.targets:
            tighter = "<span class='fail'>remove this access entirely</span> &mdash; none of it was used"
        else:
            tighter = (f"may {_e(', '.join(sorted(rec.operations)))} on {_e(', '.join(sorted(rec.targets)))}"
                       + (f", up to {rec.max_scale} per action" if rec.max_scale is not None else ""))
        size = ""
        if r.granted_max_scale is not None:
            size = (f"<dt>Size limit</dt><dd>{r.granted_max_scale} per action granted; the largest "
                    f"real change was {r.largest_change}</dd>")
        cards.append(
            "<div class='card'>"
            f"<h3>{_e(r.identity)}</h3>"
            f"<p class='muted small'>{r.sessions} request(s) &middot; {r.actions} action(s) by it or "
            f"agents it delegated to &middot; "
            f"{r.unused_count} of {r.granted_count} permissions never used &middot; "
            f"confidence {_e(r.confidence)}</p>"
            f"<dl><dt>Operations</dt><dd>{ops}</dd><dt>Targets</dt><dd>{targets}</dd>{size}"
            f"<dt>Safer setup</dt><dd>{tighter}</dd></dl></div>"
        )
    unused, granted = report.unused_permissions, report.granted_permissions
    headline = (f"<div class='tiles'>"
                f"<div class='tile'><div class='n fail'>{unused}</div>"
                f"<div class='l'>permissions granted but never used</div></div>"
                f"<div class='tile'><div class='n'>{granted}</div><div class='l'>permissions granted in total</div></div>"
                f"<div class='tile'><div class='n'>{len(cards)}</div>"
                f"<div class='l'>agents and people with standing access</div></div></div>")
    body = ("<h1>Permissions nobody needed</h1>"
            f"<p class='lede'>Over the last {days} days: what each agent and person was allowed to do, "
            "against what they actually did. <span class='perm used'>green</span> was used; "
            "<span class='perm unused'>struck through</span> was granted and never touched. The "
            "&ldquo;safer setup&rdquo; only ever removes access, and only what the evidence shows "
            "was unused.</p>"
            f"{headline}{''.join(cards) or '<p class=muted>Nothing recorded in this window.</p>'}")
    return _page("Segurai - permissions", body, store=store, verifier=verifier, current="permissions")


# ---- signing in, people, the access log -------------------------------------------------------

def message_page(title: str, message: str, status_class: str = "") -> str:
    body = f"<div class='card login'><h1>{_e(title)}</h1><p class='{status_class}'>{_e(message)}</p>" \
           f"<p><a href='/'>Back to the overview</a></p></div>"
    return _page(f"Segurai - {title}", body)


def login_page(csrf: str, *, error: str = "", next_path: str = "/", local: bool = True,
               oidc_label: str | None = None) -> str:
    parts = ["<div class='card login'><h1>Sign in to Segurai</h1>"]
    if error:
        parts.append(f"<div class='error'>{_e(error)}</div>")
    if oidc_label:
        parts.append(f"<p><a class='chip ok' style='font-size:14px;padding:8px 14px' "
                     f"href='/auth/start?{_e(urlencode({'next': next_path}))}'>Sign in with {_e(oidc_label)}</a></p>")
    if local:
        parts.append(
            "<form method='post' action='/login'>"
            f"<input type='hidden' name='csrf' value='{_e(csrf)}'>"
            f"<input type='hidden' name='next' value='{_e(next_path)}'>"
            "<label for='email'>Email</label><input id='email' name='email' type='email' required "
            "autocomplete='username' maxlength='254'>"
            "<label for='password'>Password</label><input id='password' name='password' type='password' "
            "required autocomplete='current-password' maxlength='200'>"
            "<p style='margin-top:14px'><button class='primary' type='submit'>Sign in</button></p></form>")
    parts.append("</div>")
    return _page("Segurai - sign in", "".join(parts))


def users_page(store: Store, *, csrf: str, message: str = "", error: str = "") -> str:
    from .auth import ROLES

    rows = []
    for u in store.users():
        options = "".join(f"<option value='{r}'{' selected' if r == u['role'] else ''}>{r}</option>" for r in ROLES)
        state = "<span class='chip fail'>disabled</span>" if u["disabled"] else "<span class='chip ok'>active</span>"
        rows.append(
            f"<tr><td>{_e(u['email'])}</td><td>{_e(u['source'])}</td><td>{state}</td><td>"
            f"<form class='inline' method='post' action='/admin/users'>"
            f"<input type='hidden' name='csrf' value='{_e(csrf)}'><input type='hidden' name='action' value='update'>"
            f"<input type='hidden' name='email' value='{_e(u['email'])}'>"
            f"<select name='role'>{options}</select> "
            f"<select name='disabled'><option value='0'{' selected' if not u['disabled'] else ''}>active</option>"
            f"<option value='1'{' selected' if u['disabled'] else ''}>disabled</option></select> "
            f"<button type='submit'>Save</button></form></td>"
            f"<td class='muted small'>{_e(u['updated_at'][:16])} by {_e(u['updated_by'])}</td></tr>")
    role_options = "".join(f"<option value='{r}'>{r}</option>" for r in ROLES)
    body = ("<h1>People</h1><p class='lede'>Who can see this dashboard, and what they can do. Every change "
            "here is written to the tamper-evident log.</p>"
            + (f"<div class='error'>{_e(error)}</div>" if error else "")
            + (f"<p class='ok'>{_e(message)}</p>" if message else "")
            + "<div class='card'><div class='table-wrap'><table><thead><tr><th>Email</th><th>Signs in with</th>"
              "<th>State</th><th>Role</th><th>Last change</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table></div></div>"
            "<div class='card'><h2>Add a person with a password</h2>"
            "<form method='post' action='/admin/users' class='filters'>"
            f"<input type='hidden' name='csrf' value='{_e(csrf)}'><input type='hidden' name='action' value='create'>"
            "<input name='email' type='email' placeholder='email' required maxlength='254'>"
            f"<select name='role'>{role_options}</select>"
            "<input name='password' type='password' placeholder='temporary password (12+ characters)' "
            "required minlength='12' maxlength='200' autocomplete='new-password'>"
            "<button class='primary' type='submit'>Add</button></form>"
            "<p class='muted small'>People who sign in with the company login system are added "
            "automatically, with the role their groups map to.</p></div>")
    return _page("Segurai - people", body, store=store, current="people")


def access_page(store: Store, email: str | None = None) -> str:
    rows = "".join(
        f"<tr><td class='mono'>{_e(r['at'][:19])}</td><td>{_e(r['email'])}</td><td>{_e(r['method'])}</td>"
        f"<td class='mono'>{_e(r['path'])}</td><td>{_e(r['status'])}</td><td class='mono muted'>{_e(r['ip'])}</td></tr>"
        for r in store.access_log(limit=300, email=email))
    body = ("<h1>Access log</h1><p class='lede'>Who opened which page, and every sign-in - successful or "
            "not. These entries are part of the tamper-evident log too.</p>"
            "<form class='filters' method='get' action='/access'>"
            f"<input type='search' name='email' placeholder='Filter by email' value='{_e(email or '')}'>"
            "<button type='submit'>Filter</button></form>"
            "<div class='card'><div class='table-wrap'><table><thead><tr><th>When (UTC)</th><th>Who</th>"
            "<th>Did</th><th>Page</th><th>Result</th><th>From</th></tr></thead><tbody>"
            f"{rows or '<tr><td colspan=6 class=muted>Nothing yet.</td></tr>'}</tbody></table></div></div>")
    return _page("Segurai - access log", body, store=store, current="access")
