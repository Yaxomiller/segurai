"""Governed templates: ready-made agents for known jobs, with their guardrails already wired.

A company that wants an agent to tidy its CRM, or to issue small refunds,
should not have to design routes, rules, limits and approvals from scratch -
that is where over-broad permissions creep in. A template is the whole
package for one job:

    segurai template list
    segurai template show refunds
    segurai template init refunds --set billing_url=https://billing.internal --set auto_limit_cents=5000

``init`` writes two files:

  * ``refunds.toml`` - the part of segurai.toml the job needs: the gateway
    routes for the system's API, the company rules (refunds above the limit
    wait for a person, none above the maximum), and the ceiling for the
    people who may use it. Append it to segurai.toml.
  * ``refunds_agent.py`` - the agent itself: a Claude agent whose tools are
    exactly those routes, called through the gateway, that tells the person
    plainly when something is waiting for approval or was refused.

The customer sets parameters (addresses, limits, who approves); nothing is
written per customer. The agent is not meant to be the cleverest refund agent
there is - it is meant to be one a security team can approve, because every
action it can take is described, limited and recorded before it runs.

Deliberately few templates, each narrow. A system whose API can't be
described by a template's routes (set its ``*_path`` parameters) is a reason
to write routes by hand, not to stretch the template.
"""

from __future__ import annotations

import json
import pprint
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

__all__ = ["Param", "Tool", "Template", "TEMPLATES", "TemplateError", "TemplateAgent", "get"]


class TemplateError(ValueError):
    """An unknown template or parameter, or a value of the wrong kind."""


@dataclass(frozen=True)
class Param:
    name: str
    description: str
    default: Any
    kind: type = str

    def read(self, value: Any) -> Any:
        if self.kind is int:
            try:
                number = int(value)
            except (TypeError, ValueError) as exc:
                raise TemplateError(f"{self.name} must be a whole number, got {value!r}") from exc
            if number < 0:
                raise TemplateError(f"{self.name} must not be negative")
            return number
        if self.kind is list:
            items = value if isinstance(value, (list, tuple)) else [v for v in str(value).split(",")]
            return [str(v).strip() for v in items if str(v).strip()]
        text = str(value).strip()
        if self.name.endswith("_url"):
            parts = urllib.parse.urlsplit(text)
            if parts.scheme not in ("http", "https") or not parts.hostname:
                raise TemplateError(f"{self.name} must be an http(s) URL")
        if self.name.endswith("_path") and not text.startswith("/"):
            raise TemplateError(f"{self.name} must start with /")
        return text


@dataclass(frozen=True)
class Tool:
    """One thing the agent can do: a Claude tool that is exactly one gateway route."""

    name: str
    description: str
    method: str
    path_param: str                       # the parameter holding the path, e.g. "list_path"
    operation: str
    resource: str
    properties: Mapping[str, Any]
    body: tuple[str, ...] = ()            # inputs sent as the JSON body
    query: tuple[str, ...] = ()           # inputs sent as query parameters
    scale: int | str = 1
    irreversible: bool = False
    evidence: Mapping[str, str] = field(default_factory=dict)

    def schema(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "strict": True,
                "input_schema": {"type": "object", "properties": dict(self.properties),
                                 "required": list(self.properties), "additionalProperties": False}}


@dataclass(frozen=True)
class Template:
    name: str
    title: str
    summary: str
    upstream: str
    prefix: str
    params: tuple[Param, ...]
    tools: tuple[Tool, ...]
    system: str                                        # formatted with the parameters
    rules: Callable[[dict[str, Any]], list[dict[str, Any]]]
    ceiling: Callable[[dict[str, Any]], dict[str, Any]]
    version: int = 1

    def values(self, given: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Every parameter's value: what was given, else the default. Unknown names are refused."""
        given = dict(given or {})
        known = {p.name: p for p in self.params}
        unknown = sorted(set(given) - set(known))
        if unknown:
            raise TemplateError(f"{self.name} has no parameter(s) {unknown}; it takes {sorted(known)}")
        return {name: p.read(given[name] if name in given else p.default) for name, p in known.items()}

    def routes(self, values: Mapping[str, Any]) -> list[dict[str, Any]]:
        out = []
        for tool in self.tools:
            path = values[tool.path_param]
            route = {"method": tool.method, "path": path, "operation": tool.operation, "resource": tool.resource}
            if tool.scale != 1:
                route["scale"] = tool.scale
            if tool.irreversible:
                route["irreversible"] = True
            if tool.evidence:
                route["evidence"] = dict(tool.evidence)
            out.append(route)
        return out

    def render(self, given: Mapping[str, Any] | None = None) -> str:
        """The segurai.toml fragment for this job, with its parameters filled in."""
        values = self.values(given)
        lines = [f"# ---- Segurai template: {self.name} (version {self.version}) ----",
                 f"# {self.title}. Generated with: segurai template init {self.name}"
                 + "".join(f" --set {k}={_arg(v)}" for k, v in sorted(values.items())),
                 "# Append to segurai.toml (which needs [issuer] for the ceiling below).", "",
                 "[[gateway.upstreams]]", f"name = {_toml(self.upstream)}", f"prefix = {_toml(self.prefix)}",
                 f"url = {_toml(values[self.upstream + '_url'])}",
                 "[gateway.upstreams.headers_env]                # or fetch it: [gateway.upstreams.credentials]",
                 f"Authorization = {_toml(values['credential_env'])}"]
        for route in self.routes(values):
            lines += ["[[gateway.upstreams.routes]]"]
            lines += [f"{k} = {_toml(v)}" for k, v in route.items() if k != "evidence"]
            if "evidence" in route:
                lines += ["[gateway.upstreams.routes.evidence]"]
                lines += [f"{k} = {_toml(v)}" for k, v in route["evidence"].items()]
        for rule in self.rules(values):
            lines += ["", "[[policy.rules]]"] + [f"{k} = {_toml(v)}" for k, v in rule.items()]
        lines += ["", "[[issuer.ceilings]]"] + [f"{k} = {_toml(v)}" for k, v in self.ceiling(values).items()]
        return "\n".join(lines) + "\n"

    def agent_script(self, given: Mapping[str, Any] | None = None) -> str:
        """A runnable agent for this job (needs ``pip install 'segurai[stage]'`` for Claude)."""
        values = self.values(given)
        return _AGENT_SCRIPT.format(name=self.name, name_file=self.file_stem, holder=self.file_stem + "_agent",
                                    values=pprint.pformat(values, indent=4, sort_dicts=True))

    @property
    def file_stem(self) -> str:
        return self.name.replace("-", "_")

    def agent(self, gateway_url: str, given: Mapping[str, Any] | None = None, *, brain: Any = None,
              client: Any = None) -> "TemplateAgent":
        return TemplateAgent(self, self.values(given), gateway_url, brain=brain, client=client)


def _toml(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml(v) for v in value) + "]"
    if isinstance(value, Mapping):
        return "{ " + ", ".join(f"{k} = {_toml(v)}" for k, v in value.items()) + " }"
    return json.dumps(str(value))                  # a TOML basic string


def _arg(value: Any) -> str:
    return ",".join(value) if isinstance(value, list) else str(value)


# ---- running the agent --------------------------------------------------------------------------

class TemplateAgent:
    """A template's agent: Claude, with the template's tools, every call through the gateway.

    Run it inside the warrant it acts under (``segurai.resume(chain_token,
    holder=...)``): each call is signed with that warrant's key.
    """

    def __init__(self, template: Template, values: dict[str, Any], gateway_url: str, *, brain: Any = None,
                 client: Any = None):
        from .gateway import GatewayClient

        self.template, self.values = template, values
        self.client = client or GatewayClient(gateway_url)
        self._brain = brain
        self.log: list[dict[str, Any]] = []            # what each tool call did, for the caller

    @property
    def brain(self) -> Any:
        if self._brain is None:
            from .stage.agents import (
                ClaudeBrain,  # needs segurai[stage] (the anthropic SDK)
            )

            self._brain = ClaudeBrain()
        return self._brain

    def run(self, task: str, *, max_turns: int = 10) -> str:
        from .stage.agents import run_agent

        if hasattr(self.brain, "begin_run"):
            self.brain.begin_run()
        system = self.template.system.format(**self.values)
        return run_agent(self.brain, system=system, tools=[t.schema() for t in self.template.tools],
                         task=task, call_tool=self.call, max_turns=max_turns)

    def call(self, name: str, given: dict[str, Any]) -> tuple[str, bool]:
        """One tool call, as one gateway request. Returns (text for Claude, is_error)."""
        from .gateway import APPROVAL_HEADER

        tool = next((t for t in self.template.tools if t.name == name), None)
        if tool is None:
            return f"There is no tool called {name}.", True
        path = self.values[tool.path_param].format(**{k: urllib.parse.quote(str(v), safe="")
                                                      for k, v in given.items()})
        query = {k: given[k] for k in tool.query if k in given}
        target = self.template.prefix + path + (("?" + urllib.parse.urlencode(query)) if query else "")
        body = {k: given[k] for k in tool.body if k in given} if tool.body else None
        status, headers, payload = self.client.request(tool.method, target, body)
        text = payload.decode("utf-8", "replace")
        entry = {"tool": name, "status": status, "target": target}
        self.log.append(entry)
        held = {k.lower(): v for k, v in headers.items()}.get(APPROVAL_HEADER.lower())
        if status == 202 and held:
            entry["approval_id"] = held
            reasons = "; ".join(json.loads(text or "{}").get("why") or [])
            return (f"Held for a person's approval ({held}): {reasons}. Nothing has been done yet. Tell the "
                    f"person it is waiting for approval; do not try another way."), False
        if status == 403:
            error = (json.loads(text or "{}") or {}).get("error", text)
            entry["refused"] = error
            return f"Refused by Segurai: {error}. Do not try to get around this; tell the person.", True
        if not 200 <= status < 300:
            return f"The system answered {status}: {text[:500]}", True
        return text[:6000], False


_AGENT_SCRIPT = '''"""The {name} agent, from a Segurai template. Every action goes through the gateway.

    pip install 'segurai[stage]'          # the Claude SDK
    set ANTHROPIC_API_KEY, SEGURAI_GATEWAY (the gateway's address) and
    SEGURAI_CHAIN_TOKEN (from POST /v1/sessions for the person asking), then:
    python {name_file}_agent.py "what the person asked for"
"""

import os
import sys

import segurai
from segurai.templates import get

#: The template's parameters, as given to segurai template init.
VALUES = {values}


def main() -> int:
    task = " ".join(sys.argv[1:]) or "Do the job you are for, and report what you did."
    with segurai.resume(os.environ["SEGURAI_CHAIN_TOKEN"], holder="{holder}"):
        agent = get("{name}").agent(os.environ["SEGURAI_GATEWAY"], VALUES)
        print(agent.run(task))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# ---- the templates ------------------------------------------------------------------------------

_IDS = {"type": "array", "items": {"type": "string"}, "description": "The deal ids."}
_DAYS = {"type": "array", "items": {"type": "integer"},
         "description": "For each id, in the same order, how many days since the deal last had activity "
                        "(from find_stale_deals)."}
_REASON = {"type": "string", "description": "One sentence for the audit log: why."}


def _crm_rules(v: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": f"never archive or delete deals active in the last {v['stale_days']} days",
         "effect": "deny", "operations": ["archive", "delete"], "targets": ["crm.deals"],
         "when_below": {"days_since_activity": v["stale_days"]},
         "reason": "Recently active deals belong to live customers."},
        {"name": "deleting deals needs a second person", "effect": "approve", "operations": ["delete"],
         "targets": ["crm.deals"], "only_irreversible": True,
         **({"approvers": v["approvers"]} if v["approvers"] else {}),
         "reason": "A deleted deal can't be brought back."},
    ]


def _crm_ceiling(v: dict[str, Any]) -> dict[str, Any]:
    return {"name": "crm-hygiene", "groups": [v["group"]], "operations": ["search", "archive", "delete"],
            "targets": ["crm.deals"], "max_scale": v["archive_limit"], "max_total": v["total_limit"],
            "irreversible_allowed": True}


CRM_HYGIENE = Template(
    name="crm-hygiene", title="CRM hygiene: archive deals that went quiet",
    summary="Finds deals with no activity for a while and archives them in small batches. Never touches a "
            "recently active deal; deleting needs a second person.",
    upstream="crm", prefix="/crm",
    params=(
        Param("crm_url", "the CRM API's base address", "https://crm.internal.example/api"),
        Param("credential_env", "the environment variable holding the CRM credential", "CRM_AUTHORIZATION"),
        Param("stale_days", "a deal is stale after this many days without activity", 180, int),
        Param("archive_limit", "most deals changed in one action", 50, int),
        Param("total_limit", "most deals changed in one request", 500, int),
        Param("approvers", "who may approve deletions (emails or patterns); empty = any admin", "", list),
        Param("group", "the login-system group allowed to use it", "sales-ops"),
        Param("list_path", "the CRM's path for listing deals", "/deals"),
        Param("archive_path", "the CRM's path for archiving deals", "/deals/archive"),
        Param("delete_path", "the CRM's path for deleting deals", "/deals/delete"),
    ),
    tools=(
        Tool("find_stale_deals", "List deals with no activity for at least inactive_days days, with their ids "
             "and days since activity.", "GET", "list_path", "search", "crm.deals",
             {"inactive_days": {"type": "integer", "description": "Days without activity."}},
             query=("inactive_days",)),
        Tool("archive_deals", "Archive deals (they can be restored). Give each deal's days since activity.",
             "POST", "archive_path", "archive", "crm.deals",
             {"ids": _IDS, "days_since_activity": _DAYS, "reason": _REASON},
             body=("ids", "days_since_activity", "reason"), scale="json:ids|len",
             evidence={"days_since_activity": "json:days_since_activity"}),
        Tool("delete_deals", "Permanently delete deals. Needs a person's approval; prefer archiving.",
             "POST", "delete_path", "delete", "crm.deals",
             {"ids": _IDS, "days_since_activity": _DAYS, "reason": _REASON},
             body=("ids", "days_since_activity", "reason"), scale="json:ids|len", irreversible=True,
             evidence={"days_since_activity": "json:days_since_activity"}),
    ),
    system=("You keep the CRM tidy. A deal is stale after {stale_days} days without activity. Find stale "
            "deals, then archive them in batches of at most {archive_limit}, giving each deal's days since "
            "activity. Never archive a deal active more recently. Prefer archiving to deleting: deleting is "
            "permanent and waits for a second person's approval. If Segurai holds or refuses something, say "
            "so plainly and stop; never look for another way. End with a short report of what you did."),
    rules=_crm_rules, ceiling=_crm_ceiling,
)


def _refund_rules(v: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"name": f"refunds over {_money(v['auto_limit_cents'])} need a person", "effect": "approve",
         "operations": ["refund"], "targets": ["billing.refunds"],
         "when_above": {"amount_cents": v["auto_limit_cents"]},
         **({"approvers": v["approvers"]} if v["approvers"] else {}),
         "reason": "Larger refunds are a decision for a person."},
        {"name": f"no refund over {_money(v['max_refund_cents'])}", "effect": "deny", "operations": ["refund"],
         "targets": ["billing.refunds"], "when_above": {"amount_cents": v["max_refund_cents"]},
         "reason": "Refunds this large go through finance, not an agent."},
    ]


def _refund_ceiling(v: dict[str, Any]) -> dict[str, Any]:
    return {"name": "refunds", "groups": [v["group"]], "operations": ["read", "refund"],
            "targets": ["billing.orders", "billing.refunds"], "max_scale": 1, "max_total": v["refunds_per_request"]}


def _money(cents: int) -> str:
    return f"${cents / 100:,.2f}".replace(".00", "")


REFUNDS = Template(
    name="refunds", title="Refunds: small refunds at once, larger ones after a person agrees",
    summary="Looks up an order and refunds it. Refunds up to the limit go straight through; above it they wait "
            "for a person; above the maximum they are refused.",
    upstream="billing", prefix="/billing",
    params=(
        Param("billing_url", "the billing API's base address", "https://billing.internal.example/api"),
        Param("credential_env", "the environment variable holding the billing credential", "BILLING_AUTHORIZATION"),
        Param("auto_limit_cents", "refunds up to this many cents need no approval", 5000, int),
        Param("max_refund_cents", "no refund above this many cents, approved or not", 50000, int),
        Param("refunds_per_request", "most refunds in one request", 20, int),
        Param("approvers", "who may approve larger refunds (emails or patterns); empty = any admin", "", list),
        Param("group", "the login-system group allowed to use it", "support"),
        Param("order_path", "the billing API's path for one order", "/orders/{order_id}"),
        Param("refund_path", "the billing API's path for issuing a refund", "/refunds"),
    ),
    tools=(
        Tool("look_up_order", "Look up one order: its customer, amount paid and refunds so far.", "GET",
             "order_path", "read", "billing.orders", {"order_id": {"type": "string", "description": "The order id."}}),
        Tool("issue_refund", "Refund part or all of an order, in cents.", "POST", "refund_path", "refund",
             "billing.refunds",
             {"order_id": {"type": "string", "description": "The order id."},
              "amount_cents": {"type": "integer", "description": "How much to refund, in cents."},
              "reason": _REASON},
             body=("order_id", "amount_cents", "reason"), evidence={"amount_cents": "json:amount_cents|int"}),
    ),
    system=("You handle refunds. Look the order up first, and never refund more than was paid. Refunds up to "
            "{auto_limit_cents} cents go straight through; larger ones wait for a person's approval, and none "
            "above {max_refund_cents} cents is allowed. If Segurai holds or refuses something, say so plainly "
            "and stop; never split a refund to get under a limit. End with a short report."),
    rules=_refund_rules, ceiling=_refund_ceiling,
)

TEMPLATES: dict[str, Template] = {t.name: t for t in (CRM_HYGIENE, REFUNDS)}


def get(name: str) -> Template:
    try:
        return TEMPLATES[name]
    except KeyError:
        raise TemplateError(f"there is no template {name!r}; there are {sorted(TEMPLATES)}") from None
