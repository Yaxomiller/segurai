"""One structured call to Claude, shared by the intent compiler and the judge.

Both of them ask Claude a single question and need the answer in a fixed
shape. This module makes that call once, carefully, so the two can't drift
apart:

  * structured output - the reply must match a Pydantic model's JSON schema
  * the fixed instructions are marked for prompt caching
  * server-side refusal fallbacks are on by default
  * why generation stopped is read BEFORE the reply is parsed, so a refusal
    or a cut-off answer gets a clear error instead of a confusing parse error
  * API errors become plain-language ModelCallErrors, most specific first

Nothing here is Segurai-specific; callers turn ModelCallError into their own
error types (IntentError, JudgeError).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Mapping

__all__ = ["DEFAULT_MODEL", "FALLBACK_BETA", "PRICES", "ModelCallError", "ModelRefusal",
           "UsageTotals", "anthropic_module", "default_client", "structured_call"]

DEFAULT_MODEL = "claude-opus-5"

#: Beta flag for server-side refusal fallbacks in their "default" form.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


#: List prices in dollars per million tokens, as (input, output). Only the
#: models this library defaults to are listed; anything else reports tokens
#: without a dollar figure rather than guessing.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00),
    "claude-opus-5": (5.00, 25.00),
    "claude-sonnet-5-5": (2.00, 10.00),
    "claude-haiku-5-5": (0.10, 0.50),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
}

#: A cached prefix is read at a tenth of the input price and written at 1.25x.
CACHE_READ_MULTIPLIER = 0.10
CACHE_WRITE_MULTIPLIER = 1.25


@dataclass
class UsageTotals:
    """What a run of calls actually used, straight from the API's own counts.

    Reported so nobody has to trust an estimate: the API returns exact token
    counts per call, and the only guess left is the price table above.
    """

    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_tokens: int = 0
    cache_write_tokens: int = 0
    models: set[str] = field(default_factory=set)

    def add(self, usage: Mapping[str, Any] | None, model: str | None = None) -> None:
        if not usage:
            return
        self.calls += 1
        self.input_tokens += int(usage.get("input_tokens") or 0)
        self.output_tokens += int(usage.get("output_tokens") or 0)
        self.cache_read_tokens += int(usage.get("cache_read_input_tokens") or 0)
        self.cache_write_tokens += int(usage.get("cache_creation_input_tokens") or 0)
        if model:
            self.models.add(model)

    @property
    def estimated_cost(self) -> float | None:
        """Dollars, or None when a model in the run has no published price here."""
        if not self.models or any(m not in PRICES for m in self.models):
            return None
        # One model per run in practice; with several, charge each at its own
        # rate would need per-call detail, so the most expensive one is used.
        price_in, price_out = max(PRICES[m] for m in self.models)
        dollars = (
            self.input_tokens * price_in
            + self.cache_read_tokens * price_in * CACHE_READ_MULTIPLIER
            + self.cache_write_tokens * price_in * CACHE_WRITE_MULTIPLIER
            + self.output_tokens * price_out
        )
        return dollars / 1_000_000

    def to_dict(self) -> dict[str, Any]:
        return {
            "calls": self.calls, "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens, "cache_read_tokens": self.cache_read_tokens,
            "cache_write_tokens": self.cache_write_tokens, "models": sorted(self.models),
            "estimated_cost_usd": self.estimated_cost,
        }

    def to_text(self) -> str:
        cost = self.estimated_cost
        money = f"${cost:.2f}" if cost is not None else "cost unknown for this model"
        # The API counts cached tokens SEPARATELY from input_tokens, so they
        # are an addition to that number, not a part of it.
        cached = f" plus {self.cache_read_tokens:,} read from cache" if self.cache_read_tokens else ""
        written = (f" and {self.cache_write_tokens:,} written to cache"
                   if self.cache_write_tokens else "")
        return (f"{self.calls} API call(s): {self.input_tokens:,} fresh input tokens{cached}"
                f"{written}, {self.output_tokens:,} output. Estimated {money} at list prices - "
                f"your console has the authoritative figure.")


class ModelCallError(RuntimeError):
    """The call to Claude did not produce a usable answer."""


class ModelRefusal(ModelCallError):
    """Claude declined to answer (a safety refusal)."""

    def __init__(self, category: str | None):
        self.category = category
        super().__init__(f"the model declined (category: {category or 'unspecified'})")


def anthropic_module(extra: str) -> Any:
    """Import the Anthropic SDK, or explain which optional extra installs it."""
    try:
        import anthropic
    except ImportError as exc:
        raise ModelCallError(f"this needs the Anthropic SDK: pip install 'segurai[{extra}]'") from exc
    return anthropic


def default_client(extra: str) -> Any:
    """A client configured from the environment (ANTHROPIC_API_KEY or a login profile)."""
    anthropic = anthropic_module(extra)
    try:
        return anthropic.Anthropic()
    except anthropic.AnthropicError as exc:
        raise ModelCallError(f"could not create an Anthropic client ({exc}); set ANTHROPIC_API_KEY") from exc


def structured_call(client: Any, *, model: str, system: str, user: str, output_model: Any,
                    effort: str | None = None, fallbacks: bool = True, max_tokens: int = 16000,
                    extra: str = "intent") -> tuple[dict[str, Any], dict[str, Any]]:
    """Ask one question; return (the parsed answer as a dict, facts about the call).

    The facts are ``model`` (which model actually answered - a fallback may
    have), ``usage`` (token counts, including prompt-cache hits) and
    ``latency_ms``.
    """
    anthropic = anthropic_module(extra)
    params: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        # cache_control marks the fixed instructions as reusable: the API
        # stores that prefix and later calls read it at a fraction of the
        # normal input price.
        "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": user}],
        "output_format": output_model,
    }
    if effort is not None:
        params["output_config"] = {"effort": effort}
    if fallbacks:
        params["betas"] = [FALLBACK_BETA]
        params["fallbacks"] = "default"

    started = time.perf_counter()
    # Most specific errors first: a bad key or a bad request will not fix
    # itself, while rate limits and outages might (the SDK already retried
    # those twice before raising).
    try:
        # with_raw_response hands back the HTTP reply BEFORE it is parsed, so
        # the reason generation stopped can be checked first.
        raw = client.beta.messages.with_raw_response.parse(**params)
    except anthropic.AuthenticationError as exc:
        raise ModelCallError("the Anthropic API rejected the credentials; check ANTHROPIC_API_KEY") from exc
    except anthropic.BadRequestError as exc:
        raise ModelCallError(f"the Anthropic API rejected the request: {exc.message}") from exc
    except anthropic.RateLimitError as exc:
        raise ModelCallError("rate limited by the Anthropic API; try again shortly") from exc
    except anthropic.APIStatusError as exc:
        raise ModelCallError(f"Anthropic API error {exc.status_code}: {exc.message}") from exc
    except anthropic.APIConnectionError as exc:
        raise ModelCallError("could not reach the Anthropic API") from exc
    except TypeError as exc:
        # When it finds no credentials at all (no key, token or login
        # profile) the SDK raises a TypeError rather than an API error.
        # Any other TypeError is a real bug and must not be disguised.
        if "authentication" not in str(exc).lower():
            raise
        raise ModelCallError("no Anthropic credentials found; set ANTHROPIC_API_KEY") from exc
    latency_ms = int((time.perf_counter() - started) * 1000)

    body = raw.http_response.json()
    facts = {"model": body.get("model"), "usage": body.get("usage"), "latency_ms": latency_ms}

    # Check why generation stopped BEFORE reading the content: a refusal
    # carries no answer, and a cut-off reply carries half of one.
    stop_reason = body.get("stop_reason")
    if stop_reason == "refusal":
        details = body.get("stop_details") or {}
        raise ModelRefusal(details.get("category"))
    if stop_reason == "max_tokens":
        raise ModelCallError("the model's answer was cut off; raise max_tokens")

    try:
        response = raw.parse()
    except ValueError as exc:  # a reply that does not validate against the schema
        raise ModelCallError(f"the model's reply did not match the expected shape: {exc}") from exc
    parsed = getattr(response, "parsed_output", None)
    if parsed is None:
        raise ModelCallError("the model returned no structured answer")
    return parsed.model_dump(), facts
