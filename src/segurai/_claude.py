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
from typing import Any

__all__ = ["DEFAULT_MODEL", "FALLBACK_BETA", "ModelCallError", "ModelRefusal",
           "anthropic_module", "default_client", "structured_call"]

DEFAULT_MODEL = "claude-opus-5"

#: Beta flag for server-side refusal fallbacks in their "default" form.
FALLBACK_BETA = "server-side-fallback-2026-07-01"


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
