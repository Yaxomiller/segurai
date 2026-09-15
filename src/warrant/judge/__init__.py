"""Tier 2: a semantic judge for the actions Tier 1 flagged (milestone M4).

    judge.py   Judge, Verdict, the Claude backend, and a listener for live judging
    eval.py    measuring the judge against labeled cases

Typical use - review a finished session:

    from warrant.judge import Judge

    for verdict in Judge().review_session(store, session_id):
        print(verdict.verdict, verdict.reasoning)

or from the command line: ``warrant judge <session_id>``.

Needs the optional extra (pip install 'warrant-provenance[judge]') and an
Anthropic API key in ANTHROPIC_API_KEY.
"""

from .judge import (
    CONFIDENCES,
    PROMPT_VERSION,
    VERDICTS,
    ClaudeJudgeBackend,
    Judge,
    JudgeError,
    JudgeListener,
    Verdict,
    build_review,
    needs_review,
    render_review,
)

__all__ = [
    "Judge", "Verdict", "JudgeError", "JudgeListener", "ClaudeJudgeBackend",
    "needs_review", "build_review", "render_review", "VERDICTS", "CONFIDENCES", "PROMPT_VERSION",
]
