"""Human labels for the judge's eval set, and how far two people agree.

The first live runs showed the eval's weakest part was its answer key: the
labels were drafted by the same kind of model being graded. Two people
labelling independently fix that, and how often they agree with EACH OTHER
says how much any score can mean.

    segurai label --as alice --out labels-alice.jsonl      (one person)
    segurai label --as bob   --out labels-bob.jsonl        (another, separately)
    segurai label-agreement labels-alice.jsonl labels-bob.jsonl --merged agreed.jsonl

Labelling shows each case the way the judge sees it - the request, what was
granted, what the agent did, what Tier 1 flagged, the evidence it reported -
and never the existing label. Answers are saved as you go, so a session can
stop and resume. Agreement is reported as raw agreement and Cohen's kappa
(agreement beyond what chance alone would produce: 1 is perfect, 0 is no
better than chance; above about 0.6 is usually called substantial). Cases
the two people disagree on are listed: they are genuinely ambiguous, and
should be dropped from the score or counted as "needs a person".
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping

from .judge import VERDICTS

__all__ = ["present_case", "label_cases", "load_labels", "agreement", "Agreement", "cohen_kappa", "merged"]

_KEYS = {"w": "within_intent", "o": "outside_intent", "n": "needs_human"}


def present_case(review: Mapping[str, Any]) -> str:
    """One case as plain text, as the judge would see it - without any label."""
    action = review.get("action", {})
    lines = [f"REQUEST   {review.get('request')!r}  (asked by {review.get('principal')})"]
    chain = review.get("chain") or []
    lines.append("AGENTS    " + " -> ".join(h.get("holder", "?") for h in chain))
    acting = next((h.get("scope") for h in reversed(chain) if h.get("scope")), None)
    if acting:
        lines.append(f"GRANTED   operations {acting.get('operations')} on {acting.get('targets')}, "
                     f"up to {acting.get('max_scale')} per action")
        for c in acting.get("constraints") or []:
            lines.append(f"          condition: {c}")
    limits = review.get("limits") or {}
    if limits.get("source"):
        lines.append(f"LIMITS    {limits.get('source')}")
    lines.append(f"ACTION    {action.get('actor')} {action.get('operation')} {action.get('resource')} "
                 f"x{action.get('scale')}{' (irreversible)' if action.get('irreversible') else ''}")
    if action.get("reported"):
        lines.append(f"REPORTED  {json.dumps(action.get('reported'), sort_keys=True)}")
    for f in review.get("findings") or []:
        lines.append(f"FLAGGED   [{f.get('status')}] {f.get('reason')}")
    for earlier in review.get("earlier_actions") or []:
        lines.append(f"BEFORE    {earlier.get('actor')} {earlier.get('operation')} {earlier.get('resource')} "
                     f"x{earlier.get('scale')}")
    return "\n".join(lines)


def load_labels(path: str | Path) -> dict[str, dict[str, Any]]:
    """case id -> {"verdict", "note", "labeller"} from a labels file (missing file: empty)."""
    labels: dict[str, dict[str, Any]] = {}
    p = Path(path)
    if not p.exists():
        return labels
    for line in p.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            if entry.get("verdict") not in VERDICTS:
                raise ValueError(f"{path}: case {entry.get('case_id')} has verdict {entry.get('verdict')!r}")
            labels[entry["case_id"]] = entry
    return labels


def label_cases(cases: Iterable[Any], out: str | Path, labeller: str,
                ask: Callable[[str], str] | None = None, say: Callable[[str], None] | None = None) -> int:
    """Ask a person about every case not yet in ``out``. Returns how many were labelled now.

    ``ask`` and ``say`` default to the terminal (input and print).
    """
    ask = ask or input
    say = say or print
    out = Path(out)
    done = load_labels(out)
    todo = [c for c in cases if c.id not in done]
    say(f"{len(done)} already labelled, {len(todo)} to go. For each case answer "
        f"w (within what was asked), o (outside it), n (a person must decide), or q to stop.")
    labelled = 0
    for number, case in enumerate(todo, 1):
        say("")
        say(f"--- case {case.id} ({number} of {len(todo)}) ---")
        say(present_case(case.review))
        while True:
            answer = ask("verdict [w/o/n/q]: ").strip().lower()
            if answer in ("q", "quit"):
                say(f"Saved {labelled} label(s) to {out}.")
                return labelled
            if answer in _KEYS:
                break
            say("Please answer w, o, n or q.")
        note = ask("note (optional): ").strip()
        with out.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"case_id": case.id, "verdict": _KEYS[answer], "note": note,
                                 "labeller": labeller}) + "\n")
        labelled += 1
    say(f"All done: {labelled} label(s) saved to {out}.")
    return labelled


def cohen_kappa(a: list[str], b: list[str]) -> float:
    """Agreement beyond chance between two labellers over the same items."""
    if not a or len(a) != len(b):
        raise ValueError("kappa needs two equal, non-empty lists of labels")
    observed = sum(x == y for x, y in zip(a, b, strict=True)) / len(a)
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(a) | set(b)) / (len(a) ** 2)
    return 1.0 if expected == 1 else (observed - expected) / (1 - expected)


@dataclass
class Agreement:
    shared: int
    agreed: int
    kappa: float
    disagreements: list[tuple[str, str, str]] = field(default_factory=list)   # (case, a, b)
    against_key: dict[str, float] = field(default_factory=dict)              # labeller -> agreement with expected

    def to_text(self) -> str:
        lines = [f"Cases both labelled : {self.shared}",
                 f"Agreed              : {self.agreed} ({self.agreed / self.shared:.0%})" if self.shared else
                 "Agreed              : -",
                 f"Cohen's kappa       : {self.kappa:.2f}  (1 = perfect, 0 = chance; > 0.6 substantial)"]
        for who, rate in self.against_key.items():
            lines.append(f"{who:<20}: agrees with the existing answer key on {rate:.0%}")
        if self.disagreements:
            lines.append("")
            lines.append("Genuinely ambiguous - the two people disagree (drop these from the score, or count")
            lines.append("them as 'a person must decide'):")
            lines += [f"  {case}: {a} vs {b}" for case, a, b in self.disagreements]
        return "\n".join(lines)


def agreement(first: Mapping[str, Mapping[str, Any]], second: Mapping[str, Mapping[str, Any]],
              expected: Mapping[str, str] | None = None, names: tuple[str, str] = ("first", "second")) -> Agreement:
    shared = sorted(set(first) & set(second))
    a = [first[c]["verdict"] for c in shared]
    b = [second[c]["verdict"] for c in shared]
    result = Agreement(shared=len(shared), agreed=sum(x == y for x, y in zip(a, b, strict=True)),
                       kappa=cohen_kappa(a, b) if shared else 0.0,
                       disagreements=[(c, x, y) for c, x, y in zip(shared, a, b, strict=True) if x != y])
    if expected:
        for name, labels in zip(names, (first, second), strict=True):
            scored = [c for c in labels if c in expected]
            if scored:
                result.against_key[name] = sum(labels[c]["verdict"] == expected[c] for c in scored) / len(scored)
    return result


def merged(first: Mapping[str, Mapping[str, Any]], second: Mapping[str, Mapping[str, Any]]) -> list[dict[str, Any]]:
    """Labels both people agree on - the trustworthy answer key."""
    return [{"case_id": c, "verdict": first[c]["verdict"],
             "labellers": [first[c].get("labeller"), second[c].get("labeller")]}
            for c in sorted(set(first) & set(second)) if first[c]["verdict"] == second[c]["verdict"]]
