"""Human labels for the judge's eval, agreement between labellers, and voting.

The judge's first live score was limited by its answer key, which a model
drafted. These tests cover the two fixes: people label the cases blind and
we measure how far they agree, and the judge can be asked more than once so
a wavering answer goes to a person instead of being reported as certain.
"""

import json
from pathlib import Path

import pytest

from segurai.cli import main as cli_main
from segurai.judge import Judge
from segurai.judge.eval import load_cases
from segurai.judge.labelling import (
    agreement,
    cohen_kappa,
    label_cases,
    load_labels,
    merged,
    present_case,
)

ROOT = Path(__file__).resolve().parents[1]
CASES_FILE = ROOT / "evals" / "tier2" / "cases.jsonl"
CASES = load_cases(CASES_FILE)


def _scripted(*answers):
    """An ``ask`` that replies with these answers in turn."""
    replies = iter(answers)
    return lambda prompt: next(replies)


def _write(path, rows):
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


# ---- showing a case ------------------------------------------------------------

def test_a_case_is_shown_without_its_label():
    for case in CASES:
        text = present_case(case.review)
        assert case.review["request"] in text or repr(case.review["request"]) in text
        assert "expected" not in text.lower()
        assert case.expected not in text                       # no verdict word leaks through
        assert "ACTION" in text and "FLAGGED" in text


# ---- labelling -------------------------------------------------------------------

def test_labelling_saves_each_answer_and_resumes(tmp_path):
    out = tmp_path / "alice.jsonl"
    said = []
    first_three = CASES[:3]
    # case 1: a bad key first, then "w"; case 2: "o" with a note; then stop.
    n = label_cases(first_three, out, "alice", ask=_scripted("x", "w", "", "o", "deal was active", "q"),
                    say=said.append)
    assert n == 2
    assert "Please answer w, o, n or q." in said
    labels = load_labels(out)
    assert [labels[c.id]["verdict"] for c in first_three[:2]] == ["within_intent", "outside_intent"]
    assert labels[first_three[1].id]["note"] == "deal was active"
    assert all(v["labeller"] == "alice" for v in labels.values())

    # resuming asks only about the case not yet answered
    said.clear()
    assert label_cases(first_three, out, "alice", ask=_scripted("n", ""), say=said.append) == 1
    assert said[0].startswith("2 already labelled, 1 to go")
    assert load_labels(out)[first_three[2].id]["verdict"] == "needs_human"


def test_a_corrupt_labels_file_is_refused(tmp_path):
    bad = _write(tmp_path / "bad.jsonl", [{"case_id": "t2-01", "verdict": "probably fine"}])
    with pytest.raises(ValueError, match="probably fine"):
        load_labels(bad)
    assert load_labels(tmp_path / "missing.jsonl") == {}


# ---- agreement -------------------------------------------------------------------

def test_kappa_is_one_for_perfect_agreement_and_zero_for_chance():
    assert cohen_kappa(["a", "b", "a", "b"], ["a", "b", "a", "b"]) == 1.0
    # each labeller says "a" half the time, independently: no better than chance
    assert cohen_kappa(["a", "a", "b", "b"], ["a", "b", "a", "b"]) == pytest.approx(0.0)
    assert cohen_kappa(["a", "a"], ["a", "a"]) == 1.0           # one label used by both: no division by zero
    with pytest.raises(ValueError):
        cohen_kappa([], [])


def test_agreement_lists_the_cases_people_disagree_on():
    first = {"c1": {"verdict": "within_intent"}, "c2": {"verdict": "outside_intent"},
             "c3": {"verdict": "needs_human"}, "only_first": {"verdict": "within_intent"}}
    second = {"c1": {"verdict": "within_intent"}, "c2": {"verdict": "within_intent"},
              "c3": {"verdict": "needs_human"}}
    key = {"c1": "within_intent", "c2": "outside_intent", "c3": "outside_intent", "only_first": "within_intent"}
    result = agreement(first, second, key, names=("alice", "bob"))
    assert (result.shared, result.agreed) == (3, 2)
    assert result.disagreements == [("c2", "outside_intent", "within_intent")]
    assert result.against_key == {"alice": 0.75, "bob": pytest.approx(1 / 3)}
    text = result.to_text()
    assert "Agreed              : 2 (67%)" in text and "c2: outside_intent vs within_intent" in text
    assert [r["case_id"] for r in merged(first, second)] == ["c1", "c3"]


# ---- the commands -----------------------------------------------------------------

def test_label_and_agreement_commands(tmp_path, monkeypatch, capsys):
    ambiguous = [c for c in CASES if c.ambiguous and c.split == "dev"]
    answers = iter(["w", ""] * len(ambiguous))
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    alice = tmp_path / "alice.jsonl"
    assert cli_main(["label", "--as", "alice", "--out", str(alice), "--cases", str(CASES_FILE),
                     "--split", "dev", "--ambiguous-only"]) == 0
    assert set(load_labels(alice)) == {c.id for c in ambiguous}

    bob = _write(tmp_path / "bob.jsonl", [
        {"case_id": c.id, "verdict": "within_intent" if i else "outside_intent", "labeller": "bob"}
        for i, c in enumerate(ambiguous)])
    agreed = tmp_path / "agreed.jsonl"
    capsys.readouterr()
    assert cli_main(["label-agreement", str(alice), str(bob), "--cases", str(CASES_FILE),
                     "--merged", str(agreed)]) == 0
    out = capsys.readouterr().out
    assert f"Cases both labelled : {len(ambiguous)}" in out and "Cohen's kappa" in out
    assert "alice" in out and "agrees with the existing answer key" in out
    assert len(agreed.read_text(encoding="utf-8").splitlines()) == len(ambiguous) - 1

    nobody = _write(tmp_path / "nobody.jsonl", [])
    assert cli_main(["label-agreement", str(alice), str(nobody)]) == 1


# ---- voting -----------------------------------------------------------------------

class Ballots:
    """A backend that gives these answers in turn."""

    last_model = "fake"
    last_latency_ms = 5

    def __init__(self, *answers):
        self.answers = list(answers)

    def complete(self, system, review):
        verdict, confidence = self.answers.pop(0)
        return {"verdict": verdict, "confidence": confidence, "reasoning": f"said {verdict}", "clause": "c"}


def test_votes_that_agree_give_that_verdict():
    review = CASES[0].review
    verdict = Judge(Ballots(("outside_intent", "high"), ("outside_intent", "medium")), votes=2).judge(
        review, "a1", "s1")
    assert (verdict.verdict, verdict.confidence) == ("outside_intent", "medium")
    assert verdict.model == "fake x2" and verdict.latency_ms == 10


def test_votes_that_disagree_go_to_a_person():
    review = CASES[0].review
    verdict = Judge(Ballots(("within_intent", "high"), ("outside_intent", "high")), votes=2).judge(
        review, "a1", "s1")
    assert (verdict.verdict, verdict.confidence) == ("needs_human", "low")
    assert verdict.reasoning.startswith("Independent reviews disagreed (outside_intent (1), within_intent (1))")
    assert "within_intent: said within_intent" in verdict.reasoning


def test_one_vote_is_the_old_behaviour_and_silly_counts_are_refused():
    backend = Ballots(("within_intent", "high"))
    assert Judge(backend).judge(CASES[0].review, "a1", "s1").model == "fake"
    for votes in (0, 6):
        with pytest.raises(ValueError):
            Judge(backend, votes=votes)
