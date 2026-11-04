"""The Tier 2 eval: the labeled dataset, and the scoring rules."""

from collections import Counter
from pathlib import Path

from segurai._claude import ModelCallError
from segurai.judge import VERDICTS, Judge, render_review
from segurai.judge.eval import load_cases, run_eval

ROOT = Path(__file__).resolve().parents[1]
CASES = load_cases(ROOT / "evals" / "tier2" / "cases.jsonl")


class LabelJudge:
    """Answers each case with its own label: a perfect judge."""

    last_model = "labels"
    last_latency_ms = 900

    def __init__(self):
        self.answers = {render_review(c.review): c.expected for c in CASES}

    def complete(self, system, review):
        return {"verdict": self.answers[review], "confidence": "high", "reasoning": "label", "clause": ""}


class Always:
    last_model = "always"
    last_latency_ms = 10

    def __init__(self, verdict):
        self.verdict = verdict

    def complete(self, system, review):
        return {"verdict": self.verdict, "confidence": "low", "reasoning": "fixed answer", "clause": ""}


class Down:
    def complete(self, system, review):
        raise ModelCallError("could not reach the Anthropic API")


# ---- the dataset ----------------------------------------------------------

def test_dataset_has_50_cases_with_enough_ambiguity():
    assert len(CASES) == 50 and len({c.id for c in CASES}) == 50
    assert sum(c.ambiguous for c in CASES) >= 25
    assert set(Counter(c.expected for c in CASES)) == set(VERDICTS)


def test_every_case_is_a_flagged_action_by_a_named_agent():
    for case in CASES:
        review = case.review
        assert review["findings"], case.id
        assert all(f["status"] in ("fail", "unverifiable") for f in review["findings"]), case.id
        assert review["chain"][-1]["holder"] == review["action"]["actor"], case.id


def test_prompt_injection_cases_are_included():
    injected = [c for c in CASES if "approved" in str(c.review["action"]["reported"]).lower()]
    assert len(injected) >= 3
    assert all(c.expected == "outside_intent" for c in injected)


# ---- scoring -------------------------------------------------------------

def test_a_perfect_judge_meets_the_target():
    report = run_eval(Judge(LabelJudge()), CASES)
    assert report.agreement == 1.0 and report.ambiguous_agreement == 1.0
    assert report.dangerous_misses == 0 and report.meets_target
    assert "Milestone M4: MET" in report.to_markdown()
    assert report.latency_ms()["p95"] == 900


def test_approving_everything_is_caught_as_dangerous():
    report = run_eval(Judge(Always("within_intent")), CASES)
    outside = sum(c.expected == "outside_intent" for c in CASES)
    assert report.dangerous_misses == outside
    assert not report.meets_target
    assert "**DANGEROUS**" in report.to_markdown()


def test_deferring_everything_is_safe_but_misses_the_target():
    report = run_eval(Judge(Always("needs_human")), CASES)
    assert report.dangerous_misses == 0
    assert report.deferrals == sum(c.expected != "needs_human" for c in CASES)
    assert not report.meets_target


def test_failed_calls_count_as_disagreement():
    report = run_eval(Judge(Down()), CASES[:3])
    assert report.errors == 3 and report.agreement == 0
    assert report.confusion()[CASES[0].expected]["error"] >= 1


# ---- the repaired dataset (after the first live run) ----------------------

def test_the_set_is_split_so_tuning_and_reporting_use_different_cases():
    splits = Counter(c.split for c in CASES)
    assert splits == {"dev": 20, "test": 30}
    # Every case that informed the v2 prompt is in dev and can't inflate test.
    informed = {"t2-03", "t2-04", "t2-05", "t2-07", "t2-09", "t2-21", "t2-25", "t2-28", "t2-29",
                "t2-31", "t2-33", "t2-39", "t2-40", "t2-41", "t2-43", "t2-46", "t2-49", "t2-50"}
    assert informed <= {c.id for c in CASES if c.split == "dev"}


def test_every_case_tells_the_judge_where_its_limits_came_from():
    for case in CASES:
        source = case.review["limits"]["source"]
        assert "estimated by the intent compiler" in source or "as granted" in source, case.id


def test_relabelled_cases_say_why_they_changed():
    changed = [c for c in CASES if "Label changed after the first live run" in c.notes]
    assert len(changed) == 7
    assert {c.id for c in changed} == {"t2-03", "t2-25", "t2-28", "t2-31", "t2-39", "t2-43", "t2-49"}
    for case in changed:
        assert len(case.notes) > 80, case.id          # a real reason, not a shrug


def test_scoring_still_separates_dev_from_test():
    dev = [c for c in CASES if c.split == "dev"]
    report = run_eval(Judge(LabelJudge()), dev)
    assert report.meets_target
    assert {r.split for r in report.results} == {"dev"}
    assert "dev 20" in report.to_markdown()
