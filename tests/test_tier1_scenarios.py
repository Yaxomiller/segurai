"""Milestone M2: the Tier 1 scenario suite must meet its target on every change."""

from pathlib import Path

import pytest

from segurai.scenarios import load_scenarios, run_scenarios

SCENARIOS = load_scenarios(Path(__file__).resolve().parents[1] / "evals" / "tier1" / "scenarios.json")


@pytest.fixture(scope="module")
def report():
    return run_scenarios(SCENARIOS)


def test_the_suite_has_ten_violating_and_ten_benign_scenarios():
    kinds = [s.kind for s in SCENARIOS]
    assert kinds.count("violating") == 10 and kinds.count("benign") == 10


def test_milestone_target_is_met(report):
    assert report.meets_target, report.to_markdown()


def test_every_scenario_is_judged_correctly(report):
    """Stricter than the milestone: the check is deterministic, so no misses are acceptable."""
    wrong = [f"{r.id}: {r.note}" for r in report.results if not r.correct]
    assert not wrong, wrong


def test_missing_evidence_is_reported_as_unverifiable_not_as_a_violation(report):
    result = next(r for r in report.results if r.id == "b10-missing-evidence")
    assert result.correct and result.unverifiable > 0


def test_a_checked_action_is_well_under_five_milliseconds(report):
    assert report.act_p99_us < 5000
    assert report.check_p99_us < 1000


def test_the_runner_leaves_the_runtime_as_it_found_it():
    import segurai

    store_before = segurai._runtime.store
    run_scenarios(SCENARIOS[:1])
    assert segurai._runtime.store is store_before
