"""The intent eval: the grading rules, and the labeled dataset itself."""

import csv
from collections import Counter
from dataclasses import replace
from pathlib import Path

from segurai.intent import Catalog, IntentCompiler, IntentError, ScopeContract
from segurai.intent.eval import grade, load_cases, run_eval

ROOT = Path(__file__).resolve().parents[1]
CATALOG = Catalog.load(ROOT / "evals" / "intent" / "catalog.json")
CASES = load_cases(ROOT / "evals" / "intent" / "cases.jsonl")
BY_ID = {c.id: c for c in CASES}


def _perfect(case) -> ScopeContract:
    """A contract that satisfies its label exactly: the first choice from every group."""
    return ScopeContract(
        goal=case.request,
        expected_operations=tuple(g[0] for g in case.operations_required),
        expected_targets=tuple(g[0] for g in case.targets_required),
        typical_max=None if case.scale is None else case.scale[0],
        implied_constraints=tuple(g[0] for g in case.constraints),
        irreversible_expected=bool(case.irreversible),
    )


# ---- the dataset ---------------------------------------------------------

def test_dataset_has_50_unique_cases_split_into_dev_and_test():
    assert len(CASES) == 50
    assert len(BY_ID) == 50
    splits = Counter(c.split for c in CASES)
    assert set(splits) == {"dev", "test"} and splits["test"] >= 30


def test_every_label_uses_only_catalog_names():
    ops, resources = set(CATALOG.operation_names), set(CATALOG.resource_names)
    for c in CASES:
        assert c.operations_allowed <= ops, c.id
        assert c.targets_allowed <= resources, c.id


def test_a_contract_matching_each_label_is_acceptable():
    for case in CASES:
        result = grade(case, _perfect(case), CATALOG)
        assert result.acceptable, (case.id, result.failures)


# ---- grading rules -------------------------------------------------------

def test_an_operation_the_request_did_not_ask_for_fails():
    case = BY_ID["dev-11"]  # "Draft a reply ... but don't send it"
    contract = _perfect(case)
    result = grade(case, replace(contract, expected_operations=contract.expected_operations + ("send",)),
                   CATALOG)
    assert not result.operations_ok and not result.acceptable
    assert any("send" in f for f in result.failures)


def test_a_missing_required_target_fails():
    case = BY_ID["dev-02"]  # needs both email and invoices
    result = grade(case, replace(_perfect(case), expected_targets=("email.messages",)), CATALOG)
    assert not result.targets_ok


def test_a_wildcard_is_graded_by_what_it_reaches():
    case = BY_ID["test-22"]  # "Delete everything in the CRM"
    assert grade(case, replace(_perfect(case), expected_targets=("crm.*",)), CATALOG).targets_ok
    assert not grade(case, replace(_perfect(case), expected_targets=("*",)), CATALOG).targets_ok


def test_scale_outside_the_range_fails():
    case = BY_ID["dev-13"]  # three new hires: 3..10
    assert not grade(case, replace(_perfect(case), typical_max=400), CATALOG).scale_ok


def test_wrong_irreversibility_fails():
    case = BY_ID["dev-09"]  # explicit deletion
    assert not grade(case, replace(_perfect(case), irreversible_expected=False), CATALOG).irreversible_ok


def test_the_injection_case_passes_only_when_the_contract_grants_nothing():
    case = BY_ID["test-25"]
    assert grade(case, _perfect(case), CATALOG).acceptable
    greedy = replace(_perfect(case), expected_operations=("delete",), expected_targets=("crm.*",))
    assert not grade(case, greedy, CATALOG).acceptable


# ---- running -------------------------------------------------------------

class LabelBackend:
    """Answers every case with its perfect contract."""

    last_model = "label-backend"

    def complete(self, system, request, catalog):
        case = next(c for c in CASES if c.request == request)
        return _perfect(case).to_dict()


class DownBackend:
    def complete(self, system, request, catalog):
        raise IntentError("service unavailable")


def test_a_perfect_run_meets_the_milestone_and_writes_reports(tmp_path):
    report = run_eval(IntentCompiler(CATALOG, LabelBackend()), CASES)
    assert report.acceptable_rate == 1.0
    assert report.to_dict()["meets_milestone"] is True
    assert "| Operations | 100.0% |" in report.to_markdown()

    sheet = tmp_path / "review.csv"
    report.write_review_sheet(sheet)
    with open(sheet, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 50 and "human_verdict" in rows[0]


def test_compile_errors_count_as_not_acceptable():
    report = run_eval(IntentCompiler(CATALOG, DownBackend()), CASES[:3])
    assert report.acceptable_rate == 0
    assert all(r.error == "service unavailable" for r in report.results)
