from __future__ import annotations

import inspect

import pytest

from backend.sable.research_eval import (
    CASES,
    _confusion_metrics,
    _metric_status,
    independent_moved_only,
    run_experiment,
    validate_dataset,
)


def test_oracle_contract_has_rationales_and_unreviewed_provenance():
    validate_dataset()
    assert len(CASES) >= 6
    assert {case["review_status"] for case in CASES} == {"UNREVIEWED"}
    assert all(case["reviewer"] is None and case["reviewed_at"] is None for case in CASES)
    assert {case["expected_outcome"] for case in CASES} == {"PRESERVED", "REGRESSED", "UNKNOWN"}


def test_dataset_rejects_unknown_scenarios_and_incomplete_review_attestation():
    with pytest.raises(ValueError, match="unknown scenario_id"):
        validate_dataset((dict(CASES[0], scenario_id="not-a-fixture"),))
    invalid_review = dict(CASES[0], review_status="REVIEWED", reviewer=None, reviewed_at="2026-10-24", reviewed_outcome="PRESERVED", reviewed_rationale="reviewed")
    with pytest.raises(ValueError, match="Review attestation incomplete"):
        validate_dataset((invalid_review,))


def test_moved_only_baseline_is_independent_and_conservative():
    source = "aws_s3_bucket.old"
    obligation = {"protected_asset": source}
    moved = {"moves.tf": "moved { from = aws_s3_bucket.old to = aws_s3_bucket.new }"}
    result = independent_moved_only({}, moved, obligation)
    assert result["verdict"] == "PRESERVED"
    assert result["successor"] == "aws_s3_bucket.new"
    assert independent_moved_only({}, {"main.tf": "resource {}"}, obligation)["verdict"] == "UNKNOWN"

    implementation = inspect.getsource(independent_moved_only)
    assert "backend.sable" not in implementation
    assert "evaluate_authorization" not in implementation
    assert "rank(" not in implementation


def test_metric_calculation_and_review_gate():
    rows = [
        {"expected": "REGRESSED", "predicted": "PRESERVED"},
        {"expected": "REGRESSED", "predicted": "REGRESSED"},
        {"expected": "PRESERVED", "predicted": "REGRESSED"},
        {"expected": "UNKNOWN", "predicted": "UNKNOWN"},
    ]
    metrics = _confusion_metrics(rows, "expected", "predicted")
    assert metrics["false_safe_rate"] == 0.5
    assert metrics["regression_recall"] == 0.5
    assert metrics["false_regression_rate"] == 1.0
    assert metrics["unknown_rate"] == 0.25
    assert _metric_status([(CASES[0], {"predicted": "PRESERVED"})], "predicted")["status"] == "UNMEASURED"


def test_metrics_use_separate_reviewer_label_not_authored_expectation():
    authored = dict(CASES[0], expected_outcome="PRESERVED")
    authored.update(review_status="REVIEWED", reviewer="reviewer-1", reviewed_at="2026-10-24",
                    reviewed_successor="aws_s3_bucket.cdata", reviewed_outcome="REGRESSED",
                    reviewed_rationale="Independent reviewer found the policy scope unsafe.")
    validate_dataset((authored,))
    result = _metric_status([(authored, {"prediction": "PRESERVED"})], "prediction")
    assert result["status"] == "MEASURED_ON_REVIEWED_SET"
    assert result["false_safe_rate"] == 1.0


def test_experiment_refuses_metrics_without_external_review():
    result = run_experiment()
    assert result["dataset"]["reviewed_count"] == 0
    assert result["baseline"]["independent_of_sable_core"] is True
    assert result["metrics"]["sable_outcomes"]["status"] == "UNMEASURED"
    assert result["metrics"]["moved_only_outcomes"]["status"] == "UNMEASURED"
    assert result["metrics"]["correspondence_accuracy"]["status"] == "UNMEASURED"
    assert len(result["cases"]) == len(CASES)
