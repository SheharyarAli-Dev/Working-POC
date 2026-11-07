from __future__ import annotations

import copy

import pytest

from backend.sable.benchmark import _run_sable_engine
from backend.sable.fixtures.scenarios import SCENARIOS
from backend.sable.hcl_parser import parse
from backend.sable.policy_semantics import evaluate as evaluate_integrated_policy


@pytest.mark.parametrize(
    "invalid_field, replacement, expected_reason",
    [
        ("Action", "Action = [1]", "Action must be a non-empty string"),
        ("Resource", "Resource = [1]", "Resource must be a non-empty string"),
        ("Action", "Action = []", "Action must be a non-empty string"),
        ("Resource", "Resource = []", "Resource must be a non-empty string"),
    ],
)
def test_malformed_policy_value_types_fail_closed_in_standalone_pipeline(
    invalid_field, replacement, expected_reason
):
    scenario = copy.deepcopy(SCENARIOS["resource_wildened"])
    original = scenario["candidate_tf"]["main.tf"]
    old = (
        'Action = ["s3:GetObject", "s3:PutObject"]'
        if invalid_field == "Action"
        else 'Resource = "*"'
    )
    assert old in original
    scenario["candidate_tf"]["main.tf"] = original.replace(old, replacement, 1)

    result = _run_sable_engine(scenario)
    assert result["verdict"] == "UNKNOWN"
    assert expected_reason in result["reason"]


@pytest.mark.parametrize(
    "replacement, expected_reason",
    [
        ('Action = [1]', "Action must be a non-empty string"),
        ('Resource = [1]', "Resource must be a non-empty string"),
    ],
)
def test_integrated_policy_evaluator_reports_malformed_values_as_unknown(
    tmp_path, replacement, expected_reason
):
    scenario = copy.deepcopy(SCENARIOS["resource_wildened"])
    text = scenario["candidate_tf"]["main.tf"]
    field = "Action" if replacement.startswith("Action") else "Resource"
    old = 'Action = ["s3:GetObject", "s3:PutObject"]' if field == "Action" else 'Resource = "*"'
    assert old in text
    (tmp_path / "main.tf").write_text(text.replace(old, replacement, 1), encoding="utf-8")
    model = parse(tmp_path)

    result = evaluate_integrated_policy(
        model,
        "aws_iam_role.app",
        "aws_s3_bucket.customer_data",
        ["s3:GetObject", "s3:PutObject"],
    )
    assert result["known"] is False
    assert result["holds"] is False
    assert any(expected_reason in message for message in result["unknown"])
