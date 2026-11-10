from __future__ import annotations

import copy

import pytest

from backend.sable.authorization import evaluate_authorization
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


EDGE_POLICY_CASES = [
    ("exact_good", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"${aws_s3_bucket.b.arn}/*"}]}', "PRESERVED"),
    ("wildcard_resource_string", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}', "REGRESSED"),
    ("wildcard_resource_list", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["*"]}]}', "REGRESSED"),
    ("wildcard_resource_mixed", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["${aws_s3_bucket.b.arn}/*","*"]}]}', "REGRESSED"),
    ("wildcard_action_star", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"${aws_s3_bucket.b.arn}/*"}]}', "REGRESSED"),
    ("wildcard_action_s3_star", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:*"],"Resource":"${aws_s3_bucket.b.arn}/*"}]}', "REGRESSED"),
    ("wildcard_action_extra", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject","s3:DeleteObject"],"Resource":"${aws_s3_bucket.b.arn}/*"}]}', "REGRESSED"),
    ("missing_action", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"${aws_s3_bucket.b.arn}/*"}]}', "REGRESSED"),
    ("explicit_deny", '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":["s3:GetObject"],"Resource":"${aws_s3_bucket.b.arn}/*"}]}', "UNKNOWN"),
    ("unsupported_condition", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"${aws_s3_bucket.b.arn}/*","Condition":{"Bool":{"aws:SecureTransport":"true"}}}]}', "UNKNOWN"),
    ("unsupported_not_action", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","NotAction":["s3:DeleteObject"],"Resource":"${aws_s3_bucket.b.arn}/*"}]}', "UNKNOWN"),
    ("wrong_resource", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::unrelated-bucket/*"}]}', "REGRESSED"),
    ("bucket_arn_not_object_arn", '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"${aws_s3_bucket.b.arn}"}]}', "REGRESSED"),
]


@pytest.mark.parametrize("case_name, candidate_policy_json, expected_verdict", EDGE_POLICY_CASES)
def test_standalone_and_integrated_policy_semantics_match_on_edge_cases(
    tmp_path, case_name, candidate_policy_json, expected_verdict
):
    tf = f'''
resource "aws_iam_role" "app" {{
  name = "app-role"
}}
resource "aws_s3_bucket" "b" {{
  bucket = "my-bucket"
}}
resource "aws_iam_role_policy" "p" {{
  name = "p"
  role = aws_iam_role.app.id
  policy = jsonencode({candidate_policy_json})
}}
'''
    (tmp_path / "main.tf").write_text(tf, encoding="utf-8")
    model = parse(tmp_path)
    actions = ["s3:GetObject", "s3:PutObject"]

    standalone_auth = evaluate_authorization(model, "aws_iam_role.app", "aws_s3_bucket.b", actions)
    integrated_auth = evaluate_integrated_policy(model, "aws_iam_role.app", "aws_s3_bucket.b", actions)

    s_verdict = "PRESERVED" if standalone_auth.holds else ("UNKNOWN" if not standalone_auth.known else "REGRESSED")
    i_verdict = "PRESERVED" if integrated_auth["holds"] else ("UNKNOWN" if not integrated_auth["known"] else "REGRESSED")

    assert s_verdict == expected_verdict
    assert i_verdict == expected_verdict
    assert s_verdict == i_verdict


@pytest.mark.parametrize("scenario_id", list(SCENARIOS.keys()))
def test_standalone_and_integrated_scenarios_consistency(tmp_path, scenario_id):
    from backend.sable.analyzer import _evaluate

    class DummyContext:
        def __init__(self, b, c):
            self.baseline = b
            self.path = c

    scenario = SCENARIOS[scenario_id]
    v_standalone = _run_sable_engine(scenario)["verdict"]

    b_dir = tmp_path / "baseline"
    c_dir = tmp_path / "candidate"
    b_dir.mkdir()
    c_dir.mkdir()

    for fn, content in scenario["baseline_tf"].items():
        f = b_dir / fn
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")
    for fn, content in scenario["candidate_tf"].items():
        f = c_dir / fn
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(content, encoding="utf-8")

    ctx = DummyContext(str(b_dir), str(c_dir))
    cfg = dict(scenario["obligation"], minimum_score=6, margin=3)
    knowledge = {"SABLE-SUCCESSOR-001": {"data": {"minimum_score": 6, "margin": 3}}}
    v_integrated, _, _ = _evaluate(ctx, lambda *_: None, knowledge, cfg, b_dir, c_dir)

    assert v_standalone == v_integrated
