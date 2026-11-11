"""Focused tests for the unambiguous obligation-misbinding amendment.

Background: the SABLE engine is successor-first — when the protected asset is
absent from the candidate and no unique successor resolves, it used to fail
closed to UNKNOWN even when the obligation was demonstrably misbound
(``wrong_binding_regressed``, ``hard_wrong_binding``). The amendment in
``backend/sable/correspondence.py`` upgrades such cases to REGRESSED **only**
when the misbinding is unambiguous:

  1. successor resolution already failed closed, with no conflicting evidence;
  2. the principal's linked inline role policies Allow the required actions on
     exactly one concrete candidate resource;
  3. exactly one candidate of the protected asset's type carries the baseline
     asset's identity family (equal or token-superset bucket name or ``Asset``
     tag), and that family candidate is not the policy-bound one;
  4. the policy-bound resource carries none of the protected asset's identity
     family and no continuity signal connects it to the protected asset.

Every other unresolved-successor situation stays UNKNOWN, and the logical
successor is never fabricated (it stays ``None``).

Both engine paths (standalone ``_run_sable_engine`` and the integrated
``analyzer._evaluate``) must agree on every verdict below.
"""
from __future__ import annotations

import copy

import pytest

from backend.sable.benchmark import _run_sable_engine
from backend.sable.fixtures.scenarios import SCENARIOS
from backend.sable.fixtures.ground_truth import load_ground_truth


# ── Shared helpers ───────────────────────────────────────────────────────────


def _run_integrated(scenario: dict, tmp_path) -> str:
    from backend.sable.analyzer import _evaluate

    class DummyContext:
        def __init__(self, b, c):
            self.baseline = b
            self.path = c

    b_dir = tmp_path / f"{scenario['id']}_baseline"
    c_dir = tmp_path / f"{scenario['id']}_candidate"
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
    verdict, _, _ = _evaluate(ctx, lambda *_: None, knowledge, cfg, b_dir, c_dir)
    return verdict


def _both_paths(scenario: dict, tmp_path, expected: str):
    standalone = _run_sable_engine(scenario)
    assert standalone["verdict"] == expected, standalone["reason"]
    integrated = _run_integrated(scenario, tmp_path)
    assert integrated == expected, f"integrated path diverged: {integrated}"
    return standalone


# ── The fix: unambiguous misbinding → REGRESSED with unresolved successor ────


@pytest.mark.parametrize("scenario_id", ["wrong_binding_regressed", "hard_wrong_binding"])
def test_unambiguous_misbinding_is_regressed_with_successor_still_unresolved(tmp_path, scenario_id):
    result = _both_paths(SCENARIOS[scenario_id], tmp_path, "REGRESSED")
    # The logical successor is NOT fabricated: it stays unresolved.
    assert result["details"]["successor"] is None
    misbinding = result["details"]["misbinding"]
    # The evidence names the policy-bound wrong asset and the identity-family candidate.
    assert misbinding["misbound_target"] == "aws_s3_bucket.logs_bucket"
    assert misbinding["identity_family_candidate"] != misbinding["misbound_target"]
    assert set(misbinding["required_actions"]) == {"s3:GetObject", "s3:PutObject"}
    # False-safe guard: the wrong bucket satisfies the local predicate, yet the
    # verdict must never be PRESERVED for this obligation.
    assert result["verdict"] != "PRESERVED"


def test_misbinding_oracle_stays_regressed_with_null_successor():
    gt = load_ground_truth()
    assert gt["wrong_binding_regressed"] == "REGRESSED"
    assert gt["hard_wrong_binding"] == "REGRESSED"


# ── Safeguards: ambiguous/missing evidence must stay UNKNOWN ────────────────


@pytest.mark.parametrize(
    "scenario_id",
    [
        # Multiple plausible identity-family successors (P >= 2).
        "split_to_two",
        "ambiguous_set_three_candidates",
        "parallel_similar_names",
        "hard_module_split_ambiguous",
        # No identity-family successor at all (P == 0).
        "replacement_wrong_bucket",
        "no_successor_found",
        # Conflicting continuity evidence stays UNKNOWN.
        "conflicting_move_and_physical",
        "hard_conflicting_evidence",
    ],
)
def test_non_unambiguous_unresolved_successors_stay_unknown(tmp_path, scenario_id):
    _both_paths(SCENARIOS[scenario_id], tmp_path, "UNKNOWN")


def test_clean_rename_with_moved_block_stays_preserved(tmp_path):
    _both_paths(SCENARIOS["rename_with_moved"], tmp_path, "PRESERVED")


def test_wildcard_resource_semantics_are_unchanged(tmp_path):
    # Resource="*" on a resolved successor stays REGRESSED.
    _both_paths(SCENARIOS["resource_wildened"], tmp_path, "REGRESSED")
    _both_paths(SCENARIOS["privilege_widening"], tmp_path, "REGRESSED")


# ── Synthetic boundary conditions of the amendment ──────────────────────────


def _scenario_with_candidate(candidate_tf: str) -> dict:
    scenario = copy.deepcopy(SCENARIOS["wrong_binding_regressed"])
    scenario["candidate_tf"] = {"main.tf": candidate_tf}
    return scenario


def test_policy_bound_to_the_identity_family_candidate_itself_stays_unknown(tmp_path):
    # The policy targets the only identity-family candidate: consistent with
    # continuity, so the misbinding claim is not available.
    tf = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_new" {
  bucket = "customer-data-new"
  tags = { Asset = "customer-data-new" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_new.arn}/*" }]
  })
}
'''
    _both_paths(_scenario_with_candidate(tf), tmp_path, "UNKNOWN")


def test_partial_name_token_overlap_is_not_identity_family_evidence(tmp_path):
    # "data-lake" shares a token with "customer-data" but is not a token superset:
    # no identity-family successor exists, so the case stays UNKNOWN (no P >= 1).
    tf = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "data_lake" {
  bucket = "data-lake"
  tags = { Asset = "data" Stage = "production" }
}
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-storage"
  tags = { Asset = "logs" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.logs_bucket.arn}/*" }]
  })
}
'''
    _both_paths(_scenario_with_candidate(tf), tmp_path, "UNKNOWN")


def test_asset_tag_family_evidence_alone_supports_the_misbinding(tmp_path):
    # The family candidate carries the exact protected Asset tag but a different
    # bucket name and a different lifecycle stage — too weak for the successor
    # ranking to resolve (score below threshold), so only the amendment can
    # establish the verdict. The policy binds an unrelated logs bucket.
    tf = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "renewed_store" {
  bucket = "renewed-storage"
  tags = { Asset = "customer-data" Stage = "staging" }
}
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-storage"
  tags = { Asset = "logs" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${aws_s3_bucket.logs_bucket.arn}/*" }]
  })
}
'''
    result = _both_paths(_scenario_with_candidate(tf), tmp_path, "REGRESSED")
    # The successor stays unresolved even under the amendment.
    assert result["details"]["successor"] is None
    assert result["details"]["misbinding"]["identity_family_candidate"] == "aws_s3_bucket.renewed_store"


def test_policy_bound_to_multiple_buckets_stays_unknown(tmp_path):
    # Two Allow statements bind different buckets: the binding is ambiguous.
    tf = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_new" {
  bucket = "customer-data-new"
  tags = { Asset = "customer-data-new" Stage = "production" }
}
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-storage"
  tags = { Asset = "logs" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow" Action = ["s3:GetObject"] Resource = "${aws_s3_bucket.logs_bucket.arn}/*" },
      { Effect = "Allow" Action = ["s3:PutObject"] Resource = "${aws_s3_bucket.customer_data_new.arn}/*" }
    ]
  })
}
'''
    _both_paths(_scenario_with_candidate(tf), tmp_path, "UNKNOWN")


def test_statically_unresolvable_policy_target_stays_unknown(tmp_path):
    # A module-output Resource reference cannot be resolved statically; the
    # amendment must not fire on unresolvable evidence.
    tf = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
module "storage" {
  source = "./storage_module"
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:GetObject", "s3:PutObject"] Resource = "${module.storage.bucket_arn}/*" }]
  })
}
output "customer_data_arn" {
  value = module.storage.bucket_arn
}
'''
    scenario = _scenario_with_candidate(tf)
    scenario["candidate_tf"]["storage_module/main.tf"] = '''
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-storage"
  tags = { Asset = "logs" Stage = "production" }
}
output "bucket_arn" {
  value = aws_s3_bucket.logs_bucket.arn
}
'''
    _both_paths(scenario, tmp_path, "UNKNOWN")


def test_granted_actions_not_covering_the_obligation_stay_unknown(tmp_path):
    # The wrong bucket is bound, but the granted actions do not cover the
    # required ones; a detached obligation is not an unambiguous misbinding.
    tf = '''
resource "aws_iam_role" "app" {
  name = "app-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Principal = { Service = "ec2.amazonaws.com" } Action = "sts:AssumeRole" }]
  })
}
resource "aws_s3_bucket" "customer_data_new" {
  bucket = "customer-data-new"
  tags = { Asset = "customer-data-new" Stage = "production" }
}
resource "aws_s3_bucket" "logs_bucket" {
  bucket = "logs-storage"
  tags = { Asset = "logs" Stage = "production" }
}
resource "aws_iam_role_policy" "app_policy" {
  name   = "CustomerDataAccess"
  role   = aws_iam_role.app.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{ Effect = "Allow" Action = ["s3:ListBucket"] Resource = "${aws_s3_bucket.logs_bucket.arn}" }]
  })
}
'''
    _both_paths(_scenario_with_candidate(tf), tmp_path, "UNKNOWN")


# ── Full-fixture sweep: only the two wrong-binding cases may flip ───────────


def test_amendment_changes_no_verdict_beyond_the_two_wrong_binding_cases():
    """33-scenario engine sweep: the amendment must flip exactly the two
    wrong-binding cases to REGRESSED (matching their oracle labels) and leave
    every other verdict untouched, including the pre-existing ``merge_into_one``
    oracle mismatch (engine PRESERVED vs oracle UNKNOWN), which is out of scope
    for this change."""
    from backend.sable.fixtures.ground_truth import GROUND_TRUTH

    flipped = {"wrong_binding_regressed", "hard_wrong_binding"}
    unchanged_mismatch = {"merge_into_one"}
    for sid, scenario in SCENARIOS.items():
        verdict = _run_sable_engine(scenario)["verdict"]
        oracle = GROUND_TRUTH[sid]
        if sid in flipped:
            assert verdict == "REGRESSED" == oracle, sid
        elif sid in unchanged_mismatch:
            assert verdict != oracle, sid  # pre-existing mismatch stays untouched
        else:
            assert verdict == oracle, sid
