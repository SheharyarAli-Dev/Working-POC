"""Focused regression tests for the wrong-binding successor attribution audit.

Background: the oracle's authored expectation for ``wrong_binding_regressed``
previously over-attributed the successor to ``aws_s3_bucket.customer_data_new``
despite no continuity evidence (different bucket name, different tag, no moved
block, no policy reference). The author-review record
(report``reports/SABLE_AUTHOR_REVIEW_2026-11-10.md``) pins the case as
REGRESSED with an unresolved successor, while the independent-review
attestations stay UNREVIEWED.

Covers Task B and Task C of the SABLE author-review closing check.
"""
from __future__ import annotations

import json
import pathlib

import pytest

from backend.sable.fixtures.scenarios import SCENARIOS
from backend.sable.research_eval import CASES, REVIEW_PROTOCOL, generate_review_package

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WRONG_BINDING = "wrong_binding_regressed"


def _case(scenario_id: str):
    return next(c for c in CASES if c["scenario_id"] == scenario_id)


def test_wrong_binding_oracle_is_regressed_with_unresolved_successor():
    case = _case(WRONG_BINDING)
    assert case["expected_outcome"] == "REGRESSED"
    assert case["expected_successor"] is None
    assert "unresolved" in case["rationale"].lower()
    validate_reasoning = case["rationale"].lower()
    assert "customer_data_new" in validate_reasoning
    assert "no continuity evidence" in validate_reasoning


def test_wrong_binding_candidate_has_no_continuity_evidence_for_the_disclaimed_successor():
    candidate = SCENARIOS[WRONG_BINDING]["candidate_tf"]["main.tf"]
    # No moved block exists at all.
    assert "moved {" not in candidate
    # The distractor's physical identity and tag both differ from the protected asset.
    assert 'bucket = "customer-data-new"' in candidate
    assert 'Asset = "customer-data-new"' in candidate
    assert 'Asset = "customer-data"' not in candidate
    # The distractor is not what the policy binds to.
    assert "aws_s3_bucket.customer_data_new.arn" not in candidate
    assert "${aws_s3_bucket.logs_bucket.arn}/*" in candidate


def test_review_package_on_disk_matches_the_corrected_oracle():
    disk = json.loads((REPO_ROOT / "reports" / "SABLE_INDEPENDENT_REVIEW_PACKAGE.json").read_text(encoding="utf-8"))
    generated = generate_review_package()
    # Full-package equality: the committed evidence file must stay in sync with
    # the source metadata (protocol, taxonomy, cases, attestation templates).
    assert disk == generated
    disk_case = next(c for c in disk["cases"] if c["scenario_id"] == WRONG_BINDING)
    assert disk_case["authored_expectation"]["expected_successor"] is None
    assert disk_case["authored_expectation"]["expected_outcome"] == "REGRESSED"


def test_independent_attestations_remain_unreviewed_after_author_review():
    pkg = generate_review_package()
    for c in pkg["cases"]:
        att = c["independent_attestation_template"]
        assert att["review_status"] == "UNREVIEWED"
        assert att["reviewer"] == "<Reviewer Name, Title, Institution>"
        assert att["reviewed_outcome"] == "<PRESERVED | REGRESSED | UNKNOWN>"


def test_review_protocol_records_evidence_tiers_with_metric_exclusivity():
    tiers = REVIEW_PROTOCOL["review_evidence_tiers"]
    assert set(tiers) == {"independent_human_review", "author_review", "ai_assisted_review"}
    assert tiers["independent_human_review"]["may_feed_metrics"] is True
    assert tiers["author_review"]["may_feed_metrics"] is False
    assert tiers["ai_assisted_review"]["may_feed_metrics"] is False
    # The author-review tier points at the real evidence document.
    doc_ref = tiers["author_review"]["definition"]
    assert "reports/SABLE_AUTHOR_REVIEW_2026-11-10.md" in doc_ref
    assert (REPO_ROOT / "reports" / "SABLE_AUTHOR_REVIEW_2026-11-10.md").is_file()
    # Only the independent tier may feed metrics.
    assert [k for k, v in tiers.items() if v["may_feed_metrics"]] == ["independent_human_review"]
    # The independent attestation template declares its tier explicitly.
    for c in generate_review_package()["cases"]:
        assert c["independent_attestation_template"]["evidence_tier"] == "independent_human_review"


# ── Review-tier metric safeguards (Task: enforce at validation/metric boundary) ──


def _attested_case(scenario_id: str, tier: str):
    from backend.sable.research_eval import CASES

    base = next(c for c in CASES if c["scenario_id"] == scenario_id)
    return dict(
        base,
        review_status="REVIEWED",
        evidence_tier=tier,
        reviewer="Test Reviewer",
        reviewed_at="2026-11-11",
        reviewed_successor="aws_s3_bucket.cdata",
        reviewed_outcome="PRESERVED",
        reviewed_rationale="Detailed technical reasoning for verdict.",
    )


def test_author_review_evidence_is_rejected_and_excluded_from_metrics():
    from backend.sable.research_eval import _metric_status, validate_dataset

    author_case = _attested_case("rename_with_moved", "author_review")
    # Dataset boundary: rejected outright.
    with pytest.raises(ValueError, match="Only independent-human-review attestations may feed metrics"):
        validate_dataset((author_case,))
    # Metric boundary: excluded even if a caller bypasses validate_dataset.
    status = _metric_status([(author_case, {"prediction": "PRESERVED"})], "prediction")
    assert status["status"] == "UNMEASURED"
    assert "not independently reviewed" in status["reason"]


def test_ai_assisted_review_evidence_is_rejected_and_excluded_from_metrics():
    from backend.sable.research_eval import _metric_status, validate_dataset

    ai_case = _attested_case("rename_with_moved", "ai_assisted_review")
    with pytest.raises(ValueError, match="Only independent-human-review attestations may feed metrics"):
        validate_dataset((ai_case,))
    status = _metric_status([(ai_case, {"prediction": "PRESERVED"})], "prediction")
    assert status["status"] == "UNMEASURED"


def test_unreviewed_case_must_not_carry_an_evidence_tier():
    from backend.sable.research_eval import CASES, validate_dataset

    stray = dict(next(c for c in CASES if c["scenario_id"] == "split_to_two"), evidence_tier="independent_human_review")
    with pytest.raises(ValueError, match="Unreviewed case must not carry an evidence tier"):
        validate_dataset((stray,))


def test_valid_independent_human_attestation_passes_and_feeds_metrics():
    from backend.sable.research_eval import _metric_status, validate_dataset

    ok_case = _attested_case("rename_with_moved", "independent_human_review")
    validate_dataset((ok_case,))  # must not raise
    status = _metric_status([(ok_case, {"prediction": "PRESERVED"})], "prediction")
    assert status["status"] == "MEASURED_ON_REVIEWED_SET"
    assert status["n"] == 1
    assert status["confusion"]["PRESERVED"]["PRESERVED"] == 1


def test_current_six_cases_stay_unreviewed_with_null_tier_and_unmeasured_metrics():
    from backend.sable.research_eval import CASES, run_experiment

    assert all(c["review_status"] == "UNREVIEWED" for c in CASES)
    assert all(c["evidence_tier"] is None for c in CASES)
    result = run_experiment()
    assert result["dataset"]["reviewed_count"] == 0
    assert result["metrics"]["sable_outcomes"]["status"] == "UNMEASURED"
    assert result["metrics"]["moved_only_outcomes"]["status"] == "UNMEASURED"
    for c in result["cases"]:
        assert c["independent_review"]["evidence_tier"] is None


def test_wrong_binding_engine_discrepancy_is_documented_not_resolved():
    """The engine intentionally still fails closed to UNKNOWN; the discrepancy is
    recorded in the author-review evidence document, and the oracle keeps REGRESSED.
    The fix must be encoded in the engine later, not painted over here."""
    from backend.sable.benchmark import _run_sable_engine

    result = _run_sable_engine(SCENARIOS[WRONG_BINDING])
    assert result["verdict"] == "UNKNOWN"  # engine discrepancy stays honest and visible
    case = _case(WRONG_BINDING)
    assert case["expected_outcome"] == "REGRESSED"  # oracle is not weakened to match the engine
    doc = (REPO_ROOT / "reports" / "SABLE_AUTHOR_REVIEW_2026-11-10.md").read_text(encoding="utf-8")
    assert "Proposed smallest defensible engine fix" in doc
    assert "NOT implemented in this task" in doc
