"""Tests for the blinded SABLE reviewer package and its separate answer key.

The blinded copy (``reports/SABLE_BLINDED_REVIEW_PACKAGE.json``) is what an
independent reviewer receives: neutral case identifiers, the registered
obligation and both Terraform configurations per case, blank reviewer
assessment fields — and none of the answer-revealing material (expected
outcomes/successors, author rationales, SABLE predictions, scenario
identifiers, outcome-hinting fixture names/notes).

The identifier-to-scenario mapping lives only in the answer key
(``reports/SABLE_BLINDED_REVIEW_KEY.json``), which reviewers must not receive.
The existing source of truth (``generate_review_package`` and its committed
JSON) is unchanged by this feature.
"""
from __future__ import annotations

import json
import pathlib

from backend.sable.research_eval import (
    _BLINDED_REVIEWER_FIELDS,
    CASES,
    SCENARIOS,
    blinded_case_ids,
    generate_blinded_answer_key,
    generate_blinded_review_package,
    generate_review_package,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
BLINDED_PATH = REPO_ROOT / "reports" / "SABLE_BLINDED_REVIEW_PACKAGE.json"
KEY_PATH = REPO_ROOT / "reports" / "SABLE_BLINDED_REVIEW_KEY.json"
SOURCE_OF_TRUTH_PATH = REPO_ROOT / "reports" / "SABLE_INDEPENDENT_REVIEW_PACKAGE.json"


# ── Blinded package structure ────────────────────────────────────────────────


def test_blinded_package_has_neutral_ids_in_non_dataset_order():
    package = generate_blinded_review_package()
    ids = [c["blind_id"] for c in package["cases"]]
    assert ids == blinded_case_ids()
    assert len(ids) == len(CASES) == 6
    # Presentation order is deliberately not the dataset order, so position
    # alone cannot reveal which dataset case is which.
    dataset_order = [c["scenario_id"] for c in CASES]
    key = generate_blinded_answer_key()
    presentation = [key["mapping"][i]["scenario_id"] for i in ids]
    assert presentation != dataset_order
    assert set(presentation) == set(dataset_order)


def test_blinded_reviewer_assessment_fields_are_blank():
    for case in generate_blinded_review_package()["cases"]:
        assert case["reviewer_assessment"] == {field: "" for field in _BLINDED_REVIEWER_FIELDS}
        assert set(case) == {"blind_id", "instruction", "obligation", "baseline_tf", "candidate_tf", "reviewer_assessment"}


def test_blinded_package_carries_the_raw_review_material():
    # A reviewer can genuinely assess each case: the registered obligation and
    # both Terraform configurations are present.
    for case in generate_blinded_review_package()["cases"]:
        assert case["obligation"]["principal"]
        assert case["obligation"]["actions"]
        assert case["obligation"]["protected_asset"]
        assert case["baseline_tf"] and case["candidate_tf"]


# ── No answer-revealing material ─────────────────────────────────────────────


def _blinded_metadata_blob(package) -> str:
    """JSON of everything except the Terraform content and (blank) reviewer fields."""
    parts = [json.dumps({k: v for k, v in package.items() if k != "cases"}, sort_keys=True)]
    for case in package["cases"]:
        parts.append(json.dumps(
            {k: v for k, v in case.items() if k not in ("baseline_tf", "candidate_tf", "reviewer_assessment")},
            sort_keys=True,
        ))
    return " ".join(parts).lower()


def test_blinded_package_leaks_no_authored_answers_or_scenario_identity():
    package = generate_blinded_review_package()
    blob = _blinded_metadata_blob(package)
    leaked = []
    for case in CASES:
        scenario = SCENARIOS[case["scenario_id"]]
        for value in (
            case["scenario_id"], scenario["id"], scenario["name"], scenario["notes"],
            case["rationale"], case["expected_outcome"], case["expected_successor"] or "",
        ):
            if value and value.lower() in blob:
                leaked.append(value)
    # A successor address that coincides with the obligation's protected_asset is
    # inherent reviewer material (the obligation is presented to the reviewer);
    # no authored successor *field* exists (structural check), so the substring
    # coincidence is benign.
    reviewer_material = {SCENARIOS[c["scenario_id"]]["obligation"]["protected_asset"] for c in CASES}
    leaked = [v for v in leaked if v not in reviewer_material]
    assert leaked == [], f"blinded package leaks authored answers: {leaked}"


def test_blinded_package_contains_no_engine_or_evaluator_outputs():
    package = generate_blinded_review_package()
    blob = _blinded_metadata_blob(package)
    for field in ("verdict", "prediction", "sable", "moved_only", "hypotheses", "projected_authorization"):
        assert f'"{field}"' not in blob, f"blinded package must not carry engine output field {field!r}"


# ── Answer key separateness ──────────────────────────────────────────────────


def test_answer_key_maps_every_blind_case_to_its_dataset_scenario():
    key = generate_blinded_answer_key()
    assert set(key["mapping"]) == set(blinded_case_ids())
    assert {v["scenario_id"] for v in key["mapping"].values()} == {c["scenario_id"] for c in CASES}
    assert key["warning"].startswith("REVIEWERS MUST NOT RECEIVE THIS FILE")


def test_answer_key_is_not_embedded_in_the_blinded_copy():
    package = generate_blinded_review_package()
    key = generate_blinded_answer_key()
    package_blob = json.dumps(package, sort_keys=True).lower()
    # The blinded copy carries no scenario identifiers and no mapping section.
    assert "mapping" not in package_blob or '"mapping"' not in json.dumps(package["cases"])
    assert "scenario_id" not in package_blob
    for case in key["mapping"].values():
        assert case["scenario_id"] not in package_blob
    # And the key itself is a distinct document with the answers.
    assert all("expected_outcome" in v for v in key["mapping"].values())


# ── Committed artifacts match the generators; source of truth unchanged ─────


def test_blinded_package_on_disk_matches_the_generator():
    assert json.loads(BLINDED_PATH.read_text(encoding="utf-8")) == generate_blinded_review_package()


def test_answer_key_on_disk_matches_the_generator():
    assert json.loads(KEY_PATH.read_text(encoding="utf-8")) == generate_blinded_answer_key()


def test_existing_source_of_truth_is_unchanged():
    # The blinded feature must not alter the original review package.
    assert json.loads(SOURCE_OF_TRUTH_PATH.read_text(encoding="utf-8")) == generate_review_package()
    source = json.loads(SOURCE_OF_TRUTH_PATH.read_text(encoding="utf-8"))
    assert all(c["independent_attestation_template"]["review_status"] == "UNREVIEWED" for c in source["cases"])


def test_blinded_cases_reuse_the_same_terraform_as_their_dataset_scenario():
    # Spot-proof that the blinded raw material is genuine: each blinded case's
    # configurations equal the mapped dataset scenario's configurations (mapping
    # taken from the answer key, which the reviewer never receives).
    key = generate_blinded_answer_key()
    for case in generate_blinded_review_package()["cases"]:
        scenario = SCENARIOS[key["mapping"][case["blind_id"]]["scenario_id"]]
        assert case["baseline_tf"] == scenario["baseline_tf"]
        assert case["candidate_tf"] == scenario["candidate_tf"]
        assert case["obligation"] == scenario["obligation"]
