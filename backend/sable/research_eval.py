"""Separate, provenance-aware research evaluation for SABLE.

These authored reference cases are intentionally not imported by SABLE's engine.
They are not independently reviewed; outcome metrics remain UNMEASURED until a
reviewer records a review attestation for every included case.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any

from backend.sable.fixtures.scenarios import SCENARIOS


DATASET_ID = "sable-independent-oracle-v1"
DATASET_PROVENANCE = (
    "Authored as a separate evaluation specification from the stated Terraform "
    "refactor and authorization obligation. Scenario Terraform is reused from "
    "the implementation fixture catalog; authorship is not independent review."
)

# Architectural taxonomy distinguishing independent baselines from internal ablations.
# B4 shares SABLE's correspondence ranker and authorization engine, and must never
# be represented as an independent baseline or comparator.
COMPARATOR_TAXONOMY: dict[str, dict[str, Any]] = {
    "independent_moved_only": {
        "classification": "INDEPENDENT_BASELINE",
        "implementation_independence": "ZERO_SABLE_COUPLING",
        "description": (
            "Pure regex-based moved-block parser. Does not import or execute any SABLE "
            "modules (HCL parser, correspondence, or authorization). Predicts PRESERVED "
            "if a unique moved block targets the obligation asset; UNKNOWN otherwise."
        ),
        "limitations": (
            "Cannot evaluate policy semantics or detect authorization regressions "
            "(e.g., privilege widening, misbinding, or weakening)."
        ),
        "evaluates_policy": False,
        "evaluates_correspondence": True,
    },
    "B0_candidate_only": {
        "classification": "INTERNAL_ABLATION",
        "implementation_independence": "REUSES_SABLE_CORE",
        "description": (
            "Ablation evaluating authorization on the candidate without correspondence "
            "resolution (evaluates original asset address directly)."
        ),
        "limitations": "Reuses SABLE's evaluate_authorization engine; not an independent baseline.",
        "evaluates_policy": True,
        "evaluates_correspondence": False,
    },
    "B1_policy_scan_diff": {
        "classification": "INTERNAL_ABLATION",
        "implementation_independence": "REUSES_SABLE_CORE",
        "description": (
            "Ablation comparing before/after effective permission sets without structural "
            "resource correspondence."
        ),
        "limitations": "Reuses SABLE's evaluate_authorization engine; not an independent baseline.",
        "evaluates_policy": True,
        "evaluates_correspondence": False,
    },
    "B2_moved_evidence": {
        "classification": "INTERNAL_ABLATION",
        "implementation_independence": "REUSES_SABLE_CORE",
        "description": (
            "Ablation using only HCL-parsed moves without correspondence scoring or policy check."
        ),
        "limitations": "Reuses SABLE's python-hcl2 wrapper; does not verify policy security.",
        "evaluates_policy": False,
        "evaluates_correspondence": True,
    },
    "B3_structural_correspondence": {
        "classification": "INTERNAL_ABLATION",
        "implementation_independence": "REUSES_SABLE_CORE",
        "description": (
            "Ablation executing SABLE correspondence ranking and selection without "
            "obligation projection."
        ),
        "limitations": "Reuses SABLE's rank and choose algorithms; omits authorization projection.",
        "evaluates_policy": False,
        "evaluates_correspondence": True,
    },
    "B4_composite_ablation": {
        "classification": "INTERNAL_ABLATION_COMPOSITE",
        "implementation_independence": "REUSES_SABLE_CORE",
        "description": (
            "Composite internal ablation combining B0+B1+B2+B3 with policy-target relationships. "
            "Must NOT be described as an independent comparator because it reuses SABLE's "
            "correspondence ranker and authorization engine."
        ),
        "limitations": (
            "Implementation leakage: shares identical AST/graph, correspondence scoring, "
            "and authorization code with SABLE."
        ),
        "evaluates_policy": True,
        "evaluates_correspondence": True,
    },
}

REVIEW_PROTOCOL: dict[str, Any] = {
    "version": "1.0",
    "goal": (
        "Independent expert validation of SABLE benchmark ground truth to determine: "
        "(1) logical asset continuity, and (2) least-privilege obligation preservation."
    ),
    "attestation_fields": [
        "reviewer",
        "evidence_tier",
        "reviewed_at",
        "reviewed_successor",
        "reviewed_outcome",
        "reviewed_rationale",
    ],
    "review_criteria": [
        "Reviewer must not be an author or contributor to SABLE code.",
        "Reviewer inspects raw baseline and candidate HCL files independently.",
        "Reviewer independently determines whether a unique logical successor exists.",
        "Reviewer independently determines whether the candidate IAM policy satisfies the least-privilege obligation.",
        "Reviewer must provide explicit technical rationale for every reviewed case.",
    ],
    "review_evidence_tiers": {
        "independent_human_review": {
            "definition": "External experts with no contribution to SABLE code, executing this protocol independently of the authors' expectations.",
            "may_feed_metrics": True,
        },
        "author_review": {
            "definition": "Evaluations performed by SABLE authors or contributors; recorded as provenance only and never used for metrics. Evidence record: reports/SABLE_AUTHOR_REVIEW_2026-11-10.md.",
            "may_feed_metrics": False,
        },
        "ai_assisted_review": {
            "definition": "Analyses produced with AI-tool assistance (including the SABLE engine itself); recorded as observations, never as review attestation.",
            "may_feed_metrics": False,
        },
    },
    "current_status": "PENDING_INDEPENDENT_REVIEW",
}

# Logical successor is an evaluation annotation, never read by either predictor.
CASES: tuple[dict[str, Any], ...] = (
    {"scenario_id": "rename_with_moved", "expected_successor": "aws_s3_bucket.cdata", "expected_outcome": "PRESERVED", "rationale": "Explicit moved block maps the protected bucket address to cdata; physical bucket identity and policy target are retained.", "review_status": "UNREVIEWED", "evidence_tier": None, "reviewer": None, "reviewed_at": None, "reviewed_successor": None, "reviewed_outcome": None, "reviewed_rationale": None},
    {"scenario_id": "split_to_two", "expected_successor": None, "expected_outcome": "UNKNOWN", "rationale": "Two new bucket resources divide the prior logical asset; the case provides no unique logical successor rule.", "review_status": "UNREVIEWED", "evidence_tier": None, "reviewer": None, "reviewed_at": None, "reviewed_successor": None, "reviewed_outcome": None, "reviewed_rationale": None},
    {"scenario_id": "resource_wildened", "expected_successor": "aws_s3_bucket.customer_data", "expected_outcome": "REGRESSED", "rationale": "The original logical bucket remains, but the policy resource scope becomes wildcard rather than bucket-specific.", "review_status": "UNREVIEWED", "evidence_tier": None, "reviewer": None, "reviewed_at": None, "reviewed_successor": None, "reviewed_outcome": None, "reviewed_rationale": None},
    {"scenario_id": "wrong_binding_regressed", "expected_successor": None, "expected_outcome": "REGRESSED", "rationale": "REGRESSED: the required actions are re-bound to logs_bucket, whose Asset tag ('logs') is categorically incompatible with the customer-data obligation; the successor stays unresolved because customer_data_new shows no continuity evidence (different bucket name, different tag, no moved block, and no policy reference).", "review_status": "UNREVIEWED", "evidence_tier": None, "reviewer": None, "reviewed_at": None, "reviewed_successor": None, "reviewed_outcome": None, "reviewed_rationale": None},
    {"scenario_id": "ambiguous_set_three_candidates", "expected_successor": None, "expected_outcome": "UNKNOWN", "rationale": "Three candidates carry equivalent logical tags and no unique identity evidence selects one.", "review_status": "UNREVIEWED", "evidence_tier": None, "reviewer": None, "reviewed_at": None, "reviewed_successor": None, "reviewed_outcome": None, "reviewed_rationale": None},
    {"scenario_id": "replacement_wrong_bucket", "expected_successor": None, "expected_outcome": "UNKNOWN", "rationale": "Replacement has different physical identity and no continuity evidence; the intended successor cannot be established from this case.", "review_status": "UNREVIEWED", "evidence_tier": None, "reviewer": None, "reviewed_at": None, "reviewed_successor": None, "reviewed_outcome": None, "reviewed_rationale": None},
)

_ALLOWED = {"PRESERVED", "REGRESSED", "UNKNOWN"}


def validate_dataset(cases: tuple[dict[str, Any], ...] = CASES) -> None:
    """Validates the oracle dataset, including the review-evidence-tier safeguard.

    Only ``independent_human_review`` attestations may ever be marked REVIEWED and
    only they can feed metrics. Author-review and AI-assisted evidence are rejected
    here at the dataset boundary and excluded again by ``_metric_status`` at the
    metric boundary.
    """
    ids: set[str] = set()
    for case in cases:
        required = {"scenario_id", "expected_successor", "expected_outcome", "rationale", "review_status", "evidence_tier", "reviewer", "reviewed_at", "reviewed_successor", "reviewed_outcome", "reviewed_rationale"}
        if set(case) != required:
            raise ValueError(f"Invalid case fields for {case.get('scenario_id')}: expected {sorted(required)}")
        sid = case["scenario_id"]
        if sid in ids or sid not in SCENARIOS:
            raise ValueError(f"Duplicate or unknown scenario_id: {sid}")
        ids.add(sid)
        if case["expected_outcome"] not in _ALLOWED or not case["rationale"].strip():
            raise ValueError(f"Missing/invalid expected outcome or rationale: {sid}")
        if case["review_status"] not in {"UNREVIEWED", "REVIEWED"}:
            raise ValueError(f"Invalid review status: {sid}")
        reviewed = case["review_status"] == "REVIEWED"
        if reviewed != bool(case["reviewer"] and case["reviewed_at"] and case["reviewed_outcome"] in _ALLOWED and case["reviewed_rationale"]):
            raise ValueError(f"Review attestation incomplete: {sid}")
        if reviewed:
            if case["evidence_tier"] != "independent_human_review":
                raise ValueError(f"Only independent-human-review attestations may feed metrics: {sid} (got {case['evidence_tier']!r})")
        elif case["evidence_tier"] is not None:
            raise ValueError(f"Unreviewed case must not carry an evidence tier: {sid}")


def generate_review_package(cases: tuple[dict[str, Any], ...] = CASES) -> dict[str, Any]:
    """Generates a self-contained, review-ready package for independent reviewers.

    Includes exact Terraform inputs, obligations, authored rationale, and an empty
    attestation template for each case.
    """
    validate_dataset(cases)
    dossier_cases = []
    for case in cases:
        scenario = SCENARIOS[case["scenario_id"]]
        dossier_cases.append({
            "scenario_id": case["scenario_id"],
            "description": scenario.get("notes", ""),
            "obligation": scenario["obligation"],
            "baseline_tf": scenario["baseline_tf"],
            "candidate_tf": scenario["candidate_tf"],
            "authored_expectation": {
                "expected_successor": case["expected_successor"],
                "expected_outcome": case["expected_outcome"],
                "rationale": case["rationale"],
            },
            "independent_attestation_template": {
                "review_status": "UNREVIEWED",
                "evidence_tier": "independent_human_review",
                "reviewer": "<Reviewer Name, Title, Institution>",
                "reviewed_at": "<YYYY-MM-DD>",
                "reviewed_successor": "<e.g. aws_s3_bucket.cdata or None>",
                "reviewed_outcome": "<PRESERVED | REGRESSED | UNKNOWN>",
                "reviewed_rationale": "<Detailed technical reasoning for verdict>",
            },
        })
    return {
        "dataset_id": DATASET_ID,
        "provenance": DATASET_PROVENANCE,
        "review_protocol": REVIEW_PROTOCOL,
        "comparator_taxonomy": COMPARATOR_TAXONOMY,
        "cases": dossier_cases,
    }


# ── Blinded reviewer copy (answer-revealing material removed) ────────────────

BLINDED_CASE_INSTRUCTION = (
    "For this case, independently assess the registered obligation below against "
    "the baseline and candidate Terraform configurations below: determine whether "
    "a unique logical successor of the protected asset exists, and whether the "
    "candidate IAM policy preserves the least-privilege obligation. Record your "
    "outcome, successor attribution and technical rationale in the reviewer "
    "assessment fields. Do not assume any expected answer exists."
)

_BLINDED_REVIEWER_FIELDS = (
    "review_status",
    "reviewer",
    "reviewed_at",
    "reviewed_successor",
    "reviewed_outcome",
    "reviewed_rationale",
)

def blinded_case_ids() -> list[str]:
    """Neutral identifiers for the blinded copy, in a deterministic presentation
    order that is NOT the dataset order (reversed), so a case's position does not
    reveal its dataset identity."""
    return [f"BLIND-{i}" for i in range(1, len(CASES) + 1)]


def generate_blinded_review_package() -> dict[str, Any]:
    """Blinded reviewer copy of the independent-review package.

    Each case appears under a neutral identifier with the raw material a reviewer
    genuinely needs (the registered obligation and both Terraform configurations)
    and blank reviewer assessment fields. Everything answer-revealing is removed:
    expected outcomes and successors, author rationales, SABLE/evaluator outputs,
    scenario identifiers, outcome-hinting fixture notes and classification flags.
    The identifier-to-scenario mapping lives only in ``generate_blinded_answer_key``
    and must never be stored in, or shared with, the blinded copy."""
    validate_dataset()
    blinded_cases = []
    for blind_id, case in zip(blinded_case_ids(), reversed(CASES)):
        scenario = SCENARIOS[case["scenario_id"]]
        blinded_cases.append({
            "blind_id": blind_id,
            "instruction": BLINDED_CASE_INSTRUCTION,
            "obligation": scenario["obligation"],
            "baseline_tf": scenario["baseline_tf"],
            "candidate_tf": scenario["candidate_tf"],
            "reviewer_assessment": {field: "" for field in _BLINDED_REVIEWER_FIELDS},
        })
    package = {
        "dataset_id": f"{DATASET_ID}-blinded",
        "provenance": (
            "Blinded reviewer copy of the SABLE independent-review package: neutral "
            "case identifiers; expected outcomes, successors, author rationales, "
            "engine predictions and scenario identifiers are deliberately excluded. "
            "The identifier mapping is kept separately in the answer key, which must "
            "not be shared with reviewers. Complete one reviewer_assessment per case."
        ),
        "review_protocol": REVIEW_PROTOCOL,
        "cases": blinded_cases,
    }
    _assert_blinded_package_leaks_nothing(package)
    return package


def _assert_blinded_package_leaks_nothing(package: dict[str, Any]) -> None:
    """Structural guard: no authored answer material may appear in the blinded copy.

    Checks the actual leaked values — authored expectations, successors, author
    rationales, scenario identifiers and outcome-hinting fixture names/notes —
    against the package metadata (Terraform content is raw reviewer material and
    is not substring-checked). Also pins the exact blinded case structure so no
    answer-bearing field can be added silently."""
    allowed_case_keys = {"blind_id", "instruction", "obligation", "baseline_tf", "candidate_tf", "reviewer_assessment"}
    # Authored answer material that must not appear anywhere in the blinded copy.
    # Authored successor *values* are excluded from the substring sweep because a
    # successor address can legitimately coincide with the obligation's
    # protected_asset (reviewer material); the structural case-key check above is
    # what guarantees no authored successor claim is carried.
    forbidden_values: list[str] = []
    for case in CASES:
        scenario = SCENARIOS[case["scenario_id"]]
        forbidden_values += [
            case["scenario_id"], scenario["id"], scenario["name"], scenario.get("notes", ""),
            case["rationale"], case["expected_outcome"],
        ]
    for case in package["cases"]:
        assert set(case) == allowed_case_keys, f"blinded case has unexpected fields: {sorted(set(case) - allowed_case_keys)}"
        assert case["reviewer_assessment"] == {field: "" for field in _BLINDED_REVIEWER_FIELDS}, "reviewer assessment fields must be blank"
    blob = json.dumps(
        {k: v for k, v in package.items() if k != "cases"},
        sort_keys=True,
    ).lower()
    for case in package["cases"]:
        blob += json.dumps(
            {k: v for k, v in case.items() if k not in ("baseline_tf", "candidate_tf", "reviewer_assessment")},
            sort_keys=True,
        ).lower()
    for value in forbidden_values:
        if value:
            assert value.lower() not in blob, f"blinded package leaks authored material: {value[:60]!r}"


def generate_blinded_answer_key() -> dict[str, Any]:
    """Separate answer key for the blinded reviewer copy.

    Reviewers must receive only ``generate_blinded_review_package`` output; this
    mapping (and the authored expectations it reveals) stays in a separate file
    that is never part of the blinded package."""
    validate_dataset()
    mapping: dict[str, dict[str, Any]] = {}
    for blind_id, case in zip(blinded_case_ids(), reversed(CASES)):
        mapping[blind_id] = {
            "scenario_id": case["scenario_id"],
            "expected_successor": case["expected_successor"],
            "expected_outcome": case["expected_outcome"],
            "author_rationale": case["rationale"],
            "review_status": case["review_status"],
        }
    return {
        "dataset_id": DATASET_ID,
        "blinded_dataset_id": f"{DATASET_ID}-blinded",
        "warning": "REVIEWERS MUST NOT RECEIVE THIS FILE: it maps blinded cases to dataset scenarios and authored answers.",
        "mapping": mapping,
    }


def independent_moved_only(baseline_files: dict[str, str], candidate_files: dict[str, str], obligation: dict[str, Any]) -> dict[str, Any]:
    """Tiny, transparent comparator: explicit moved{} evidence only.

    It deliberately does not parse HCL or use SABLE parser, correspondence, or
    authorization code. A unique move predicts PRESERVED; all other cases UNKNOWN.
    It cannot identify regressions and must not be described as a full security
    baseline.
    """
    del baseline_files  # This comparator only consumes the declared source address.
    source = re.escape(obligation["protected_asset"])
    targets = re.findall(
        rf"(?ms)\bmoved\s*\{{[^}}]*\bfrom\s*=\s*{source}\b[^}}]*\bto\s*=\s*([\w.\-]+)",
        "\n".join(candidate_files.values()),
    )
    targets = list(dict.fromkeys(targets))
    if len(targets) == 1:
        return {"verdict": "PRESERVED", "successor": targets[0], "reason": "Exactly one explicit moved block; policy and authorization are not checked."}
    return {"verdict": "UNKNOWN", "successor": None, "reason": "No unique explicit moved-block target; policy and authorization are not checked."}


def _confusion_metrics(rows: list[dict[str, Any]], expected_key: str, predicted_key: str) -> dict[str, Any]:
    labels = {"PRESERVED", "REGRESSED", "UNKNOWN"}
    matrix = {actual: {predicted: 0 for predicted in labels} for actual in labels}
    for row in rows:
        matrix[row[expected_key]][row[predicted_key]] += 1
    regressed = sum(matrix["REGRESSED"].values())
    preserved = sum(matrix["PRESERVED"].values())
    return {
        "n": len(rows), "confusion": matrix,
        "false_safe_rate": matrix["REGRESSED"]["PRESERVED"] / regressed if regressed else None,
        "regression_recall": matrix["REGRESSED"]["REGRESSED"] / regressed if regressed else None,
        "false_regression_rate": matrix["PRESERVED"]["REGRESSED"] / preserved if preserved else None,
        "unknown_rate": sum(matrix[a]["UNKNOWN"] for a in labels) / len(rows) if rows else None,
    }


def _metric_status(rows: list[dict[str, Any]], prediction_key: str) -> dict[str, Any]:
    """Metric gate: excludes everything that is not an independent-human attestation.

    This is enforced at the metric boundary even if a caller bypasses
    ``validate_dataset``: author-review and AI-assisted evidence can never feed
    metrics because they are excluded alongside UNREVIEWED cases.
    """
    if not rows or any(
        case["review_status"] != "REVIEWED" or case.get("evidence_tier") != "independent_human_review"
        for case, _ in rows
    ):
        return {"status": "UNMEASURED", "reason": "Expected outcomes are not independently reviewed."}
    metric_rows = [{"expected": c["reviewed_outcome"], "predicted": r[prediction_key]} for c, r in rows]
    return {"status": "MEASURED_ON_REVIEWED_SET", **_confusion_metrics(metric_rows, "expected", "predicted")}


def run_experiment() -> dict[str, Any]:
    validate_dataset()
    from backend.sable.benchmark import _run_sable_engine

    case_results = []
    runtimes: dict[str, list[float]] = {"SABLE": [], "moved_only": []}
    for case in CASES:
        scenario = SCENARIOS[case["scenario_id"]]
        start = time.perf_counter()
        sable = _run_sable_engine(scenario)
        runtimes["SABLE"].append(time.perf_counter() - start)
        start = time.perf_counter()
        moved = independent_moved_only(scenario["baseline_tf"], scenario["candidate_tf"], scenario["obligation"])
        runtimes["moved_only"].append(time.perf_counter() - start)
        case_results.append({
            "scenario_id": case["scenario_id"],
            "authored_expectation": {k: case[k] for k in ("expected_successor", "expected_outcome", "rationale")},
            "independent_review": {k: case[k] for k in ("review_status", "evidence_tier", "reviewer", "reviewed_at", "reviewed_successor", "reviewed_outcome", "reviewed_rationale")},
            "sable": {"verdict": sable["verdict"], "successor": sable.get("details", {}).get("successor"), "reason": sable.get("reason")},
            "moved_only": moved,
        })

    all_reviewed = all(c["review_status"] == "REVIEWED" for c in CASES)
    sable_rows = [(c, {"prediction": x["sable"]["verdict"]}) for c, x in zip(CASES, case_results)]
    moved_rows = [(c, {"prediction": x["moved_only"]["verdict"]}) for c, x in zip(CASES, case_results)]
    return {
        "dataset": {"id": DATASET_ID, "provenance": DATASET_PROVENANCE, "case_count": len(CASES), "reviewed_count": sum(c["review_status"] == "REVIEWED" for c in CASES)},
        "baseline": {"id": "moved_only_v1", "description": "Unique explicit moved-block target predicts PRESERVED; otherwise UNKNOWN. No policy/security check; cannot predict REGRESSED.", "independent_of_sable_core": True},
        "comparator_taxonomy": COMPARATOR_TAXONOMY,
        "review_protocol": REVIEW_PROTOCOL,
        "metrics": {
            "sable_outcomes": _metric_status(sable_rows, "prediction"),
            "moved_only_outcomes": _metric_status(moved_rows, "prediction"),
            "correspondence_accuracy": {"status": "UNMEASURED", "reason": "No independently reviewed successor annotations."},
            "runtime_seconds_total": {"status": "DIAGNOSTIC_ONLY", "values": {k: round(sum(v), 6) for k, v in runtimes.items()}, "reason": "Single local run; not a controlled performance experiment."},
        },
        "cases": case_results,
    }


if __name__ == "__main__":
    import argparse
    import json
    from pathlib import Path

    parser = argparse.ArgumentParser(description="Run the provenance-aware SABLE research evaluation.")
    parser.add_argument("--output", type=Path, help="Write JSON here; stdout is used if omitted.")
    parser.add_argument("--package", action="store_true", help="Generate self-contained review package.")
    parser.add_argument("--blinded-package", type=Path, help="Write the blinded reviewer package JSON here.")
    parser.add_argument("--blinded-answer-key", type=Path, help="Write the blinded answer key JSON here (reviewers must not receive it).")
    parser.add_argument("--check-readiness", action="store_true", help="Check review attestation status.")
    args = parser.parse_args()

    if args.blinded_package:
        args.blinded_package.write_text(json.dumps(generate_blinded_review_package(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.blinded_answer_key:
        args.blinded_answer_key.write_text(json.dumps(generate_blinded_answer_key(), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.blinded_package or args.blinded_answer_key:
        if not (args.check_readiness or args.package):
            raise SystemExit(0)

    if args.check_readiness:
        reviewed = [c for c in CASES if c["review_status"] == "REVIEWED"]
        unreviewed = [c for c in CASES if c["review_status"] != "REVIEWED"]
        print(f"Dataset '{DATASET_ID}': {len(reviewed)}/{len(CASES)} cases reviewed.")
        if unreviewed:
            print("Unreviewed cases:")
            for c in unreviewed:
                print(f"  - {c['scenario_id']}: {c['rationale']}")
            print("Status: UNMEASURED (awaiting independent expert review)")
    elif args.package:
        pkg = generate_review_package()
        payload = json.dumps(pkg, indent=2, sort_keys=True)
        if args.output:
            args.output.write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
    else:
        payload = json.dumps(run_experiment(), indent=2, sort_keys=True)
        if args.output:
            args.output.write_text(payload + "\n", encoding="utf-8")
        else:
            print(payload)
