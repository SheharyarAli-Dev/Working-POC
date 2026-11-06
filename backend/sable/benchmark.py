"""
SABLE Benchmark Runner.

Runs all scenarios through SABLE and each baseline (B0-B4), computes metrics,
ablations and kill tests. NEVER imports ground_truth directly — uses the loader.

The analysis engine import isolation is enforced by tests/test_sable_isolation.py.
"""
from __future__ import annotations
import json
import time
import hashlib
import tempfile
from pathlib import Path
from typing import Callable

from backend.sable.fixtures.scenarios import SCENARIOS
from backend.sable.baselines import run_b0, run_b1, run_b2, run_b3, run_b4
from backend.sable.authorization import evaluate_authorization
from backend.sable.hcl_parser import parse as hcl_parse
from backend.sable.correspondence import rank, choose


# Load ground truth via loader (only here, never in engine modules)
def _load_gt() -> dict[str, str]:
    from backend.sable.fixtures.ground_truth import load_ground_truth
    return load_ground_truth()


def _load_models(baseline_tf: dict, candidate_tf: dict) -> tuple[dict, dict]:
    def write_and_parse(tf_files: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, content in tf_files.items():
                fpath = Path(tmpdir) / fname
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(content, encoding="utf-8")
            try:
                return hcl_parse(tmpdir)
            except Exception as e:
                return {"resources": {}, "moves": [], "outputs": {}, "errors": [str(e)],
                        "graph": {"nodes": [], "edges": []}}
    return write_and_parse(baseline_tf), write_and_parse(candidate_tf)


def _run_sable_engine(scenario: dict, ablation_flags: dict | None = None) -> dict:
    """Run the full SABLE engine on a scenario. Returns verdict + details."""
    from backend.sable.hcl_parser import parse as hcl_parse

    baseline_tf = scenario["baseline_tf"]
    candidate_tf = scenario["candidate_tf"]
    obligation = scenario["obligation"]
    principal = obligation["principal"]
    asset = obligation["protected_asset"]
    actions = obligation["actions"]
    config_threshold = 6
    config_margin = 3

    ablation = ablation_flags or {}

    bm, cm = _load_models(baseline_tf, candidate_tf)

    # Baseline predicate
    b_auth = evaluate_authorization(bm, principal, asset, actions)
    if not b_auth.known or not b_auth.holds:
        return {"verdict": "UNKNOWN", "reason": "Baseline predicate fails", "details": {}}

    # Correspondence
    use_moves = not ablation.get("no_move_evidence")
    use_dep = not ablation.get("no_dependency_context")
    use_policy_rel = not ablation.get("no_policy_relationship")
    force_match = ablation.get("no_ambiguity_handling")

    if asset not in bm["resources"]:
        return {"verdict": "UNKNOWN", "reason": f"Asset '{asset}' not in baseline", "details": {}}

    hyp, conflicts = rank(bm, cm, asset)

    # Ablate move evidence
    if not use_moves:
        for h in hyp:
            h["signals"] = [s for s in h["signals"] if s["signal"] != "explicit moved block"]
            h["score"] = sum(s["weight"] for s in h["signals"])
        hyp.sort(key=lambda x: (-x["score"], x["address"]))
        conflicts = []

    # Ablate dependency context
    if not use_dep:
        for h in hyp:
            h["signals"] = [s for s in h["signals"]
                            if s["signal"] not in ("same exported application reference",
                                                    "module output preserves application reference")]
            h["score"] = sum(s["weight"] for s in h["signals"])
        hyp.sort(key=lambda x: (-x["score"], x["address"]))

    # Ablation: no correspondence (B0-style)
    if ablation.get("no_correspondence"):
        c_auth = evaluate_authorization(cm, principal, asset, actions)
        verdict = "PRESERVED" if c_auth.holds else ("UNKNOWN" if not c_auth.known else "REGRESSED")
        return {"verdict": verdict, "reason": c_auth.reason, "details": {"ablation": "no_correspondence"}}

    margin = config_margin if not force_match else 0
    target, why = choose(hyp, conflicts, config_threshold, margin)

    if not target:
        return {"verdict": "UNKNOWN", "reason": why, "details": {"hypotheses": hyp[:5]}}

    # Ablation: no obligation projection
    if ablation.get("no_obligation_projection"):
        return {"verdict": "PRESERVED", "reason": "Correspondence only (no projection)", "details": {"successor": target}}

    # Authorization evaluation on successor
    c_auth = evaluate_authorization(cm, principal, target, actions)

    if not c_auth.known:
        verdict = "UNKNOWN"
    elif c_auth.holds:
        verdict = "PRESERVED"
    else:
        verdict = "REGRESSED"

    return {
        "verdict": verdict,
        "reason": c_auth.reason,
        "details": {
            "successor": target,
            "hypotheses": hyp[:5],
            "authorization": {
                "known": c_auth.known,
                "holds": c_auth.holds,
                "widening": c_auth.widening,
                "weakening": c_auth.weakening,
                "misbinding": c_auth.misbinding,
                "actual_actions": c_auth.actual_actions,
            }
        }
    }


def _classify(predicted: str, actual: str) -> str:
    if predicted == actual:
        if actual == "PRESERVED":
            return "TP"   # True preserved
        if actual == "REGRESSED":
            return "TP"
        return "TN"       # True UNKNOWN
    if predicted == "PRESERVED" and actual == "REGRESSED":
        return "FP_SAFE"  # False safe (dangerous)
    if predicted == "REGRESSED" and actual == "PRESERVED":
        return "FP_REG"   # False regression
    if predicted == "UNKNOWN":
        return "FN_UNKNOWN"  # Sent to UNKNOWN (conservative)
    return "OTHER"


def _compute_metrics(results: list[dict], gt: dict[str, str]) -> dict:
    total = len(results)
    if total == 0:
        return {}

    n_preserved = sum(1 for r in results if gt.get(r["scenario_id"]) == "PRESERVED")
    n_regressed = sum(1 for r in results if gt.get(r["scenario_id"]) == "REGRESSED")
    n_unknown_gt = sum(1 for r in results if gt.get(r["scenario_id"]) == "UNKNOWN")

    false_safe = sum(1 for r in results
                     if r["verdict"] == "PRESERVED" and gt.get(r["scenario_id"]) == "REGRESSED")
    recalled = sum(1 for r in results
                   if r["verdict"] == "REGRESSED" and gt.get(r["scenario_id"]) == "REGRESSED")
    false_reg = sum(1 for r in results
                    if r["verdict"] == "REGRESSED" and gt.get(r["scenario_id"]) == "PRESERVED")
    unknown_pred = sum(1 for r in results if r["verdict"] == "UNKNOWN")
    unknown_correct = sum(1 for r in results
                           if r["verdict"] == "UNKNOWN" and gt.get(r["scenario_id"]) == "UNKNOWN")

    false_safe_rate = false_safe / n_regressed if n_regressed else 0.0
    regression_recall = recalled / n_regressed if n_regressed else 0.0
    false_reg_rate = false_reg / n_preserved if n_preserved else 0.0
    unknown_precision = unknown_correct / unknown_pred if unknown_pred else 0.0
    correct_count = sum(1 for r in results if r.get("correct") is True)

    return {
        "n": total,
        "n_preserved": n_preserved,
        "n_regressed": n_regressed,
        "n_unknown_gt": n_unknown_gt,
        "verdict_accuracy": round(correct_count / total, 3),
        "verdict_correct_count": correct_count,
        "false_safe_rate": round(false_safe_rate, 3),
        "false_safe_count": false_safe,
        "regression_recall": round(regression_recall, 3),
        "recall_count": recalled,
        "false_regression_rate": round(false_reg_rate, 3),
        "false_regression_count": false_reg,
        "correspondence_accuracy": None,
        "unknown_precision": round(unknown_precision, 3),
        "unknown_count": unknown_pred,
        "evidence_completeness": None,
        "small_sample_note": f"Synthetic, authored-in-house evaluation set (n={total}); descriptive results do not establish generality.",
    }


def _compute_kill_tests(sable_metrics: dict, b4_metrics: dict, b0_metrics: dict,
                         b2_results: list[dict], gt: dict[str, str],
                         runtime_s: float, config: dict) -> dict:
    """Compute K1-K6 from real benchmark results."""
    th = config.get("kill_test_thresholds", {})

    # K1: Strong baseline equivalence — does B4 match SABLE on false-safe rate?
    k1_fsr_delta = abs(sable_metrics.get("false_safe_rate", 0) - b4_metrics.get("false_safe_rate", 0))
    k1_recall_delta = b4_metrics.get("regression_recall", 0) - sable_metrics.get("regression_recall", 0)
    k1_threshold_fsr = th.get("K1_false_safe_rate_delta_max", 0.05)
    k1_threshold_recall = th.get("K1_recall_delta_min", 0.0)
    k1_pass = False

    # K2: Address evidence suffices — does B2 solve hard cases?
    hard_cases = [s_id for s_id, s in SCENARIOS.items() if s["is_hard_case"]]
    b2_hard_correct = sum(1 for r in b2_results
                           if r["scenario_id"] in hard_cases and r["verdict"] == gt.get(r["scenario_id"]))
    b2_hard_recall = b2_hard_correct / len(hard_cases) if hard_cases else 0
    k2_threshold = th.get("K2_hard_case_recall_b2_max", 0.60)
    k2_pass = b2_hard_recall < k2_threshold  # B2 should NOT solve most hard cases

    # K3: No hard cases exist (is there meaningful ambiguity?)
    k3_threshold = th.get("K3_ambiguity_fraction_min", 0.10)
    hard_fraction = len(hard_cases) / max(len(SCENARIOS), 1)
    k3_pass = hard_fraction >= k3_threshold

    # K4: UNKNOWN escape hatch — does SABLE send hard cases to UNKNOWN without better safety?
    sable_hard_unknown = sum(1 for r in [r for r in sable_metrics.get("_results", [])
                                          if r["scenario_id"] in hard_cases]
                              if r["verdict"] == "UNKNOWN")
    k4_threshold = th.get("K4_unknown_rate_hard_cases_min", 0.50)
    k4_rate = sable_hard_unknown / len(hard_cases) if hard_cases else 0
    k4_pass = k4_rate >= k4_threshold or sable_metrics.get("false_safe_rate", 1) <= 0.05

    # K5: Security predicate is trivial — does B0 resolve everything?
    b0_fsr = b0_metrics.get("false_safe_rate", 1.0)
    k5_threshold = th.get("K5_b0_false_safe_rate_max", 0.15)
    b0_regression_recall = b0_metrics.get("regression_recall", 0)
    k5_pass = b0_fsr > k5_threshold or b0_regression_recall < 1.0

    # K6: Feasibility — runtime within window?
    k6_threshold = th.get("K6_runtime_seconds_max", 60)
    k6_pass = runtime_s <= k6_threshold

    def kresult(kid, pass_: bool, measured: dict, threshold: dict | str, consequence: str) -> dict:
        status = "PASS" if pass_ else "FAIL"
        return {
            "id": kid,
            "status": status,
            "measured": measured,
            "threshold": threshold,
            "consequence": consequence if not pass_ else "No contribution claim withdrawn."
        }

    results = {
        "K1": kresult("K1", k1_pass,
                       {"fsr_delta": round(k1_fsr_delta, 3), "recall_delta": round(k1_recall_delta, 3)},
                       f"fsr_delta ≤ {k1_threshold_fsr}",
                       "SABLE and B4 are equivalent; contribution claim withdrawn or narrowed."),
        "K2": kresult("K2", k2_pass,
                       {"b2_hard_recall": round(b2_hard_recall, 3), "n_hard": len(hard_cases)},
                       f"b2 recall on hard cases < {k2_threshold}",
                       "Address-only evidence (B2) already solves hard cases; structural analysis adds nothing."),
        "K3": kresult("K3", k3_pass,
                       {"hard_fraction": round(hard_fraction, 3), "n_hard": len(hard_cases)},
                       f"hard fraction ≥ {k3_threshold}",
                       "No meaningful attribution ambiguity in benchmark; hard-case claim unsupported."),
        "K4": kresult("K4", k4_pass,
                       {"unknown_rate_on_hard": round(k4_rate, 3)},
                       f"unknown rate on hard ≥ {k4_threshold}",
                       "SABLE escapes to UNKNOWN on hard cases without improving safety; UNKNOWN claim unsupported."),
        "K5": kresult("K5", k5_pass,
                       {"b0_false_safe_rate": round(b0_fsr, 3)},
                       f"B0 fsr > {k5_threshold}",
                       "B0 alone resolves all regressions; security predicate is trivial; SABLE adds no value."),
        "K6": kresult("K6", k6_pass,
                       {"runtime_s": round(runtime_s, 1)},
                       f"runtime ≤ {k6_threshold}s",
                       "Runtime infeasible for practical use."),
    }
    results["K1"]["status"] = "UNMEASURED"
    results["K1"]["measured"]["comparable_evidence_quality"] = False
    results["K1"]["measured"]["independent_b4"] = False
    results["K1"]["consequence"] = (
        "Cannot adjudicate equivalence: evidence quality is unmeasured and B4 reuses SABLE's core code."
    )
    results["K6"]["status"] = "UNMEASURED"
    results["K6"]["consequence"] = (
        "The measured wall time covers the entire batch and ablations, not per-case overhead beyond an independent B4."
    )
    results["K5"]["measured"]["b0_regression_recall"] = round(b0_regression_recall, 3)
    results["K5"]["threshold"] = f"B0 false_safe_rate > {k5_threshold} OR regression_recall < 1.0"
    return results


ABLATION_FLAGS = {
    "no_move_evidence": {"no_move_evidence": True},
    "no_dependency_context": {"no_dependency_context": True},
    "no_policy_relationship": {"no_policy_relationship": True},
    "no_ambiguity_handling": {"no_ambiguity_handling": True},
    "no_obligation_projection": {"no_obligation_projection": True},
    "no_correspondence": {"no_correspondence": True},
}


def run_benchmark(emit: Callable | None = None) -> dict:
    """
    Run all scenarios through SABLE + B0-B4 + all ablations.
    emit: optional callback for SSE progress: emit(type, payload)
    Returns full benchmark results.
    """
    import json
    from pathlib import Path

    config_path = Path(__file__).parent.parent / "sable_config.json"
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    gt = _load_gt()

    start = time.time()
    systems = {"SABLE": [], "B0": [], "B1": [], "B2": [], "B3": [], "B4": []}
    for abl_name in ABLATION_FLAGS:
        systems[f"SABLE_no_{abl_name.replace('no_', '')}"] = []

    scenario_list = list(SCENARIOS.values())
    total = len(scenario_list)

    for i, scenario in enumerate(scenario_list):
        sid = scenario["id"]
        obligation = scenario["obligation"]
        baseline_tf = scenario["baseline_tf"]
        candidate_tf = scenario["candidate_tf"]

        if emit:
            emit("benchmark.progress", {
                "scenario": sid,
                "index": i + 1,
                "total": total,
                "pct": round((i + 1) / total * 100, 1)
            })

        # Run all baselines
        b0 = run_b0(baseline_tf, candidate_tf, obligation)
        b1 = run_b1(baseline_tf, candidate_tf, obligation)
        b2 = run_b2(baseline_tf, candidate_tf, obligation)
        b3 = run_b3(baseline_tf, candidate_tf, obligation)
        b4 = run_b4(baseline_tf, candidate_tf, obligation)

        # Run SABLE engine
        sable = _run_sable_engine(scenario)

        # Determine successor correctness
        gt_label = gt.get(sid)
        for sys_name, result, b_result in [
            ("SABLE", sable, None),
            ("B0", {"verdict": b0["verdict"]}, b0),
            ("B1", {"verdict": b1["verdict"]}, b1),
            ("B2", {"verdict": b2["verdict"]}, b2),
            ("B3", {"verdict": b3["verdict"]}, b3),
            ("B4", {"verdict": b4["verdict"]}, b4),
        ]:
            systems[sys_name].append({
                "scenario_id": sid,
                "verdict": result["verdict"],
                "gt": gt_label,
                "correct": result["verdict"] == gt_label,
            })

        # Run ablations
        for abl_name, flags in ABLATION_FLAGS.items():
            abl_result = _run_sable_engine(scenario, ablation_flags=flags)
            sys_key = f"SABLE_no_{abl_name.replace('no_', '')}"
            systems[sys_key].append({
                "scenario_id": sid,
                "verdict": abl_result["verdict"],
                "gt": gt_label,
                "correct": abl_result["verdict"] == gt_label,
            })

    runtime_s = time.time() - start

    # Compute metrics for each system
    metrics = {}
    for sys_name, results in systems.items():
        m = _compute_metrics(results, gt)
        metrics[sys_name] = m

    # Attach raw results for K4 computation
    metrics["SABLE"]["_results"] = systems["SABLE"]

    # Kill tests
    kill_tests = _compute_kill_tests(
        metrics["SABLE"], metrics["B4"], metrics["B0"],
        systems["B2"], gt, runtime_s, config
    )
    # Clean internal field
    metrics["SABLE"].pop("_results", None)

    # Ablation deltas (change vs full SABLE)
    ablation_deltas = {}
    for abl_name in ABLATION_FLAGS:
        sys_key = f"SABLE_no_{abl_name.replace('no_', '')}"
        abl_m = metrics.get(sys_key, {})
        ablation_deltas[abl_name] = {
            "false_safe_rate_delta": round(
                abl_m.get("false_safe_rate", 0) - metrics["SABLE"].get("false_safe_rate", 0), 3),
            "recall_delta": round(
                abl_m.get("regression_recall", 0) - metrics["SABLE"].get("regression_recall", 0), 3),
            "full_fsr": metrics["SABLE"].get("false_safe_rate", 0),
            "ablated_fsr": abl_m.get("false_safe_rate", 0),
        }

    # Per-scenario matrix
    scenario_matrix = {}
    for scenario in scenario_list:
        sid = scenario["id"]
        scenario_matrix[sid] = {
            sys_name: next((r["verdict"] for r in results if r["scenario_id"] == sid), "N/A")
            for sys_name, results in systems.items()
            if not sys_name.startswith("SABLE_no_")
        }

    # Confusion matrices per system
    confusion = {}
    for sys_name in ["SABLE", "B0", "B1", "B2", "B3", "B4"]:
        results = systems[sys_name]
        cm = {"PRESERVED": {"PRESERVED": 0, "REGRESSED": 0, "UNKNOWN": 0},
              "REGRESSED": {"PRESERVED": 0, "REGRESSED": 0, "UNKNOWN": 0},
              "UNKNOWN": {"PRESERVED": 0, "REGRESSED": 0, "UNKNOWN": 0}}
        for r in results:
            gt_lbl = r["gt"]
            pred = r["verdict"]
            if gt_lbl in cm and pred in cm[gt_lbl]:
                cm[gt_lbl][pred] += 1
        confusion[sys_name] = cm

    # B4 reduced strength flag
    b4_reduced = any(b4.get("reduced_strength") for b4 in [run_b4(s["baseline_tf"], s["candidate_tf"], s["obligation"]) for s in [scenario_list[0]]])

    return {
        "total_scenarios": total,
        "runtime_s": round(runtime_s, 2),
        "ground_truth_hidden_note": "Ground truth hidden from SABLE during evaluation. Labels loaded only by benchmark evaluator.",
        "metrics": {k: v for k, v in metrics.items() if not k.startswith("SABLE_no_")},
        "ablation_metrics": {k: v for k, v in metrics.items() if k.startswith("SABLE_no_")},
        "ablation_deltas": ablation_deltas,
        "kill_tests": kill_tests,
        "scenario_matrix": scenario_matrix,
        "confusion_matrices": confusion,
        "b4_reduced_strength": b4_reduced,
        "b4_reduced_strength_note": "Reduced-strength baseline: Checkov/Trivy unavailable. Results use built-in approximations." if b4_reduced else None,
        "green_light_note": "Green numbers mean the problem is testable, not that a SABLE advantage has been observed.",
        "evaluation_limits_note": "Scenario labels contain verdicts only, not independently reviewed intended successors. Correspondence accuracy and evidence completeness are unmeasured. B4 reuses SABLE correspondence and authorization functions and is not independent. K1 and K6 are unmeasured: evidence comparability and per-case overhead beyond an independent B4 are not recorded.",
        "small_sample_note": f"Synthetic, authored-in-house evaluation set (n={total}); descriptive results do not establish generality.",
    }
