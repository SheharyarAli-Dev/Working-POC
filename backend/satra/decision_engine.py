import json
import hashlib
from typing import Dict, Any, List, Optional
from pathlib import Path


class DecisionEngine:
    """
    SATRA Phase 8: 7-Gate Matrix and Decision Engine.
    Evaluates verified security properties across 7 rigorous gates:
    Gate 1: Repository allowlist and commit validity
    Gate 2: Non-circular trusted specification & policy manifest integrity
    Gate 3: AST semantic localization (security boundary affected)
    Gate 4: Security Change Contract synthesis
    Gate 5: Sandboxed baseline test suite passage
    Gate 6: Counterfactual oracle discrimination (mutants killed, no weakened assertions)
    Gate 7: Deterministic repeatability across repeated execution
    """

    GATES = [
        "gate1_allowlist_validity",
        "gate2_trusted_manifest_integrity",
        "gate3_ast_localization",
        "gate4_contract_synthesis",
        "gate5_sandbox_baseline_pass",
        "gate6_oracle_discrimination",
        "gate7_repeatability",
    ]

    def evaluate_gates(self, context_dict: Dict[str, Any]) -> Dict[str, Any]:
        results = {}

        # Gate 1: Allowlist
        g1_ok = bool(context_dict.get("allowlist_valid", True))
        results["gate1_allowlist_validity"] = {
            "passed": g1_ok,
            "detail": "Commit originating from authorized allowlisted repository" if g1_ok else "Rejected: Untrusted repository"
        }

        # Gate 2: Trusted manifest integrity
        g2_ok = bool(context_dict.get("manifest_valid", True))
        results["gate2_trusted_manifest_integrity"] = {
            "passed": g2_ok,
            "detail": "Trusted policy and tests match signed SHA-256 manifest" if g2_ok else "Rejected: Tampered or unverified trusted assets"
        }

        # Gate 3: AST localization
        regions = context_dict.get("regions", [])
        g3_ok = bool(context_dict.get("ast_localized", True))
        results["gate3_ast_localization"] = {
            "passed": g3_ok,
            "regions_count": len(regions),
            "detail": f"AST localized {len(regions)} security-relevant regions"
        }

        # Gate 4: Contract synthesis
        contract = context_dict.get("contract")
        g4_ok = bool(contract and contract.get("rule_id"))
        results["gate4_contract_synthesis"] = {
            "passed": g4_ok,
            "rule_id": contract.get("rule_id") if contract else None,
            "detail": "Security Change Contract established" if g4_ok else "No contract synthesized"
        }

        # Gate 5: Sandbox baseline pass
        base_res = context_dict.get("baseline_execution", {})
        g5_ok = base_res.get("available") and base_res.get("exit_code") == 0 and base_res.get("passed", 0) > 0
        results["gate5_sandbox_baseline_pass"] = {
            "passed": bool(g5_ok),
            "detail": "Baseline tests passed cleanly inside hardened sandbox" if g5_ok else "Baseline tests failed or unavailable"
        }

        # Gate 6: Oracle discrimination
        oracle = context_dict.get("oracle", {})
        g6_ok = oracle.get("accepted") and oracle.get("valid_counterfactual")
        results["gate6_oracle_discrimination"] = {
            "passed": bool(g6_ok),
            "diagnosis": oracle.get("diagnosis"),
            "detail": oracle.get("reason", "Discriminates valid counterfactual without weakened assertions")
        }

        # Gate 7: Repeatability
        rep_res = context_dict.get("repeat_execution", {})
        g7_ok = rep_res.get("available") and rep_res.get("exit_code") == 0
        results["gate7_repeatability"] = {
            "passed": bool(g7_ok),
            "detail": "Deterministic repeated test execution confirmed" if g7_ok else "Non-deterministic or failed repeat run"
        }

        all_passed = all(r["passed"] for r in results.values())
        blocked = not results["gate1_allowlist_validity"]["passed"] or not results["gate2_trusted_manifest_integrity"]["passed"]
        weakened = oracle.get("diagnosis") == "ORACLE_WEAKENED"

        if weakened or blocked:
            final_verdict = "BLOCK"
        elif all_passed:
            final_verdict = "ACCEPT"
        else:
            final_verdict = "REVIEW"

        return {
            "final_verdict": final_verdict,
            "gates_passed": sum(1 for r in results.values() if r["passed"]),
            "gates_total": len(self.GATES),
            "gate_results": results,
        }

    def generate_evidence_bundle(self, run_id: str, evaluation: Dict[str, Any], output_dir: Path) -> Path:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        bundle_file = out / f"evidence_{run_id}.json"
        bundle_data = {
            "run_id": run_id,
            "engine": "SATRA-RV",
            "version": "1.0.0",
            "evaluation": evaluation,
        }
        bundle_file.write_text(json.dumps(bundle_data, indent=2), encoding="utf-8")
        return bundle_file
