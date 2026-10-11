import pytest
from pathlib import Path
from backend.satra.decision_engine import DecisionEngine
from backend.satra.repair import propose


def test_decision_engine_accepts_clean_run():
    engine = DecisionEngine()
    context = {
        "allowlist_valid": True,
        "manifest_valid": True,
        "ast_localized": True,
        "regions": [{"file": "app/main.py"}],
        "contract": {"rule_id": "AUTHZ.IDOR.001", "expected_status": 403},
        "baseline_execution": {"available": True, "exit_code": 0, "passed": 5},
        "oracle": {"accepted": True, "valid_counterfactual": True, "diagnosis": "PRESERVED_WITHIN_MODEL"},
        "repeat_execution": {"available": True, "exit_code": 0},
    }
    evaluation = engine.evaluate_gates(context)
    assert evaluation["final_verdict"] == "ACCEPT"
    assert evaluation["gates_passed"] == 7


def test_decision_engine_blocks_on_weakened_oracle():
    engine = DecisionEngine()
    context = {
        "allowlist_valid": True,
        "manifest_valid": True,
        "ast_localized": True,
        "contract": {"rule_id": "AUTHZ.IDOR.001"},
        "baseline_execution": {"available": True, "exit_code": 0, "passed": 5},
        "oracle": {"accepted": False, "valid_counterfactual": True, "diagnosis": "ORACLE_WEAKENED"},
        "repeat_execution": {"available": True, "exit_code": 0},
    }
    evaluation = engine.evaluate_gates(context)
    assert evaluation["final_verdict"] == "BLOCK"
    assert not evaluation["gate_results"]["gate6_oracle_discrimination"]["passed"]


def test_decision_engine_evidence_bundle(tmp_path):
    engine = DecisionEngine()
    eval_data = {"final_verdict": "ACCEPT", "gates_passed": 7, "gates_total": 7}
    bundle = engine.generate_evidence_bundle("run-1234", eval_data, tmp_path)
    assert bundle.exists()
    assert "run-1234" in bundle.read_text()


def test_repair_propose_on_ownership_vulnerability(tmp_path):
    # Setup mock worktree
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    sec_file = app_dir / "security.py"
    sec_file.write_text("def can_access_invoice(user, invoice):\n    return True\n")

    evidence = {
        "details": {
            "contract": {"rule_id": "AUTHZ.IDOR.001"},
            "oracle": {"accepted": True}
        }
    }
    changed = propose(tmp_path, evidence)
    assert "app/security.py" in changed
    new_text = sec_file.read_text()
    assert "user['role'] == 'admin' or invoice['owner_id'] == user['id']" in new_text

