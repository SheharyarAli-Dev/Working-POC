import pytest
from pathlib import Path
from backend.satra.contract_runner import (
    select_tests_for_regions,
    trusted_suite,
    TRUST_DIR,
)
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


def test_rts_selection_known_regions():
    regions = [{"families": ["AUTHZ.IDOR.001"], "function": "can_access_invoice"}]
    selected, selection_map = select_tests_for_regions(regions)
    assert "test_authz_idor" in selected
    assert selection_map["test_authz_idor"]["selected"] is True
    # Non-impacted test families must be pruned in selection map
    for stem, info in selection_map.items():
        if stem != "test_authz_idor":
            assert info["selected"] is False
            assert "Pruned" in info["reason"]


def test_rts_safe_pruning_evidence_model(monkeypatch, tmp_path):
    # Mock run_contract_test to simulate execution of selected test
    executed_stems = []

    def mock_run_contract_test(worktree_dir, test_rel, out_dir, timeout=60):
        stem = Path(test_rel).stem
        executed_stems.append(stem)
        return {
            "verdict": "SATISFIED",
            "reason": "Security obligations satisfied",
            "exit_code": 0,
            "tests": [{"name": "test_pass", "status": "PASS"}],
            "passed": 1,
            "failed": 0,
            "sandboxed": True,
            "mode": "docker-hardened",
        }

    monkeypatch.setattr("backend.satra.contract_runner.run_contract_test", mock_run_contract_test)

    target_stems = {"test_authz_idor"}
    result = trusted_suite(tmp_path, tmp_path / "out", target_families=target_stems)

    # 1. Executed stem must be recorded properly
    assert "test_authz_idor" in executed_stems
    assert result["families"]["test_authz_idor"]["verdict"] == "SATISFIED"
    assert result["families"]["test_authz_idor"]["sandboxed"] is True
    assert result["families"]["test_authz_idor"]["pruned"] is False

    # 2. Pruned stems must NOT claim SATISFIED or sandboxed execution
    for stem, fam in result["families"].items():
        if stem != "test_authz_idor":
            assert fam["verdict"] in ("NOT_RUN", "PRUNED"), f"Expected NOT_RUN/PRUNED, got {fam['verdict']}"
            assert fam["status"] == "PRUNED"
            assert fam["sandboxed"] is False, f"Pruned family {stem} must NOT claim sandboxed=True"
            assert fam["pruned"] is True
            assert fam["passed"] == 0
            assert fam["failed"] == 0

    assert result["passed"] == 1
    assert result["failed"] == 0
    assert result["skipped"] > 0
    assert result["exit_code"] == 0
    assert result["backend"] == "docker"


def test_rts_unknown_regions_fails_safe_to_full_suite():
    regions = [{"file": "unknown.py", "function": "mystery_func", "families": []}]
    all_stems = {f.stem for f in (TRUST_DIR / "trusted_tests").glob("test_*.py")}
    selected, selection_map = select_tests_for_regions(regions)
    # Fail-safe must select all test stems when regions cannot be mapped
    assert selected == all_stems
    assert all(info["selected"] for info in selection_map.values())


def test_rts_empty_selection_fails_safe_to_full_suite():
    all_stems = {f.stem for f in (TRUST_DIR / "trusted_tests").glob("test_*.py")}
    selected_empty, _ = select_tests_for_regions([])
    assert selected_empty == all_stems

    selected_none, _ = select_tests_for_regions(None)
    assert selected_none == all_stems


def test_rts_missing_or_unmapped_family_mapping_fails_safe():
    regions = [{"families": ["UNMAPPED.VULN.999"], "function": "some_func"}]
    all_stems = {f.stem for f in (TRUST_DIR / "trusted_tests").glob("test_*.py")}
    selected, _ = select_tests_for_regions(regions)
    # Since UNMAPPED.VULN.999 is not in FAMILY_TO_TEST and no routes match,
    # it must fall back to the full suite
    assert selected == all_stems


def test_trusted_suite_empty_selection_cannot_satisfy_verification(tmp_path):
    # If target_families is an empty set (no families selected at all)
    result = trusted_suite(tmp_path, tmp_path / "out", target_families=set())
    assert result["available"] is False
    assert result["exit_code"] == 1
    assert result["passed"] == 0
    assert result["backend"] == "none"
    assert "No test families executed" in result["reason"]
    # All families must be NOT_RUN/PRUNED and sandboxed=False
    for stem, fam in result["families"].items():
        assert fam["verdict"] in ("NOT_RUN", "PRUNED")
        assert fam["sandboxed"] is False


def test_trusted_suite_failed_selected_test_blocks_assurance(monkeypatch, tmp_path):
    def mock_run_contract_failing(worktree_dir, test_rel, out_dir, timeout=60):
        return {
            "verdict": "VIOLATED",
            "reason": "Security obligation violated by target candidate code",
            "exit_code": 1,
            "tests": [{"name": "test_authz_fail", "status": "FAIL"}],
            "passed": 0,
            "failed": 1,
            "sandboxed": True,
            "mode": "docker-hardened",
        }

    monkeypatch.setattr("backend.satra.contract_runner.run_contract_test", mock_run_contract_failing)
    result = trusted_suite(tmp_path, tmp_path / "out", target_families={"test_authz_idor"})
    assert result["exit_code"] == 1
    assert result["failed"] >= 1
    assert result["families"]["test_authz_idor"]["verdict"] == "VIOLATED"

    # Evaluated at DecisionEngine
    engine = DecisionEngine()
    context = {
        "allowlist_valid": True,
        "manifest_valid": True,
        "ast_localized": True,
        "regions": [{"file": "app/main.py"}],
        "contract": {"rule_id": "AUTHZ.IDOR.001"},
        "baseline_execution": {"available": True, "exit_code": 0, "passed": 5},
        "candidate_execution": result,
        "oracle": {"accepted": True, "valid_counterfactual": True, "diagnosis": "PRESERVED_WITHIN_MODEL"},
        "repeat_execution": result,
    }
    evaluation = engine.evaluate_gates(context)
    assert evaluation["final_verdict"] != "ACCEPT", "Failed test execution must never produce ACCEPT"


def test_decision_engine_rejects_unexecuted_candidate_tests():
    engine = DecisionEngine()
    # Candidate with 0 passed tests (unexecuted)
    unexecuted_result = {
        "available": False,
        "exit_code": 1,
        "passed": 0,
        "failed": 0,
        "skipped": 5,
        "reason": "No test families executed",
    }
    context = {
        "allowlist_valid": True,
        "manifest_valid": True,
        "ast_localized": True,
        "regions": [{"file": "app/main.py"}],
        "contract": {"rule_id": "AUTHZ.IDOR.001"},
        "baseline_execution": {"available": True, "exit_code": 0, "passed": 5},
        "candidate_execution": unexecuted_result,
        "oracle": {"accepted": True, "valid_counterfactual": True, "diagnosis": "PRESERVED_WITHIN_MODEL"},
        "repeat_execution": {"available": True, "exit_code": 0, "passed": 5},
    }
    evaluation = engine.evaluate_gates(context)
    assert evaluation["final_verdict"] != "ACCEPT", "Unexecuted candidate tests must not produce ACCEPT"

