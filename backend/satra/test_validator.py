import ast
import difflib
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from backend.satra.counterfactuals import mutate_candidate_worktree


def check_static_test_integrity(base_test_text, cand_test_text, file_name="tests/test_security.py"):
    findings = []
    base_tree = ast.parse(base_test_text) if base_test_text else None
    cand_tree = ast.parse(cand_test_text) if cand_test_text else None

    if not cand_tree:
        return findings

    base_asserts = {}
    if base_tree:
        for node in ast.walk(base_tree):
            if isinstance(node, ast.Assert):
                rendered = ast.unparse(node.test)
                base_asserts[rendered] = node.lineno

    for node in ast.walk(cand_tree):
        if isinstance(node, ast.Assert):
            rendered = ast.unparse(node.test)
            if "in [200, 403]" in rendered or "in (200, 403)" in rendered or "in [403, 200]" in rendered:
                findings.append({
                    "file": file_name,
                    "line": node.lineno,
                    "category": "ASSERTION_WEAKENED",
                    "detail": f"Assertion broadened to accept insecure status: `{rendered}`"
                })
            elif rendered == "True" or rendered == "1":
                findings.append({
                    "file": file_name,
                    "line": node.lineno,
                    "category": "ASSERTION_VACUOUS",
                    "detail": "Assertion replaced with trivial constant True"
                })

        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in node.decorator_list:
                label = ast.unparse(dec)
                if any(k in label for k in ("skip", "xfail", "skipif")):
                    findings.append({
                        "file": file_name,
                        "line": dec.lineno,
                        "category": "TEST_SKIPPED_OR_XFAIL",
                        "detail": f"Test marked with `{label}`"
                    })
    return findings


def run_tests_in_worktree(worktree_dir, test_targets):
    """Run pytest on a worktree inside the hardened sandbox (network none, read-only root,
    cap-drop ALL, resource limits). Host execution is refused unless SATRA_ALLOW_HOST_EXEC=1."""
    engine = shutil.which("docker")
    if engine:
        with tempfile.TemporaryDirectory(prefix="satra-run-") as tmp:
            work = Path(tmp) / "project"
            shutil.copytree(worktree_dir, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
            user_flag = ["-u", "%d:%d" % (os.getuid(), os.getgid())] if hasattr(os, "getuid") else []
            cmd = [engine, "run", "--rm", *user_flag, "--network", "none", "--read-only",
                   "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                   "--memory", "512m", "--cpus", "1", "--pids-limit", "64",
                   "--tmpfs", "/tmp:rw,nosuid,size=64m", "-v", str(work) + ":/work:rw", "-w", "/work",
                   "-e", "PYTHONDONTWRITEBYTECODE=1", "-e", "PYTHONPATH=/work",
                   "asent-sandbox:local", "python", "-m", "pytest", "-q", "-o", "addopts=", "-p", "no:cacheprovider",
                   *test_targets]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            except subprocess.TimeoutExpired:
                return {"exit_code": None, "stdout": "", "passed": False, "backend": "docker", "reason": "timeout"}
            return {"exit_code": proc.returncode, "stdout": proc.stdout, "passed": proc.returncode == 0, "backend": "docker"}
    if os.environ.get("SATRA_ALLOW_HOST_EXEC") != "1":
        return {"exit_code": None, "stdout": "", "passed": False, "backend": "none",
                "reason": "Docker unavailable; refusing to execute untrusted code on the host"}
    cmd = [sys.executable, "-m", "pytest", "-q", "-o", "addopts=", *test_targets]
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PYTHONPATH"] = str(worktree_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(cmd, cwd=str(worktree_dir), env=env, capture_output=True, text=True, timeout=30)
    return {"exit_code": proc.returncode, "stdout": proc.stdout, "passed": proc.returncode == 0, "backend": "host-optin"}


def judge_counterfactual_oracles(baseline_dir, candidate_dir, operator_name="MUT_AUTHZ_IDOR_RETURN_TRUE"):
    with tempfile.TemporaryDirectory(prefix="satra-mut-base-") as d_b, \
         tempfile.TemporaryDirectory(prefix="satra-mut-cand-") as d_c:

        base_mut = Path(d_b) / "project"
        cand_mut = Path(d_c) / "project"
        shutil.copytree(baseline_dir, base_mut)
        shutil.copytree(candidate_dir, cand_mut)

        mutate_candidate_worktree(base_mut, operator_name)
        mutate_candidate_worktree(cand_mut, operator_name)

        cand_test_file = Path(candidate_dir) / "tests" / "test_security.py"
        base_test_file = Path(baseline_dir) / "tests" / "test_security.py"

        integrity_findings = []
        if cand_test_file.exists() and base_test_file.exists():
            integrity_findings = check_static_test_integrity(
                base_test_file.read_text(encoding="utf-8", errors="replace"),
                cand_test_file.read_text(encoding="utf-8", errors="replace"),
                file_name="tests/test_security.py"
            )

        test_target = ["tests/test_security.py"] if (Path(candidate_dir) / "tests" / "test_security.py").exists() else ["tests"]

        base_on_base = run_tests_in_worktree(baseline_dir, test_target)
        cand_on_mut = run_tests_in_worktree(cand_mut, test_target)

        kill_matrix = {
            "operator": operator_name,
            "baseline_healthy": base_on_base["passed"],
            "candidate_mutant_survived": cand_on_mut["passed"],
            "integrity_findings": integrity_findings
        }

        if integrity_findings or cand_on_mut["passed"]:
            verdict = "ORACLE_WEAKENED"
            reason = "Candidate test oracle failed to kill valid counterfactual mutant (or assertion weakened)"
        else:
            verdict = "PRESERVED_WITHIN_MODEL"
            reason = "Candidate tests successfully discriminate against counterfactual mutation"

        return {
            "verdict": verdict,
            "reason": reason,
            "kill_matrix": kill_matrix
        }


def preflight(source):
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return False, "Syntax error: " + str(e)
    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            modules = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module]
            if any(m not in ("pytest",) for m in modules if m):
                return False, "Imports outside permitted test vocabulary"
        if isinstance(n, ast.Attribute) and (n.attr.startswith("__") or n.attr in ("skip", "xfail", "system", "execute", "Popen")):
            return False, "Unsafe or non-discriminative test construct"
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("eval", "exec", "open", "compile", "getattr", "setattr", "__import__"):
            return False, "Unsafe side effect / dynamic execution"
        if isinstance(n, ast.Assert):
            if isinstance(n.test, ast.Constant) and n.test.value in (True, False, 1, 0, "", None):
                return False, "Vacuous assertion cannot discriminate secure from insecure behaviour"
            rendered = ast.unparse(n.test)
            if rendered in ("True", "1", "False", "0"):
                return False, "Vacuous assertion cannot discriminate secure from insecure behaviour"
    if not any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
        return False, "No assertion"
    return True, "Passed syntax preflight"


def is_pass(result):
    return result.get("available") and result.get("exit_code") == 0 and result.get("passed", 0) > 0 and result.get("skipped", 0) == 0 and result.get("errors", 0) == 0


def killed(result):
    """
    Classifies mutant kill by pytest JUnit XML element (<failure> vs <error>):
    - An assertion failure (<failure> / status == 'FAIL') indicates genuine mutant kill.
    - An infrastructure crash / import failure (<error> / status == 'ERROR') is NOT a genuine kill.
    - If every mutant is an infrastructure error, the kill check evaluates False.
    """
    if not result.get("available"):
        return False
    tests = result.get("tests", [])
    if tests:
        # At least one test must have status == 'FAIL' (assertion failure / <failure> in JUnit XML)
        return any(t.get("status") == "FAIL" for t in tests)
    # When tests array is unavailable, fall back to counts: failed > 0 and errors == 0
    return result.get("exit_code") == 1 and result.get("failed", 0) > 0 and result.get("errors", 0) == 0


def judge(baseline, mutant, repeat, feasible):
    if not feasible:
        return {"accepted": False, "diagnosis": "INCONCLUSIVE", "reason": "Counterfactual not independently shown to violate contract"}
    if not is_pass(baseline):
        return {"accepted": False, "diagnosis": "PRE_EXISTING_TEST_GAP", "reason": "Candidate test does not pass secure baseline"}
    if not is_pass(repeat):
        return {"accepted": False, "diagnosis": "INCONCLUSIVE", "reason": "Baseline repeatability failed"}
    if killed(mutant):
        return {"accepted": True, "diagnosis": "PRESERVED_WITHIN_MODEL", "reason": "Passes secure baseline twice and kills valid mutation"}
    if is_pass(mutant):
        return {"accepted": False, "diagnosis": "ORACLE_WEAKENED", "reason": "Test passes even when mutation is active"}
    return {"accepted": False, "diagnosis": "INCONCLUSIVE", "reason": "Execution failure is not a mutant kill"}


def validate_generated_test(test_code, contract, baseline_result=None, mutant_result=None, repeat_result=None):
    """
    SATRA Phase 7: 7-Check Validator Pipeline for Generated / Adaptive Tests:
    1. Preflight Syntax & Vocabulary (ast.parse, no forbidden imports/calls)
    2. Assertion presence (not vacuous or trivial)
    3. No assertion weakening (in [200, 403], True, 1)
    4. Contract alignment (targets applicable security contract & rule ID)
    5. Clean pass on secure baseline
    6. Decisive mutant kill (discriminates against counterfactual mutant)
    7. Baseline repeatability (deterministic result across repeated execution)
    """
    checks = {}

    # Check 1: Syntax & vocabulary
    try:
        tree = ast.parse(test_code)
    except SyntaxError as e:
        checks["check1_syntax_and_vocabulary"] = {"passed": False, "reason": str(e)}
        return {"valid": False, "failing_check": 1, "reason": f"Syntax error: {e}", "checks": checks}

    for n in ast.walk(tree):
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            modules = [a.name for a in n.names] if isinstance(n, ast.Import) else [n.module]
            if any(m not in ("pytest",) for m in modules if m):
                checks["check1_syntax_and_vocabulary"] = {"passed": False, "reason": "Imports outside permitted test vocabulary"}
                return {"valid": False, "failing_check": 1, "reason": "Imports outside permitted test vocabulary", "checks": checks}
        if isinstance(n, ast.Attribute) and (n.attr.startswith("__") or n.attr in ("skip", "xfail", "system", "execute", "Popen")):
            checks["check1_syntax_and_vocabulary"] = {"passed": False, "reason": "Unsafe or non-discriminative test construct"}
            return {"valid": False, "failing_check": 1, "reason": "Unsafe or non-discriminative test construct", "checks": checks}
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in ("eval", "exec", "open", "compile", "getattr", "setattr", "__import__"):
            checks["check1_syntax_and_vocabulary"] = {"passed": False, "reason": "Unsafe side effect / dynamic execution"}
            return {"valid": False, "failing_check": 1, "reason": "Unsafe side effect / dynamic execution", "checks": checks}
    checks["check1_syntax_and_vocabulary"] = {"passed": True, "reason": "Passed syntax and vocabulary check"}

    # Check 2: Assertion presence
    assert_nodes = [n for n in ast.walk(tree) if isinstance(n, ast.Assert)]
    checks["check2_assertion_present"] = {"passed": bool(assert_nodes), "count": len(assert_nodes)}
    if not assert_nodes:
        return {"valid": False, "failing_check": 2, "reason": "No assertion found in test code", "checks": checks}

    # Check 3: Assertion weakening / tampering
    findings = check_static_test_integrity("", test_code, file_name="generated_test.py")
    checks["check3_no_weakened_assertions"] = {"passed": len(findings) == 0, "findings": findings}
    if findings:
        return {"valid": False, "failing_check": 3, "reason": f"Weakened assertion detected: {findings[0]['detail']}", "checks": checks}

    # Check 4: Contract alignment
    rule_id = contract.get("rule_id") if isinstance(contract, dict) else getattr(contract, "rule_id", None)
    expected_status = str(contract.get("expected_status", 403) if isinstance(contract, dict) else getattr(contract, "expected_status", 403))
    mentions_rule = rule_id is None or (rule_id.lower() in test_code.lower() or expected_status in test_code)
    checks["check4_contract_alignment"] = {"passed": mentions_rule, "rule_id": rule_id, "expected_status": expected_status}
    if not mentions_rule:
        return {"valid": False, "failing_check": 4, "reason": f"Test does not align with contract expected status ({expected_status}) or rule", "checks": checks}

    # Checks 5, 6, 7 (Dynamic differential execution if results provided)
    if baseline_result is not None:
        p_base = is_pass(baseline_result)
        checks["check5_passes_secure_baseline"] = {"passed": p_base}
        if not p_base:
            return {"valid": False, "failing_check": 5, "reason": "Generated test failed on secure baseline", "checks": checks}

    if mutant_result is not None:
        k_mut = killed(mutant_result)
        checks["check6_kills_counterfactual"] = {"passed": k_mut}
        if not k_mut:
            return {"valid": False, "failing_check": 6, "reason": "Generated test failed to kill counterfactual mutant", "checks": checks}

    if repeat_result is not None:
        p_rep = is_pass(repeat_result)
        checks["check7_baseline_repeatability"] = {"passed": p_rep}
        if not p_rep:
            return {"valid": False, "failing_check": 7, "reason": "Generated test baseline run is not deterministic/repeatable", "checks": checks}

    return {"valid": True, "failing_check": None, "reason": "All validation checks passed", "checks": checks}

