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
    cmd = [
        sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
        *test_targets
    ]
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["PYTHONPATH"] = str(worktree_dir)
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    proc = subprocess.run(cmd, cwd=str(worktree_dir), env=env, capture_output=True, text=True, timeout=30)
    return {
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "passed": proc.returncode == 0
    }


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
    if not any(isinstance(n, ast.Assert) for n in ast.walk(tree)):
        return False, "No assertion"
    return True, "Passed syntax preflight"


def is_pass(result):
    return result.get("available") and result.get("exit_code") == 0 and result.get("passed", 0) > 0 and result.get("skipped", 0) == 0 and result.get("errors", 0) == 0


def killed(result):
    return result.get("available") and result.get("exit_code") == 1 and result.get("failed", 0) > 0


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
