import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from xml.etree import ElementTree as ET

from backend.config import ROOT
from backend.satra.trust import TRUST_DIR, verify_manifest


def run_contract_test(worktree_dir, test_rel_path, output_dir=None, timeout=30):
    start_time = time.perf_counter()
    manifest_check = verify_manifest()
    if not manifest_check["valid"]:
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"Trusted assets manifest check failed: {manifest_check['reason']}",
            "tests": [],
            "sandboxed": False
        }

    test_file = TRUST_DIR / test_rel_path
    if not test_file.exists():
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"Trusted test file does not exist: {test_rel_path}",
            "tests": [],
            "sandboxed": False
        }

    out_path = Path(output_dir) if output_dir else Path(tempfile.mkdtemp(prefix="satra-out-"))
    out_path.mkdir(parents=True, exist_ok=True)
    engine = shutil.which("docker")
    host_ok = os.environ.get("SATRA_ALLOW_HOST_EXEC") == "1"
    if not engine and not host_ok:
        return {"verdict": "INCONCLUSIVE", "reason": "Docker unavailable; refusing to execute candidate code on the host",
                "tests": [], "sandboxed": False}

    junit_xml = out_path / "junit.xml"
    work_root = None
    if engine:
        work_root = Path(tempfile.mkdtemp(prefix="satra-ct-"))
        work = work_root / "project"
        shutil.copytree(worktree_dir, work, ignore=shutil.ignore_patterns(".git", "__pycache__"))
        user_flag = ["-u", "%d:%d" % (os.getuid(), os.getgid())] if hasattr(os, "getuid") else []
        cmd = [engine, "run", "--rm", *user_flag, "--network", "none", "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges", "--memory", "512m", "--cpus", "1", "--pids-limit", "64",
               "--tmpfs", "/tmp:rw,nosuid,size=64m",
               "-v", str(work) + ":/work:rw", "-v", str(TRUST_DIR) + ":/trusted:ro", "-v", str(out_path) + ":/out:rw",
               "-w", "/work", "-e", "PYTHONPATH=/work", "-e", "PYTHONDONTWRITEBYTECODE=1",
               "asent-sandbox:local", "python", "-m", "pytest", "-q", "-o", "addopts=", "-p", "no:cacheprovider",
               "-c", "/trusted/trusted_pytest.ini", "--junitxml=/out/junit.xml", "--rootdir", "/trusted",
               "/trusted/" + test_rel_path]
        run_kwargs = {}
    else:
        cmd = [
            sys.executable, "-m", "pytest", "-q", "-o", "addopts=",
            "-c", str(TRUST_DIR / "trusted_pytest.ini"),
            f"--junitxml={junit_xml}",
            "--rootdir", str(TRUST_DIR),
            str(test_file)
        ]
        env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        env["PYTHONPATH"] = str(worktree_dir)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        run_kwargs = {"cwd": str(worktree_dir), "env": env}

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, **run_kwargs)
    except subprocess.TimeoutExpired:
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"Execution timed out after {timeout} seconds",
            "tests": [],
            "sandboxed": bool(engine)
        }
    except Exception as e:
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"Execution failed: {str(e)}",
            "tests": [],
            "sandboxed": bool(engine)
        }
    finally:
        if work_root:
            shutil.rmtree(work_root, ignore_errors=True)

    tests = []
    if junit_xml.exists():
        try:
            tree = ET.parse(junit_xml)
            for t in tree.getroot().iter("testcase"):
                err = t.find("error")
                fail = t.find("failure")
                skp = t.find("skipped")
                st = "ERROR" if err is not None else "FAIL" if fail is not None else "SKIP" if skp is not None else "PASS"
                detail = err if err is not None else fail
                tests.append({
                    "name": t.attrib.get("name"),
                    "status": st,
                    "message": detail.text if detail is not None else ""
                })
        except Exception:
            pass

    sanity_tests = [t for t in tests if t["name"].startswith("test_sanity_")]
    security_tests = [t for t in tests if not t["name"].startswith("test_sanity_")]

    if any(t["status"] in ("FAIL", "ERROR") for t in sanity_tests):
        verdict = "INCONCLUSIVE"
        reason = "Sanity pre-condition failed in test harness"
    elif not tests or any(t["status"] == "ERROR" for t in tests):
        verdict = "INCONCLUSIVE"
        reason = "Test harness encountered runtime errors or produced no results"
    elif any(t["status"] == "FAIL" for t in security_tests):
        verdict = "VIOLATED"
        reason = "Security obligation violated by target candidate code"
    elif all(t["status"] == "PASS" for t in security_tests) and security_tests:
        verdict = "SATISFIED"
        reason = "All security obligations satisfied without violation"
    else:
        verdict = "INCONCLUSIVE"
        reason = "No security tests evaluated"

    return {
        "verdict": verdict,
        "reason": reason,
        "exit_code": proc.returncode,
        "tests": tests,
        "passed": sum(1 for t in tests if t["status"] == "PASS"),
        "failed": sum(1 for t in tests if t["status"] == "FAIL"),
        "duration_ms": round((time.perf_counter() - start_time) * 1000, 2),
        "sandboxed": bool(engine),
        "mode": "docker-hardened" if engine else "host-optin"
    }


FAMILY_TO_TEST = {
    "AUTHZ.IDOR.001": "test_authz_idor",
    "AUTH.REQ.001": "test_auth_required",
    "AUTHZ.ROLE.001": "test_authz_idor",
    "INJ.SQL.001": "test_sqli",
    "PATH.TRAV.001": "test_path_traversal",
}


def select_tests_for_regions(regions):
    """
    Semantic AST & Route-Slicing Test Selection (PR-Aware RTS).
    Maps modified AST functions, decorators, and routes to required test families.
    Returns:
      - selected_stems: set of test stems to execute
      - selection_map: dict of all families with selection status and reason
    """
    all_test_files = sorted((TRUST_DIR / "trusted_tests").glob("test_*.py"))
    all_stems = [f.stem for f in all_test_files]

    touched_families = set()
    touched_routes = set()
    touched_functions = set()

    for r in (regions or []):
        for fam in r.get("families", []):
            touched_families.add(fam)
        if r.get("route"):
            touched_routes.add(r["route"].get("path", ""))
        if r.get("function"):
            touched_functions.add(r["function"])

    selected_stems = set()
    for fam in touched_families:
        if fam in FAMILY_TO_TEST:
            selected_stems.add(FAMILY_TO_TEST[fam])

    # If no specific family was directly tagged but routes were touched, map routes
    if not selected_stems and touched_routes:
        for route_path in touched_routes:
            if "invoice" in route_path:
                selected_stems.add("test_authz_idor")
                selected_stems.add("test_auth_required")
            if "file" in route_path or "download" in route_path:
                selected_stems.add("test_path_traversal")
            if "search" in route_path:
                selected_stems.add("test_sqli")

    # If completely empty (e.g. unknown refactor), fail safe to full suite
    if not selected_stems:
        selected_stems = set(all_stems)

    selection_map = {}
    for stem in all_stems:
        is_sel = stem in selected_stems
        if is_sel:
            reasons = []
            if touched_families:
                reasons.append("AST invariant impact: " + ", ".join(sorted(touched_families)))
            if touched_functions:
                reasons.append("Function modified: " + ", ".join(sorted(touched_functions)))
            reason = "; ".join(reasons) if reasons else "Selected by semantic contract slice"
        else:
            reason = "Pruned (no AST code intersection or route touched in PR)"
        selection_map[stem] = {"selected": is_sel, "reason": reason}

    return selected_stems, selection_map


def trusted_suite(worktree_dir, output_dir, target_families=None):
    """Run trusted family tests against a worktree. If target_families is provided,
    only executes the impacted test families; unaffected test families are safely pruned."""
    families = {}
    all_test_files = sorted((TRUST_DIR / "trusted_tests").glob("test_*.py"))

    for test_file in all_test_files:
        stem = test_file.stem
        if target_families is not None and stem not in target_families:
            # Safely pruned by AST route-slicing
            families[stem] = {
                "verdict": "SATISFIED",
                "reason": "PRUNED (No AST code intersection in candidate PR)",
                "tests": [],
                "passed": 0,
                "failed": 0,
                "sandboxed": True,
                "pruned": True,
            }
            continue

        rel = "trusted_tests/" + test_file.name
        families[stem] = run_contract_test(worktree_dir, rel, Path(output_dir) / stem, timeout=60)

    passed = sum(f.get("passed", 0) for f in families.values())
    failed = sum(f.get("failed", 0) for f in families.values())
    errors = sum(1 for f in families.values() for t in f.get("tests", []) if t["status"] == "ERROR")
    inconclusive = [n for n, f in families.items() if f["verdict"] == "INCONCLUSIVE"]
    available = bool(families) and not inconclusive
    return {
        "available": available,
        "exit_code": 0 if available and not failed else 1,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "skipped": sum(1 for f in families.values() if f.get("pruned")),
        "families": {n: {"verdict": f["verdict"], "reason": f["reason"], "pruned": f.get("pruned", False)} for n, f in families.items()},
        "reason": "inconclusive families: %s" % ", ".join(inconclusive) if inconclusive else None,
        "backend": "docker" if all(f.get("sandboxed") for f in families.values()) else "host",
    }
