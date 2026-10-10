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
    junit_xml = out_path / "junit.xml"

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

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(worktree_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout
        )
    except subprocess.TimeoutExpired:
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"Execution timed out after {timeout} seconds",
            "tests": [],
            "sandboxed": False
        }
    except Exception as e:
        return {
            "verdict": "INCONCLUSIVE",
            "reason": f"Execution failed: {str(e)}",
            "tests": [],
            "sandboxed": False
        }

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
        "sandboxed": False,
        "mode": "unsandboxed-subprocess"
    }
