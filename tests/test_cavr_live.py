"""Live checks against the real PyPI and OSV. Skipped unless CAVR_LIVE=1.

    CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py
"""
import io
import json
import os
import subprocess
import sys

import pytest

import shutil

from backend.cavr.advisories import check_advisories
from backend.cavr.pip_shim import main as pip_wrapper
from backend.cavr.pipeline import verify_request
from backend.cavr.pypi_client import fetch_artifact
from backend.cavr.storage import CavrStorage
from test_cavr_support import PYPDF_SHA256, REPO, sha256_file

pytestmark = pytest.mark.skipif(os.environ.get("CAVR_LIVE") != "1", reason="live network test; set CAVR_LIVE=1")


def test_live_pypi_pypdf_wheel_matches_the_registry_digest(tmp_path):
    result = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine")
    assert (result["result"], result["rule"]) == ("OK", "HASH_MATCH"), result["reason"]
    # The same file that is checked in under artifacts/, so the digest is known in advance.
    assert result["sha256"] == result["registry_sha256"] == PYPDF_SHA256
    assert sha256_file(result["path"]) == PYPDF_SHA256


def test_live_pypi_unknown_release_is_unresolved(tmp_path):
    result = fetch_artifact("pypdf", "0.0.0.dev987654321", tmp_path / "quarantine")
    assert (result["result"], result["rule"]) == ("UNRESOLVED", "RELEASE_NOT_FOUND"), result["reason"]


def test_live_osv_pypdf_5_1_0_is_rejected(tmp_path):
    result = check_advisories("pypdf", "5.1.0", tmp_path / "osv", live=True)
    assert (result["result"], result["rule"]) == ("REJECTED", "KNOWN_VULNERABILITY"), result["reason"]
    assert result["mode"] == "LIVE"
    # 97 advisories were recorded on 2026-10-10. One of them is checked by id; the count is not
    # asserted because an advisory can be withdrawn later.
    assert "GHSA-7hfw-26vp-jp8m" in [entry["id"] for entry in result["affected"]]
    # The live answer is now in the dated cache and is read back offline.
    again = check_advisories("pypdf", "5.1.0", tmp_path / "osv", live=False)
    assert again["mode"] == "DATED CACHE" and again["result"] == "REJECTED"


def test_live_osv_pypdf_6_19_0_gets_an_answer(tmp_path):
    # Not asserted to be clean: a new advisory for 6.19.0 may be published after this was written.
    result = check_advisories("pypdf", "6.19.0", tmp_path / "osv", live=True)
    assert result["mode"] == "LIVE" and result["rule"] != "ADVISORIES_UNAVAILABLE", result["reason"]


def test_live_pipeline_pypdf_6_19_0_in_the_invoicehub_project(tmp_path):
    """The whole path against the real PyPI and OSV: nothing is injected."""
    project = tmp_path / "project"
    shutil.copytree(REPO / "demo_project" / "InvoiceHub" / "app", project / "app")
    shutil.copy(REPO / "demo_project" / "InvoiceHub" / "dependencies.lock.json", project / "dependencies.lock.json")
    policy = {"project_task_description": "Invoice PDF text extraction", "denied_packages": [],
              "allowed_scopes": ["FILE_READ:invoice_documents", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
              "approved_requirements": ["pypdf==6.19.0"]}
    store = CavrStorage(tmp_path / "cavr.sqlite3")
    args = {"quarantine_dir": tmp_path / "quarantine", "advisory_cache_dir": tmp_path / "osv", "live_advisories": True}
    first = verify_request("pip install pypdf==6.19.0", project, policy, store, **args)
    package = first["packages"][0]
    assert package["evidence"]["artifact"]["sha256"] == PYPDF_SHA256, first["reason"]
    assert package["evidence"]["advisories"][0]["mode"] == "LIVE"
    # Not asserted to be VERIFIED for ever: OSV may list 6.19.0 one day, and then REJECTED is the right answer.
    assert first["status"] in ("VERIFIED", "REJECTED"), first["reason"]
    if first["status"] == "VERIFIED":
        second = verify_request("pip install pypdf==6.19.0", project, policy, store, **args)
        assert second["status"] == "VERIFIED" and second["cache_hit"] is True


def test_live_pip_wrapper_installs_only_with_the_flag_and_only_the_verified_wheel(tmp_path):
    """Plan step 12's manual check with the real PyPI, the real OSV and the real pip, in a scratch venv."""
    project = tmp_path / "project"
    shutil.copytree(REPO / "demo_project" / "InvoiceHub" / "app", project / "app")
    shutil.copy(REPO / "demo_project" / "InvoiceHub" / "dependencies.lock.json", project / "dependencies.lock.json")
    (project / "cavr-policy.json").write_text(json.dumps({
        "project_task_description": "Invoice PDF text extraction", "denied_packages": [{"name": "reqeusts", "reason": "typosquat"}],
        "allowed_scopes": ["FILE_READ:invoice_documents", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
        "approved_requirements": ["pypdf==6.19.0"]}))
    subprocess.run([sys.executable, "-m", "venv", str(tmp_path / "venv")], check=True)
    python = tmp_path / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def installed_version():
        done = subprocess.run([str(python), "-c", "import pypdf; print(pypdf.__version__)"], capture_output=True, text=True)
        return done.stdout.strip() if done.returncode == 0 else None

    def wrapper(*argv):
        out = io.StringIO()
        code = pip_wrapper(["--cavr-project", str(project), "--cavr-python", str(python), *argv], out=out,
                           store=CavrStorage(tmp_path / "cavr.sqlite3"), quarantine_dir=tmp_path / "quarantine",
                           advisory_cache_dir=tmp_path / "osv", live_advisories=True)
        return code, out.getvalue()

    assert wrapper("install", "reqeusts==2.31.0", "--install")[0] == 3 and installed_version() is None
    code, text = wrapper("install", "pypdf==6.19.0")
    # Not asserted to be VERIFIED for ever: OSV may list 6.19.0 one day, and then REJECTED is the right answer.
    assert code in (0, 1), text
    assert installed_version() is None  # deciding installs nothing
    code_with_flag, text = wrapper("install", "pypdf==6.19.0", "--install")
    if code == 0:
        assert code_with_flag == 0, text
        assert "cache_hit: True" in text and f"pypdf==6.19.0 --hash=sha256:{PYPDF_SHA256}" in text
        assert installed_version() == "6.19.0"
    else:
        assert code_with_flag == 1 and installed_version() is None


def test_live_dashboard_scenarios_are_real_requests(tmp_path, monkeypatch):
    """The six dashboard chips, in order, against the real PyPI and OSV, with the shipped project and policy."""
    import asyncio

    from backend.cavr import api

    monkeypatch.setattr(api, "storage", CavrStorage(tmp_path / "dashboard.sqlite3"))
    monkeypatch.setattr(api, "QUARANTINE_DIR", tmp_path / "quarantine")
    monkeypatch.setattr(api, "ADVISORY_CACHE_DIR", tmp_path / "osv")
    seen = {}
    for scenario in api.SCENARIOS:
        run_id = f"live-{scenario['id']}"
        api.RUN_EVENTS[run_id] = []
        api.RUN_CHAINS[run_id] = api.EvidenceChain(run_id)
        body = api.InterceptRequest(package=scenario["package"], version=scenario["version"],
                                    scenario_type=scenario["condition"] or scenario["id"])
        seen[scenario["id"]] = asyncio.run(api.run_verification(run_id, body))
    outcome = {key: (verdict["status"], verdict["rule"]) for key, verdict in seen.items()}
    # Not asserted to be VERIFIED for ever: OSV may list 6.19.0 one day, and then REJECTED is the right answer.
    assert outcome["verified"] in (("VERIFIED", "ALL_CHECKS_PASSED"), ("REJECTED", "KNOWN_VULNERABILITY")), seen["verified"]["reason"]
    assert seen["verified"]["packages"][0]["evidence"]["artifact"]["sha256"] == PYPDF_SHA256
    assert outcome["known_vulnerable"] == ("REJECTED", "KNOWN_VULNERABILITY"), seen["known_vulnerable"]["reason"]
    vulnerable = seen["known_vulnerable"]["packages"][0]["evidence"]
    assert vulnerable["artifact"]["rule"] == "HASH_MATCH" and vulnerable["artifact"]["filename"] == "pypdf-5.1.0-py3-none-any.whl"
    assert "GHSA-7hfw-26vp-jp8m" in [match["id"] for advisory in vulnerable["advisories"] for match in advisory["affected"]]
    if outcome["verified"][0] == "VERIFIED":
        # The second chip is the same request: a cache hit on what the first one stored.
        assert outcome["verified_again"] == ("VERIFIED", "ALL_CHECKS_PASSED") and seen["verified_again"]["cache_hit"] is True
        assert seen["verified"]["cache_hit"] is False
    assert outcome["not_on_allowlist"] == ("BLOCK", "NOT_ON_ALLOWLIST") and seen["not_on_allowlist"]["packages"] == []
    assert outcome["tampered_wheel"] == ("REJECTED", "HASH_MISMATCH"), seen["tampered_wheel"]["reason"]
    tampered = seen["tampered_wheel"]["packages"][0]["evidence"]["artifact"]
    assert tampered["registry_sha256"] == PYPDF_SHA256 != tampered["sha256"] == sha256_file(tampered["path"])
    # The tampered run kept its file in its own directory and left the genuine wheel of the real runs alone.
    assert tampered["path"].startswith(str(api.demo_quarantine_dir("tampered_wheel")))
    assert sha256_file(tmp_path / "quarantine" / "pypdf-6.19.0-py3-none-any.whl") == PYPDF_SHA256
    assert sorted(path.name for path in (tmp_path / "quarantine").iterdir()) == ["pypdf-5.1.0-py3-none-any.whl",
                                                                                 "pypdf-6.19.0-py3-none-any.whl"]
    assert outcome["network_off"] == ("UNRESOLVED", "REGISTRY_UNAVAILABLE")
