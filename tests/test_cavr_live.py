"""Live checks against the real PyPI and OSV. Skipped unless CAVR_LIVE=1.

    CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py

Every test here uses live settings explicitly. tests/conftest.py makes orchestrator demo runs offline for the
whole session (`analyzer.DEMO_SETTINGS` = recorded answers); the `live` fixture below overrides that, and the
dashboard and gate settings, with the real network. Each test then proves it reached the network, not a
recording: `LiveTransport` lists every URL the real HTTPS transport fetched (registry JSON from pypi.org, the
wheel from files.pythonhosted.org), and every OSV answer has mode "LIVE".
"""
import io
import json
import os
import shutil
import subprocess
import sys

import pytest

from backend.cavr import analyzer, api, gate_adapter
from backend.cavr.advisories import check_advisories
from backend.cavr.pip_shim import main as pip_wrapper
from backend.cavr.pipeline import verify_request
from backend.cavr.pypi_client import FILES_HOST, REGISTRY_HOST, HttpxTransport, fetch_artifact
from backend.cavr.storage import CavrStorage
from test_cavr_support import PIN_SHA256, PIN_VERSION, PYPDF_SHA256, REPO, sha256_file

pytestmark = pytest.mark.skipif(os.environ.get("CAVR_LIVE") != "1", reason="live network test; set CAVR_LIVE=1")


class LiveTransport:
    """The real HTTPS transport, listing every URL it fetched: proof that the answer came from the network."""

    def __init__(self):
        self.real = HttpxTransport()
        self.urls = []

    def stream(self, url):
        self.urls.append(url)
        yield from self.real.stream(url)

    def reached(self, name, version) -> bool:
        """Both the registry JSON and a wheel of name==version were fetched live."""
        registry = f"https://{REGISTRY_HOST}/pypi/{name}/{version}/json"
        wheel = f"{name}-{version}-"
        return registry in self.urls and any(FILES_HOST in url and wheel in url for url in self.urls)


@pytest.fixture
def live(monkeypatch, tmp_path):
    """Live settings for every entry point, replacing the offline demo settings of tests/conftest.py."""
    transport = LiveTransport()
    settings = {"transport": transport, "osv": None, "advisory_cache_dir": tmp_path / "live-osv", "live_advisories": True}
    monkeypatch.setattr(analyzer, "DEMO_SETTINGS", settings)
    monkeypatch.setattr(gate_adapter, "SETTINGS", settings)
    return transport


def live_osv(verdict) -> list[str]:
    """The mode of every OSV answer in a pipeline verdict."""
    return [advisory["mode"] for package in verdict["packages"] for advisory in package["evidence"]["advisories"]]


@pytest.mark.parametrize("version,sha256", [(PIN_VERSION, PIN_SHA256), ("6.19.0", PYPDF_SHA256)])
def test_live_pypi_pypdf_wheel_matches_the_registry_digest(tmp_path, live, version, sha256):
    result = fetch_artifact("pypdf", version, tmp_path / "quarantine", transport=live)
    assert (result["result"], result["rule"]) == ("OK", "HASH_MATCH"), result["reason"]
    # The same bytes as the recording in tests/test_cavr_data/ (6.21.4) or artifacts/ (6.19.0).
    assert result["sha256"] == result["registry_sha256"] == sha256 == sha256_file(result["path"])
    assert live.reached("pypdf", version)


def test_live_pypi_unknown_release_is_unresolved(tmp_path, live):
    result = fetch_artifact("pypdf", "0.0.0.dev987654321", tmp_path / "quarantine", transport=live)
    assert (result["result"], result["rule"]) == ("UNRESOLVED", "RELEASE_NOT_FOUND"), result["reason"]
    assert live.urls == [f"https://{REGISTRY_HOST}/pypi/pypdf/0.0.0.dev987654321/json"]


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


def test_live_osv_pypdf_6_19_0_is_rejected(tmp_path):
    # 18 advisories on 2026-11-22. The count is not asserted (one may be withdrawn); one recorded id is.
    result = check_advisories("pypdf", "6.19.0", tmp_path / "osv", live=True)
    assert result["mode"] == "LIVE" and (result["result"], result["rule"]) == ("REJECTED", "KNOWN_VULNERABILITY"), result["reason"]
    assert "GHSA-39mj-jf6j-2qj3" in [entry["id"] for entry in result["affected"]]


def test_live_osv_pypdf_6_21_4_gets_an_answer(tmp_path):
    # Not asserted to be clean: a new advisory for 6.21.4 may be published after this was written.
    result = check_advisories("pypdf", PIN_VERSION, tmp_path / "osv", live=True)
    assert result["mode"] == "LIVE" and result["rule"] != "ADVISORIES_UNAVAILABLE", result["reason"]


def test_live_pipeline_demo_pin_in_the_invoicehub_project(tmp_path, live):
    """The whole path against the real PyPI and OSV, with the shipped project files and policy."""
    project = tmp_path / "project"
    shutil.copytree(REPO / "demo_project" / "InvoiceHub" / "app", project / "app")
    shutil.copy(REPO / "demo_project" / "InvoiceHub" / "dependencies.lock.json", project / "dependencies.lock.json")
    policy = json.loads((REPO / "demo_project" / "InvoiceHub" / ".asent" / "cavr" / "policy.json").read_text())
    store = CavrStorage(tmp_path / "cavr.sqlite3")
    args = {"transport": live, "quarantine_dir": tmp_path / "quarantine", "advisory_cache_dir": tmp_path / "osv",
            "live_advisories": True}
    first = verify_request(f"pip install pypdf=={PIN_VERSION}", project, policy, store, **args)
    package = first["packages"][0]
    assert package["evidence"]["artifact"]["sha256"] == PIN_SHA256, first["reason"]
    assert live_osv(first) == ["LIVE"] and live.reached("pypdf", PIN_VERSION)
    # Not asserted to be VERIFIED for ever: OSV may list 6.21.4 one day, and then REJECTED is the right answer.
    assert first["status"] in ("VERIFIED", "REJECTED"), first["reason"]
    if first["status"] == "VERIFIED":
        second = verify_request(f"pip install pypdf=={PIN_VERSION}", project, policy, store, **args)
        assert second["status"] == "VERIFIED" and second["cache_hit"] is True and live_osv(second) == ["LIVE"]


def test_live_orchestrator_demo_run_uses_the_network(tmp_path, live, scenario, service):
    """An orchestrator demo run (the `safe` scenario) with the live settings, not the session's recordings."""
    _, context = scenario("safe")
    status, details, _ = analyzer.analyze(context, service.store, tmp_path / "out", lambda *a: None)
    pypdf = next(node for node in details["nodes"] if node["name"] == "pypdf")
    assert pypdf["engine"] == "pipeline" and pypdf["sha256"] == PIN_SHA256
    assert [advisory["mode"] for advisory in pypdf["advisories"]] == ["LIVE"] and live.reached("pypdf", PIN_VERSION)
    assert status in ("VERIFIED", "REJECTED"), details["reason"]


def test_live_pip_wrapper_installs_only_with_the_flag_and_only_the_verified_wheel(tmp_path, live):
    """Plan step 12's manual check with the real PyPI, the real OSV and the real pip, in a scratch venv."""
    project = tmp_path / "project"
    shutil.copytree(REPO / "demo_project" / "InvoiceHub" / "app", project / "app")
    shutil.copy(REPO / "demo_project" / "InvoiceHub" / "dependencies.lock.json", project / "dependencies.lock.json")
    (project / "cavr-policy.json").write_text(json.dumps({
        "project_task_description": "Invoice PDF text extraction", "denied_packages": [{"name": "reqeusts", "reason": "typosquat"}],
        "allowed_scopes": ["FILE_READ:invoice_documents", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
        "approved_requirements": [f"pypdf=={PIN_VERSION}"]}))
    subprocess.run([sys.executable, "-m", "venv", str(tmp_path / "venv")], check=True)
    python = tmp_path / "venv" / ("Scripts/python.exe" if os.name == "nt" else "bin/python")

    def installed_version():
        done = subprocess.run([str(python), "-c", "import pypdf; print(pypdf.__version__)"], capture_output=True, text=True)
        return done.stdout.strip() if done.returncode == 0 else None

    def wrapper(*argv):
        out = io.StringIO()
        code = pip_wrapper(["--cavr-project", str(project), "--cavr-python", str(python), *argv], out=out,
                           store=CavrStorage(tmp_path / "cavr.sqlite3"), quarantine_dir=tmp_path / "quarantine",
                           advisory_cache_dir=tmp_path / "osv", live_advisories=True, transport=live)
        return code, out.getvalue()

    assert wrapper("install", "reqeusts==2.31.0", "--install")[0] == 3 and installed_version() is None
    code, text = wrapper("install", f"pypdf=={PIN_VERSION}")
    assert live.reached("pypdf", PIN_VERSION)
    # Not asserted to be VERIFIED for ever: OSV may list 6.21.4 one day, and then REJECTED is the right answer.
    assert code in (0, 1), text
    assert installed_version() is None  # deciding installs nothing
    code_with_flag, text = wrapper("install", f"pypdf=={PIN_VERSION}", "--install")
    if code == 0:
        assert code_with_flag == 0, text
        assert "cache_hit: True" in text and f"pypdf=={PIN_VERSION} --hash=sha256:{PIN_SHA256}" in text
        assert installed_version() == PIN_VERSION
    else:
        assert code_with_flag == 1 and installed_version() is None


def test_live_dashboard_scenarios_are_real_requests(tmp_path, monkeypatch, live):
    """The seven dashboard chips, in order, against the real PyPI and OSV, with the shipped project and policy."""
    import asyncio

    monkeypatch.setattr(api, "TRANSPORT", live)
    monkeypatch.setattr(api, "LIVE_ADVISORIES", True)
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
    for chip in ("verified", "recent_advisories", "known_vulnerable"):
        assert live_osv(seen[chip]) == ["LIVE"], (chip, live_osv(seen[chip]))
    assert live.reached("pypdf", PIN_VERSION) and live.reached("pypdf", "6.19.0") and live.reached("pypdf", "5.1.0")
    # Not asserted to be VERIFIED for ever: OSV may list 6.21.4 one day, and then REJECTED is the right answer.
    assert outcome["verified"] in (("VERIFIED", "ALL_CHECKS_PASSED"), ("REJECTED", "KNOWN_VULNERABILITY")), seen["verified"]["reason"]
    assert seen["verified"]["packages"][0]["evidence"]["artifact"]["sha256"] == PIN_SHA256
    assert outcome["recent_advisories"] == ("REJECTED", "KNOWN_VULNERABILITY"), seen["recent_advisories"]["reason"]
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
    assert tampered["registry_sha256"] == PIN_SHA256 != tampered["sha256"] == sha256_file(tampered["path"])
    # The tampered run kept its file in its own directory and left the genuine wheel of the real runs alone.
    assert tampered["path"].startswith(str(api.demo_quarantine_dir("tampered_wheel")))
    assert sha256_file(tmp_path / "quarantine" / f"pypdf-{PIN_VERSION}-py3-none-any.whl") == PIN_SHA256
    assert sorted(path.name for path in (tmp_path / "quarantine").iterdir()) == [
        "pypdf-5.1.0-py3-none-any.whl", "pypdf-6.19.0-py3-none-any.whl", f"pypdf-{PIN_VERSION}-py3-none-any.whl"]
    assert outcome["network_off"] == ("UNRESOLVED", "REGISTRY_UNAVAILABLE")


def test_live_repair_for_pypdf_6_19_0(tmp_path, live):
    """Repair against the real registry and OSV: a REJECTED pypdf 6.19.0 gets a newer pin that passed a live re-check.
    The version is not asserted (OSV may list 6.21.4 one day); its digest, its re-check and the untouched project are."""
    from packaging.version import Version
    from backend.cavr.repair_proposal import propose_repair
    project = tmp_path / "project"
    shutil.copytree(REPO / "demo_project" / "InvoiceHub" / "app", project / "app")
    (project / "requirements.txt").write_text("pypdf==6.19.0\n")
    lock = {"lock_version": 1, "edges": [],
            "packages": [{"name": "pypdf", "version": "6.19.0", "ecosystem": "PyPI", "sha256": PYPDF_SHA256}]}
    (project / "dependencies.lock.json").write_text(json.dumps(lock))
    policy = {**json.loads((REPO / "demo_project" / "InvoiceHub" / ".asent" / "cavr" / "policy.json").read_text())}
    policy["approved_requirements"] = ["pypdf==6.19.0"]
    args = {"transport": live, "advisory_cache_dir": tmp_path / "osv", "live_advisories": True}
    verdict = verify_request("pip install -r requirements.txt", project, policy, None,
                             quarantine_dir=tmp_path / "quarantine", **args)
    package = verdict["packages"][0]
    assert (package["status"], package["stage"]) == ("REJECTED", "advisories"), verdict["reason"]
    before = {path: path.read_bytes() for path in project.rglob("*") if path.is_file()}
    block = propose_repair(verdict, package, project_dir=project, policy=policy, requirements_file="requirements.txt",
                           work_dir=tmp_path / "work", **args)
    assert block["advisory_screen"]["mode"] == "LIVE" and block["registry"]["rule"] == "RELEASES_READ"
    assert block["result"] == "PROPOSED" and block["pin"], block["reason"]
    pin = block["pin"]
    assert Version(pin["version"]) > Version("6.19.0") and pin["recheck"]["status"] == "VERIFIED"
    assert pin["recheck"]["package"]["sha256"] == pin["recheck"]["package"]["registry_sha256"]
    assert pin["lockfile_entry"]["after"]["sha256"] == pin["recheck"]["package"]["sha256"]
    assert live.reached("pypdf", pin["version"])
    assert {path: path.read_bytes() for path in project.rglob("*") if path.is_file()} == before
