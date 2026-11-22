"""PR 1 of docs/cavr-m2-plan.md: orchestrator demo / scenario runs judge every PyPI node with `verify_request`.

Q1 option A: the demo has no advisory rule of its own; without an OSV answer a package is UNRESOLVED.
Q2: the VERIFIED demo pin is pypdf 6.21.4; pypdf 6.19.0 and 5.1.0 are REJECTED demo cases.
What is real: the shipped InvoiceHub project and its `.asent/` policy, the pypdf 6.21.4 and 6.19.0 wheels, their
registry JSON and the OSV answers recorded on 2026-11-22 (tests/test_cavr_data/), served offline by
`test_cavr_support.recorded_demo_settings` (tests/conftest.py puts them into `analyzer.DEMO_SETTINGS`).
"""
import json
import shutil
from pathlib import Path

import pytest

from backend.cavr import analyzer, gate_adapter
from backend.cavr.pipeline import verify_request
from backend.cavr.storage import CavrStorage
from backend.cavr.verdict_cache import KEY_FIELDS
from backend.integrations import osv_adapter
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.scenarios import apply_scenario, replace_lab
from backend.project_config.frozen import FROZEN_DIR
from test_cavr_support import (INVOICEHUB, build_wheel, PIN_REGISTRY, PIN_SHA256, PIN_VERSION, PIN_WHEEL, PYPDF_SHA256, RECORDED_5_1_0,
                               RECORDED_6_19_0_NOW, World, recorded_demo_settings, sha256_file, write_osv_cache)

SHIPPED_POLICY = INVOICEHUB / ".asent" / "cavr" / "policy.json"


def run_cavr(context, service, tmp_path, name="out"):
    events = []
    status, details, uncertainty = analyzer.analyze(context, service.store, tmp_path / name, lambda kind, data: events.append(kind))
    return status, details, uncertainty, events


def row(details, name):
    return next(node for node in details["nodes"] if node["name"] == name)


def fresh_context(service, run):
    return ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot())


def test_demo_pypi_node_is_judged_by_the_pipeline(scenario, service, tmp_path):
    _, context = scenario("safe")
    status, details, uncertainty, events = run_cavr(context, service, tmp_path)
    assert status == "VERIFIED", details["reason"]
    assert details["engine"] == "pipeline" and details["pipeline"][0]["request"] == "pip install -r requirements.txt"
    pypdf = row(details, "pypdf")
    assert (pypdf["engine"], pypdf["version"], pypdf["status"], pypdf["rule"]) == ("pipeline", PIN_VERSION, "VERIFIED", "ALL_CHECKS_PASSED")
    assert pypdf["sha256"] == PIN_SHA256 and set(pypdf["key_fields"]) == set(KEY_FIELDS)
    assert "cavr.pipeline_verdict" in events and gate_adapter.BOUNDED in uncertainty


def test_demo_run_never_asks_osv_outside_the_pipeline(scenario, service, tmp_path, monkeypatch):
    settings = recorded_demo_settings(tmp_path / "settings")
    real = osv_adapter.OSV(settings["advisory_cache_dir"]).query    # bound before the class is patched
    asked, outside = [], []

    class Stub:  # the pipeline's own OSV seam (`osv=`): the only way an advisory may be asked for
        @staticmethod
        def query(name, version, *args, **kwargs):
            asked.append((name, version))
            return real(name, version, *args, **kwargs)

    monkeypatch.setattr(analyzer, "DEMO_SETTINGS", {**settings, "osv": Stub})
    monkeypatch.setattr(osv_adapter.OSV, "query", lambda *a, **k: outside.append(a) or {"available": False})
    _, context = scenario("safe")
    status, details, _, _ = run_cavr(context, service, tmp_path)
    assert status == "VERIFIED", details["reason"]
    assert asked == [("pypdf", PIN_VERSION)] and outside == []
    assert not hasattr(analyzer, "OSV")  # the analyzer's own advisory rule is gone


def test_demo_run_without_an_osv_answer_is_unresolved(scenario, service, tmp_path, monkeypatch):
    settings = recorded_demo_settings(tmp_path / "settings")
    monkeypatch.setattr(analyzer, "DEMO_SETTINGS", {**settings, "advisory_cache_dir": tmp_path / "no-answers"})
    _, context = scenario("safe")
    status, details, _, _ = run_cavr(context, service, tmp_path)
    pypdf = row(details, "pypdf")
    assert status == "UNRESOLVED" and (pypdf["status"], pypdf["rule"]) == ("UNRESOLVED", "ADVISORIES_UNAVAILABLE")
    assert pypdf["mapped"] == "UNRESOLVED"


def test_demo_pin_6_21_4_is_verified_on_the_recorded_answers(tmp_path):
    # The shipped demo files name the pin, and the recorded files are the bytes PyPI serves for it.
    assert (INVOICEHUB / "requirements.txt").read_text() == f"pypdf=={PIN_VERSION}\n"
    (locked,) = json.loads((INVOICEHUB / "dependencies.lock.json").read_text())["packages"]
    assert (locked["name"], locked["version"], locked["sha256"]) == ("pypdf", PIN_VERSION, PIN_SHA256)
    policy = json.loads(SHIPPED_POLICY.read_text())
    assert policy["approved_requirements"] == [f"pypdf=={PIN_VERSION}"]
    registry = json.loads(PIN_REGISTRY.read_text())["response"]
    assert sha256_file(PIN_WHEEL) == PIN_SHA256 in [entry["digests"]["sha256"] for entry in registry["urls"]]
    project = tmp_path / "project"
    shutil.copytree(INVOICEHUB, project, ignore=shutil.ignore_patterns(".asent", "__pycache__"))
    settings = recorded_demo_settings(tmp_path)
    verdict = verify_request(["pip", "install", "-r", "requirements.txt"], project, policy, CavrStorage(tmp_path / "c.sqlite3"),
                             transport=settings["transport"], quarantine_dir=tmp_path / "q",
                             advisory_cache_dir=settings["advisory_cache_dir"], live_advisories=False)
    assert (verdict["status"], verdict["rule"]) == ("VERIFIED", "ALL_CHECKS_PASSED"), verdict["reason"]
    assert verdict["packages"][0]["evidence"]["artifact"]["sha256"] == PIN_SHA256


@pytest.mark.parametrize("version,vulns,count", [("6.19.0", RECORDED_6_19_0_NOW, 18), ("5.1.0", RECORDED_5_1_0, 97)])
def test_rejected_demo_pins_are_rejected_by_recorded_advisories(tmp_path, version, vulns, count):
    """The two REJECTED demo cases, in the shipped project with only the pin changed. No 5.1.0 wheel is served:
    advisories are asked for even when the download fails, and an affected version is REJECTED either way."""
    project = tmp_path / "project"
    shutil.copytree(INVOICEHUB, project, ignore=shutil.ignore_patterns(".asent", "__pycache__"))
    (project / "requirements.txt").write_text(f"pypdf=={version}\n")
    lock = {"lock_version": 1, "packages": [{"name": "pypdf", "version": version, "ecosystem": "PyPI"}], "edges": []}
    if version == "6.19.0":
        lock["packages"][0]["sha256"] = PYPDF_SHA256
    (project / "dependencies.lock.json").write_text(json.dumps(lock))
    policy = {**json.loads(SHIPPED_POLICY.read_text()), "approved_requirements": [f"pypdf=={version}"]}
    settings = recorded_demo_settings(tmp_path)
    write_osv_cache(settings["advisory_cache_dir"], "pypdf", version, vulns)
    verdict = verify_request(f"pip install pypdf=={version}", project, policy, None, transport=settings["transport"],
                             quarantine_dir=tmp_path / "q", advisory_cache_dir=settings["advisory_cache_dir"], live_advisories=False)
    assert (verdict["status"], verdict["stage"], verdict["rule"]) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    assert f"affected by {count} known advisories" in verdict["reason"]


@pytest.mark.integration
def test_assurance_report_lists_each_cavr_package_sha256_and_contract(integration_runs):
    svc, runs = integration_runs
    report = svc.report(runs["safe"].run_id)
    (identifier,) = [item for item in report["artifact_identifiers"] if item["package"] == "pypdf"]
    assert (identifier["version"], identifier["sha256"], identifier["artifact"]) == (
        PIN_VERSION, PIN_SHA256, f"pypdf-{PIN_VERSION}-py3-none-any.whl")
    (obligation,) = [item for item in report["capability_obligations"] if item["package"] == "pypdf"]
    assert obligation["required"] and obligation["denied"] and obligation["confidence"] == "CONTRACT_INFERRED"
    assert obligation["authority"]
    assert {entry["capability"] for entry in obligation["denied"]} >= {"PROCESS_EXEC", "NETWORK_CONNECT"}


def test_pipeline_fault_in_a_demo_run_is_unresolved(scenario, service, tmp_path, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("stage exploded")

    monkeypatch.setattr(gate_adapter, "verify_request", broken)
    _, context = scenario("safe")
    status, details, uncertainty, _ = run_cavr(context, service, tmp_path)
    assert status == "UNRESOLVED" and "INTERNAL_ERROR" in details["reason"] and "stage exploded" in details["reason"]
    assert any("INTERNAL_ERROR" in item for item in uncertainty)


def test_local_lab_node_keeps_the_lab_path_labelled_demo_lab(scenario, service, tmp_path):
    _, context = scenario("cavr_canary")
    status, details, _, _ = run_cavr(context, service, tmp_path)
    lab = row(details, "invoice-pdf-lab")
    assert status == "REJECTED" and (lab["engine"], lab["status"]) == ("demo-lab", "REJECTED")
    # pypdf is judged by the pipeline here too; the app reaches it through the unguarded lab adapter.
    pypdf = row(details, "pypdf")
    assert pypdf["engine"] == "pipeline" and (pypdf["status"], pypdf["rule"]) == ("UNRESOLVED", "SINK_REACHABLE")
    assert pypdf["escalation"]


def test_locked_pypi_node_no_request_verifies_is_unresolved(scenario, service, tmp_path):
    run, _ = scenario("safe")
    lock_path = Path(run.candidate_workspace) / "dependencies.lock.json"
    lock = json.loads(lock_path.read_text())
    lock["packages"].append({"name": "helper", "version": "2.0", "ecosystem": "PyPI"})
    lock_path.write_text(json.dumps(lock))
    status, details, uncertainty, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    helper = row(details, "helper")
    assert (helper["status"], helper["rule"], helper["engine"]) == ("UNRESOLVED", "LOCKED_NOT_VERIFIED", "demo")
    assert status == "UNRESOLVED" and any("helper==2.0" in item for item in uncertainty)


def test_demo_settings_never_change_gate_settings(scenario, service, tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(gate_adapter, "analyze_pipeline",
                        lambda *args, settings=None: seen.append(settings) or ("VERIFIED", {"nodes": [], "pipeline": [], "reason": ""}, []))
    _, context = scenario("safe")
    analyzer.analyze(context, service.store, tmp_path / "demo", lambda *a: None)
    context.gate = True
    analyzer.analyze(context, service.store, tmp_path / "gate", lambda *a: None)
    assert seen == [analyzer.DEMO_SETTINGS, None]
    # The gate keeps its live default (tests/conftest.py only replaces the demo's settings).
    assert gate_adapter.SETTINGS["transport"] is None and gate_adapter.SETTINGS["live_advisories"] is True


def test_disabled_trigger_rule_does_not_change_the_fast_gate(scenario, service, tmp_path):
    """The fast gate does not read trigger rules (they come in with PR 10), so disabling TRIG-ENV changes nothing."""
    run, context = scenario("safe")
    before = run_cavr(context, service, tmp_path, "before")[1]
    service.change_threats(record_id="TRIG-ENV", enabled=False)
    status, after, _, _ = run_cavr(fresh_context(service, run), service, tmp_path, "after")
    assert status == "VERIFIED", after["reason"]
    assert row(after, "pypdf")["key_fields"] == row(before, "pypdf")["key_fields"]


# --- the reachability proof and the vendored adapter of the cross_module repair ---------------------------------

INLINE_ADAPTER = '''from io import BytesIO
from pypdf import PdfReader, apply_configuration


def extract_invoice_text(content: bytes) -> str:
    with apply_configuration(jbig2dec_binary=None):
        return "\\n".join(page.extract_text() or "" for page in PdfReader(BytesIO(content)).pages)
'''


def test_inline_pdfreader_pages_form_is_unresolved_never_verified(tmp_path):
    """Known reachability limitation: the guard proof follows only `reader = PdfReader(...)` bound to one name.
    The same guarded call written inline cannot be followed, so the sink stays reachable: UNRESOLVED, escalated."""
    world = World(tmp_path)
    world.write("app/pdf_adapter.py", INLINE_ADAPTER)
    verdict = world.verify()
    assert (verdict["status"], verdict["rule"]) == ("UNRESOLVED", "SINK_REACHABLE"), verdict["reason"]
    assert verdict["escalated"] is True
    (proof,) = verdict["packages"][0]["evidence"]["reachability"]["proofs"]
    assert proof["accepted"] is False and "does not bind the reader to one plain name" in proof["reason"]


def test_repaired_cross_module_state_verifies_pypdf(scenario, service, tmp_path):
    """The reviewed replacement adapter binds the reader to a name, so the guard proof holds after the repair."""
    run, _ = scenario("cross_module")
    replace_lab(run.candidate_workspace)
    status, details, _, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    pypdf = row(details, "pypdf")
    assert (pypdf["status"], pypdf["rule"]) == ("VERIFIED", "ALL_CHECKS_PASSED"), pypdf["reason"]
    assert row(details, "invoice-pdf-safe")["engine"] == "demo-lab"


# --- fail-closed edges of a demo run (review of Step M2-1) -------------------------------------------------------

def frozen_dir(run):
    """The run's frozen copy of the base `.asent/` (what `ContextService` reads), next to the baseline workspace."""
    return Path(run.baseline_workspace).parent / FROZEN_DIR


def edit_lock(run, change):
    path = Path(run.candidate_workspace) / "dependencies.lock.json"
    lock = json.loads(path.read_text())
    change(lock)
    path.write_text(json.dumps(lock))


def test_local_wheel_in_the_lock_is_unresolved_never_verified(scenario, service, tmp_path):
    """A LOCAL wheel would carry its own Requires-Dist; the lab reads only .py sources, so it is not verified."""
    run, _ = scenario("safe")
    wheel = build_wheel(Path(run.candidate_workspace) / "vendor", "invoice-pdf-safe", "1.0.0", requires=("missing-dep>=1",))
    relative = wheel.relative_to(run.candidate_workspace).as_posix()
    edit_lock(run, lambda lock: lock["packages"].append({"name": "invoice-pdf-safe", "version": "1.0.0", "ecosystem": "LOCAL",
                                                          "artifact": relative, "sha256": sha256_file(wheel)}))
    status, details, uncertainty, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    local = row(details, "invoice-pdf-safe")
    assert (local["engine"], local["status"], local["rule"]) == ("demo-lab", "UNRESOLVED", "LOCAL_ARTIFACT_NOT_SUPPORTED")
    assert status == "UNRESOLVED" and any("LOCAL_ARTIFACT_NOT_SUPPORTED" in item for item in uncertainty)


def test_non_pypi_ecosystem_in_the_lock_is_unresolved(scenario, service, tmp_path):
    run, _ = scenario("safe")
    edit_lock(run, lambda lock: lock["packages"].append({"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"}))
    status, details, _, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    assert status == "UNRESOLVED" and row(details, "left-pad")["rule"] == "UNSUPPORTED_ECOSYSTEM"


@pytest.mark.parametrize("entry", [{"version": "1.0"}, {"name": "x", "version": 7}, "pypdf==6.21.4", {"name": " ", "version": "1"}])
def test_lock_entry_without_a_usable_name_and_version_is_unresolved(scenario, service, tmp_path, entry):
    run, _ = scenario("safe")
    edit_lock(run, lambda lock: lock["packages"].append(entry))
    status, details, _, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    # The entry itself is LOCK_ENTRY_INVALID; the pipeline cannot use the lockfile either, so pypdf is not verified.
    assert status == "UNRESOLVED" and "LOCK_ENTRY_INVALID" in [n.get("rule") for n in details["nodes"]]
    assert not any(n.get("status") == "VERIFIED" for n in details["nodes"])


@pytest.mark.parametrize("text", ["{not json", "[]", '{"packages": {"name": "pypdf"}}'])
def test_unreadable_lockfile_is_unresolved(scenario, service, tmp_path, text):
    run, _ = scenario("safe")
    (Path(run.candidate_workspace) / "dependencies.lock.json").write_text(text)
    status, _, uncertainty, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    assert status == "UNRESOLVED" and any("dependencies.lock.json" in item for item in uncertainty)


def test_missing_lockfile_is_judged_like_the_gate(scenario, service, tmp_path):
    """No lockfile: the same as a gate run. The exact pin is still verified (pypdf 6.21.4 has no dependencies);
    a dependency without a pin would be UNRESOLVED in the pipeline's tree stage."""
    run, _ = scenario("safe")
    (Path(run.candidate_workspace) / "dependencies.lock.json").unlink()
    status, details, _, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    assert status == "VERIFIED" and [n["name"] for n in details["nodes"]] == ["pypdf"]


def test_demo_run_without_a_frozen_cavr_config_is_unresolved(scenario, service, tmp_path):
    run, _ = scenario("safe")
    shutil.rmtree(frozen_dir(run))
    context = fresh_context(service, run)
    assert context.config is None
    status, details, _, _ = run_cavr(context, service, tmp_path)
    assert status == "UNRESOLVED" and "no usable CAVR section" in details["reason"]


def test_orchestrator_demo_run_with_the_6_19_0_pin_is_rejected(scenario, service, tmp_path):
    """The REJECTED demo case through `analyzer.analyze`: the pin changed in the candidate, approved by the base policy."""
    run, _ = scenario("safe")
    (Path(run.candidate_workspace) / "requirements.txt").write_text("pypdf==6.19.0\n")
    edit_lock(run, lambda lock: lock["packages"][0].update(version="6.19.0", sha256=PYPDF_SHA256))
    policy_path = frozen_dir(run) / "cavr" / "policy.json"
    policy_path.write_text(json.dumps({**json.loads(policy_path.read_text()), "approved_requirements": ["pypdf==6.19.0"]}))
    status, details, _, _ = run_cavr(fresh_context(service, run), service, tmp_path)
    pypdf = row(details, "pypdf")
    assert status == "REJECTED" and (pypdf["status"], pypdf["stage"], pypdf["rule"]) == ("REJECTED", "advisories", "KNOWN_VULNERABILITY")
    assert pypdf["advisories"][0]["advisory_count"] == 18 and pypdf["sha256"] == PYPDF_SHA256
