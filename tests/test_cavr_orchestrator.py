"""Plan step 14: the orchestrator's CAVR analyzer delegates every dependency decision to `pipeline.verify_request`.

The path under test is the one `POST /api/runs` takes: `Service.create` -> `Service.analyze` ->
`Service._module` -> `analyzer.analyze` -> `final_gate.decide`.

Offline. What is real: the InvoiceHub demo project, the pypdf 6.19.0 wheel and its recorded registry
response, the recorded OSV answer for pypdf 6.19.0, the SATRA and SABLE runs. A test that wants
another outcome changes the bytes, the network or the project, never the verdict.
"""
import ast
import json
from pathlib import Path

import pytest

from backend.cavr import analyzer
from backend.cavr.pypi_client import TransportError
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.service import Service
from test_cavr_support import PYPDF_WHEEL, FakeIndex, pypdf_registry_response

pytestmark = pytest.mark.integration


class NoNetwork:
    """A transport for a machine without a network: every URL fails, and every attempt is recorded."""

    def __init__(self):
        self.calls = []

    def stream(self, url):
        self.calls.append(url)
        raise TransportError(f"network unreachable: {url}")
        yield b""  # makes this a generator, like the real transport


def current(svc, run, module):
    return [e for e in svc.store.evidence(run.run_id) if e["analyzer"] == module and not e["stale"]][-1]


def flip_one_byte(index):
    """Serve the pypdf wheel with one bit changed; the registry response still names the real digest."""
    url = pypdf_registry_response()["urls"][0]["url"]
    data = bytearray(PYPDF_WHEEL.read_bytes())
    data[len(data) // 2] ^= 0x01
    index.routes[url] = bytes(data)


@pytest.fixture
def index(monkeypatch):
    """The recorded PyPI for this test; the advisory cache is the session's recorded one (conftest.py)."""
    index = FakeIndex()
    index.add_pypdf()
    monkeypatch.setattr(analyzer, "TRANSPORT", index)
    return index


@pytest.fixture
def svc(tmp_path, index):
    return Service(tmp_path / "runtime")


def context_of(svc, run):
    return ContextService(run.candidate_workspace, run.baseline_workspace, svc.threats.snapshot())


# --- the four pipeline verdicts drive the final gate -------------------------------------------------------

def no_change(candidate, index, monkeypatch):
    pass


def tampered_wheel(candidate, index, monkeypatch):
    flip_one_byte(index)


def name_not_in_policy(candidate, index, monkeypatch):
    (candidate / "requirements.txt").write_text("left-pad==1.0\n")


def network_off(candidate, index, monkeypatch):
    monkeypatch.setattr(analyzer, "TRANSPORT", NoNetwork())


@pytest.mark.parametrize("condition,pipeline_status,rule,module_status,decision", [
    (no_change, "VERIFIED", "ALL_CHECKS_PASSED", "VERIFIED", "ACCEPT"),
    (tampered_wheel, "REJECTED", "HASH_MISMATCH", "REJECTED", "BLOCK"),
    (name_not_in_policy, "BLOCK", "NOT_ON_ALLOWLIST", "REJECTED", "BLOCK"),
    (network_off, "UNRESOLVED", None, "UNRESOLVED", "REVIEW"),
], ids=["verified-accept", "rejected-block", "block-block", "unresolved-review"])
def test_each_pipeline_verdict_drives_the_final_gate(svc, index, monkeypatch, condition, pipeline_status, rule,
                                                      module_status, decision):
    run = svc.create("safe")
    condition(Path(run.candidate_workspace), index, monkeypatch)
    svc.analyze(run.run_id)
    run = svc.store.run(run.run_id)
    cavr = current(svc, run, "CAVR")

    # The pipeline decided, and the analyzer passed its verdict on.
    assert cavr["details"]["pipeline_status"] == pipeline_status, cavr["details"]["reason"]
    assert cavr["details"]["pipeline"]["status"] == pipeline_status
    if rule:
        assert cavr["details"]["pipeline"]["rule"] == rule
    assert cavr["status"] == module_status
    assert cavr["blocking"] is (module_status == "REJECTED")

    # The other modules accept the unchanged InvoiceHub, so the decision is CAVR's.
    assert current(svc, run, "SATRA")["status"] == "ACCEPT"
    assert current(svc, run, "SABLE")["status"] == "PRESERVED"
    assert run.final_decision == decision, run.reasons
    if decision != "ACCEPT":
        assert any(reason.startswith("CAVR: ") for reason in run.reasons), run.reasons
    else:
        assert run.clean_commit


def test_a_gate_block_downloads_nothing(svc, index):
    run = svc.create("safe")
    name_not_in_policy(Path(run.candidate_workspace), index, None)
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert (status, details["pipeline_status"]) == ("REJECTED", "BLOCK")
    assert index.downloads() == [] and index.calls == []
    assert "requirement gate" in details["reason"]


def test_network_loss_is_unresolved_and_says_why(svc, monkeypatch):
    run = svc.create("safe")
    offline = NoNetwork()
    monkeypatch.setattr(analyzer, "TRANSPORT", offline)
    status, details, uncertainty = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert status == "UNRESOLVED" and offline.calls
    assert "network unreachable" in details["reason"] and uncertainty


# --- fail closed: a fault is never a pass -----------------------------------------------------------------

@pytest.mark.parametrize("fault", [
    RuntimeError("stage crashed"),
    None,
    {"status": "PASS"},
    {"status": "VERIFIED"},             # a VERIFIED without its packages is not a proof
    {"status": "VERIFIED", "packages": "not a list"},
], ids=["exception", "none", "unknown-status", "verified-without-packages", "verified-malformed-packages"])
def test_a_fault_or_an_unknown_verdict_is_unresolved(svc, monkeypatch, fault):
    def fake_verify_request(*args, **kwargs):
        if isinstance(fault, Exception):
            raise fault
        return fault

    monkeypatch.setattr(analyzer, "verify_request", fake_verify_request)
    run = svc.create("safe")
    status, details, uncertainty = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert status == "UNRESOLVED", details
    assert details["reason"] and uncertainty
    json.dumps(details)


def test_an_exception_in_the_analyzer_reaches_the_final_gate_as_review(svc, monkeypatch):
    monkeypatch.setattr(analyzer, "verify_request", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stage crashed")))
    run = svc.create("safe")
    svc.analyze(run.run_id)
    run = svc.store.run(run.run_id)
    cavr = current(svc, run, "CAVR")
    assert cavr["status"] == "UNRESOLVED" and "stage crashed" in cavr["details"]["reason"]
    assert run.final_decision == "REVIEW" and "CAVR: UNRESOLVED" in run.reasons


def test_an_emit_that_fails_is_unresolved_not_a_lost_verdict(svc):
    def broken_emit(kind, data):
        raise OSError("event store unavailable")

    run = svc.create("safe")
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, broken_emit)
    assert status == "UNRESOLVED" and "event store unavailable" in details["reason"]


# --- what the pipeline does not cover is not a pass -------------------------------------------------------

def local_entries(details):
    return [(e["name"], e["status"], e["rule"], e["escalation"]) for e in details["lock_entries"] if e["ecosystem"] == "LOCAL"]


def test_a_local_artifact_has_no_m1_verdict_and_is_unresolved(svc):
    """A LOCAL entry next to a VERIFIED pypdf: the verdict says nothing about the vendored file."""
    run = svc.create("safe")
    candidate = Path(run.candidate_workspace)
    (candidate / "vendor").mkdir()
    (candidate / "vendor" / "helper.py").write_text("VALUE = 1\n")
    lock = json.loads((candidate / "dependencies.lock.json").read_text())
    lock["packages"].append({"name": "helper", "version": "1.0.0", "ecosystem": "LOCAL", "artifact": "vendor/helper.py"})
    (candidate / "dependencies.lock.json").write_text(json.dumps(lock))
    status, details, uncertainty = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert (details["pipeline_status"], status) == ("VERIFIED", "UNRESOLVED")
    assert local_entries(details) == [("helper", "UNRESOLVED", "LOCAL_ARTIFACT_UNVERIFIED", "deep analysis required (M2)")]
    assert "helper==1.0.0" in details["reason"] and any("helper" in line for line in uncertainty)
    # `nodes` holds what the pipeline verified; a vendored file is never one of them.
    assert [node["name"] for node in details["nodes"]] == ["pypdf"]


def test_the_lab_scenario_reaches_pypdf_outside_the_guard_and_is_escalated(svc):
    """cavr_canary: the vendored lab file calls PdfReader outside apply_configuration, so pypdf's subprocess sink is reachable."""
    run = svc.create("cavr_canary")
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    pipeline = details["pipeline"]
    assert (status, pipeline["status"], pipeline["rule"], pipeline["escalation"]) == (
        "UNRESOLVED", "UNRESOLVED", "SINK_REACHABLE", "deep analysis required (M2)")
    assert local_entries(details) == [("invoice-pdf-lab", "UNRESOLVED", "LOCAL_ARTIFACT_UNVERIFIED", "deep analysis required (M2)")]
    assert "SINK_REACHABLE" in details["reason"] and "invoice-pdf-lab==1.0.0" in details["reason"]
    pypdf = next(e for e in details["lock_entries"] if e["name"] == "pypdf")
    assert (pypdf["status"], pypdf["rule"]) == ("NOT_VERIFIED", "VERDICT_NOT_VERIFIED")


@pytest.mark.parametrize("tamper", [False, True], ids=["lab-unresolved", "lab-with-rejected-pypdf"])
def test_the_sandbox_is_not_reached_from_the_orchestrator_path(svc, index, monkeypatch, tamper):
    """Even with `auto_repair` and a REJECTED CAVR, no counterfactual run starts (the sandbox is M2)."""
    calls = []
    monkeypatch.setattr("backend.orchestrator.service.run_counterfactual", lambda *a, **k: calls.append(a))
    monkeypatch.setattr("backend.cavr.sandbox.run_counterfactual", lambda *a, **k: calls.append(a))
    if tamper:
        flip_one_byte(index)
    run = svc.create("cavr_canary")
    svc.analyze(run.run_id, auto_repair=True)
    run = svc.store.run(run.run_id)
    kinds = {event["kind"] for event in svc.store.events(run.run_id)}
    assert calls == []
    assert not kinds & {"cavr.counterfactual_started", "cavr.repair_candidate_checked", "repair.applied"}
    assert current(svc, run, "CAVR")["status"] == ("REJECTED" if tamper else "UNRESOLVED")
    assert run.final_decision == ("BLOCK" if tamper else "REVIEW") and run.lifecycle == "COMPLETE"


def test_a_locked_package_the_request_does_not_reach_is_unresolved(svc):
    run = svc.create("safe")
    lock_path = Path(run.candidate_workspace) / "dependencies.lock.json"
    lock = json.loads(lock_path.read_text())
    lock["packages"].append({"name": "left-pad", "version": "1.0", "ecosystem": "PyPI"})
    lock_path.write_text(json.dumps(lock))
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert (details["pipeline_status"], status) == ("VERIFIED", "UNRESOLVED")
    entry = next(e for e in details["lock_entries"] if e["name"] == "left-pad")
    assert (entry["status"], entry["rule"]) == ("UNRESOLVED", "LOCKED_NOT_VERIFIED")
    pypdf = next(e for e in details["lock_entries"] if e["name"] == "pypdf")
    assert (pypdf["status"], pypdf["rule"]) == ("VERIFIED", "COVERED_BY_VERDICT")


def test_disabled_seed_rule_makes_a_verified_verdict_unresolved(svc):
    run = svc.create("safe")
    svc.change_threats(record_id="TRIG-ENV", enabled=False)
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert details["pipeline_status"] == "VERIFIED" and status == "UNRESOLVED"
    assert details["rule_coverage"] == ["Required rule coverage unavailable: TRIG-ENV"]


# --- policy: the project's policy.json, translated ----------------------------------------------------------

def test_gate_policy_maps_dependencies_allowed_and_the_denied_flags():
    policy = analyzer.gate_policy({"dependencies": {"allowed": ["pypdf", "Invoice_PDF_Lab"], "purpose": "PDF text extraction",
                                                    "allow_network": False, "allow_process": False, "allow_secret": True}})
    assert policy["approved_requirements"] == ["invoice-pdf-lab", "pypdf"]
    assert policy["denied_packages"] == []
    assert policy["project_task_description"] == "PDF text extraction"
    # A flag that is false is a denial; a flag that is true names no scope, so it grants nothing.
    assert policy["allowed_scopes"] == ["NETWORK_CONNECT:none", "PROCESS_EXEC:none"]
    secret_denied = analyzer.gate_policy({"dependencies": {"allowed": [], "allow_secret": False, "allow_network": "no"}})
    assert secret_denied["allowed_scopes"] == ["SECRET_READ:none"]  # only a JSON false is a denial


@pytest.mark.parametrize("project_policy", [
    {}, None, "text", {"dependencies": None}, {"dependencies": {}}, {"dependencies": {"allowed": "pypdf"}},
    {"dependencies": {"allowed": ["pypdf", 3]}}, {"dependencies": {"allowed": ["pypdf>=1"]}},
    {"dependencies": {"allowed": ["pypdf"], "purpose": 7}},
], ids=["empty", "none", "text", "dependencies-none", "no-allowed", "allowed-text", "allowed-not-text",
        "allowed-with-specifier", "purpose-not-text"])
def test_a_policy_that_cannot_be_mapped_is_no_policy(project_policy):
    assert analyzer.gate_policy(project_policy) is None


def test_a_project_without_dependencies_allowed_is_unresolved(svc, index):
    run = svc.create("safe")
    policy_path = Path(run.candidate_workspace) / "policy.json"
    policy = json.loads(policy_path.read_text())
    del policy["dependencies"]
    policy_path.write_text(json.dumps(policy))
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    assert (status, details["pipeline_status"], details["pipeline"]["rule"]) == ("UNRESOLVED", "UNRESOLVED", "POLICY_MISSING")
    assert index.calls == []


# --- the 8-field cache and the evidence the orchestrator reads ----------------------------------------------

def test_the_second_analysis_is_a_cache_hit_that_rechecks_advisories(svc):
    run = svc.create("safe")
    context = context_of(svc, run)
    first = analyzer.analyze(context, svc.store, None, lambda *a: None)
    events = []
    second = analyzer.analyze(context, svc.store, None, lambda kind, data: events.append((kind, data)))
    assert first[0] == second[0] == "VERIFIED"
    assert first[1]["pipeline"]["cache_hit"] is False and second[1]["pipeline"]["cache_hit"] is True
    package = second[1]["pipeline"]["packages"][0]
    assert set(package["key_fields"]) == {"ecosystem", "name", "version", "artifact_sha256", "subtree_digest",
                                          "contract_digest", "policy_version", "analyzer_version"}
    assert [a["rule"] for a in package["evidence"]["advisories"]] == ["NO_KNOWN_VULNERABILITY"]
    assert ("cavr.cache_hit", {"package": "pypdf", "version": "6.19.0", "cache_key": package["cache"]["key"]}) in events


def test_the_evidence_keeps_the_fields_the_orchestrator_reads(svc):
    run = svc.create("safe")
    status, details, _ = analyzer.analyze(context_of(svc, run), svc.store, None, lambda *a: None)
    node = details["nodes"][0]
    # Service.report reads name / version / sha256 / artifact; Service._repair reads name.
    assert (node["name"], node["version"], node["status"]) == ("pypdf", "6.19.0", "VERIFIED")
    assert node["sha256"] == "7e5d6e730e7dae87d560a2cee218b852f6498c8be61966f3cd02ead971e48d14"
    assert node["artifact"] == "pypdf-6.19.0-py3-none-any.whl"
    assert details["dependency_tree"]["nodes"] == [{"id": "pypdf", "version": "6.19.0"}]
    json.dumps(details)


@pytest.mark.parametrize("pipeline_status,module_status", [
    ("VERIFIED", "VERIFIED"), ("REJECTED", "REJECTED"), ("BLOCK", "REJECTED"), ("UNRESOLVED", "UNRESOLVED")])
def test_the_status_map_is_the_one_documented(pipeline_status, module_status):
    assert analyzer.MODULE_STATUS[pipeline_status] == module_status
    # The final gate has no RESTRICTED from CAVR to accept: the analyzer never returns it.
    assert "RESTRICTED" not in analyzer.MODULE_STATUS.values()


def test_the_orchestrator_analyzer_does_not_import_the_sandbox():
    tree = ast.parse(Path(analyzer.__file__).read_text())
    imported = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    imported |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    assert not imported & {"backend.cavr.sandbox", "backend.cavr.m2_deep_analyzer", "backend.cavr.policy",
                           "backend.cavr.counterfactual", "backend.cavr.sandbox_runner"}
