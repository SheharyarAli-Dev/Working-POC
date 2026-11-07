"""Step 5 of docs/dev-env-plan.md: in a gate run CAVR is the M1 pipeline, mapped onto the orchestrator.

Real gate runs (Service.create_gate_run on real base/head directories with a base `.asent/`), the real
pypdf 6.19.0 wheel and its recorded registry answer served by `FakeIndex`, and advisory answers in the
exact OSV cache format (recorded "none" for pypdf 6.19.0; one hand-written SYNTH- advisory where a
REJECTED verdict is needed). Mapping: VERIFIED -> VERIFIED, REJECTED and BLOCK -> REJECTED, anything
else -> UNRESOLVED.
"""
import json
import shutil
from pathlib import Path

import pytest

from backend.cavr import analyzer as cavr_analyzer
from backend.cavr import gate_adapter
from backend.cavr.context_extractor import SAMPLE_PROJECT_DIR
from backend.cavr.pypi_client import TransportError
from backend.cavr.verdict_cache import KEY_FIELDS
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.service import Service
from test_cavr_support import (FakeIndex, INVOICEHUB, POLICY, PYPDF_SHA256, RECORDED_6_19_0, synthetic_advisory,
                               write_osv_cache)


class Gate:
    def __init__(self, tmp_path, monkeypatch, base_requirements="pypdf==6.19.0\n", head_requirements="pypdf==6.19.0\n",
                 policy=None, cavr=None, head_files=None):
        self.tmp_path = tmp_path
        self.base, self.head = tmp_path / "base", tmp_path / "head"
        cavr_section = {"enabled": True, "requirements_files": ["requirements.txt"], **(cavr or {})}
        for root, requirements in ((self.base, base_requirements), (self.head, head_requirements)):
            shutil.copytree(INVOICEHUB / "app", root / "app")
            if requirements is not None:
                (root / "requirements.txt").write_text(requirements)
            (root / ".asent/cavr").mkdir(parents=True)
            (root / ".asent/config.json").write_text(json.dumps({"schema_version": 1, "project": {"name": "t"}, "modules": {
                "CAVR": cavr_section,
                "SATRA": {"enabled": False, "reason": "not part of this test"},
                "SABLE": {"enabled": False, "reason": "not part of this test"}}}))
            (root / ".asent/cavr/policy.json").write_text(json.dumps(policy or POLICY))
        for name, text in (head_files or {}).items():
            (self.head / name).parent.mkdir(parents=True, exist_ok=True)
            (self.head / name).write_text(text)
        self.index = FakeIndex()
        self.index.add_pypdf()
        self.osv = tmp_path / "osv"
        write_osv_cache(self.osv, "pypdf", "6.19.0", RECORDED_6_19_0)
        monkeypatch.setattr(gate_adapter, "SETTINGS", {"transport": self.index, "osv": None,
                                                       "advisory_cache_dir": self.osv, "live_advisories": False})
        self.service = Service(tmp_path / "runtime")
        self.run = self.service.create_gate_run(self.base, self.head, {"base": "b", "head": "h"})
        self.events = []

    def context(self):
        return ContextService(self.run.candidate_workspace, self.run.baseline_workspace, self.service.threats.snapshot(), gate=True)

    def analyze(self):
        out = self.tmp_path / "runtime/evidence" / self.run.run_id / "1-analysis-CAVR"
        return gate_adapter.analyze_pipeline(self.context(), self.service.store, out, lambda kind, data: self.events.append((kind, data)))


def test_approved_pin_is_verified_with_the_eight_field_key(tmp_path, monkeypatch):
    status, details, uncertainty = Gate(tmp_path, monkeypatch).analyze()
    assert status == "VERIFIED", details["reason"]
    assert details["engine"] == "pipeline"
    (entry,) = details["pipeline"]
    assert entry["file"] == "requirements.txt" and entry["status"] == "VERIFIED" and entry["rule"] == "ALL_CHECKS_PASSED"
    (node,) = details["nodes"]
    assert node["name"] == "pypdf" and node["sha256"] == PYPDF_SHA256 and node["status"] == "VERIFIED"
    assert set(node["key_fields"]) == set(KEY_FIELDS) and node["key_fields"]["artifact_sha256"] == PYPDF_SHA256
    assert any("deep" in item for item in uncertainty)


def test_denied_package_is_rejected_without_a_download(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch, head_requirements="pypdf==6.19.0\nreqeusts==2.31.0\n")
    status, details, _ = gate.analyze()
    assert status == "REJECTED"
    assert details["pipeline"][0]["status"] == "BLOCK" and details["pipeline"][0]["stage"] == "gate"
    assert gate.index.downloads() == []


def test_affected_version_is_rejected_by_the_advisory_range(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch)
    write_osv_cache(gate.osv, "pypdf", "6.19.0", [synthetic_advisory("SYNTH-PYPDF-1", "pypdf", introduced="6.0.0", fixed="6.20.0")])
    status, details, _ = gate.analyze()
    assert status == "REJECTED" and details["pipeline"][0]["status"] == "REJECTED"
    assert details["pipeline"][0]["stage"] == "advisories"


def test_unpinned_requirement_is_blocked_by_the_requirement_gate(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch, head_requirements="pypdf>=6\n")
    status, details, _ = gate.analyze()
    entry = details["pipeline"][0]
    assert status == "REJECTED" and (entry["status"], entry["stage"], entry["rule"]) == ("BLOCK", "gate", "NOT_PINNED")
    assert gate.index.downloads() == []


def test_tampered_wheel_is_not_verified(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch)
    url = next(u for u in gate.index.routes if u.endswith(".whl"))
    body = bytearray(gate.index.routes[url]); body[100] ^= 1; gate.index.routes[url] = bytes(body)
    status, details, _ = gate.analyze()
    entry = details["pipeline"][0]
    assert status == "REJECTED" and (entry["status"], entry["stage"], entry["rule"]) == ("REJECTED", "artifact", "HASH_MISMATCH")


def test_network_off_is_unresolved(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch)
    for url in list(gate.index.routes):
        gate.index.routes[url] = TransportError("ConnectError: the network is off")
    status, details, _ = gate.analyze()
    assert status == "UNRESOLVED" and details["pipeline"][0]["status"] == "UNRESOLVED"


def test_only_pyproject_dependencies_is_unsupported(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch, base_requirements=None, head_requirements=None,
                head_files={"pyproject.toml": '[project]\nname = "x"\ndependencies = ["pypdf==6.19.0"]\n'})
    status, details, _ = gate.analyze()
    assert status == "UNRESOLVED" and "unsupported manifest" in details["reason"] and "pyproject.toml" in details["reason"]
    assert gate.index.calls == []


@pytest.mark.parametrize("name,text", [("setup.py", "from setuptools import setup\nsetup()\n"), ("poetry.lock", ""),
                                       ("package.json", "{}"), ("Pipfile", "")])
def test_other_unverified_manifests_next_to_requirements_are_unresolved(tmp_path, monkeypatch, name, text):
    status, details, _ = Gate(tmp_path, monkeypatch, head_files={name: text}).analyze()
    assert status == "UNRESOLVED" and name in details["reason"]


def test_pyproject_for_tool_settings_only_is_fine(tmp_path, monkeypatch):
    status, details, _ = Gate(tmp_path, monkeypatch, head_files={"pyproject.toml": "[tool.black]\nline-length = 100\n"}).analyze()
    assert status == "VERIFIED", details["reason"]


def test_configured_requirements_file_missing_in_head(tmp_path, monkeypatch):
    status, details, _ = Gate(tmp_path, monkeypatch, head_requirements=None).analyze()
    assert status == "UNRESOLVED" and "requirements.txt" in details["reason"]


def test_changed_mode_without_an_edit_is_verified_at_the_gate_stage(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch, cavr={"verify": "changed"})
    status, details, _ = gate.analyze()
    assert status == "VERIFIED" and details["pipeline"][0]["stage"] == "gate"
    assert gate.index.calls == []


def test_changed_mode_with_a_denied_addition_is_rejected(tmp_path, monkeypatch):
    status, details, _ = Gate(tmp_path, monkeypatch, cavr={"verify": "changed"},
                              head_requirements="pypdf==6.19.0\nreqeusts==2.31.0\n").analyze()
    assert status == "REJECTED" and details["pipeline"][0]["status"] == "BLOCK"


@pytest.mark.parametrize("pipeline_status,expected", [("VERIFIED", "VERIFIED"), ("REJECTED", "REJECTED"), ("BLOCK", "REJECTED"),
                                                      ("UNRESOLVED", "UNRESOLVED"), ("SOMETHING_NEW", "UNRESOLVED"), (None, "UNRESOLVED")])
def test_status_mapping(pipeline_status, expected):
    assert gate_adapter.map_status(pipeline_status) == expected


def test_unknown_pipeline_status_through_the_adapter(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch)
    monkeypatch.setattr(gate_adapter, "verify_request", lambda *a, **k: {"status": "SOMETHING_NEW", "stage": "x", "rule": "y", "reason": "z", "packages": []})
    assert gate.analyze()[0] == "UNRESOLVED"


def test_pipeline_gets_the_candidate_directory_never_the_sample_project(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch)
    seen = []
    real = gate_adapter.verify_request
    monkeypatch.setattr(gate_adapter, "verify_request", lambda request, project_dir, *a, **k: seen.append(Path(project_dir)) or real(request, project_dir, *a, **k))
    context = gate.context()
    gate_adapter.analyze_pipeline(context, gate.service.store, tmp_path / "out", lambda *a: None)
    assert seen == [context.path] and SAMPLE_PROJECT_DIR not in seen


def test_disabled_cavr_config_is_unresolved(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch, cavr={"enabled": False, "reason": "x"})
    assert gate.analyze()[0] == "UNRESOLVED"


def test_gate_context_dispatches_to_the_pipeline_and_demo_context_does_not(tmp_path, monkeypatch, scenario):
    gate = Gate(tmp_path, monkeypatch)
    out = tmp_path / "runtime/evidence/x"
    status, details, _ = cavr_analyzer.analyze(gate.context(), gate.service.store, out, lambda *a: None)
    assert details["engine"] == "pipeline" and status == "VERIFIED"
    called = []
    monkeypatch.setattr(gate_adapter, "analyze_pipeline", lambda *a, **k: called.append(1))
    run, demo_context = scenario("safe")
    assert demo_context.gate is False
    cavr_analyzer.analyze(demo_context, gate.service.store, tmp_path / "demo-out", lambda *a: None)
    assert called == []


def test_gate_run_through_the_service_publishes_pipeline_evidence(tmp_path, monkeypatch):
    gate = Gate(tmp_path, monkeypatch)
    gate.service.analyze(gate.run.run_id)
    run = gate.service.store.run(gate.run.run_id)
    (row,) = [e for e in gate.service.store.evidence(run.run_id) if e["analyzer"] == "CAVR"]
    assert row["status"] == "VERIFIED" and row["details"]["engine"] == "pipeline"
    assert run.final_decision == "ACCEPT", run.reasons
    assert run.coverage["SATRA"]["state"] == "disabled"
