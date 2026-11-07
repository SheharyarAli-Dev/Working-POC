"""Step 4 of docs/dev-env-plan.md: the orchestrator takes its authority from a frozen base `.asent/`.

Real projects in tmp_path and the real InvoiceHub demo fixture; real Service runs where a decision is
checked. What must hold:

- the config is frozen into the run directory when the run is created and found again from the run's
  baseline, so every ContextService of that run (also ones built by tests) sees the same config;
- a config edit changes every module's input hash (old evidence is not reused);
- disabled modules are "not assessed (disabled by base config)" and never counted as passed;
- a module whose inputs exist but which has no section, or any invalid config, gives REVIEW;
- a gate run never falls back to the candidate's policy.json.
"""
import json
import shutil
from pathlib import Path

import pytest

from backend.config import ROOT
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.final_gate import decide
from backend.orchestrator.run_context import RunContext
from backend.orchestrator.service import Service
from backend.orchestrator.workspace_manager import WorkspaceManager
from backend.project_config import load
from backend.project_config.frozen import NOT_ASSESSED, frozen_config, policy_from_config

DEMO = ROOT / "demo_project" / "InvoiceHub"


def write(path: Path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data, indent=2))


def asent(root: Path, modules: dict, extra: dict | None = None):
    write(root / ".asent/config.json", {"schema_version": 1, "project": {"name": "t"}, "modules": modules})
    for name, body in (extra or {}).items():
        write(root / ".asent" / name, body)


CAVR_POLICY = {"project_task_description": "test service", "allowed_scopes": [], "approved_requirements": [],
               "denied_packages": []}


# --- the demo fixture uses the same mechanism --------------------------------------------------------

def test_demo_fixture_config_is_valid_and_mirrors_its_legacy_policy():
    result = load(DEMO / ".asent")
    assert result.valid, result.problems
    legacy = json.loads((DEMO / "policy.json").read_text())
    mapped = policy_from_config(result)
    for key in ("ownership", "dependencies", "infrastructure"):
        assert mapped[key] == legacy[key], key


def test_demo_fixture_trusted_tests_are_the_bundled_satra_tests():
    tests = DEMO / ".asent/satra/trusted_tests"
    pairs = {"conftest.py": "trusted_fixtures.py", "test_security.py": "trusted_security.py",
             "test_functional.py": "trusted_functional.py"}
    assert sorted(p.name for p in tests.iterdir()) == sorted(pairs)
    for copy, original in pairs.items():
        assert (tests / copy).read_bytes() == (ROOT / "backend/satra" / original).read_bytes(), copy


def test_demo_scenario_run_freezes_the_fixture_config(tmp_path):
    service = Service(tmp_path / "runtime")
    run = service.create("safe")
    assert run.config_digest == load(DEMO / ".asent").digest
    context = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot())
    assert context.config is not None and context.config.valid
    assert context.config.digest == run.config_digest
    assert not (Path(run.candidate_workspace) / ".asent").exists()  # never part of the candidate
    assert context.applicability() == ["CAVR", "SATRA", "SABLE"]
    assert all(entry["label"] == "assessed" for entry in context.coverage().values())


# --- config binding ------------------------------------------------------------------------------------

def test_config_edit_changes_every_module_input_hash(tmp_path):
    service = Service(tmp_path / "runtime")
    run = service.create("safe")
    knowledge = service.threats.snapshot()
    before = ContextService(run.candidate_workspace, run.baseline_workspace, knowledge)
    hashes = {m: before.input_hash(m) for m in ("CAVR", "SATRA", "SABLE")}
    (Path(run.baseline_workspace).parent / "asent/README.md").write_text("changed")
    after = ContextService(run.candidate_workspace, run.baseline_workspace, knowledge)
    assert all(after.input_hash(m) != hashes[m] for m in hashes)


def test_project_without_asent_keeps_the_legacy_policy_in_server_runs(tmp_path):
    project = tmp_path / "project"
    write(project / "policy.json", {"infrastructure": {"principal": "p"}})
    write(project / "app/main.py", "x = 1\n")
    run = Service(tmp_path / "runtime").create(source=project)
    context = ContextService(run.candidate_workspace, run.baseline_workspace)
    assert context.config is None and run.config_digest is None
    assert context.policy == {"infrastructure": {"principal": "p"}}
    assert "@config" not in context.inputs("SATRA")


def test_workspace_manager_requires_a_source(tmp_path):
    with pytest.raises(ValueError):
        WorkspaceManager(tmp_path / "w").create(RunContext(), None)


# --- final gate ----------------------------------------------------------------------------------------

def evidence(module, status, snapshot="s", input_hash="h"):
    return {"analyzer": module, "status": status, "stale": False, "integrity_valid": True,
            "candidate_snapshot": snapshot, "input_hash": input_hash, "blocking": status == "REJECTED"}


def test_extra_reasons_turn_accept_into_review():
    rows = [evidence("CAVR", "VERIFIED")]
    assert decide(["CAVR"], rows, "s", {"CAVR": "h"})[0] == "ACCEPT"
    decision, reasons, _ = decide(["CAVR"], rows, "s", {"CAVR": "h"}, extra_reasons=["ASENT config: x"])
    assert decision == "REVIEW" and "ASENT config: x" in reasons


def test_block_beats_a_config_review():
    decision, reasons, _ = decide(["CAVR"], [evidence("CAVR", "REJECTED")], "s", {"CAVR": "h"}, extra_reasons=["config changed"])
    assert decision == "BLOCK" and reasons[0] == "CAVR: REJECTED" and "config changed" in reasons


def test_no_applicable_module_with_extra_reasons_is_review():
    decision, reasons, _ = decide([], [], "s", {}, extra_reasons=["SATRA: applies but is not configured"])
    assert decision == "REVIEW" and "SATRA: applies but is not configured" in reasons


# --- coverage: disabled, absent, invalid -----------------------------------------------------------------

def mixed_project(root: Path):
    """CAVR enabled, SABLE disabled although .tf exists, SATRA absent although .py exists."""
    write(root / "requirements.txt", "")
    write(root / "infra/main.tf", "")
    write(root / "app/main.py", "x = 1\n")
    asent(root, {"CAVR": {"enabled": True}, "SABLE": {"enabled": False, "reason": "infra owned by another team"}},
          {"cavr/policy.json": CAVR_POLICY})
    return root


def test_disabled_and_absent_modules_in_coverage(tmp_path):
    run = Service(tmp_path / "runtime").create(source=mixed_project(tmp_path / "p"))
    context = ContextService(run.candidate_workspace, run.baseline_workspace)
    assert context.applicability() == ["CAVR"]
    coverage = context.coverage()
    assert coverage["SABLE"] == {"inputs_present": True, "state": "disabled", "assessed": False,
                                 "label": NOT_ASSESSED, "reason": "infra owned by another team"}
    assert coverage["SATRA"]["assessed"] is False and coverage["SATRA"]["state"] == "absent"
    assert context.config_reasons() == ["SATRA: applies but is not configured in base .asent/config.json"]


def test_disabled_modules_are_never_passed_and_absent_module_gives_review(tmp_path):
    service = Service(tmp_path / "runtime")
    run = service.create(source=mixed_project(tmp_path / "p"))
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "REVIEW"
    assert "SATRA: applies but is not configured in base .asent/config.json" in run.reasons
    assert {e["analyzer"] for e in service.store.evidence(run.run_id)} <= {"CAVR"}
    assert run.coverage["SABLE"]["label"] == NOT_ASSESSED
    report = service.report(run.run_id)
    assert report["coverage"]["SABLE"]["label"] == NOT_ASSESSED and report["coverage"]["SABLE"]["assessed"] is False
    assert report["config"]["digest"] == run.config_digest


def test_every_module_disabled_is_review(tmp_path):
    project = tmp_path / "p"
    write(project / "infra/main.tf", "")
    asent(project, {m: {"enabled": False, "reason": "not used"} for m in ("CAVR", "SATRA", "SABLE")})
    service = Service(tmp_path / "runtime")
    run = service.create(source=project)
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "REVIEW" and run.applicable == []
    assert run.coverage["SABLE"]["label"] == NOT_ASSESSED


def test_invalid_config_in_a_server_run_is_review_without_analysis(tmp_path):
    project = tmp_path / "p"
    write(project / "infra/main.tf", "")
    write(project / ".asent/config.json", "{broken")
    service = Service(tmp_path / "runtime")
    run = service.create(source=project)
    assert run.config_problems and run.config_problems[0].startswith("ASENT_CONFIG_JSON")
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "REVIEW" and run.applicable == []
    assert any(reason.startswith("ASENT config: ASENT_CONFIG_JSON") for reason in run.reasons)
    assert service.store.evidence(run.run_id) == []


def test_enabled_module_with_invalid_file_is_review(tmp_path):
    project = tmp_path / "p"
    write(project / "infra/main.tf", "")
    asent(project, {"SABLE": {"enabled": True}}, {"sable/obligations.json": {"obligations": []}})
    service = Service(tmp_path / "runtime")
    run = service.create(source=project)
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "REVIEW"
    assert any("ASENT_CONFIG_OBLIGATIONS" in reason for reason in run.reasons)


def test_symlinked_asent_in_source_is_not_copied_and_is_review(tmp_path):
    project = tmp_path / "p"
    write(project / "infra/main.tf", "")
    real = tmp_path / "real"
    asent(real, {"SABLE": {"enabled": False, "reason": "x"}})
    (project / ".asent").symlink_to(real / ".asent")
    service = Service(tmp_path / "runtime")
    run = service.create(source=project)
    assert any(p.startswith("ASENT_CONFIG_UNSAFE") for p in run.config_problems)
    assert not (Path(run.baseline_workspace).parent / "asent").exists()
    assert frozen_config(run.baseline_workspace).valid is False


# --- gate runs -------------------------------------------------------------------------------------------

def test_gate_run_uses_base_config_and_head_files(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    for root in (base, head):
        write(root / "infra/main.tf", "")
        asent(root, {"SABLE": {"enabled": False, "reason": "base says so"}})
    write(head / "infra/extra.tf", "# head only\n")
    run = Service(tmp_path / "runtime").create_gate_run(base, head, {"base": "b", "head": "h"})
    assert run.mode == "gate" and run.config_changed_in_head is False
    assert (Path(run.candidate_workspace) / "infra/extra.tf").exists()
    assert not (Path(run.baseline_workspace) / "infra/extra.tf").exists()
    context = ContextService(run.candidate_workspace, run.baseline_workspace)
    assert context.coverage()["SABLE"]["reason"] == "base says so"


def test_gate_run_flags_a_head_config_change(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    asent(base, {"SABLE": {"enabled": False, "reason": "x"}})
    asent(head, {"SABLE": {"enabled": False, "reason": "head edited the config"}})
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    assert run.config_changed_in_head is True
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "REVIEW"
    assert "ASENT configuration changed in this change; requires maintainer review" in run.reasons
    context = ContextService(run.candidate_workspace, run.baseline_workspace)
    assert context.coverage()["SABLE"]["reason"] == "x"  # base wins


def test_gate_run_without_base_config_never_falls_back_to_policy_json(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    for root in (base, head):
        write(root / "policy.json", {"infrastructure": {"principal": "p"}})
        write(root / "infra/main.tf", "")
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    assert run.config_problems and run.config_problems[0].startswith("ASENT_CONFIG_MISSING")
    context = ContextService(run.candidate_workspace, run.baseline_workspace)
    assert context.policy == {} and context.applicability() == []
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "REVIEW" and service.store.evidence(run.run_id) == []


def test_gate_run_is_never_repaired(tmp_path):
    base, head = tmp_path / "base", tmp_path / "head"
    for root in (base, head):
        write(root / "infra/main.tf", "")
        asent(root, {"SABLE": {"enabled": False, "reason": "x"}})
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    service.analyze(run.run_id, auto_repair=True)
    assert not any(e["kind"].startswith("repair.") for e in service.store.events(run.run_id))
