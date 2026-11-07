"""Step 7 of docs/dev-env-plan.md: SABLE in gate runs evaluates every obligation of the base config.

Real gate runs; Terraform from the demo project (base) and the built-in SABLE scenario folders (head),
the same files the catalog scenarios use. Aggregation: any REGRESSED -> REGRESSED, else any UNKNOWN ->
UNKNOWN, else PRESERVED. Terraform outside the configured directories is UNKNOWN.
"""
import json
import shutil
from pathlib import Path

import pytest

from backend.config import ROOT
from backend.orchestrator.context_service import ContextService
from backend.orchestrator.service import Service
from backend.project_config import load
from backend.sable import analyzer as sable_analyzer

DEMO_INFRA = ROOT / "demo_project/InvoiceHub/infra"
SCENARIOS = ROOT / "scenarios/sable"
INVOICE = {"id": "invoice-data", "principal": "aws_iam_role.app", "protected_asset": "aws_s3_bucket.invoice_data",
           "actions": ["s3:GetObject", "s3:PutObject"]}


def project(root: Path, infra: Path, obligations, sable=None, extra=None):
    shutil.copytree(infra, root / "infra")
    files = {".asent/config.json": json.dumps({"schema_version": 1, "project": {"name": "t"}, "modules": {
                 "SABLE": {"enabled": True, **(sable or {})},
                 "CAVR": {"enabled": False, "reason": "not in this test"}, "SATRA": {"enabled": False, "reason": "not in this test"}}}),
             ".asent/sable/obligations.json": json.dumps({"obligations": obligations})}
    files.update(extra or {})
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text)
    return root


def gate(tmp_path, head_infra, obligations=(INVOICE,), sable=None, head_extra=None, base_extra=None):
    base = project(tmp_path / "base", DEMO_INFRA, list(obligations), sable, base_extra)
    head = project(tmp_path / "head", head_infra, list(obligations), sable, head_extra)
    service = Service(tmp_path / "runtime")
    run = service.create_gate_run(base, head, {})
    context = ContextService(run.candidate_workspace, run.baseline_workspace, service.threats.snapshot(), gate=True)
    return sable_analyzer.analyze(context, lambda *a: None), service, run


@pytest.mark.parametrize("case,expected", [("preserved", "PRESERVED"), ("regressed", "REGRESSED"), ("widened", "REGRESSED"),
                                           ("unknown", "UNKNOWN"), ("unresolved_role_binding", "UNKNOWN")])
def test_single_obligation_matches_the_catalog_scenarios(tmp_path, case, expected):
    (status, details, _), _, _ = gate(tmp_path, SCENARIOS / case)
    assert status == expected, details["reason"]
    assert details["mode"] == "configured" and [o["id"] for o in details["obligations"]] == ["invoice-data"]


def test_unchanged_infrastructure_is_preserved(tmp_path):
    (status, details, _), _, _ = gate(tmp_path, DEMO_INFRA)
    assert status == "PRESERVED", details["reason"]


def test_two_obligations_one_regressed(tmp_path):
    # Two Terraform roots: infra/ regresses in head, platform/ is unchanged.
    platform = {f"platform/{p.name}": p.read_text() for p in DEMO_INFRA.glob("*.tf")}
    kept = {**INVOICE, "id": "platform-data", "terraform_dir": "platform"}
    (status, details, _), _, _ = gate(tmp_path, SCENARIOS / "regressed", [INVOICE, kept], {"terraform_dirs": ["infra", "platform"]},
                                      head_extra=platform, base_extra=platform)
    assert status == "REGRESSED"
    assert {o["id"]: o["status"] for o in details["obligations"]} == {"invoice-data": "REGRESSED", "platform-data": "PRESERVED"}
    assert details["reason"].startswith("invoice-data: REGRESSED")


def test_obligation_that_does_not_hold_on_the_base_is_unknown(tmp_path):
    read_only = {**INVOICE, "id": "invoice-read", "actions": ["s3:GetObject"]}
    (status, details, _), _, _ = gate(tmp_path, DEMO_INFRA, [read_only])
    assert status == "UNKNOWN" and "Baseline least-privilege obligation is not independently verified" in details["reason"]


def test_one_unknown_obligation_makes_the_module_unknown(tmp_path):
    missing = {**INVOICE, "id": "ghost", "protected_asset": "aws_s3_bucket.does_not_exist"}
    (status, details, _), _, _ = gate(tmp_path, DEMO_INFRA, [INVOICE, missing])
    assert status == "UNKNOWN"
    assert {o["id"]: o["status"] for o in details["obligations"]} == {"invoice-data": "PRESERVED", "ghost": "UNKNOWN"}


def test_terraform_outside_the_configured_dirs_is_unknown(tmp_path):
    (status, details, _), _, _ = gate(tmp_path, DEMO_INFRA, head_extra={"deploy/extra.tf": 'resource "aws_s3_bucket" "x" {}\n'})
    assert status == "UNKNOWN" and "deploy/extra.tf" in details["reason"]


def test_obligation_in_a_second_terraform_root(tmp_path):
    second = {**INVOICE, "id": "second-root", "terraform_dir": "platform"}
    sable = {"terraform_dirs": ["infra", "platform"]}
    extra = {f"platform/{p.name}": p.read_text() for p in DEMO_INFRA.glob("*.tf")}
    (status, details, _), _, _ = gate(tmp_path, DEMO_INFRA, [INVOICE, second], sable, head_extra=extra, base_extra=extra)
    assert status == "PRESERVED", details["reason"]
    assert {o["id"]: o["terraform_dir"] for o in details["obligations"]} == {"invoice-data": "infra", "second-root": "platform"}


def test_obligation_naming_an_unconfigured_root_is_invalid_config(tmp_path):
    root = project(tmp_path / "p", DEMO_INFRA, [{**INVOICE, "terraform_dir": "elsewhere"}])
    result = load(root / ".asent")
    assert not result.valid and any(p.startswith("ASENT_CONFIG_OBLIGATIONS") and "elsewhere" in p for p in result.problems)


def test_gate_run_decision_for_a_regression(tmp_path):
    _, service, run = gate(tmp_path, SCENARIOS / "regressed")
    service.analyze(run.run_id)
    run = service.store.run(run.run_id)
    assert run.final_decision == "BLOCK" and "SABLE: REGRESSED" in run.reasons


def test_demo_context_keeps_the_single_obligation_path(scenario, monkeypatch):
    called = []
    monkeypatch.setattr(sable_analyzer, "analyze_configured", lambda *a, **k: called.append(1))
    _, context = scenario("sable_preserved")
    status, details, _ = sable_analyzer.analyze(context, lambda *a: None)
    assert called == [] and status == "PRESERVED" and "mode" not in details
