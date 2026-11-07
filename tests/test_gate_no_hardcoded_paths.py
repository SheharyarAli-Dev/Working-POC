"""Step 11 of docs/dev-env-plan.md: no hardcoded demo project on the gate path.

1. Text guard: the modules a gate run executes contain none of the demo paths, except the lines in
   ALLOWED, each with the reason it cannot be reached from a gate run.
2. Behaviour guard: a gate run works while every demo-scenario function raises, never imports the
   dashboard / SATRA-live modules, and never touches the CAVR sample project.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

from backend.orchestrator import service as service_module
from gate_support import GateRepo, config, git

REPO = Path(__file__).resolve().parents[1]
GATE_PATH = ["backend/gate/runner.py", "backend/gate/summary.py", "backend/project_config/schema.py",
             "backend/project_config/loader.py", "backend/project_config/frozen.py", "backend/project_config/starter.py",
             "backend/orchestrator/service.py", "backend/orchestrator/workspace_manager.py",
             "backend/orchestrator/context_service.py", "backend/orchestrator/final_gate.py", "backend/orchestrator/run_context.py",
             "backend/integrations/git_adapter.py", "backend/cavr/analyzer.py", "backend/cavr/gate_adapter.py",
             "backend/cavr/pipeline.py", "backend/satra/analyzer.py", "backend/satra/gate_mode.py",
             "backend/satra/pytest_runner.py", "backend/satra/security_contract.py", "backend/sable/analyzer.py"]
PATTERNS = ["demo_project", "sample_project", "SAMPLE_PROJECT_DIR", "scenarios/", "fixtures/invoice.pdf", "InvoiceHub/", "import DEMO",
            ",DEMO", "DEMO,"]
# (file, text that the line contains) -> why a gate run never reaches it
ALLOWED = {
    ("backend/cavr/analyzer.py", "context.path/'fixtures/invoice.pdf'"): "lockfile analyzer; analyze() returns the pipeline adapter first for every gate run",
    ("backend/orchestrator/service.py", "scenarios/cavr_controlled/invoice_pdf_safe.py"): "demo repair (_repair); analyze() forces auto_repair=False for gate runs",
    ("backend/orchestrator/service.py", "branch/'fixtures'/'invoice.pdf'"): "demo repair (_repair); unreachable for gate runs",
    ("backend/satra/pytest_runner.py", "ROOT/'scenarios/laboratory_hashes.json'"): "ASENT's own index of bundled inert sources; only read when external=False",
    ("backend/satra/pytest_runner.py", "ROOT/'demo_project/InvoiceHub'"): "host fallback for bundled sources; run_pytest(external=True) returns before it",
    ("backend/satra/pytest_runner.py", "for name in ('pytest.ini','fixtures/invoice.pdf'):"): "same host fallback (permitted_builtin); not consulted when external=True",
}


def test_gate_path_has_no_hardcoded_demo_paths():
    found = []
    for name in GATE_PATH:
        for number, line in enumerate((REPO / name).read_text().splitlines(), 1):
            for pattern in PATTERNS:
                if pattern in line and not any(f == name and text in line for f, text in ALLOWED):
                    found.append(f"{name}:{number}: {pattern}: {line.strip()[:120]}")
    assert found == []


def test_every_allowlist_entry_still_matches_a_line():
    for (name, text), reason in ALLOWED.items():
        assert reason and text in (REPO / name).read_text(), (name, text)


def small_repo(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    infra = {f"infra/{p.name}": p.read_text() for p in (REPO / "demo_project/InvoiceHub/infra").glob("*.tf")}
    obligations = {"obligations": [{"id": "d", "principal": "aws_iam_role.app", "protected_asset": "aws_s3_bucket.invoice_data",
                                    "actions": ["s3:GetObject", "s3:PutObject"]}]}
    base = repo.commit({**infra, ".asent/config.json": config(SABLE={"enabled": True}, CAVR={"enabled": False, "reason": "x"},
                                                              SATRA={"enabled": False, "reason": "x"}),
                        ".asent/sable/obligations.json": json.dumps(obligations)})
    return repo, base


def test_gate_run_never_calls_a_demo_scenario_function(tmp_path, monkeypatch):
    def forbidden(*a, **k):
        raise AssertionError("a gate run called a demo-scenario function")
    for name in ("catalog", "apply_scenario", "replace_lab", "scenario_project"):
        monkeypatch.setattr(service_module, name, forbidden)
    from backend.gate.runner import run_gate
    repo, base = small_repo(tmp_path)
    code, report = run_gate(repo.root, base, base, tmp_path / "out")
    assert code == 0, report["reasons"]


def test_gate_run_does_not_import_dashboard_or_live_satra_modules(tmp_path):
    repo, base = small_repo(tmp_path)
    script = ("import sys, json; from backend.gate.runner import run_gate; "
              f"code, report = run_gate({str(repo.root)!r}, {base!r}, {base!r}, {str(tmp_path / 'out')!r}); "
              "print(json.dumps({'code': code, 'mods': sorted(m for m in sys.modules if m.startswith('backend.'))}))")
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO, capture_output=True, text=True, timeout=300)
    data = json.loads(result.stdout.strip().splitlines()[-1])
    assert data["code"] == 0
    for module in ("backend.main", "backend.cavr.api", "backend.cavr.context_extractor_sample", "backend.satra.settings",
                   "backend.satra.api", "backend.sable.api", "backend.sable.fixtures.scenarios"):
        assert module not in data["mods"], module
