"""Step 8 of docs/dev-env-plan.md: `asent gate --repository PATH --base REF --head REF`, no server.

Every case is a real git repository with real base and head commits. Exit codes: 0 ACCEPT, 1 BLOCK,
2 REVIEW, and 2 for anything that goes wrong (fail closed). Both `asent-report.json` and
`asent-summary.md` are written in every case where the output directory is writable.
"""
import json
import os
import shutil
from pathlib import Path

import pytest

from backend.config import ROOT
from backend.gate import runner
from backend.orchestrator.service import Service
from backend.project_config.frozen import NOT_ASSESSED
from backend.project_config.starter import init_project
from backend.satra import pytest_runner
from gate_support import DISABLED, GateRepo, cavr_files, config, git, recorded_pypi, run_cli

DEMO_INFRA = ROOT / "demo_project/InvoiceHub/infra"
OBLIGATIONS = json.dumps({"obligations": [{"id": "invoice-data", "principal": "aws_iam_role.app",
                                           "protected_asset": "aws_s3_bucket.invoice_data", "actions": ["s3:GetObject", "s3:PutObject"]}]})


def infra_files(folder=DEMO_INFRA):
    return {f"infra/{p.relative_to(folder).as_posix()}": p.read_text() for p in folder.rglob("*.tf")}


def sable_repo(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({**infra_files(), ".asent/config.json": config(SABLE={"enabled": True}, CAVR=DISABLED, SATRA=DISABLED),
                        ".asent/sable/obligations.json": OBLIGATIONS}, tag="base")
    return repo, base


# --- fail-closed cases: REVIEW, exit 2 ---------------------------------------------------------------

def test_no_asent_at_base(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({"infra/main.tf": ""})
    head = repo.commit({"infra/main.tf": "# x\n"})
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 2 and report["decision"] == "REVIEW" and report["exit_code"] == 2
    assert any("ASENT_CONFIG_MISSING" in reason for reason in report["reasons"])
    assert summary.startswith("# ASENT gate: REVIEW")


def test_invalid_config(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({".asent/config.json": "{broken", "infra/main.tf": ""})
    code, report, _ = run_cli(repo, base, base, tmp_path / "out")
    assert code == 2 and any("ASENT_CONFIG_JSON" in reason for reason in report["reasons"])


def test_unreviewed_starter(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    (repo.root / "requirements.txt").write_text("pypdf==6.19.0\n")
    init_project(repo.root)
    base = repo.commit({})
    code, report, _ = run_cli(repo, base, base, tmp_path / "out")
    assert code == 2 and any("ASENT_CONFIG_STARTER" in reason for reason in report["reasons"])


def test_head_edits_asent(tmp_path):
    repo, base = sable_repo(tmp_path)
    head = repo.commit({".asent/README.md": "relaxed\n"})
    code, report, _ = run_cli(repo, base, head, tmp_path / "out")
    assert code == 2 and report["config"]["changed_in_head"] is True
    assert "ASENT configuration changed in this change; requires maintainer review" in report["reasons"]


def test_unknown_ref_still_writes_a_report(tmp_path):
    repo, base = sable_repo(tmp_path)
    code, report, summary = run_cli(repo, base, "no-such-branch", tmp_path / "out")
    assert code == 2 and report["head"]["sha"] is None and report["base"]["sha"] == base
    assert any("unknown commit" in reason for reason in report["reasons"]) and "REVIEW" in summary


def test_not_a_repository(tmp_path):
    (tmp_path / "plain").mkdir()
    from backend import cli
    out = tmp_path / "out"
    assert cli.main(["gate", "--repository", str(tmp_path / "plain"), "--base", "a", "--head", "b", "--output-dir", str(out)]) == 2
    report = json.loads((out / "asent-report.json").read_text())
    assert report["decision"] == "REVIEW" and any("not a git repository" in reason for reason in report["reasons"])


def test_tf_present_without_sable_section(tmp_path, monkeypatch):
    recorded_pypi(monkeypatch, tmp_path)
    repo = GateRepo(tmp_path / "repo")
    files = cavr_files()
    files[".asent/config.json"] = config(CAVR={"enabled": True}, SATRA=DISABLED)  # no SABLE section
    base = repo.commit({**files, **infra_files()})
    code, report, summary = run_cli(repo, base, base, tmp_path / "out")
    assert code == 2 and "SABLE: applies but is not configured in base .asent/config.json" in report["reasons"]
    assert report["modules"]["SABLE"]["result"] == "review"


def test_sable_enabled_with_invalid_obligations(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({**infra_files(), ".asent/config.json": config(SABLE={"enabled": True}),
                        ".asent/sable/obligations.json": '{"obligations": []}'})
    code, report, _ = run_cli(repo, base, base, tmp_path / "out")
    assert code == 2 and any("ASENT_CONFIG_OBLIGATIONS" in reason for reason in report["reasons"])


def test_satra_enabled_without_a_container_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": False}, "podman": {"available": False}})
    repo = GateRepo(tmp_path / "repo")
    contract = {"rule_id": "AUTHZ.IDOR.001", "route": "GET /x", "expected_status": 403, "authority_sources": ["README"],
                "scope": ["app/security.py"], "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::f"}}
    base = repo.commit({"app/security.py": "def f():\n    return False\n", ".asent/config.json": config(SATRA={"enabled": True}),
                        ".asent/satra/contract.json": json.dumps(contract),
                        ".asent/satra/trusted_tests/test_x.py": "def test_x():\n    assert 1 + 1 == 2\n"})
    code, report, _ = run_cli(repo, base, base, tmp_path / "out")
    assert code == 2 and report["modules"]["SATRA"]["status"] == "INCONCLUSIVE"
    assert "Docker/Podman" in report["modules"]["SATRA"]["reason"]


def test_symlink_in_head(tmp_path):
    repo, base = sable_repo(tmp_path)
    os.symlink("main.tf", repo.root / "infra/link.tf")
    head = repo.commit({})
    code, report, _ = run_cli(repo, base, head, tmp_path / "out")
    assert code == 2 and any("symlink" in reason for reason in report["reasons"])


def test_internal_error_is_review_with_a_report(tmp_path, monkeypatch):
    repo, base = sable_repo(tmp_path)
    def boom(*a, **k):
        raise RuntimeError("injected failure")
    monkeypatch.setattr(Service, "create_gate_run", boom)
    code, report, _ = run_cli(repo, base, base, tmp_path / "out")
    assert code == 2 and any("RuntimeError: injected failure" in reason for reason in report["reasons"])


def test_unwritable_output_directory(tmp_path, capsys):
    repo, base = sable_repo(tmp_path)
    blocker = tmp_path / "out"
    blocker.write_text("a file, not a directory")
    code, _, _ = run_cli(repo, base, base, blocker)
    assert code == 2 and "could not write" in capsys.readouterr().err


# --- decisions ---------------------------------------------------------------------------------------

def test_sable_preserved_is_accept(tmp_path):
    repo, base = sable_repo(tmp_path)
    head = repo.commit({"README.md": "docs only\n"})
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 0 and report["decision"] == "ACCEPT", report["reasons"]
    assert report["modules"]["SABLE"] == {**report["modules"]["SABLE"], "result": "pass", "status": "PRESERVED", "assessed": True}


def test_sable_regression_is_block(tmp_path):
    repo, base = sable_repo(tmp_path)
    for p in (repo.root / "infra").rglob("*.tf"):
        p.unlink()
    head = repo.commit(infra_files(ROOT / "scenarios/sable/regressed"))
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 1 and report["decision"] == "BLOCK" and report["modules"]["SABLE"]["result"] == "block"
    assert summary.startswith("# ASENT gate: BLOCK")


def test_terraform_only_change_keeps_satra_active_and_routes_surfaces(tmp_path, monkeypatch):
    """Applicability is project-surface + base-config based, never changed-file based.

    The candidate keeps its application .py code and the base config enables SATRA, so a
    Terraform-only rename of the protected bucket still assesses SATRA (here INCONCLUSIVE,
    because a container engine is unavailable) and the gate stays REVIEW even though SABLE
    preserves the obligation through the rename. The .tf changes alone are routed to SABLE
    in changed_surfaces. Disabling a module in changed files must not happen by routing.
    """
    monkeypatch.setattr(pytest_runner, "availability", lambda: {"docker": {"available": False}, "podman": {"available": False}})
    repo = GateRepo(tmp_path / "repo")
    contract = {"rule_id": "AUTHZ.IDOR.001", "route": "GET /x", "expected_status": 403, "authority_sources": ["README"],
                "scope": ["app/security.py"], "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::f"}}
    base = repo.commit({"app/security.py": "def f():\n    return False\n", ".asent/config.json": config(SATRA={"enabled": True}, SABLE={"enabled": True}, CAVR=DISABLED),
                        ".asent/satra/contract.json": json.dumps(contract),
                        ".asent/satra/trusted_tests/test_x.py": "def test_x():\n    assert 1 + 1 == 2\n",
                        ".asent/sable/obligations.json": OBLIGATIONS, **infra_files()})
    refactor = {}
    for name, text in infra_files().items():
        # A well-formed rename: restate the resource block address AND every reference.
        text = text.replace('resource "aws_s3_bucket" "invoice_data"', 'resource "aws_s3_bucket" "ledger_store"')
        refactor[name] = text.replace("aws_s3_bucket.invoice_data", "aws_s3_bucket.ledger_store")
    refactor["infra/moved.tf"] = "moved {\n  from = aws_s3_bucket.invoice_data\n  to   = aws_s3_bucket.ledger_store\n}\n"
    head = repo.commit(refactor)
    changed = set(infra_files()) | {"infra/moved.tf"}

    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 2 and report["decision"] == "REVIEW", report["reasons"]
    sable = report["modules"]["SABLE"]
    assert sable["result"] == "pass" and sable["status"] == "PRESERVED" and sable["assessed"] is True
    satra = report["modules"]["SATRA"]
    assert satra["status"] == "INCONCLUSIVE" and satra["assessed"] is True
    cavr = report["modules"]["CAVR"]
    assert cavr["result"] == NOT_ASSESSED and cavr["assessed"] is False
    assert report["coverage"]["SATRA"]["assessed"] is True and report["coverage"]["SABLE"]["assessed"] is True
    assert report["assurance"]["run"]["changed_surfaces"] == {"SABLE": sorted(changed)}
    assert not any(line.startswith("| SABLE |") and "| pass |" not in line for line in summary.splitlines())


def test_denied_package_added_in_head_is_block(tmp_path, monkeypatch):
    index, _ = recorded_pypi(monkeypatch, tmp_path)
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit(cavr_files())
    head = repo.commit({"requirements.txt": "pypdf==6.19.0\nreqeusts==2.31.0\n"})
    code, report, _ = run_cli(repo, base, head, tmp_path / "out")
    assert code == 1 and report["modules"]["CAVR"]["status"] == "REJECTED"


def test_cavr_only_accept_with_disabled_modules_never_shown_as_passed(tmp_path, monkeypatch):
    recorded_pypi(monkeypatch, tmp_path)
    repo = GateRepo(tmp_path / "repo")
    sable_off = {"enabled": False, "reason": "infrastructure is reviewed by the platform team"}
    satra_off = {"enabled": False, "reason": "no security contract written yet"}
    base = repo.commit({**cavr_files(SATRA=satra_off, SABLE=sable_off), **infra_files()})
    head = repo.commit({"README.md": "x\n"})
    code, report, summary = run_cli(repo, base, head, tmp_path / "out")
    assert code == 0 and report["decision"] == "ACCEPT", report["reasons"]
    assert report["modules"]["CAVR"]["result"] == "pass"
    for module, reason in (("SATRA", satra_off["reason"]), ("SABLE", sable_off["reason"])):
        entry = report["modules"][module]
        assert entry["result"] == NOT_ASSESSED and entry["assessed"] is False and entry["reason"] == reason
        row = next(line for line in summary.splitlines() if line.startswith(f"| {module} |"))
        assert NOT_ASSESSED in row and reason in row and "| pass |" not in row
    assert "Accepted for the assessed modules only" in summary


# --- report contents -----------------------------------------------------------------------------------

def test_report_identifies_the_exact_commits_and_config(tmp_path):
    repo, base = sable_repo(tmp_path)
    head = repo.commit({"README.md": "x\n"}, tag="head")
    code, report, summary = run_cli(repo, "base", "head", tmp_path / "out")
    assert report["schema"] == "asent.gate.v1" and code == report["exit_code"]
    assert report["base"] == {"ref": "base", "sha": git(repo.root, "rev-parse", "base")}
    assert report["head"] == {"ref": "head", "sha": git(repo.root, "rev-parse", "head")}
    assert report["config"]["digest"] and report["config"]["problems"] == []
    assert report["assurance"]["schema"] == "asent.assurance.v1"
    assert [line.split("|")[1].strip() for line in summary.splitlines() if line.startswith("| ") and not line.startswith("| Module")
            and not line.startswith("|---")] == ["CAVR", "SATRA", "SABLE"]


def test_hooks_in_the_target_repository_are_not_run(tmp_path):
    repo, base = sable_repo(tmp_path)
    marker = tmp_path / "hook-ran"
    for hook in ("post-checkout", "post-commit", "pre-commit", "post-merge"):
        path = repo.root / ".git/hooks" / hook
        path.write_text(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(path, 0o755)
    run_cli(repo, base, base, tmp_path / "out")
    assert not marker.exists()


def test_work_directory_is_removed_unless_kept(tmp_path, monkeypatch):
    repo, base = sable_repo(tmp_path)
    monkeypatch.setenv("TMPDIR", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    import tempfile
    monkeypatch.setattr(tempfile, "tempdir", None)
    run_cli(repo, base, base, tmp_path / "out1")
    assert list((tmp_path / "tmp").iterdir()) == []
    kept = tmp_path / "kept"
    code, report, _ = run_cli(repo, base, base, tmp_path / "out2", "--data-dir", str(kept))
    assert code == 0 and (kept / "runtime").is_dir() and report["data_dir"] == str(kept)


def test_run_gate_api_returns_the_same_report(tmp_path):
    repo, base = sable_repo(tmp_path)
    code, report = runner.run_gate(repo.root, base, base, tmp_path / "out")
    assert code == 0 and json.loads((tmp_path / "out/asent-report.json").read_text()) == report
