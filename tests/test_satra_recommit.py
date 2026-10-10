import pytest
from pathlib import Path
from backend.satra.recommit import (
    prepare_signed_commit_message,
    create_verified_repair_branch,
    push_repair_branch_if_allowed,
)
from backend.satra.settings import SatraSettings
from backend.satra.ingest import run_git


def test_prepare_signed_commit_message():
    orig = "fix(auth): restore ownership invariant"
    msg = prepare_signed_commit_message(orig, "run-998877")
    assert "ASENT-Verified-By: SATRA-RV" in msg
    assert "ASENT-Run-ID: run-998877" in msg
    assert orig in msg


def test_create_verified_repair_branch(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    run_git(repo, "init", "-b", "main")
    run_git(repo, "config", "user.name", "Test Committer")
    run_git(repo, "config", "user.email", "committer@asent.local")

    f = repo / "README.md"
    f.write_text("# Test Repo\n")
    run_git(repo, "add", "README.md")
    run_git(repo, "commit", "-m", "initial commit")
    head_sha = run_git(repo, "rev-parse", "HEAD").strip()

    result = create_verified_repair_branch(
        repo_dir=repo,
        base_sha=head_sha,
        run_id="run-test-01",
        changed_files=["app/security.py"],
    )

    expected_branch = f"satra/repair/{head_sha[:7]}"
    assert result["branch"] == expected_branch
    assert result["trailer"] == "ASENT-Verified-By: SATRA-RV"

    branches = run_git(repo, "branch", "--list", expected_branch).strip()
    assert expected_branch in branches


def test_push_repair_branch_if_allowed(tmp_path):
    settings_no_push = SatraSettings(
        target_url="https://github.com/SheharyarAli-Dev/Threat-Repository",
        target_source="https://github.com/SheharyarAli-Dev/Threat-Repository",
        allowlist=("SheharyarAli-Dev/Threat-Repository",),
        workspace=tmp_path,
        ollama_endpoint="http://127.0.0.1:11434",
        model_name="qwen2.5-coder:1.5b",
        sandbox_image="asent-sandbox-app",
        repair_budget=3,
        push_enabled=False,
    )

    res = push_repair_branch_if_allowed(tmp_path, "satra/repair/1234567", settings_no_push)
    assert not res["pushed"]
    assert "Push disabled by policy" in res["reason"]
