import os
import pytest
from pathlib import Path
from backend.satra.recommit import (
    prepare_trailer_tagged_commit_message,
    prepare_signed_commit_message,
    create_verified_repair_branch,
    push_repair_branch_if_allowed,
    get_unique_repair_branch_name,
)
from backend.satra.audit_trail import AuditTrail, canonical_digest
from backend.satra.settings import SatraSettings
from backend.satra.ingest import run_git


def test_prepare_trailer_tagged_commit_message():
    orig = "fix(auth): restore ownership invariant"
    msg = prepare_trailer_tagged_commit_message(orig, "run-998877", approved_by="Auditor Alice", approved_at="2026-10-11 12:00:00 UTC")
    assert "ASENT-Verified-By: SATRA-RV" in msg
    assert "ASENT-Run-ID: run-998877" in msg
    assert "ASENT-Approved-By: Auditor Alice" in msg
    assert "ASENT-Approved-At: 2026-10-11 12:00:00 UTC" in msg
    assert orig in msg

    # Backward-compatible alias
    alias_msg = prepare_signed_commit_message(orig, "run-112233")
    assert "ASENT-Run-ID: run-112233" in alias_msg


def test_create_verified_repair_branch_unique_naming(tmp_path):
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

    # First repair branch creation
    result1 = create_verified_repair_branch(
        repo_dir=repo,
        base_sha=head_sha,
        run_id="run-test-alpha01",
        changed_files=["app/security.py"],
    )
    primary_branch = f"satra/repair/{head_sha[:7]}"
    assert result1["branch"] == primary_branch
    assert result1["trailer"] == "ASENT-Verified-By: SATRA-RV"

    # Second repair for the same commit must create a unique non-colliding branch
    result2 = create_verified_repair_branch(
        repo_dir=repo,
        base_sha=head_sha,
        run_id="run-test-beta02",
        changed_files=["app/security.py"],
    )
    assert result2["branch"] != primary_branch
    assert result2["branch"].startswith(f"satra/repair/{head_sha[:7]}-")
    assert "beta02" in result2["branch"]


def test_recommit_flow_with_local_bare_remote(tmp_path):
    bare_remote = tmp_path / "remote.git"
    bare_remote.mkdir()
    run_git(bare_remote, "init", "--bare")

    # Clone local repo from bare remote
    work_repo = tmp_path / "work_repo"
    run_git(tmp_path, "clone", str(bare_remote), "work_repo")
    run_git(work_repo, "config", "user.name", "ASENT CI")
    run_git(work_repo, "config", "user.email", "ci@example.com")

    # Initial commit on main
    run_git(work_repo, "checkout", "-b", "main")
    (work_repo / "file.txt").write_text("secure baseline")
    run_git(work_repo, "add", "file.txt")
    run_git(work_repo, "commit", "-m", "initial commit on main")
    run_git(work_repo, "push", "-u", "origin", "main")
    base_sha = run_git(work_repo, "rev-parse", "HEAD").strip()

    settings = SatraSettings(
        target_url=str(bare_remote),
        target_source=str(bare_remote),
        allowlist=(str(bare_remote),),
        workspace=tmp_path,
        ollama_endpoint="http://127.0.0.1:11434",
        model_name="qwen2.5-coder:1.5b",
        sandbox_image="asent-sandbox-app",
        repair_budget=3,
        push_enabled=True,
    )

    # Create repair branch locally
    rep1 = create_verified_repair_branch(work_repo, base_sha, "run-rev-001")
    branch1 = rep1["branch"]

    # 0. Refuse push when running under pytest
    res_test_env = push_repair_branch_if_allowed(work_repo, branch1, settings, {"approved": True})
    assert not res_test_env["pushed"]
    assert "PYTEST_CURRENT_TEST is set" in res_test_env["reason"]

    # Temporarily unset PYTEST_CURRENT_TEST to test the remaining policy gates
    pytest_env = os.environ.pop("PYTEST_CURRENT_TEST", None)
    try:
        # 1. No push when SATRA_ALLOW_PUSH is off
        old_env = os.environ.get("SATRA_ALLOW_PUSH")
        os.environ["SATRA_ALLOW_PUSH"] = "0"
        try:
            res_no_flag = push_repair_branch_if_allowed(work_repo, branch1, settings, {"approved": True})
            assert not res_no_flag["pushed"]
            assert "SATRA_ALLOW_PUSH" in res_no_flag["reason"]
        finally:
            if old_env is not None:
                os.environ["SATRA_ALLOW_PUSH"] = old_env
            else:
                os.environ.pop("SATRA_ALLOW_PUSH", None)

        # 2. No push without human approval record
        os.environ["SATRA_ALLOW_PUSH"] = "1"
        res_no_approval = push_repair_branch_if_allowed(work_repo, branch1, settings, approval_record=None)
        assert not res_no_approval["pushed"]
        assert "approval record is missing" in res_no_approval["reason"]

        res_rejected = push_repair_branch_if_allowed(work_repo, branch1, settings, approval_record={"approved": False})
        assert not res_rejected["pushed"]
        assert "approval record is missing or not approved" in res_rejected["reason"]

        # 3. Successful push with human approval
        res_approved = push_repair_branch_if_allowed(
            work_repo, branch1, settings, approval_record={"approved": True, "approver": "Human Lead"}
        )
        assert res_approved["pushed"]

        # Verify on bare remote: main is UNTOUCHED, branch1 exists
        remote_heads = run_git(bare_remote, "branch", "-a")
        assert "main" in remote_heads
        assert branch1 in remote_heads

        # 4. A second repair of the same commit creates a NEW unique branch instead of overwriting
        rep2 = create_verified_repair_branch(work_repo, base_sha, "run-rev-002")
        branch2 = rep2["branch"]
        assert branch2 != branch1
        assert branch2.startswith(f"satra/repair/{base_sha[:7]}-")

        # Push the second branch successfully without force
        res_approved2 = push_repair_branch_if_allowed(
            work_repo, branch2, settings, approval_record={"approved": True, "approver": "Human Lead"}
        )
        assert res_approved2["pushed"]

        remote_heads_updated = run_git(bare_remote, "branch", "-a")
        assert branch1 in remote_heads_updated
        assert branch2 in remote_heads_updated
    finally:
        if pytest_env is not None:
            os.environ["PYTEST_CURRENT_TEST"] = pytest_env
        os.environ.pop("SATRA_ALLOW_PUSH", None)


def test_audit_trail_append_only_and_tamper_detection(tmp_path):
    log_file = tmp_path / "satra_audit.jsonl"
    trail = AuditTrail(log_file)

    # Empty verification
    assert trail.verify_chain()["valid"]

    # Append 3 entries
    e1 = trail.append("run-001", "Alice", "APPROVE_AND_PUSH", "satra/repair/111", "sha111", {"notes": "clean"})
    e2 = trail.append("run-002", "Bob", "LOCAL_BRANCH", "satra/repair/222", "sha222", {"notes": "local"})
    e3 = trail.append("run-003", "Charlie", "APPROVE_AND_PUSH", "satra/repair/333", "sha333", {"notes": "verified"})

    assert e1["prev_hash"] == "0" * 64
    assert e2["prev_hash"] == e1["entry_hash"]
    assert e3["prev_hash"] == e2["entry_hash"]

    # Verify clean chain
    res = trail.verify_chain()
    assert res["valid"]
    assert res["count"] == 3

    # Tampering test: alter content in entry 1
    lines = log_file.read_text(encoding="utf-8").splitlines()
    tampered_entry = lines[1].replace("satra/repair/222", "satra/repair/evil_override")
    lines[1] = tampered_entry
    log_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Verify detection of tampering
    tamper_res = trail.verify_chain()
    assert not tamper_res["valid"]
    assert tamper_res["tampered_index"] == 1
    assert "tampering detected" in tamper_res["reason"].lower()
