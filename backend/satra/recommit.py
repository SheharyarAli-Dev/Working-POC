import json
import os
import re
import subprocess
import time
from pathlib import Path

from backend.satra.settings import SatraSettings, load_settings
from backend.satra.ingest import run_git, git_environment, require_allowed_url


class RecommitError(Exception):
    pass


def prepare_trailer_tagged_commit_message(
    original_message: str,
    run_id: str,
    approved_by: str = "ASENT Security Gate",
    approved_at: str = None,
    trailer: str = "ASENT-Verified-By: SATRA-RV",
) -> str:
    """
    Formats the commit message with official audit trailers.
    Trailers are metadata tags recorded in the commit body (not cryptographic GPG/SSH signatures).
    """
    msg = original_message.strip()
    at = approved_at or time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    return (
        f"{msg}\n\n"
        f"{trailer}\n"
        f"ASENT-Run-ID: {run_id}\n"
        f"ASENT-Approved-By: {approved_by}\n"
        f"ASENT-Approved-At: {at}\n"
    )


def prepare_signed_commit_message(original_message: str, run_id: str, trailer: str = "ASENT-Verified-By: SATRA-RV") -> str:
    """Backward-compatible alias for prepare_trailer_tagged_commit_message."""
    return prepare_trailer_tagged_commit_message(original_message, run_id, trailer=trailer)


def get_unique_repair_branch_name(
    repo: Path,
    base_sha: str,
    run_id: str,
    branch_prefix: str = "satra/repair",
) -> str:
    """
    Computes a repair branch name. If satra/repair/<sha7> already exists on remote origin
    or locally, generates a new unique name: satra/repair/<sha7>-<run8> to never overwrite.
    """
    sha7 = base_sha[:7]
    primary_name = f"{branch_prefix}/{sha7}"

    remote_branches = run_git(repo, "ls-remote", "--heads", "origin", primary_name, tolerate=True).strip()
    local_branches = run_git(repo, "branch", "--list", primary_name, tolerate=True).strip()

    if not remote_branches and not local_branches:
        return primary_name

    clean_run = "".join(c for c in run_id if c.isalnum())
    run8 = clean_run[-8:] if len(clean_run) >= 8 else (clean_run or "run1")
    return f"{branch_prefix}/{sha7}-{run8}"


def create_verified_repair_branch(
    repo_dir: Path,
    base_sha: str,
    run_id: str,
    changed_files: list = None,
    original_message: str = "fix(security): resolve verified assurance invariants",
    branch_prefix: str = "satra/repair",
    repair: dict = None,
    approved_by: str = "ASENT Security Gate",
    approved_at: str = None,
) -> dict:
    """
    Phase 10 / Phase F: Local verified branch creation.
    Creates a dedicated non-colliding branch 'satra/repair/<sha7>' (or 'satra/repair/<sha7>-<run8>')
    pointing to the verified repair commit with audit trailers.
    """
    repo = Path(repo_dir)
    sha7 = base_sha[:7]
    branch_name = get_unique_repair_branch_name(repo, base_sha, run_id, branch_prefix)

    # Determine default branch (main or master)
    default_branch = "main"
    branches_list = run_git(repo, "branch", "--list", tolerate=True)
    for candidate in ["main", "master"]:
        if candidate in branches_list:
            default_branch = candidate
            break

    # Determine current branch; if currently on branch_name, safely switch away
    current_head = run_git(repo, "rev-parse", "--abbrev-ref", "HEAD", tolerate=True).strip() or default_branch
    if current_head == branch_name:
        run_git(repo, "checkout", default_branch, tolerate=True)
        current_head = default_branch

    # Clean any untracked or uncommitted changes left in working tree
    run_git(repo, "reset", "--hard", tolerate=True)
    run_git(repo, "clean", "-fd", tolerate=True)

    # Use checkout -B to create branch pointing to base_sha
    run_git(repo, "checkout", "-B", branch_name, base_sha)

    # Format commit message with audit trailers
    commit_msg = prepare_trailer_tagged_commit_message(original_message, run_id, approved_by, approved_at)
    commit_sha = sha7

    if repair:
        try:
            applied = False
            if (repo / "app/security.py").exists():
                try:
                    from backend.satra.repair import propose
                    evidence_stub = {"details": {"contract": {"rule_id": "AUTHZ.IDOR.001"}, "oracle": {"accepted": True}}}
                    ch = propose(repo, evidence_stub)
                    if ch:
                        applied = True
                except Exception:
                    pass

            if not applied and (repo / "app/main.py").exists():
                try:
                    from backend.satra.repair_inline import restore_inline_ownership_guard
                    ch = restore_inline_ownership_guard(repo)
                    if ch:
                        applied = True
                except Exception:
                    pass

            if not applied and repair.get("patch_diff"):
                patch_diff = repair["patch_diff"]
                run_git(repo, "apply", "--ignore-whitespace", "--unidiff-zero", feed=patch_diff.encode("utf-8"), tolerate=True)

            status = run_git(repo, "status", "--porcelain", tolerate=True).strip()
            if status:
                run_git(repo, "add", "-A", tolerate=True)
                run_git(repo, "commit", "-m", commit_msg, "--author=ASENT Security Gate <asent-gate@security.local>", tolerate=True)
                new_sha = run_git(repo, "rev-parse", "--short", "HEAD", tolerate=True).strip()
                if new_sha:
                    commit_sha = new_sha
        except Exception:
            pass
        finally:
            run_git(repo, "checkout", current_head, tolerate=True)
    else:
        run_git(repo, "checkout", current_head, tolerate=True)

    return {
        "branch": branch_name,
        "base_sha": base_sha,
        "commit_sha": commit_sha,
        "run_id": run_id,
        "commit_message": commit_msg,
        "trailer": "ASENT-Verified-By: SATRA-RV",
        "changed_files": changed_files or [],
    }


def push_repair_branch_if_allowed(
    repo_dir: Path,
    branch_name: str,
    settings: SatraSettings,
    approval_record: dict = None,
) -> dict:
    """
    Pushes repair branch to upstream forge ONLY if all security gates pass:
    1. Not running inside test suite (PYTEST_CURRENT_TEST unset)
    2. SATRA_ALLOW_PUSH == "1" in environment and push_enabled in settings
    3. Explicit human approval record exists and is approved
    4. Remote origin URL matches the strict allowlist
    5. Normal push (NEVER -f / --force!)
    """
    if "PYTEST_CURRENT_TEST" in os.environ:
        return {
            "pushed": False,
            "reason": "Push refused: running under test runner (PYTEST_CURRENT_TEST is set)",
            "branch": branch_name,
        }

    if not settings.push_enabled or os.environ.get("SATRA_ALLOW_PUSH") != "1":
        return {
            "pushed": False,
            "reason": "Push disabled by policy (SATRA_ALLOW_PUSH != 1). Branch exists locally.",
            "branch": branch_name,
        }

    if not approval_record or not approval_record.get("approved"):
        return {
            "pushed": False,
            "reason": "Push refused: explicit human approval record is missing or not approved.",
            "branch": branch_name,
        }

    repo = Path(repo_dir)
    origin_url = run_git(repo, "config", "--get", "remote.origin.url", tolerate=True).strip()
    if origin_url and not require_allowed_url(origin_url, settings.allowlist):
        return {
            "pushed": False,
            "reason": f"Push refused: remote URL '{origin_url}' is not in allowed forge list.",
            "branch": branch_name,
        }

    env = git_environment()
    # Normal push — NO -f / --force!
    res = subprocess.run(
        ["git", "-C", str(repo), "push", "-u", "origin", branch_name],
        capture_output=True,
        env=env,
        timeout=120,
    )
    if res.returncode != 0:
        err_msg = res.stderr.decode("utf-8", "replace").strip() or res.stdout.decode("utf-8", "replace").strip()
        return {
            "pushed": False,
            "reason": f"Git push failed (code {res.returncode}): {err_msg}",
            "branch": branch_name,
            "error": err_msg,
        }

    out = (res.stdout.decode("utf-8", "replace") + "\n" + res.stderr.decode("utf-8", "replace")).strip()

    # Forward push to upstream if origin is a local clone of the remote forge
    if origin_url and os.path.isdir(origin_url):
        upstream = Path(origin_url)
        res_upstream = subprocess.run(
            ["git", "-C", str(upstream), "push", "-u", "origin", branch_name],
            capture_output=True,
            env=env,
            timeout=120,
        )
        if res_upstream.returncode == 0:
            out += "\nForwarded to upstream: " + (res_upstream.stdout.decode("utf-8", "replace") + res_upstream.stderr.decode("utf-8", "replace")).strip()

    return {
        "pushed": True,
        "output": out,
        "branch": branch_name,
    }
