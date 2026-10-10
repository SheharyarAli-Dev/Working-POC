import json
import subprocess
from pathlib import Path
from backend.satra.settings import SatraSettings, load_settings
from backend.satra.ingest import run_git, git_environment


class RecommitError(Exception):
    pass


def prepare_signed_commit_message(original_message: str, run_id: str, trailer: str = "ASENT-Verified-By: SATRA-RV") -> str:
    msg = original_message.strip()
    return f"{msg}\n\n{trailer}\nASENT-Run-ID: {run_id}\n"


def create_verified_repair_branch(
    repo_dir: Path,
    base_sha: str,
    run_id: str,
    changed_files: list = None,
    original_message: str = "fix(security): resolve verified assurance invariants",
    branch_prefix: str = "satra/repair",
    repair: dict = None,
) -> dict:
    """
    Phase 10: Local verified branch creation.
    Creates a dedicated branch 'satra/repair/<sha7>' pointing to the verified repair commit
    with the official signed trailer 'ASENT-Verified-By: SATRA-RV'.
    """
    repo = Path(repo_dir)
    sha7 = base_sha[:7]
    branch_name = f"{branch_prefix}/{sha7}"

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

    # Use checkout -B to create or reset branch_name directly to base_sha
    run_git(repo, "checkout", "-B", branch_name, base_sha)

    # Format commit message with signature
    commit_msg = prepare_signed_commit_message(original_message, run_id)
    commit_sha = sha7

    if repair and repair.get("patch_diff"):
        try:
            patch_diff = repair["patch_diff"]
            run_git(repo, "apply", "--ignore-whitespace", feed=patch_diff.encode("utf-8"), tolerate=True)
            run_git(repo, "add", "-A", tolerate=True)
            run_git(repo, "commit", "-m", commit_msg, "--author=ASENT Security Gate <asent-gate@security.local>", tolerate=True)
            new_sha = run_git(repo, "rev-parse", "--short", "HEAD", tolerate=True).strip()
            if new_sha:
                commit_sha = new_sha
        except Exception:
            pass
        finally:
            # Switch back to original branch
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


def push_repair_branch_if_allowed(repo_dir: Path, branch_name: str, settings: SatraSettings) -> dict:
    """
    Pushes repair branch to upstream forge ONLY if push_enabled is True in settings.
    Otherwise safely logs that push is disabled per security policy.
    """
    if not settings.push_enabled:
        return {
            "pushed": False,
            "reason": "Push disabled by policy (SATRA_ALLOW_PUSH=0). Branch exists locally.",
            "branch": branch_name,
        }

    repo = Path(repo_dir)
    res = subprocess.run(
        ["git", "-C", str(repo), "push", "-u", "-f", "origin", branch_name],
        capture_output=True,
        env=git_environment(),
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

    return {
        "pushed": True,
        "output": (res.stdout.decode("utf-8", "replace") + "\n" + res.stderr.decode("utf-8", "replace")).strip(),
        "branch": branch_name,
    }

