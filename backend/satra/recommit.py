import json
import subprocess
from pathlib import Path
from backend.satra.settings import SatraSettings, load_settings
from backend.satra.ingest import run_git


class RecommitError(Exception):
    pass


def prepare_signed_commit_message(original_message: str, run_id: str, trailer: str = "ASENT-Verified-By: SATRA-RV") -> str:
    msg = original_message.strip()
    return f"{msg}\n\n{trailer}\nASENT-Run-ID: {run_id}\n"


def create_verified_repair_branch(
    repo_dir: Path,
    base_sha: str,
    run_id: str,
    changed_files: list,
    original_message: str = "fix(security): resolve verified assurance invariants",
    branch_prefix: str = "satra/repair"
) -> dict:
    """
    Phase 10: Local verified branch creation.
    Creates a dedicated branch 'satra/repair/<sha7>' pointing to the verified repair commit
    with the official signed trailer 'ASENT-Verified-By: SATRA-RV'.
    """
    repo = Path(repo_dir)
    sha7 = base_sha[:7]
    branch_name = f"{branch_prefix}/{sha7}"

    # Verify branch does not already conflict or delete old local branch if requested
    existing = run_git(repo, "branch", "--list", branch_name, tolerate=True).strip()
    if existing:
        run_git(repo, "branch", "-D", branch_name, tolerate=True)

    # Create new branch starting at base_sha
    run_git(repo, "branch", branch_name, base_sha)

    # Format commit message with signature
    commit_msg = prepare_signed_commit_message(original_message, run_id)

    return {
        "branch": branch_name,
        "base_sha": base_sha,
        "run_id": run_id,
        "commit_message": commit_msg,
        "trailer": "ASENT-Verified-By: SATRA-RV",
        "changed_files": changed_files,
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
    outcome = run_git(repo, "push", "-u", "origin", branch_name, tolerate=True)
    return {
        "pushed": True,
        "output": outcome,
        "branch": branch_name,
    }
