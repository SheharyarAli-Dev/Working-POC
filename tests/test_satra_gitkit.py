import os
import subprocess
from pathlib import Path

IDENTITY = {
    "GIT_AUTHOR_NAME": "Fixture Author",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "Fixture Author",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
}


def git_do(repo, *arguments, feed=None):
    scrubbed = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    scrubbed.update(IDENTITY)
    outcome = subprocess.run(["git", "-C", str(repo), *arguments], input=feed, capture_output=True, env=scrubbed, check=True)
    return outcome.stdout.decode("utf-8", "replace").strip()


def start_repo(parent_dir, name="fixture"):
    repo = Path(parent_dir) / name
    repo.mkdir(parents=True)
    git_do(repo, "init", "-q", "-b", "main")
    return repo


def put_files(repo, tree):
    for relative, content in tree.items():
        target = Path(repo) / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content)


def record(repo, tree=None, remove=(), message="step"):
    put_files(repo, tree or {})
    for relative in remove:
        (Path(repo) / relative).unlink()
    git_do(repo, "add", "-A")
    git_do(repo, "commit", "-q", "--allow-empty", "-m", message)
    return git_do(repo, "rev-parse", "HEAD")


def make_settings(workspace, repo, extra_allow=()):
    from backend.satra.settings import SatraSettings

    return SatraSettings(
        target_url=str(repo),
        target_source=str(repo),
        allowlist=(str(repo), *extra_allow),
        workspace=Path(workspace),
        ollama_endpoint="http://127.0.0.1:1",
        model_name="none",
        sandbox_image="asent-sandbox-app",
        repair_budget=3,
        push_enabled=False,
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "req(id): Map test to SATRA functional or non-functional requirement ID")
