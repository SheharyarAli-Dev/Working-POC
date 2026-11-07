"""Step 3 of docs/dev-env-plan.md: resolve a ref and export one commit's exact files, without running anything.

Every case is a real git repository in tmp_path. The export must equal the committed blobs byte for
byte, ignore the repository's own attributes (`export-ignore` would hide files, `export-subst` would
rewrite them), never run hooks, and refuse what cannot be analysed (symlinks, submodules, unknown refs,
over-budget trees) with ValueError, which the gate turns into REVIEW.
"""
import os
import subprocess
from pathlib import Path

import pytest

from backend.integrations import git_adapter
from backend.integrations.git_adapter import export_commit, resolve_commit


def run(repo, *args):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True).stdout.strip()


def make_repo(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    run(path, "init", "-q", "-b", "main")
    run(path, "config", "user.email", "t@example.invalid")
    run(path, "config", "user.name", "t")
    return path


def commit(repo: Path, files: dict, message="c") -> str:
    for name, data in files.items():
        target = repo / name
        if data is None:
            target.unlink()
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data if isinstance(data, bytes) else data.encode())
    run(repo, "add", "-A")
    run(repo, "commit", "-q", "-m", message)
    return run(repo, "rev-parse", "HEAD")


def tree(root: Path) -> dict:
    return {p.relative_to(root).as_posix(): p.read_bytes() for p in sorted(root.rglob("*")) if p.is_file()}


def test_resolve_branch_tag_and_sha(tmp_path):
    repo = make_repo(tmp_path / "repo")
    first = commit(repo, {"a.txt": "1"})
    run(repo, "tag", "v1")
    second = commit(repo, {"a.txt": "2"})
    assert resolve_commit(repo, "main") == second
    assert resolve_commit(repo, "v1") == first
    assert resolve_commit(repo, first[:10]) == first
    assert resolve_commit(repo, "HEAD~1") == first


@pytest.mark.parametrize("ref", ["does-not-exist", "", "--output=/tmp/x", "HEAD:a.txt", "0" * 40])
def test_unknown_or_unsafe_ref(tmp_path, ref):
    repo = make_repo(tmp_path / "repo")
    commit(repo, {"a.txt": "1"})
    with pytest.raises(ValueError):
        resolve_commit(repo, ref)


def test_not_a_repository(tmp_path):
    (tmp_path / "plain").mkdir()
    with pytest.raises(ValueError, match="not a git repository"):
        resolve_commit(tmp_path / "plain", "HEAD")
    with pytest.raises(ValueError):
        resolve_commit(tmp_path / "missing", "HEAD")


def test_export_is_byte_exact_and_keeps_the_exec_bit(tmp_path):
    repo = make_repo(tmp_path / "repo")
    files = {"app/main.py": "print('x')\r\n", "bin/run.sh": "#!/bin/sh\n", "data.bin": bytes(range(256)),
             ".asent/config.json": "{}", "empty.txt": ""}
    commit(repo, files)
    os.chmod(repo / "bin/run.sh", 0o755)
    run(repo, "add", "-A"); run(repo, "commit", "-q", "-m", "exec bit")
    sha = run(repo, "rev-parse", "HEAD")
    dest = export_commit(repo, sha, tmp_path / "out")
    assert tree(dest) == {k: (v if isinstance(v, bytes) else v.encode()) for k, v in files.items()}
    assert os.stat(dest / "bin/run.sh").st_mode & 0o111
    assert not os.stat(dest / "app/main.py").st_mode & 0o111


def test_export_of_an_older_commit_ignores_the_worktree(tmp_path):
    repo = make_repo(tmp_path / "repo")
    first = commit(repo, {"a.txt": "old"})
    commit(repo, {"a.txt": "new", "b.txt": "added"})
    (repo / "c.txt").write_text("uncommitted")
    assert tree(export_commit(repo, first, tmp_path / "out")) == {"a.txt": b"old"}


def test_repository_attributes_cannot_hide_or_rewrite_files(tmp_path):
    repo = make_repo(tmp_path / "repo")
    sha = commit(repo, {".gitattributes": "hidden.py export-ignore\nsubst.txt export-subst\n*.txt text eol=crlf\n",
                        "hidden.py": "import os\n", "subst.txt": "$Format:%H$\n"})
    out = tree(export_commit(repo, sha, tmp_path / "out"))
    assert out["hidden.py"] == b"import os\n"
    assert out["subst.txt"] == b"$Format:%H$\n"


def test_hooks_are_not_run(tmp_path):
    repo = make_repo(tmp_path / "repo")
    marker = tmp_path / "hook-ran"
    for hook in ("post-checkout", "post-merge", "pre-commit", "reference-transaction"):
        path = repo / ".git/hooks" / hook
        path.write_text(f"#!/bin/sh\ntouch {marker}\n")
        os.chmod(path, 0o755)
    run(repo, "-c", "core.hooksPath=/dev/null", "commit", "-q", "--allow-empty", "-m", "c")
    sha = run(repo, "rev-parse", "HEAD")
    resolve_commit(repo, "HEAD")
    export_commit(repo, sha, tmp_path / "out")
    assert not marker.exists()


def test_symlink_in_commit_is_refused(tmp_path):
    repo = make_repo(tmp_path / "repo")
    commit(repo, {"real.txt": "x"})
    os.symlink("real.txt", repo / "link.txt")
    run(repo, "add", "-A"); run(repo, "commit", "-q", "-m", "link")
    with pytest.raises(ValueError, match="symlink"):
        export_commit(repo, run(repo, "rev-parse", "HEAD"), tmp_path / "out")


def test_submodule_is_refused(tmp_path):
    inner = make_repo(tmp_path / "inner")
    commit(inner, {"x.txt": "x"})
    repo = make_repo(tmp_path / "repo")
    commit(repo, {"a.txt": "a"})
    run(repo, "-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner), "vendor/inner")
    run(repo, "commit", "-q", "-m", "sub")
    with pytest.raises(ValueError, match="submodule"):
        export_commit(repo, run(repo, "rev-parse", "HEAD"), tmp_path / "out")


def test_budget_is_checked_before_reading(tmp_path, monkeypatch):
    repo = make_repo(tmp_path / "repo")
    sha = commit(repo, {"a.txt": "12345", "b.txt": "67890"})
    monkeypatch.setattr(git_adapter, "EXPORT_MAX_BYTES", 9)
    with pytest.raises(ValueError, match="budget"):
        export_commit(repo, sha, tmp_path / "out")
    monkeypatch.setattr(git_adapter, "EXPORT_MAX_BYTES", 10**9)
    monkeypatch.setattr(git_adapter, "EXPORT_MAX_FILES", 1)
    with pytest.raises(ValueError, match="budget"):
        export_commit(repo, sha, tmp_path / "out2")


def test_destination_must_be_new(tmp_path):
    repo = make_repo(tmp_path / "repo")
    sha = commit(repo, {"a.txt": "1"})
    (tmp_path / "out").mkdir()
    (tmp_path / "out/keep").write_text("k")
    with pytest.raises(ValueError):
        export_commit(repo, sha, tmp_path / "out")


def test_base_equal_to_head(tmp_path):
    repo = make_repo(tmp_path / "repo")
    sha = commit(repo, {"a.txt": "1"})
    assert tree(export_commit(repo, sha, tmp_path / "b")) == tree(export_commit(repo, sha, tmp_path / "h"))


def test_empty_tree(tmp_path):
    repo = make_repo(tmp_path / "repo")
    run(repo, "commit", "-q", "--allow-empty", "-m", "empty")
    assert tree(export_commit(repo, run(repo, "rev-parse", "HEAD"), tmp_path / "out")) == {}


def test_baseline_commit_message_is_generic(tmp_path):
    (tmp_path / "w").mkdir()
    (tmp_path / "w/a.txt").write_text("a")
    git_adapter.init_repo(tmp_path / "w")
    assert run(tmp_path / "w", "log", "-1", "--format=%s") == "Trusted baseline"


def test_baseline_of_an_empty_tree_can_be_committed(tmp_path):
    # A base commit with nothing but .asent/ (excluded from snapshots) gives an empty baseline.
    (tmp_path / "w").mkdir()
    assert len(git_adapter.init_repo(tmp_path / "w")) == 40
