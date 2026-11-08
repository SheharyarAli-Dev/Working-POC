"""Packaging step 3: `asent --version`, `--json`, and `asent gate` defaults.

`asent gate` with no arguments gates the current repository: its top level (found from any
subdirectory), head HEAD, and a base that is the repository's default branch:

1. `origin/HEAD` when it names an existing remote-tracking branch (refs/remotes/origin/<name>);
2. otherwise the local branch `main`, then the local branch `master` (branches only, never a tag);
3. otherwise no base: REVIEW, exit 2, with the reason in the report.

Every case is a real git repository; the decision itself comes from the unchanged `run_gate`.
"""
import json
from pathlib import Path

import pytest

from backend import cli
from backend.config import VERSION
from backend.gate import defaults
from gate_support import GateRepo, config, git

NO_MODULES = config(CAVR={"enabled": False, "reason": "x"})


def repo_on(tmp_path, branch, name="repo"):
    repo = GateRepo(tmp_path / name)
    git(repo.root, "symbolic-ref", "HEAD", f"refs/heads/{branch}")  # unborn, so `main` never exists
    return repo


def gate_json(capsys, *argv):
    code = cli.main(["gate", "--json", *argv])
    out = capsys.readouterr().out
    return code, json.loads(out)


# --- default branch ----------------------------------------------------------------------------------

def test_origin_head_names_the_default_branch_even_when_it_is_not_main_or_master(tmp_path, capsys, monkeypatch):
    upstream = repo_on(tmp_path, "trunk", "upstream")
    trunk = upstream.commit({".asent/config.json": NO_MODULES, "README.md": "x\n"})
    clone = tmp_path / "clone"
    git(tmp_path, "clone", "-q", str(upstream.root), str(clone))
    assert git(clone, "symbolic-ref", "refs/remotes/origin/HEAD") == "refs/remotes/origin/trunk"
    git(clone, "checkout", "-q", "-b", "main")  # a local main exists but origin/HEAD wins
    git(clone, "-c", "user.email=t@e.invalid", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "head")
    (clone / "sub").mkdir()
    monkeypatch.chdir(clone / "sub")
    assert defaults.default_base(clone) == ("refs/remotes/origin/trunk", "origin/HEAD")
    code, report = gate_json(capsys)
    assert report["base"] == {"ref": "refs/remotes/origin/trunk", "sha": trunk}
    assert report["head"]["ref"] == "HEAD" and report["head"]["sha"] == git(clone, "rev-parse", "HEAD")
    assert report["repository"] == str(clone.resolve())
    assert (clone / "asent-report.json").is_file() and (clone / "asent-summary.md").is_file()
    assert code == report["exit_code"] == 2  # README-only project: no module applies


def test_dangling_origin_head_falls_back_to_main(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    repo.commit({"README.md": "x\n"})
    git(repo.root, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/gone")
    assert defaults.default_base(repo.root) == ("refs/heads/main", "branch main")


def test_main_is_used_without_origin(tmp_path, capsys, monkeypatch):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({".asent/config.json": NO_MODULES})
    git(repo.root, "checkout", "-q", "-b", "feature")
    head = repo.commit({"README.md": "x\n"})
    monkeypatch.chdir(repo.root)
    code, report = gate_json(capsys)
    assert report["base"] == {"ref": "refs/heads/main", "sha": base} and report["head"]["sha"] == head


def test_main_is_preferred_over_master(tmp_path):
    repo = GateRepo(tmp_path / "repo")
    repo.commit({"README.md": "x\n"})
    git(repo.root, "branch", "master")
    assert defaults.default_base(repo.root) == ("refs/heads/main", "branch main")


def test_master_is_used_when_there_is_no_main(tmp_path, capsys, monkeypatch):
    repo = repo_on(tmp_path, "master")
    base = repo.commit({".asent/config.json": NO_MODULES})
    monkeypatch.chdir(repo.root)
    assert defaults.default_base(repo.root) == ("refs/heads/master", "branch master")
    _, report = gate_json(capsys)
    assert report["base"] == {"ref": "refs/heads/master", "sha": base}


def test_a_tag_named_main_is_not_a_default_branch(tmp_path):
    repo = repo_on(tmp_path, "trunk")
    repo.commit({"README.md": "x\n"}, tag="main")
    assert defaults.default_base(repo.root) == (None, None)


def test_no_default_branch_is_review_with_a_clear_reason(tmp_path, capsys, monkeypatch):
    repo = repo_on(tmp_path, "trunk")
    repo.commit({".asent/config.json": NO_MODULES})
    monkeypatch.chdir(repo.root)
    code, report = gate_json(capsys)
    assert code == 2 and report["decision"] == "REVIEW" and report["exit_code"] == 2
    assert report["base"]["ref"] is None and report["base"]["sha"] is None
    assert any("no base commit" in r and "origin/HEAD" in r and "--base" in r for r in report["reasons"]), report["reasons"]
    assert (repo.root / "asent-report.json").is_file()


def test_explicit_base_and_head_override_the_defaults(tmp_path, capsys, monkeypatch):
    repo = repo_on(tmp_path, "trunk")  # no default branch at all
    first = repo.commit({".asent/config.json": NO_MODULES})
    second = repo.commit({"README.md": "x\n"})
    monkeypatch.chdir(repo.root)
    _, report = gate_json(capsys, "--base", first, "--head", second)
    assert report["base"] == {"ref": first, "sha": first} and report["head"] == {"ref": second, "sha": second}


def test_outside_a_git_repository_is_review(tmp_path, capsys, monkeypatch):
    monkeypatch.chdir(tmp_path)
    code, report = gate_json(capsys)
    assert code == 2 and report["decision"] == "REVIEW"
    assert any("not a git repository" in r or "no base commit" in r for r in report["reasons"])
    assert (tmp_path / "asent-report.json").is_file()


def test_run_gate_with_no_base_is_review(tmp_path):
    from backend.gate.runner import run_gate
    repo = GateRepo(tmp_path / "repo")
    repo.commit({"README.md": "x\n"})
    code, report = run_gate(repo.root, None, "HEAD", tmp_path / "out")
    assert code == 2 and report["decision"] == "REVIEW" and report["reasons"][0].startswith("no base commit")


# --- --json --------------------------------------------------------------------------------------------

def test_gate_json_prints_exactly_the_written_report(tmp_path, capsys):
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({".asent/config.json": NO_MODULES})
    code, printed = gate_json(capsys, "--repository", str(repo.root), "--base", base, "--head", base,
                              "--output-dir", str(tmp_path / "out"))
    assert printed == json.loads((tmp_path / "out/asent-report.json").read_text())
    assert code == printed["exit_code"]


def test_gate_text_output_names_the_chosen_base(tmp_path, capsys, monkeypatch):
    repo = GateRepo(tmp_path / "repo")
    repo.commit({".asent/config.json": NO_MODULES})
    monkeypatch.chdir(repo.root)
    cli.main(["gate"])
    out = capsys.readouterr().out
    assert "base refs/heads/main (branch main)" in out and "ASENT gate: REVIEW (exit 2)" in out


def test_version(capsys):
    assert cli.main(["--version"]) == 0
    assert capsys.readouterr().out == f"asent {VERSION}\n"
    assert cli.main(["--version", "--json"]) == 0
    assert json.loads(capsys.readouterr().out) == {"name": "asent", "version": VERSION}


def test_no_command_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as stop:
        cli.main([])
    assert stop.value.code == 2 and "asent" in capsys.readouterr().err


def test_init_json(tmp_path, capsys):
    (tmp_path / "requirements.txt").write_text("pypdf==6.19.0\nhttpx>=0.27\n")
    assert cli.main(["init", "--repository", str(tmp_path), "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert ".asent/config.json" in out["files"] and out["not_copied"] == ["httpx>=0.27"] and out["starter"] is True
    assert cli.main(["init", "--repository", str(tmp_path), "--json"]) == 2  # exists, not --force
    assert "error" in json.loads(capsys.readouterr().out)
