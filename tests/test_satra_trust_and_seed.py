import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from backend.satra import trust

TRUSTED_DIR = trust.TRUST_DIR
SEED_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "satra_seed_threat_repo.sh"
from test_satra_gitkit import IDENTITY, git_do, record, start_repo


def clone_trusted(tmp_path):
    target = tmp_path / "trusted"
    shutil.copytree(TRUSTED_DIR, target, ignore=shutil.ignore_patterns("__pycache__"))
    return target


def test_shipped_manifest_is_valid():
    outcome = trust.verify_manifest()
    assert outcome["valid"], outcome


def test_manifest_lists_every_trusted_test():
    listed = set(trust.compute_table())
    assert "policy.json" in listed and "SRS.md" in listed
    assert any(name.startswith("trusted_tests/test_authz_idor") for name in listed)


def test_modified_file_is_detected(tmp_path):
    copy = clone_trusted(tmp_path)
    (copy / "policy.json").write_text((copy / "policy.json").read_text().replace("403", "200"))
    outcome = trust.verify_manifest(copy)
    assert not outcome["valid"] and outcome["mismatched"] == ["policy.json"]


def test_deleted_file_is_detected(tmp_path):
    copy = clone_trusted(tmp_path)
    (copy / "trusted_tests" / "test_sqli.py").unlink()
    outcome = trust.verify_manifest(copy)
    assert not outcome["valid"] and outcome["missing"] == ["trusted_tests/test_sqli.py"]


def test_planted_file_is_detected(tmp_path):
    copy = clone_trusted(tmp_path)
    (copy / "trusted_tests" / "test_extra.py").write_text("def test_x():\n    assert True\n")
    outcome = trust.verify_manifest(copy)
    assert not outcome["valid"] and outcome["unlisted"] == ["trusted_tests/test_extra.py"]


def test_missing_manifest_is_invalid(tmp_path):
    copy = clone_trusted(tmp_path)
    (copy / trust.MANIFEST_NAME).unlink()
    assert trust.verify_manifest(copy)["valid"] is False


def test_line_endings_do_not_change_fingerprint():
    assert trust.fingerprint_bytes(b"a\r\nb\r\n") == trust.fingerprint_bytes(b"a\nb\n")


@pytest.fixture(scope="module")
def seeded(tmp_path_factory):
    if shutil.which("bash") is None:
        pytest.skip("bash unavailable")
    root = tmp_path_factory.mktemp("seed")
    repo = start_repo(root, "target")
    record(repo, {"TestFile.py": "print('legacy')\n"}, message="legacy history")
    import os

    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(IDENTITY)
    done = subprocess.run(["bash", str(SEED_SCRIPT), str(repo)], capture_output=True, text=True, env=environment)
    assert done.returncode == 0, done.stderr
    return repo


def checkout_and_run(repo, branch, suite):
    import os

    git_do(repo, "checkout", "-q", branch)
    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment["PYTHONPATH"] = str(repo)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    arguments = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"]
    if suite == "trusted":
        arguments += ["-c", str(TRUSTED_DIR / "trusted_pytest.ini"), "--rootdir", str(TRUSTED_DIR), str(TRUSTED_DIR / "trusted_tests")]
    return subprocess.run(arguments, cwd=repo, capture_output=True, text=True, env=environment).returncode


def test_seed_creates_all_branches(seeded):
    names = set(git_do(seeded, "branch", "--format=%(refname:short)").split())
    assert names >= {"main", "scenario/idor-bypass", "scenario/weakened-test", "scenario/sqli-fstring", "scenario/path-traversal", "scenario/docs-only", "scenario/secure-refactor"}


def test_seed_refuses_to_run_twice(seeded):
    import os

    environment = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    environment.update(IDENTITY)
    git_do(seeded, "checkout", "-q", "main")
    again = subprocess.run(["bash", str(SEED_SCRIPT), str(seeded)], capture_output=True, text=True, env=environment)
    assert again.returncode != 0


def test_baseline_own_suite_passes(seeded):
    assert checkout_and_run(seeded, "main", "own") == 0


def test_trusted_suite_passes_on_main_in_plain_subprocess(seeded):
    assert checkout_and_run(seeded, "main", "trusted") == 0


@pytest.mark.parametrize("branch", ["scenario/idor-bypass", "scenario/sqli-fstring", "scenario/path-traversal", "scenario/weakened-test"])
def test_trusted_suite_fails_on_attack_branches(seeded, branch):
    assert checkout_and_run(seeded, branch, "trusted") != 0


@pytest.mark.parametrize("branch", ["scenario/docs-only", "scenario/secure-refactor"])
def test_trusted_suite_passes_on_benign_branches(seeded, branch):
    assert checkout_and_run(seeded, branch, "trusted") == 0


def test_weakened_branch_is_green_for_its_own_suite(seeded):
    assert checkout_and_run(seeded, "scenario/weakened-test", "own") == 0


def test_idor_branch_fails_its_own_suite(seeded):
    assert checkout_and_run(seeded, "scenario/idor-bypass", "own") != 0
