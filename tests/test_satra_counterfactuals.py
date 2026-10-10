import pytest
from pathlib import Path
from backend.satra import counterfactuals, test_validator
from test_satra_gitkit import git_do, make_settings, start_repo, record, IDENTITY
import subprocess, os


def test_mutate_file_ast_ownership(tmp_path):
    f = tmp_path / "main.py"
    f.write_text("""
def read_invoice(user, invoice):
    if user['id'] != invoice['owner_id']:
        raise Exception(403)
    return invoice
""")
    res = counterfactuals.mutate_file_ast(f, counterfactuals.op_replace_ownership_predicate)
    assert res is True
    assert "False" in f.read_text()


def test_static_integrity_catches_broadened_assertion():
    base_src = "def test_sec():\n    assert r.status_code == 403\n"
    cand_src = "def test_sec():\n    assert r.status_code in [200, 403]\n"
    findings = test_validator.check_static_test_integrity(base_src, cand_src)
    assert len(findings) == 1
    assert findings[0]["category"] == "ASSERTION_WEAKENED"


def test_judge_on_scenario_branches(tmp_path):
    seed_script = Path(__file__).resolve().parents[1] / "scripts" / "satra_seed_threat_repo.sh"
    repo = start_repo(tmp_path, "target")
    record(repo, {"TestFile.py": "print('init')\n"}, message="init")

    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(IDENTITY)
    subprocess.run(["bash", str(seed_script), str(repo)], capture_output=True, text=True, env=env, check=True)

    git_do(repo, "checkout", "-q", "main")
    main_dir = tmp_path / "main_dir"
    import shutil
    shutil.copytree(repo, main_dir)

    git_do(repo, "checkout", "-q", "scenario/weakened-test")
    res_weak = test_validator.judge_counterfactual_oracles(main_dir, repo)
    assert res_weak["verdict"] == "ORACLE_WEAKENED"
    assert len(res_weak["kill_matrix"]["integrity_findings"]) > 0

    git_do(repo, "checkout", "-q", "scenario/secure-refactor")
    res_refactor = test_validator.judge_counterfactual_oracles(main_dir, repo)
    assert res_refactor["verdict"] == "PRESERVED_WITHIN_MODEL"
