import pytest
from pathlib import Path
from backend.satra import dictionary, contract_runner
from backend.satra.trust import TRUST_DIR
from test_satra_gitkit import git_do, make_settings, start_repo
# seed test


def test_dictionary_rules_table():
    matrix = dictionary.get_coverage_matrix()
    assert len(matrix) >= 8
    tier1 = [r for r in matrix if r["tier"] == 1]
    assert len(tier1) >= 3
    assert all(r["status"] == "FULL" and r["test_file"] is not None for r in tier1)


def test_contract_runner_sanity_failure_gives_inconclusive(tmp_path):
    broken_app_dir = tmp_path / "broken"
    broken_app_dir.mkdir()
    (broken_app_dir / "app").mkdir()
    (broken_app_dir / "app" / "__init__.py").write_text("")
    (broken_app_dir / "app" / "main.py").write_text("def create_app(data_dir):\n    raise RuntimeError('boot error')\n")

    res = contract_runner.run_contract_test(broken_app_dir, "trusted_tests/test_authz_idor.py")
    assert res["verdict"] == "INCONCLUSIVE"
    assert "Sanity" in res["reason"] or "runtime errors" in res["reason"]


import sys


@pytest.mark.skipif(sys.platform == "win32", reason="Requires bash and POSIX execution for satra_seed_threat_repo.sh")
def test_tier1_rules_against_seed_repos(tmp_path):
    import os, subprocess
    from test_satra_gitkit import IDENTITY, start_repo, record

    seed_script = Path(__file__).resolve().parents[1] / "scripts" / "satra_seed_threat_repo.sh"
    repo = start_repo(tmp_path, "target")
    record(repo, {"TestFile.py": "print('legacy')\n"}, message="init")

    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(IDENTITY)
    subprocess.run(["bash", str(seed_script), str(repo)], capture_output=True, text=True, env=env, check=True)

    git_do(repo, "checkout", "-q", "main")
    res_idor_main = contract_runner.run_contract_test(repo, "trusted_tests/test_authz_idor.py")
    assert res_idor_main["verdict"] == "SATISFIED"

    res_sql_main = contract_runner.run_contract_test(repo, "trusted_tests/test_sqli.py")
    assert res_sql_main["verdict"] == "SATISFIED"

    res_path_main = contract_runner.run_contract_test(repo, "trusted_tests/test_path_traversal.py")
    assert res_path_main["verdict"] == "SATISFIED"

    git_do(repo, "checkout", "-q", "scenario/idor-bypass")
    res_idor_vuln = contract_runner.run_contract_test(repo, "trusted_tests/test_authz_idor.py")
    assert res_idor_vuln["verdict"] == "VIOLATED"

    git_do(repo, "checkout", "-q", "scenario/sqli-fstring")
    res_sql_vuln = contract_runner.run_contract_test(repo, "trusted_tests/test_sqli.py")
    assert res_sql_vuln["verdict"] == "VIOLATED"

    git_do(repo, "checkout", "-q", "scenario/path-traversal")
    res_path_vuln = contract_runner.run_contract_test(repo, "trusted_tests/test_path_traversal.py")
    assert res_path_vuln["verdict"] == "VIOLATED"
