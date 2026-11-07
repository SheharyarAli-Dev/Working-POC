"""Done criterion of docs/dev-env-plan.md: `asent init`, a person's review, then `asent gate`.

A fresh project (the InvoiceHub application code and requirements in a new git repository), through
the real CLI. The starter gives REVIEW; after review an unchanged dependency gives ACCEPT, a denied
package gives BLOCK, and a pull request that edits `.asent/` gives REVIEW again.
"""
import json

from backend import cli
from gate_support import GateRepo, invoice_app_files, recorded_pypi, run_cli
from test_cavr_support import POLICY


def test_init_review_gate(tmp_path, monkeypatch):
    recorded_pypi(monkeypatch, tmp_path)
    repo = GateRepo(tmp_path / "repo")
    repo.commit({**invoice_app_files(), "requirements.txt": "pypdf==6.19.0\n"}, message="project")
    assert cli.main(["init", "--repository", str(repo.root)]) == 0
    starter = repo.commit({}, message="asent init")

    code, report, _ = run_cli(repo, starter, starter, tmp_path / "out-starter")
    assert code == 2 and any("ASENT_CONFIG_STARTER" in reason for reason in report["reasons"])

    # The review: describe the task, grant only the capabilities the application needs, drop _starter.
    policy_path = repo.root / ".asent/cavr/policy.json"
    policy = json.loads(policy_path.read_text())
    assert policy["approved_requirements"] == ["pypdf==6.19.0"]
    policy.update(project_task_description=POLICY["project_task_description"], allowed_scopes=POLICY["allowed_scopes"],
                  denied_packages=POLICY["denied_packages"])
    policy_path.write_text(json.dumps(policy, indent=2))
    config_path = repo.root / ".asent/config.json"
    settings = json.loads(config_path.read_text())
    settings.pop("_starter")
    config_path.write_text(json.dumps(settings, indent=2))
    reviewed = repo.commit({}, message="reviewed .asent")

    head = repo.commit({"README.md": "docs\n"}, message="docs only")
    code, report, summary = run_cli(repo, reviewed, head, tmp_path / "out-accept")
    assert code == 0 and report["decision"] == "ACCEPT", report["reasons"]
    assert report["modules"]["SATRA"]["result"] == "not assessed (disabled by base config)"

    denied = repo.commit({"requirements.txt": "pypdf==6.19.0\nreqeusts==2.31.0\n"}, message="typosquat")
    code, report, _ = run_cli(repo, reviewed, denied, tmp_path / "out-block")
    assert code == 1 and report["decision"] == "BLOCK"

    loosened = repo.commit({"requirements.txt": "pypdf==6.19.0\n", ".asent/cavr/policy.json": json.dumps({**policy, "denied_packages": []})},
                           message="edit policy in the PR")
    code, report, _ = run_cli(repo, reviewed, loosened, tmp_path / "out-config")
    assert code == 2 and report["config"]["changed_in_head"] is True
