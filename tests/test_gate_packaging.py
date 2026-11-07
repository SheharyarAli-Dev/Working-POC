"""Step 10 of docs/dev-env-plan.md: the CLI in the Docker image and a reusable GitHub Actions workflow.

The workflow files are parsed with PyYAML and checked for what makes them safe to copy into any
repository: read-only permissions, no `pull_request_target`, no untrusted `${{ }}` expansion inside
shell scripts, full history for the base commit, the real `asent gate` command with the PR's base and
head SHAs, and the exit-code mapping. The `scripts/asent` wrapper is run for real.
(Docker is not installed on this machine: the image itself is built and smoke-tested by cd.yml.)
"""
import os
import re
import subprocess
import sys
from pathlib import Path

import yaml

from gate_support import GateRepo, config

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/asent-gate.yml"
CALLER = REPO / "docs/gate/asent-pr.yml"
WRAPPER = REPO / "scripts/asent"


def load(path):
    data = yaml.safe_load(path.read_text())
    data["on"] = data.pop(True, data.get("on"))  # YAML 1.1 reads the key `on` as true
    return data


def steps(workflow):
    return [step for job in workflow["jobs"].values() for step in job.get("steps", [])]


def test_reusable_workflow_interface():
    workflow = load(WORKFLOW)
    call = workflow["on"]["workflow_call"]
    assert call["inputs"]["asent-repository"]["required"] is True
    assert call["inputs"]["asent-ref"]["required"] is True
    assert call["inputs"]["review-fails"]["type"] == "boolean" and call["inputs"]["review-fails"]["default"] is True
    assert {"decision", "exit-code"} <= set(call["outputs"])


def test_workflow_permissions_are_read_only():
    for path in (WORKFLOW, CALLER):
        workflow = load(path)
        assert workflow["permissions"] == {"contents": "read"}, path
        for job in workflow["jobs"].values():
            assert job.get("permissions", {"contents": "read"}) == {"contents": "read"}, path


def test_no_pull_request_target_anywhere():
    for path in (WORKFLOW, CALLER):
        assert "pull_request_target" not in path.read_text(), path


def test_no_untrusted_expressions_inside_shell_scripts():
    # Event data reaches scripts only through env, so a crafted ref or title cannot inject shell code.
    for step in steps(load(WORKFLOW)):
        if "run" in step:
            assert "${{" not in step["run"], step.get("name")


def test_checkouts_have_full_history_and_no_persisted_credentials():
    checkouts = [s for s in steps(load(WORKFLOW)) if str(s.get("uses", "")).startswith("actions/checkout@")]
    target = next(s for s in checkouts if s["with"]["path"] == "target")
    asent = next(s for s in checkouts if s["with"]["path"] == "asent")
    assert target["with"]["fetch-depth"] == 0
    assert asent["with"]["repository"] == "${{ inputs.asent-repository }}" and asent["with"]["ref"] == "${{ inputs.asent-ref }}"
    assert all(s["with"]["persist-credentials"] is False for s in checkouts)


def test_gate_step_uses_the_pull_request_shas_and_maps_exit_codes():
    all_steps = steps(load(WORKFLOW))
    gate = next(s for s in all_steps if "asent gate" in s.get("run", ""))
    assert re.search(r'asent/scripts/asent gate --repository target --base "\$BASE_SHA" --head "\$HEAD_SHA"', gate["run"])
    assert "github.event.pull_request.base.sha" in gate["env"]["BASE_SHA"]
    assert "github.event.pull_request.head.sha" in gate["env"]["HEAD_SHA"]
    assert "GITHUB_STEP_SUMMARY" in gate["run"] and "GITHUB_OUTPUT" in gate["run"]
    build = next(s for s in all_steps if "docker build" in s.get("run", ""))
    assert "asent-sandbox:local" in build["run"] and "sandbox.Dockerfile" in build["run"]
    upload = next(s for s in all_steps if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["if"] == "always()"
    decide = all_steps[-1]
    assert "REVIEW_FAILS" in decide["env"] and re.search(r'"1"\)', decide["run"]) and re.search(r'"2"\)', decide["run"])


def test_caller_example_runs_on_pull_requests():
    caller = load(CALLER)
    assert set(caller["on"]) == {"pull_request"}
    (job,) = caller["jobs"].values()
    assert job["uses"].startswith("SheharyarAli-Dev/Working-POC/.github/workflows/asent-gate.yml@")
    assert job["with"]["asent-repository"] == "SheharyarAli-Dev/Working-POC"


def test_dockerfile_installs_the_cli_and_keeps_the_server():
    text = (REPO / "Dockerfile").read_text()
    assert "install -m 0755 scripts/asent /usr/local/bin/asent" in text
    assert "ENV ASENT_HOME=/app" in text
    assert text.strip().splitlines()[-1].startswith('CMD ["python", "-m", "uvicorn"')


def test_cd_smoke_test_runs_the_gate_cli():
    assert 'asent gate --help' in (REPO / ".github/workflows/cd.yml").read_text()


def test_wrapper_is_executable_and_runs_a_real_gate(tmp_path):
    assert os.access(WRAPPER, os.X_OK)
    env = {**os.environ, "ASENT_PYTHON": sys.executable}
    help_text = subprocess.run([str(WRAPPER), "gate", "--help"], env=env, capture_output=True, text=True, cwd=tmp_path)
    assert help_text.returncode == 0 and "--repository" in help_text.stdout
    repo = GateRepo(tmp_path / "repo")
    base = repo.commit({".asent/config.json": config(CAVR={"enabled": False, "reason": "x"}), "README.md": "x\n"})
    result = subprocess.run([str(WRAPPER), "gate", "--repository", str(repo.root), "--base", base, "--head", base,
                             "--output-dir", str(tmp_path / "out")], env=env, capture_output=True, text=True, cwd=tmp_path)
    # No module applies to a README-only project: REVIEW, exit 2, and both files are written.
    assert result.returncode == 2, result.stderr
    assert (tmp_path / "out/asent-report.json").is_file() and (tmp_path / "out/asent-summary.md").is_file()
