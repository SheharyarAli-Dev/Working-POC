"""Packaging step 6: `.github/workflows/package.yml` builds, checks, uploads and runs the installed wheel.

Parsed with PyYAML like tests/test_gate_packaging.py: read-only token, no pull_request_target, no
`${{ }}` inside shell scripts, the wheel uploaded as an artifact, and the installed `asent` run from
outside the checkout (fresh venv in $RUNNER_TEMP, no PYTHONPATH, never the scripts/asent wrapper).
"""
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github/workflows/package.yml"


def load():
    data = yaml.safe_load(WORKFLOW.read_text())
    data["on"] = data.pop(True, data.get("on"))
    return data


def steps(job):
    return load()["jobs"][job]["steps"]


def runs(job):
    return "\n".join(step.get("run", "") for step in steps(job))


def test_permissions_and_triggers_are_safe():
    workflow = load()
    assert workflow["permissions"] == {"contents": "read"}
    assert all("permissions" not in job for job in workflow["jobs"].values())
    assert "pull_request_target" not in WORKFLOW.read_text()
    assert set(workflow["on"]) == {"push", "pull_request", "workflow_dispatch"}
    for job in workflow["jobs"].values():
        for step in job["steps"]:
            if "run" in step:
                assert "${{" not in step["run"], step.get("name")
            if str(step.get("uses", "")).startswith("actions/checkout@"):
                assert step["with"]["persist-credentials"] is False


def test_wheel_job_bundles_the_ui_checks_and_uploads():
    text = runs("wheel")
    assert text.index("npm run build --prefix frontend") < text.index("python -m build --wheel")
    assert "scripts/ci/check_wheel.py dist/*.whl --require-ui" in text
    upload = next(s for s in steps("wheel") if str(s.get("uses", "")).startswith("actions/upload-artifact@"))
    assert upload["with"]["name"] == "asent-wheel" and upload["with"]["if-no-files-found"] == "error"


def test_installed_job_uses_a_fresh_venv_outside_the_checkout():
    workflow = load()
    job = workflow["jobs"]["installed"]
    assert job["needs"] == "wheel"
    checkout = next(s for s in job["steps"] if str(s.get("uses", "")).startswith("actions/checkout@"))
    assert checkout["with"]["path"] == "source"  # the checkout is a subfolder; asent runs in $RUNNER_TEMP
    text = runs("installed")
    assert 'python -m venv "$RUNNER_TEMP/venv"' in text
    assert '--constraint source/requirements.lock.txt "$RUNNER_TEMP"/wheel/*.whl' in text
    assert "unset PYTHONPATH" in text and "scripts/asent " not in text and "pip install -e" not in text
    for step in job["steps"]:
        if "asent " in step.get("run", "") and "venv" not in step.get("name", ""):
            assert step.get("working-directory") == "${{ runner.temp }}", step["name"]


def test_installed_job_runs_version_doctor_and_gate_with_expected_decisions():
    text = runs("installed")
    for command in ("asent --version", "asent --version --json", "asent doctor --json", "asent gate --json", "asent report"):
        assert command in text, command
    assert "accept:0:ACCEPT block:1:BLOCK" in text and "make_sample_repo.sh" in text
    assert 'docker build -t asent-sandbox:local -f "$assets/docker/sandbox.Dockerfile" "$assets"' in text
    assert 'docker build -t asent-satra-runner:local -f "$assets/docker/satra-runner.Dockerfile" "$assets/docker"' in text
