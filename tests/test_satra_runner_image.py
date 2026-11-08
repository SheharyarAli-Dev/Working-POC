"""SATRA runner base image (docker/satra-runner.Dockerfile): pytest only, hash-pinned, wheels only.

Static checks of the files; the Docker check of the built image is in
tests/test_satra_project_image_docker.py (it must run, not skip, in CI).
"""
import re

import pytest

from backend.config import ROOT
from backend.satra import project_image

DOCKERFILE = ROOT / "docker/satra-runner.Dockerfile"
REQUIREMENTS = ROOT / "docker/satra-runner.requirements.txt"
LINE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*==[0-9][0-9A-Za-z.+!-]* --hash=sha256:[0-9a-f]{64}$")


def test_every_runner_requirement_is_one_exact_pin_with_one_hash():
    lines = [line for line in REQUIREMENTS.read_text().splitlines() if line.strip() and not line.startswith("#")]
    assert lines, "the runner needs pytest"
    for line in lines:
        assert LINE.match(line), line


def test_runner_pins_are_pytest_and_its_linux_dependencies_only():
    pins = project_image.runner_pins()
    assert set(pins) == {"pytest", "pluggy", "iniconfig", "packaging", "pygments"}
    assert pins["pytest"]["version"] == "9.1.1"
    assert all(len(pin["hashes"]) == 1 for pin in pins.values())


def test_runner_dockerfile_uses_a_pinned_base_and_installs_wheels_by_hash_only():
    text = DOCKERFILE.read_text()
    assert re.search(r"^FROM python:3\.12-slim@sha256:[0-9a-f]{64}$", text, re.M)
    install = " ".join(text.split("RUN", 1)[1].split())
    for flag in ("--require-hashes", "--no-deps", "--only-binary :all:", "-r /opt/asent/satra-runner.requirements.txt"):
        assert flag in install
    copies = re.findall(r"^COPY .*$", text, re.M)
    assert copies == ["COPY satra-runner.requirements.txt /opt/asent/satra-runner.requirements.txt"]
    assert "pip install ." not in text and " -e " not in text


def test_runner_pins_reader_refuses_a_line_without_a_hash(tmp_path):
    bad = tmp_path / "r.txt"
    bad.write_text("pytest==9.1.1\n")
    try:
        project_image.runner_pins(bad)
    except ValueError as exc:
        assert "pytest==9.1.1" in str(exc)
    else:
        raise AssertionError("an unhashed runner line was accepted")


def test_build_script_builds_the_runner_image():
    script = (ROOT / "scripts/satra_build_sandbox.sh").read_text()
    assert "-t asent-satra-runner:local" in script and "docker/satra-runner.Dockerfile" in script


# --- CI: images are built the same way, and Docker-backed tests must really run -------------------

import ast  # noqa: E402

import yaml  # noqa: E402

WORKFLOWS = ROOT / ".github/workflows"


def _steps(path):
    data = yaml.safe_load(path.read_text())
    return {name: job.get("steps", []) for name, job in data["jobs"].items()}


def _docker_tests():
    tree = ast.parse((ROOT / "tests/test_satra_project_image_docker.py").read_text())
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}


def test_satra_ci_fails_when_any_docker_backed_test_is_missing_or_skipped():
    jobs = _steps(WORKFLOWS / "satra-ci.yml")
    [check] = [s for s in jobs["satra-suite"] if s.get("name") == "Verify Docker sandbox tests ran without skips"]
    for name in _docker_tests() | {"test_sandbox_network_isolated", "test_sandbox_readonly_root"}:
        assert f'"{name}"' in check["run"], name
    assert "test_satra_project_image_docker" in check["run"]  # every test of that module, not only the listed ones
    run = [s for s in jobs["satra-suite"] if "pytest" in s.get("run", "") and "junitxml" in s.get("run", "")][0]["run"]
    assert "tests/test_satra*.py" in run


def test_both_satra_ci_jobs_build_the_runner_through_the_build_script():
    for name, steps in _steps(WORKFLOWS / "satra-ci.yml").items():
        names = [s.get("run", "") for s in steps]
        assert any("scripts/satra_build_sandbox.sh" in r for r in names), name
    assert any("asent-satra-runner:local" in s.get("run", "") for s in _steps(WORKFLOWS / "satra-ci.yml")["satra-suite"])


def test_reusable_gate_workflow_builds_the_runner_before_the_gate_runs():
    [steps] = _steps(WORKFLOWS / "asent-gate.yml").values()
    runs = [s.get("run", "") for s in steps]
    build = next(i for i, r in enumerate(runs) if "-t asent-satra-runner:local" in r)
    gate = next(i for i, r in enumerate(runs) if "asent gate" in r)
    assert build < gate and "-f asent/docker/satra-runner.Dockerfile asent/docker" in runs[build]


@pytest.mark.parametrize("name", ["asent-gate.yml", "satra-ci.yml"])
def test_gate_and_satra_ci_workflows_do_not_switch_to_a_buildx_builder(name):
    # docker/setup-buildx-action (like `docker buildx create`/`use`) makes a docker-container builder the
    # default for later `docker build`s. That builder cannot see the local image store, so the gate
    # image's `FROM asent-satra-runner:local` would fail (pull access denied) and every gate run would
    # be INCONCLUSIVE. cd.yml may use it: it never builds FROM the runner.
    path = WORKFLOWS / name
    uses = [step.get("uses", "") for steps in _steps(path).values() for step in steps]
    assert not [u for u in uses if u.split("@")[0].strip() == "docker/setup-buildx-action"], uses
    text = path.read_text(encoding="utf-8")
    for phrase in ("setup-buildx-action", "buildx create", "buildx use"):
        assert phrase not in text, phrase


def test_no_shipped_workflow_or_image_turns_on_cached_gate_image_reuse():
    # Reuse of a cached gate image is for local development only (backend/satra/project_image.py).
    shipped = [*sorted(WORKFLOWS.glob("*.yml")), *sorted(WORKFLOWS.glob("*.yaml")), ROOT / "docs/gate/asent-pr.yml",
               ROOT / "Dockerfile", *sorted((ROOT / "docker").glob("*.Dockerfile"))]
    assert {WORKFLOWS / "asent-gate.yml", WORKFLOWS / "satra-ci.yml"} <= set(shipped)
    for path in shipped:
        assert "ASENT_SATRA_REUSE_IMAGES" not in path.read_text(encoding="utf-8"), path
    assert project_image.REUSE_ENV == "ASENT_SATRA_REUSE_IMAGES"


def test_sandbox_doc_states_that_cached_image_reuse_is_opt_in():
    text = (ROOT / "docs/satra/per-project-sandbox.md").read_text(encoding="utf-8")
    assert "ASENT_SATRA_REUSE_IMAGES=1" in text and "--no-cache" in text


def test_gate_documentation_states_the_dependency_rule_and_limits():
    text = (ROOT / "docs/asent-gate.md").read_text()
    for phrase in ("asent-satra-runner:local", "dependencies.lock.json", "its own pull request", ".asent/satra/sandbox.json",
                   "180", "2g", "INCONCLUSIVE"):
        assert phrase in text, phrase
