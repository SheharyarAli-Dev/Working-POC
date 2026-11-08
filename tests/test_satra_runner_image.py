"""SATRA runner base image (docker/satra-runner.Dockerfile): pytest only, hash-pinned, wheels only.

Static checks of the files; the Docker check of the built image is in
tests/test_satra_project_image_docker.py (it must run, not skip, in CI).
"""
import re

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
