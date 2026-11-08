"""Packaging step 4a: `asent doctor` checks, explains and prints fixes; it never changes anything.

Each failure is produced on its own with fake `which`/`run` probes, so the tests do not depend on
what this machine has installed. One test runs the real probes on this machine and only checks the
shape. Every command doctor may run is read-only: `git --version`, `docker info`,
`docker image inspect`; it never builds, pulls, runs containers or calls sudo.
"""
import json
import subprocess
from pathlib import Path

import pytest

from backend import cli
from backend.commands import doctor
from backend.config import ASSETS, VERSION

IMAGES = ("asent-sandbox:local", "asent-satra-runner:local")
REAL_RUN_CHECKS = doctor.run_checks  # the CLI tests replace doctor.run_checks with a call to this


class Machine:
    """A fake machine: which tools exist and how each read-only probe answers. Records every command."""

    def __init__(self, tools=("git", "docker"), daemon=True, images=IMAGES):
        self.tools, self.daemon, self.images, self.commands = set(tools), daemon, set(images), []

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.tools else None

    def run(self, argv):
        self.commands.append(list(argv))
        done = lambda code, out="", err="": subprocess.CompletedProcess(argv, code, out, err)
        if argv[:2] == ["git", "--version"]:
            return done(0, "git version 2.43.0\n")
        if argv[:2] == ["docker", "info"]:
            return done(0, "27.1.1\n") if self.daemon else done(1, "", "Cannot connect to the Docker daemon at unix:///var/run/docker.sock")
        if argv[:3] == ["docker", "image", "inspect"]:
            return done(0, "sha256:abc\n") if argv[-1] in self.images else done(1, "", "No such image: " + argv[-1])
        raise AssertionError(f"doctor ran a command it must not run: {argv}")


def check(result, name):
    return next(c for c in result["checks"] if c["id"] == name)


def run_doctor(machine, version=(3, 12, 4)):
    return REAL_RUN_CHECKS(which=machine.which, run=machine.run, version_info=version)


def test_everything_present_is_ready():
    result = run_doctor(Machine())
    assert result["ready"] is True and result["schema"] == "asent.doctor.v1" and result["version"] == VERSION
    required = [c for c in result["checks"] if c["required"]]
    assert {c["id"] for c in required} == {"python", "resources", "git", "docker", "docker-daemon",
                                          "image:asent-sandbox:local", "image:asent-satra-runner:local"}
    assert all(c["status"] == "ok" and c["fix"] is None for c in required)


def test_old_python_is_missing_with_a_fix():
    result = run_doctor(Machine(), version=(3, 11, 9))
    python = check(result, "python")
    assert result["ready"] is False and python["status"] == "missing"
    assert "3.11.9" in python["detail"] and "3.12" in python["fix"]


def test_no_git():
    result = run_doctor(Machine(tools=("docker",)))
    git = check(result, "git")
    assert result["ready"] is False and git["status"] == "missing" and "install git" in git["fix"].lower()
    assert "gate" in git["detail"]


def test_no_docker_skips_daemon_and_images_and_says_what_it_means():
    machine = Machine(tools=("git",))
    result = run_doctor(machine)
    docker = check(result, "docker")
    assert result["ready"] is False and docker["status"] == "missing"
    assert "SATRA" in docker["detail"] and "REVIEW" in docker["detail"]
    for name in ("docker-daemon", "image:asent-sandbox:local", "image:asent-satra-runner:local"):
        assert check(result, name)["status"] == "skipped"
    assert not any(cmd[0] == "docker" for cmd in machine.commands)


def test_daemon_down():
    result = run_doctor(Machine(daemon=False))
    daemon = check(result, "docker-daemon")
    assert result["ready"] is False and daemon["status"] == "missing"
    assert "Cannot connect" in daemon["detail"] and "start docker" in daemon["fix"].lower()
    assert check(result, "image:asent-satra-runner:local")["status"] == "skipped"


def test_missing_image_prints_the_exact_build_command_with_packaged_paths():
    result = run_doctor(Machine(images=("asent-sandbox:local",)))
    image = check(result, "image:asent-satra-runner:local")
    assert result["ready"] is False and image["status"] == "missing"
    assert image["fix"] == (f"docker build -t asent-satra-runner:local -f {ASSETS / 'docker/satra-runner.Dockerfile'} "
                            f"{ASSETS / 'docker'}")
    sandbox = doctor.build_command("asent-sandbox:local")
    assert sandbox == f"docker build -t asent-sandbox:local -f {ASSETS / 'docker/sandbox.Dockerfile'} {ASSETS}"
    assert check(result, "image:asent-sandbox:local")["status"] == "ok"


def test_missing_packaged_resources(tmp_path):
    result = doctor.run_checks(which=Machine().which, run=Machine().run, version_info=(3, 12, 0), assets=tmp_path)
    resources = check(result, "resources")
    assert result["ready"] is False and resources["status"] == "missing"
    assert "docker/asent-seccomp.json" in resources["detail"] and "reinstall" in resources["fix"].lower()


def test_dashboard_ui_is_optional_and_said_plainly(tmp_path, monkeypatch):
    monkeypatch.setattr(doctor, "ui_bundled", lambda: False)
    result = run_doctor(Machine())
    ui = check(result, "dashboard-ui")
    assert result["ready"] is True and ui["required"] is False and ui["status"] == "warning"
    assert "API only" in ui["detail"]


def test_doctor_only_runs_read_only_probes():
    for machine in (Machine(), Machine(daemon=False), Machine(images=())):
        run_doctor(machine)
        for cmd in machine.commands:
            assert cmd[:2] in (["git", "--version"], ["docker", "info"]) or cmd[:3] == ["docker", "image", "inspect"], cmd
    # And the module itself has no other way to run or change anything.
    source = Path(doctor.__file__).read_text()
    # (quoted command words: the prose and the printed fix text may mention them)
    for forbidden in ('"sudo"', "'sudo'", '"build"', "'build'", '"pull"', "'pull'", '"run"', "'run'", "Popen", "os.system",
                      "shutil.rmtree", "write_text", "mkdir", "unlink"):
        assert forbidden not in source, forbidden


def test_cli_doctor_text_and_exit_code(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_checks", lambda: run_doctor(Machine(daemon=False)))
    assert cli.main(["doctor"]) == 1
    out = capsys.readouterr().out
    assert "MISSING" in out and "Docker daemon" in out and "fix:" in out and "Not ready" in out
    monkeypatch.setattr(doctor, "run_checks", lambda: run_doctor(Machine()))
    assert cli.main(["doctor"]) == 0
    assert "Ready" in capsys.readouterr().out


def test_cli_doctor_json(monkeypatch, capsys):
    monkeypatch.setattr(doctor, "run_checks", lambda: run_doctor(Machine(images=())))
    assert cli.main(["doctor", "--json"]) == 1
    out = json.loads(capsys.readouterr().out)
    assert out["ready"] is False and out["assets"] == str(ASSETS)
    assert all(set(c) == {"id", "label", "status", "required", "detail", "fix"} for c in out["checks"])


def test_real_probes_on_this_machine_have_the_documented_shape():
    result = doctor.run_checks()
    assert isinstance(result["ready"], bool)
    assert {c["status"] for c in result["checks"]} <= {"ok", "missing", "warning", "skipped"}
    assert check(result, "resources")["status"] == "ok"  # this checkout has every asset
