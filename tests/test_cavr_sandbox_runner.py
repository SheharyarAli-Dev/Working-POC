"""Commit 0: package code must never run on the host.

No Docker, or a container run without a usable behavior report, is UNRESOLVED (fail closed).
The process launchers listed in `no_real_processes` are replaced in every test, so no test
starts a real process through them.
"""
import json
import os
import subprocess
import types
from pathlib import Path

import pytest

from backend.cavr import sandbox_runner
from backend.cavr.causal_graph import build_causal_graph
from backend.cavr.sandbox_runner import SandboxRunner

START = "--- ASENT_BEHAVIOR_REPORT_START ---"
END = "--- ASENT_BEHAVIOR_REPORT_END ---"
CLEAN_METRICS = {"network_attempts": 0, "writes_outside_scratch": 0, "processes_spawned": 0,
                 "secrets_touched": 0, "honeytoken_accessed": False}


def clean_report(**overrides):
    report = {"verdict": "ALLOW", "hash": "ab" * 32, "test_passed": True, "error": None,
              "metrics": dict(CLEAN_METRICS), "events": []}
    report.update(overrides)
    return report


def framed(report):
    """Container output carrying one behavior report, as the harness prints it."""
    return f"boot\n{START}\n{json.dumps(report)}\n{END}\n"


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    """Replace the process launchers of `subprocess` and `os` (system, popen, fork*, exec*,
    spawn*, posix_spawn*). A test that needs one installs its own fake on top.
    Calls are recorded and checked at teardown, because the runner catches exceptions."""
    forbidden = []

    def refuse(name):
        def launcher(*args, **kwargs):
            forbidden.append((name, args))
            raise AssertionError(f"{name} must not be called")
        return launcher

    for name in ("run", "call", "check_output", "Popen"):
        monkeypatch.setattr(subprocess, name, refuse(f"subprocess.{name}"))
    os_launchers = [n for n in dir(os) if n in ("system", "popen", "fork", "forkpty")
                    or n.startswith(("exec", "spawn", "posix_spawn"))]
    for name in os_launchers:
        monkeypatch.setattr(os, name, refuse(f"os.{name}"))
    yield forbidden
    assert forbidden == []


@pytest.fixture
def pkg(tmp_path):
    pkg_dir = tmp_path / "pkg"
    pkg_dir.mkdir()
    (pkg_dir / "evil.py").write_text("raise SystemExit('package code ran')\n")
    return pkg_dir


class _Lines:
    def __init__(self, text):
        self._lines = text.splitlines(keepends=True)

    def readline(self):
        return self._lines.pop(0) if self._lines else ""


class FakeProc:
    """Stands in for a `docker run` that printed `text`. finished=False never exits on its own."""

    def __init__(self, text, finished=True):
        self.stdout = _Lines(text)
        self.finished = finished
        self.killed = False

    def poll(self):
        return 0 if self.finished or self.killed else None

    def wait(self):
        return 0

    def kill(self):
        self.killed = True


def fake_popen(calls, text=None, error=None, procs=None, finished=True):
    def popen(cmd, **kwargs):
        calls.append(list(cmd))
        if error:
            raise error
        proc = FakeProc(text or "", finished)
        if procs is not None:
            procs.append(proc)
        return proc
    return popen


def run_container(monkeypatch, pkg_dir, text, calls=None):
    """Run SandboxRunner with Docker 'present' and a container that prints `text`."""
    monkeypatch.setattr(SandboxRunner, "_docker_available", lambda self: True)
    monkeypatch.setattr(subprocess, "Popen", fake_popen(calls if calls is not None else [], text=text))
    return SandboxRunner().run(pkg_dir, "run-x")


def assert_unresolved(result):
    assert result["observed"] is False
    assert result["report"]["verdict"] == "UNRESOLVED"
    assert result["report"]["metrics"] is None   # no fabricated "0 network attempts"
    assert result["report"]["events"][0]["type"] == "NOT_OBSERVED"


# --- SandboxRunner ---------------------------------------------------------

def test_no_docker_executes_nothing_and_is_unresolved(pkg, monkeypatch, no_real_processes):
    monkeypatch.setattr(SandboxRunner, "_docker_available", lambda self: False)

    result = SandboxRunner().run(pkg, "run-1")

    assert no_real_processes == []          # no process of any kind was started
    assert_unresolved(result)
    assert result["isolation"] == "none"
    assert "not executed" in result["report"]["error"]
    assert any("UNRESOLVED" in line for line in result["logs"])


def test_docker_launch_failure_does_not_fall_back_to_host(pkg, monkeypatch):
    calls = []
    monkeypatch.setattr(SandboxRunner, "_docker_available", lambda self: True)
    monkeypatch.setattr(subprocess, "Popen", fake_popen(calls, error=OSError("daemon not running")))

    result = SandboxRunner().run(pkg, "run-2")

    assert len(calls) == 1 and calls[0][0] == "docker"   # only the container attempt
    assert_unresolved(result)
    assert result["isolation"] == "container_failed"   # Docker is there, but no container ran


def test_container_output_without_report_is_unresolved(pkg, monkeypatch):
    calls = []
    result = run_container(monkeypatch, pkg, "Unable to find image 'asent-sandbox'\n", calls)

    assert len(calls) == 1 and calls[0][0] == "docker"
    assert_unresolved(result)
    assert result["isolation"] == "container_failed"   # the docker CLI ran, no container did


def test_docker_command_matches_the_image_entrypoint(pkg):
    # docker/asent-sandbox/Dockerfile: ENTRYPOINT ["python", "/opt/asent/harness.py"], CMD ["/pkg"].
    # Repeating the interpreter and script would hand "python" to the harness as the package path.
    cmd = SandboxRunner().get_docker_command(pkg, "run-cmd")

    assert cmd[-2:] == ["asent-sandbox", "/pkg"]
    assert "python" not in cmd and "/opt/asent/harness.py" not in cmd
    seccomp = [a for a in cmd if a.startswith("seccomp=")]
    assert len(seccomp) == 1
    profile = Path(seccomp[0].split("=", 1)[1])
    assert profile.is_absolute() and profile.is_file()
    assert profile == sandbox_runner.SECCOMP_PROFILE


def test_container_report_is_passed_through_unchanged(pkg, monkeypatch):
    report = clean_report(verdict="BLOCK", metrics={**CLEAN_METRICS, "network_attempts": 2,
                                                    "secrets_touched": 1, "honeytoken_accessed": True})
    calls = []
    result = run_container(monkeypatch, pkg, framed(report), calls)

    assert result["report"] == report
    assert result["observed"] is True and result["isolation"] == "container"
    assert "--network" in calls[0] and "none" in calls[0]


def test_timeout_kills_the_container_and_is_unresolved(pkg, monkeypatch):
    procs = []
    monkeypatch.setattr(SandboxRunner, "_docker_available", lambda self: True)
    monkeypatch.setattr(subprocess, "Popen", fake_popen([], text="still running\n", procs=procs, finished=False))
    runner = SandboxRunner()
    runner.timeout_seconds = -1             # already past the deadline on the first check

    result = runner.run(pkg, "run-timeout")

    assert procs[0].killed is True
    assert_unresolved(result)
    assert any("timeout of -1 seconds" in line for line in result["logs"])   # the real value, not "30"


def test_report_printed_before_the_deadline_then_hang_is_unresolved(pkg, monkeypatch):
    # The package prints one clean, well-framed report at import and then never exits.
    procs = []
    monkeypatch.setattr(SandboxRunner, "_docker_available", lambda self: True)
    monkeypatch.setattr(subprocess, "Popen", fake_popen([], text=framed(clean_report()), procs=procs, finished=False))

    def clock():
        # Stays at 0 until every output line has been read, then jumps past the deadline.
        return 1000.0 if procs and not procs[0].stdout._lines else 0.0
    monkeypatch.setattr(sandbox_runner, "time", types.SimpleNamespace(time=clock))

    result = SandboxRunner().run(pkg, "run-hang")

    assert any(END in line for line in result["logs"])   # the whole report was read before the kill
    assert procs[0].killed is True
    assert_unresolved(result)
    assert result["isolation"] == "container_failed"
    assert any("timeout of 30 seconds" in line for line in result["logs"])


@pytest.mark.parametrize("output", [
    f"{START}\n{{not json\n{END}\n",                      # malformed JSON
    f"{START}\n[1]\n{END}\n",                             # valid JSON, not an object
    f"{START}\n\"x\"\n{END}\n",
    f"{START}\n{json.dumps(clean_report())}\n",           # start marker without end
    f"{json.dumps(clean_report())}\n{END}\n",             # end marker without start
    f"{START}\n{{}}\n{END}\n",                            # empty object: nothing was reported
    f"{END}\n{json.dumps(clean_report())}\n{START}\n",    # END before START
    f"{END}\n{START}\n{json.dumps(clean_report())}\n",
])
def test_unusable_report_is_unresolved(pkg, monkeypatch, output):
    assert_unresolved(run_container(monkeypatch, pkg, output))


@pytest.mark.parametrize("forged_first", [True, False])
def test_forged_report_printed_by_the_package_is_not_trusted(pkg, monkeypatch, forged_first):
    # The package shares stdout with the harness. It prints a clean report of its own,
    # either at import (before the real one) or from an exit hook (after it).
    forged = f"{START}\n{json.dumps(clean_report())}\n{END}\n"
    real = f"{START}\n{json.dumps(clean_report(verdict='BLOCK', metrics={**CLEAN_METRICS, 'network_attempts': 1}))}\n{END}\n"

    result = run_container(monkeypatch, pkg, forged + real if forged_first else real + forged)

    assert_unresolved(result)
    assert any("More than one behavior report" in line for line in result["logs"])


def test_docker_probe_is_false_when_binary_is_missing(monkeypatch):
    def missing(*args, **kwargs):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(subprocess, "run", missing)
    assert SandboxRunner()._docker_available() is False


@pytest.mark.parametrize("returncode,expected", [(0, True), (1, False), (127, False)])
def test_docker_probe_follows_the_return_code(monkeypatch, returncode, expected):
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: types.SimpleNamespace(returncode=returncode))
    assert SandboxRunner()._docker_available() is expected


# --- build_causal_graph -----------------------------------------------------

def _run(*behaviors):
    return [{"run_number": 0, "behaviors_found": list(behaviors)}]


NOT_OBSERVED = {"action": "NOT_OBSERVED", "resource": "sandbox", "verdict_impact": "UNRESOLVED"}
CLEAN = {"action": "FILE_READ", "resource": "pure_import", "verdict_impact": "NEUTRAL"}
SECRET = {"action": "SECRET_ACCESS", "resource": "~/.aws/credentials", "verdict_impact": "VIOLATION"}


def test_unobserved_run_makes_the_verdict_unresolved():
    out = build_causal_graph("some-pkg", "1.0", {"contract_rows": []}, [], _run(NOT_OBSERVED))
    assert out["policy_state"] == "UNRESOLVED" and out["alias_verdict"] == "NEEDS_REVIEW"
    assert "violations" not in out["honesty_wording"]
    assert out["clean_message"] is None     # "No prohibited path found" would claim a clean result


def test_observed_violation_still_wins_over_unobserved_run():
    out = build_causal_graph("some-pkg", "1.0", {"contract_rows": []}, [], _run(NOT_OBSERVED, SECRET))
    assert out["policy_state"] == "REJECTED"
    assert out["clean_message"] is None


def test_observed_clean_run_is_verified():
    # VERIFIED comes from the one observed NEUTRAL behaviour, not from a default.
    out = build_causal_graph("some-pkg", "1.0", {"contract_rows": []}, [], _run(CLEAN))
    assert out["policy_state"] == "VERIFIED"
    assert out["clean_message"] == "No prohibited path found in explored conditions"


UNKNOWN = {"action": "FILE_READ", "resource": "pure_import", "verdict_impact": "PROBABLY_FINE"}
NO_IMPACT = {"action": "FILE_READ", "resource": "pure_import"}


@pytest.mark.parametrize("runs", [
    [],                                     # no runs at all
    _run(),                                 # a run with no behaviours
    [{"run_number": 0}],                    # a run without the behaviors_found key
    _run(UNKNOWN),                          # impact the builder does not know
    _run(NO_IMPACT),                        # impact missing
    _run(CLEAN, UNKNOWN),                   # a clean behaviour does not outweigh an unknown one
    _run(CLEAN, NO_IMPACT),
])
def test_without_observed_neutral_evidence_the_verdict_is_unresolved(runs):
    out = build_causal_graph("some-pkg", "1.0", {"contract_rows": []}, [], runs)
    assert out["policy_state"] == "UNRESOLVED" and out["alias_verdict"] == "NEEDS_REVIEW"
    assert out["clean_message"] is None


def test_required_contract_row_alone_does_not_verify():
    # The old code had a branch that set VERIFIED from the contract with no observed run.
    contract = {"contract_rows": [{"status": "REQUIRED"}]}
    assert build_causal_graph("some-pkg", "1.0", contract, [], [])["policy_state"] == "UNRESOLVED"


def test_violation_still_wins_over_unknown_impact():
    out = build_causal_graph("some-pkg", "1.0", {"contract_rows": []}, [], _run(UNKNOWN, SECRET))
    assert out["policy_state"] == "REJECTED"
