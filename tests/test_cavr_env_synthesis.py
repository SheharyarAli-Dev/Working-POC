"""PR 11 of docs/cavr-m2-plan.md: run specs with canaries (`env_synthesis`) and the spec run's host side (`sandbox_spec`).

Unit tests: frontier entries come from real wheels built in `tmp_path` (`trigger_frontier.frontier`); the sandbox run
is replaced (`sandbox_observe.IDENTITY` / `RUN`), so no container starts. Docker tests are in test_cavr_sandbox_spec.py.
"""
import base64
import datetime
import hashlib
import json
import os
import re
from pathlib import Path

import pytest

from backend.cavr import env_synthesis, sandbox_events, sandbox_exec, sandbox_observe, sandbox_spec, trigger_frontier
from tests.test_cavr_trigger_frontier import CONNECT, DENY_ALL, NOW, node

IMAGE_ID = "sha256:" + "ab" * 32


def entry_for(tmp_path, test, imports="os, socket"):
    found = trigger_frontier.frontier([node(tmp_path, f"import {imports}\nif {test}:\n" + CONNECT)], DENY_ALL, now=NOW)
    assert len(found["entries"]) == 1, found
    return found["entries"][0]


def built(tmp_path, test, imports="os, socket"):
    out = env_synthesis.synthesize(entry_for(tmp_path, test, imports))
    assert out["ok"], out["reason"]
    return out["spec"]


# --- canaries ---------------------------------------------------------------------------------------------------------

def test_every_spec_has_the_file_and_variable_canaries():
    spec = env_synthesis.canary_spec()
    assert set(trigger_frontier.CANARY_FILES) <= set(spec["files"])
    assert set(env_synthesis.CANARY_ENV) <= set(spec["env"])
    kinds = {item["id"]: item["kind"] for item in spec["canaries"]}
    assert {"file:aws-access-key", "file:aws-secret-key", "file:env-api-key", "file:netrc-password", "file:ssh-key",
            "env:AWS_ACCESS_KEY_ID", "env:AWS_SECRET_ACCESS_KEY", "env:GITHUB_TOKEN", "env:PYPI_TOKEN"} == set(kinds)
    for item in spec["canaries"]:
        where = spec["env"][item["where"]] if item["kind"] == "env" else spec["files"][item["where"]]["content"]
        assert item["value"] in where
    assert spec["entry_id"] is None and spec["faketime"] is None and spec["hostname"] == "cavr-sandbox"


def test_canaries_are_unique_in_a_run_and_new_in_every_run():
    first, second = env_synthesis.canary_spec(), env_synthesis.canary_spec()
    values = [item["value"] for item in first["canaries"]]
    assert len(values) == len(set(values))
    assert not set(values) & {item["value"] for item in second["canaries"]}
    assert all(len(re.sub(r"^(AKIA|ghp_|pypi-)", "", value)) >= 16 for value in values)


def test_the_canary_files_are_the_ones_the_frontier_counts_as_there():
    assert tuple(sorted(env_synthesis.canary_spec()["files"])) == tuple(sorted(trigger_frontier.CANARY_FILES))


def test_canary_forms_find_the_value_verbatim_in_hex_and_in_base64_at_every_offset():
    value = "AKIA0123456789ABCDEF"
    forms = env_synthesis.canary_forms(value)
    assert ("verbatim", value.encode()) in forms and ("hex", value.encode().hex().encode()) in forms
    for prefix in (b"", b"x", b"xy", b"key=", b"abcde"):
        encoded = base64.b64encode(prefix + value.encode() + b"tail")
        assert any(form in encoded for kind, form in forms if kind == "base64"), prefix


def test_a_short_base64_form_is_not_used():
    assert all(len(form) >= env_synthesis.MIN_FORM for kind, form in env_synthesis.canary_forms("abcd") if kind == "base64")


def test_the_hex_of_digits_is_one_form_and_base64_keeps_its_name():
    forms = env_synthesis.canary_forms("01234567890123456789")  # hex "30313233..." has no letters: upper == lower
    kinds = [kind for kind, _ in forms]
    assert kinds.count("hex") == 1 and kinds.count("base64") == 3 and len({f for _, f in forms}) == len(forms)


# --- one spec per family ----------------------------------------------------------------------------------------------

def test_env_spec(tmp_path):
    spec = built(tmp_path, "os.environ.get('CI') == 'true'")
    assert spec["env"]["CI"] == "true" and spec["entry_id"].startswith("") and spec["id"] == f"spec-{spec['entry_id']}"


def test_time_spec_uses_libfaketime(tmp_path):
    spec = built(tmp_path, "datetime.date.today() >= datetime.date(2027, 1, 1)", "datetime, socket")
    assert spec["faketime"] == "2027-01-02 12:00:00"
    env = env_synthesis.step_env(spec, machine="x86_64")
    assert env["LD_PRELOAD"] == "/usr/lib/x86_64-linux-gnu/faketime/libfaketime.so.1"
    assert env["FAKETIME"] == "@2027-01-02 12:00:00" and env["FAKETIME_DISABLE_SHM"] == "1"
    assert env["FAKETIME_DONT_FAKE_MONOTONIC"] == "1"


def test_without_a_clock_libfaketime_is_not_loaded():
    env = env_synthesis.step_env(env_synthesis.canary_spec(), machine="x86_64")
    assert "LD_PRELOAD" not in env and "FAKETIME" not in env


def test_an_unknown_machine_has_no_libfaketime(tmp_path):
    spec = built(tmp_path, "datetime.date.today() >= datetime.date(2027, 1, 1)", "datetime, socket")
    with pytest.raises(ValueError):
        env_synthesis.step_env(spec, machine="sparc")


def test_file_spec_creates_the_file_with_a_canary(tmp_path):
    spec = built(tmp_path, "os.path.exists(os.path.expanduser('~/.kube/config'))")
    item = spec["files"]["/tmp/home/.kube/config"]
    assert item["kind"] == "file" and item["canaries"] == ["file:trigger:.kube/config"]
    value = next(c["value"] for c in spec["canaries"] if c["id"] == "file:trigger:.kube/config")
    assert value in item["content"]


def test_directory_spec(tmp_path):
    spec = built(tmp_path, "pathlib.Path.home().joinpath('.docker').is_dir()", "os, pathlib, socket")
    assert spec["files"]["/tmp/home/.docker"] == {"kind": "dir", "canaries": [], "content": None}


def test_hostname_spec(tmp_path):
    assert built(tmp_path, "socket.gethostname() == 'build-prod-7'", "socket")["hostname"] == "build-prod-7"


def test_argv_spec(tmp_path):
    assert built(tmp_path, "'--deploy' in sys.argv", "sys, socket")["argv"] == ["-c", "--deploy"]


def test_a_trigger_that_sets_a_canary_variable_wins_and_that_canary_is_dropped(tmp_path):
    spec = built(tmp_path, "os.getenv('GITHUB_TOKEN') == 'ghp_fixed'")
    assert spec["env"]["GITHUB_TOKEN"] == "ghp_fixed"
    assert "env:GITHUB_TOKEN" not in {item["id"] for item in spec["canaries"]}


def test_an_unsimulable_entry_gives_no_spec(tmp_path):
    out = env_synthesis.synthesize(entry_for(tmp_path, "sys.platform == 'win32'", "sys, socket"))
    assert out["ok"] is False and out["spec"] is None and out["rule"] == "TRIGGER_UNSIMULABLE"
    assert "win32" in out["reason"]


@pytest.mark.parametrize("activation, why", [
    ({"env": {"HOME": "/root"}}, "fixed by the sandbox"),
    ({"env": {"LD_PRELOAD": "/x.so"}}, "fixed by the sandbox"),
    ({"env": {"PYTHONPATH": "/x"}}, "fixed by the sandbox"),
    ({"env": {"X": "a\0b"}}, "cannot be passed"),
    ({"files": {"/etc/passwd": "file"}}, "CAVR can create under /tmp/home"),
    ({"files": {"/tmp/home/../etc/x": "file"}}, "CAVR can create under /tmp/home"),
    ({"files": {"/tmp/home/.aws/credentials": "dir"}}, "canary file"),
    ({"files": {"/tmp/home/.aws": "file"}}, "directory of the canary files"),
    ({"files": {"/tmp/home/.netrc/x": "file"}}, "inside the canary file"),
    ({"hostname": "bad_host!"}, "not a valid hostname"),
    ({"time": "1960-01-01T00:00:00"}, "outside the clock"),
    ({"time": "soon"}, "not a time"),
    ({"argv": ["-c", "a\0"]}, "argv cannot be passed"),
    ({"env": {"X\n": "1"}}, "fixed by the sandbox"),
    ({"hostname": "build\n"}, "not a valid hostname"),
])
def test_a_spec_that_cannot_be_built_safely_is_refused(activation, why):
    entry = {"id": "e1", "simulable": True, "activation": {"env": {}, "files": {}, "time": None, "hostname": None,
                                                            "argv": None, **activation}}
    out = env_synthesis.synthesize(entry)
    assert out["ok"] is False and out["rule"] == "SPEC_REFUSED" and why in out["reason"], out["reason"]


def test_a_canary_path_or_parent_already_there_is_accepted():
    for files in ({"/tmp/home/.aws/credentials": "file"}, {"/tmp/home/.ssh": "dir"}):
        entry = {"id": "e1", "simulable": True, "activation": {"env": {}, "files": files, "time": None,
                                                                "hostname": None, "argv": None}}
        assert env_synthesis.synthesize(entry)["ok"]


# --- the spec run on the host (the container replaced) -------------------------------------------------------------

@pytest.fixture
def fake_run(monkeypatch):
    """The image check and the container run replaced; records the docker argv, the job file and the HOME given."""
    seen = {}
    monkeypatch.setattr(sandbox_observe, "IDENTITY", lambda: {"ok": True, "rule": "IMAGE_OK", "image": "x",
                                                             "image_id": IMAGE_ID,
                                                             "seccomp_sha256": sandbox_observe._sha256(sandbox_observe.sandbox_image.SECCOMP_PROFILE)})

    def run(cmd, name, deadline, stderr_cap):
        mounts = dict(re.findall(r"type=bind,src=([^,]+),dst=([^,]+),readonly", " ".join(cmd)))
        by_inside = {inside: host for host, inside in mounts.items()}
        home = Path(by_inside["/tmp/home"])
        seen.update(cmd=list(cmd), stderr_cap=stderr_cap, home=home, home_root=home.parent,
                    root_mode=os.stat(home.parent).st_mode & 0o777,
                    job=(Path(by_inside["/job"]) / "job.json").read_text(),
                    files={str(p.relative_to(home)): (p.read_text() if p.is_file() else None, os.stat(p).st_mode & 0o777)
                           for p in home.rglob("*")})
        if seen.get("raise"):
            raise RuntimeError("engine fault")
        return {"status": seen.get("status", "COMPLETED"), "reason": "fake", "name": name, "exit_code": 0,
                "elapsed_seconds": 0.1, "deadline_seconds": deadline, "stdout": b"", "stderr": b"",
                "stdout_text": "", "stderr_text": "", "over_cap": []}
    monkeypatch.setattr(sandbox_observe, "RUN", run)
    return seen


@pytest.fixture
def tree(tmp_path):
    entry = node(tmp_path, "VALUE = 1\n")
    quarantine = Path(entry["path"]).parent
    return [entry], quarantine


def test_the_spec_run_mounts_a_read_only_home_built_from_the_spec(fake_run, tree):
    nodes, quarantine = tree
    spec = env_synthesis.canary_spec()
    out = sandbox_spec.run_spec(nodes, ["demo"], spec, quarantine_dir=quarantine)
    assert "type=bind,src=%s,dst=/tmp/home,readonly" % fake_run["home"] in fake_run["cmd"]
    assert fake_run["root_mode"] == 0o700
    assert fake_run["files"][".aws/credentials"] == (spec["files"]["/tmp/home/.aws/credentials"]["content"], 0o644)
    assert fake_run["files"][".aws"] == (None, 0o755)
    assert out["evidence"]["home_removed"] is True and not fake_run["home_root"].exists()
    assert out["status"] == "UNRESOLVED" and out["stage"] == "deep-spec"


@pytest.mark.parametrize("how", ["status", "raise"])
def test_the_fake_home_is_removed_after_a_timeout_or_a_failure(fake_run, tree, how):
    nodes, quarantine = tree
    fake_run.update({"status": "TIMEOUT"} if how == "status" else {"raise": True})
    out = sandbox_spec.run_spec(nodes, ["demo"], env_synthesis.canary_spec(), quarantine_dir=quarantine)
    assert out["status"] == "UNRESOLVED" and out["rule"] in ("SANDBOX_TIMEOUT", "INTERNAL_ERROR")
    assert not fake_run["home_root"].exists() and out["evidence"]["home_removed"] is True


def test_the_fake_home_is_removed_when_writing_it_fails(monkeypatch, fake_run, tree):
    nodes, quarantine = tree
    made = []
    real = sandbox_spec.write_home
    monkeypatch.setattr(sandbox_spec, "write_home", lambda spec, root: made.append(root) or real(spec, root))
    spec = env_synthesis.canary_spec()
    spec["files"]["/tmp/home/../escape"] = {"kind": "file", "content": "x", "canaries": []}
    out = sandbox_spec.run_spec(nodes, ["demo"], spec, quarantine_dir=quarantine)
    assert out["rule"] == "INTERNAL_ERROR" and made and not Path(made[0]).exists()
    assert "cmd" not in fake_run  # nothing was started


def test_a_home_that_cannot_be_removed_is_unresolved(monkeypatch, fake_run, tree):
    nodes, quarantine = tree
    real = sandbox_spec._remove
    monkeypatch.setattr(sandbox_spec, "_remove", lambda root: False)
    out = sandbox_spec.run_spec(nodes, ["demo"], env_synthesis.canary_spec(), quarantine_dir=quarantine)
    assert out["rule"] == "SPEC_HOME_LEFT_BEHIND" and out["status"] == "UNRESOLVED"
    assert real(fake_run["home_root"]) and not fake_run["home_root"].exists()  # the test cleans up what it kept


def test_the_steps_give_canaries_only_to_the_imports_step(fake_run, tree):
    nodes, quarantine = tree
    spec = env_synthesis.canary_spec()
    sandbox_spec.run_spec(nodes, ["demo"], spec, quarantine_dir=quarantine)
    install, imports = json.loads(fake_run["job"])["steps"]
    assert install["name"] == "install" and install["env"] == {"HOME": "/tmp/install-home"}
    assert install["argv"] == sandbox_observe.PIP_INSTALL
    assert imports["env"] == spec["env"] and imports["argv"][:-1] == sandbox_spec.SPEC_IMPORT_ARGV
    assert json.loads(imports["argv"][-1]) == {"modules": ["demo"], "argv": ["-c"]}


def test_the_spec_run_uses_its_own_strace_and_trace_cap_and_the_hostname(fake_run, tree, tmp_path):
    nodes, quarantine = tree
    spec = built(tmp_path / "e", "socket.gethostname() == 'build-prod-7'", "socket")
    sandbox_spec.run_spec(nodes, ["demo"], spec, quarantine_dir=quarantine)
    cmd = fake_run["cmd"]
    assert cmd[cmd.index("--hostname") + 1] == "build-prod-7" and cmd.count("--hostname") == 1
    assert fake_run["stderr_cap"] == sandbox_spec.SPEC_STDERR_CAP
    strace = cmd[cmd.index(IMAGE_ID) + 1:]
    assert strace == sandbox_spec.STRACE_SPEC and strace[strace.index("-s") + 1] == "65536"
    assert {"write", "writev", "pwrite64"} <= set(strace[strace.index("-e") + 1].removeprefix("trace=").split(","))


TRACES = Path(__file__).parent / "test_cavr_data" / "traces"
PR9_FLAGS = ["--network", "none", "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
             "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE", "--cap-add", "SETUID", "--cap-add", "SETGID", "--cap-add",
             "DAC_READ_SEARCH", "--security-opt", "no-new-privileges", "--security-opt",
             f"seccomp={sandbox_exec.SECCOMP_PROFILE}", "--pids-limit", "64", "--memory", "256m", "--memory-swap",
             "256m", "--cpus", "1", "--ulimit", "nofile=256:256", "--ulimit", "fsize=67108864:67108864", "--ulimit",
             "core=0:0", "--log-driver", "none", "--hostname", "cavr-sandbox"]


def test_the_pr9_strace_and_flags_are_unchanged():
    # Review of PRs 10-11 (MINOR 9): the whole command, as recorded by the PR 7 recordings, and every flag.
    recorded = json.loads((TRACES / "events-probe.json").read_text())["strace"]
    assert sandbox_observe.STRACE == recorded
    assert sandbox_exec.lockdown_flags() == PR9_FLAGS
    assert sandbox_spec.STRACE_SPEC != sandbox_observe.STRACE


def test_the_frontiers_canary_variables_have_the_shapes_the_spec_gives_them():
    env = env_synthesis.canary_spec()["env"]
    assert tuple(trigger_frontier.CANARY_ENV_SHAPES) == env_synthesis.CANARY_ENV
    for name, shape in trigger_frontier.CANARY_ENV_SHAPES.items():
        prefix = re.match(r"^[A-Za-z_-]*", shape).group(0)
        assert env[name].startswith(prefix) and len(env[name]) == len(shape), name


def test_a_spec_path_that_is_not_normal_is_refused_before_anything_is_written(fake_run, tree):
    nodes, quarantine = tree
    spec = env_synthesis.canary_spec()
    spec["files"]["/tmp/home//etc/x"] = {"kind": "file", "content": "x", "canaries": []}
    out = sandbox_spec.run_spec(nodes, ["demo"], spec, quarantine_dir=quarantine)
    assert out["rule"] == "INTERNAL_ERROR" and "not under /tmp/home" in out["reason"] and "cmd" not in fake_run


def test_no_host_environment_value_reaches_a_run(monkeypatch, fake_run, tree):
    nodes, quarantine = tree
    monkeypatch.setenv("CAVR_TEST_HOST_SECRET", "host-secret-5f1e2d")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "host-aws-secret-77aa")
    monkeypatch.setenv("GITHUB_TOKEN", "host-gh-token-31cc")
    sandbox_spec.run_spec(nodes, ["demo"], env_synthesis.canary_spec(), quarantine_dir=quarantine)
    everything = " ".join(fake_run["cmd"]) + fake_run["job"] + json.dumps(fake_run["files"])
    for value in ("host-secret-5f1e2d", "host-aws-secret-77aa", "host-gh-token-31cc"):
        assert value not in everything
    env_flags = [fake_run["cmd"][i + 1] for i, a in enumerate(fake_run["cmd"]) if a == "--env"]
    assert [flag.split("=")[0] for flag in env_flags] == [sandbox_observe.NONCE_VARIABLE]


@pytest.mark.parametrize("hostname", ["bad_host!", "-x", "a" * 64, "x\n"])
def test_docker_refuses_an_invalid_hostname(hostname):
    with pytest.raises(ValueError):
        sandbox_exec.docker_command("cavr-0123456789ab-1", IMAGE_ID, ["true"], hostname=hostname)


def test_a_wheel_whose_quarantine_bytes_changed_is_refused_before_anything_is_written(fake_run, tree):
    nodes, quarantine = tree
    nodes[0]["sha256"] = "0" * 64
    out = sandbox_spec.run_spec(nodes, ["demo"], env_synthesis.canary_spec(), quarantine_dir=quarantine)
    assert out["rule"] == "WHEEL_HASH_MISMATCH" and "cmd" not in fake_run and out["evidence"]["home_removed"]
