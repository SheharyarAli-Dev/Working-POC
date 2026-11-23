"""PR 5 of docs/cavr-m2-plan.md: behaviour evidence from a trace the package cannot write.

Unit tests read a real trace recorded from `sandbox_observe.run_harness` in asent-cavr-sandbox
(tests/test_cavr_data/traces/harness-two-steps.txt, its command, image ID and date beside it in the .json) and
change it the way a truncation, a forgery or a lost line would. Docker tests (`requires_docker`, CAVR_DOCKER=1) run
packages that try to reach, forge, fill or cut the trace.
"""
import ast
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from backend.cavr import sandbox_exec, sandbox_harness, sandbox_observe
from backend.cavr.sandbox_trace import check_trace, expected_markers
from tests.test_cavr_support import cavr_containers, requires_docker

TRACES = Path(__file__).resolve().parent / "test_cavr_data" / "traces"
RECORDED = (TRACES / "harness-two-steps.txt").read_text()
META = json.loads((TRACES / "harness-two-steps.json").read_text())
NONCE, STEPS = META["nonce"], META["steps"]
OTHER = "f" * 32


def lines():
    return RECORDED.splitlines(keepends=True)


def check(text, nonce=NONCE, steps=STEPS):
    return check_trace(text, nonce, steps)


# --- the recorded trace ---------------------------------------------------------------------------------------------------

def test_recorded_trace_is_what_its_metadata_says():
    import hashlib
    assert hashlib.sha256(RECORDED.encode()).hexdigest() == META["trace_sha256"]
    assert META["image_id"].startswith("sha256:") and META["recorded"] == "2026-11-23"


def test_recorded_trace_is_complete_and_maps_each_process_to_its_step():
    got = check(RECORDED)
    assert got["complete"] is True and got["rule"] == "TRACE_COMPLETE"
    assert got["root_pid"] == 9 and got["steps"] == {"probe": [10], "second": [12]}
    assert got["processes"][9]["role"] == "harness"
    assert got["processes"][11] == {"parent": 10, "step": "probe", "role": "step"}  # the probe's /bin/sh
    assert got["processes"][12]["step"] == "second"


def test_expected_markers_are_in_order():
    assert expected_markers(["a", "b"]) == ["start", "step:a:begin", "step:a:end:0", "step:b:begin", "step:b:end:0", "end:ok"]


# --- incomplete: truncated, tampered, forged ------------------------------------------------------------------------------

def test_empty_trace_is_incomplete():
    assert check("")["rule"] == "TRACE_EMPTY" and check("\n\n")["rule"] == "TRACE_EMPTY"


def test_trace_cut_in_the_middle_of_a_line_is_incomplete():
    assert check(RECORDED[:-10])["rule"] == "TRACE_TRUNCATED"


def test_trace_without_its_last_lines_is_incomplete():
    got = check("".join(lines()[:-3]))
    assert got["complete"] is False and got["rule"] == "TRACE_TRUNCATED"


def test_trace_without_the_harness_exit_line_is_incomplete():
    assert check("".join(lines()[:-1]))["rule"] == "TRACE_TRUNCATED"


def test_trace_cut_at_half_is_incomplete():
    assert check("".join(lines()[: len(lines()) // 2]))["complete"] is False


def test_harness_exit_code_other_than_zero_is_incomplete():
    text = RECORDED.replace("9     +++ exited with 0 +++\n", "9     +++ exited with 4 +++\n")
    assert check(text)["rule"] == "TRACE_TRUNCATED"


def test_line_after_the_harness_exited_is_incomplete():
    assert check(RECORDED + "9     getpid() = 9\n")["rule"] == "TRACE_TRUNCATED"


def test_child_without_an_exit_line_is_incomplete():
    text = "".join(line for line in lines() if line != "12    +++ exited with 0 +++\n")
    assert check(text)["rule"] == "TRACE_TRUNCATED"


def test_a_child_strace_never_followed_is_incomplete():
    """clone(CLONE_UNTRACED) returns a PID that strace never attaches to: its activity would be invisible."""
    body = lines()
    at = next(i for i, line in enumerate(body) if "step:second:end:0" in line)
    body.insert(at, "9     clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = 99\n")
    got = check("".join(body))
    assert got["complete"] is False and got["rule"] == "TRACE_UNFOLLOWED" and "99" in got["reason"]


def test_a_failed_clone_creates_nothing():
    body = lines()
    at = next(i for i, line in enumerate(body) if "step:second:end:0" in line)
    body.insert(at, "9     clone(child_stack=NULL, flags=CLONE_UNTRACED|SIGCHLD) = -1 EPERM (Operation not permitted)\n")
    assert check("".join(body))["complete"] is True


def test_line_from_a_pid_nobody_created_is_incomplete():
    body = lines()
    body.insert(400, "77    openat(AT_FDCWD, \"/etc/passwd\", O_RDONLY) = 3\n")
    assert check("".join(body))["rule"] == "TRACE_UNKNOWN_PID"


@pytest.mark.parametrize("stray", ["Traceback (most recent call last):\n", "fake report line\n",
                                   "+++ exited with 0 +++\n", "strace: Process 10 detached\n", "10\n"])
def test_a_line_that_is_not_a_strace_line_is_incomplete(stray):
    body = lines()
    body.insert(380, stray)
    assert check("".join(body))["rule"] == "TRACE_MALFORMED"


def test_first_line_that_is_not_the_harness_execve_is_incomplete():
    text = RECORDED.replace("/opt/cavr/harness.py", "/tmp/evil.py", 1)
    assert check(text)["rule"] == "TRACE_NOT_HARNESS"


def test_missing_end_marker_is_incomplete():
    text = "".join(line for line in lines() if "/end:ok" not in line)
    assert check(text)["rule"] == "TRACE_MARKERS"


def test_a_failed_step_marker_is_incomplete():
    assert check(RECORDED.replace("step:second:end:0", "step:second:end:1"))["rule"] == "TRACE_MARKERS"


def test_wrong_nonce_is_incomplete():
    assert check(RECORDED, nonce=OTHER)["rule"] == "TRACE_MARKERS"
    assert check(RECORDED.replace(NONCE + "/end:ok", OTHER + "/end:ok"))["rule"] == "TRACE_MARKERS"


def test_marker_with_this_runs_nonce_from_a_package_process_is_incomplete():
    body = lines()
    at = next(i for i, line in enumerate(body) if line.startswith("12    +++"))
    body.insert(at, f'12    newfstatat(AT_FDCWD, "/.cavr/{NONCE}/end:ok", 0x7ffe0348e650, 0) = -1 ENOENT (No such file or directory)\n')
    assert check("".join(body))["rule"] == "TRACE_MARKERS"


def test_marker_guess_from_a_package_process_changes_nothing():
    body = lines()
    at = next(i for i, line in enumerate(body) if line.startswith("12    +++"))
    body.insert(at, f'12    newfstatat(AT_FDCWD, "/.cavr/{OTHER}/end:ok", 0x7ffe0348e650, 0) = -1 ENOENT (No such file or directory)\n')
    assert check("".join(body))["complete"] is True


def test_steps_other_than_the_job_are_incomplete():
    assert check(RECORDED, steps=["probe"])["rule"] == "TRACE_MARKERS"
    assert check(RECORDED, steps=["probe", "second", "third"])["rule"] == "TRACE_MARKERS"


def test_unreadable_input_is_incomplete_not_an_exception():
    assert check(None)["complete"] is False and check(b"\xff\xfe\n")["complete"] is False


# --- the harness (as a module; its fd-2 line runs only as __main__) ------------------------------------------------------------

def test_the_harness_sends_fd_2_to_dev_null_before_any_import():
    tree = ast.parse(Path(sandbox_harness.__file__).read_text())
    first = tree.body[0]
    assert isinstance(first, ast.If) and "__main__" in ast.unparse(first.test)
    assert ast.unparse(first.body[0]) == "__import__('posix').dup2(__import__('posix').open('/dev/null', 1), 2)"
    imports = [i for i, node in enumerate(tree.body) if isinstance(node, (ast.Import, ast.ImportFrom))]
    assert imports and min(imports) > 0
    assert "os.close(0)" in ast.unparse(next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"))


def test_strace_starts_the_harness_with_isolated_python_and_no_site():
    assert sandbox_observe.STRACE[-5:] == ["/usr/local/bin/python", "-I", "-S", "/opt/cavr/harness.py", "/job/job.json"]
    assert sandbox_observe.STRACE[:4] == ["strace", "-f", "-q", "--always-show-pid"]
    assert sandbox_observe.STRACE[sandbox_observe.STRACE.index("-u") + 1] == "cavr"


def test_the_nonce_is_in_no_child_argv_or_environment(tmp_path, monkeypatch):
    nonce = "a" * 32
    monkeypatch.setenv("CAVR_RUN_NONCE", nonce)
    monkeypatch.setenv("HOST_SECRET", "real-credential")
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"steps": [{"name": "install", "argv": ["python", "-c", "1"], "env": {"X": "1"}},
                                         {"name": "imports", "argv": ["python", "-c", "2"]}]}))
    steps = sandbox_harness.read_job(job, nonce)
    for _, argv, env in steps:
        assert not any(nonce in a for a in argv)
        assert not any(nonce in k or nonce in v for k, v in env.items())
        assert "HOST_SECRET" not in env and "CAVR_RUN_NONCE" not in env
        assert set(env) <= set(sandbox_harness.CHILD_ENV) | {"X"}


@pytest.mark.parametrize("step", [{"name": "s", "argv": ["python", "-c", "print('" + "b" * 32 + "')"]},
                                  {"name": "s", "argv": ["python"], "env": {"K": "x" + "b" * 32}},
                                  {"name": "s", "argv": ["python"], "env": {"b" * 32: "1"}}])
def test_a_step_that_would_carry_the_nonce_is_refused(tmp_path, step):
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"steps": [step]}))
    with pytest.raises(ValueError, match="nonce"):
        sandbox_harness.read_job(job, "b" * 32)
    with pytest.raises(ValueError, match="nonce"):
        sandbox_observe.job_file([step], "b" * 32)


@pytest.mark.parametrize("job", [{}, {"steps": []}, {"steps": [{"name": "a b", "argv": ["x"]}]},
                                 {"steps": [{"name": "a", "argv": []}]}, {"steps": [{"name": "a", "argv": ["x"], "env": {"K": 1}}]}])
def test_a_malformed_job_is_refused(tmp_path, job):
    path = tmp_path / "job.json"
    path.write_text(json.dumps(job))
    with pytest.raises((ValueError, AttributeError)):
        sandbox_harness.read_job(path, "c" * 32)


def test_leftover_processes_are_killed_until_none_is_left():
    sent = []

    def kill(pid, sig):
        sent.append((pid, sig))
        if len(sent) == 3:
            raise ProcessLookupError
    assert sandbox_harness.kill_leftovers(kill) == 3 and sent == [(-1, 9)] * 3


def test_kill_minus_one_is_never_sent_outside_the_sandbox():
    assert sandbox_harness.in_sandbox() is False  # this host is not UID 10001 running /opt/cavr/harness.py


def _run_harness_here(tmp_path, steps, nonce="d" * 32):
    """The harness file run on this host (not the sandbox: no kill(-1)), with its own job."""
    job = tmp_path / "job.json"
    job.write_text(json.dumps({"steps": steps}))
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "CAVR_RUN_NONCE": nonce}
    return subprocess.run([sys.executable, "-I", "-S", sandbox_harness.__file__, str(job)], env=env,
                          capture_output=True, timeout=60)


def test_harness_writes_nothing_to_its_stderr_even_when_a_step_does(tmp_path):
    done = _run_harness_here(tmp_path, [{"name": "talk", "argv": [sys.executable, "-c",
                                         "import sys; sys.stderr.write('err-line'); print('out-line')"]}])
    assert done.returncode == 0 and done.stderr == b""
    assert b"err-line" in done.stdout and b"out-line" in done.stdout


@pytest.mark.parametrize("steps, nonce, code", [
    ([{"name": "a", "argv": [sys.executable, "-c", "raise SystemExit(2)"]}], "d" * 32, 4),
    ([{"name": "a", "argv": ["/nonexistent/binary"]}], "d" * 32, 4),
    ([{"name": "a", "argv": [sys.executable, "-c", "1"]}], "not-a-nonce", 3),
    ([], "d" * 32, 3),
])
def test_harness_exit_codes(tmp_path, steps, nonce, code):
    done = _run_harness_here(tmp_path, steps, nonce)
    assert done.returncode == code and done.stderr == b""


# --- run_harness without Docker (fake identity and run) --------------------------------------------------------------------

IMAGE_OK = {"ok": True, "rule": "IMAGE_OK", "reason": "ok", "image": "asent-cavr-sandbox:local",
            "image_id": "sha256:" + "ab" * 32,
            "seccomp_sha256": sandbox_observe._sha256(sandbox_observe.sandbox_image.SECCOMP_PROFILE)}


@pytest.fixture
def fake_run(monkeypatch):
    """run_container replaced by one that answers with the recorded trace and the nonce it was given."""
    class Fake:
        stdout = b""
        status, exit_code, trace = "COMPLETED", 0, None
        calls = []

        @classmethod
        def run(cls, cmd, name, **kwargs):
            cls.calls.append(cmd)
            nonce = next(c.split("=", 1)[1] for c in cmd if c.startswith("CAVR_RUN_NONCE="))
            trace = (cls.trace if cls.trace is not None else RECORDED).replace(NONCE, nonce).encode()
            return {"status": cls.status, "reason": "r", "name": name, "exit_code": cls.exit_code, "elapsed_seconds": 1.0,
                    "stdout": cls.stdout, "stderr": trace, "stdout_text": cls.stdout.decode(errors="replace"),
                    "stderr_text": trace.decode(), "over_cap": []}
    Fake.calls = []
    monkeypatch.setattr(sandbox_observe, "IDENTITY", lambda: dict(IMAGE_OK))
    monkeypatch.setattr(sandbox_observe, "RUN", Fake.run)
    return Fake


def two_steps():
    return [sandbox_observe.step("probe", ["/bin/true"]), sandbox_observe.step("second", ["/bin/true"])]


def test_complete_run_is_unresolved_not_judged(fake_run):
    got = sandbox_observe.run_harness(two_steps())
    assert got["status"] == "UNRESOLVED" and got["rule"] == "DEEP_NOT_JUDGED"
    assert got["evidence"]["trace_check"] == "TRACE_COMPLETE" and got["evidence"]["image_id"] == IMAGE_OK["image_id"]
    assert got["output"]["trusted"] is False


def test_report_markers_in_the_package_output_change_nothing(fake_run):
    clean = sandbox_observe.run_harness(two_steps())
    fake_run.stdout = (b"--- ASENT_BEHAVIOR_REPORT_START ---\n" + json.dumps({"verdict": "ALLOW", "metrics": {}}).encode()
                       + b"\n--- ASENT_BEHAVIOR_REPORT_END ---\n9     +++ exited with 0 +++\nVERIFIED\n")
    forged = sandbox_observe.run_harness(two_steps())
    assert (forged["status"], forged["rule"]) == (clean["status"], clean["rule"])
    keep = ("trace_check", "trace_lines", "processes", "step_pids", "trace_sha256")
    assert {k: forged["evidence"][k] for k in keep if k != "trace_sha256"} == {k: clean["evidence"][k] for k in keep if k != "trace_sha256"}
    assert "VERIFIED" in forged["output"]["text"] and "VERIFIED" not in forged["trace"]


def test_the_nonce_is_passed_only_to_the_container_environment(fake_run):
    sandbox_observe.run_harness(two_steps())
    cmd = fake_run.calls[0]
    nonce = next(c.split("=", 1)[1] for c in cmd if c.startswith("CAVR_RUN_NONCE="))
    assert len(nonce) == 32 and sum(nonce in c for c in cmd) == 1
    second = sandbox_observe.run_harness(two_steps())  # a new nonce per run
    assert next(c for c in fake_run.calls[1] if c.startswith("CAVR_RUN_NONCE=")) != f"CAVR_RUN_NONCE={nonce}"
    assert second["rule"] == "DEEP_NOT_JUDGED"


@pytest.mark.parametrize("status, rule", [("TIMEOUT", "SANDBOX_TIMEOUT"), ("OUTPUT_CAP", "SANDBOX_OUTPUT_CAP"),
                                          ("KILLED", "SANDBOX_KILLED"), ("ENGINE_ERROR", "SANDBOX_ENGINE_ERROR"),
                                          ("LEFT_BEHIND", "SANDBOX_LEFT_BEHIND")])
def test_a_run_that_did_not_complete_is_unresolved(fake_run, status, rule):
    fake_run.status = status
    got = sandbox_observe.run_harness(two_steps())
    assert got["status"] == "UNRESOLVED" and got["rule"] == rule


def test_harness_exit_other_than_zero_is_unresolved(fake_run):
    fake_run.exit_code = 4
    assert sandbox_observe.run_harness(two_steps())["rule"] == "SANDBOX_EXIT_NONZERO"


def test_incomplete_trace_is_unresolved(fake_run):
    fake_run.trace = "".join(lines()[:-2])
    got = sandbox_observe.run_harness(two_steps())
    assert got["rule"] == "TRACE_INCOMPLETE" and got["evidence"]["trace_check"] == "TRACE_TRUNCATED"


def test_image_problem_runs_nothing(fake_run, monkeypatch):
    monkeypatch.setattr(sandbox_observe, "IDENTITY", lambda: {"ok": False, "rule": "IMAGE_ID_MISMATCH", "reason": "x"})
    got = sandbox_observe.run_harness(two_steps())
    assert got["status"] == "UNRESOLVED" and got["rule"] == "IMAGE_ID_MISMATCH" and fake_run.calls == []


def test_a_seccomp_profile_changed_after_the_image_check_runs_nothing(fake_run, monkeypatch):
    monkeypatch.setattr(sandbox_observe, "IDENTITY", lambda: {**IMAGE_OK, "seccomp_sha256": "0" * 64})
    got = sandbox_observe.run_harness(two_steps())
    assert got["status"] == "UNRESOLVED" and got["rule"] == "SECCOMP_CHANGED" and fake_run.calls == []


def test_a_fault_is_unresolved_internal_error(fake_run, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(sandbox_observe, "RUN", boom)
    got = sandbox_observe.run_harness(two_steps())
    assert got["status"] == "UNRESOLVED" and got["rule"] == "INTERNAL_ERROR"


def test_a_bad_step_is_unresolved(fake_run):
    got = sandbox_observe.run_harness([{"name": "a b", "argv": ["x"]}])
    assert got["rule"] == "JOB_INVALID" and fake_run.calls == []


# --- Docker ---------------------------------------------------------------------------------------------------------------

def probe(tmp_path, code):
    """A package stand-in: `code` in /pkg/probe.py, run as one step."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / "probe.py").write_text(code)
    os.chmod(pkg, 0o755)
    os.chmod(pkg / "probe.py", 0o644)
    return [sandbox_observe.step("probe", ["/usr/local/bin/python", "-I", "-S", "/pkg/probe.py"])], [(pkg, "/pkg")]


def observed(tmp_path, code, **kwargs):
    steps, mounts = probe(tmp_path, code)
    got = sandbox_observe.run_harness(steps, mounts=mounts, **kwargs)
    assert cavr_containers() == []
    return got


@requires_docker
def test_benign_step_gives_a_complete_trace(tmp_path):
    got = observed(tmp_path, "print('hello')\n")
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert got["evidence"]["image_check"] == "IMAGE_OK" and got["evidence"]["trace_check"] == "TRACE_COMPLETE"
    assert "hello" in got["output"]["text"]


ROOT_PROBE = """import multiprocessing, os, subprocess, time
try:
    os.setuid(0)
except OSError as exc:
    print("setuid", exc.errno)
def nap():
    time.sleep(4)
children = [multiprocessing.get_context("fork").Process(target=nap) for _ in range(2)]
for child in children:
    child.start()
shell = subprocess.Popen(["/bin/sh", "-c", "sleep 4"])
time.sleep(4)
for child in children:
    child.join()
shell.wait()
"""


@requires_docker
def test_package_code_never_runs_as_root(tmp_path):
    """While the run is going, `docker top` (the host's view) lists every process with its UID: only strace is root."""
    steps, mounts = probe(tmp_path, ROOT_PROBE)
    run_id = sandbox_exec.new_run_id()
    name = sandbox_exec.container_name(run_id, 1)
    out = {}
    worker = threading.Thread(target=lambda: out.update(sandbox_observe.run_harness(steps, mounts=mounts, run_id=run_id)))
    worker.start()
    seen = []
    for _ in range(80):
        done = subprocess.run(["docker", "top", name, "-eo", "uid,pid,comm"], capture_output=True, text=True, timeout=30)
        if done.returncode == 0:
            rows = [line.split(None, 2) for line in done.stdout.splitlines()[1:]]
            if len(rows) >= 6:  # strace, harness, probe, two forks, sh (and sleep)
                seen = rows
                break
        time.sleep(0.1)
    worker.join(60)
    assert cavr_containers() == []
    assert seen, "the container's processes were never listed"
    root = [comm for uid, _, comm in seen if uid in ("0", "root")]
    assert root == ["strace"]
    assert all(uid == "10001" for uid, _, comm in seen if comm != "strace") and len(seen) >= 6
    assert out["rule"] == "DEEP_NOT_JUDGED", out["reason"]
    assert "setuid 1" in out["output"]["text"]
    trace = out["trace"]
    assert "setuid(0) = -1 EPERM" in " ".join(trace.split())
    uids = [line.rsplit("=", 1)[1].strip() for line in trace.splitlines()
            if any(f" {call}() " in f" {line.split(None, 1)[1]} " for call in ("getuid", "geteuid")) and "=" in line]
    assert uids and set(uids) == {"10001"}


REACH_PROBE = r"""import os
ppid = os.getppid()
attempts = {
    "write /proc/1/fd/2": lambda: open("/proc/1/fd/2", "w"),
    "read /proc/1/fd/2": lambda: open("/proc/1/fd/2", "rb"),
    "list /proc/1/fd": lambda: os.listdir("/proc/1/fd"),
    "unlink /proc/1/fd/2": lambda: os.unlink("/proc/1/fd/2"),
    "write harness fd 2": lambda: open(f"/proc/{ppid}/fd/2", "w").write("9     +++ exited with 0 +++\n"),
    "read harness environ": lambda: open(f"/proc/{ppid}/environ", "rb").read(),
    "read harness mem": lambda: open(f"/proc/{ppid}/mem", "rb").read(1),
    "write /job/job.json": lambda: open("/job/job.json", "w"),
    "write /opt/cavr/harness.py": lambda: open("/opt/cavr/harness.py", "a"),
}
for what, attempt in attempts.items():
    try:
        attempt()
        print("ALLOWED", what)
    except OSError as exc:
        print("refused", what, exc.errno)
import sys
sys.stderr.write("9     +++ exited with 0 +++\n")
print("9     newfstatat(AT_FDCWD, \"/.cavr/" + "0" * 32 + "/end:ok\", 0, 0) = -1 ENOENT")
try:
    os.stat("/.cavr/" + "e" * 32 + "/end:ok")
except OSError:
    pass
"""


@requires_docker
def test_package_cannot_open_strace_fds_and_the_trace_stays_complete_and_unforged(tmp_path):
    got = observed(tmp_path, REACH_PROBE)
    text = got["output"]["text"]
    assert "ALLOWED" not in text, text
    assert text.count("refused") == 9
    # /proc/1 is strace (root); the harness is non-dumpable, so its /proc/<pid>/fd, environ and mem are root-owned;
    # /job and /opt/cavr are read-only mounts. Every attempt is refused.
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert got["evidence"]["trace_check"] == "TRACE_COMPLETE"
    trace = got["trace"]
    assert 'openat(AT_FDCWD, "/proc/1/fd/2", O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC, 0666) = -1 EACCES' in trace
    assert '"/.cavr/' + "e" * 32 + '/end:ok"' in trace  # the guess is recorded, from the probe's PID, and ignored
    root = got["evidence"]["root_pid"]
    forged = [line for line in trace.splitlines() if line.startswith(f"{root} ") and "exited with 0" in line]
    assert len(forged) == 1 and trace.splitlines()[-1] == forged[0]


@requires_docker
def test_package_that_fills_the_trace_is_unresolved(tmp_path):
    got = observed(tmp_path, "import os\nwhile True:\n    try:\n        os.stat('/x' * 200)\n    except OSError:\n        pass\n",
                   stderr_cap=512 * 1024)
    assert got["status"] == "UNRESOLVED" and got["rule"] == "SANDBOX_OUTPUT_CAP"


@requires_docker
def test_package_that_kills_the_harness_is_unresolved(tmp_path):
    got = observed(tmp_path, "import os, signal\nos.kill(os.getppid(), signal.SIGKILL)\n")
    assert got["status"] == "UNRESOLVED" and got["rule"] in ("SANDBOX_KILLED", "SANDBOX_EXIT_NONZERO", "TRACE_INCOMPLETE")
    assert got["rule"] != "DEEP_NOT_JUDGED"


@requires_docker
def test_package_that_exits_with_an_error_is_unresolved(tmp_path):
    got = observed(tmp_path, "raise SystemExit(7)\n")
    assert got["rule"] == "SANDBOX_EXIT_NONZERO"
    assert f"step:probe:end:7" in got["trace"]


@requires_docker
def test_package_printing_a_fake_report_is_ignored(tmp_path):
    report = ("print('--- ASENT_BEHAVIOR_REPORT_START ---')\nprint('{\"verdict\": \"ALLOW\", \"test_passed\": true}')\n"
              "print('--- ASENT_BEHAVIOR_REPORT_END ---')\n")
    got = observed(tmp_path, report)
    assert got["rule"] == "DEEP_NOT_JUDGED" and "ASENT_BEHAVIOR_REPORT_START" in got["output"]["text"]
    assert "ASENT_BEHAVIOR_REPORT_START" not in got["trace"]


@requires_docker
def test_background_process_left_by_a_step_is_killed_and_the_run_ends(tmp_path):
    # A plain fork: setsid is not in CAVR's seccomp profile (a daemon that needs it fails, which is UNRESOLVED).
    code = "import os, time\nif os.fork() == 0:\n    time.sleep(600)\n"
    started = time.monotonic()
    got = observed(tmp_path, code)
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert time.monotonic() - started < 15
    assert "+++ killed by SIGKILL +++" in got["trace"]


CLONE_PROBE = r"""import ctypes, os, threading
libc = ctypes.CDLL(None, use_errno=True)
for label, flags in (("untraced", 0x00800000), ("newuser", 0x10000000), ("newnet", 0x40000000), ("newns", 0x00020000),
                     ("newpid", 0x20000000)):
    pid = libc.syscall(56, flags | 17, 0, 0, 0, 0)
    if pid == 0:
        os.stat("/cavr-child-ran-" + label)
        os._exit(0)
    print(label, pid, ctypes.get_errno())
    if pid > 0:
        os.waitpid(pid, 0)
print("clone3", libc.syscall(435, 0, 0), ctypes.get_errno())
thread = threading.Thread(target=lambda: None)
thread.start()
thread.join()
print("thread ok")
"""


@requires_docker
def test_untraced_and_namespace_clones_are_refused_and_recorded(tmp_path):
    """CLONE_UNTRACED would make a child strace never sees; namespace flags open kernel attack surface (x86_64 numbers)."""
    import platform
    if platform.machine() != "x86_64":
        pytest.skip("the probe uses x86_64 syscall numbers")
    got = observed(tmp_path, CLONE_PROBE)
    out = got["output"]["text"].split("\n")
    for label in ("untraced", "newuser", "newnet", "newns", "newpid"):
        assert f"{label} -1 1" in out, out  # EPERM
    assert "clone3 -1 38" in out and "thread ok" in out  # ENOSYS; glibc falls back to clone for threads
    assert got["rule"] == "DEEP_NOT_JUDGED", got["reason"]
    assert "cavr-child-ran" not in got["trace"]
    refused = [line for line in got["trace"].splitlines() if "clone(" in line and "= -1 EPERM" in line]
    assert any("CLONE_UNTRACED" in line for line in refused) and any("CLONE_NEWUSER" in line for line in refused)


# Syscall numbers (x86_64, aarch64) for the refused-syscall probe.
SYSCALLS = {"io_uring_setup": (425, 425), "io_uring_enter": (426, 426), "io_uring_register": (427, 427),
            "process_vm_readv": (310, 270), "process_vm_writev": (311, 271), "userfaultfd": (323, 282),
            "bpf": (321, 280), "perf_event_open": (298, 241), "ptrace": (101, 117)}
# (case, syscall, arguments as Python source; `child` is a sleeping child of the probe, `ppid` the harness)
REFUSED = [
    ("io_uring_setup", "io_uring_setup", "0, 0"),
    ("io_uring_enter", "io_uring_enter", "0, 0, 0, 0, 0, 0"),
    ("io_uring_register", "io_uring_register", "0, 0, 0, 0"),
    ("process_vm_readv", "process_vm_readv", "ppid, 0, 0, 0, 0, 0"),
    ("process_vm_writev", "process_vm_writev", "ppid, 0, 0, 0, 0, 0"),
    ("userfaultfd", "userfaultfd", "0"),
    ("bpf", "bpf", "0, 0, 0"),
    ("perf_event_open", "perf_event_open", "0, 0, -1, -1, 0"),
    ("ptrace_traceme", "ptrace", "0, 0, 0, 0"),                 # PTRACE_TRACEME: it is already traced by strace
    ("ptrace_attach_strace", "ptrace", "16, 1, 0, 0"),          # PTRACE_ATTACH to PID 1, strace (root)
    ("ptrace_attach_harness", "ptrace", "16, ppid, 0, 0"),      # the harness: non-dumpable and already traced
    ("ptrace_attach_own_child", "ptrace", "16, child, 0, 0"),   # its own child: already traced by strace -f
    ("ptrace_seize_own_child", "ptrace", "0x4206, child, 0, 0"),  # PTRACE_SEIZE
]

REFUSED_PROBE = """import ctypes, os, signal, time
libc = ctypes.CDLL(None, use_errno=True)
ppid = os.getppid()
child = os.fork()
if child == 0:
    time.sleep(10)
    os._exit(0)
time.sleep(0.2)
ret = libc.syscall({number}, {args})
print("RESULT", ret, ctypes.get_errno())
os.kill(child, signal.SIGKILL)
os.waitpid(child, 0)
"""


@requires_docker
@pytest.mark.parametrize("case, name, args", REFUSED, ids=[case for case, _, _ in REFUSED])
def test_a_package_process_is_refused_dangerous_syscalls_and_ptrace(tmp_path, case, name, args):
    """io_uring, process_vm_*, userfaultfd, bpf, perf_event_open are refused by the profile; ptrace (which strace
    needs, so the profile allows it) is refused by the kernel. Each attempt fails and is in the trace."""
    import platform
    machine = platform.machine()
    if machine not in ("x86_64", "aarch64"):
        pytest.skip(f"no syscall numbers for {machine}")
    number = SYSCALLS[name][0 if machine == "x86_64" else 1]
    got = observed(tmp_path, REFUSED_PROBE.format(number=number, args=args))
    assert got["rule"] == "DEEP_NOT_JUDGED", (got["reason"], got["output"]["text"])
    result = next(line.split() for line in got["output"]["text"].splitlines() if line.startswith("RESULT"))
    assert result[1] == "-1" and result[2] in ("1", "38"), result  # EPERM or ENOSYS
    probe_pid = got["evidence"]["step_pids"]["probe"][0]
    attempts = [line for line in got["trace"].splitlines()
                if line.split(None, 1)[0] == str(probe_pid) and line.split(None, 1)[1].startswith(f"{name}(")]
    assert len(attempts) == 1, attempts
    assert attempts[0].split(" = ")[-1].startswith(("-1 EPERM", "-1 ENOSYS")), attempts[0]


def test_the_refused_syscalls_are_traced_by_name_and_not_in_the_profile():
    profile = json.loads(sandbox_observe.sandbox_image.SECCOMP_PROFILE.read_text())
    allowed = {n for entry in profile["syscalls"] if entry["action"] == "SCMP_ACT_ALLOW" for n in entry["names"]}
    assert profile["defaultAction"] == "SCMP_ACT_ERRNO"
    assert not allowed & {"io_uring_setup", "io_uring_enter", "io_uring_register", "process_vm_readv",
                          "process_vm_writev", "userfaultfd", "bpf", "perf_event_open"}
    assert "ptrace" in allowed  # strace needs it; the kernel refuses it to package processes (Docker test above)
    traced = sandbox_observe.STRACE[sandbox_observe.STRACE.index("-e") + 1].removeprefix("trace=").split(",")
    assert set(SYSCALLS) <= set(traced)
