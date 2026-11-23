"""PR 4 of docs/cavr-m2-plan.md: the run of one sandbox container -- deadline, kill, output caps, removal.

Unit tests use a fake `docker run` process whose stdout and stderr are real OS pipes, so the reader threads,
the deadline and the cap are exercised as they are with Docker. Docker tests (`requires_docker`, CAVR_DOCKER=1)
run the real image with a short deadline; after each one `docker ps -a` must list no cavr-* container.
"""
import os
import threading

import pytest

from backend.cavr import sandbox_exec
from tests.test_cavr_support import cavr_containers, requires_docker, sandbox_identity


class FakeDockerRun:
    """A `docker run` that is silent until the test writes, finishes or kills it."""

    def __init__(self):
        out_r, self._out_w = os.pipe()
        err_r, self._err_w = os.pipe()
        self.stdout, self.stderr = os.fdopen(out_r, "rb", buffering=0), os.fdopen(err_r, "rb", buffering=0)
        self.returncode = None
        self.killed = self.waited = False
        self._lock = threading.Lock()

    def write(self, stream, data):
        os.write(self._out_w if stream == "stdout" else self._err_w, data)

    def finish(self, code):
        with self._lock:
            self._close()
            self.returncode = code

    def _close(self):
        for fd in (self._out_w, self._err_w):
            try:
                os.close(fd)
            except OSError:
                pass

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True
        self.finish(-9)

    def wait(self, timeout=None):
        self.waited = True
        return self.returncode


@pytest.fixture
def docker(monkeypatch):
    """Fake `docker kill / rm / ps` and `docker run`. `.listed` is what `docker ps -a` prints."""
    class Docker:
        calls = []
        listed = ""
        procs = []
        popen_error = None
        on_start = None

        @classmethod
        def run(cls, cmd, **kwargs):
            cls.calls.append(cmd[1:])
            if cmd[1] == "ps":
                return _done(0, cls.listed)
            if cmd[1] == "rm":
                cls.listed = ""
            return _done(0, "")

        @classmethod
        def popen(cls, cmd, **kwargs):
            cls.calls.append(["run-cli", *cmd[2:4]])
            assert kwargs["stdin"] is sandbox_exec.subprocess.DEVNULL
            if cls.popen_error:
                raise cls.popen_error
            proc = FakeDockerRun()
            cls.procs.append(proc)
            if cls.on_start:
                cls.on_start(proc)
            return proc
    Docker.calls, Docker.procs = [], []
    monkeypatch.setattr(sandbox_exec, "DOCKER", Docker.run)
    monkeypatch.setattr(sandbox_exec, "POPEN", Docker.popen)
    return Docker


def _done(code, stdout):
    return sandbox_exec.subprocess.CompletedProcess([], code, stdout, "")


NAME = "cavr-0123456789ab-1"


def run(**kwargs):
    kwargs.setdefault("deadline", 0.3)
    kwargs.setdefault("grace", 0.5)
    return sandbox_exec.run_container(["docker", "run", "--name", NAME], NAME, **kwargs)


# --- unit ---------------------------------------------------------------------------------------------------------------

def test_the_default_deadline_is_twenty_seconds_per_run():
    assert sandbox_exec.DEADLINE_SECONDS == 20.0 and sandbox_exec.KILL_GRACE_SECONDS == 5.0


def test_silent_container_is_killed_at_the_deadline(docker):
    got = run()
    assert got["status"] == "TIMEOUT" and not sandbox_exec.completed(got)
    assert 0.3 <= got["elapsed_seconds"] < 0.3 + 0.5 + 1
    proc = docker.procs[0]
    assert proc.killed and proc.waited


def test_kill_and_removal_target_the_container_name(docker):
    run()
    names = [call for call in docker.calls if call[0] in ("kill", "rm")]
    assert names[0] == ["kill", NAME] and ["rm", "-f", NAME] not in names[:1]
    assert ["ps", "-a", "-q", "--filter", f"name=^/{NAME}$"] in docker.calls


def test_kill_happens_before_the_cli_process_is_killed(docker):
    def start(proc):
        proc.kill = lambda: (docker.calls.append(["cli-kill"]), FakeDockerRun.kill(proc))
    docker.on_start = start
    run()
    assert docker.calls.index(["kill", NAME]) < docker.calls.index(["cli-kill"])


def test_output_does_not_keep_a_container_alive_past_its_deadline(docker):
    def chatter(proc):
        def talk():
            for _ in range(200):
                try:
                    proc.write("stdout", b"x" * 10)
                except OSError:
                    return
                threading.Event().wait(0.01)
        threading.Thread(target=talk, daemon=True).start()
    docker.on_start = chatter
    got = run()
    assert got["status"] == "TIMEOUT" and got["elapsed_seconds"] < 1.5


def test_finished_container_is_completed_with_its_exit_code(docker):
    docker.on_start = lambda proc: (proc.write("stdout", b"out"), proc.write("stderr", b"trace"), proc.finish(0))
    got = run(deadline=5)
    assert got["status"] == "COMPLETED" and got["exit_code"] == 0 and sandbox_exec.completed(got)
    assert got["stdout"] == b"out" and got["stderr"] == b"trace"
    assert not any(call[0] == "kill" for call in docker.calls)


def test_non_zero_exit_is_completed_but_not_usable(docker):
    docker.on_start = lambda proc: proc.finish(3)
    got = run(deadline=5)
    assert got["status"] == "COMPLETED" and got["exit_code"] == 3 and not sandbox_exec.completed(got)


@pytest.mark.parametrize("code, status", [(125, "ENGINE_ERROR"), (126, "ENGINE_ERROR"), (127, "ENGINE_ERROR"),
                                          (137, "KILLED"), (-9, "KILLED")])
def test_docker_failure_and_foreign_kill_are_not_completed(docker, code, status):
    docker.on_start = lambda proc: proc.finish(code)
    got = run(deadline=5)
    assert got["status"] == status and not sandbox_exec.completed(got)


def test_invalid_utf8_is_replaced_not_fatal(docker):
    docker.on_start = lambda proc: (proc.write("stdout", b"ok \xff\xfe end"), proc.write("stderr", b"\xc3("), proc.finish(0))
    got = run(deadline=5)
    assert got["status"] == "COMPLETED"
    assert got["stdout_text"] == "ok \ufffd\ufffd end" and got["stderr_text"] == "\ufffd("
    assert got["stdout"] == b"ok \xff\xfe end"


@pytest.mark.parametrize("stream", ["stdout", "stderr"])
def test_output_over_the_cap_is_killed_and_unresolved(docker, stream):
    docker.on_start = lambda proc: proc.write(stream, b"y" * 5000)
    got = run(deadline=5, stdout_cap=1000, stderr_cap=1000)
    assert got["status"] == "OUTPUT_CAP" and got["over_cap"] == [stream] and not sandbox_exec.completed(got)
    assert len(got[stream]) == 1000 and docker.procs[0].killed
    assert got["elapsed_seconds"] < 2


def test_output_over_the_cap_at_exit_is_still_unresolved(docker):
    docker.on_start = lambda proc: (proc.write("stdout", b"y" * 5000), proc.finish(0))
    got = run(deadline=5, stdout_cap=1000)
    assert got["status"] == "OUTPUT_CAP"


def test_output_over_the_cap_at_exit_is_never_completed(docker, monkeypatch):
    """The CLI exits before the readers have read the bytes over the cap: the decision waits for the readers."""
    monkeypatch.setattr(sandbox_exec, "RECHECK_SECONDS", 0.001)
    for _ in range(50):
        docker.on_start = lambda proc: (proc.write("stdout", b"y" * 5000), proc.finish(0))
        got = run(deadline=5, stdout_cap=1000)
        assert got["status"] == "OUTPUT_CAP" and not sandbox_exec.completed(got)


def test_output_not_read_to_its_end_is_not_completed(docker):
    """A stream still open after the CLI exited (its reader still blocked) is ENGINE_ERROR, never COMPLETED."""
    def start(proc):
        proc.returncode = 0  # exited, but the write ends stay open: the readers never see EOF
    docker.on_start = start
    got = run(deadline=5, grace=0.3)
    assert got["status"] == "ENGINE_ERROR" and "not read to its end" in got["reason"]
    docker.procs[0]._close()


def test_a_stopped_run_is_listed_twice_before_it_counts_as_gone(monkeypatch, docker):
    """A container the daemon was still creating when the CLI was killed can appear after a first empty listing."""
    monkeypatch.setattr(sandbox_exec, "RECHECK_SECONDS", 0.01)
    listings = iter(["", "late123\n", ""])

    def ps(cmd, **kwargs):
        docker.calls.append(cmd[1:])
        return _done(0, next(listings, "") if cmd[1] == "ps" else "")
    monkeypatch.setattr(sandbox_exec, "DOCKER", ps)
    got = run()
    assert got["status"] == "TIMEOUT"
    assert ["rm", "-f", NAME] in docker.calls and [c[0] for c in docker.calls].count("ps") == 3


def test_a_completed_run_is_listed_once(docker):
    docker.on_start = lambda proc: proc.finish(0)
    run(deadline=5)
    assert [c[0] for c in docker.calls].count("ps") == 1


@pytest.mark.parametrize("tmpfs", ["/site:rw,exec,size=128m", "/site:rw,exec,nosuid,nodev,mode=1777",
                                   "/tmp:rw,exec,nosuid,nodev,size=64m,mode=1777", "/pkg:rw,exec,nosuid,nodev,size=1m,mode=1777",
                                   "/site:rw,exec,suid,nodev,size=128m,mode=1777", "site:rw,exec,nosuid,nodev,size=1m,mode=1777"])
def test_a_tmpfs_without_nosuid_nodev_and_a_size_is_refused(tmpfs):
    with pytest.raises(ValueError, match="tmpfs"):
        sandbox_exec.docker_command(NAME, "sha256:" + "ab" * 32, ["true"], tmpfs=[tmpfs])


def test_the_install_target_tmpfs_is_accepted():
    cmd = sandbox_exec.docker_command(NAME, "sha256:" + "ab" * 32, ["true"],
                                      tmpfs=["/site:rw,exec,nosuid,nodev,size=128m,mode=1777"])
    assert cmd[cmd.index("/site:rw,exec,nosuid,nodev,size=128m,mode=1777") - 1] == "--tmpfs"


@pytest.mark.parametrize("error", [FileNotFoundError("docker"), PermissionError("denied"), RuntimeError("boom")])
def test_docker_that_cannot_start_is_an_engine_error_and_is_still_cleaned_up(docker, error):
    docker.popen_error = error
    got = run()
    assert got["status"] == "ENGINE_ERROR" and type(error).__name__ in got["reason"]
    assert ["ps", "-a", "-q", "--filter", f"name=^/{NAME}$"] in docker.calls


def test_no_docker_binary_at_all_returns_without_waiting(monkeypatch, docker):
    def missing(cmd, **kwargs):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(sandbox_exec, "DOCKER", missing)
    docker.popen_error = FileNotFoundError("docker")
    got = run()
    assert got["status"] == "ENGINE_ERROR" and got["elapsed_seconds"] < 1


def test_container_still_listed_after_removal_is_left_behind(monkeypatch, docker):
    monkeypatch.setattr(sandbox_exec, "DOCKER_SECONDS", 0)

    def stuck(cmd, **kwargs):
        docker.calls.append(cmd[1:])
        return _done(0, "abc123\n" if cmd[1] == "ps" else "")
    monkeypatch.setattr(sandbox_exec, "DOCKER", stuck)
    docker.on_start = lambda proc: proc.finish(0)
    got = run(deadline=5, grace=0.3)
    assert got["status"] == "LEFT_BEHIND" and NAME in got["reason"] and not sandbox_exec.completed(got)
    assert ["rm", "-f", NAME] in docker.calls


def test_names_are_unique_and_well_formed():
    names = {sandbox_exec.container_name(sandbox_exec.new_run_id(), n) for n in range(1000)}
    assert len(names) == 1000 and all(sandbox_exec.NAME.match(name) for name in names)
    with pytest.raises(ValueError):
        sandbox_exec.container_name("../x", 1)


# --- Docker -------------------------------------------------------------------------------------------------------------

def docker_run(command, deadline=3.0, **kwargs):
    identity = sandbox_identity()
    name = sandbox_exec.container_name(sandbox_exec.new_run_id(), 1)
    cmd = sandbox_exec.docker_command(name, identity["image_id"], command)
    got = sandbox_exec.run_container(cmd, name, deadline=deadline, **kwargs)
    assert cavr_containers() == [], "a cavr-* container was left behind"
    return got


PY = ["/usr/local/bin/python", "-I", "-S", "-c"]


@requires_docker
def test_infinite_loop_is_killed_within_deadline_plus_grace():
    got = docker_run(PY + ["while True: pass"])
    assert got["status"] == "TIMEOUT"
    assert 3.0 <= got["elapsed_seconds"] <= 3.0 + sandbox_exec.KILL_GRACE_SECONDS


@requires_docker
def test_sleeping_container_is_killed_and_removed():
    got = docker_run(["sleep", "600"], deadline=2.0)
    assert got["status"] == "TIMEOUT" and got["elapsed_seconds"] <= 2.0 + sandbox_exec.KILL_GRACE_SECONDS


@requires_docker
@pytest.mark.parametrize("command, status", [(["/nonexistent"], "ENGINE_ERROR"),
                                             (PY + ["raise SystemExit(3)"], "COMPLETED")])
def test_failed_run_leaves_no_container(command, status):
    got = docker_run(command, deadline=20.0)
    assert got["status"] == status and not sandbox_exec.completed(got)


@requires_docker
def test_fork_bomb_stops_at_the_pids_limit():
    code = ("import os, time\nn = 0\ntry:\n    while True:\n        if os.fork() == 0:\n            time.sleep(30)\n"
            "            os._exit(0)\n        n += 1\nexcept OSError as e:\n    print(n, e.errno)\n")
    got = docker_run(PY + [code], deadline=20.0)
    assert sandbox_exec.completed(got), got["stderr_text"]
    forked, errno = map(int, got["stdout_text"].split())
    assert forked < 64 and errno == 11  # EAGAIN: the pids cgroup refused the 64th task


@requires_docker
def test_memory_hog_is_killed_and_unresolved():
    got = docker_run(PY + ["b = []\nwhile True:\n    b.append(bytearray(16 << 20))\n"], deadline=20.0)
    assert got["status"] == "KILLED" and not sandbox_exec.completed(got)


@requires_docker
def test_flood_of_output_is_capped_and_killed():
    got = docker_run(["yes"], deadline=20.0, stdout_cap=1024 * 1024)
    assert got["status"] == "OUTPUT_CAP" and len(got["stdout"]) == 1024 * 1024


@requires_docker
def test_invalid_utf8_from_a_real_container_is_replaced():
    got = docker_run(PY + ["import sys; sys.stdout.buffer.write(b'a\\xffb')"], deadline=20.0)
    assert sandbox_exec.completed(got) and got["stdout_text"] == "a\ufffdb"
