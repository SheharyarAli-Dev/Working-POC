if __name__ == "__main__": __import__("posix").dup2(__import__("posix").open("/dev/null", 1), 2)  # noqa: E701,E702
# ^ First statement, before any other import: in the sandbox this file is the process strace starts, and its fd 2
#   is strace's own stderr, the trace channel. Pointing fd 2 at /dev/null here means no code that runs after this
#   line (and no package code ever) can write into the trace. `posix` is a built-in module (no file is read).
#
# CAVR sandbox harness (PR 5 of docs/cavr-m2-plan.md). Trusted, stdlib only, mounted read-only at /opt/cavr/harness.py
# and started as UID 10001 by `strace -f -u cavr -- /usr/local/bin/python -I -S /opt/cavr/harness.py /job/job.json`.
#
# It never runs package code itself. It
#   1. closes stdin, takes the run's marker nonce out of its environment (CAVR_RUN_NONCE) and makes itself
#      non-dumpable (prctl PR_SET_DUMPABLE 0), so a process of the same UID cannot read its environment or memory;
#   2. runs each step of the job (pip install, import, ...) as a child process with an environment built from
#      scratch, stdin from /dev/null and stdout + stderr to the container's stdout (untrusted output, shown only);
#      the nonce is in neither the argv nor the environment of any child (refused otherwise);
#   3. after each step kills every remaining process of its UID (kill(-1, SIGKILL)), so nothing a step left behind
#      runs on;
#   4. marks each phase with a failed stat of /.cavr/<nonce>/<phase>, which strace records with the harness's PID.
#
# Markers: start, step:<name>:begin, step:<name>:end:<exit code>, end:ok | end:fail. Exit codes: 0 every step exited 0;
# 3 bad job or nonce; 4 a step failed; 5 internal error. `sandbox_trace.check_trace` reads the markers.
import json
import os
import signal
import subprocess
import sys

NONCE_VARIABLE = "CAVR_RUN_NONCE"
SANDBOX_UID = 10001
INSTALLED_AT = "/opt/cavr/harness.py"
CHILD_ENV = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/tmp/home", "LANG": "C.UTF-8", "TMPDIR": "/tmp",
             "PYTHONDONTWRITEBYTECODE": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1",
             "PIP_NO_INPUT": "1"}
EXIT_OK, EXIT_BAD_JOB, EXIT_STEP_FAILED, EXIT_INTERNAL = 0, 3, 4, 5
PHASE = ("start", "begin", "end")


def valid_nonce(nonce) -> bool:
    return isinstance(nonce, str) and len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce)


def marker(nonce, phase):
    """A failed stat that strace records as `newfstatat(AT_FDCWD, "/.cavr/<nonce>/<phase>", ...) = -1 ENOENT`."""
    try:
        os.stat(f"/.cavr/{nonce}/{phase}")
    except OSError:
        pass


def child_env(extra, nonce) -> dict:
    """The environment of a step: CHILD_ENV plus the job's own variables. Never anything of the harness's own."""
    env = dict(CHILD_ENV)
    env.update(extra or {})
    if any(nonce in key or nonce in value for key, value in env.items()):
        raise ValueError("the marker nonce would reach a child's environment")
    return env


def read_job(path, nonce) -> list:
    """[(name, argv, env)] from the job file. Raises ValueError on anything malformed or carrying the nonce."""
    with open(path, encoding="utf-8") as handle:
        job = json.load(handle)
    steps = job.get("steps") if isinstance(job, dict) else None
    if not isinstance(steps, list) or not steps:
        raise ValueError("job has no steps")
    out = []
    for step in steps:
        name, argv, extra = step.get("name"), step.get("argv"), step.get("env", {})
        if not (isinstance(name, str) and name.isidentifier()):
            raise ValueError(f"bad step name {name!r}")
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
            raise ValueError(f"step {name}: bad argv")
        if not (isinstance(extra, dict) and all(isinstance(k, str) and isinstance(v, str) for k, v in extra.items())):
            raise ValueError(f"step {name}: bad env")
        if any(nonce in a for a in argv):
            raise ValueError(f"step {name}: the marker nonce would reach a child's argv")
        out.append((name, argv, child_env(extra, nonce)))
    return out


def run_step(argv, env) -> int:
    # No cwd: the image's WORKDIR is /tmp, and chdir is not in CAVR's seccomp profile.
    done = subprocess.run(argv, env=env, stdin=subprocess.DEVNULL, stdout=1, stderr=subprocess.STDOUT, close_fds=True)
    return done.returncode


def kill_leftovers(kill=os.kill, rounds=50) -> int:
    """SIGKILL every other process of this UID until none is left (kill(-1) reaches no root process). Rounds used."""
    for used in range(1, rounds + 1):
        try:
            kill(-1, signal.SIGKILL)
        except ProcessLookupError:
            return used
    return rounds


def in_sandbox() -> bool:
    """kill(-1) is only ever sent inside the sandbox: as UID 10001, from the mounted harness file."""
    return os.getuid() == SANDBOX_UID and os.path.abspath(__file__) == INSTALLED_AT


def make_undumpable():
    import ctypes
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(4, 0, 0, 0, 0) != 0:  # PR_SET_DUMPABLE = 4
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_DUMPABLE, 0) failed")


def main(argv) -> int:
    os.close(0)  # stdin closed; children get /dev/null
    nonce = os.environ.pop(NONCE_VARIABLE, "")
    if not valid_nonce(nonce):
        return EXIT_BAD_JOB
    try:
        make_undumpable()
    except OSError:
        return EXIT_INTERNAL
    marker(nonce, "start")
    try:
        steps = read_job(argv[1], nonce)
    except (OSError, ValueError, IndexError, AttributeError):
        marker(nonce, "end:fail")
        return EXIT_BAD_JOB
    sandboxed = in_sandbox()
    for name, step_argv, env in steps:
        marker(nonce, f"step:{name}:begin")
        try:
            code = run_step(step_argv, env)
        except OSError:
            code = 127
        if sandboxed:
            kill_leftovers()
        marker(nonce, f"step:{name}:end:{code if code >= 0 else 128 - code}")
        if code != 0:
            marker(nonce, "end:fail")
            return EXIT_STEP_FAILED
    marker(nonce, "end:ok")
    return EXIT_OK


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv))
    except SystemExit:
        raise
    except BaseException:
        os._exit(EXIT_INTERNAL)
