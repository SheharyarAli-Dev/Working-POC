"""One CAVR sandbox container: its lockdown flags (PR 3 of docs/cavr-m2-plan.md). Fail closed.

`docker_command` is the only place that builds a `docker run` command for the CAVR sandbox. Every run gets:

    --rm --name cavr-<run>-<n>       disposable, findable by name (rule 9)
    --network none                   no network, no DNS (rule 1)
    --read-only + tmpfs /tmp         read-only root; /tmp writable, noexec,nosuid,nodev, 64 MiB (rule 2)
    --cap-drop ALL + SYS_PTRACE,     only what strace needs: trace (SYS_PTRACE), drop to UID 10001 (SETUID, SETGID)
      SETUID, SETGID,                and read /proc/<pid>/fd of a UID 10001 process so that `strace -y` can print each
      DAC_READ_SEARCH                fd's path (DAC_READ_SEARCH, PR 7) (rule 3, Q5). Package processes hold none of
                                     them: the drop to UID 10001 clears every set, and the image has no setuid file
    no-new-privileges + seccomp      CAVR's profile docker/cavr-sandbox/cavr-seccomp.json (see the notes, Step M2-7)
    --pids-limit 64, --memory 256m,  limits (rule 4)
      --memory-swap 256m, --cpus 1,
      --ulimit nofile/fsize/core
    --log-driver none                the daemon keeps no copy of the output
    no host environment              only the variables passed in `env`; docker run passes none of its own
    read-only bind mounts only       every mount is `readonly`; no Docker socket, no host home

The container has no `--user`: strace is its process and runs as container root with the four capabilities
above; it starts the package's processes as UID 10001 (`strace -u cavr`). The image is named by its checked ID
(`sandbox_image.image_identity`), never by tag.
"""
from __future__ import annotations

import re
import secrets
import subprocess
import threading
import time

from backend.cavr.sandbox_image import ENGINE, SECCOMP_PROFILE

PIDS_LIMIT = 64
MEMORY = "256m"
CPUS = "1"
TMP_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"
ULIMITS = ("nofile=256:256", "fsize=67108864:67108864", "core=0:0")
CAPABILITIES = ("SYS_PTRACE", "SETUID", "SETGID", "DAC_READ_SEARCH")
NAME = re.compile(r"^cavr-[0-9a-f]{12}-[0-9]{1,3}$")
TMPFS = re.compile(r"^/[a-z][a-z0-9_-]*:rw,(?:noexec|exec),nosuid,nodev,size=[0-9]{1,4}m,mode=1777$")
_UNSAFE_MOUNT = re.compile(r"[,\n\r\0]")
DEFAULT_HOSTNAME = "cavr-sandbox"
# RFC 1123 host name: dot-separated labels of letters, digits and inner hyphens, at most 63 characters each, 253 in all.
HOSTNAME = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def lockdown_flags(seccomp=SECCOMP_PROFILE, hostname: str = DEFAULT_HOSTNAME) -> list[str]:
    flags = ["--network", "none", "--read-only", "--tmpfs", TMP_TMPFS, "--cap-drop", "ALL"]
    for cap in CAPABILITIES:
        flags += ["--cap-add", cap]
    flags += ["--security-opt", "no-new-privileges", "--security-opt", f"seccomp={seccomp}",
              "--pids-limit", str(PIDS_LIMIT), "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", CPUS]
    for limit in ULIMITS:
        flags += ["--ulimit", limit]
    if not HOSTNAME.fullmatch(hostname or ""):
        raise ValueError(f"hostname {hostname!r} is not a valid host name")
    return flags + ["--log-driver", "none", "--hostname", hostname]


def docker_command(name: str, image_id: str, command, *, mounts=(), env=None, tmpfs=(), seccomp=SECCOMP_PROFILE,
                   engine: str = ENGINE, hostname: str = DEFAULT_HOSTNAME) -> list[str]:
    """The `docker run` argv for one run. Raises ValueError on a bad name, image ID, mount or variable.

    `mounts` are (host path, container path) pairs, all mounted read-only. `tmpfs` adds mounts to /tmp's; each
    must be nosuid,nodev with a size cap (`TMPFS`). `hostname` is the container's host name (PR 11: a trigger's
    spec may set it; checked against HOSTNAME).
    """
    if not NAME.match(name or ""):
        raise ValueError(f"container name {name!r} is not cavr-<12 hex>-<n>")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id or ""):
        raise ValueError(f"image {image_id!r} is not an image ID")
    cmd = [engine, "run", "--rm", "--name", name, *lockdown_flags(seccomp, hostname)]
    for extra in tmpfs:
        if not TMPFS.match(extra) or extra.split(":", 1)[0] in ("/tmp", "/", "/pkg", "/job", "/opt/cavr", "/proc"):
            raise ValueError(f"tmpfs {extra!r} is not <path>:rw,[no]exec,nosuid,nodev,size=<n>m,mode=1777")
        cmd += ["--tmpfs", extra]
    for host, inside in mounts:
        host, inside = str(host), str(inside)
        if _UNSAFE_MOUNT.search(host) or _UNSAFE_MOUNT.search(inside) or not inside.startswith("/"):
            raise ValueError(f"mount {host!r} -> {inside!r} cannot be passed safely")
        cmd += ["--mount", f"type=bind,src={host},dst={inside},readonly"]
    for key, value in (env or {}).items():
        if not re.fullmatch(r"[A-Z_][A-Z0-9_]*", key) or "\0" in str(value):
            raise ValueError(f"environment variable {key!r} cannot be passed safely")
        cmd += ["--env", f"{key}={value}"]
    return cmd + [image_id, *command]


# --- one run: deadline, kill, output caps, removal (PR 4) ------------------------------------------------------------------
#
# `run_container(cmd, name)` starts `docker run` and returns when the container is gone. The deadline is kept by the
# host's clock, independent of output: two reader threads drain stdout and stderr into byte buffers while the main
# thread waits. At the deadline, or when a stream passes its cap, the container is killed by name (`docker kill`),
# the docker CLI process is killed and waited for, and the container is removed (`docker rm -f`). Whatever happened,
# the `finally` removes the container by name and checks with `docker ps -a` that it is gone.
#
#     COMPLETED      the container exited by itself; `exit_code` is its exit code (strace's, i.e. the harness's)
#     TIMEOUT        still running at the deadline; killed and removed
#     OUTPUT_CAP     a stream passed its cap; killed and removed
#     KILLED         exited with 137 (SIGKILL) that CAVR did not send: the memory limit or another kill
#     ENGINE_ERROR   docker could not be started, or `docker run` itself failed (exit 125, 126, 127)
#     LEFT_BEHIND    the container was still listed after removal
#
# Only COMPLETED with exit code 0 can lead anywhere; every other status is UNRESOLVED for the caller.

DEADLINE_SECONDS = 20.0  # per run (Q8)
KILL_GRACE_SECONDS = 5.0
STDOUT_CAP = 1024 * 1024  # untrusted package output, shown only
STDERR_CAP = 16 * 1024 * 1024  # the strace trace (PR 5)
DOCKER_SECONDS = 20
CLOCK = time.monotonic
POPEN = None  # tests replace it; None means subprocess.Popen
DOCKER = None  # tests replace it; None means subprocess.run (docker kill / rm / ps)
RECHECK_SECONDS = 0.5
STATUSES = ("COMPLETED", "TIMEOUT", "OUTPUT_CAP", "KILLED", "ENGINE_ERROR", "LEFT_BEHIND")


def new_run_id() -> str:
    return secrets.token_hex(6)


def container_name(run_id: str, n: int) -> str:
    name = f"cavr-{run_id}-{n}"
    if not NAME.match(name):
        raise ValueError(f"container name {name!r} is not cavr-<12 hex>-<n>")
    return name


def run_container(cmd, name: str, *, deadline: float = DEADLINE_SECONDS, grace: float = KILL_GRACE_SECONDS,
                  stdout_cap: int = STDOUT_CAP, stderr_cap: int = STDERR_CAP) -> dict:
    """Run `cmd` (from `docker_command`, container `name`) to its end, its deadline or its output cap. Never raises."""
    started = CLOCK()
    status, reason, exit_code, proc = None, None, None, None
    readers, buffers, over = [], {"stdout": bytearray(), "stderr": bytearray()}, {}
    wake = threading.Event()
    try:
        proc = (POPEN or subprocess.Popen)(list(cmd), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE)
        for stream, cap in (("stdout", stdout_cap), ("stderr", stderr_cap)):
            reader = threading.Thread(target=_drain, args=(getattr(proc, stream), buffers[stream], cap, stream, over, wake),
                                      daemon=True)
            reader.start()
            readers.append(reader)
        while proc.poll() is None:
            if over:
                status, reason = "OUTPUT_CAP", f"{' and '.join(sorted(over))} passed its cap; the container was killed"
                break
            if CLOCK() - started > deadline:
                status, reason = "TIMEOUT", f"still running after the {deadline:g} s deadline; the container was killed"
                break
            wake.wait(0.05)
            wake.clear()
        if status is not None:
            _stop(proc, name, grace)
        else:
            exit_code = proc.returncode
            # Decide only after both streams were read to their end: the docker CLI can exit before a reader has
            # seen the last bytes (and with them an output over its cap).
            for reader in readers:
                reader.join(grace)
            if any(reader.is_alive() for reader in readers):
                status, reason = "ENGINE_ERROR", f"the container's output was not read to its end within {grace:g} s"
                _stop(proc, name, grace)
            elif over:
                status, reason = "OUTPUT_CAP", f"{' and '.join(sorted(over))} passed its cap"
            elif exit_code in (125, 126, 127):
                status, reason = "ENGINE_ERROR", f"docker run failed (exit {exit_code})"
            elif exit_code in (137, -9):
                status, reason = "KILLED", "the container was killed (SIGKILL) by something other than CAVR: memory limit or kill"
            else:
                status, reason = "COMPLETED", f"the container exited with {exit_code}"
    except Exception as exc:  # no docker binary, a reader that failed, ...: nothing was observed
        status, reason = "ENGINE_ERROR", f"the container could not be run: {type(exc).__name__}: {exc}"
        if proc is not None:
            _stop(proc, name, grace)
    finally:
        for reader in readers:
            reader.join(grace)
        gone, why = _remove(name, grace, recheck=status != "COMPLETED")
        if not gone:
            status, reason = "LEFT_BEHIND", why
    stdout, stderr = bytes(buffers["stdout"]), bytes(buffers["stderr"])
    return {"status": status, "reason": reason, "name": name, "exit_code": exit_code,
            "elapsed_seconds": round(CLOCK() - started, 3), "deadline_seconds": deadline,
            "stdout": stdout, "stderr": stderr,
            "stdout_text": stdout.decode("utf-8", errors="replace"), "stderr_text": stderr.decode("utf-8", errors="replace"),
            "over_cap": sorted(over)}


def completed(result: dict) -> bool:
    """True only for a container that exited by itself with exit code 0 and was removed."""
    return result.get("status") == "COMPLETED" and result.get("exit_code") == 0


def _drain(pipe, buffer: bytearray, cap: int, stream: str, over: dict, wake: threading.Event):
    """Read `pipe` to its end. Bytes past `cap` are counted, not kept; passing the cap wakes the main thread."""
    try:
        while True:
            chunk = pipe.read1(65536) if hasattr(pipe, "read1") else pipe.read(65536)
            if not chunk:
                break
            room = cap - len(buffer)
            if room > 0:
                buffer.extend(chunk[:room])
            if len(chunk) > room:
                over[stream] = True
                wake.set()
    except (OSError, ValueError):
        pass  # the pipe was closed by the kill
    finally:
        wake.set()


def _docker(args, timeout=DOCKER_SECONDS):
    return (DOCKER or subprocess.run)([ENGINE, *args], capture_output=True, text=True, timeout=timeout)


def _stop(proc, name, grace):
    """Kill the container by name, then the docker CLI process; wait for it."""
    for step in (lambda: _docker(["kill", name], timeout=grace + DOCKER_SECONDS),
                 lambda: proc.kill(),
                 lambda: proc.wait(timeout=grace)):
        try:
            step()
        except Exception:
            pass  # removal below checks the outcome


def _remove(name, grace, recheck=False) -> tuple[bool, str | None]:
    """`docker rm -f` by name until `docker ps -a` no longer lists it. (gone, reason when not).

    `recheck`: a run that was stopped (or never got going) is listed twice, RECHECK_SECONDS apart, before it counts
    as gone: a CLI killed while the daemon was still creating the container can leave one that appears a moment later.
    """
    deadline = CLOCK() + grace + DOCKER_SECONDS
    last = None
    while True:
        try:
            listed = _docker(["ps", "-a", "-q", "--filter", f"name=^/{name}$"])
            if listed.returncode == 0 and not listed.stdout.strip():
                if not recheck:
                    return True, None
                recheck = False
                time.sleep(RECHECK_SECONDS)
                continue
            last = f"docker ps -a still lists {name}" if listed.returncode == 0 else f"docker ps failed: {listed.stderr.strip()[:200]}"
            _docker(["rm", "-f", name])
        except FileNotFoundError:
            return True, None  # no docker binary: nothing could have been started
        except Exception as exc:
            last = f"cannot check that {name} is gone: {type(exc).__name__}: {exc}"
        if CLOCK() > deadline:
            return False, last
        time.sleep(0.1)
