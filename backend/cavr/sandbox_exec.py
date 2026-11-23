"""One CAVR sandbox container: its lockdown flags (PR 3 of docs/cavr-m2-plan.md). Fail closed.

`docker_command` is the only place that builds a `docker run` command for the CAVR sandbox. Every run gets:

    --rm --name cavr-<run>-<n>       disposable, findable by name (rule 9)
    --network none                   no network, no DNS (rule 1)
    --read-only + tmpfs /tmp         read-only root; /tmp writable, noexec,nosuid,nodev, 64 MiB (rule 2)
    --cap-drop ALL + SYS_PTRACE,     only what strace needs to trace and to drop to UID 10001 (rule 3, Q5)
      SETUID, SETGID
    no-new-privileges + seccomp      CAVR's profile docker/cavr-sandbox/cavr-seccomp.json (see the notes, Step M2-7)
    --pids-limit 64, --memory 256m,  limits (rule 4)
      --memory-swap 256m, --cpus 1,
      --ulimit nofile/fsize/core
    --log-driver none                the daemon keeps no copy of the output
    no host environment              only the variables passed in `env`; docker run passes none of its own
    read-only bind mounts only       every mount is `readonly`; no Docker socket, no host home

The container has no `--user`: strace is its process and runs as container root with the three capabilities
above; it starts the package's processes as UID 10001 (`strace -u cavr`). The image is named by its checked ID
(`sandbox_image.image_identity`), never by tag.
"""
from __future__ import annotations

import re

from backend.cavr.sandbox_image import ENGINE, SECCOMP_PROFILE

PIDS_LIMIT = 64
MEMORY = "256m"
CPUS = "1"
TMP_TMPFS = "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"
ULIMITS = ("nofile=256:256", "fsize=67108864:67108864", "core=0:0")
CAPABILITIES = ("SYS_PTRACE", "SETUID", "SETGID")
NAME = re.compile(r"^cavr-[0-9a-f]{12}-[0-9]{1,3}$")
_UNSAFE_MOUNT = re.compile(r"[,\n\r\0]")


def lockdown_flags(seccomp=SECCOMP_PROFILE) -> list[str]:
    flags = ["--network", "none", "--read-only", "--tmpfs", TMP_TMPFS, "--cap-drop", "ALL"]
    for cap in CAPABILITIES:
        flags += ["--cap-add", cap]
    flags += ["--security-opt", "no-new-privileges", "--security-opt", f"seccomp={seccomp}",
              "--pids-limit", str(PIDS_LIMIT), "--memory", MEMORY, "--memory-swap", MEMORY, "--cpus", CPUS]
    for limit in ULIMITS:
        flags += ["--ulimit", limit]
    return flags + ["--log-driver", "none", "--hostname", "cavr-sandbox"]


def docker_command(name: str, image_id: str, command, *, mounts=(), env=None, tmpfs=(), seccomp=SECCOMP_PROFILE,
                   engine: str = ENGINE) -> list[str]:
    """The `docker run` argv for one run. Raises ValueError on a bad name, image ID, mount or variable.

    `mounts` are (host path, container path) pairs, all mounted read-only. `tmpfs` adds mounts to /tmp's.
    """
    if not NAME.match(name or ""):
        raise ValueError(f"container name {name!r} is not cavr-<12 hex>-<n>")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id or ""):
        raise ValueError(f"image {image_id!r} is not an image ID")
    cmd = [engine, "run", "--rm", "--name", name, *lockdown_flags(seccomp)]
    for extra in tmpfs:
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
