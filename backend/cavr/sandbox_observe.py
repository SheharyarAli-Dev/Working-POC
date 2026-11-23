"""One observed sandbox run: harness + strace in asent-cavr-sandbox (PR 5 of docs/cavr-m2-plan.md). Fail closed.

`run_harness(steps, ...)` checks the image (`sandbox_image.image_identity`), writes the job file, starts

    strace -f -q --always-show-pid -y -s 4096 -e trace=%file,%network,%process,%creds,<TRACED_BY_NAME>,fchdir -u cavr --
        /usr/local/bin/python -I -S /opt/cavr/harness.py /job/job.json

as the container's process (root, with only SYS_PTRACE, SETUID, SETGID, DAC_READ_SEARCH and no-new-privileges, Q5), keeps the
deadline (`sandbox_exec.run_container`) and checks the trace (`sandbox_trace.check_trace`). strace starts the
harness, and with it every package process, as UID 10001.

Channels: the container's stderr is strace's trace, which nothing else can write (see sandbox_trace). The container's
stdout is the packages' output: it is returned as `output`, marked untrusted, and never parsed.

The run's marker nonce (32 hex characters, new per run) reaches only strace's environment (`--env CAVR_RUN_NONCE`);
the harness removes it from its own and never passes it to a child. The job file carries no nonce (refused if a
step's argv or env would).

The result is never VERIFIED in Phase 2a: judging the events against the contract is PR 7 / PR 8. A complete run is
UNRESOLVED `DEEP_NOT_JUDGED` with the trace attached; anything incomplete is UNRESOLVED with the reason:

    image rules (sandbox_image)   IMAGE_MISSING, IMAGE_ID_MISMATCH, ENGINE_UNAVAILABLE, ...; nothing is started
    SANDBOX_TIMEOUT / _OUTPUT_CAP / _KILLED / _ENGINE_ERROR / _LEFT_BEHIND   from the container run
    SANDBOX_EXIT_NONZERO          the harness (strace) exited non-zero: a step failed, bad job, internal error
    TRACE_INCOMPLETE              the trace failed `check_trace` (its own rule is in the evidence)
    JOB_INVALID                   a step cannot be passed (bad name, or it would carry the nonce)
    SECCOMP_CHANGED               the profile's SHA-256 differs from the one the image check read; nothing is run
    INTERNAL_ERROR                anything that raised
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import tempfile
from pathlib import Path

from backend.cavr import sandbox_exec, sandbox_image
from backend.cavr.sandbox_trace import check_trace

HARNESS = Path(__file__).resolve().with_name("sandbox_harness.py")
HARNESS_INSIDE = "/opt/cavr/harness.py"
JOB_INSIDE = "/job"
# Refused or kernel-blocked syscalls that are not in strace's %file/%network/%process/%creds classes, traced by
# name so that every attempt is in the trace: ptrace (allowed by the profile because strace needs it; the kernel
# refuses it to package processes) and eight the profile refuses (EPERM).
TRACED_BY_NAME = ("ptrace", "process_vm_readv", "process_vm_writev", "io_uring_setup", "io_uring_enter",
                  "io_uring_register", "userfaultfd", "bpf", "perf_event_open")
# fchdir is not in %file (it takes an fd, not a path); it is traced so that each process's current directory, and
# with it every relative path, can be followed (PR 7).
FOLLOWED_BY_NAME = ("fchdir",)
# -s 4096: strings up to PATH_MAX are printed whole; a longer one is cut and marked `"..."...`, which the normaliser
# treats as an incomplete event (PR 7). -y: every fd argument is printed with its path (`3</site/lib>`), so a path
# relative to a directory fd can be resolved.
STRING_LIMIT = 4096
STRACE = ["strace", "-f", "-q", "--always-show-pid", "-y", "-s", str(STRING_LIMIT),
          "-e", "trace=%file,%network,%process,%creds," + ",".join(TRACED_BY_NAME + FOLLOWED_BY_NAME),
          "-u", "cavr", "--", "/usr/local/bin/python", "-I", "-S", HARNESS_INSIDE, f"{JOB_INSIDE}/job.json"]
NONCE_VARIABLE = "CAVR_RUN_NONCE"
OUTPUT_SHOWN = 4000
RUN_RULES = {"TIMEOUT": "SANDBOX_TIMEOUT", "OUTPUT_CAP": "SANDBOX_OUTPUT_CAP", "KILLED": "SANDBOX_KILLED",
             "ENGINE_ERROR": "SANDBOX_ENGINE_ERROR", "LEFT_BEHIND": "SANDBOX_LEFT_BEHIND"}
IDENTITY = None  # tests replace it; None means sandbox_image.image_identity
RUN = None  # tests replace it; None means sandbox_exec.run_container


def step(name: str, argv, env=None) -> dict:
    return {"name": name, "argv": list(argv), "env": dict(env or {})}


def job_file(steps, nonce: str) -> dict:
    """The job the harness reads. Raises ValueError when a step is malformed or would carry the nonce."""
    out = []
    for item in steps:
        name, argv, env = item.get("name"), item.get("argv"), item.get("env", {})
        if not (isinstance(name, str) and name.isidentifier()):
            raise ValueError(f"bad step name {name!r}")
        if not (isinstance(argv, list) and argv and all(isinstance(a, str) for a in argv)):
            raise ValueError(f"step {name}: bad argv")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
            raise ValueError(f"step {name}: bad env")
        if any(nonce in a for a in argv) or any(nonce in k or nonce in v for k, v in env.items()):
            raise ValueError(f"step {name}: the marker nonce would reach a child")
        out.append({"name": name, "argv": argv, "env": env})
    if not out:
        raise ValueError("no steps")
    return {"steps": out}


def run_harness(steps, *, mounts=(), tmpfs=(), deadline: float = sandbox_exec.DEADLINE_SECONDS,
                stderr_cap: int = sandbox_exec.STDERR_CAP, run_id: str | None = None, n: int = 1, strace=None,
                hostname: str | None = None) -> dict:
    """{status, stage, rule, reason, evidence, trace, output}. Never raises; never VERIFIED.

    `strace` (default STRACE) and `hostname` (default cavr-sandbox) are for PR 11's spec runs (`sandbox_spec`).
    """
    try:
        return _run(list(steps), mounts, tmpfs, deadline, stderr_cap, run_id or sandbox_exec.new_run_id(), n,
                    list(strace or STRACE), hostname or sandbox_exec.DEFAULT_HOSTNAME)
    except Exception as exc:
        return _result("INTERNAL_ERROR", f"the sandbox run failed: {type(exc).__name__}: {exc}", {})


def _run(steps, mounts, tmpfs, deadline, stderr_cap, run_id, n, strace, hostname) -> dict:
    identity = (IDENTITY or sandbox_image.image_identity)()
    evidence = {"image": identity.get("image"), "image_id": identity.get("image_id"), "image_check": identity.get("rule"),
                "seccomp_sha256": identity.get("seccomp_sha256"), "harness_sha256": _sha256(HARNESS),
                "strace": strace, "deadline_seconds": deadline, "hostname": hostname}
    if not identity.get("ok"):
        return _result(identity.get("rule") or "ENGINE_ERROR", f"no isolation: {identity.get('reason')}; "
                       "the package was not run", evidence)
    if _sha256(sandbox_image.SECCOMP_PROFILE) != identity.get("seccomp_sha256"):
        return _result("SECCOMP_CHANGED", "the CAVR seccomp profile changed after the image check; the package was not run",
                       evidence)
    nonce = secrets.token_hex(16)
    try:
        job = job_file(steps, nonce)
    except ValueError as exc:
        return _result("JOB_INVALID", str(exc), evidence)
    name = sandbox_exec.container_name(run_id, n)
    with tempfile.TemporaryDirectory(prefix="cavr-job-") as directory:
        job_dir = Path(directory)
        (job_dir / "job.json").write_text(json.dumps(job, indent=2), encoding="utf-8")
        os.chmod(job_dir, 0o755)  # the harness runs as UID 10001 and must read it; nothing in it is secret
        os.chmod(job_dir / "job.json", 0o644)
        cmd = sandbox_exec.docker_command(name, identity["image_id"], strace,
                                          mounts=[(HARNESS, HARNESS_INSIDE), (job_dir, JOB_INSIDE), *mounts],
                                          env={NONCE_VARIABLE: nonce}, tmpfs=tmpfs, hostname=hostname)
        run = (RUN or sandbox_exec.run_container)(cmd, name, deadline=deadline, stderr_cap=stderr_cap)
    evidence.update({"container": name, "run_status": run["status"], "exit_code": run["exit_code"],
                     "elapsed_seconds": run["elapsed_seconds"], "lockdown_flags": sandbox_exec.lockdown_flags(hostname=hostname),
                     "extra_tmpfs": list(tmpfs), "steps": [s["name"] for s in job["steps"]],
                     "trace_sha256": hashlib.sha256(run["stderr"]).hexdigest(), "trace_bytes": len(run["stderr"])})
    output = {"text": run["stdout_text"][:OUTPUT_SHOWN], "bytes": len(run["stdout"]), "trusted": False}
    trace_text = run["stderr_text"]
    ended_well = run["status"] == "COMPLETED" and run["exit_code"] == 0
    checked = check_trace(run["stderr"], nonce, evidence["steps"]) if ended_well else None
    if checked is None or not checked["complete"]:
        # D6: a run that did not end well (or whose trace is not complete) is still read in partial mode, so that a
        # violation it shows can be judged; its result stays UNRESOLVED here (never VERIFIED).
        partial = check_trace(run["stderr"], nonce, evidence["steps"], partial=True)
        checked = partial if checked is None else {**partial, "rule": checked["rule"], "reason": checked["reason"]}
    evidence.update({"trace_check": checked["rule"], "trace_reason": checked["reason"], "trace_lines": checked["lines"],
                     "trace_attributable": checked["attributable"], "root_pid": checked["root_pid"],
                     "processes": checked["processes"], "step_pids": checked["steps"], "job_steps": job["steps"]})
    if run["status"] != "COMPLETED":
        return _result(RUN_RULES.get(run["status"], "SANDBOX_ENGINE_ERROR"), run["reason"], evidence, trace_text, output)
    if run["exit_code"] != 0:
        return _result("SANDBOX_EXIT_NONZERO", f"the harness exited with {run['exit_code']} (a step failed or the run "
                       "was cut short)", evidence, trace_text, output)
    if not checked["complete"]:
        return _result("TRACE_INCOMPLETE", f"the trace is incomplete: {checked['reason']}", evidence, trace_text, output)
    return _result("DEEP_NOT_JUDGED", "the run completed and its trace is complete; judging the events against the "
                   "contract is PR 7 / PR 8, so this is not a verdict", evidence, trace_text, output)


def _sha256(path) -> str | None:
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None


def _result(rule, reason, evidence, trace="", output=None) -> dict:
    return {"status": "UNRESOLVED", "stage": "deep", "rule": rule, "reason": reason, "evidence": evidence,
            "trace": trace, "output": output or {"text": "", "bytes": 0, "trusted": False}}


# --- install the verified wheels and import their top-level modules (PR 6) ---------------------------------------------
#
# `observe(nodes, modules)` is the deep run of one verified tree. On the host, before anything is mounted, every node
# must be a verified wheel in CAVR's quarantine (name, version, a .whl filename that is the file's own name, a
# 64-hex sha256, a regular file inside the quarantine directory). Its bytes are read once, hashed, compared with the
# tree's sha256 and written to a per-run staging directory (0644: the quarantine's files are 0600 and the sandbox user
# is 10001), which is mounted read-only at /pkg with `hashes.txt` (`name==version --hash=sha256:<sha256>` per node).
# In the sandbox the harness runs two steps:
#
#   install   python -I -B -c <PIP_CODE> install --no-index --no-deps --only-binary :all: --require-hashes --no-compile
#             --find-links /pkg --target /site/lib -r /pkg/hashes.txt         (pip re-checks every hash)
#   imports   python -I -S -B -c <site.addsitedir('/site/lib'); import each module>   (addsitedir runs .pth files)
#
# /site is its own tmpfs (rw,exec,nosuid,nodev,128 MiB): exec only there, so a wheel's native .so can be mapped;
# /tmp stays noexec (sandbox rule 2 deviation, see the notes, Step M2-10). Never an sdist, never setup.py.
#
#     WHEEL_NOT_VERIFIED    a node is not a verified wheel in the quarantine (or a name repeats)
#     WHEEL_HASH_MISMATCH   the quarantine file's bytes no longer have the tree's sha256
#     MODULES_UNKNOWN       no top-level module to import, a name that is not one, or one no staged wheel provides
#     otherwise             run_harness's result (never VERIFIED in Phase 2a)

SITE_TMPFS = "/site:rw,exec,nosuid,nodev,size=128m,mode=1777"
SITE_LIB = "/site/lib"
PKG_INSIDE = "/pkg"
HASH_FILE = "hashes.txt"
# pip builds a User-Agent for its HTTP session even with --no-index, which never sends one: its vendored `distro` execs
# `lsb_release -a` and `uname -rs` and stats every file in /etc (measured, pip 25.0.1, 2026-11-23). The install
# command replaces that builder with a constant, so the install step has no exec and no /etc scan. If a pip ever
# ignored the replacement, those events fall outside the install envelope (contract_check) -> UNRESOLVED.
PIP_VERSION = "25.0.1"  # the image's pip (Dockerfile checks it); the replacement is written for this version
PIP_CODE = ("import sys\nimport pip._internal.network.session as session\n"
            "session.user_agent = lambda: 'cavr-sandbox'\n"
            "from pip._internal.cli.main import main\nsys.exit(main(sys.argv[1:]))\n")
# --isolated: no pip.conf and no PIP_* variable is read, so the flags below are the whole configuration.
PIP_INSTALL = ["/usr/local/bin/python", "-I", "-B", "-c", PIP_CODE, "install", "--isolated", "--disable-pip-version-check",
               "--no-cache-dir", "--no-input", "--no-index", "--no-deps",
               "--only-binary", ":all:", "--require-hashes", "--no-compile", "--find-links", PKG_INSIDE, "--target", SITE_LIB,
               "-r", f"{PKG_INSIDE}/{HASH_FILE}"]
IMPORT_CODE = (f"import importlib, site, sys\nsite.addsitedir({SITE_LIB!r})\n"
               "for name in sys.argv[1:]:\n    importlib.import_module(name)\n")
# -B: no .pyc is written (-I ignores PYTHONDONTWRITEBYTECODE), so a clean import has no FILE_WRITE event.
IMPORT_ARGV = ["/usr/local/bin/python", "-I", "-S", "-B", "-c", IMPORT_CODE]
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+!_-]*$")


class NotStaged(Exception):
    def __init__(self, rule, reason):
        super().__init__(reason)
        self.rule, self.reason = rule, reason


def install_steps(modules) -> list[dict]:
    return [step("install", PIP_INSTALL),
            step("imports", IMPORT_ARGV + list(modules))]


def check_modules(modules) -> list[str]:
    names = list(modules) if isinstance(modules, (list, tuple)) else []  # a str would split into letters
    if not names or len(set(names)) != len(names) or not all(isinstance(m, str) and m.isidentifier() for m in names):
        raise NotStaged("MODULES_UNKNOWN", f"no usable top-level modules to import: {names!r}")
    return names


def stage_wheels(nodes, quarantine_dir, stage_dir) -> list[dict]:
    """Copy each verified wheel's checked bytes into `stage_dir` and write the hash file. Raises NotStaged."""
    quarantine = Path(quarantine_dir).resolve()
    staged, seen = [], set()
    for node in nodes or []:
        if not isinstance(node, dict):
            raise NotStaged("WHEEL_NOT_VERIFIED", f"a tree node is not a dict: {node!r}"[:200])
        name, version, filename, path, sha = (node.get(k) for k in ("name", "version", "filename", "path", "sha256"))
        label = f"{name} {version}"
        if not (isinstance(name, str) and _NAME.match(name) and isinstance(version, str) and _VERSION.match(version)):
            raise NotStaged("WHEEL_NOT_VERIFIED", f"node {label!r} has no usable name and version")
        if not (isinstance(filename, str) and filename.endswith(".whl") and "/" not in filename and "\\" not in filename):
            raise NotStaged("WHEEL_NOT_VERIFIED", f"{label}: {filename!r} is not a wheel file name (no sdist is ever installed)")
        if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{64}", sha)):
            raise NotStaged("WHEEL_NOT_VERIFIED", f"{label}: no verified sha256")
        key = re.sub(r"[-_.]+", "-", name).lower()
        if key in seen:
            raise NotStaged("WHEEL_NOT_VERIFIED", f"{name} appears twice in the tree")
        seen.add(key)
        source = Path(str(path)) if path else None
        if source is None or source.name != filename or source.is_symlink() or not source.is_file():
            raise NotStaged("WHEEL_NOT_VERIFIED", f"{label}: {path!r} is not the regular file {filename}")
        if not source.resolve().is_relative_to(quarantine):
            raise NotStaged("WHEEL_NOT_VERIFIED", f"{label}: {path} is not in CAVR's quarantine {quarantine}")
        data = source.read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if actual != sha:
            raise NotStaged("WHEEL_HASH_MISMATCH", f"{filename} in the quarantine has SHA-256 {actual}; the verified tree "
                            f"says {sha}; it was not mounted")
        target = Path(stage_dir) / filename
        target.write_bytes(data)
        os.chmod(target, 0o644)
        staged.append({"name": name, "version": version, "filename": filename, "sha256": sha, "size": len(data),
                       "top_level": top_level_names(data, filename)})
    if not staged:
        raise NotStaged("WHEEL_NOT_VERIFIED", "the tree has no wheel to install")
    (Path(stage_dir) / HASH_FILE).write_text("".join(f"{w['name']}=={w['version']} --hash=sha256:{w['sha256']}\n"
                                                     for w in staged), encoding="utf-8")
    os.chmod(Path(stage_dir) / HASH_FILE, 0o644)
    os.chmod(stage_dir, 0o755)
    return staged


def top_level_names(data: bytes, filename: str) -> list[str]:
    """Importable top-level names in a wheel's archive: `x/...` packages, `x.py` and `x.<tag>.so` modules."""
    import io
    import zipfile
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            entries = archive.namelist()
    except (zipfile.BadZipFile, ValueError) as exc:
        raise NotStaged("WHEEL_NOT_VERIFIED", f"{filename} is not a readable wheel: {exc}")
    names = set()
    for entry in entries:
        first, _, rest = entry.partition("/")
        if first.endswith((".dist-info", ".data")):
            continue
        if rest and (rest.endswith((".py", ".so")) or "/" in rest):
            names.add(first)
        elif not rest and first.endswith(".py"):
            names.add(first[:-3])
        elif not rest and first.endswith(".so"):
            names.add(first.split(".", 1)[0])
    return sorted(name for name in names if name.isidentifier())


def observe(nodes, modules, *, quarantine_dir=None, deadline: float = sandbox_exec.DEADLINE_SECONDS,
            run_id: str | None = None, n: int = 1) -> dict:
    """Install the verified tree and import `modules` in one sandbox run. Never raises; never VERIFIED."""
    try:
        if quarantine_dir is None:
            from backend.cavr.pipeline import default_quarantine_dir
            quarantine_dir = default_quarantine_dir()
        names = check_modules(modules)
        with tempfile.TemporaryDirectory(prefix="cavr-pkg-") as directory:
            staged = stage_wheels(nodes, quarantine_dir, directory)
            offered = {name for wheel in staged for name in wheel["top_level"]}
            if not set(names) <= offered:
                raise NotStaged("MODULES_UNKNOWN", f"{sorted(set(names) - offered)} are not top-level modules of the "
                                f"staged wheels ({sorted(offered)}); importing them would test nothing of the tree")
            hash_sha = hashlib.sha256((Path(directory) / HASH_FILE).read_bytes()).hexdigest()
            result = run_harness(install_steps(names), mounts=[(directory, PKG_INSIDE)], tmpfs=[SITE_TMPFS],
                                 deadline=deadline, run_id=run_id, n=n)
        result["evidence"].update({"wheels": staged, "modules": names, "hash_file_sha256": hash_sha,
                                   "install_target": SITE_LIB, "site_tmpfs": SITE_TMPFS})
        return result
    except NotStaged as exc:
        return _result(exc.rule, exc.reason, {"modules": modules if isinstance(modules, list) else None})
    except Exception as exc:
        return _result("INTERNAL_ERROR", f"the sandbox run failed: {type(exc).__name__}: {exc}", {})
