"""One observed sandbox run: harness + strace in asent-cavr-sandbox (PR 5 of docs/cavr-m2-plan.md). Fail closed.

`run_harness(steps, ...)` checks the image (`sandbox_image.image_identity`), writes the job file, starts

    strace -f -q --always-show-pid -s 1024 -e trace=%file,%network,%process,%creds -u cavr --
        /usr/local/bin/python -I -S /opt/cavr/harness.py /job/job.json

as the container's process (root, with only SYS_PTRACE, SETUID, SETGID and no-new-privileges, Q5), keeps the
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
    INTERNAL_ERROR                anything that raised
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from pathlib import Path

from backend.cavr import sandbox_exec, sandbox_image
from backend.cavr.sandbox_trace import check_trace

HARNESS = Path(__file__).resolve().with_name("sandbox_harness.py")
HARNESS_INSIDE = "/opt/cavr/harness.py"
JOB_INSIDE = "/job"
STRACE = ["strace", "-f", "-q", "--always-show-pid", "-s", "1024", "-e", "trace=%file,%network,%process,%creds",
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
                stderr_cap: int = sandbox_exec.STDERR_CAP, run_id: str | None = None, n: int = 1) -> dict:
    """{status, stage, rule, reason, evidence, trace, output}. Never raises; never VERIFIED."""
    try:
        return _run(list(steps), mounts, tmpfs, deadline, stderr_cap, run_id or sandbox_exec.new_run_id(), n)
    except Exception as exc:
        return _result("INTERNAL_ERROR", f"the sandbox run failed: {type(exc).__name__}: {exc}", {})


def _run(steps, mounts, tmpfs, deadline, stderr_cap, run_id, n) -> dict:
    identity = (IDENTITY or sandbox_image.image_identity)()
    evidence = {"image": identity.get("image"), "image_id": identity.get("image_id"), "image_check": identity.get("rule"),
                "seccomp_sha256": identity.get("seccomp_sha256"), "harness_sha256": _sha256(HARNESS),
                "strace": STRACE, "deadline_seconds": deadline}
    if not identity.get("ok"):
        return _result(identity.get("rule") or "ENGINE_ERROR", f"no isolation: {identity.get('reason')}; "
                       "the package was not run", evidence)
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
        cmd = sandbox_exec.docker_command(name, identity["image_id"], STRACE,
                                          mounts=[(HARNESS, HARNESS_INSIDE), (job_dir, JOB_INSIDE), *mounts],
                                          env={NONCE_VARIABLE: nonce}, tmpfs=tmpfs)
        run = (RUN or sandbox_exec.run_container)(cmd, name, deadline=deadline, stderr_cap=stderr_cap)
    evidence.update({"container": name, "run_status": run["status"], "exit_code": run["exit_code"],
                     "elapsed_seconds": run["elapsed_seconds"], "lockdown_flags": sandbox_exec.lockdown_flags(),
                     "extra_tmpfs": list(tmpfs), "steps": [s["name"] for s in job["steps"]],
                     "trace_sha256": hashlib.sha256(run["stderr"]).hexdigest(), "trace_bytes": len(run["stderr"])})
    output = {"text": run["stdout_text"][:OUTPUT_SHOWN], "bytes": len(run["stdout"]), "trusted": False}
    trace_text = run["stderr_text"]
    if run["status"] != "COMPLETED":
        return _result(RUN_RULES.get(run["status"], "SANDBOX_ENGINE_ERROR"), run["reason"], evidence, trace_text, output)
    if run["exit_code"] != 0:
        return _result("SANDBOX_EXIT_NONZERO", f"the harness exited with {run['exit_code']} (a step failed or the run "
                       "was cut short)", evidence, trace_text, output)
    checked = check_trace(run["stderr"], nonce, evidence["steps"])
    evidence.update({"trace_check": checked["rule"], "trace_reason": checked["reason"], "trace_lines": checked["lines"],
                     "root_pid": checked["root_pid"], "processes": checked["processes"], "step_pids": checked["steps"]})
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
