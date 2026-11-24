"""One sandbox run under a run spec, with canaries (PR 11 of docs/cavr-m2-plan.md). Fail closed; never a verdict.

`run_spec(nodes, modules, spec, contract=...)` runs the verified tree once in asent-cavr-sandbox under the spec of
`env_synthesis` (a trigger's spec, or `canary_spec()`):

    1. the wheels are checked and staged as for `sandbox_observe.observe` (same hash checks, mounted read-only at /pkg);
    2. the spec's files are written to a new host directory (mode 0700; the HOME inside it 0755, files 0644, so that
       UID 10001 can read them) and that HOME is mounted read-only at /tmp/home; the directory is removed after the
       run whatever happened (failure, timeout, exception), and the evidence says so (`home_removed`);
    3. two steps: `install` (the same pip command; HOME=/tmp/install-home, no canary in its environment) and
       `imports` (SPEC_IMPORT_CODE: sets sys.argv to the spec's argv, then imports the modules) with the spec's
       variables, libfaketime's when the spec has a clock (`env_synthesis.step_env`); with `drives` (PR 12) one
       more step per driven call site (`call_drive.DRIVE_ARGV`), with the imports step's variables;
    4. `docker run --hostname <spec hostname>`, strace STRACE_SPEC: the PR 9 command with `-s 65536` and the
       write-family syscalls, so every write, send and connect payload up to 64 KiB is in the trace (pip writes at
       most 65536 bytes per call, measured 2026-11-23); trace cap SPEC_STDERR_CAP (64 MiB);
    5. the trace is normalised with the spec's canaries (`sandbox_events.normalise(..., canaries=)`): a canary in a
       write, send or connect argument is a CANARY_EXFIL_ATTEMPT event, a payload strace cut is CANARY_UNCHECKED;
       with a contract the events are judged (`contract_check.judge`: a canary exfiltration is always a violation).

Result: {status: "UNRESOLVED" always, stage, rule (the run's: DEEP_NOT_JUDGED when it completed with a complete trace,
else the run rule), reason, evidence (spec with its canaries, container, trace SHA-256, hostname, home_removed, ...),
trace, output (untrusted), events, event_counts, canary {checked, exfil, unchecked}, judged}. Not connected to any
verdict (PR 12 does that).
"""
from __future__ import annotations

import json
import os
import posixpath
import shutil
import tempfile
from pathlib import Path

from backend.cavr import call_drive, contract_check, env_synthesis, sandbox_events, sandbox_observe

STRING_LIMIT = 65536
WRITE_SYSCALLS = ("write", "pwrite64", "writev", "pwritev", "pwritev2")
SPEC_STDERR_CAP = 64 * 1024 * 1024
HOME_INSIDE = "/tmp/home"
INSTALL_HOME = "/tmp/install-home"
SPEC_IMPORT_CODE = (f"import importlib, json, site, sys\njob = json.loads(sys.argv[1])\n"
                    f"site.addsitedir({sandbox_observe.SITE_LIB!r})\nsys.argv = job['argv']\n"
                    "for name in job['modules']:\n    importlib.import_module(name)\n")
SPEC_IMPORT_ARGV = ["/usr/local/bin/python", "-I", "-S", "-B", "-c", SPEC_IMPORT_CODE]


def spec_strace() -> list[str]:
    command = list(sandbox_observe.STRACE)
    command[command.index("-s") + 1] = str(STRING_LIMIT)
    at = command.index("-e") + 1
    command[at] = command[at] + "," + ",".join(WRITE_SYSCALLS)
    return command


STRACE_SPEC = spec_strace()


def spec_steps(spec, modules, machine=None, drives=()) -> list[dict]:
    """install, imports, and one step per drive of `call_drive.plan` (PR 12), with the imports step's environment."""
    job = json.dumps({"modules": list(modules), "argv": list(spec["argv"])})
    env = env_synthesis.step_env(spec, machine)
    steps = [sandbox_observe.step("install", sandbox_observe.PIP_INSTALL, {"HOME": INSTALL_HOME}),
             sandbox_observe.step("imports", SPEC_IMPORT_ARGV + [job], env)]
    for drive in drives or ():
        steps.append(sandbox_observe.step(drive["step"], call_drive.DRIVE_ARGV
                                          + [call_drive.drive_job(drive, modules, spec["argv"])], env))
    return steps


def write_home(spec, root: Path) -> Path:
    """The spec's files under `root`/home (0755 directories, 0644 files). `root` itself stays 0700."""
    home = root / "home"
    home.mkdir(mode=0o755)
    os.chmod(home, 0o755)
    for path, item in sorted(spec["files"].items()):
        relative = path[len(HOME_INSIDE) + 1:]
        if (posixpath.normpath(path) != path or not path.startswith(HOME_INSIDE + "/") or not relative
                or ".." in relative.split("/")):
            raise ValueError(f"{path!r} is not under {HOME_INSIDE}")
        target = home / relative
        for parent in reversed(target.relative_to(home).parents):
            directory = home / parent
            if not directory.exists():
                directory.mkdir()
                os.chmod(directory, 0o755)
        if item["kind"] == "dir":
            target.mkdir(exist_ok=True)
            os.chmod(target, 0o755)
        else:
            target.write_text(item["content"], encoding="utf-8")
            os.chmod(target, 0o644)
    return home


def run_spec(nodes, modules, spec, *, contract=None, quarantine_dir=None,
             deadline: float = 20.0, run_id: str | None = None, n: int = 1, machine=None, drives=()) -> dict:
    """Run the verified tree once under `spec`. Never raises; never a verdict."""
    home_root = None
    try:
        if quarantine_dir is None:
            from backend.cavr.pipeline import default_quarantine_dir
            quarantine_dir = default_quarantine_dir()
        names = sandbox_observe.check_modules(modules)
        steps = spec_steps(spec, names, machine, drives)
        with tempfile.TemporaryDirectory(prefix="cavr-pkg-") as stage:
            staged = sandbox_observe.stage_wheels(nodes, quarantine_dir, stage)
            offered = {name for wheel in staged for name in wheel["top_level"]}
            if not set(names) <= offered:
                raise sandbox_observe.NotStaged("MODULES_UNKNOWN", f"{sorted(set(names) - offered)} are not top-level "
                                                f"modules of the staged wheels ({sorted(offered)})")
            home_root = Path(tempfile.mkdtemp(prefix="cavr-home-"))  # mode 0700
            home = write_home(spec, home_root)
            result = sandbox_observe.run_harness(steps, mounts=[(stage, sandbox_observe.PKG_INSIDE), (home, HOME_INSIDE)],
                                                 tmpfs=[sandbox_observe.SITE_TMPFS], deadline=deadline,
                                                 stderr_cap=SPEC_STDERR_CAP, run_id=run_id, n=n, strace=STRACE_SPEC,
                                                 hostname=spec["hostname"])
        result["evidence"].update({"wheels": staged, "modules": names, "spec": spec, "home_host": str(home_root),
                                   "drives": [drive["step"] for drive in drives or ()]})
    except sandbox_observe.NotStaged as exc:
        result = sandbox_observe._result(exc.rule, exc.reason, {"modules": modules if isinstance(modules, list) else None,
                                                                "spec": spec})
    except Exception as exc:
        result = sandbox_observe._result("INTERNAL_ERROR", f"the spec run failed: {type(exc).__name__}: {exc}",
                                         {"spec": spec})
    finally:
        removed = _remove(home_root)
    result["stage"] = "deep-spec"
    result["evidence"]["home_removed"] = removed
    if not removed:
        result.update(rule="SPEC_HOME_LEFT_BEHIND", reason=f"the fake HOME {home_root} could not be removed")
    return _read(result, spec, contract)


def _remove(root) -> bool:
    if root is None:
        return True
    shutil.rmtree(root, ignore_errors=True)
    return not Path(root).exists()


def _read(result, spec, contract) -> dict:
    evidence = result["evidence"]
    events, counts = [], {}
    if evidence.get("trace_attributable") and evidence.get("processes"):
        found = sandbox_events.normalise(result.get("trace") or "", evidence["processes"], evidence.get("step_pids"),
                                         evidence.get("job_steps"), canaries=spec.get("canaries") or [])
        events, counts = found["events"], found["counts"]
    exfil = [e for e in events if e["type"] == "CANARY_EXFIL_ATTEMPT"]
    unchecked = [e for e in events if e["type"] == "CANARY_UNCHECKED"]
    result.update({"events": events, "event_counts": counts,
                   "canary": {"checked": sum(1 for e in events if e.get("canary_checked")), "exfil": exfil,
                              "unchecked": unchecked},
                   "judged": contract_check.judge(events, contract) if contract is not None and events else None})
    return result
