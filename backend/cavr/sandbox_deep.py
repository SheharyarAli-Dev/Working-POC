"""The deep stage for escalated packages: the counterfactual activation loop (PRs 9 and 12 of docs/cavr-m2-plan.md).

`SandboxDeepAnalyzer` is the Phase 1 deep-analyzer interface (`deep_stage`) on top of PRs 3-11:

    version    cavr-sandbox-deep/2 plus the SHA-256 of the harness, the seccomp profile, the spec strace command, the
               step commands (pip, import, drive), the docker lockdown flags, the versions of the event normaliser,
               the contract check, the trigger frontier, the environment synthesis, the loop and the drive plan, and
               the source of every module that decides the verdict (VERDICT_CODE)
    image_id   the checked image ID (`sandbox_image.image_identity`)
    budget     {"runs": 8, "run_seconds": 20, "package_seconds": 120, "gate_run_seconds": 300} (Q8)

`deep_stage.identity` puts all three into `analyzer_version`, so a new image, harness, profile, strace command,
frontier, loop or budget is a cache miss. One analyzer lives for one gate run (`for_gate_run`): the 300 s cap.

`analyse(package)` for one escalated package:

    1. the gate run's deep time used up (300 s)              -> UNRESOLVED DEEP_RUN_BUDGET_USED_UP, nothing run
    2. the empty-harness baseline (D2), recorded once per identity with the spec run's strace and imports step
       (no module); one that cannot be produced or is not clean -> UNRESOLVED (its rule)
    3. the trigger frontier of the verified tree (`trigger_frontier.frontier`, PR 10)
    4. the drive plan (`call_drive.plan`): the project's call sites that pass only literals
    5. the loop (`activation_loop.explore`): the canary-only run, then one run per distinct trigger activation, each
       run = install, imports, the drive steps (`sandbox_spec.run_spec`, PR 11); events minus the baseline, judged
       against the contract (`contract_check.judge`)

Verdict (Q8, Maryam 2026-11-22 and 2026-11-24), first match wins:

    1. any event outside the contract in any run (also one that did not finish, D6)     -> REJECTED DEEP_CONTRACT_VIOLATION
    2. no run could start, or a run did not complete / its trace is not complete       -> UNRESOLVED (that run's rule)
    3. an event of any run could not be judged                                        -> UNRESOLVED (the judge's rule)
    4. `frontier_residual(frontier, explored)` does not allow VERIFIED: the frontier is missing, malformed,
       incomplete or truncated, an entry (any risk) is unsimulable, or a simulable entry was not explored  -> UNRESOLVED
       (its rule; DEEP_RUN_BUDGET_EXHAUSTED when entries were never run because the budget ended; D1: kept as strict
       as PR 10 wrote it)
    5. an `other_guards` entry in front of a high-risk sink, and no completed run showed that sink -> UNRESOLVED
       DEEP_GUARD_UNEXPLORED
    6. no escalation reason / one that no completed run exercised                      -> UNRESOLVED DEEP_ESCALATION_UNKNOWN
                                                                                          / DEEP_SINK_NOT_EXERCISED
    7. otherwise                                                                       -> VERIFIED DEEP_RUN_CLEAN

A high-risk entry is one whose sink the contract does not grant, so a run that shows it is a violation: a package with
a high-risk entry is REJECTED (explored) or UNRESOLVED (not explored), never VERIFIED.

An escalation reason (a reachable sink the contract does not grant without a scope limit) is exercised when

    - the call is module-level code and a completed run's imports step has an event of its capability, or
    - the call is inside a function or lambda and a completed run's drive step has an event of its capability that
      the same run's imports step does not have (what the driven call did beyond the import),

and (D3) it is the only reachable sink of that capability in the tree: strace cannot say which Python line made an
event, so an event cannot stand for one of two sinks that share a capability.

What VERIFIED claims (NFR-6): in the canary-only environment and in the synthesized environment of every trigger of
the frontier, installing the verified wheels, importing them and calling the project's literal-only call sites did
nothing outside the contract, every trigger was explored and every escalation reason exercised. Call sites with
computed arguments, method calls on returned objects and anything outside the scanned source are not exercised;
`evidence["not_exercised"]` lists them.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from backend.cavr import (activation_loop, call_drive, contract_check, env_synthesis, sandbox_events, sandbox_exec,
                          sandbox_image, sandbox_observe, sandbox_spec, trigger_frontier)
from backend.orchestrator.hashing import digest
from backend.threat_repo.behavior_rules import normalize_name

VERSION = "cavr-sandbox-deep/2"
BUDGET = {"runs": 8, "run_seconds": 20, "package_seconds": 120, "gate_run_seconds": 300}
MIN_RUN_SECONDS = activation_loop.MIN_RUN_SECONDS  # below this a run cannot even start Python; nothing is started
KEY_EVENTS = 5
CLAIM = ("the counterfactual activation loop: a canary-only run, then one run per distinct trigger activation of the "
         "frontier; in each run the verified wheels were installed offline, imported, and the project's call sites "
         "that pass only literals were called")
CLOCK = time.monotonic
NOW = None  # tests replace it (the frontier's analysis time); None means now
RUN_SPEC = None  # tests replace it; None means sandbox_spec.run_spec
RUN_HARNESS = None  # tests replace it; None means sandbox_observe.run_harness (the baseline run)

# The source files whose code decides a deep verdict: a change to any of them is a new identity, so no verdict cached
# by older code is reused (review of PRs 7-9; the version strings alone would need a manual bump).
VERDICT_CODE = ("sandbox_deep.py", "sandbox_events.py", "contract_check.py", "sandbox_trace.py", "sandbox_observe.py",
                "sandbox_exec.py", "trigger_frontier.py", "env_synthesis.py", "sandbox_spec.py", "activation_loop.py",
                "call_drive.py")
RESIDUAL_RULES = ("FRONTIER_MISSING", "FRONTIER_MALFORMED", "FRONTIER_INCOMPLETE", "FRONTIER_TRUNCATED",
                  "TRIGGER_UNSIMULABLE", "TRIGGER_UNEXPLORED", "DEEP_RUN_BUDGET_EXHAUSTED")


def deep_version(identity: dict) -> str:
    here = Path(__file__).resolve().parent
    code = hashlib.sha256(b"".join(f"{name}\0".encode() + (_sha256(here / name) or "missing").encode()
                                   for name in VERDICT_CODE)).hexdigest()
    parts = {"harness": _sha256(sandbox_observe.HARNESS), "profile": identity.get("seccomp_sha256"),
             "strace": digest(sandbox_spec.STRACE_SPEC),
             "steps": digest([sandbox_observe.PIP_INSTALL, sandbox_spec.SPEC_IMPORT_ARGV, call_drive.DRIVE_ARGV]),
             "flags": digest([sandbox_exec.lockdown_flags(), sandbox_observe.SITE_TMPFS]),
             "events": sandbox_events.EVENTS_VERSION, "check": contract_check.CHECK_VERSION,
             "frontier": trigger_frontier.VERSION, "synthesis": env_synthesis.VERSION, "loop": activation_loop.VERSION,
             "drive": call_drive.VERSION, "code": code}
    return VERSION + "".join(f";{key}:{value}" for key, value in parts.items())


def for_gate_run(data_root, quarantine_dir=None):
    """(analyzer or None, {enabled, rule, reason}). None (no Docker, no image, image mismatch) keeps today's verdicts."""
    try:
        identity = sandbox_image.image_identity()
    except Exception as exc:
        identity = {"ok": False, "rule": "ENGINE_ERROR", "reason": f"{type(exc).__name__}: {exc}"}
    if not identity.get("ok"):
        return None, {"enabled": False, "rule": identity.get("rule"), "reason": f"deep stage off: {identity.get('reason')}"}
    root = Path(data_root)
    analyzer = SandboxDeepAnalyzer(identity, quarantine_dir or root / "quarantine", root / "deep")
    return analyzer, {"enabled": True, "rule": identity.get("rule"), "reason": f"deep stage on: {identity.get('reason')}",
                      "version": analyzer.version, "image_id": analyzer.image_id, "budget": analyzer.budget}


class SandboxDeepAnalyzer:
    def __init__(self, identity: dict, quarantine_dir, baseline_dir, budget=None):
        self.identity_record = dict(identity)
        self.image_id = identity.get("image_id")
        self.version = deep_version(identity)
        self.budget = dict(budget or BUDGET)
        self.quarantine_dir = Path(quarantine_dir)
        self.baseline_dir = Path(baseline_dir)
        self.spent = 0.0  # seconds of sandbox time in this gate run (baseline + package runs)
        self.last = None  # the last package's loop result, with its events (PR 13 builds the graph from it)
        self._baseline = None
        self._baseline_problem = None

    @property
    def baseline_identity(self) -> str:
        return f"{self.version};image:{self.image_id}"

    def left(self) -> float:
        return self.budget["gate_run_seconds"] - self.spent

    def analyse(self, package: dict) -> dict:
        name = f"{package.get('name')} {package.get('version')}"
        evidence = {"claim": CLAIM, "not_exercised": [], "image_id": self.image_id, "deep_version": self.version,
                    "budget": self.budget, "gate_run_seconds_used_before": round(self.spent, 3)}
        if self.left() < MIN_RUN_SECONDS:
            return _answer("UNRESOLVED", "DEEP_RUN_BUDGET_USED_UP", f"the deep budget of this gate run "
                           f"({self.budget['gate_run_seconds']} s) is used up; {name} was not run", evidence)
        baseline, problem = self.baseline()
        evidence["baseline"] = {"rule": problem[0] if problem else "BASELINE_OK",
                                "sha256": baseline and baseline.get("sha256"), "events": baseline and baseline.get("event_count")}
        if problem:
            return _answer("UNRESOLVED", problem[0], f"{problem[1]}; {name} was not judged", evidence)
        started = CLOCK()
        contract = package.get("contract") or {}
        nodes = (package.get("tree") or {}).get("nodes")
        modules = contract.get("import_names")
        found = trigger_frontier.frontier(nodes, contract, now=NOW() if NOW else None)
        drives = call_drive.plan(package)
        run_id = sandbox_exec.new_run_id()

        def run(spec, deadline, n):
            begun = CLOCK()
            try:
                result = (RUN_SPEC or sandbox_spec.run_spec)(nodes, modules, spec, quarantine_dir=self.quarantine_dir,
                                                             deadline=deadline, run_id=run_id, n=n,
                                                             drives=drives["drives"])
            finally:
                self.spent += CLOCK() - begun
            return activation_loop.read_run(result, n=n, baseline=baseline, contract=contract, image_id=self.image_id)

        loop = activation_loop.explore(found, run, budget=self.budget, clock=CLOCK, gate_left=self.left,
                                       synthesize=env_synthesis.synthesize, canary_spec=env_synthesis.canary_spec,
                                       started=started)
        self.last = {"package": name, "frontier": found, "drives": drives, "loop": loop}
        return self._verdict(package, found, drives, loop, evidence)

    def _verdict(self, package, found, drives, loop, evidence) -> dict:
        name = f"{package.get('name')} {package.get('version')}"
        runs = loop["runs"]
        evidence.update(_loop_evidence(found, drives, loop))
        violating = next((r for r in runs if (r.get("judged") or {}).get("result") == "VIOLATION"), None)
        incomplete = next((r for r in runs if not r["completed"]), None)
        decisive = violating or incomplete or (runs[0] if runs else None)
        if decisive:
            evidence.update(_run_evidence(decisive))
        if violating:
            return _answer("REJECTED", "DEEP_CONTRACT_VIOLATION", f"{name}: {_which(violating)}: "
                           f"{violating['judged']['reason']}", evidence)
        if not runs:
            return _answer("UNRESOLVED", "DEEP_RUN_BUDGET_USED_UP", f"{name}: no run could be started: "
                           f"{loop['stop_reason']}", evidence)
        if incomplete:
            return _answer("UNRESOLVED", incomplete["rule"] or "SANDBOX_ENGINE_ERROR", f"{name}: {_which(incomplete)} "
                           f"did not complete: {incomplete['reason']}", evidence)
        unjudged = next((r for r in runs if r["judged"]["result"] != "OK"), None)
        if unjudged:
            evidence.update(_run_evidence(unjudged))
            return _answer("UNRESOLVED", unjudged["judged"]["rule"], f"{name}: {_which(unjudged)}: "
                           f"{unjudged['judged']['reason']}", evidence)
        residual = trigger_frontier.frontier_residual(found, loop["explored"])
        outcomes = {o["id"]: o for o in loop["outcomes"]}
        evidence["residual"] = {**residual, "entries": [outcomes[i] for i in residual["unsimulable"] + residual["unexplored"]
                                                        if i in outcomes]}
        if not residual["verified_possible"]:
            rule = residual["rule"]
            never = [i for i in residual["unexplored"] if outcomes.get(i, {}).get("stopped_by") in ("runs", "seconds")]
            if rule == "TRIGGER_UNEXPLORED" and never:
                rule = "DEEP_RUN_BUDGET_EXHAUSTED"
            first = next(iter(evidence["residual"]["entries"]), None)
            detail = (f"; first: {first['package']} {first['file']}:{first['line']} `{first['predicate']}` "
                      f"({first['risk']} risk): {first['outcome']}") if first and rule != "TRIGGER_UNSIMULABLE" else ""
            evidence["residual"]["rule"] = rule
            return _answer("UNRESOLVED", rule, f"{name}: the runs were clean, but {residual['reason']}{detail}", evidence)
        guards = unexplored_guards(found, runs)
        evidence["unexplored_guards"] = guards
        if guards:
            first = guards[0]
            return _answer("UNRESOLVED", "DEEP_GUARD_UNEXPLORED", f"{name}: the runs were clean, but {len(guards)} "
                           f"guard(s) CAVR cannot evaluate stand in front of a sink the contract does not grant, and no "
                           f"run showed that sink; first: {first['package']} {first['file']}:{first['line']} "
                           f"`{first['predicate']}` gates {', '.join(first['capabilities'])}", evidence)
        reasons = escalation_reasons(package, runs, drives)
        evidence["escalation_reasons"] = reasons
        if not reasons:
            return _answer("UNRESOLVED", "DEEP_ESCALATION_UNKNOWN", f"{name}: the fast gate's escalation names no "
                           "reachable sink, so the runs cannot show that they covered the reason", evidence)
        missed = [reason for reason in reasons if not reason["exercised"]]
        if missed:
            first = missed[0]
            sites = ", ".join(first["call_sites"][:3]) or "no recorded call site"
            return _answer("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED", f"{name}: the runs were clean, but {len(missed)} of "
                           f"{len(reasons)} escalation reason(s) were not exercised: {first['package']} "
                           f"{first['file']}:{first['line']} calls {first['sink']} ({first['capability']}), reachable "
                           f"from the project's call sites {sites}; {first['why']}", evidence)
        counter = sum(1 for r in runs if r["kind"] == activation_loop.COUNTERFACTUAL)
        entries = len((found or {}).get("entries") or [])
        return _answer("VERIFIED", "DEEP_RUN_CLEAN", f"{name}: {len(runs)} run(s) (canary-only + {counter} counterfactual), "
                       f"{len(drives['drives'])} call site(s) driven; every trigger of the frontier ({entries}) explored "
                       f"and every escalation reason ({len(reasons)}) exercised; nothing outside the contract", evidence)

    def baseline(self):
        """(baseline, None) or (None, (rule, reason)). Recorded once per identity; refused unless clean (D2)."""
        if self._baseline is not None or self._baseline_problem is not None:
            return self._baseline, self._baseline_problem
        path = self.baseline_dir / f"baseline-{hashlib.sha256(self.baseline_identity.encode()).hexdigest()[:24]}.json"
        record = None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            record = self._record_baseline(path)
        if isinstance(record, tuple):
            self._baseline_problem = record
            return None, record
        usable, rule, reason = sandbox_events.check_baseline(record, self.baseline_identity)
        if not usable:
            self._baseline_problem = (rule, reason)
            return None, self._baseline_problem
        self._baseline = record
        return record, None

    def _record_baseline(self, path):
        """The spec runs' imports step with no module, under the canary-only spec's variables and the spec strace."""
        spec = env_synthesis.canary_spec()
        job = json.dumps({"modules": [], "argv": spec["argv"]})
        steps = [sandbox_observe.step("imports", sandbox_spec.SPEC_IMPORT_ARGV + [job], env_synthesis.step_env(spec))]
        deadline = min(self.budget["run_seconds"], self.left())
        started = CLOCK()
        try:
            run = (RUN_HARNESS or sandbox_observe.run_harness)(steps, tmpfs=[sandbox_observe.SITE_TMPFS], deadline=deadline,
                                                               strace=sandbox_spec.STRACE_SPEC)
        finally:
            self.spent += CLOCK() - started
        observed = run.get("evidence") or {}
        if run.get("rule") != "DEEP_NOT_JUDGED" or observed.get("image_id") != self.image_id:
            return ("BASELINE_UNAVAILABLE", f"the empty-harness baseline run did not complete: {run.get('rule')}: "
                                            f"{run.get('reason')}")
        found = sandbox_events.normalise(run.get("trace") or "", observed["processes"], observed["step_pids"],
                                         observed["job_steps"])
        record = sandbox_events.make_baseline(self.baseline_identity, found)
        record.update({"sha256": observed.get("trace_sha256"), "event_count": len(found["events"]),
                       "recorded_by": observed.get("container")})
        usable, rule, reason = sandbox_events.check_baseline(record, self.baseline_identity)
        if not usable:
            return rule, reason  # never stored: the next gate run records it again
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(".tmp")
            temporary.write_text(json.dumps(record), encoding="utf-8")
            os.replace(temporary, path)
        except OSError:
            pass  # not stored: still used for this gate run
        return record


def escalation_reasons(package: dict, runs: list, drives: dict) -> list[dict]:
    """Each reachable denied sink that escalated the package, and whether a completed run exercised it (see above)."""
    sinks = [s for s in ((package.get("reachability") or {}).get("sinks") or []) if s.get("verdict") == "REACHABLE"]
    wheels = {node.get("name"): node.get("path") for node in (package.get("tree") or {}).get("nodes") or []}
    completed = [r for r in runs or [] if r.get("completed")]
    shared = {}
    for sink in sinks:
        capability = normalize_name(sink.get("capability"))
        shared[capability] = shared.get(capability, 0) + 1
    contract = package.get("contract") or {}
    call_sites = [f"{site.get('file')}:{site.get('line')} {site.get('expression') or site.get('symbol') or ''}".rstrip()
                  for site in contract.get("call_sites") or []]
    driven = drives.get("drives") or []
    reasons = []
    for sink in sinks:
        capability = normalize_name(sink.get("capability"))
        placement = sink_placement(wheels.get(sink.get("package")), sink.get("file"), sink.get("line"), sink.get("sink"))
        hits = []
        if placement == "module level":
            for record in completed:
                count = sum(1 for e in record["events"] if e.get("step") == activation_loop.IMPORTS
                            and capability in activation_loop.event_capabilities(e))
                if count:
                    hits.append({"run": record["n"], "step": activation_loop.IMPORTS, "events": count})
        elif placement.startswith(("function ", "a lambda")):
            for record in completed:
                for drive in driven:
                    count = sum(1 for e in activation_loop.drive_events(record, drive["step"])
                                if capability in activation_loop.event_capabilities(e))
                    if count:
                        hits.append({"run": record["n"], "step": drive["step"], "events": count,
                                     "call": call_drive.describe(drive)})
        observed = sum(hit["events"] for hit in hits)
        exercised = bool(hits) and shared[capability] == 1
        reasons.append({"package": sink.get("package"), "file": sink.get("file"), "line": sink.get("line"),
                        "sink": sink.get("sink"), "capability": capability, "placement": placement,
                        "events_of_capability": observed, "exercised": exercised, "exercised_by": hits,
                        "why": _why(placement, capability, hits, shared[capability], drives), "call_sites": call_sites})
    return reasons


def _why(placement, capability, hits, shared, drives) -> str:
    if hits and shared > 1:
        return (f"{shared} reachable sinks share {capability}, and strace cannot say which Python line made an event, "
                f"so the {sum(h['events'] for h in hits)} {capability} event(s) cannot stand for this one (D3)")
    if hits:
        where = ", ".join(f"run {h['run']} {h['step']}" + (f" ({h['call']})" if h.get("call") else "") for h in hits[:3])
        return f"{placement}; {sum(h['events'] for h in hits)} {capability} event(s) in {where}, all within the contract"
    if placement == "module level":
        return f"the call is module-level code, but no completed run's import step has a {capability} event (it did not run)"
    if not placement.startswith(("function ", "a lambda")):
        return f"the call is in {placement}"
    driven = drives.get("drives") or []
    if driven:
        calls = ", ".join(call_drive.describe(d) for d in driven[:3])
        return (f"the call is in {placement}, which an import does not run; the driven call site(s) {calls} showed no "
                f"{capability} event beyond their import")
    refused = (drives.get("not_driven") or [{}])[0]
    why = f"{refused.get('call') or refused.get('expression')} at {refused.get('file')}:{refused.get('line')}: " \
          f"{refused.get('why')}" if refused else "no call site of the package was recorded"
    return f"the call is in {placement}, which an import does not run, and no call site could be driven ({why})"


def unexplored_guards(found, runs) -> list[dict]:
    """`other_guards` in front of a high-risk sink whose capability no completed run showed (outside the install step)."""
    seen = set()
    for record in runs or []:
        if record.get("completed"):
            for event in record["events"]:
                if event.get("step") != activation_loop.INSTALL:
                    seen.update(activation_loop.event_capabilities(event))
    out = []
    for guard in (found or {}).get("other_guards") or []:
        capabilities = activation_loop.sink_capabilities(guard)
        if guard.get("risk") == "high" and not capabilities & seen:
            out.append({"id": guard.get("id"), "package": guard.get("package"), "file": guard.get("file"),
                        "line": guard.get("line"), "predicate": guard.get("predicate"), "capabilities": sorted(capabilities)})
    return out


def sink_placement(wheel_path, file, line, sink) -> str:
    """"module level", "function <name>" / "a lambda", or "an unknown place" for the sink call at file:line of the wheel."""
    import ast
    import zipfile
    try:
        with zipfile.ZipFile(wheel_path) as archive:
            tree = ast.parse(archive.read(file))
    except Exception:
        return "an unknown place (the wheel's source could not be read)"
    found = []

    def visit(node, scope):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            scope = f"function {node.name}"
        elif isinstance(node, ast.Lambda):
            scope = "a lambda"
        if isinstance(node, ast.Call) and node.lineno == line:
            found.append((ast.unparse(node.func) == sink, scope))
        for child in ast.iter_child_nodes(node):
            visit(child, scope)
    visit(tree, None)
    exact = [scope for match, scope in found if match] or [scope for _, scope in found]
    if not exact:
        return "an unknown place (no call at that line)"
    inner = next((scope for scope in exact if scope), None)
    return inner or "module level"


def _loop_evidence(found, drives, loop) -> dict:
    """What the loop did, without the events themselves (they stay in memory for the verdict and the graph)."""
    runs = [{key: record.get(key) for key in ("n", "kind", "spec_id", "entries", "activation", "rule", "completed",
                                              "container", "trace_sha256", "trace_lines", "trace_check", "elapsed_seconds",
                                              "deadline_seconds", "home_removed")}
            | {"judged": _judged(record.get("judged")), "new_events": len(record.get("new_events") or [])}
            for record in loop["runs"]]
    frontier = {key: (found or {}).get(key) for key in ("version", "ok", "rule", "reason", "now", "total", "dropped",
                                                         "other_guards_count")}
    not_exercised = [f"trigger {o['file']}:{o['line']} `{o['predicate']}`: {o['outcome']}" for o in loop["outcomes"]
                     if o["outcome"] != "explored"]
    not_exercised += [f"call site {d.get('file')}:{d.get('line')} {d.get('call') or d.get('expression')}: {d.get('why')}"
                      for d in drives.get("not_driven") or []]
    return {"frontier": frontier, "triggers": loop["outcomes"], "runs": runs,
            "drives": {"version": drives.get("version"), "driven": [{key: d.get(key) for key in
                                                                     ("step", "file", "line", "symbol", "call")}
                                                                    for d in drives.get("drives") or []],
                       "not_driven": drives.get("not_driven") or []},
            "loop": {key: loop[key] for key in ("version", "stop", "stop_reason", "planned_runs", "budget_used",
                                                "activation_rate", "new_sensitive_events")},
            "not_exercised": not_exercised}


def _run_evidence(record) -> dict:
    """The run a verdict rests on: its trace identity, its events summary and key events (the PR 9 evidence keys)."""
    judged = record.get("judged")
    out = {"run_rule": record.get("rule"), "run_reason": record.get("reason"), "decisive_run": record.get("n"),
           "container": record.get("container"), "elapsed_seconds": record.get("elapsed_seconds"),
           "trace_sha256": record.get("trace_sha256"), "trace_lines": record.get("trace_lines"),
           "trace_check": record.get("trace_check"), "output": record.get("output")}
    if judged:
        out["events"] = {"counts": record.get("event_counts"), "after_baseline": len(record["events"]),
                         "judged": judged["judged"], "install_events": judged["install_events"]}
        out["check"] = _judged(judged)
        out["key_events"] = [_key_event(item, record) for item in (judged["violations"] or judged["unresolved"])[:KEY_EVENTS]]
    return out


def _judged(judged):
    if not judged:
        return None
    return {key: judged.get(key) for key in ("result", "rule", "reason", "violation_count", "unresolved_count",
                                              "not_exercised", "used")}


def _which(record) -> str:
    label = "the canary-only run" if record.get("kind") == activation_loop.CANARY_ONLY else f"the counterfactual run " \
            f"{record.get('spec_id')}"
    return f"run {record.get('n')} ({label})"


def _key_event(item: dict, record: dict) -> dict:
    event = item["event"]
    return {"rule": item["rule"], "capability": item.get("capability"), "why": item["why"], "type": event.get("type"),
            "syscall": event.get("syscall"), "step": event.get("step"), "path": event.get("path"),
            "address": event.get("address"), "argv": event.get("argv"), "ok": event.get("ok"), "errno": event.get("errno"),
            "line": event.get("line"), "run": record.get("n"), "run_kind": record.get("kind")}


def _answer(status, rule, reason, evidence) -> dict:
    return {"status": status, "rule": rule, "reason": reason, "evidence": evidence}


def _sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None
