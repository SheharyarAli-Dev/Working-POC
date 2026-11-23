"""The deep stage for escalated packages: one observed install + import run (PR 9 of docs/cavr-m2-plan.md). Fail closed.

`SandboxDeepAnalyzer` is the Phase 1 deep-analyzer interface (`deep_stage`) on top of PRs 3-8:

    version    cavr-sandbox-deep/1 plus the SHA-256 of the harness, the seccomp profile, the strace command, the two
               step commands (pip, import), the event normaliser's and the contract check's versions
    image_id   the checked image ID (`sandbox_image.image_identity`)
    budget     {"runs": 1, "run_seconds": 20, "package_seconds": 120, "gate_run_seconds": 300}

`deep_stage.identity` puts all three into `analyzer_version`, so a new image, harness, profile, strace command or
budget is a cache miss. One analyzer lives for one gate run (`for_gate_run`), which is what the 300 s cap counts.

`analyse(package)` for one escalated package:

    1. the gate run's deep time used up (300 s)          -> UNRESOLVED DEEP_RUN_BUDGET_USED_UP, nothing run
    2. the empty-harness baseline (D2): read from the data directory, or recorded once by one run with the same
       image, harness, profile and strace; one that cannot be produced or is not clean -> UNRESOLVED (its rule)
    3. one `sandbox_observe.observe` run of the verified tree, importing the wheel's import names (deadline: 20 s,
       cut to what is left of the package's 120 s and the run's 300 s)
    4. the trace's events (`sandbox_events.normalise`) minus the baseline, judged against the package's contract
       (`contract_check.judge`)

Verdict (Q8):

    any event outside the contract (also from a run that did not end well, D6)    -> REJECTED DEEP_CONTRACT_VIOLATION
    the run did not complete, the trace is not complete, an event cannot be judged -> UNRESOLVED (the rule says which)
    a gated branch in the scanned code reaches a sink the contract does not grant
      without a scope limit (a high-risk trigger the frontier of Phase 3 has not
      explored)                                                                    -> UNRESOLVED DEEP_TRIGGERS_UNEXPLORED
    otherwise                                                                      -> VERIFIED DEEP_RUN_CLEAN

What VERIFIED claims (NFR-6): installing the verified wheels and importing them, in the baseline environment, did
nothing outside the contract. The project's own call sites are not executed, and no counterfactual run is made.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

from backend.cavr import contract_check, sandbox_events, sandbox_image, sandbox_observe
from backend.orchestrator.hashing import digest
from backend.threat_repo.behavior_rules import normalize_name

VERSION = "cavr-sandbox-deep/1"
BUDGET = {"runs": 1, "run_seconds": 20, "package_seconds": 120, "gate_run_seconds": 300}
MIN_RUN_SECONDS = 2.0  # below this a run cannot even start Python; the package is not run
KEY_EVENTS = 5
CLAIM = ("one observed run: the verified wheels were installed offline and their top-level modules imported in the "
         "baseline environment; the project's call sites were not executed and no gated branch was explored")
NOT_EXERCISED = ["the project's call sites", "counterfactual environments (Phase 3)"]
CLOCK = time.monotonic
OBSERVE = None  # tests replace it; None means sandbox_observe.observe
RUN_HARNESS = None  # tests replace it; None means sandbox_observe.run_harness


def deep_version(identity: dict) -> str:
    parts = {"harness": _sha256(sandbox_observe.HARNESS), "profile": identity.get("seccomp_sha256"),
             "strace": digest(sandbox_observe.STRACE), "steps": digest([sandbox_observe.PIP_INSTALL, sandbox_observe.IMPORT_ARGV]),
             "events": sandbox_events.EVENTS_VERSION, "check": contract_check.CHECK_VERSION}
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
        self._baseline = None
        self._baseline_problem = None

    @property
    def baseline_identity(self) -> str:
        return f"{self.version};image:{self.image_id}"

    def left(self) -> float:
        return self.budget["gate_run_seconds"] - self.spent

    def analyse(self, package: dict) -> dict:
        name = f"{package.get('name')} {package.get('version')}"
        evidence = {"claim": CLAIM, "not_exercised": list(NOT_EXERCISED), "image_id": self.image_id,
                    "deep_version": self.version, "budget": self.budget, "gate_run_seconds_used_before": round(self.spent, 3)}
        if self.left() < MIN_RUN_SECONDS:
            return _answer("UNRESOLVED", "DEEP_RUN_BUDGET_USED_UP", f"the deep budget of this gate run "
                           f"({self.budget['gate_run_seconds']} s) is used up; {name} was not run", evidence)
        baseline, problem = self.baseline()
        evidence["baseline"] = {"rule": problem[0] if problem else "BASELINE_OK",
                                "sha256": baseline and baseline.get("sha256"), "events": baseline and baseline.get("event_count")}
        if problem:
            return _answer("UNRESOLVED", problem[0], f"{problem[1]}; {name} was not judged", evidence)
        deadline = min(self.budget["run_seconds"], self.budget["package_seconds"], self.left())
        if deadline < MIN_RUN_SECONDS:
            return _answer("UNRESOLVED", "DEEP_RUN_BUDGET_USED_UP", f"only {self.left():.1f} s of this gate run's deep "
                           f"budget is left; {name} was not run", evidence)
        contract = package.get("contract") or {}
        modules = contract.get("import_names")
        started = CLOCK()
        try:
            run = (OBSERVE or sandbox_observe.observe)(package.get("tree", {}).get("nodes"), modules,
                                                       quarantine_dir=self.quarantine_dir, deadline=deadline)
        finally:
            self.spent += CLOCK() - started
        return self._verdict(package, run, baseline, deadline, evidence)

    def _verdict(self, package, run, baseline, deadline, evidence) -> dict:
        name = f"{package.get('name')} {package.get('version')}"
        observed = run.get("evidence") or {}
        evidence.update({"run_rule": run.get("rule"), "run_reason": run.get("reason"), "deadline_seconds": deadline,
                         "container": observed.get("container"), "elapsed_seconds": observed.get("elapsed_seconds"),
                         "trace_sha256": observed.get("trace_sha256"), "trace_lines": observed.get("trace_lines"),
                         "trace_check": observed.get("trace_check"), "modules": observed.get("modules"),
                         "wheels": [{k: w.get(k) for k in ("name", "version", "sha256")} for w in observed.get("wheels") or []],
                         "output": run.get("output")})
        judged = None
        if observed.get("image_id") not in (None, self.image_id):
            return _answer("UNRESOLVED", "DEEP_IMAGE_CHANGED", f"{name}: the run used image {observed.get('image_id')}, "
                           f"not {self.image_id} (the identity in the cache key)", evidence)
        if observed.get("trace_attributable") and observed.get("processes"):
            found = sandbox_events.normalise(run.get("trace") or "", observed["processes"], observed.get("step_pids"),
                                             observed.get("job_steps"))
            left = sandbox_events.subtract_baseline(found["events"], baseline)
            judged = contract_check.judge(left, package.get("contract"))
            evidence["events"] = {"counts": found["counts"], "after_baseline": len(left), "judged": judged["judged"],
                                  "install_events": judged["install_events"]}
            evidence["check"] = {key: judged[key] for key in ("result", "rule", "reason", "violation_count",
                                                              "unresolved_count", "not_exercised", "used")}
            evidence["key_events"] = [_key_event(item) for item in (judged["violations"] or judged["unresolved"])[:KEY_EVENTS]]
            evidence["not_exercised"] += [f"required {cap} (not used in this run)" for cap in judged["not_exercised"]]
            if judged["result"] == "VIOLATION":
                return _answer("REJECTED", "DEEP_CONTRACT_VIOLATION", f"{name}: {judged['reason']}", evidence)
        if run.get("rule") != "DEEP_NOT_JUDGED":
            return _answer("UNRESOLVED", run.get("rule") or "SANDBOX_ENGINE_ERROR",
                           f"{name}: the sandbox run did not complete: {run.get('reason')}", evidence)
        if judged is None:
            return _answer("UNRESOLVED", "TRACE_INCOMPLETE", f"{name}: the trace could not be attributed", evidence)
        if judged["result"] != "OK":
            return _answer("UNRESOLVED", judged["rule"], f"{name}: {judged['reason']}", evidence)
        triggers = high_risk_triggers(package.get("scan") or [], package.get("contract") or {})
        evidence["unexplored_triggers"] = triggers
        if triggers:
            first = triggers[0]
            return _answer("UNRESOLVED", "DEEP_TRIGGERS_UNEXPLORED", f"{name}: the run was clean, but {len(triggers)} "
                           f"gated branch(es) reach a sink the contract does not grant, and no run explored them (Phase 3); "
                           f"first: {first['package']} {first['file']}:{first['line']} `{first['predicate']}` gates "
                           f"{', '.join(first['capabilities'])}", evidence)
        return _answer("VERIFIED", "DEEP_RUN_CLEAN", f"{name}: {CLAIM}; {judged['reason']}", evidence)

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
        steps = [sandbox_observe.step("imports", sandbox_observe.IMPORT_ARGV)]
        deadline = min(self.budget["run_seconds"], self.left())
        started = CLOCK()
        try:
            run = (RUN_HARNESS or sandbox_observe.run_harness)(steps, tmpfs=[sandbox_observe.SITE_TMPFS], deadline=deadline)
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


def high_risk_triggers(scans, contract) -> list[dict]:
    """Gated branches of the scanned wheels that reach a sink whose capability the contract does not grant with "*"."""
    unrestricted = {entry.get("capability") for entry in contract.get("allowed") or [] if entry.get("scope") == "*"}
    found = []
    for scan in scans:
        for trigger in scan.get("triggers") or []:
            capabilities = sorted({normalize_name(sink.get("capability")) for sink in trigger.get("reachable_sinks") or []}
                                  - unrestricted)
            if capabilities:
                found.append({"package": scan.get("package"), "file": trigger.get("file"), "line": trigger.get("line"),
                              "predicate": trigger.get("predicate"), "types": trigger.get("types") or [],
                              "capabilities": capabilities})
    return sorted(found, key=lambda t: (str(t["package"]), str(t["file"]), t["line"] or 0))


def _key_event(item: dict) -> dict:
    event = item["event"]
    return {"rule": item["rule"], "capability": item.get("capability"), "why": item["why"], "type": event.get("type"),
            "syscall": event.get("syscall"), "step": event.get("step"), "path": event.get("path"),
            "address": event.get("address"), "argv": event.get("argv"), "ok": event.get("ok"), "errno": event.get("errno"),
            "line": event.get("line")}


def _answer(status, rule, reason, evidence) -> dict:
    return {"status": status, "rule": rule, "reason": reason, "evidence": evidence}


def _sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError:
        return None
