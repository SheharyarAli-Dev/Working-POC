"""The budgeted counterfactual activation loop (PR 12 of docs/cavr-m2-plan.md, FR-4, design §6.4). Pure; fail closed.

`explore(frontier, run, ...)` decides which sandbox runs an escalated package gets, in which order, and what each run
showed. It never starts a container itself: `run(spec, deadline, n)` does (in `sandbox_deep`, `sandbox_spec.run_spec`
with the drive steps of `call_drive`), and `read_run` turns its result into a run record.

Order (Q8 budget: at most `runs` sandbox runs per package, `run_seconds` each, `package_seconds` for the package,
what is left of the gate run's `gate_run_seconds`):

    1. the canary-only run (`env_synthesis.canary_spec()`), always first: the reference every counterfactual
       difference is taken against, and the run that checks the entries the baseline takes (`baseline_takes_it`);
    2. one run per distinct activation of the simulable frontier entries, in frontier order (high risk first, then
       score); entries with the same activation share the run.

Every run has the same steps (install, imports, the drive steps), so a trigger inside a function the project calls
is seen under its spec. The loop stops early at the first run with a violation (also a run that did not finish,
D6), when the canary-only run did not complete (nothing could be compared with it), or when the budget ends: no run
is started with less than MIN_RUN_SECONDS of deadline, and OVERHEAD_SECONDS of the package's time is kept for staging,
writing the fake HOME and normalising.

An entry is explored only when a completed run (its trace complete, on the expected image) showed every sink
capability the entry gates:

    - a counterfactual run: events of those capabilities are in that run and not in the canary-only run (multiset
      difference of `sandbox_events.event_key`, install step left out): the trigger made the difference;
    - the canary-only run, for an entry the baseline takes: it has such events outside the install step.

`baseline_takes_it` is a prediction and never evidence. There is no "newly seen predicate" feedback (decision D4):
strace cannot show a predicate, so the frontier is computed once, from all the scanned source.
"""
from __future__ import annotations

import json
from collections import Counter

from backend.cavr import contract_check, sandbox_events
from backend.threat_repo.behavior_rules import normalize_name

VERSION = "cavr-activation-loop/1"
MIN_RUN_SECONDS = 2.0
OVERHEAD_SECONDS = 3.0
COMPLETE = "DEEP_NOT_JUDGED"  # sandbox_observe's rule for a run that completed with a complete trace
INSTALL = "install"
IMPORTS = "imports"
CANARY_ONLY = "canary-only"
COUNTERFACTUAL = "counterfactual"
STOPS = {"runs": "the budget of {runs} sandbox runs for this package is used up",
         "seconds": "the time left (package {package_seconds} s / gate run {gate_run_seconds} s) is too short for a run",
         "violation": "the loop stopped at the first run with a violation",
         "canary": "the canary-only run did not complete, so no run could be compared with it"}


def explore(frontier, run, *, budget, clock, gate_left, synthesize, canary_spec, started=None) -> dict:
    """{version, runs, explored, outcomes, stop, stop_reason, budget_used, activation_rate}. Never raises on bad input.

    `started` is when the package's analysis began (the frontier scan counts against its time); default now."""
    started = clock() if started is None else started
    entries = [e for e in (frontier or {}).get("entries") or [] if isinstance(e, dict) and isinstance(e.get("id"), str)]
    outcomes = {e["id"]: _outcome(e) for e in entries}
    plan = [{"kind": CANARY_ONLY, "spec": canary_spec(), "entries": []}]
    groups = {}
    for entry in entries:
        ident = entry["id"]
        if entry.get("simulable") is not True:
            outcomes[ident]["outcome"] = f"not run: unsimulable ({entry.get('unsimulable_reason')})"
            continue
        if entry.get("baseline_takes_it"):
            plan[0]["entries"].append(ident)
            continue
        key = json.dumps(entry.get("activation"), sort_keys=True)
        if key in groups:
            groups[key]["entries"].append(ident)
            continue
        built = synthesize(entry)
        if not built.get("ok"):
            outcomes[ident]["outcome"] = f"not run: the spec was refused ({built.get('rule')}: {built.get('reason')})"
            continue
        groups[key] = {"kind": COUNTERFACTUAL, "spec": built["spec"], "entries": [ident]}
        plan.append(groups[key])

    runs, stop = [], "done"
    for item in plan:
        if len(runs) >= budget["runs"]:
            stop = "runs"
            break
        deadline = min(budget["run_seconds"], budget["package_seconds"] - (clock() - started) - OVERHEAD_SECONDS,
                       gate_left())
        if deadline < MIN_RUN_SECONDS:
            stop = "seconds"
            break
        record = run(item["spec"], deadline, len(runs) + 1)
        record.update({"kind": item["kind"], "spec_id": item["spec"].get("id"), "entries": list(item["entries"]),
                       "activation": item["spec"].get("activation"), "deadline_seconds": round(deadline, 3),
                       "canary_ids": [c.get("id") for c in item["spec"].get("canaries") or []]})  # ids, never values
        runs.append(record)
        if (record.get("judged") or {}).get("result") == "VIOLATION":
            stop = "violation"
            break
        if item["kind"] == CANARY_ONLY and not record["completed"]:
            stop = "canary"
            break
    for item in plan[len(runs):]:
        for ident in item["entries"]:
            outcomes[ident].update(outcome=f"not run: {STOPS[stop].format(**budget)}", stopped_by=stop)

    reference = runs[0] if runs and runs[0]["kind"] == CANARY_ONLY and runs[0]["completed"] else None
    by_id = {e["id"]: e for e in entries}
    explored = []
    for record in runs:
        record["new_events"] = new_events(record, reference) if record["kind"] == COUNTERFACTUAL and reference else []
        for ident in record["entries"]:
            outcome = outcomes[ident]
            outcome["run"] = record["n"]
            if not record["completed"]:
                outcome["outcome"] = f"ran in run {record['n']}, which did not complete ({record['rule']})"
                continue
            capabilities = sink_capabilities(by_id[ident])
            pool = (record["new_events"] if record["kind"] == COUNTERFACTUAL
                    else [e for e in record["events"] if e.get("step") != INSTALL])
            shown = [e for e in pool if capabilities & set(event_capabilities(e))]
            shown_capabilities = {c for e in shown for c in event_capabilities(e)} & capabilities
            missing = sorted(capabilities - shown_capabilities)
            if shown and not missing:
                explored.append(ident)
                outcome.update(outcome="explored", shown_by=_short(shown[0]))
            elif shown:
                # Every sink the entry gates must be shown (review of Phase 3b, MAJOR 1): a branch whose read ran but
                # whose connect did not has not shown what the connect would do.
                outcome["outcome"] = (f"ran in run {record['n']}; it showed {', '.join(sorted(shown_capabilities))} but "
                                      f"not {', '.join(missing)} (not every sink of the branch was shown)")
            elif record["kind"] == COUNTERFACTUAL:
                outcome["outcome"] = (f"ran in run {record['n']}; no event of {', '.join(sorted(capabilities))} "
                                      "that the canary-only run does not have (the sink was not shown)")
            else:
                outcome["outcome"] = (f"taken by the baseline, but the canary-only run (run {record['n']}) has no "
                                      f"event of {', '.join(sorted(capabilities))} (the sink was not shown)")
    simulable = sum(1 for e in entries if e.get("simulable") is True)
    return {"version": VERSION, "runs": runs, "explored": explored, "outcomes": [outcomes[e["id"]] for e in entries],
            "stop": stop, "stop_reason": STOPS[stop].format(**budget) if stop in STOPS else "every planned run was made",
            "planned_runs": len(plan),
            "budget_used": {"runs": len(runs), "runs_limit": budget["runs"], "seconds": round(clock() - started, 3),
                            "package_seconds": budget["package_seconds"]},
            "activation_rate": {"explored": len(explored), "simulable": simulable,
                                "rate": round(len(explored) / simulable, 3) if simulable else None},
            "new_sensitive_events": {str(r["n"]): len(r["new_events"]) for r in runs if r["kind"] == COUNTERFACTUAL}}


def read_run(result: dict, *, n: int, baseline, contract, image_id) -> dict:
    """The record of one `sandbox_spec.run_spec` result: events after the baseline, judged against the contract."""
    result = result if isinstance(result, dict) else {"rule": "DEEP_NO_RESULT", "reason": "the run gave no result"}
    observed = (result or {}).get("evidence") or {}
    record = {"n": n, "rule": result.get("rule"), "reason": result.get("reason"), "container": observed.get("container"),
              "image_id": observed.get("image_id"), "elapsed_seconds": observed.get("elapsed_seconds"),
              "trace_sha256": observed.get("trace_sha256"), "trace_lines": observed.get("trace_lines"),
              "trace_check": observed.get("trace_check"), "home_removed": observed.get("home_removed"),
              "steps": observed.get("steps"), "output": result.get("output"), "events": [], "judged": None,
              "completed": False}
    ran = observed.get("trace_attributable") or observed.get("container")
    if (ran and observed.get("image_id") != image_id) or observed.get("image_id") not in (None, image_id):
        record.update(rule="DEEP_IMAGE_CHANGED", reason=f"the run used image {observed.get('image_id')}, not "
                      f"{image_id} (the identity in the cache key)")
        return record
    if observed.get("trace_attributable") and observed.get("processes"):
        events = result.get("events") or []
        record["events"] = sandbox_events.subtract_baseline(events, baseline) if baseline else list(events)
        record["judged"] = contract_check.judge(record["events"], contract)
        record["event_counts"] = result.get("event_counts")
    record["completed"] = record["rule"] == COMPLETE and record["judged"] is not None
    if record["rule"] == COMPLETE and record["judged"] is None:
        record.update(rule="TRACE_INCOMPLETE", reason="the trace could not be attributed")
    return record


def new_events(record: dict, reference: dict) -> list[dict]:
    """Events of `record` (install step left out) that the reference run does not have, by key and count."""
    left = Counter(sandbox_events.event_key(e) for e in reference["events"] if e.get("step") != INSTALL)
    out = []
    for event in record["events"]:
        if event.get("step") == INSTALL:
            continue
        key = sandbox_events.event_key(event)
        if left[key] > 0:
            left[key] -= 1
            continue
        out.append(event)
    return out


def drive_events(record: dict, step: str) -> list[dict]:
    """Events of one drive step that the same run's imports step does not have (keys without the step name)."""
    left = Counter(sandbox_events.event_key(e)[1:] for e in record["events"] if e.get("step") == IMPORTS)
    out = []
    for event in record["events"]:
        if event.get("step") != step:
            continue
        key = sandbox_events.event_key(event)[1:]
        if left[key] > 0:
            left[key] -= 1
            continue
        out.append(event)
    return out


def event_capabilities(event: dict) -> list[str]:
    kind, capabilities = contract_check.capability_of(event)
    return capabilities if kind in ("capability", "never") else []


def sink_capabilities(item: dict) -> set:
    return {normalize_name(sink.get("capability")) for sink in item.get("sinks") or [] if sink.get("capability")}


def _outcome(entry: dict) -> dict:
    return {"id": entry["id"], "package": entry.get("package"), "file": entry.get("file"), "line": entry.get("line"),
            "predicate": entry.get("predicate"), "risk": entry.get("risk"), "simulable": entry.get("simulable"),
            "baseline_takes_it": entry.get("baseline_takes_it"), "activation": entry.get("activation"),
            "capabilities": sorted(sink_capabilities(entry)), "run": None, "outcome": None}


def _short(event: dict) -> dict:
    return {key: event.get(key) for key in ("type", "syscall", "step", "path", "address", "argv", "ok", "errno", "line")}
