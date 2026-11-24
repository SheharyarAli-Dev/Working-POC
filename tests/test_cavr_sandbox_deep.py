"""PRs 9 and 12 of docs/cavr-m2-plan.md: escalated packages get the counterfactual activation loop (`sandbox_deep`).

Unit tests run the real pipeline (`test_cavr_support.World`), the real frontier, loop, normaliser and contract check;
only the container is replaced: `sandbox_deep.RUN_SPEC` / `RUN_HARNESS` return a real trace recorded on Docker
(`tests/test_cavr_data/traces/events-*.txt`) as the observed run. Docker tests (CAVR_DOCKER=1) build the demo wheels in
`tmp_path` and run them in asent-cavr-sandbox:local, through `verify_request` and through `asent gate`.
"""
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest

from backend.cavr import (activation_loop, call_drive, causal_graph, contract_check, deep_stage, env_synthesis, gate_adapter, sandbox_deep,
                          sandbox_events, sandbox_exec, sandbox_image, sandbox_observe, sandbox_spec, trigger_frontier)
from backend.cavr.pipeline import ESCALATION, analyzer_version
from backend.cavr.sandbox_trace import check_trace
from backend.commands.report import cavr_deep, render
from gate_support import DISABLED, GateRepo, POLICY, config, invoice_app_files, run_cli
from test_cavr_support import (FakeIndex, PIN_VERSION, RECORDED_6_21_4, USES_DEMO, World, build_wheel, cavr_containers,
                               requires_docker, sandbox_identity, write_osv_cache)

TRACES = Path(__file__).parent / "test_cavr_data" / "traces"
IMAGE = "sha256:" + "c" * 64
IDENTITY = {"ok": True, "rule": "IMAGE_OK", "reason": "test image", "image_id": IMAGE, "seccomp_sha256": "d" * 64}

NETWORK_SINK = "import socket\n\n\ndef send(data):\n    socket.create_connection(('example.invalid', 443))\n"
BENIGN = {"demo/__init__.py": "from .net import send\n\n\ndef run():\n    return 1\n", "demo/net.py": NETWORK_SINK}
TRIGGERED = {"demo/__init__.py": "import os\nimport socket\n\nif os.getenv('CAVR_DEMO_TRIGGER'):\n"
                                 "    socket.create_connection(('198.51.100.24', 443))\n\n\ndef run():\n    return 1\n"}
# PR 12: the same branch behind a variable the frontier can set (`CAVR_*` names are fixed by the sandbox, so the
# trigger of TRIGGERED is unsimulable, PR 10).
TRIGGERED_CI = {"demo/__init__.py": "import os\nimport socket\n\nif os.environ.get('CI') == 'true':\n"
                                    "    try:\n        socket.create_connection(('198.51.100.24', 443), timeout=1)\n"
                                    "    except OSError:\n        pass\n\n\ndef run():\n    return 1\n"}
# Escalated only by import-time code: the module-level connect runs when the package is imported, to the one endpoint
# the policy grants (the same code as the recording events-scoped).
IMPORT_TIME = {"demo/__init__.py": "import socket\n\ntry:\n    socket.create_connection(('198.51.100.24', 443), timeout=1)\n"
                                   "except OSError:\n    pass\n\n\ndef run():\n    return 1\n"}
SCOPED_POLICY = {"project_task_description": "Billing dashboard", "allowed_scopes": ["NETWORK_CONNECT:198.51.100.24:443"]}


def recorded_run(stem, rule="DEEP_NOT_JUDGED", cut=None):
    """A sandbox_observe result made of a recorded trace (cut to `cut` of its length for an unfinished run)."""
    meta = json.loads((TRACES / f"{stem}.json").read_text())
    trace = (TRACES / f"{stem}.txt").read_text()
    if cut:
        trace = trace[:int(len(trace) * cut)]
    steps = [step["name"] for step in meta["steps"]]
    checked = check_trace(trace.encode(), meta["nonce"], steps, partial=rule != "DEEP_NOT_JUDGED")
    return {"status": "UNRESOLVED", "stage": "deep", "rule": rule, "reason": f"recorded {stem}", "trace": trace,
            "output": {"text": "", "bytes": 0, "trusted": False},
            "evidence": {"image_id": IMAGE, "container": "cavr-000000000000-1", "elapsed_seconds": 4.0,
                         "trace_sha256": meta["trace_sha256"], "trace_lines": checked["lines"],
                         "trace_check": checked["rule"], "trace_attributable": checked["attributable"],
                         "processes": checked["processes"], "step_pids": checked["steps"], "job_steps": meta["steps"],
                         "modules": ["demo"], "wheels": []}}


class Sandbox:
    """Replaces the container: each spec run returns `runs[i]` (the last one again once they are used up), normalised
    as `sandbox_spec.run_spec` does it (with that run's canaries), and advances the clock by `seconds` per run."""

    def __init__(self, monkeypatch, runs, seconds=5.0, baseline="events-baseline", baseline_seconds=2.0):
        self.runs, self.seconds, self.now, self.calls, self.deadlines = list(runs), seconds, 1000.0, [], []
        self.baseline_seconds = baseline_seconds
        self.baseline_runs = 0
        monkeypatch.setattr(sandbox_deep, "CLOCK", lambda: self.now)
        monkeypatch.setattr(deep_stage, "CLOCK", lambda: self.now)
        monkeypatch.setattr(sandbox_deep, "RUN_SPEC", self.run_spec)
        monkeypatch.setattr(sandbox_deep, "RUN_HARNESS", self.harness)
        self.baseline = baseline

    def run_spec(self, nodes, modules, spec, quarantine_dir=None, deadline=None, run_id=None, n=1, drives=()):
        self.calls.append({"nodes": nodes, "modules": modules, "spec": spec, "n": n, "drives": list(drives)})
        self.deadlines.append(deadline)
        self.now += self.seconds
        run = self.runs.pop(0) if len(self.runs) > 1 else self.runs[0]
        run = copy.deepcopy(run(spec) if callable(run) else run)
        return sandbox_spec._read(run, spec, None)

    def harness(self, steps, tmpfs=(), deadline=None, **options):
        self.baseline_runs += 1
        self.now += self.baseline_seconds
        if isinstance(self.baseline, dict):
            return self.baseline
        return recorded_run(self.baseline)


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def analyzer(tmp_path, identity=IDENTITY, budget=None):
    return sandbox_deep.SandboxDeepAnalyzer(identity, tmp_path / "quarantine", tmp_path / "deep", budget=budget)


def escalated(world, files=BENIGN):
    world.add("demo", "1.0", files)
    world.write("app/uses_demo.py", USES_DEMO)


def verify(world, deep):
    verdict = world.verify("pip install demo==1.0", deep=deep)
    (package,) = verdict["packages"]
    return verdict, package


# --- one test per clause of the Q8 rule ----------------------------------------------------------------------------------

def test_a_reachable_sink_the_import_never_ran_is_unresolved_not_exercised(world, tmp_path, monkeypatch):
    """Maryam, 2026-11-23: the escalation is a sink only the project's call sites reach; an import cannot clear it."""
    escalated(world)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")])
    verdict, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["stage"], package["rule"]) == ("UNRESOLVED", "deep", "DEEP_SINK_NOT_EXERCISED")
    assert verdict["status"] == "UNRESOLVED"
    assert "demo/net.py:5 calls socket.create_connection (NETWORK_CONNECT)" in package["reason"]
    assert "app/uses_demo.py:5 demo.run" in package["reason"]
    # PR 12: the project's call site demo.run() has only literals (none), so it was driven; it never reaches send().
    assert ("the driven call site(s) demo.run() at app/uses_demo.py:5 showed no NETWORK_CONNECT event beyond their "
            "import") in package["reason"]
    assert [d["call"] for d in sandbox.calls[0]["drives"]] == ["demo.run()"] and sandbox.calls[0]["spec"]["id"] == "spec-canaries"
    deep = package["evidence"]["deep"]["evidence"]
    (reason,) = deep["escalation_reasons"]
    assert (reason["placement"], reason["exercised"], reason["events_of_capability"]) == ("function send", False, 0)
    assert deep["check"]["rule"] == "EVENTS_WITHIN_CONTRACT" and deep["baseline"]["rule"] == "BASELINE_OK"
    assert sandbox.calls[0]["modules"] == ["demo"] and sandbox.baseline_runs == 1 and world.cache_rows() == []


def test_an_import_time_sink_inside_a_scoped_contract_is_verified(world, tmp_path, monkeypatch):
    world.policy.update(SCOPED_POLICY)
    escalated(world, IMPORT_TIME)
    Sandbox(monkeypatch, [recorded_run("events-scoped")])
    verdict, package = verify(world, analyzer(tmp_path))
    assert package["evidence"]["reachability"]["sinks"][0]["verdict"] == "REACHABLE"  # escalated: a scoped grant
    assert (package["status"], package["stage"], package["rule"]) == ("VERIFIED", "deep", "DEEP_RUN_CLEAN"), package["reason"]
    assert verdict["status"] == "VERIFIED" and package["escalation"] != ESCALATION
    deep = package["evidence"]["deep"]["evidence"]
    (reason,) = deep["escalation_reasons"]
    assert (reason["placement"], reason["exercised"], reason["events_of_capability"]) == ("module level", True, 1)
    assert deep["check"]["used"] == ["NETWORK_CONNECT"] and "every escalation reason (1) exercised" in package["reason"]
    assert deep["claim"] == sandbox_deep.CLAIM and [d["call"] for d in deep["drives"]["driven"]] == ["demo.run()"]  # NFR-6
    assert [r["kind"] for r in deep["runs"]] == ["canary-only"] and deep["loop"]["stop"] == "done"


def test_a_module_level_sink_that_shows_no_event_is_not_exercised(world, tmp_path, monkeypatch):
    world.policy.update(SCOPED_POLICY)
    escalated(world, IMPORT_TIME)
    Sandbox(monkeypatch, [recorded_run("events-benign")])  # a run in which nothing connected
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED")
    (reason,) = package["evidence"]["deep"]["evidence"]["escalation_reasons"]
    assert (reason["placement"], reason["exercised"]) == ("module level", False) and "did not run" in reason["why"]


def test_an_escalation_without_a_reachable_sink_is_unresolved(tmp_path, monkeypatch):
    from backend.cavr.capability_contract import vocabulary
    Sandbox(monkeypatch, [recorded_run("events-benign")])
    contract = {"result": "OK", "import_names": ["demo"], "allowed": [], "vocabulary": vocabulary(),
                "denied": [{"capability": name} for name in vocabulary()]}
    wheel = build_wheel(tmp_path / "quarantine", "demo", "1.0", files={"demo/__init__.py": "def run():\n    return 1\n"})
    node = {"name": "demo", "version": "1.0", "filename": wheel.name, "path": str(wheel),
            "sha256": hashlib.sha256(wheel.read_bytes()).hexdigest()}
    answer = analyzer(tmp_path).analyse({"name": "demo", "version": "1.0", "contract": contract, "scan": [],
                                         "tree": {"nodes": [node]}, "reachability": {"sinks": []}})
    assert (answer["status"], answer["rule"]) == ("UNRESOLVED", "DEEP_ESCALATION_UNKNOWN")
    # With no wheel at all the frontier has nothing to scan, which is a reason left before any other (PR 12).
    empty = analyzer(tmp_path).analyse({"name": "demo", "version": "1.0", "contract": contract, "scan": [],
                                        "tree": {"nodes": []}, "reachability": {"sinks": []}})
    assert (empty["status"], empty["rule"]) == ("UNRESOLVED", "FRONTIER_INCOMPLETE")


# --- PR 12: driving the project's call sites (recordings loop-drive-send / loop-drive-quiet) -------------------------

SEND_FILES = {"demo/__init__.py": "from .net import send\n\n\ndef run():\n    return 1\n",
              "demo/net.py": "import socket\n\n\ndef send(data):\n    try:\n        socket.create_connection("
                             "('198.51.100.24', 443), timeout=1)\n    except OSError:\n        pass\n"}


def driven(world, call="demo.send('x')", files=SEND_FILES):
    world.add("demo", "1.0", files)
    world.write("app/uses_demo.py", f"import demo\n\n\ndef go():\n    return {call}\n")


def test_a_driven_call_that_connects_outside_the_contract_is_rejected(world, tmp_path, monkeypatch):
    driven(world)
    sandbox = Sandbox(monkeypatch, [recorded_run("loop-drive-send")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("REJECTED", "DEEP_CONTRACT_VIOLATION"), package["reason"]
    deep = package["evidence"]["deep"]["evidence"]
    key = deep["key_events"][0]
    assert (key["step"], key["capability"], key["address"]["host"]) == ("drive_1", "NETWORK_CONNECT", "198.51.100.24")
    assert [d["call"] for d in sandbox.calls[0]["drives"]] == ["demo.send('x')"]


def test_a_driven_call_inside_its_scope_exercises_the_sink_and_is_verified(world, tmp_path, monkeypatch):
    world.policy.update(SCOPED_POLICY)
    driven(world)
    Sandbox(monkeypatch, [recorded_run("loop-drive-send")])
    verdict, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("VERIFIED", "DEEP_RUN_CLEAN"), package["reason"]
    (reason,) = package["evidence"]["deep"]["evidence"]["escalation_reasons"]
    assert (reason["placement"], reason["exercised"]) == ("function send", True)
    assert reason["exercised_by"] == [{"run": 1, "step": "drive_1", "events": 1, "call": "demo.send('x') at app/uses_demo.py:5"}]
    assert "1 call site(s) driven" in package["reason"] and verdict["status"] == "VERIFIED"


def test_a_driven_call_that_never_reaches_the_sink_leaves_it_not_exercised(world, tmp_path, monkeypatch):
    world.policy.update(SCOPED_POLICY)
    driven(world, call="demo.run()")
    Sandbox(monkeypatch, [recorded_run("loop-drive-quiet")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED"), package["reason"]
    assert "demo.run() at app/uses_demo.py:5 showed no NETWORK_CONNECT event" in package["reason"]


def test_a_call_with_a_computed_argument_is_not_driven_and_says_why(world, tmp_path, monkeypatch):
    world.policy.update(SCOPED_POLICY)
    driven(world, call="demo.send(data)")
    sandbox = Sandbox(monkeypatch, [recorded_run("loop-drive-quiet")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED"), package["reason"]
    assert "no call site could be driven (demo.send(data) at app/uses_demo.py:5: argument 1 `data` is not a literal)" \
        in package["reason"]
    assert sandbox.calls[0]["drives"] == []
    deep = package["evidence"]["deep"]["evidence"]
    assert any("argument 1 `data` is not a literal" in item for item in deep["not_exercised"])  # NFR-6


def test_two_reachable_sinks_of_one_capability_cannot_be_told_apart_by_an_event(world, tmp_path, monkeypatch):
    """D3 (Maryam, 2026-11-24): strace cannot say which Python line made an event."""
    world.policy.update(SCOPED_POLICY)
    two = {**SEND_FILES, "demo/net.py": SEND_FILES["demo/net.py"] + "\n\ndef other():\n    socket.create_connection(('198.51.100.24', 443))\n"}
    driven(world, files=two)
    Sandbox(monkeypatch, [recorded_run("loop-drive-send")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_SINK_NOT_EXERCISED"), package["reason"]
    reasons = package["evidence"]["deep"]["evidence"]["escalation_reasons"]
    assert len(reasons) == 2 and not any(r["exercised"] for r in reasons)
    assert all("2 reachable sinks share NETWORK_CONNECT" in r["why"] and "(D3)" in r["why"] for r in reasons)


def test_a_fresh_baseline_counts_against_the_package_budget(world, tmp_path, monkeypatch):
    """Review of Phase 3b, BLOCKER 2: the baseline this package records first is inside its 120 s (deep_stage's clock)."""
    world.policy.update(SCOPED_POLICY)
    eight = {"demo/__init__.py": "import os, socket\n" + "".join(
        f"if os.environ.get('DEPLOY_{i}') == 'yes':\n    socket.create_connection(('198.51.100.24', 443))\n"
        for i in range(1, 9)) + "\n\ndef run():\n    return 1\n"}
    escalated(world, eight)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")], seconds=16.0, baseline_seconds=20.0)
    _, package = verify(world, analyzer(tmp_path))
    assert package["rule"] == "DEEP_RUN_BUDGET_EXHAUSTED", package["reason"]  # was DEEP_BUDGET_EXCEEDED (137 s)
    assert package["evidence"]["deep"]["elapsed_seconds"] <= 120 and sandbox.baseline_runs == 1
    assert sandbox.deadlines[0] == 20 and min(sandbox.deadlines) >= sandbox_deep.MIN_RUN_SECONDS


def test_a_refused_credential_reaches_no_verdict_field(world, tmp_path, monkeypatch):
    """Review of Phase 3b, BLOCKER 1: not in the drive plan, the reasons, not_exercised or anything else of the verdict."""
    token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
    driven(world, call=f"demo.send('{token}')")
    Sandbox(monkeypatch, [recorded_run("loop-drive-quiet")])
    verdict, package = verify(world, analyzer(tmp_path))
    assert package["rule"] == "DEEP_SINK_NOT_EXERCISED" and token not in json.dumps(verdict, default=str)


def test_sink_placement_reads_the_wheel(tmp_path):
    source = "\n".join(["import os", "os.system('x')", "", "", "def f():", "    os.system('y')", "", "",
                        "g = lambda: os.system('z')", "class C:", "    def m(self):", "        os.system('w')", ""])
    wheel = build_wheel(tmp_path, "demo", "1.0", files={"demo/__init__.py": source})
    place = lambda line: sandbox_deep.sink_placement(wheel, "demo/__init__.py", line, "os.system")  # noqa: E731
    assert [place(2), place(6), place(9), place(12)] == ["module level", "function f", "a lambda", "function m"]
    assert place(3).startswith("an unknown place") and sandbox_deep.sink_placement(tmp_path / "none.whl", "x", 1, "s").startswith("an unknown")


def test_violation_is_rejected_with_the_event_as_evidence(world, tmp_path, monkeypatch):
    escalated(world)
    Sandbox(monkeypatch, [recorded_run("events-probe")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("REJECTED", "DEEP_CONTRACT_VIOLATION")
    key = package["evidence"]["deep"]["evidence"]["key_events"]
    assert key and key[0]["rule"] == "CONTRACT_VIOLATION" and key[0]["line"] and key[0]["syscall"]
    assert {k["capability"] for k in key} & {"NETWORK_CONNECT", "SECRET_READ"}


def test_timeout_is_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    Sandbox(monkeypatch, [recorded_run("events-benign", rule="SANDBOX_TIMEOUT", cut=0.5)])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "SANDBOX_TIMEOUT")


def test_violation_before_a_timeout_is_rejected(world, tmp_path, monkeypatch):
    """D6: the probe's connect / secret read come before the cut; the run never finished, the violation stands."""
    escalated(world)
    Sandbox(monkeypatch, [recorded_run("events-probe", rule="SANDBOX_TIMEOUT", cut=0.995)])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("REJECTED", "DEEP_CONTRACT_VIOLATION"), package["reason"]


def test_incomplete_trace_is_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    run = recorded_run("events-benign")
    run.update(rule="TRACE_INCOMPLETE", reason="the trace is incomplete: test")
    run["evidence"].update(trace_attributable=False, processes={})
    Sandbox(monkeypatch, [run])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "TRACE_INCOMPLETE")


def test_unknown_event_is_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    run = recorded_run("events-benign")
    pid = next(p for p, info in run["evidence"]["processes"].items() if info["step"] == "imports")
    lines = run["trace"].split("\n")
    at = next(i for i, line in enumerate(lines) if line.startswith(f"{pid} ") and "openat(" in line)
    lines.insert(at, f'{pid}    inotify_add_watch(3</tmp>, "/tmp", IN_ALL_EVENTS) = -1 EPERM (Operation not permitted)')
    run["trace"] = "\n".join(lines)
    Sandbox(monkeypatch, [run])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "EVENT_TYPE_UNKNOWN")


def test_a_run_without_an_image_id_is_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    run = recorded_run("events-probe")
    run["evidence"]["image_id"] = None
    Sandbox(monkeypatch, [run])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_IMAGE_CHANGED")


def test_a_run_on_another_image_is_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    run = recorded_run("events-benign")
    run["evidence"]["image_id"] = "sha256:" + "e" * 64
    Sandbox(monkeypatch, [run])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_IMAGE_CHANGED")


def test_an_env_gated_sink_is_rejected_by_its_counterfactual_run(world, tmp_path, monkeypatch):
    """PR 12 (replaces PR 9's UNRESOLVED DEEP_TRIGGERS_UNEXPLORED): the canary-only run is clean, the run with the
    trigger's environment shows the violation."""
    escalated(world, TRIGGERED_CI)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign"), recorded_run("events-probe")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("REJECTED", "DEEP_CONTRACT_VIOLATION"), package["reason"]
    assert "run 2 (the counterfactual run spec-" in package["reason"]
    assert [c["spec"]["id"] == "spec-canaries" for c in sandbox.calls] == [True, False]
    assert sandbox.calls[1]["spec"]["env"]["CI"] == "true"
    deep = package["evidence"]["deep"]["evidence"]
    assert deep["decisive_run"] == 2 and deep["loop"]["stop"] == "violation" and deep["key_events"][0]["run"] == 2
    # PR 13: the event the verdict names first is in the CI=true run and not in the canary-only run.
    assert deep["causal"]["cause"] == "caused by CI=true" and package["reason"].endswith("; caused by CI=true")
    assert deep["causal"]["digest"] == deep["causal_graph"]["digest"]


def test_a_trigger_run_that_shows_nothing_leaves_the_trigger_unexplored(world, tmp_path, monkeypatch):
    escalated(world, TRIGGERED_CI)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")])  # both runs: no connect
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "TRIGGER_UNEXPLORED"), package["reason"]
    (entry,) = package["evidence"]["deep"]["evidence"]["residual"]["entries"]
    assert "'CI'" in entry["predicate"] and entry["run"] == 2 and "sink was not shown" in entry["outcome"]
    assert len(sandbox.calls) == 2


def test_a_trigger_on_a_variable_the_sandbox_fixes_is_unsimulable_and_gets_no_run(world, tmp_path, monkeypatch):
    escalated(world, TRIGGERED)  # os.getenv('CAVR_DEMO_TRIGGER'): CAVR_* is reserved (trigger_frontier.RESERVED_ENV)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "TRIGGER_UNSIMULABLE"), package["reason"]
    assert len(sandbox.calls) == 1  # the canary-only run only


def test_a_violation_wins_over_an_unexplored_trigger(world, tmp_path, monkeypatch):
    escalated(world, TRIGGERED)
    Sandbox(monkeypatch, [recorded_run("events-probe")])
    _, package = verify(world, analyzer(tmp_path))
    assert package["status"] == "REJECTED"


# --- baseline ------------------------------------------------------------------------------------------------------------

def test_baseline_is_recorded_once_and_reused(world, tmp_path, monkeypatch):
    escalated(world)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")])
    deep = analyzer(tmp_path)
    verify(world, deep)
    stored = list((tmp_path / "deep").glob("baseline-*.json"))
    assert len(stored) == 1 and json.loads(stored[0].read_text())["identity"] == deep.baseline_identity
    again = analyzer(tmp_path)
    assert again.baseline()[1] is None and sandbox.baseline_runs == 1  # read back, not run again


def test_baseline_unavailable_is_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    failed = recorded_run("events-baseline")
    failed.update(rule="SANDBOX_TIMEOUT", reason="test")
    Sandbox(monkeypatch, [recorded_run("events-benign")], baseline=failed)
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "BASELINE_UNAVAILABLE")
    assert not list((tmp_path / "deep").glob("baseline-*.json"))


def test_a_baseline_that_is_not_clean_is_refused_and_the_package_unresolved(world, tmp_path, monkeypatch):
    escalated(world)
    Sandbox(monkeypatch, [recorded_run("events-benign")], baseline="events-probe")  # a "baseline" that connects out
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "BASELINE_NOT_CLEAN")
    assert not list((tmp_path / "deep").glob("baseline-*.json"))


def test_a_stored_baseline_of_another_identity_or_not_clean_is_refused(tmp_path, monkeypatch):
    deep = analyzer(tmp_path)
    Sandbox(monkeypatch, [recorded_run("events-benign")])
    record, problem = deep.baseline()
    path = next((tmp_path / "deep").glob("baseline-*.json"))
    path.write_text(json.dumps({**record, "identity": "another"}))
    assert analyzer(tmp_path).baseline()[1][0] == "BASELINE_IDENTITY_MISMATCH"
    path.write_text(json.dumps({**record, "not_clean": [{"type": "NETWORK_CONNECT"}]}))
    assert analyzer(tmp_path).baseline()[1][0] == "BASELINE_NOT_CLEAN"


# --- budget --------------------------------------------------------------------------------------------------------------

def package(name):
    contract = {"result": "OK", "import_names": [name], "allowed": [], "denied": [], "vocabulary": []}
    return {"name": name, "version": "1.0", "contract": contract, "scan": [], "tree": {"nodes": []}}


def test_run_wide_cap_leaves_the_remaining_packages_unresolved(tmp_path, monkeypatch):
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")], seconds=100.0)
    deep = analyzer(tmp_path)
    answers = [deep.analyse(package(f"p{i}")) for i in range(4)]
    assert all(a["rule"] != "DEEP_RUN_BUDGET_USED_UP" and a["evidence"].get("run_rule") for a in answers[:3])  # each ran
    assert answers[3]["rule"] == "DEEP_RUN_BUDGET_USED_UP" and "300 s" in answers[3]["reason"]
    assert len(sandbox.calls) == 3 and deep.spent >= 300  # 2 s baseline + 3 x 100 s


def test_package_deadline_is_cut_to_what_is_left(tmp_path, monkeypatch):
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")], seconds=140.0)
    deep = analyzer(tmp_path)
    deep.analyse(package("a"))
    deep.analyse(package("b"))
    deep.analyse(package("c"))
    assert sandbox.deadlines[:2] == [20, 20] and sandbox.deadlines[2] == pytest.approx(300 - 2 - 280)


def test_package_over_its_budget_is_unresolved_by_the_deep_stage(world, tmp_path, monkeypatch):
    escalated(world)
    Sandbox(monkeypatch, [recorded_run("events-benign")], seconds=121.0)
    _, package_verdict = verify(world, analyzer(tmp_path))
    assert (package_verdict["status"], package_verdict["rule"]) == ("UNRESOLVED", "DEEP_BUDGET_EXCEEDED")


# --- identity and cache --------------------------------------------------------------------------------------------------

def test_identity_changes_with_image_harness_profile_and_budget(tmp_path, monkeypatch):
    base = deep_stage.identity(analyzer(tmp_path))
    assert base and IMAGE in base and sandbox_deep.VERSION in base
    assert deep_stage.identity(analyzer(tmp_path, {**IDENTITY, "image_id": "sha256:" + "f" * 64})) != base
    assert deep_stage.identity(analyzer(tmp_path, {**IDENTITY, "seccomp_sha256": "0" * 64})) != base
    assert deep_stage.identity(analyzer(tmp_path, budget={**sandbox_deep.BUDGET, "run_seconds": 10})) != base
    other = tmp_path / "harness.py"
    other.write_text("# another harness\n")
    with monkeypatch.context() as patch:
        patch.setattr(sandbox_observe, "HARNESS", other)
        assert deep_stage.identity(analyzer(tmp_path)) != base
    changes = [(sandbox_spec, "STRACE_SPEC", sandbox_spec.STRACE_SPEC + ["-v"]),
               (sandbox_observe, "PIP_INSTALL", sandbox_observe.PIP_INSTALL + ["--x"]),
               (sandbox_spec, "SPEC_IMPORT_ARGV", sandbox_spec.SPEC_IMPORT_ARGV + ["x"]),
               (call_drive, "DRIVE_ARGV", call_drive.DRIVE_ARGV + ["x"]),
               (trigger_frontier, "VERSION", "cavr-trigger-frontier/x"), (env_synthesis, "VERSION", "cavr-env-synthesis/x"),
               (activation_loop, "VERSION", "cavr-activation-loop/x"), (call_drive, "VERSION", "cavr-call-drive/x"),
               (causal_graph, "VERSION", "cavr-causal-graph/x"),
               (sandbox_observe, "SITE_TMPFS", sandbox_observe.SITE_TMPFS.replace("128m", "64m")),
               (sandbox_events, "EVENTS_VERSION", "cavr-events/x"), (contract_check, "CHECK_VERSION", "cavr-contract-check/x"),
               (sandbox_exec, "CAPABILITIES", sandbox_exec.CAPABILITIES + ("NET_RAW",))]
    for module, name, value in changes:
        with monkeypatch.context() as patch:
            patch.setattr(module, name, value)
            assert deep_stage.identity(analyzer(tmp_path)) != base, name
    assert set(sandbox_deep.VERDICT_CODE) >= {"sandbox_events.py", "contract_check.py", "sandbox_deep.py", "trigger_frontier.py",
                                              "env_synthesis.py", "sandbox_spec.py", "activation_loop.py", "call_drive.py",
                                              "causal_graph.py"}
    assert sandbox_deep.BUDGET == {"runs": 8, "run_seconds": 20, "package_seconds": 120, "gate_run_seconds": 300}
    real = sandbox_deep.deep_version(IDENTITY)
    with monkeypatch.context() as patch:
        original = sandbox_deep._sha256
        patch.setattr(sandbox_deep, "_sha256", lambda path: "0" * 64 if Path(path).name == "contract_check.py" else original(path))
        assert sandbox_deep.deep_version(IDENTITY) != real


def test_a_new_image_is_a_cache_miss(world, tmp_path, monkeypatch):
    world.policy.update(SCOPED_POLICY)
    escalated(world, IMPORT_TIME)
    Sandbox(monkeypatch, [recorded_run("events-scoped")])
    _, first = verify(world, analyzer(tmp_path))
    _, again = verify(world, analyzer(tmp_path))
    assert first["status"] == "VERIFIED" and again["cache_hit"] is True
    other = {**IDENTITY, "image_id": "sha256:" + "f" * 64}

    def on_other(stem):  # the same recorded run, as if made on the other image (its own baseline is recorded too)
        run = recorded_run(stem)
        run["evidence"]["image_id"] = other["image_id"]
        return run
    Sandbox(monkeypatch, [on_other("events-scoped")], baseline=on_other("events-baseline"))
    _, changed = verify(world, analyzer(tmp_path, other))
    assert changed["cache_hit"] is False and changed["status"] == "VERIFIED"


def test_non_escalated_packages_never_reach_the_deep_stage(world, tmp_path, monkeypatch):
    world.add("demo", "1.0", {"demo/__init__.py": "def run():\n    return 1\n"})
    world.write("app/uses_demo.py", USES_DEMO)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-probe")])
    with_deep = world.verify("pip install demo==1.0", deep=analyzer(tmp_path))
    without = world.verify("pip install demo==1.0")
    assert sandbox.calls == [] and sandbox.baseline_runs == 0
    assert (with_deep["status"], with_deep["rule"]) == (without["status"], without["rule"]) == ("VERIFIED", "ALL_CHECKS_PASSED")


# --- the gate ------------------------------------------------------------------------------------------------------------

def test_no_docker_or_no_image_keeps_todays_behaviour(world, tmp_path, monkeypatch):
    for rule in ("ENGINE_UNAVAILABLE", "IMAGE_MISSING", "IMAGE_ID_MISMATCH"):
        monkeypatch.setattr(sandbox_image, "image_identity", lambda rule=rule: {"ok": False, "rule": rule, "reason": rule})
        deep, status = sandbox_deep.for_gate_run(tmp_path)
        assert deep is None and status == {"enabled": False, "rule": rule, "reason": f"deep stage off: {rule}"}
    escalated(world)
    verdict = world.verify("pip install demo==1.0", deep=None)
    assert verdict["escalation"] == ESCALATION and verdict["analyzer_version"] == analyzer_version()


def test_the_gate_default_is_the_sandbox_and_it_builds_an_analyzer_when_the_image_passes(tmp_path, monkeypatch):
    assert gate_adapter.SETTINGS["deep"] == "sandbox"
    monkeypatch.setattr(sandbox_image, "image_identity", lambda: dict(IDENTITY))
    deep, status = sandbox_deep.for_gate_run(tmp_path)
    assert isinstance(deep, sandbox_deep.SandboxDeepAnalyzer) and deep.image_id == IMAGE and deep.spent == 0
    assert status["enabled"] is True and status["version"] == deep.version and deep.quarantine_dir == tmp_path / "quarantine"


def gate_repo(tmp_path, files, requirement="demo==1.0", policy_update=None):
    index = FakeIndex()
    wheel = build_wheel(tmp_path / "wheels", "demo", "1.0", files=files)
    index.add("demo", "1.0", wheel)
    osv = tmp_path / "osv"
    write_osv_cache(osv, "demo", "1.0", [])
    write_osv_cache(osv, "pypdf", PIN_VERSION, RECORDED_6_21_4)
    policy = {**POLICY, "approved_requirements": ["demo==1.0"], **(policy_update or {})}
    repo = GateRepo(tmp_path / "repo")
    base = {**invoice_app_files(), "requirements.txt": "", ".asent/cavr/policy.json": json.dumps(policy, indent=2),
            ".asent/config.json": config(CAVR={"enabled": True}, SATRA=DISABLED, SABLE=DISABLED)}
    repo.commit(base, tag="base")
    repo.commit({"requirements.txt": f"{requirement}\n", "app/uses_demo.py": USES_DEMO}, tag="head")
    return repo, {"transport": index, "osv": None, "advisory_cache_dir": osv, "live_advisories": False, "repair": False}


def test_gate_row_report_json_and_text_carry_the_deep_result(tmp_path, monkeypatch):
    repo, settings = gate_repo(tmp_path, BENIGN)
    monkeypatch.setattr(sandbox_image, "image_identity", lambda: dict(IDENTITY))
    Sandbox(monkeypatch, [recorded_run("events-probe")])
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**settings, "deep": "sandbox"})
    code, report, _ = run_cli(repo, "base", "head", tmp_path / "out")
    record = next(e for e in report["assurance"]["evidence"] if e["evidence_id"] == report["modules"]["CAVR"]["evidence_id"])
    (row,) = [p for entry in record["details"]["pipeline"] for p in entry["packages"]]
    assert code == 1 and row["status"] == "REJECTED" and row["deep"]["rule"] == "DEEP_CONTRACT_VIOLATION"
    assert row["deep"]["image_id"] == IMAGE and row["deep"]["key_events"] and row["deep"]["trace_sha256"]
    assert record["details"]["deep_stage"]["enabled"] is True
    lines = cavr_deep(report)
    assert len(lines) == 1 and lines[0].startswith("  CAVR deep: demo==1.0 REJECTED DEEP_CONTRACT_VIOLATION")
    assert lines[0] in render(report, tmp_path / "out" / "asent-report.json")


def test_gate_without_an_image_has_no_deep_row_and_no_report_line(tmp_path, monkeypatch):
    repo, settings = gate_repo(tmp_path, BENIGN)
    monkeypatch.setattr(sandbox_image, "image_identity", lambda: {"ok": False, "rule": "IMAGE_MISSING", "reason": "no image"})
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**settings, "deep": "sandbox"})
    code, report, _ = run_cli(repo, "base", "head", tmp_path / "out")
    record = next(e for e in report["assurance"]["evidence"] if e["evidence_id"] == report["modules"]["CAVR"]["evidence_id"])
    (row,) = [p for entry in record["details"]["pipeline"] for p in entry["packages"]]
    assert row["status"] == "UNRESOLVED" and row["escalation"] == ESCALATION and row["deep"] is None
    assert record["details"]["deep_stage"] == {"enabled": False, "rule": "IMAGE_MISSING", "reason": "deep stage off: no image"}
    assert cavr_deep(report) == []


def test_report_text_line_for_each_deep_result():
    report = {"modules": {"CAVR": {"evidence_id": "e1"}}, "assurance": {"evidence": [{"evidence_id": "e1", "details": {
        "pipeline": [{"file": "requirements.txt", "packages": [
            {"name": "a", "version": "1", "deep": {"status": "VERIFIED", "rule": "DEEP_RUN_CLEAN", "key_events": [],
                                                    "reason": "a 1: clean", "runs": [{"kind": "canary-only"}, {"kind": "counterfactual"}],
                                                    "drives": {"driven": [{"call": "a.run()"}]}}},
            {"name": "w", "version": "5", "deep": {"status": "UNRESOLVED", "rule": "TRIGGER_UNSIMULABLE", "key_events": [],
                                                    "residual": {"entries": [{"file": "w/__init__.py", "line": 3,
                                                                              "predicate": "sys.platform == 'win32'",
                                                                              "outcome": "not run: unsimulable (non-Linux platform)"}]}}},
            {"name": "b", "version": "2", "deep": {"status": "REJECTED", "rule": "DEEP_CONTRACT_VIOLATION", "key_events": [
                {"capability": "SECRET_READ", "syscall": "openat", "path": "/tmp/home/.aws/credentials", "ok": False,
                 "errno": "ENOENT", "address": None, "argv": None}], "causal": {"cause": "caused by CI=true"}}},
            {"name": "d", "version": "4", "deep": {"status": "UNRESOLVED", "rule": "DEEP_SINK_NOT_EXERCISED", "key_events": [],
                                                    "escalation_reasons": [{"file": "d/net.py", "line": 5, "sink": "socket.create_connection",
                                                                            "placement": "function send", "exercised": False}]}},
            {"name": "c", "version": "3", "deep": None}]}]}}]}}
    assert cavr_deep(report) == [
        "  CAVR deep: a==1 VERIFIED DEEP_RUN_CLEAN (2 run(s): canary-only + 1 counterfactual, 1 call site(s) driven; "
        "nothing outside the contract)",
        "  CAVR deep: w==5 UNRESOLVED TRIGGER_UNSIMULABLE - w/__init__.py:3 `sys.platform == 'win32'`: not run: "
        "unsimulable (non-Linux platform)",
        "  CAVR deep: b==2 REJECTED DEEP_CONTRACT_VIOLATION - SECRET_READ openat /tmp/home/.aws/credentials = ENOENT "
        "caused by CI=true",
        "  CAVR deep: d==4 UNRESOLVED DEEP_SINK_NOT_EXERCISED - not exercised: d/net.py:5 socket.create_connection (function send)"]


# --- the demo wheels on Docker -------------------------------------------------------------------------------------------

DEMOS = {
    "benign": (BENIGN, "UNRESOLVED", "DEEP_SINK_NOT_EXERCISED"),  # the sink is in a function only call sites reach
    "import_time": (IMPORT_TIME, "VERIFIED", "DEEP_RUN_CLEAN"),   # with SCOPED_POLICY: the sink runs at import, in scope
    "aws": ({**BENIGN, "demo/__init__.py": "import os\nfrom .net import send\n\ntry:\n"
                                          "    open(os.path.expanduser('~/.aws/credentials')).read()\nexcept OSError:\n"
                                          "    pass\n\n\ndef run():\n    return 1\n"}, "REJECTED", "DEEP_CONTRACT_VIOLATION"),
    "connect": ({**BENIGN, "demo/__init__.py": "import socket\nfrom .net import send\n\ntry:\n"
                                              "    socket.create_connection(('198.51.100.24', 443), timeout=1)\n"
                                              "except OSError:\n    pass\n\n\ndef run():\n    return 1\n"}, "REJECTED",
                "DEEP_CONTRACT_VIOLATION"),
    "shell": ({**BENIGN, "demo/__init__.py": "import subprocess\nfrom .net import send\n\n"
                                            "subprocess.run(['/bin/sh', '-c', 'true'])\n\n\ndef run():\n    return 1\n"},
              "REJECTED", "DEEP_CONTRACT_VIOLATION"),
    "env_trigger": (TRIGGERED, "UNRESOLVED", "TRIGGER_UNSIMULABLE"),  # PR 12: CAVR_* is fixed by the sandbox (PR 10)
    "ci_trigger": (TRIGGERED_CI, "REJECTED", "DEEP_CONTRACT_VIOLATION"),  # PR 12: the CI=true run connects
}


@requires_docker
@pytest.mark.parametrize("demo", list(DEMOS))
def test_demo_wheel_on_the_real_sandbox(demo, world, tmp_path):
    files, status, rule = DEMOS[demo]
    if demo == "import_time":
        world.policy.update(SCOPED_POLICY)
    escalated(world, files)
    deep = sandbox_deep.SandboxDeepAnalyzer(sandbox_identity(), tmp_path / "quarantine", tmp_path / "deep")
    verdict, found = verify(world, deep)
    assert (found["status"], found["rule"]) == (status, rule), found["reason"]
    evidence = found["evidence"]["deep"]["evidence"]
    assert evidence["image_id"] == sandbox_identity()["image_id"] and evidence["trace_check"] == "TRACE_COMPLETE"
    if demo == "aws":
        assert any(k["capability"] == "SECRET_READ" and k["path"] == "/tmp/home/.aws/credentials" for k in evidence["key_events"])
    if demo == "connect":
        hit = next(k for k in evidence["key_events"] if k["capability"] == "NETWORK_CONNECT")
        assert hit["address"]["host"] == "198.51.100.24" and hit["ok"] is False and hit["errno"] == "ENETUNREACH"
    if demo == "shell":
        assert any(k["capability"] == "PROCESS_EXEC" and k["path"] == "/bin/sh" for k in evidence["key_events"])
    if demo == "benign":
        assert evidence["events"]["judged"] == 0
    assert cavr_containers() == []


@requires_docker
@pytest.mark.parametrize("demo, decision, code", [("aws", "BLOCK", 1), ("benign", "REVIEW", 2), ("import_time", "ACCEPT", 0)])
def test_asent_gate_end_to_end_on_the_real_sandbox(demo, decision, code, tmp_path, monkeypatch):
    sandbox_identity()
    repo, settings = gate_repo(tmp_path, DEMOS[demo][0], policy_update=SCOPED_POLICY if demo == "import_time" else None)
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**settings, "deep": "sandbox"})
    got, report, _ = run_cli(repo, "base", "head", tmp_path / "out")
    assert (got, report["decision"]) == (code, decision), report["reasons"]
    (line,) = cavr_deep(report)
    assert f"demo==1.0 {DEMOS[demo][1]} {DEMOS[demo][2]}" in line
    assert cavr_containers() == []
