"""PR 9 of docs/cavr-m2-plan.md: escalated packages get one observed sandbox run (`sandbox_deep`).

Unit tests run the real pipeline (`test_cavr_support.World`) and the real normaliser and contract check; only the
container is replaced: `sandbox_deep.OBSERVE` / `RUN_HARNESS` return a real trace recorded on Docker
(`tests/test_cavr_data/traces/events-*.txt`) as the observed run. Docker tests (CAVR_DOCKER=1) build the demo wheels in
`tmp_path` and run them in asent-cavr-sandbox:local, through `verify_request` and through `asent gate`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from backend.cavr import (contract_check, deep_stage, gate_adapter, sandbox_deep, sandbox_events, sandbox_exec, sandbox_image,
                          sandbox_observe)
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
    """Replaces the container: each observe returns `runs[i]` and advances the clock by `seconds` per run."""

    def __init__(self, monkeypatch, runs, seconds=5.0, baseline="events-baseline"):
        self.runs, self.seconds, self.now, self.calls, self.deadlines = list(runs), seconds, 1000.0, [], []
        self.baseline_runs = 0
        monkeypatch.setattr(sandbox_deep, "CLOCK", lambda: self.now)
        monkeypatch.setattr(deep_stage, "CLOCK", lambda: self.now)
        monkeypatch.setattr(sandbox_deep, "OBSERVE", self.observe)
        monkeypatch.setattr(sandbox_deep, "RUN_HARNESS", self.harness)
        self.baseline = baseline

    def observe(self, nodes, modules, quarantine_dir=None, deadline=None):
        self.calls.append({"nodes": nodes, "modules": modules})
        self.deadlines.append(deadline)
        self.now += self.seconds
        run = self.runs.pop(0) if len(self.runs) > 1 else self.runs[0]
        return run() if callable(run) else run

    def harness(self, steps, tmpfs=(), deadline=None):
        self.baseline_runs += 1
        self.now += 2.0
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

def test_clean_complete_run_without_triggers_is_verified(world, tmp_path, monkeypatch):
    escalated(world)
    sandbox = Sandbox(monkeypatch, [recorded_run("events-benign")])
    verdict, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["stage"], package["rule"]) == ("VERIFIED", "deep", "DEEP_RUN_CLEAN"), package["reason"]
    assert verdict["status"] == "VERIFIED" and package["escalation"] != ESCALATION
    deep = package["evidence"]["deep"]["evidence"]
    assert deep["check"]["rule"] == "EVENTS_WITHIN_CONTRACT" and deep["trace_sha256"] and deep["baseline"]["rule"] == "BASELINE_OK"
    assert "call sites were not executed" in package["reason"] and deep["not_exercised"]  # NFR-6: the bounded claim
    assert sandbox.calls[0]["modules"] == ["demo"] and sandbox.baseline_runs == 1


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


def test_escalated_package_with_an_unexplored_trigger_is_unresolved_until_the_frontier_exists(world, tmp_path, monkeypatch):
    escalated(world, TRIGGERED)
    Sandbox(monkeypatch, [recorded_run("events-benign")])
    _, package = verify(world, analyzer(tmp_path))
    assert (package["status"], package["rule"]) == ("UNRESOLVED", "DEEP_TRIGGERS_UNEXPLORED"), package["reason"]
    (trigger,) = package["evidence"]["deep"]["evidence"]["unexplored_triggers"]
    assert trigger["capabilities"] == ["NETWORK_CONNECT"] and "CAVR_DEMO_TRIGGER" in trigger["predicate"]


def test_a_violation_wins_over_an_unexplored_trigger(world, tmp_path, monkeypatch):
    escalated(world, TRIGGERED)
    Sandbox(monkeypatch, [recorded_run("events-probe")])
    _, package = verify(world, analyzer(tmp_path))
    assert package["status"] == "REJECTED"


def test_trigger_gating_only_unrestricted_sinks_is_not_high_risk():
    scans = [{"package": "demo", "triggers": [{"file": "demo/__init__.py", "line": 4, "predicate": "os.getenv('X')",
                                               "reachable_sinks": [{"capability": "NETWORK_CONNECT"}]}]}]
    star = {"allowed": [{"capability": "NETWORK_CONNECT", "scope": "*"}]}
    scoped = {"allowed": [{"capability": "NETWORK_CONNECT", "scope": "1.2.3.4:443"}]}
    assert sandbox_deep.high_risk_triggers(scans, star) == []
    assert [t["capabilities"] for t in sandbox_deep.high_risk_triggers(scans, scoped)] == [["NETWORK_CONNECT"]]
    assert sandbox_deep.high_risk_triggers(scans, {"allowed": []})[0]["line"] == 4


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
    changes = [(sandbox_observe, "STRACE", sandbox_observe.STRACE + ["-v"]),
               (sandbox_observe, "PIP_INSTALL", sandbox_observe.PIP_INSTALL + ["--x"]),
               (sandbox_observe, "IMPORT_ARGV", sandbox_observe.IMPORT_ARGV + ["x"]),
               (sandbox_observe, "SITE_TMPFS", sandbox_observe.SITE_TMPFS.replace("128m", "64m")),
               (sandbox_events, "EVENTS_VERSION", "cavr-events/x"), (contract_check, "CHECK_VERSION", "cavr-contract-check/x"),
               (sandbox_exec, "CAPABILITIES", sandbox_exec.CAPABILITIES + ("NET_RAW",))]
    for module, name, value in changes:
        with monkeypatch.context() as patch:
            patch.setattr(module, name, value)
            assert deep_stage.identity(analyzer(tmp_path)) != base, name
    assert set(sandbox_deep.VERDICT_CODE) >= {"sandbox_events.py", "contract_check.py", "sandbox_deep.py"}
    real = sandbox_deep.deep_version(IDENTITY)
    with monkeypatch.context() as patch:
        original = sandbox_deep._sha256
        patch.setattr(sandbox_deep, "_sha256", lambda path: "0" * 64 if Path(path).name == "contract_check.py" else original(path))
        assert sandbox_deep.deep_version(IDENTITY) != real


def test_a_new_image_is_a_cache_miss(world, tmp_path, monkeypatch):
    escalated(world)
    Sandbox(monkeypatch, [recorded_run("events-benign")])
    _, first = verify(world, analyzer(tmp_path))
    _, again = verify(world, analyzer(tmp_path))
    assert first["status"] == "VERIFIED" and again["cache_hit"] is True
    other = {**IDENTITY, "image_id": "sha256:" + "f" * 64}

    def on_other(stem):  # the same recorded run, as if made on the other image (its own baseline is recorded too)
        run = recorded_run(stem)
        run["evidence"]["image_id"] = other["image_id"]
        return run
    Sandbox(monkeypatch, [on_other("events-benign")], baseline=on_other("events-baseline"))
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


def gate_repo(tmp_path, files, requirement="demo==1.0"):
    index = FakeIndex()
    wheel = build_wheel(tmp_path / "wheels", "demo", "1.0", files=files)
    index.add("demo", "1.0", wheel)
    osv = tmp_path / "osv"
    write_osv_cache(osv, "demo", "1.0", [])
    write_osv_cache(osv, "pypdf", PIN_VERSION, RECORDED_6_21_4)
    policy = {**POLICY, "approved_requirements": ["demo==1.0"]}
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
                                                    "reason": "a 1: clean"}},
            {"name": "b", "version": "2", "deep": {"status": "REJECTED", "rule": "DEEP_CONTRACT_VIOLATION", "key_events": [
                {"capability": "SECRET_READ", "syscall": "openat", "path": "/tmp/home/.aws/credentials", "ok": False,
                 "errno": "ENOENT", "address": None, "argv": None}]}},
            {"name": "c", "version": "3", "deep": None}]}]}}]}}
    assert cavr_deep(report) == [
        "  CAVR deep: a==1 VERIFIED DEEP_RUN_CLEAN (install + import observed; nothing outside the contract)",
        "  CAVR deep: b==2 REJECTED DEEP_CONTRACT_VIOLATION - SECRET_READ openat /tmp/home/.aws/credentials = ENOENT"]


# --- the demo wheels on Docker -------------------------------------------------------------------------------------------

DEMOS = {
    "benign": (BENIGN, "VERIFIED", "DEEP_RUN_CLEAN"),
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
    "env_trigger": (TRIGGERED, "UNRESOLVED", "DEEP_TRIGGERS_UNEXPLORED"),
}


@requires_docker
@pytest.mark.parametrize("demo", list(DEMOS))
def test_demo_wheel_on_the_real_sandbox(demo, world, tmp_path):
    files, status, rule = DEMOS[demo]
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
@pytest.mark.parametrize("demo, decision, code", [("aws", "BLOCK", 1), ("benign", "ACCEPT", 0)])
def test_asent_gate_end_to_end_on_the_real_sandbox(demo, decision, code, tmp_path, monkeypatch):
    sandbox_identity()
    repo, settings = gate_repo(tmp_path, DEMOS[demo][0])
    monkeypatch.setattr(gate_adapter, "SETTINGS", {**settings, "deep": "sandbox"})
    got, report, _ = run_cli(repo, "base", "head", tmp_path / "out")
    assert (got, report["decision"]) == (code, decision), report["reasons"]
    (line,) = cavr_deep(report)
    assert f"demo==1.0 {DEMOS[demo][1]} {DEMOS[demo][2]}" in line
    assert cavr_containers() == []
