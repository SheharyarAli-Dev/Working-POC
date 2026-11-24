"""PR 12 of docs/cavr-m2-plan.md: the budgeted counterfactual activation loop, with a fake sandbox run (no container).

The events are in the shape `sandbox_events.normalise` gives (only the fields the loop and the judge read).
"""
import pytest

from backend.cavr import activation_loop, env_synthesis
from tests.test_cavr_trigger_frontier import DENY_ALL

BUDGET = {"runs": 8, "run_seconds": 20, "package_seconds": 120, "gate_run_seconds": 300}


def event(kind="NETWORK_CONNECT", step="imports", host="198.51.100.24", port=443, path=None, syscall=None):
    address = {"family": "AF_INET", "host": host, "port": port} if kind.startswith("NETWORK") else None
    return {"type": kind, "syscall": syscall or ("connect" if address else "openat"), "step": step, "path": path,
            "real_path": path, "access": "read" if path else None, "address": address, "argv": None, "ok": False,
            "errno": "ENETUNREACH", "complete": True, "line": 1, "sensitive": None, "persistence": False}


def entry(ident, activation=None, risk="high", simulable=True, baseline=False, capability="NETWORK_CONNECT"):
    return {"id": ident, "package": "demo", "file": "demo/__init__.py", "line": 3, "predicate": f"p_{ident}",
            "risk": risk, "simulable": simulable, "unsimulable_reason": None if simulable else "not Linux",
            "baseline_takes_it": baseline, "activation": activation if activation is not None else {"env": {ident: "1"}},
            "sinks": [{"capability": capability}]}


def frontier(*entries):
    return {"version": "cavr-trigger-frontier/1", "ok": True, "entries": list(entries)}


class Clock:
    def __init__(self):
        self.now = 0.0

    def __call__(self):
        return self.now


class FakeRun:
    """Each call returns a record for `events_for(spec)` and advances the clock by `seconds`."""

    def __init__(self, clock, events_for, seconds=5.0, rule=activation_loop.COMPLETE, contract=None):
        self.clock, self.events_for, self.seconds, self.rule = clock, events_for, seconds, rule
        self.contract = contract or scoped_contract()
        self.calls = []

    def __call__(self, spec, deadline, n):
        self.calls.append({"spec": spec, "deadline": deadline, "n": n})
        self.clock.now += self.seconds
        rule = self.rule(spec) if callable(self.rule) else self.rule
        result = {"rule": rule, "reason": "fake", "events": self.events_for(spec),
                  "evidence": {"image_id": "img", "container": f"cavr-x-{n}", "trace_attributable": True,
                               "processes": {"1": {}}}}
        return activation_loop.read_run(result, n=n, baseline=None, contract=self.contract, image_id="img")


def scoped_contract():
    """Deny-all except NETWORK_CONNECT to 198.51.100.24:443 (a scoped grant: in-scope connects are within it)."""
    contract = dict(DENY_ALL)
    contract["allowed"] = [{"capability": "NETWORK_CONNECT", "scope": "198.51.100.24:443", "status": "OPTIONAL",
                            "source": "test", "justification": "test"}]
    contract["denied"] = [d for d in DENY_ALL["denied"] if d["capability"] != "NETWORK_CONNECT"]
    return contract


def explore(found, fake, clock, budget=BUDGET, gate_left=lambda: 300.0):
    return activation_loop.explore(found, fake, budget=budget, clock=clock, gate_left=gate_left,
                                   synthesize=env_synthesis.synthesize, canary_spec=env_synthesis.canary_spec)


def fires_on(*names):
    """Events: an in-scope connect in every run whose spec sets one of `names`."""
    return lambda spec: [event()] if set(names) & set(spec.get("env") or {}) else []


def test_the_canary_only_run_is_first_then_entries_in_frontier_order():
    clock = Clock()
    fake = FakeRun(clock, fires_on("A", "B"))
    got = explore(frontier(entry("A"), entry("B", risk="medium"), entry("C", risk="low")), fake, clock)
    assert [c["spec"]["id"] for c in fake.calls] == ["spec-canaries", "spec-A", "spec-B", "spec-C"]
    assert [r["kind"] for r in got["runs"]] == ["canary-only"] + ["counterfactual"] * 3
    assert got["explored"] == ["A", "B"] and got["stop"] == "done"
    outcome = {o["id"]: o for o in got["outcomes"]}
    assert outcome["A"]["outcome"] == "explored" and outcome["A"]["run"] == 2
    assert "sink was not shown" in outcome["C"]["outcome"]
    assert got["activation_rate"] == {"explored": 2, "simulable": 3, "rate": 0.667}
    assert got["new_sensitive_events"] == {"2": 1, "3": 1, "4": 0}


def test_entries_with_the_same_activation_share_one_run():
    clock = Clock()
    fake = FakeRun(clock, fires_on("CI"))
    same = {"env": {"CI": "true"}}
    got = explore(frontier(entry("A", same), entry("B", same)), fake, clock)
    assert len(fake.calls) == 2 and got["runs"][1]["entries"] == ["A", "B"] and got["explored"] == ["A", "B"]


def test_an_event_the_canary_only_run_also_has_does_not_explore_the_entry():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [event()])  # the same connect in every run, also without the trigger
    got = explore(frontier(entry("A")), fake, clock)
    assert got["explored"] == [] and "canary-only run does not have" in got["outcomes"][0]["outcome"]


def test_an_entry_the_baseline_takes_is_explored_only_by_the_canary_only_run_showing_its_sink():
    clock = Clock()
    shown = explore(frontier(entry("A", baseline=True)), FakeRun(clock, lambda spec: [event()]), clock)
    assert len(shown["runs"]) == 1 and shown["explored"] == ["A"] and shown["runs"][0]["entries"] == ["A"]
    clock = Clock()
    hidden = explore(frontier(entry("A", baseline=True)), FakeRun(clock, lambda spec: []), clock)
    assert hidden["explored"] == [] and "taken by the baseline, but" in hidden["outcomes"][0]["outcome"]


def test_an_install_step_event_never_explores_an_entry():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [event(step="install")] if "A" in spec["env"] else [])
    assert explore(frontier(entry("A")), fake, clock)["explored"] == []


def test_the_budget_of_eight_runs_stops_the_loop_and_names_what_was_never_run():
    clock = Clock()
    names = [f"T{i}" for i in range(9)]
    fake = FakeRun(clock, fires_on(*names), seconds=1.0)
    got = explore(frontier(*[entry(n, risk="medium") for n in names]), fake, clock)
    assert len(fake.calls) == 8 and got["stop"] == "runs" and got["explored"] == names[:7]
    never = [o for o in got["outcomes"] if o["id"] in names[7:]]
    assert all(o["stopped_by"] == "runs" and "8 sandbox runs" in o["outcome"] for o in never)
    assert got["budget_used"]["runs"] == 8 and got["planned_runs"] == 10


def test_the_package_time_cuts_each_deadline_and_stops_the_loop():
    clock = Clock()
    fake = FakeRun(clock, fires_on("A", "B", "C", "D", "E", "F", "G"), seconds=20.0)
    got = explore(frontier(*[entry(n) for n in "ABCDEFG"]), FakeRunGuard(fake), clock)
    deadlines = [c["deadline"] for c in fake.calls]
    assert deadlines[:5] == [20] * 5 and deadlines[5] == pytest.approx(120 - 100 - activation_loop.OVERHEAD_SECONDS)
    assert got["stop"] == "seconds" and len(fake.calls) == 6


class FakeRunGuard:
    """Turns every run into a clean one (no violation) so that only the budget stops the loop."""

    def __init__(self, fake):
        self.fake = fake

    def __call__(self, spec, deadline, n):
        record = self.fake(spec, deadline, n)
        record["judged"] = {"result": "OK"}
        return record


def test_the_gate_run_time_left_cuts_the_deadline():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [])
    explore(frontier(entry("A")), fake, clock, gate_left=lambda: 7.5)
    assert [c["deadline"] for c in fake.calls] == [7.5, 7.5]
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [])
    got = explore(frontier(entry("A")), fake, clock, gate_left=lambda: 1.0)
    assert fake.calls == [] and got["stop"] == "seconds" and got["runs"] == []


def test_a_violation_stops_the_loop_early():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [event(host="203.0.113.9")] if "A" in spec["env"] else [])
    got = explore(frontier(entry("A"), entry("B")), fake, clock)
    assert len(fake.calls) == 2 and got["stop"] == "violation"
    assert got["runs"][1]["judged"]["result"] == "VIOLATION"
    assert {o["id"]: o.get("stopped_by") for o in got["outcomes"]} == {"A": None, "B": "violation"}


def test_a_violation_in_the_canary_only_run_stops_before_any_trigger_run():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [event(kind="FILE_READ", path="/tmp/home/.aws/credentials")])
    got = explore(frontier(entry("A")), fake, clock)
    assert len(fake.calls) == 1 and got["stop"] == "violation"


def test_a_canary_only_run_that_did_not_complete_stops_the_loop():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [], rule="SANDBOX_TIMEOUT")
    got = explore(frontier(entry("A")), fake, clock)
    assert len(fake.calls) == 1 and got["stop"] == "canary" and got["runs"][0]["completed"] is False


def test_a_counterfactual_run_that_did_not_complete_leaves_its_entry_unexplored_and_the_loop_goes_on():
    clock = Clock()
    fake = FakeRun(clock, fires_on("A", "B"), rule=lambda spec: "SANDBOX_TIMEOUT" if "A" in spec["env"] else activation_loop.COMPLETE)
    got = explore(frontier(entry("A"), entry("B")), fake, clock)
    assert got["explored"] == ["B"] and "did not complete (SANDBOX_TIMEOUT)" in got["outcomes"][0]["outcome"]


def test_unsimulable_and_refused_entries_get_no_run():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [])
    refused = entry("R", activation={"env": {"HOME": "/root"}})
    got = explore(frontier(entry("U", simulable=False), refused), fake, clock)
    assert len(fake.calls) == 1
    outcome = {o["id"]: o["outcome"] for o in got["outcomes"]}
    assert outcome["U"].startswith("not run: unsimulable") and "the spec was refused" in outcome["R"]


def test_an_image_other_than_the_checked_one_is_not_a_completed_run():
    record = activation_loop.read_run({"rule": activation_loop.COMPLETE, "events": [event()],
                                       "evidence": {"image_id": "other", "container": "c", "trace_attributable": True,
                                                    "processes": {"1": {}}}},
                                      n=1, baseline=None, contract=scoped_contract(), image_id="img")
    assert record["rule"] == "DEEP_IMAGE_CHANGED" and record["completed"] is False and record["judged"] is None


def test_an_unattributable_trace_is_not_a_completed_run():
    record = activation_loop.read_run({"rule": activation_loop.COMPLETE, "events": [],
                                       "evidence": {"image_id": "img", "container": "c", "trace_attributable": False}},
                                      n=1, baseline=None, contract=scoped_contract(), image_id="img")
    assert record["rule"] == "TRACE_INCOMPLETE" and record["completed"] is False


def test_drive_events_are_what_the_call_did_beyond_the_import():
    imports = event(kind="FILE_READ", path="/etc/hosts")
    record = {"events": [imports, {**imports, "step": "drive_1"}, event(step="drive_1"), event(step="drive_2")]}
    assert [e["type"] for e in activation_loop.drive_events(record, "drive_1")] == ["NETWORK_CONNECT"]
    assert [e["step"] for e in activation_loop.drive_events(record, "drive_2")] == ["drive_2"]


def test_the_loop_is_deterministic_for_the_same_runs():
    found = frontier(entry("A"), entry("B", risk="medium"))
    outs = []
    for _ in range(3):
        clock = Clock()
        got = explore(found, FakeRun(clock, fires_on("A")), clock)
        outs.append((got["explored"], [o["outcome"] for o in got["outcomes"]], [r["spec_id"] for r in got["runs"]]))
    assert all(out == outs[0] for out in outs)


def test_no_frontier_still_makes_the_canary_only_run():
    clock = Clock()
    fake = FakeRun(clock, lambda spec: [])
    for found in (None, {"entries": None}, frontier()):
        got = explore(found, fake, clock)
        assert got["runs"][0]["kind"] == "canary-only" and got["explored"] == [] and got["outcomes"] == []
    assert len(fake.calls) == 3
