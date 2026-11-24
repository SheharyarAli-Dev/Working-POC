"""PR 13 of docs/cavr-m2-plan.md (FR-5): the causal capability graph of one deep verdict, from the recorded runs.

The runs come from the real loop (`activation_loop.explore`) with a fake container (`test_cavr_activation_loop`), and
once from the real drive recording `loop-drive-send`.
"""
import copy
import random

from backend.cavr import activation_loop, call_drive, causal_graph, env_synthesis
from test_cavr_activation_loop import BUDGET, Clock, FakeRun, entry, event, frontier, scoped_contract
from tests.test_cavr_trigger_frontier import DENY_ALL

REJECTED = {"status": "REJECTED", "rule": "DEEP_CONTRACT_VIOLATION"}


def explore(found, events_for, contract=DENY_ALL):
    clock = Clock()
    fake = FakeRun(clock, events_for, contract=contract)
    return activation_loop.explore(found, fake, budget=BUDGET, clock=clock, gate_left=lambda: 300.0,
                                   synthesize=env_synthesis.synthesize, canary_spec=env_synthesis.canary_spec)


def reads_granted():
    """The scoped contract with FILE_READ granted everywhere: reads are within it, other things still violate."""
    contract = scoped_contract()
    contract["allowed"] = contract["allowed"] + [{"capability": "FILE_READ", "scope": "*", "status": "OPTIONAL",
                                                  "source": "test", "justification": "test"}]
    contract["denied"] = [d for d in contract["denied"] if d["capability"] != "FILE_READ"]
    return contract


def kinds(graph, kind):
    return [n for n in graph["nodes"] if n["kind"] == kind]


def edges(graph, kind):
    nodes = {n["id"]: n for n in graph["nodes"]}
    return [(nodes[e["from"]], nodes[e["to"]]) for e in graph["edges"] if e["kind"] == kind]


def ci_world():
    found = frontier(entry("CI", activation={"env": {"CI": "true"}}))
    loop = explore(found, lambda spec: [event()] if spec["env"].get("CI") == "true" else [])
    return found, loop


def test_a_trigger_caused_the_event_only_its_run_has():
    found, loop = ci_world()
    graph = causal_graph.build("demo 1.0", found, {"drives": []}, loop, DENY_ALL, REJECTED)
    ((trigger, caused),) = edges(graph, "caused")
    assert trigger["kind"] == "trigger" and trigger["entry"] == "CI"
    assert (caused["label"], caused["run"]) == ("NETWORK_CONNECT 198.51.100.24:443", 2)
    ((_, rule),) = edges(graph, "violates")
    assert (rule["capability"], rule["grant"]) == ("NETWORK_CONNECT", "denied (default deny)")
    ((decided, verdict),) = edges(graph, "decides")
    assert decided is rule and verdict["status"] == "REJECTED"
    assert [(t["entry"], s["spec"]) for t, s in edges(graph, "synthesized_as")] == [("CI", "spec-CI")]
    assert sorted(r["run_kind"] for r in kinds(graph, "run")) == ["canary-only", "counterfactual"]
    record = loop["runs"][1]
    assert causal_graph.cause(graph, 2, record["events"][0]) == "caused by CI=true"


def test_an_event_both_runs_have_has_no_cause_edge():
    found = frontier(entry("CI", activation={"env": {"CI": "true"}}))
    loop = explore(found, lambda spec: [event()], contract=scoped_contract())  # in scope, in every run
    graph = causal_graph.build("demo 1.0", found, {"drives": []}, loop, scoped_contract(), {"status": "UNRESOLVED", "rule": "x"})
    assert edges(graph, "caused") == [] and len(edges(graph, "observed")) == 2
    assert {r["grant"] for _, r in edges(graph, "within")} == {"198.51.100.24:443"}
    assert causal_graph.cause(graph, 2, loop["runs"][1]["events"][0]) == "in run 2, and also without its trigger"


def test_a_violation_of_the_canary_only_run_needs_no_trigger():
    found = frontier(entry("CI", activation={"env": {"CI": "true"}}))
    loop = explore(found, lambda spec: [event(kind="FILE_READ", path="/tmp/home/.aws/credentials")])
    graph = causal_graph.build("demo 1.0", found, {"drives": []}, loop, DENY_ALL, REJECTED)
    assert len(loop["runs"]) == 1 and edges(graph, "caused") == []
    assert causal_graph.cause(graph, 1, loop["runs"][0]["events"][0]) == "in the canary-only run (no trigger needed)"


def test_a_canary_leak_points_at_a_rule_nothing_can_allow():
    leak = {**event(), "type": "CANARY_EXFIL_ATTEMPT", "syscall": "sendto", "canaries": ["file:aws-secret-key"]}
    loop = explore(frontier(), lambda spec: [leak])
    graph = causal_graph.build("demo 1.0", frontier(), {"drives": []}, loop, DENY_ALL, REJECTED)
    ((_, rule),) = edges(graph, "violates")
    assert rule["capability"] == "CANARY_EXFIL" and rule["grant"].startswith("never allowed")


def test_a_driven_call_caused_what_its_step_did_beyond_the_import():
    drive = {"step": "drive_1", "file": "app/uses_demo.py", "line": 5, "call": "demo.send('x')", "symbol": "demo.send"}
    imports = event(kind="FILE_READ", path="/etc/hosts")
    loop = explore(frontier(), lambda spec: [imports, {**imports, "step": "drive_1"}, event(step="drive_1")])
    graph = causal_graph.build("demo 1.0", frontier(), {"drives": [drive]}, loop, DENY_ALL, REJECTED)
    ((call, caused),) = edges(graph, "caused")
    assert call["kind"] == "call" and caused["step"] == "drive_1" and caused["type"] == "NETWORK_CONNECT"
    connect = loop["runs"][0]["events"][2]
    assert causal_graph.cause(graph, 1, connect) == "caused by calling demo.send('x') at app/uses_demo.py:5"
    assert call_drive.describe(drive) in causal_graph.cause(graph, 1, connect)


def test_the_real_drive_recording_gives_the_drive_as_the_cause(tmp_path):
    from tests.test_cavr_sandbox_deep import recorded_run
    from backend.cavr import sandbox_spec
    spec = env_synthesis.canary_spec()
    result = sandbox_spec._read(recorded_run("loop-drive-send"), spec, None)
    clock = Clock()
    loop = activation_loop.explore(frontier(), lambda s, d, n: activation_loop.read_run(
        copy.deepcopy(result), n=n, baseline=None, contract=DENY_ALL, image_id=result["evidence"]["image_id"]),
        budget=BUDGET, clock=clock, gate_left=lambda: 300.0, synthesize=env_synthesis.synthesize, canary_spec=lambda: spec)
    drive = {"step": "drive_1", "file": "app/uses_demo.py", "line": 5, "call": "demo.send('x')", "symbol": "demo.send"}
    graph = causal_graph.build("demo 1.0", frontier(), {"drives": [drive]}, loop, DENY_ALL, REJECTED)
    ((call, caused),) = edges(graph, "caused")
    assert caused["label"] == "NETWORK_CONNECT 198.51.100.24:443" and caused["errno"] == "ENETUNREACH"
    assert graph["counts"]["install_events_within_envelope"] > 0  # counted, not listed
    assert not any(n.get("step") == "install" for n in kinds(graph, "event"))


def test_each_activation_family_is_named_in_the_cause():
    text = causal_graph.activation_text
    assert text({"env": {"CI": "true"}}) == "CI=true"
    assert text({"time": "2027-01-01T00:00:00"}) == "clock 2027-01-01T00:00:00"
    assert text({"files": {"/tmp/home/.kube/config": "file"}}) == "/tmp/home/.kube/config exists"
    assert text({"files": {"/tmp/home/.cache": "dir"}}) == "/tmp/home/.cache exists (a directory)"
    assert text({"hostname": "build-prod-7"}) == "hostname build-prod-7"
    assert text({"argv": ["-c", "--deploy"]}) == "argv ['-c', '--deploy']"
    assert text({"env": {"A": "1"}, "hostname": "h"}) == "A=1 and hostname h"
    assert text(None) == "no trigger"


def test_the_graph_is_deterministic_and_its_digest_follows_every_event():
    """Review of Phase 3b, MINOR 1: perturb what is not evidence (the order of runs, outcomes, entries) of a loop whose
    runs have events, two of them with the same key; the trace order of a run's events is evidence and is kept."""
    found = frontier(entry("CI", activation={"env": {"CI": "true"}}), entry("B", risk="medium"))
    twice = [event(), {**event(), "line": 2}, event(kind="FILE_READ", path="/tmp/home/x")]
    loop = explore(found, lambda spec: twice if spec["env"].get("CI") == "true" else [twice[2]], contract=reads_granted())
    assert len(loop["runs"]) == 3 and len(loop["runs"][1]["new_events"]) == 2
    build = lambda f, l: causal_graph.build("demo 1.0", f, {"drives": []}, l, reads_granted(), REJECTED)
    first = build(found, loop)
    for seed in range(3):
        shuffled, entries = copy.deepcopy(loop), copy.deepcopy(found)
        random.Random(seed).shuffle(shuffled["runs"])
        random.Random(seed).shuffle(shuffled["outcomes"])
        random.Random(seed).shuffle(entries["entries"])
        assert build(entries, shuffled) == first
    assert len([n for n in first["nodes"] if n["kind"] == "event" and n["label"].startswith("NETWORK")]) == 2
    changed = copy.deepcopy(loop)
    changed["runs"][1]["events"][0]["address"]["port"] = 8443
    changed["runs"][1]["new_events"] = activation_loop.new_events(changed["runs"][1], changed["runs"][0])
    assert build(found, changed)["digest"] != first["digest"]
    other = causal_graph.build("demo 1.0", found, {"drives": []}, loop, reads_granted(), {"status": "UNRESOLVED", "rule": "x"})
    assert other["digest"] != first["digest"]


def test_events_within_the_contract_without_a_cause_are_capped_and_counted(monkeypatch):
    """Review of Phase 3b, MINOR 5: a run with many plain events does not make the report unbounded."""
    monkeypatch.setattr(causal_graph, "MAX_PLAIN_EVENTS", 3)
    reads = [event(kind="FILE_READ", path=f"/tmp/home/f{i}") for i in range(10)]
    contract = reads_granted()
    loop = explore(frontier(), lambda spec: reads + [event(host="203.0.113.9")], contract=contract)
    graph = causal_graph.build("demo 1.0", frontier(), {"drives": []}, loop, contract, REJECTED)
    events = kinds(graph, "event")
    assert len(events) == 4 and graph["counts"]["events_within_contract_not_listed"] == 7
    assert any(n["label"] == "NETWORK_CONNECT 203.0.113.9:443" for n in events)  # the violation is always listed


def test_a_graph_that_cannot_be_built_says_so_and_never_raises():
    graph = causal_graph.build("demo 1.0", None, None, {"runs": [{"events": 5}]}, DENY_ALL, REJECTED)
    assert graph["nodes"] == [] and graph["error"] and len(graph["digest"]) == 64
    assert causal_graph.cause(graph, 1, event()) is None
