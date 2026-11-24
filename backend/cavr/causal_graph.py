"""The causal capability graph of one deep verdict, built from the real runs (PR 13 of docs/cavr-m2-plan.md, FR-5).

`build(name, frontier, drives, loop, contract, verdict)` turns what the activation loop recorded (`activation_loop`)
into a graph. Nothing is inferred that a run did not show:

    nodes   trigger   a frontier entry: predicate, families, risk, activation, what the loop did with it
            spec      the run spec of a run: its activation (none for the canary-only spec) and its canary ids
            run       one sandbox run: number, kind, rule, completed, container, trace SHA-256
            call      a driven call site (`call_drive`): the call as the project writes it, file, line, step
            event     an observed event with a capability (or one the judge could not pass), outside the install
                      step, plus every install-step event the judge did not pass: type, syscall, step, path or
                      address, result, trace line
            rule      the contract rule the event was judged by: the capability and its grant (a scope, "*",
                      denied by default, or never allowed: a canary leak, a credential change, a refused syscall)
            verdict   the deep verdict: status and rule
    edges   synthesized_as  trigger -> spec            the spec was built from that trigger's activation
            configured      spec -> run                the run used that spec
            observed        run -> event               the event is in that run's trace
            violates / within / unjudged   event -> rule   the judge's answer for that event alone
            decides         rule -> verdict            a violated rule, when the verdict is REJECTED
            caused          trigger -> event           the event is in that trigger's run and not in the canary-only
                                                       run (the counterfactual difference, `activation_loop.new_events`)
            caused          call -> event              the event is in the call's drive step and not in the same run's
                                                       imports step (`activation_loop.drive_events`)

An event of the canary-only run's imports step has no cause edge: no trigger was needed for it.

Deterministic: every id is a hash of the node's content (an event's: its run, `sandbox_events.event_key` and its
occurrence number among equal keys), nodes and edges are sorted, and `digest` is the SHA-256 of the canonical JSON of
both. The same evidence always gives the same graph and digest; two real runs differ where their traces differ
(random canaries, container names, trace hashes). Install-step events the judge passed are counted, not listed;
events within the contract with no cause are listed up to MAX_PLAIN_EVENTS (by id), the rest counted.

`cause(graph, run, event)` is the text the report prints for one event: "caused by CI=true", "caused by calling
demo.send('x') at app/uses_demo.py:5", "in the canary-only run (no trigger needed)", or None (no such event).
"""
from __future__ import annotations

import hashlib
import json

from backend.cavr import activation_loop, contract_check, sandbox_events

VERSION = "cavr-causal-graph/1"
# Events within the contract with no cause edge are listed up to this many per graph, the rest only counted; events that
# violate, cannot be judged or have a cause are always listed (review of Phase 3b, MINOR 5).
MAX_PLAIN_EVENTS = 500
EVENT_FIELDS = ("type", "syscall", "step", "path", "address", "argv", "ok", "errno", "line")


def key_digest(event) -> str:
    return hashlib.sha256(json.dumps(list(sandbox_events.event_key(event)), default=str).encode()).hexdigest()[:16]


def _id(kind, content) -> str:
    return f"{kind}:" + hashlib.sha256(json.dumps(content, sort_keys=True, default=str).encode()).hexdigest()[:16]


def activation_text(activation) -> str:
    """CI=true, clock 2027-01-01 00:00:00, /tmp/home/.kube/config exists, hostname build-prod-7, argv ['--deploy']."""
    if not isinstance(activation, dict):
        return "no trigger"
    parts = [f"{name}={value}" for name, value in sorted((activation.get("env") or {}).items())]
    if activation.get("time"):
        parts.append(f"clock {activation['time']}")
    parts += [f"{path} exists" + (" (a directory)" if kind == "dir" else "")
              for path, kind in sorted((activation.get("files") or {}).items())]
    if activation.get("hostname"):
        parts.append(f"hostname {activation['hostname']}")
    if activation.get("argv"):
        parts.append(f"argv {activation['argv']}")
    return " and ".join(parts) or "no change from the canary-only run"


def event_label(event) -> str:
    address = event.get("address") or {}
    target = (f"{address.get('host')}:{address.get('port')}" if address.get("host") else address.get("path")) \
        or event.get("path") or " ".join((event.get("argv") or [])[:3]) or ""
    capabilities = activation_loop.event_capabilities(event)
    return f"{capabilities[0] if capabilities else event.get('type')} {target}".strip()


def build(name, frontier, drives, loop, contract, verdict) -> dict:
    """{version, nodes, edges, counts, digest}. Never raises (an error is a graph with `error`)."""
    try:
        return _build(name, frontier, drives, loop, contract, verdict)
    except Exception as exc:
        graph = {"version": VERSION, "package": name, "nodes": [], "edges": [], "counts": {},
                 "error": f"{type(exc).__name__}: {exc}"}
        graph["digest"] = _digest(graph)
        return graph


def _build(name, frontier, drives, loop, contract, verdict):
    nodes, edges = {}, set()
    grants, _ = contract_check.read_contract(contract)
    grants = grants or {}
    verdict_id = _id("verdict", [verdict.get("status"), verdict.get("rule")])
    nodes[verdict_id] = {"id": verdict_id, "kind": "verdict", "status": verdict.get("status"), "rule": verdict.get("rule")}
    entries = {e["id"]: e for e in (frontier or {}).get("entries") or [] if isinstance(e, dict) and e.get("id")}
    outcomes = {o["id"]: o for o in loop.get("outcomes") or []}
    triggers = {}
    for ident, entry in entries.items():
        node_id = _id("trigger", ident)
        triggers[ident] = node_id
        nodes[node_id] = {"id": node_id, "kind": "trigger", "entry": ident, "package": entry.get("package"),
                          "file": entry.get("file"), "line": entry.get("line"), "predicate": entry.get("predicate"),
                          "families": entry.get("families"), "risk": entry.get("risk"),
                          "activation": entry.get("activation"), "outcome": (outcomes.get(ident) or {}).get("outcome")}
    calls = {}
    for drive in (drives or {}).get("drives") or []:
        node_id = _id("call", [drive.get("step"), drive.get("file"), drive.get("line"), drive.get("call")])
        calls[drive["step"]] = node_id
        nodes[node_id] = {"id": node_id, "kind": "call", "step": drive.get("step"), "call": drive.get("call"),
                          "file": drive.get("file"), "line": drive.get("line"), "symbol": drive.get("symbol")}
    install_passed = 0
    plain = []  # (event node, its rules, its edges): within the contract, no cause; listed up to MAX_PLAIN_EVENTS
    for record in loop.get("runs") or []:
        spec_id = _id("spec", [record.get("spec_id"), record.get("activation")])
        run_id = _id("run", [record.get("n"), record.get("kind"), record.get("trace_sha256")])
        nodes[spec_id] = {"id": spec_id, "kind": "spec", "spec": record.get("spec_id"), "activation": record.get("activation"),
                          "canaries": record.get("canary_ids") or []}
        nodes[run_id] = {"id": run_id, "kind": "run", "n": record.get("n"), "run_kind": record.get("kind"),
                         "rule": record.get("rule"), "completed": record.get("completed"),
                         "container": record.get("container"), "trace_sha256": record.get("trace_sha256")}
        edges.add((spec_id, run_id, "configured"))
        for ident in record.get("entries") or []:
            if ident in triggers:
                edges.add((triggers[ident], spec_id, "synthesized_as"))
        caused = {}
        if record.get("kind") == activation_loop.COUNTERFACTUAL:
            for event in record.get("new_events") or []:
                caused.setdefault(id(event), []).extend(triggers[i] for i in record.get("entries") or [] if i in triggers)
        for step, node_id in calls.items():
            for event in activation_loop.drive_events(record, step):
                caused.setdefault(id(event), []).append(node_id)
        seen = {}
        for event in record.get("events") or []:
            key = sandbox_events.event_key(event)
            occurrence = seen[key] = seen.get(key, 0) + 1
            answer = contract_check.judge([event], contract)["result"]
            if event.get("step") == activation_loop.INSTALL and answer == "OK":
                install_passed += 1
                continue
            capabilities = activation_loop.event_capabilities(event)
            if not capabilities and answer == "OK":
                continue
            event_id = _id("event", [record.get("n"), list(key), occurrence])
            node = {"id": event_id, "kind": "event", "run": record.get("n"), "label": event_label(event),
                    "key": key_digest(event), **{field: event.get(field) for field in EVENT_FIELDS}}
            own = [(run_id, event_id, "observed")] + [(cause_id, event_id, "caused") for cause_id in caused.get(id(event), [])]
            rules = []
            never = contract_check.capability_of(event)[0] == "never"
            for capability in capabilities or [event.get("type")]:
                scope = grants.get(capability)
                grant = ("never allowed (no capability can allow it)" if never
                         else "denied (default deny)" if scope is None else scope)
                rule_id = _id("rule", [capability, grant])
                rules.append({"id": rule_id, "kind": "rule", "capability": capability, "grant": grant})
                kind = {"VIOLATION": "violates", "UNRESOLVED": "unjudged"}.get(answer, "within")
                own.append((event_id, rule_id, kind))
                if kind == "violates" and verdict.get("status") == "REJECTED":
                    own.append((rule_id, verdict_id, "decides"))
            if answer == "OK" and not caused.get(id(event)):
                plain.append((node, rules, own))
                continue
            nodes[event_id] = node
            nodes.update({rule["id"]: rule for rule in rules})
            edges.update(own)
    plain.sort(key=lambda item: item[0]["id"])
    for node, rules, own in plain[:MAX_PLAIN_EVENTS]:
        nodes[node["id"]] = node
        nodes.update({rule["id"]: rule for rule in rules})
        edges.update(own)
    graph = {"version": VERSION, "package": name,
             "nodes": sorted(nodes.values(), key=lambda n: n["id"]),
             "edges": [{"from": a, "to": b, "kind": k} for a, b, k in sorted(edges)],
             "counts": {"nodes": len(nodes), "edges": len(edges), "install_events_within_envelope": install_passed,
                        "events_within_contract_not_listed": max(0, len(plain) - MAX_PLAIN_EVENTS)}}
    graph["digest"] = _digest(graph)
    return graph


def cause(graph, run_n, event):
    """The report's text for the cause of `event` of run `run_n` (the event the verdict names first), or None when the
    graph has no node for it. The event is found by its `sandbox_events.event_key` and trace line (review of Phase 3b,
    MINOR 4), not by the shown fields."""
    nodes = {n["id"]: n for n in graph.get("nodes") or []}
    try:
        wanted = event.get("key") or key_digest(event)  # a key event of the evidence carries its key digest
    except (KeyError, TypeError, AttributeError):
        return None
    match = [n for n in nodes.values() if n["kind"] == "event" and n["run"] == run_n and n.get("key") == wanted
             and n.get("line") == event.get("line")]
    if not match:
        return None
    target = match[0]["id"]
    causes = [nodes[e["from"]] for e in graph.get("edges") or [] if e["to"] == target and e["kind"] == "caused"]
    calls = [c for c in causes if c["kind"] == "call"]
    triggers = [c for c in causes if c["kind"] == "trigger"]
    if triggers:
        return "caused by " + " / ".join(sorted({activation_text(t["activation"]) for t in triggers}))
    if calls:
        return "caused by calling " + " / ".join(f"{c['call']} at {c['file']}:{c['line']}" for c in calls)
    run = next((n for n in nodes.values() if n["kind"] == "run" and n["n"] == run_n), {})
    if run.get("run_kind") == activation_loop.CANARY_ONLY:
        return "in the canary-only run (no trigger needed)"
    return f"in run {run_n}, and also without its trigger"


def graph_digest(graph) -> str:
    """The digest of a graph's content (version, package, nodes, edges): what `build` stores in `digest`."""
    return _digest(graph)


def _digest(graph) -> str:
    body = {key: graph[key] for key in ("version", "package", "nodes", "edges")}
    return hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
