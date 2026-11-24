"""The dashboard's view of each package of a verdict (PR 19 of docs/cavr-m2-plan.md).

`package_views(verdict)` gives, for every package: its fast-gate stages with their rules, and its deep block (the
`sandbox_deep` evidence: runs, frontier entries, driven call sites, other guards, budget, residual, key events, canary
ids per run and the canary leaks, the causal summary), or why the deep stage did not run for it. `causal_graphs`
gives each package's causal graph, only when the graph hashes to the digest its evidence names
(`causal_graph._digest`); a graph that does not is left out, and the view says `digest_checked: false`.

Every value is copied from the verdict (or is the length of one of its lists); nothing here decides anything.
Kept apart from `api.py`, which only copies and publishes (it neither hashes nor imports the graph code).
"""
from __future__ import annotations

from backend.cavr.causal_graph import _digest as graph_digest, activation_text
from backend.cavr.pipeline import ESCALATION


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _affected_count(advisories: list):
    """As `api._affected_count`: None unless OSV answered for every package."""
    if not advisories or any(advisory.get("advisory_count") is None for advisory in advisories):
        return None
    return sum(len(_list(advisory.get("affected"))) for advisory in advisories)


FAST_STAGES = (("artifact", "Artifact SHA-256"), ("tree", "Dependency tree"), ("advisories", "OSV advisories"),
               ("cache", "Verdict cache"), ("contract", "Capability contract"), ("scan", "AST scan"),
               ("reachability", "Sink reachability"))
RUN_FIELDS = ("n", "kind", "spec_id", "rule", "completed", "elapsed_seconds", "deadline_seconds", "container",
              "trace_sha256", "trace_lines", "new_events", "home_removed")


def package_views(verdict: dict) -> list[dict]:
    """For each package of the verdict: its fast-gate stages with their rules, and its deep block or why there is none.

    Every value is copied from the verdict (or is the length of one of its lists); nothing is computed here.
    """
    return [_package_view(package) for package in _list(verdict.get("packages")) if isinstance(package, dict)]


def _package_view(package: dict) -> dict:
    evidence, cache = _dict(package.get("evidence")), _dict(package.get("cache"))
    advisories = [item for item in _list(evidence.get("advisories")) if isinstance(item, dict)]
    scans = [item for item in _list(evidence.get("scan")) if isinstance(item, dict)]
    rules = {"artifact": _dict(evidence.get("artifact")).get("rule"), "tree": _dict(evidence.get("tree")).get("rule"),
             "advisories": ", ".join(sorted({str(a.get("rule")) for a in advisories})) or None,
             "cache": cache.get("lookup"), "contract": _dict(evidence.get("contract")).get("rule"),
             "scan": ", ".join(sorted({str(scan.get("rule")) for scan in scans})) or None,
             "reachability": _dict(evidence.get("reachability")).get("rule")}
    reasons = {"artifact": _dict(evidence.get("artifact")).get("reason"), "tree": _dict(evidence.get("tree")).get("reason"),
               "cache": cache.get("reason"), "contract": _dict(evidence.get("contract")).get("reason"),
               "reachability": _dict(evidence.get("reachability")).get("reason")}
    fast = [{"id": stage, "title": title, "rule": rules[stage], "reason": reasons.get(stage),
             "affected": _affected_count(advisories) if stage == "advisories" else None} for stage, title in FAST_STAGES]
    deep = _deep_view(evidence.get("deep"))
    if deep is not None:
        not_run = None
    elif package.get("escalation") == ESCALATION:
        not_run = "not run: the package was escalated, but this run had no deep analyzer (the dashboard's live runs use the fast gate only)"
    else:
        not_run = (f"not run: the fast gate did not escalate this package ({package.get('status')} "
                   f"{package.get('stage')} / {package.get('rule')})")
    return {"package": package.get("package"), "version": package.get("version"), "status": package.get("status"),
            "stage": package.get("stage"), "rule": package.get("rule"), "reason": package.get("reason"),
            "escalation": package.get("escalation"), "fast": fast, "deep": deep, "deep_not_run": not_run}


def _deep_view(deep):
    """The deep block of one package (`sandbox_deep` evidence), copied; None when the deep stage did not run for it."""
    if not isinstance(deep, dict):
        return None
    evidence = _dict(deep.get("evidence"))
    graph = _dict(evidence.get("causal_graph"))
    specs = {node.get("spec"): [str(c) for c in _list(node.get("canaries"))] for node in _list(graph.get("nodes"))
             if isinstance(node, dict) and node.get("kind") == "spec"}
    runs = [{**{key: run.get(key) for key in RUN_FIELDS},
             "activation": activation_text(run.get("activation")) if run.get("activation") else None,
             "judged": _dict(run.get("judged")).get("result"), "judged_rule": _dict(run.get("judged")).get("rule"),
             "canaries": specs.get(run.get("spec_id"), [])}
            for run in _list(evidence.get("runs")) if isinstance(run, dict)]
    triggers = [{key: trigger.get(key) for key in ("id", "package", "file", "line", "predicate", "risk", "simulable",
                                                  "outcome", "run", "capabilities")}
                | {"activation": activation_text(trigger.get("activation")) if trigger.get("activation") else None}
                for trigger in _list(evidence.get("triggers")) if isinstance(trigger, dict)]
    frontier, loop = _dict(evidence.get("frontier")), _dict(evidence.get("loop"))
    used = _dict(loop.get("budget_used"))
    key_events = [event for event in _list(evidence.get("key_events")) if isinstance(event, dict)]
    causal = _dict(evidence.get("causal"))
    return {
        "status": deep.get("status"), "rule": deep.get("rule"), "reason": deep.get("reason"),
        "elapsed_seconds": deep.get("elapsed_seconds"), "image_id": evidence.get("image_id"), "claim": evidence.get("claim"),
        "runs": runs, "triggers": triggers,
        "frontier": {key: frontier.get(key) for key in ("rule", "reason", "total", "dropped", "other_guards_count", "now")},
        "other_guards": _list(frontier.get("other_guards")), "unexplored_guards": _list(evidence.get("unexplored_guards")),
        "drives": evidence.get("drives"),
        "budget": {"runs": used.get("runs"), "runs_limit": used.get("runs_limit"), "seconds": used.get("seconds"),
                   "package_seconds": used.get("package_seconds"), "planned_runs": loop.get("planned_runs"),
                   "stop": loop.get("stop"), "stop_reason": loop.get("stop_reason")},
        "residual": evidence.get("residual"), "escalation_reasons": _list(evidence.get("escalation_reasons")),
        "key_events": key_events, "not_exercised": _list(evidence.get("not_exercised")),
        "leaks": [event for event in key_events if event.get("type") == "CANARY_EXFIL_ATTEMPT"],
        "causal": {"digest": causal.get("digest"), "counts": causal.get("counts"), "cause": causal.get("cause"),
                   "error": causal.get("error"), "digest_checked": _graph_ok(graph, causal.get("digest"))},
    }


def _graph_ok(graph: dict, digest) -> bool:
    """True when the graph is there and its content hashes to the digest the evidence names."""
    try:
        return bool(graph) and isinstance(digest, str) and graph.get("digest") == digest and graph_digest(graph) == digest
    except Exception:
        return False


def causal_graphs(verdict: dict) -> dict:
    """"name==version" -> causal graph, for each package whose graph hashes to its digest. A graph that does not is left out."""
    out = {}
    for package in _list(verdict.get("packages")):
        evidence = _dict(_dict(_dict(package).get("evidence")).get("deep")).get("evidence")
        evidence = _dict(evidence)
        graph = _dict(evidence.get("causal_graph"))
        if _graph_ok(graph, _dict(evidence.get("causal")).get("digest")):
            out[f"{package.get('package')}=={package.get('version')}"] = graph
    return out
