"""CAVR in a gate run: the M1 pipeline (`pipeline.verify_request`) on the project's requirements files.

`analyze_pipeline(context, store, outdir, emit, settings=None)` has the return shape of
`analyzer.analyze` (status, details, uncertainty), so the orchestrator publishes it like any other
CAVR evidence. `analyzer.analyze` calls it for every run: gate runs with `SETTINGS`, demo and
scenario runs with `analyzer.DEMO_SETTINGS` (PR 1 of docs/cavr-m2-plan.md).

Inputs, all from the run: the base config's CAVR section and policy (`context.config`), the head
commit's files (`context.path`, always passed explicitly, never the dashboard's sample project),
and the threat-repository snapshot (`context.knowledge`). Per configured requirements file:

    verify "all"      `pip install -r <file>` in head: every requirement is verified
    verify "changed"  the base -> head edit of that file: only added or changed requirements

Each verdict is mapped onto the orchestrator's CAVR statuses (`map_status`):

    pipeline VERIFIED            -> VERIFIED     pass
    pipeline REJECTED or BLOCK   -> REJECTED     block (BLOCK = refused by the requirement gate)
    UNRESOLVED or anything else  -> UNRESOLVED   review

The module result is REJECTED if any file is REJECTED, else UNRESOLVED if any is not VERIFIED,
else VERIFIED. A dependency manifest the pipeline cannot read (pyproject dependencies, Poetry,
Pipenv, setup.py, npm) is UNRESOLVED: those dependencies would otherwise pass unseen.

`SETTINGS` replaces the outside world in tests (PyPI transport, OSV); None means the pipeline's
own default (live PyPI, live OSV). `repair` (default True) turns the repair proposal on or off. `deep` is the deep
analyzer for escalated packages (PR 2 of docs/cavr-m2-plan.md): "sandbox" (the default, PR 9) makes one
`sandbox_deep.SandboxDeepAnalyzer` for this gate run when the CAVR sandbox image passes its identity check, and
none otherwise (no Docker, no image, a mismatch: the escalated package stays UNRESOLVED, as before); None means no
deep stage; any other value is used as the analyzer. `details["deep_stage"]` says which, and each row's `deep` is the
package's deep result (status, rule, reason, image ID, trace and baseline SHA-256, key events), or None.
A `settings` argument is used instead of `SETTINGS` when given.

Each package row carries what the orchestrator's assurance report reads: `sha256`, `artifact` (the
wheel's file name), `escalation`, `tree_nodes`, `advisories` (one line per OSV answer), and the
contract with `required` (the allowed
capabilities the project's call sites need), `denied`, `confidence` (the contract's rule, e.g.
CONTRACT_INFERRED; demo-lab rows keep the older 'rule-grounded' / 'insufficient') and `authority`. The verdict cache, quarantine and advisory cache live in the
run store's data directory, so a gate run never touches the dashboard's database.

Every row also has `repair`: None unless the package is REJECTED, else the block of
`repair_proposal.propose_repair` (a proposed pin and / or removal for a person to approve, or
"no repair found"). It is extra information: the row's status, the module status, the reasons and
the events are computed exactly as without it, and a failure inside repair is NO_REPAIR_FOUND.

Repair budget per gate run: `REPAIR_RUN_SECONDS` (120 s) of time spent in repair, summed over all REJECTED
packages of the run (verification time does not count), on top of each package's own budget
(`repair_proposal.BUDGET_SECONDS`, 60 s), which is cut to what is left of the run.
Once the run's budget is used up, every further REJECTED package gets NOT_ATTEMPTED / RUN_BUDGET_USED_UP.
Like the package budget it is checked before a package starts; a repair already running is not stopped.
`CLOCK` is the run's clock (seconds), replaced in tests.
"""
from __future__ import annotations

import time
import tomllib
from pathlib import Path

from backend.cavr.causal_graph import activation_text
from backend.cavr.manifest_parser import snapshot_requirements
from backend.cavr.pipeline import ESCALATION, verify_request
from backend.cavr.repair_proposal import BUDGET_SECONDS, no_repair, not_attempted, propose_repair
from backend.cavr.storage import CavrStorage
from backend.cavr.verdict_cache import KEY_FIELDS

SETTINGS = {"transport": None, "osv": None, "advisory_cache_dir": None, "live_advisories": True, "deep": "sandbox",
            "repair": True}
STATUS_MAP = {"VERIFIED": "VERIFIED", "REJECTED": "REJECTED", "BLOCK": "REJECTED"}
UNSUPPORTED_MANIFESTS = ("poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "package.json",
                         "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
ADVISORY_FIELDS = ("name", "version", "result", "rule", "mode", "advisory_count", "response_sha256", "retrieved_at")
REPAIR_RUN_SECONDS = 120.0
RUN_BUDGET_USED_UP = "repair budget for this run used up"
CLOCK = time.monotonic
BOUNDED = "M1 fast gate: artifact hash, dependency tree, advisories, capability contract and AST sink scan; no deep runtime analysis (M2)"
BOUNDED_DEEP = ("fast gate (artifact hash, dependency tree, advisories, capability contract, AST sink scan) and, for "
                "escalated packages, the counterfactual activation loop in the CAVR sandbox (a canary-only run and one "
                "run per trigger of the frontier, at most 8 runs; install, import, and the project's literal-only call "
                "sites called); call sites with computed arguments and code outside the scanned source are not exercised")
DEEP_ROW = ("status", "rule", "reason", "elapsed_seconds")
DEEP_EVIDENCE = ("image_id", "trace_sha256", "trace_lines", "trace_check", "run_rule", "decisive_run", "key_events",
                 "escalation_reasons", "claim", "not_exercised", "runs", "triggers", "residual", "unexplored_guards",
                 "drives", "loop", "causal", "causal_graph")


def map_status(status) -> str:
    return STATUS_MAP.get(status, "UNRESOLVED")


def _unsupported(context) -> list[str]:
    found = [name for name in UNSUPPORTED_MANIFESTS if name in context.manifest]
    if "pyproject.toml" in context.manifest:
        try:
            data = tomllib.loads(context.read("pyproject.toml"))
        except (tomllib.TOMLDecodeError, ValueError):
            found.append("pyproject.toml (unreadable)")
        else:
            project = data.get("project") or {}
            poetry = ((data.get("tool") or {}).get("poetry") or {})
            poetry_deps = {k for k in (poetry.get("dependencies") or {}) if k.lower() != "python"}
            if project.get("dependencies") or project.get("optional-dependencies") or poetry_deps or poetry.get("group"):
                found.append("pyproject.toml")
    return found


def _result(status, reason, pipeline=None, nodes=None, extra=None):
    details = {"engine": "pipeline", "reason": reason, "pipeline": pipeline or [], "nodes": nodes or [],
               "cache_key_fields": list(KEY_FIELDS), **(extra or {})}
    return status, details


def _row_contract(contract: dict) -> dict:
    """The package's contract, plus the names the orchestrator report reads (`required`, `confidence`)."""
    if not contract:
        return {}
    required = [f"{entry['capability']}({entry['scope']})" for entry in contract.get("allowed") or []
                if entry.get("status") == "REQUIRED"]
    return {**contract, "required": required, "confidence": contract.get("rule")}


def _deep_row(evidence: dict):
    """The package's deep result for the report, or None when the deep stage did not run for it."""
    deep = evidence.get("deep")
    if not isinstance(deep, dict):
        return None
    inner = deep.get("evidence") or {}
    row = {key: deep.get(key) for key in DEEP_ROW}
    row.update({key: inner.get(key) for key in DEEP_EVIDENCE})
    row["baseline_sha256"] = (inner.get("baseline") or {}).get("sha256")
    return row


# The fields of the orchestrator's assurance report (`asent.assurance.v1`) that read the LOCAL lab before Step M2-18
# (PR 19). `assurance_fields` fills them from the CAVR rows' deep results.
ASSURANCE_FIELDS = ("discovered_triggers", "triggered_conditions", "exercised_conditions", "unresolved_conditions",
                    "execution_modes", "observed_security_events", "causal_evidence")
NO_PACKAGE = "CAVR checked no package in this run"
RUN_KEYS = ("n", "kind", "spec_id", "rule", "completed", "elapsed_seconds", "container")


def assurance_fields(evidence: list) -> dict:
    """The seven lab fields of the assurance report, from the CAVR evidence records' package rows. Never raises.

    Each field is one entry per package: {"package": "name==version", ...the package's deep data...}, or
    {"package", "not_available": why} when the deep stage did not run for it. With no CAVR package row at all each
    field is [{"not_available": NO_PACKAGE}]: never an empty list, and never a value that was not observed.
    """
    fields = {name: [] for name in ASSURANCE_FIELDS}
    for record in evidence or []:
        if not isinstance(record, dict) or record.get("analyzer") != "CAVR":
            continue
        details = record.get("details") if isinstance(record.get("details"), dict) else {}
        stage = details.get("deep_stage") if isinstance(details.get("deep_stage"), dict) else {}
        for row in details.get("nodes") or []:
            if isinstance(row, dict):
                for name, entry in _package_fields(row, stage).items():
                    fields[name].append(entry)
    return {name: entries or [{"not_available": NO_PACKAGE}] for name, entries in fields.items()}


def _package_fields(row: dict, stage: dict) -> dict:
    package = f"{row.get('name')}=={row.get('version')}"
    deep = row.get("deep")
    if not isinstance(deep, dict):
        if row.get("escalation") == ESCALATION:
            why = f"escalated, but {stage.get('reason') or 'no deep analyzer was given'}"
        else:
            why = f"the fast gate did not escalate this package ({row.get('status')} {row.get('rule')})"
        return {name: {"package": package, "not_available": f"the deep stage did not run: {why}"} for name in ASSURANCE_FIELDS}
    items = lambda key: [item for item in (deep.get(key) if isinstance(deep.get(key), list) else []) if isinstance(item, dict)]
    text = lambda activation: activation_text(activation) if isinstance(activation, dict) else None
    triggers, runs = items("triggers"), items("runs")
    causal = deep.get("causal") if isinstance(deep.get("causal"), dict) else {}
    return {
        "discovered_triggers": {"package": package, "triggers": triggers},
        "triggered_conditions": {"package": package, "conditions": [
            {key: trigger.get(key) for key in ("id", "file", "line", "predicate", "risk", "run")}
            | {"activation": text(trigger.get("activation"))} for trigger in triggers if trigger.get("outcome") == "explored"]},
        "exercised_conditions": {"package": package, "runs": [
            {key: run.get(key) for key in RUN_KEYS} | {"activation": text(run.get("activation"))} for run in runs]},
        "unresolved_conditions": {"package": package, "residual": deep.get("residual"),
                                  "unexplored_guards": items("unexplored_guards"),
                                  "not_exercised": [item for item in deep.get("not_exercised") or [] if isinstance(item, str)]
                                  if isinstance(deep.get("not_exercised"), list) else []},
        "execution_modes": {"package": package, "mode": "CAVR sandbox (deep stage)", "image_id": deep.get("image_id"),
                            "runs": len(runs), "elapsed_seconds": deep.get("elapsed_seconds")},
        "observed_security_events": {"package": package, "events": items("key_events")},
        "causal_evidence": {"package": package, **{key: causal.get(key) for key in ("digest", "counts", "cause", "error")}},
    }


def _deep_analyzer(settings, data_root):
    """(analyzer or None, details["deep_stage"] or None)."""
    deep = settings.get("deep")
    if deep != "sandbox":
        return deep, None
    from backend.cavr.sandbox_deep import for_gate_run
    return for_gate_run(data_root)


def _repair(verdict, package, project, policy, requirements_file, data_root, context, settings, spent):
    """The repair block of one REJECTED package; never raises and never changes the verdict.

    `spent` is a one-item list: the seconds this run has spent in repair so far (only repair time counts).
    """
    left = REPAIR_RUN_SECONDS - spent[0]
    if left <= 0:
        return not_attempted(package.get("package"), package.get("version"), package, "RUN_BUDGET_USED_UP",
                             RUN_BUDGET_USED_UP)
    started = CLOCK()
    try:
        return propose_repair(verdict, package, project_dir=project, policy=policy, requirements_file=requirements_file,
                              budget_seconds=min(BUDGET_SECONDS, left), clock=CLOCK,
                              transport=settings.get("transport"), osv=settings.get("osv"),
                              advisory_cache_dir=settings.get("advisory_cache_dir") or data_root / "advisories",
                              live_advisories=settings.get("live_advisories", True), knowledge=context.knowledge,
                              work_dir=data_root / "repair")
    except Exception as exc:
        return no_repair(package.get("package"), package.get("version"), package, "INTERNAL_ERROR",
                         f"repair failed: {type(exc).__name__}: {exc}")
    finally:
        spent[0] += CLOCK() - started


def analyze_pipeline(context, store, outdir, emit, settings=None):
    settings = SETTINGS if settings is None else settings
    config = getattr(context, "config", None)
    cavr = config.module("CAVR") if config is not None and config.valid else None
    policy = (config.documents.get("cavr_policy") if cavr is not None else None)
    if cavr is None or not cavr.enabled or policy is None:
        status, details = _result("UNRESOLVED", "no usable CAVR section and policy in the base .asent/ config")
        return status, details, ["CAVR configuration unavailable"]

    present = [name for name in cavr.requirements_files if name in context.manifest]
    missing = [name for name in cavr.requirements_files if name not in context.manifest]
    unsupported = _unsupported(context)
    problems = []
    if missing:
        problems.append("configured requirements file not in this commit: " + ", ".join(missing))
    if unsupported:
        problems.append("unsupported manifest (its dependencies are not verified): " + ", ".join(unsupported))
    if not present:
        status, details = _result("UNRESOLVED", "; ".join(problems) or "no requirements file to verify")
        return status, details, problems

    data_root = Path(getattr(store, "root", Path(outdir).parent)) / "cavr"
    cavr_store = CavrStorage(data_root / "cavr.sqlite3")
    project = Path(context.path)
    pipeline, nodes = [], []
    repair_spent = [0.0]   # seconds spent in repair in this run, against REPAIR_RUN_SECONDS
    deep, deep_stage = _deep_analyzer(settings, data_root)  # one per gate run: its 300 s cap is this run's
    for name in present:
        if cavr.verify == "changed":
            before, after = snapshot_requirements(Path(context.baseline) / name), snapshot_requirements(project / name)
            before["path"] = after["path"] = name
            request = {"requirements_edit": {"before": before, "after": after}}
            shown = f"requirements edit of {name} (base -> head)"
        else:
            request = ["pip", "install", "-r", name]
            shown = "pip install -r " + name
        emit("dependency.intercepted", {"source": "gate: " + shown, "file": name})
        verdict = verify_request(request, project, policy, cavr_store,
                                 transport=settings.get("transport"), osv=settings.get("osv"),
                                 quarantine_dir=data_root / "quarantine",
                                 advisory_cache_dir=settings.get("advisory_cache_dir") or data_root / "advisories",
                                 live_advisories=settings.get("live_advisories", True), knowledge=context.knowledge,
                                 deep=deep)
        entry = {"file": name, "request": shown, "status": verdict.get("status"), "mapped": map_status(verdict.get("status")),
                 "stage": verdict.get("stage"), "rule": verdict.get("rule"), "reason": verdict.get("reason"),
                 "policy_version": verdict.get("policy_version"), "analyzer_version": verdict.get("analyzer_version"),
                 "packages": []}
        for package in verdict.get("packages") or []:
            keys = package.get("key_fields") or {}
            evidence = package.get("evidence") or {}
            artifact = evidence.get("artifact") or {}
            tree = evidence.get("tree") or {}
            row = {"engine": "pipeline", "name": package.get("package"), "version": package.get("version"),
                   "status": package.get("status"), "mapped": map_status(package.get("status")), "stage": package.get("stage"),
                   "rule": package.get("rule"), "reason": package.get("reason"), "cache_hit": package.get("cache_hit"),
                   "key_fields": package.get("key_fields"), "cache": package.get("cache"),
                   "sha256": keys.get("artifact_sha256") or artifact.get("sha256"), "artifact": artifact.get("filename"),
                   "escalation": package.get("escalation"),
                   "tree_nodes": [{"name": n.get("name"), "version": n.get("version"), "sha256": n.get("sha256")}
                                  for n in tree.get("nodes") or []],
                   "advisories": [{key: advisory.get(key) for key in ADVISORY_FIELDS} for advisory in evidence.get("advisories") or []],
                   "contract": _row_contract(evidence.get("contract") or {}),
                   "deep": _deep_row(evidence),
                   "repair": None}
            if package.get("status") == "REJECTED" and settings.get("repair", True):
                row["repair"] = _repair(verdict, package, project, policy, name, data_root, context, settings, repair_spent)
            entry["packages"].append(row)
            nodes.append(row)
        emit("cavr.pipeline_verdict", {k: entry[k] for k in ("file", "status", "mapped", "stage", "rule", "reason")})
        pipeline.append(entry)

    mapped = [entry["mapped"] for entry in pipeline]
    status = "REJECTED" if "REJECTED" in mapped else "UNRESOLVED" if any(m != "VERIFIED" for m in mapped) else "VERIFIED"
    if problems and status == "VERIFIED":
        status = "UNRESOLVED"
    reasons = [f"{e['file']}: {e['status']} {e['rule']}: {e['reason']}" for e in pipeline if e["mapped"] != "VERIFIED"] + problems
    reason = "; ".join(reasons) if reasons else "; ".join(f"{e['file']}: {e['reason']}" for e in pipeline)
    status, details = _result(status, reason, pipeline, nodes, {"deep_stage": deep_stage} if deep_stage else None)
    return status, details, reasons + [BOUNDED_DEEP if deep is not None else BOUNDED]
