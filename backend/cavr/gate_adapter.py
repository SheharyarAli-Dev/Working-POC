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
own default (live PyPI, live OSV). `repair` (default True) turns the repair proposal on or off. `deep` is the deep analyzer for escalated packages (PR 2 of
docs/cavr-m2-plan.md); None, the default until the sandbox exists, means no deep stage.
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
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from backend.cavr.manifest_parser import snapshot_requirements
from backend.cavr.pipeline import verify_request
from backend.cavr.repair_proposal import no_repair, propose_repair
from backend.cavr.storage import CavrStorage
from backend.cavr.verdict_cache import KEY_FIELDS

SETTINGS = {"transport": None, "osv": None, "advisory_cache_dir": None, "live_advisories": True, "deep": None, "repair": True}
STATUS_MAP = {"VERIFIED": "VERIFIED", "REJECTED": "REJECTED", "BLOCK": "REJECTED"}
UNSUPPORTED_MANIFESTS = ("poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "package.json",
                         "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
ADVISORY_FIELDS = ("name", "version", "result", "rule", "mode", "advisory_count", "response_sha256", "retrieved_at")
BOUNDED = "M1 fast gate: artifact hash, dependency tree, advisories, capability contract and AST sink scan; no deep runtime analysis (M2)"


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


def _repair(verdict, package, project, policy, requirements_file, data_root, context, settings):
    """The repair block of one REJECTED package; never raises and never changes the verdict."""
    try:
        return propose_repair(verdict, package, project_dir=project, policy=policy, requirements_file=requirements_file,
                              transport=settings.get("transport"), osv=settings.get("osv"),
                              advisory_cache_dir=settings.get("advisory_cache_dir") or data_root / "advisories",
                              live_advisories=settings.get("live_advisories", True), knowledge=context.knowledge,
                              work_dir=data_root / "repair")
    except Exception as exc:
        return no_repair(package.get("package"), package.get("version"), package, "INTERNAL_ERROR",
                         f"repair failed: {type(exc).__name__}: {exc}")


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
                                 deep=settings.get("deep"))
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
                   "repair": None}
            if package.get("status") == "REJECTED" and settings.get("repair", True):
                row["repair"] = _repair(verdict, package, project, policy, name, data_root, context, settings)
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
    status, details = _result(status, reason, pipeline, nodes)
    return status, details, reasons + [BOUNDED]
