"""CAVR in a gate run: the M1 pipeline (`pipeline.verify_request`) on the project's requirements files.

`analyze_pipeline(context, store, outdir, emit)` has the return shape of `analyzer.analyze`
(status, details, uncertainty), so the orchestrator publishes it like any other CAVR evidence.
`analyzer.analyze` calls it for every gate run (`context.gate`); the older lockfile analyzer is
only reached by the built-in demo scenarios, and no project config can select it.

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
own default (live PyPI, live OSV). The verdict cache, quarantine and advisory cache live in the
run store's data directory, so a gate run never touches the dashboard's database.
"""
from __future__ import annotations

import tomllib
from pathlib import Path

from backend.cavr.manifest_parser import snapshot_requirements
from backend.cavr.pipeline import verify_request
from backend.cavr.storage import CavrStorage
from backend.cavr.verdict_cache import KEY_FIELDS

SETTINGS = {"transport": None, "osv": None, "advisory_cache_dir": None, "live_advisories": True}
STATUS_MAP = {"VERIFIED": "VERIFIED", "REJECTED": "REJECTED", "BLOCK": "REJECTED"}
UNSUPPORTED_MANIFESTS = ("poetry.lock", "uv.lock", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "package.json",
                         "package-lock.json", "yarn.lock", "pnpm-lock.yaml")
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


def analyze_pipeline(context, store, outdir, emit):
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
                                 transport=SETTINGS.get("transport"), osv=SETTINGS.get("osv"),
                                 quarantine_dir=data_root / "quarantine",
                                 advisory_cache_dir=SETTINGS.get("advisory_cache_dir") or data_root / "advisories",
                                 live_advisories=SETTINGS.get("live_advisories", True), knowledge=context.knowledge)
        entry = {"file": name, "request": shown, "status": verdict.get("status"), "mapped": map_status(verdict.get("status")),
                 "stage": verdict.get("stage"), "rule": verdict.get("rule"), "reason": verdict.get("reason"),
                 "policy_version": verdict.get("policy_version"), "analyzer_version": verdict.get("analyzer_version"),
                 "packages": []}
        for package in verdict.get("packages") or []:
            keys = package.get("key_fields") or {}
            row = {"name": package.get("package"), "version": package.get("version"), "status": package.get("status"),
                   "mapped": map_status(package.get("status")), "stage": package.get("stage"), "rule": package.get("rule"),
                   "reason": package.get("reason"), "cache_hit": package.get("cache_hit"), "key_fields": package.get("key_fields"),
                   "cache": package.get("cache"), "sha256": keys.get("artifact_sha256"),
                   "contract": (package.get("evidence") or {}).get("contract") or {}}
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
