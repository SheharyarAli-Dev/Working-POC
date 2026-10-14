"""The orchestrator's CAVR analyzer: `POST /api/runs` -> `Service._module` -> `analyze` -> `final_gate.decide`.

Every dependency decision comes from `pipeline.verify_request`, the M1 path (C1 capture, C2 gate,
C3 artifact / tree / advisories / AST scan, C4 contract, 8-field verdict cache). This module turns
the frozen candidate into a request, and the verdict into the status the final gate reads:

    pipeline VERIFIED    -> VERIFIED     final gate: ACCEPT, when the other modules accept too
    pipeline REJECTED    -> REJECTED     final gate: BLOCK
    pipeline BLOCK       -> REJECTED     final gate: BLOCK
    pipeline UNRESOLVED  -> UNRESOLVED   final gate: REVIEW
    anything else, or an exception      -> UNRESOLVED

BLOCK is passed on as REJECTED because, for CAVR, the final gate blocks only on REJECTED
(`final_gate.BLOCKING`, and the `blocking` flag set in `Service._module`); both are orchestrator
files. `details["pipeline_status"]` keeps the pipeline's own word.

The request is `pip install -r requirements.txt` in the candidate. Around it, three more checks can
turn a VERIFIED verdict into UNRESOLVED (they never turn anything into VERIFIED):

    LOCAL_ARTIFACT_UNVERIFIED  a lockfile entry with ecosystem LOCAL (a vendored file, not on PyPI):
                               M1 has no verdict for it; the sandbox that judged it is M2
    LOCKED_NOT_VERIFIED        a locked PyPI entry that is neither requested nor in the tree of
                               a requested package, so the verdict says nothing about it
    rule coverage              a seed behaviour or trigger rule of the threat repository is disabled
                               or narrowed, so the scan is weaker than the one the pipeline was tested with

The policy is the project's `policy.json` `dependencies` section, translated by `gate_policy`.
Nothing here runs package code; the M2 sandbox analysis is `m2_deep_analyzer.py` and is not imported.
"""
from __future__ import annotations
import threading
import time
from pathlib import Path

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name, canonicalize_version
from packaging.version import InvalidVersion, Version

from backend.cavr.pipeline import ESCALATION, LOCKFILE_NAME, verify_request
from backend.cavr.requirement_gate import load_json_file
from backend.cavr.storage import CavrStorage
from backend.threat_repo.repository import active, seeds

# The outside world. None / True is the real PyPI and the live OSV API; tests replace them (tests/conftest.py).
TRANSPORT = None
LIVE_ADVISORIES = True
ADVISORY_CACHE_DIR = None    # None: <service root>/cavr/advisories
QUARANTINE_DIR = None        # None: <service root>/cavr/quarantine

REQUEST = ["pip", "install", "-r", "requirements.txt"]
MODULE_STATUS = {"VERIFIED": "VERIFIED", "REJECTED": "REJECTED", "BLOCK": "REJECTED", "UNRESOLVED": "UNRESOLVED"}
# Policy flag -> the capability it denies when it is false. A true flag names no scope, so it grants nothing.
DENIAL_FLAGS = {"allow_network": "NETWORK_CONNECT", "allow_process": "PROCESS_EXEC", "allow_secret": "SECRET_READ"}
_STORES = {}                 # one CavrStorage per database file: its set-up must not run twice at once
_STORES_GUARD = threading.Lock()
CLAIM = "M1 fast gate: PyPI wheels, hashes, tree, advisories, AST scan and contract; no package code is run (deep analysis is M2)"


def analyze(context, store, outdir, emit):
    """(status, details, uncertainty) for the candidate in `context`. `outdir` is unused: nothing is executed."""
    started = time.perf_counter()
    try:
        return _analyze(context, store, emit, started)
    except Exception as exc:  # a fault is "unknown", never a pass
        reason = f"CAVR could not finish: {type(exc).__name__}: {exc}"
        return "UNRESOLVED", {"pipeline_status": None, "pipeline": None, "nodes": [], "lock_entries": [], "rule_coverage": [],
                              "reason": reason, "total_ms": _ms(started)}, [reason]


def gate_policy(project_policy):
    """The pipeline policy for a project policy.json, or None when it has no usable `dependencies.allowed`.

    `allowed` holds bare names: each becomes an approved requirement without a version specifier,
    so the gate's other rules decide the version (pinned with `==`, and in the lockfile).
    """
    dependencies = project_policy.get("dependencies") if isinstance(project_policy, dict) else None
    allowed = dependencies.get("allowed") if isinstance(dependencies, dict) else None
    purpose = dependencies.get("purpose", "") if isinstance(dependencies, dict) else None
    if not isinstance(allowed, list) or not isinstance(purpose, str):
        return None
    names = []
    for entry in allowed:
        try:
            requirement = Requirement(entry) if isinstance(entry, str) else None
        except InvalidRequirement:
            requirement = None
        if requirement is None or str(requirement) != requirement.name:  # a bare name only
            return None
        names.append(canonicalize_name(requirement.name))
    return {"source": "policy.json dependencies", "approved_requirements": sorted(set(names)), "denied_packages": [],
            "project_task_description": purpose,
            "allowed_scopes": [f"{capability}:none" for flag, capability in sorted(DENIAL_FLAGS.items())
                               if dependencies.get(flag) is False]}


def rule_coverage(knowledge) -> list[str]:
    """One line per seed behaviour / trigger rule that the current threat repository no longer fully holds."""
    current = {rule["id"]: rule for category in ("behaviors", "triggers") for rule in active(knowledge, category)}
    problems = []
    for required in seeds():
        if required["category"] not in ("behaviors", "triggers"):
            continue
        field = "python_sinks" if required["category"] == "behaviors" else "match_calls"
        rule = current.get(required["id"])
        if not rule or not set(required["data"].get(field, [])) <= set(rule["data"].get(field, [])):
            problems.append("Required rule coverage unavailable: " + required["id"])
    return problems


# --- internals ---------------------------------------------------------------

def _analyze(context, store, emit, started):
    root = Path(store.root) / "cavr" if hasattr(store, "root") else None
    emit("dependency.intercepted", {"request": " ".join(REQUEST), "source": "candidate requirements.txt; nothing is installed"})
    verdict = verify_request(REQUEST, context.path, gate_policy(context.policy),
                             _storage(store),
                             transport=TRANSPORT, live_advisories=LIVE_ADVISORIES, knowledge=context.knowledge,
                             quarantine_dir=QUARANTINE_DIR or (root / "quarantine" if root else None),
                             advisory_cache_dir=ADVISORY_CACHE_DIR or (root / "advisories" if root else None))

    problems = []
    pipeline_status = verdict.get("status") if isinstance(verdict, dict) else None
    packages = verdict.get("packages") if isinstance(verdict, dict) else None
    if pipeline_status not in MODULE_STATUS:
        problems.append(f"the pipeline returned no known verdict: {pipeline_status!r}")
    elif not isinstance(packages, list) or (pipeline_status == "VERIFIED" and not packages and _requested(verdict)):
        problems.append("the verdict does not list the packages it verified")
    packages = packages if isinstance(packages, list) else []
    for package in packages:
        kind = "cavr.cache_hit" if package["cache_hit"] else "cavr.fast_gate"
        emit(kind, {"package": package["package"], "version": package["version"], "cache_key": package["cache"]["key"]})

    lock = load_json_file(context.path / LOCKFILE_NAME)
    locked = lock.get("packages") if isinstance(lock, dict) and isinstance(lock.get("packages"), list) else []
    covered = _covered(packages) if pipeline_status == "VERIFIED" else None
    lock_entries = [_lock_entry(entry, covered, pipeline_status) for entry in locked]
    problems += [f"{e['name']}=={e['version']}: {e['reason']}" for e in lock_entries if e["status"] == "UNRESOLVED"]
    coverage = rule_coverage(context.knowledge)
    problems += coverage

    status = MODULE_STATUS.get(pipeline_status, "UNRESOLVED")
    if status == "VERIFIED" and problems:
        status = "UNRESOLVED"
    reasons = [] if pipeline_status == "VERIFIED" else [_pipeline_reason(verdict)]
    reason = "; ".join(reasons + problems) or verdict["reason"]
    emit("cavr.verdict", {"status": status, "pipeline_status": pipeline_status, "reason": reason,
                          "fast_gate_ms": verdict.get("fast_gate_ms") if isinstance(verdict, dict) else None})
    details = {"pipeline_status": pipeline_status, "pipeline": verdict if isinstance(verdict, dict) else None,
               "nodes": [_node(package) for package in packages], "lock_entries": lock_entries, "rule_coverage": coverage,
               "dependency_tree": {"nodes": [{"id": e["name"], "version": e["version"]} for e in lock_entries],
                                   "edges": lock.get("edges", []) if isinstance(lock, dict) else []},
               "reason": reason, "total_ms": _ms(started)}
    uncertainty = ([] if status == "VERIFIED" else reasons + problems) + [CLAIM]
    return status, details, uncertainty


def _storage(store):
    """The verdict cache and verdict log in the orchestrator's own database (`Store.path`), or None without one."""
    path = getattr(store, "path", None)
    if path is None:
        return None
    with _STORES_GUARD:
        if path not in _STORES:
            _STORES[path] = CavrStorage(path)
        return _STORES[path]


def _requested(verdict) -> bool:
    """Whether the gate let any requirement through (a VERIFIED with nothing requested lists no packages)."""
    gate = verdict.get("gate")
    return bool(isinstance(gate, dict) and gate.get("decisions"))


def _pipeline_reason(verdict) -> str:
    if not isinstance(verdict, dict):
        return f"the pipeline returned {type(verdict).__name__}, not a verdict"
    status, stage, rule = verdict.get("status"), verdict.get("stage"), verdict.get("rule")
    where = "requirement gate" if stage == "gate" else f"stage {stage}"
    return f"{where} {status} ({rule}): {verdict.get('reason')}"


def _release(name, version):
    """(canonical name, canonical version), or None when either cannot be read."""
    try:
        return canonicalize_name(name), canonicalize_version(Version(str(version)))
    except (TypeError, InvalidVersion):
        return None


def _covered(packages) -> set:
    """Every release a VERIFIED verdict speaks for: each requested package and each node of its tree."""
    covered = set()
    for package in packages:
        covered.add(_release(package["package"], package["version"]))
        tree = (package.get("evidence") or {}).get("tree") or {}
        covered |= {_release(node["name"], node["version"]) for node in tree.get("nodes", [])}
    return covered - {None}


def _lock_entry(entry, covered, pipeline_status) -> dict:
    """What the verdict says about one lockfile entry. `covered` is None when the verdict is not VERIFIED.

    UNRESOLVED is a problem of its own; NOT_VERIFIED only repeats the verdict, which already says why.
    """
    entry = entry if isinstance(entry, dict) else {}
    fields = {"name": entry.get("name"), "version": entry.get("version"), "ecosystem": entry.get("ecosystem", "PyPI")}

    def result(status, rule, reason, escalation=None):
        return {**fields, "status": status, "rule": rule, "reason": reason, "escalation": escalation}

    if fields["ecosystem"] == "LOCAL":
        return result("UNRESOLVED", "LOCAL_ARTIFACT_UNVERIFIED",
                      f"local artifact {entry.get('artifact')!r} is not on PyPI; M1 has no verdict for it (sandbox analysis is M2)",
                      ESCALATION)
    if fields["ecosystem"] != "PyPI":
        return result("UNRESOLVED", "UNSUPPORTED_ECOSYSTEM", f"ecosystem {fields['ecosystem']!r} is not verified by CAVR")
    if covered is None:
        return result("NOT_VERIFIED", "VERDICT_NOT_VERIFIED", f"the verdict of the request is {pipeline_status}")
    if _release(fields["name"], fields["version"]) in covered:
        return result("VERIFIED", "COVERED_BY_VERDICT", "requested, or in the tree of a requested package, and verified")
    return result("UNRESOLVED", "LOCKED_NOT_VERIFIED", "locked, but not requested and not in the tree of a requested package")


def _node(package: dict) -> dict:
    """One verified package in the shape `Service.report` reads (name, version, sha256, artifact)."""
    artifact = (package.get("evidence") or {}).get("artifact") or {}
    return {"name": package["package"], "version": package["version"], "status": package["status"],
            "stage": package["stage"], "rule": package["rule"], "reason": package["reason"],
            "sha256": artifact.get("sha256"), "artifact": artifact.get("filename"), "cache_hit": package["cache_hit"],
            "cache_key": package["cache"]["key"], "escalation": package["escalation"], "fast_gate_ms": package["fast_gate_ms"]}


def _ms(started) -> float:
    return round((time.perf_counter() - started) * 1000, 2)
