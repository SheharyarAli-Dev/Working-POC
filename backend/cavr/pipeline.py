"""The one path from a request to a verdict: `verify_request(request, project_dir, policy, store)`.

A request is a `pip install ...` command, a requirements.txt edit, or a capture record. The
stages run in this order, and each one adds its result to the evidence:

    1. C1 capture           the request as a structured record                      (capture, manifest_parser)
    2. C2 requirement gate  policy / allowlist / lockfile; BLOCK stops here,
                            before anything is downloaded                           (requirement_gate)
    3. C3a artifact         download the real wheel, SHA-256 of the bytes on disk
                            against the registry digest                             (pypi_client)
    4. C3b tree             every dependency from real Requires-Dist, each one
                            downloaded and hashed; subtree digest                   (dep_tree)
    5. C4 contract          the project's imports and call sites, what is allowed   (capability_contract)
    6. cache lookup         on the 8-field key, which needs 3, 4 and 5              (verdict_cache)
    7. advisories           OSV, for every package of the tree, on every run        (advisories)
    8. AST scan             cache miss only; sinks judged against the contract
                            and against call-site reachability                      (ast_scan, reachability)
    9. verdict              VERIFIED / REJECTED / UNRESOLVED, or BLOCK from stage 2

Rules of the verdict:

- REJECTED when the downloaded bytes do not match the registry, a wheel is unsafe, or OSV
  lists the version (of the package or of anything in its tree) as affected.
- UNRESOLVED when anything is unknown: the request, the policy, the network, a dependency
  that is not pinned, a project that cannot be read, a package the project never uses, code
  the scan cannot read. Nothing unknown ever becomes VERIFIED.
- A sensitive sink in a wheel is evidence, not a failure, unless the contract does not allow
  its capability outright (it is denied, or granted only for a scope the scan cannot check)
  and the project's call sites can reach it. Then the verdict is UNRESOLVED and carries
  `escalation: "deep analysis required (M2)"`.
- Only the analysis of stage 8 is cached, and only when it is VERIFIED or REJECTED. The
  advisory result is never cached: a cached VERIFIED becomes REJECTED the day OSV lists the
  version, and VERIFIED again if the advisory is withdrawn.
- Several requirements in one request: REJECTED if any is REJECTED, else UNRESOLVED if any
  is UNRESOLVED, else VERIFIED. The same release asked for twice is verified once when both
  lines are identical; when their extras, `--hash` values or markers differ it is UNRESOLVED.

Every verdict, whatever its status, has `fast_gate_ms` (wall time of this call), `cache_hit`
(every package's analysis came from the cache) and `escalated`. One row per call goes to the
store's verdict log; `metrics(store)` gives the cache hit rate and the p50 / p95 of
`fast_gate_ms` per status and per cache lookup (never one percentile over all verdicts).

No stage installs, imports or runs package code.
"""
from __future__ import annotations
import hashlib
import time
from pathlib import Path
from types import SimpleNamespace

from packaging.utils import canonicalize_version
from packaging.version import InvalidVersion, Version

from backend.config import DATA
from backend.cavr.advisories import check_advisories
from backend.cavr.ast_scan import ANALYZER_VERSION as SCAN_VERSION, scan_wheel
from backend.cavr.capability_contract import infer_capability_contract
from backend.cavr.capture import parse_pip_command, redact
from backend.cavr.context_extractor import extract_project_context
from backend.cavr.dep_tree import build_tree
from backend.cavr.manifest_parser import capture_requirements_edit
from backend.cavr.reachability import judge_sinks
from backend.cavr.requirement_gate import evaluate_capture, load_json_file, policy_problems, policy_version
from backend.cavr.verdict_cache import CACHEABLE, lookup, store as store_verdict
from backend.orchestrator.hashing import digest
from backend.threat_repo.behavior_rules import python_sinks
from backend.threat_repo.repository import seeds

PIPELINE_VERSION = "cavr-pipeline/2"  # /2: the sink judgement changed after the review of steps 9-11
ESCALATION = "deep analysis required (M2)"
LOCKFILE_NAME = "dependencies.lock.json"
PASSED = ("verdict", "ALL_CHECKS_PASSED")
ANALYSIS_KEYS = {"status", "stage", "rule", "reason", "escalation", "scan", "reachability"}  # what `_analyse` returns
MAX_LOGGED_REQUEST = 500
STATUSES = ("VERIFIED", "REJECTED", "BLOCK", "UNRESOLVED")   # the order the report lists them in
CACHE_LOOKUPS = ("HIT", "MISS", "NOT_REACHED")


def verify_request(request, project_dir, policy, store, *, transport=None, quarantine_dir=None, advisory_cache_dir=None,
                   live_advisories=True, osv=None, knowledge=None, environment=None, lockfile_name=LOCKFILE_NAME) -> dict:
    """Verify one request for the project at `project_dir`. Every result has the same keys.

    `request`  a pip command (string or list of tokens), a capture record, or
               {"requirements_edit": {"before": snapshot, "after": snapshot}}.
    `policy`   the parsed project policy; None when the project has none.
    `store`    a `CavrStorage` for the verdict cache and the verdict log, or None for neither.

    The keyword arguments replace the outside world in tests: `transport` (PyPI),
    `osv` / `advisory_cache_dir` / `live_advisories` (OSV), `knowledge` (threat-repository
    rules), `environment` (marker variables), `quarantine_dir` (where wheels are kept).
    """
    started = time.perf_counter()
    knowledge = knowledge or {"records": seeds()}
    fields = {"request": None, "gate": None, "lockfile": {"path": None, "present": False},
              "project": None, "packages": [], "policy_version": None, "analyzer_version": analyzer_version(knowledge)}

    def finish(status, stage, rule, reason) -> dict:
        packages = fields["packages"]
        escalated = any(package["escalated"] for package in packages)
        verdict = {"status": status, "stage": stage, "rule": rule, "reason": reason,
                   "fast_gate_ms": round((time.perf_counter() - started) * 1000, 2),
                   "cache_hit": bool(packages) and all(package["cache_hit"] for package in packages),
                   "escalated": escalated, "escalation": ESCALATION if escalated else None, **fields}
        verdict["logged"] = _log(store, request, verdict)
        return verdict

    try:
        project_dir = Path(project_dir)
        lockfile_path = project_dir / lockfile_name
    except TypeError:
        return finish("UNRESOLVED", "capture", "REQUEST_INVALID", f"not a project directory: {project_dir!r}")
    fields["lockfile"] = {"path": str(lockfile_path), "present": lockfile_path.exists()}

    # 1. C1 capture
    record, problem = _capture(request, project_dir)
    if record is None:
        return finish("UNRESOLVED", "capture", *problem)
    fields["request"] = record

    # 2. C2 requirement gate: nothing is downloaded unless every requirement is permitted.
    lockfile = load_json_file(lockfile_path)
    gate = fields["gate"] = evaluate_capture(record, policy, lockfile)
    fields["policy_version"] = gate["policy_version"]
    if gate["result"] != "PERMITTED":
        return finish("BLOCK" if gate["result"] == "BLOCK" else "UNRESOLVED", "gate", gate["rule"], gate["reason"])
    if not gate["decisions"]:
        return finish("VERIFIED", "gate", gate["rule"], gate["reason"])

    context = extract_project_context(project_dir)
    fields["project"] = {"project_dir": context["project_dir"], "result": context["result"], "rule": context["rule"],
                         "reason": context["reason"], "files": len(context["files"]), "sources_digest": context["sources_digest"],
                         # Directories the contract and the proofs did not look into (virtual environments, dot-directories).
                         "skipped_directories": context["skipped_directories"]}
    run = SimpleNamespace(policy=policy, lockfile=lockfile, context=context, store=store, transport=transport,
                          quarantine_dir=Path(quarantine_dir) if quarantine_dir is not None else default_quarantine_dir(),
                          advisory_cache_dir=Path(advisory_cache_dir) if advisory_cache_dir is not None else Path(DATA) / "cavr" / "advisories",
                          live_advisories=live_advisories, osv=osv, knowledge=knowledge, environment=environment,
                          policy_version=policy_version(policy), analyzer_version=fields["analyzer_version"])

    # 3-9, once per requirement.
    seen = {}
    for requirement, decision in zip(record["requirements"], gate["decisions"]):
        release = (decision["package"], canonicalize_version(Version(decision["version"])))
        asked = _asked(requirement)
        if release in seen:
            if seen[release] != asked:
                # Verifying only the first line would leave the second line's extras and hashes unchecked.
                fields["packages"].append(_package_verdict(
                    decision, "UNRESOLVED", "capture", "DUPLICATE_REQUIREMENT",
                    "this release is asked for twice in one request with different extras, --hash values or markers"))
            continue
        seen[release] = asked
        try:
            package = _verify_package(requirement, decision, run)
        except Exception as exc:  # a fault in a stage is "unknown", never a pass and never a lost verdict
            package = _package_verdict(decision, "UNRESOLVED", "internal", "INTERNAL_ERROR",
                                       f"a verification stage failed: {type(exc).__name__}: {exc}")
        fields["packages"].append(package)

    packages = fields["packages"]
    worst = (next((p for p in packages if p["status"] == "REJECTED"), None)
             or next((p for p in packages if p["status"] != "VERIFIED"), None))
    if worst:
        return finish(worst["status"], worst["stage"], worst["rule"], f"{worst['package']}=={worst['version']}: {worst['reason']}")
    return finish("VERIFIED", *PASSED, f"{len(packages)} requested packages verified: " + ", ".join(
        f"{p['package']}=={p['version']}" for p in packages))


def default_quarantine_dir() -> Path:
    """Where downloaded wheels are kept when the caller names no directory."""
    return Path(DATA) / "cavr" / "quarantine"


def analyzer_version(knowledge=None) -> str:
    """The cache-key field that changes when the code or the sink rules that judge an artifact change."""
    return f"{PIPELINE_VERSION};{SCAN_VERSION};rules:{digest(python_sinks(knowledge or {'records': seeds()}))}"


def metrics(store) -> dict:
    """The report numbers, from the verdict log: counts, cache hit rates, and p50 / p95 of `fast_gate_ms` per group.

    There is no percentile over all verdicts. A BLOCK takes a few milliseconds and downloads
    nothing, so a median over everything says nothing about how long verifying a package
    takes. The times are grouped three ways instead (nearest-rank percentiles):

        by_status                   VERIFIED / REJECTED / BLOCK / UNRESOLVED, each always listed
        by_cache_lookup             HIT / MISS / NOT_REACHED, each always listed
        by_status_and_cache_lookup  one row per pair that occurs; "VERIFIED, HIT" against
                                    "VERIFIED, MISS" is what a cache hit saves

    Two hit rates: `cache_hit_rate` is hits / all verdicts (a BLOCK counts as "not a hit");
    `cache_hit_rate_of_lookups` is hits / verdicts that reached the cache lookup.
    A row written before the lookup was logged is NOT_RECORDED, also when it was a hit: its misses
    cannot be told from BLOCKs, so counting only its hits would make the lookup rate too high.
    `cache_lookup_hits` is therefore the number of rows logged as HIT, which can be smaller
    than `cache_hits` (the `cache_hit` column) on a database that has such older rows.
    """
    rows = store.get_verdict_log()
    by_status = {status: [] for status in STATUSES}
    by_lookup = {found: [] for found in CACHE_LOOKUPS}
    by_pair = {}
    for row in rows:
        found = row.get("cache_lookup") or "NOT_RECORDED"
        for groups, key in ((by_status, row["status"]), (by_lookup, found), (by_pair, (row["status"], found))):
            groups.setdefault(key, []).append(row["fast_gate_ms"])
    hits = sum(1 for row in rows if row["cache_hit"])
    lookup_hits = len(by_lookup["HIT"])
    lookups = lookup_hits + len(by_lookup["MISS"])
    return {"verdicts": len(rows), "cache_hits": hits, "cache_hit_rate": hits / len(rows) if rows else None,
            "cache_lookups": lookups, "cache_lookup_hits": lookup_hits,
            "cache_hit_rate_of_lookups": lookup_hits / lookups if lookups else None,
            "by_status": {status: len(times) for status, times in sorted(by_status.items()) if times},
            "fast_gate_ms": {
                "by_status": {status: _time_summary(times) for status, times in by_status.items()},
                "by_cache_lookup": {found: _time_summary(times) for found, times in by_lookup.items()},
                "by_status_and_cache_lookup": [{"status": status, "cache_lookup": found, **_time_summary(times)}
                                               for (status, found), times in sorted(by_pair.items())]}}


def cache_lookup_of(verdict: dict) -> str:
    """What the verdict log records about the cache for one request: HIT, MISS or NOT_REACHED.

    HIT          the analysis of every package came from the cache (`cache_hit`)
    MISS         at least one package got as far as the cache lookup and was not served from it
    NOT_REACHED  no package got that far: a BLOCK, a failed download, an unusable contract
    """
    if verdict["cache_hit"]:
        return "HIT"
    reached = any((package.get("cache") or {}).get("lookup") is not None for package in verdict["packages"])
    return "MISS" if reached else "NOT_REACHED"


# --- internals ---------------------------------------------------------------

def _time_summary(times: list) -> dict:
    """How many times there are, and their nearest-rank p50 and p95 (None when there are none)."""
    ordered = sorted(times)
    return {"count": len(ordered), "p50": _nearest_rank(ordered, 50), "p95": _nearest_rank(ordered, 95)}


def _nearest_rank(ordered: list, percent: int):
    """The smallest value with at least `percent` % of the values at or below it. `ordered` is sorted ascending."""
    if not ordered:
        return None
    rank = -(-percent * len(ordered) // 100)      # ceil(percent * n / 100), in whole numbers
    return ordered[max(rank, 1) - 1]


def _capture(request, project_dir: Path):
    """(capture record, None), or (None, (rule, reason)) when the request cannot be turned into one."""
    try:
        if isinstance(request, (str, list, tuple)):
            return parse_pip_command(request, cwd=project_dir), None
        if isinstance(request, dict) and "requirements_edit" in request:
            edit = request["requirements_edit"]
            return capture_requirements_edit(edit["before"], edit["after"]), None
    except (ValueError, KeyError, TypeError) as exc:
        return None, ("CAPTURE_FAILED", f"the request could not be captured: {type(exc).__name__}: {exc}")
    if isinstance(request, dict) and "requirements" in request:
        return request, None  # already captured; the gate checks it like any other input
    return None, ("REQUEST_INVALID", "the request is not a pip command, a requirements edit or a capture record")


def _asked(requirement):
    """What one request line asks for besides the release itself: its extras, `--hash` values and marker."""
    if not isinstance(requirement, dict):
        return repr(requirement)
    return (sorted(requirement.get("extras") or ()), sorted(requirement.get("hashes") or ()), requirement.get("marker"))


def _verify_package(requirement: dict, decision: dict, run) -> dict:
    """Stages 3 to 9 for one permitted requirement."""
    started = time.perf_counter()
    name, version = decision["package"], decision["version"]
    evidence = {"gate": decision, "artifact": None, "tree": None, "contract": None, "advisories": [], "scan": [],
                "reachability": None, "analysis_from_cache": False}
    cache = {"lookup": None, "key": None, "stored": False, "reason": None}
    key_fields = None

    def done(status, stage, rule, reason, cache_hit=False, escalation=None) -> dict:
        return _package_verdict(decision, status, stage, rule, reason, started, cache_hit, escalation, cache, key_fields, evidence)

    # 3 + 4. Download and hash the wheel and every dependency under it.
    tree = build_tree(name, version, run.lockfile, run.quarantine_dir, transport=run.transport, environment=run.environment,
                      extras=tuple(requirement.get("extras") or ()) if isinstance(requirement, dict) else ())
    root = _root(tree)
    evidence["tree"] = {key: tree[key] for key in ("result", "rule", "reason", "root", "environment", "edges", "excluded",
                                                   "problems", "subtree_digest")}
    evidence["tree"]["nodes"] = [{key: node[key] for key in ("name", "version", "sha256", "filename", "size", "extras",
                                                             "lockfile_sha256", "import_names", "native_files")}
                                 for node in tree["nodes"]]
    evidence["artifact"] = root["artifact"] if root else _failed_root_artifact(tree)
    problem = _deciding_problem(tree)
    if tree["result"] == "REJECTED":
        return done("REJECTED", problem["stage"], tree["rule"], tree["reason"])

    # 5 + 6. The contract, then the cache lookup on the 8-field key.
    hit, cached = False, None
    contract = None
    if tree["result"] == "OK":
        contract = evidence["contract"] = infer_capability_contract(root["metadata"], run.context, run.policy, run.knowledge)
        if contract["result"] == "OK":
            key_fields = {"ecosystem": "PyPI", "name": root["name"], "version": root["version"], "artifact_sha256": root["sha256"],
                          "subtree_digest": tree["subtree_digest"], "contract_digest": contract["digest"],
                          "policy_version": run.policy_version, "analyzer_version": run.analyzer_version}
            found = lookup(run.store, key_fields)
            cache.update(lookup=found["rule"], key=found["key"], reason=found["reason"])
            hit, cached = found["hit"], found["verdict"]
            if hit and not (isinstance(cached, dict) and ANALYSIS_KEYS <= set(cached) and cached["status"] in CACHEABLE):
                # A sound row that does not hold an analysis (written by other code): analyse again and replace it.
                hit, cached = False, None
                cache.update(lookup="ROW_INCOMPLETE", reason="the stored verdict is not a complete analysis; analysed again")

    # 7. Advisories for every package of the tree, also on a cache hit and also when something above is unknown.
    targets = {(node["name"], node["version"]) for node in tree["nodes"]}
    targets.add((tree["root"]["name"], tree["root"]["version"]) if tree["root"] and tree["root"]["name"] else (name, version))
    advisories = evidence["advisories"] = [
        check_advisories(target, target_version, run.advisory_cache_dir, live=run.live_advisories, osv=run.osv)
        for target, target_version in sorted(targets, key=lambda item: (str(item[0]), str(item[1])))]
    affected = next((advisory for advisory in advisories if advisory["result"] == "REJECTED"), None)
    if affected:
        return done("REJECTED", "advisories", affected["rule"], affected["reason"], cache_hit=hit)
    if tree["result"] != "OK":
        return done("UNRESOLVED", problem["stage"], tree["rule"], tree["reason"])
    pinned = requirement.get("hashes") if isinstance(requirement, dict) else None
    if pinned and f"sha256:{root['sha256']}" not in pinned:
        return done("UNRESOLVED", "artifact", "REQUEST_HASH_MISMATCH",
                    f"the request pins {', '.join(pinned)}; the wheel that was verified is sha256:{root['sha256']}")
    if contract["result"] != "OK":
        return done("UNRESOLVED", "contract", contract["rule"], contract["reason"])
    unknown = next((advisory for advisory in advisories if advisory["result"] != "OK"), None)
    if unknown:
        return done("UNRESOLVED", "advisories", unknown["rule"], unknown["reason"], cache_hit=hit)

    # 8. The AST scan and the sink judgement, unless a sound stored analysis exists for exactly these inputs.
    if hit:
        analysis = cached
        evidence["analysis_from_cache"] = True
    else:
        analysis = _analyse(tree, contract, run)
        if analysis["status"] in CACHEABLE:
            stored = store_verdict(run.store, key_fields, analysis)
            cache.update(stored=stored["stored"], reason=stored["reason"])
    evidence["scan"], evidence["reachability"] = analysis["scan"], analysis["reachability"]

    # 9. Verdict.
    return done(analysis["status"], analysis["stage"], analysis["rule"], analysis["reason"], cache_hit=hit,
                escalation=analysis["escalation"])


def _package_verdict(decision, status, stage, rule, reason, started=None, cache_hit=False, escalation=None, cache=None,
                     key_fields=None, evidence=None) -> dict:
    """The verdict of one requested package. Every one has the same keys."""
    elapsed = 0.0 if started is None else round((time.perf_counter() - started) * 1000, 2)
    return {"status": status, "stage": stage, "rule": rule, "reason": reason, "package": decision["package"],
            "version": decision["version"], "requested": decision["requested"], "fast_gate_ms": elapsed,
            "cache_hit": cache_hit, "escalated": escalation is not None, "escalation": escalation,
            "cache": cache or {"lookup": None, "key": None, "stored": False, "reason": None}, "key_fields": key_fields,
            "evidence": evidence or {"gate": decision}}


def _analyse(tree: dict, contract: dict, run) -> dict:
    """Scan every wheel of the tree and judge its sinks. This is the part of a verdict that is cached."""
    scans = []

    def analysis(status, stage, rule, reason, reachability=None, escalation=None) -> dict:
        return {"status": status, "stage": stage, "rule": rule, "reason": reason, "escalation": escalation,
                "scan": scans, "reachability": reachability}

    for node in tree["nodes"]:
        # The file was hashed when it was downloaded; make sure the scan reads those same bytes.
        if _sha256_of_file(node["path"]) != node["sha256"]:
            return analysis("UNRESOLVED", "scan", "ARTIFACT_CHANGED",
                            f"{node['filename']} in quarantine no longer has the SHA-256 it was downloaded with")
        scans.append({"package": node["name"], "version": node["version"], **scan_wheel(node["path"], run.knowledge)})
    bad = (next((scan for scan in scans if scan["result"] == "REJECTED"), None)
           or next((scan for scan in scans if scan["result"] != "OK"), None))
    if bad:
        return analysis(bad["result"] if bad["result"] == "REJECTED" else "UNRESOLVED", "scan", bad["rule"],
                        f"{bad['package']} {bad['version']}: {bad['reason']}")
    judgement = judge_sinks(tree["nodes"], scans, contract, run.context)
    if judgement["result"] != "OK":
        return analysis("UNRESOLVED", "reachability", judgement["rule"], judgement["reason"], judgement, ESCALATION)
    return analysis("VERIFIED", *PASSED, f"hash, tree, advisories and contract checked; {judgement['reason']}", judgement)


def _root(tree: dict):
    """The loaded node of the package that was asked for, or None when it could not be loaded."""
    root = tree["root"] or {}
    try:
        wanted = Version(root["version"])
    except (KeyError, TypeError, InvalidVersion):
        return None
    return next((node for node in tree["nodes"] if node["name"] == root["name"] and Version(node["version"]) == wanted), None)


def _failed_root_artifact(tree: dict):
    """The download result of the requested package when it failed (the evidence of a hash mismatch, for example)."""
    root = tree["root"] or {}
    label = f"{root.get('name')}=={root.get('version')}"
    return next((failure["artifact"] for failure in tree["failed_nodes"] if failure["node"] == label), None)


def _deciding_problem(tree: dict) -> dict:
    """The tree problem that gave the tree its result; a result without one (a bad lockfile) is a "tree" problem."""
    return next((problem for problem in tree["problems"]
                 if problem["rule"] == tree["rule"] and problem["reason"] == tree["reason"]), {"stage": "tree"})


def _sha256_of_file(path):
    sha = hashlib.sha256()
    try:
        with open(path, "rb") as source:
            while chunk := source.read(64 * 1024):
                sha.update(chunk)
    except OSError:
        return None
    return sha.hexdigest()


def _log(store, request, verdict: dict) -> bool:
    """Write one row to the verdict log. False when there is no store or it cannot be written."""
    try:
        record = verdict["request"] or {}
        command = record.get("command")
        if isinstance(command, (list, tuple)) and command:
            requested = " ".join(str(token) for token in command)
        else:
            requested = record.get("path") or repr(request)
        # A caller-made record was not redacted by the capture, so URL passwords are removed here as well.
        store.record_verdict(record.get("source"), redact(str(requested))[:MAX_LOGGED_REQUEST], verdict["status"],
                             verdict["stage"], verdict["rule"], verdict["fast_gate_ms"], verdict["cache_hit"],
                             verdict["escalated"], cache_lookup_of(verdict))
    except Exception:  # the log is for the report; it must never change or lose a verdict
        return False
    return True
