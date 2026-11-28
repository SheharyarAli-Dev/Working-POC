#!/usr/bin/env python3
"""The reduced PR 21 evaluation of CAVR (docs/cavr-m2-plan.md, Phase 5b): a pinned corpus through `asent gate`.

    CAVR_DOCKER=1 .venv/bin/python scripts/eval/cavr_eval.py run       live: PyPI, OSV and the CAVR sandbox (Docker)
    .venv/bin/python scripts/eval/cavr_eval.py report                  offline: CSV, tables, SVG charts from the raw JSON
    .venv/bin/python scripts/eval/cavr_eval.py check                   offline: the recordings against the raw JSON
    .venv/bin/python scripts/eval/cavr_eval.py repair-screen <item>    offline: repair's advisory screen against the
                                                                       OSV specification, from the recordings

The corpus is `cavr_eval_corpus.json` next to this file: real PyPI releases, each in a small project of its own
(an app file that calls it with literal arguments, a policy, a lockfile that pins every child), and the 14 synthetic
M2 demo wheels of `tests/test_cavr_m2_wheels.py` (`WHEELS`, served by the test's local index, as in that test).

`run` judges every item twice with `asent gate` (in-process, deep "sandbox", repair on). Both runs of one item share
one data directory (the verdict cache), and no two items share one. For each run it keeps the pipeline verdict that
`verify_request` returned inside the gate run, the gate decision and exit code, and the time of every stage. The
stage times come from wrappers put around the pipeline's stage functions for the duration of the run (nothing in
`backend/` is edited); calls made by repair's own re-verification count as repair, not as fast-gate stages. It
refuses to run with uncommitted changes to tracked files, so the recorded commit is the code (and the expectations)
that ran. Every result is compared with the expectation written in the corpus before the run; a mismatch is
recorded and printed, never adjusted, and makes the exit code 3; an OSV answer that was used but not
recorded makes it 4, and a HEAD that moved during the run makes it 5.

What is saved so the numbers can be checked later (docs/evaluation/recordings/):

    pypi/<item>.json.gz          every URL the transport fetched, per run: the registry JSON bodies in full, the
                                 wheel files as SHA-256 and size only (the files stay on PyPI)
    osv/<item>-run<N>.json.gz    the advisory cache directory after that run: OSV's dated answers as the adapter
                                 stored them (query, retrieved_at, response, response_sha256), per version and
                                 package-wide; for the synthetic wheels the seeded empty answers

The OSV-only column (what a pip-audit-like check would say) is computed from those recorded answers for every node
of the item's tree, with no extra run: VULNERABLE when any answer lists a non-withdrawn advisory, NO_ANSWER when a
node has no answer, else PASS.
"""
from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import io
import json
import math
import platform
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

REPO = Path(__file__).resolve().parents[2]
for _path in (REPO, REPO / "tests"):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

from packaging.requirements import InvalidRequirement, Requirement  # noqa: E402
from packaging.utils import canonicalize_name  # noqa: E402

from backend.cavr import gate_adapter, pipeline  # noqa: E402
from backend.cavr.pypi_client import REGISTRY_HOST, HttpxTransport, TransportError  # noqa: E402
from backend.orchestrator.hashing import digest  # noqa: E402

CORPUS = Path(__file__).with_name("cavr_eval_corpus.json")
CORPUS_SCHEMA = "cavr.eval-corpus.v1"
RAW_SCHEMA = "cavr.eval-raw.v1"
OUT = REPO / "docs" / "evaluation"
RAW_NAME, CSV_NAME, MD_NAME = "cavr-m2-eval-raw.json", "cavr-m2-eval.csv", "cavr-m2-evaluation.md"
VERDICT_SVG, STAGE_SVG = "verdicts-by-set.svg", "time-per-stage.svg"
SETS = ("clean", "vulnerable", "attack")
ATTACK_LABELS = ("attack", "benign_control")
GROUPS = ("clean", "vulnerable", "attack", "benign_control")   # the rows of every per-set table
GROUP_TITLES = {"clean": "Clean", "vulnerable": "Vulnerable", "attack": "Attack", "benign_control": "Benign control"}
KINDS = ("pypi", "wheel")
STATUSES = ("VERIFIED", "REJECTED", "UNRESOLVED", "BLOCK")
ITEM_FIELDS = ("id", "set", "kind", "reason", "expected")
EXPECTED_FIELDS = ("status", "rule", "deep", "repair", "decision", "exit_code")
RUNS = (1, 2)
# (module, function name, stage): the stage functions `verify_request` and the gate adapter call by global name.
STAGE_TARGETS = ((pipeline, "evaluate_capture", "requirement_gate"), (pipeline, "extract_project_context", "project_context"),
                 (pipeline, "build_tree", "tree"), (pipeline, "infer_capability_contract", "contract"),
                 (pipeline, "lookup", "cache_lookup"), (pipeline, "check_advisories", "advisories"),
                 (pipeline, "_analyse", "scan"), (pipeline, "run_deep", "deep"), (gate_adapter, "propose_repair", "repair"))
STAGES = tuple(stage for _, _, stage in STAGE_TARGETS)
TIMED = STAGES + ("verify_request", "gate_run")
UNRESOLVED_REASONS = (("compiled code", ("COMPILED_CODE_NOT_SCANNED",)), (".pth file", ("PTH_EXECUTES_CODE",)),
                      ("unsimulable trigger", ("TRIGGER_UNSIMULABLE",)), ("sink not exercised", ("DEEP_SINK_NOT_EXERCISED",)),
                      ("budget", ("DEEP_RUN_BUDGET_EXHAUSTED", "DEEP_RUN_BUDGET_USED_UP")))
OTHER_REASON = "other"
BLOCKS = ("environment", "attack_vs_osv", "tables")
MD_SKELETON = """# CAVR M2 evaluation (reduced PR 21)

<!-- cavr-eval:begin environment -->
<!-- cavr-eval:end environment -->

## Findings

<!-- cavr-eval:begin attack_vs_osv -->
<!-- cavr-eval:end attack_vs_osv -->

(findings: written by hand from the tables below)

## Limitations

(written by hand)

## Tables

<!-- cavr-eval:begin tables -->
<!-- cavr-eval:end tables -->
"""


# --- corpus -------------------------------------------------------------------------------------------------------

def load_corpus(path=CORPUS, wheels=None) -> dict:
    """The parsed corpus, checked. Raises ValueError on anything that would make a row ambiguous.

    `wheels` is the synthetic table (`WHEELS` of tests/test_cavr_m2_wheels.py) the wheel items must match; by default
    it is imported. A wheel item's expected (status, rule, decision, exit code) must equal that table's, so the attack
    set's expectations are the tested ones.
    """
    if wheels is None:
        from test_cavr_m2_wheels import WHEELS as wheels
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict) or data.get("schema") != CORPUS_SCHEMA or not isinstance(data.get("items"), list):
        raise ValueError(f"not a {CORPUS_SCHEMA} corpus")
    seen = set()
    for item in data["items"]:
        if not isinstance(item, dict) or any(key not in item for key in ITEM_FIELDS):
            raise ValueError(f"corpus item needs {', '.join(ITEM_FIELDS)}: {item!r}")
        name = item["id"]
        if name in seen:
            raise ValueError(f"duplicate corpus id: {name}")
        seen.add(name)
        if item["set"] not in SETS or item["kind"] not in KINDS:
            raise ValueError(f"{name}: unknown set or kind: {item['set']!r}, {item['kind']!r}")
        if not isinstance(item["reason"], str) or not item["reason"].strip():
            raise ValueError(f"{name}: every item needs a reason")
        expected = item["expected"]
        if not isinstance(expected, dict) or any(key not in expected for key in EXPECTED_FIELDS):
            raise ValueError(f"{name}: expected needs {', '.join(EXPECTED_FIELDS)}")
        if expected["status"] not in STATUSES:
            raise ValueError(f"{name}: unknown expected status {expected['status']!r}")
        if item["kind"] == "wheel":
            if item["set"] != "attack" or item.get("label") not in ATTACK_LABELS:
                raise ValueError(f"{name}: a synthetic wheel belongs to the attack set with a label in {ATTACK_LABELS}")
            if name not in wheels:
                raise ValueError(f"{name}: not a wheel of tests/test_cavr_m2_wheels.py")
            tested = tuple(wheels[name][3])
            written = (expected["status"], expected["rule"], expected["decision"], expected["exit_code"])
            if written != tested:
                raise ValueError(f"{name}: expected {written} differs from the tested {tested}")
        else:
            _check_pypi_item(item)
    return data


def _check_pypi_item(item: dict):
    name = item["id"]
    if item["set"] == "attack":
        raise ValueError(f"{name}: the attack set is synthetic wheels only (no real package is used as an attack)")
    try:
        requirement = Requirement(item.get("requirement") or "")
    except InvalidRequirement as exc:
        raise ValueError(f"{name}: bad requirement: {exc}") from None
    pins = list(requirement.specifier)
    if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
        raise ValueError(f"{name}: the requirement must be pinned with == to one version: {item.get('requirement')!r}")
    lock = item.get("lock")
    if not isinstance(lock, dict) or not all(isinstance(v, str) and v and "*" not in v for v in lock.values()):
        raise ValueError(f"{name}: lock must map every child to one version")
    policy = item.get("policy")
    if not isinstance(policy, dict) or not isinstance(policy.get("allowed_scopes"), list) \
            or not str(policy.get("project_task_description") or "").strip():
        raise ValueError(f"{name}: policy needs allowed_scopes and a project_task_description (the gate config requires one)")
    if item.get("app") is None and item.get("app_files") != "invoicehub":
        raise ValueError(f"{name}: a real item needs an app file that calls the package (or app_files: invoicehub)")


def pinned(item: dict) -> tuple[str, str]:
    """(canonical name, version) of a real item's requirement."""
    requirement = Requirement(item["requirement"])
    return canonicalize_name(requirement.name), next(iter(requirement.specifier)).version


def group_of(item: dict) -> str:
    return item.get("label") if item["set"] == "attack" else item["set"]


# --- the live run -------------------------------------------------------------------------------------------------

class RecordingTransport:
    """A transport that passes every byte through unchanged and lists what it fetched.

    For the registry host the whole body is kept (the JSON answers); for any other host (the wheel files) only the
    SHA-256 and the size. `run` is set by the caller so every fetch is filed under the run that made it.
    """

    def __init__(self, inner=None):
        self.inner = inner if inner is not None else HttpxTransport()
        self.fetches = []
        self.bodies = {}
        self.run = None

    def stream(self, url):
        entry = {"run": self.run, "url": url, "outcome": None, "sha256": None, "bytes": 0}
        self.fetches.append(entry)
        keep = urlsplit(url).hostname == REGISTRY_HOST
        sha, parts, size = hashlib.sha256(), [], 0
        try:
            for chunk in self.inner.stream(url):
                sha.update(chunk)
                size += len(chunk)
                if keep:
                    parts.append(chunk)
                entry["bytes"] = size
                yield chunk
        except TransportError as exc:
            entry.update(outcome="error", error=str(exc), status=exc.status)
            raise
        except GeneratorExit:  # the reader stopped early (a size cap or a deadline): what arrived is not a whole body
            entry.update(outcome="incomplete")
            raise
        entry.update(outcome="ok", sha256=sha.hexdigest())
        if keep:
            body = b"".join(parts)
            try:
                self.bodies[entry["sha256"]] = {"text": body.decode("utf-8")}
            except UnicodeDecodeError:
                self.bodies[entry["sha256"]] = {"base64": base64.b64encode(body).decode("ascii")}

    def recording(self) -> dict:
        return {"fetches": self.fetches, "bodies": dict(sorted(self.bodies.items()))}


class StageTimer:
    """Wall time per pipeline stage for one gate run. Calls made inside repair count only as repair."""

    def __init__(self):
        self.seconds, self.calls = {}, {}
        self._in_repair = 0

    def wrap(self, stage, function):
        def timed(*args, **kwargs):
            if self._in_repair and stage != "repair":
                return function(*args, **kwargs)
            if stage == "repair":
                self._in_repair += 1
            started = time.perf_counter()
            try:
                return function(*args, **kwargs)
            finally:
                if stage == "repair":
                    self._in_repair -= 1
                self.seconds[stage] = self.seconds.get(stage, 0.0) + time.perf_counter() - started
                self.calls[stage] = self.calls.get(stage, 0) + 1
        timed.__wrapped__ = function
        return timed

    def milliseconds(self) -> dict:
        """stage -> milliseconds (None for a stage that did not run)."""
        return {stage: round(self.seconds[stage] * 1000, 2) if stage in self.seconds else None for stage in STAGES}

    @contextmanager
    def installed(self, targets=STAGE_TARGETS):
        saved = [(module, name, getattr(module, name)) for module, name, _ in targets]
        try:
            for (module, name, stage), (_, _, original) in zip(targets, saved):
                setattr(module, name, self.wrap(stage, original))
            yield self
        finally:
            for module, name, original in saved:
                setattr(module, name, original)


def git(*args) -> str:
    return subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True).stdout.strip()


CODE_DIRECTORIES = ("backend", "scripts", "tests", "docker")


def require_clean_tree(repo=REPO):
    """Refuse to run when tracked files have uncommitted changes, or untracked files sit where code is imported from:
    the recorded commit must be the code that ran."""
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=no"],
                           capture_output=True, text=True).stdout.strip()
    if dirty:
        raise SystemExit(f"run needs a clean working tree (tracked changes):\n{dirty}")
    untracked = subprocess.run(["git", "-C", str(repo), "status", "--porcelain", "--untracked-files=all", "--",
                                *CODE_DIRECTORIES], capture_output=True, text=True).stdout.strip()
    if untracked:
        raise SystemExit(f"run needs a clean working tree (untracked files where code is imported from):\n{untracked}")


def project_files(item: dict) -> tuple[dict, dict]:
    """(base files, head files) of a real item's project, except the .asent config the caller adds."""
    from gate_support import invoice_app_files
    name, version = pinned(item)
    lock = {"lock_version": 1, "edges": [],
            "packages": [{"name": name, "version": version, "ecosystem": "PyPI"}]
            + [{"name": canonicalize_name(child), "version": child_version, "ecosystem": "PyPI"}
               for child, child_version in sorted(item["lock"].items())]}
    base = {"requirements.txt": "", "dependencies.lock.json": json.dumps(lock, indent=2) + "\n"}
    base.update(invoice_app_files() if item.get("app_files") == "invoicehub" else {"app/__init__.py": ""})
    head = {"requirements.txt": item["requirement"] + "\n"}
    if item.get("app"):
        head["app/uses_package.py"] = item["app"]
    return base, head


def live_world(item: dict, workdir: Path) -> dict:
    """The outside world of one item: the real PyPI and OSV for a real item; the test's local index for a wheel."""
    if item["kind"] == "wheel":
        from test_cavr_m2_wheels import WHEELS
        from test_cavr_support import PIN_VERSION, RECORDED_6_21_4, FakeIndex, build_wheel, write_osv_cache
        files = WHEELS[item["id"]][0]
        index = FakeIndex()
        index.add("demo", "1.0", build_wheel(workdir / "wheels", "demo", "1.0", files=files))
        osv = workdir / "osv"
        write_osv_cache(osv, "demo", "1.0", [])
        write_osv_cache(osv, "pypdf", PIN_VERSION, RECORDED_6_21_4)
        return {"transport": RecordingTransport(index), "advisory_cache_dir": osv, "live_advisories": False,
                "deep": "sandbox", "osv_dir": osv}
    # An explicit advisory cache directory: the gate and repair write OSV's answers exactly where they are recorded
    # from (the first live attempt read a directory the gate does not use, and saved no answer; findings, Step M2-22).
    osv = workdir / "osv-live"
    return {"transport": RecordingTransport(), "advisory_cache_dir": osv, "live_advisories": True, "deep": "sandbox",
            "osv_dir": osv}


def make_repo(item: dict, workdir: Path):
    """The item's git repository with tags base and head, as `asent gate` sees it."""
    from gate_support import DISABLED, GateRepo, POLICY, config, invoice_app_files
    if item["kind"] == "wheel":
        from test_cavr_m2_wheels import WHEELS
        _, call, policy_change, _ = WHEELS[item["id"]]
        policy = {**POLICY, "approved_requirements": ["demo==1.0"], **(policy_change or {})}
        base = {**invoice_app_files(), "requirements.txt": ""}
        head = {"requirements.txt": "demo==1.0\n", "app/uses_demo.py": f"import demo\n\n\ndef go():\n    return {call}\n"}
    else:
        defaults = json.loads(CORPUS.read_text(encoding="utf-8")).get("policy_defaults") or {}
        policy = {**defaults, **item["policy"], "approved_requirements": [item["requirement"]]}
        base, head = project_files(item)
    repo = GateRepo(workdir / "repo")
    repo.commit({**base, ".asent/cavr/policy.json": json.dumps(policy, indent=2),
                 ".asent/config.json": config(CAVR={"enabled": True}, SATRA=DISABLED, SABLE=DISABLED)}, tag="base")
    repo.commit(head, tag="head")
    return repo


def gate_once(item: dict, repo, workdir: Path, world: dict, run_number: int) -> dict:
    """One `asent gate` run of the item; the data directory is shared by both runs of the item."""
    from gate_support import run_cli
    world["transport"].run = run_number
    verdicts = []
    real = gate_adapter.verify_request

    def keep(*args, **kwargs):
        verdicts.append(real(*args, **kwargs))
        return verdicts[-1]

    settings = {**gate_adapter.SETTINGS, "transport": world["transport"], "osv": None,
                "advisory_cache_dir": world["advisory_cache_dir"], "live_advisories": world["live_advisories"],
                "repair": True, "deep": world["deep"]}
    saved = gate_adapter.SETTINGS
    gate_adapter.SETTINGS, gate_adapter.verify_request = settings, keep
    timer = StageTimer()
    try:
        with timer.installed():
            started = time.perf_counter()
            code, report, _ = run_cli(repo, "base", "head", workdir / f"out-{run_number}", "--data-dir", str(workdir / "data"))
            gate_ms = round((time.perf_counter() - started) * 1000, 2)
    finally:
        gate_adapter.SETTINGS, gate_adapter.verify_request = saved, real
    if len(verdicts) != 1 or report is None:
        return {"run": run_number, "error": f"expected one pipeline verdict and a report; got {len(verdicts)} verdict(s)",
                "exit_code": code}
    record = next(e for e in report["assurance"]["evidence"] if e["evidence_id"] == report["modules"]["CAVR"]["evidence_id"])
    rows = [p for entry in record["details"]["pipeline"] for p in entry["packages"]]
    return extract(verdicts[0], rows[0] if len(rows) == 1 else None, report, code, gate_ms, timer.milliseconds(),
                   record["details"].get("deep_stage"), run_number)


def extract(verdict: dict, row, report: dict, code, gate_ms, stage_ms: dict, deep_stage, run_number: int) -> dict:
    """The recorded fields of one gate run, from the pipeline verdict and the gate's CAVR row."""
    package = (verdict.get("packages") or [{}])[0]
    evidence = package.get("evidence") or {}
    deep = evidence.get("deep") if isinstance(evidence.get("deep"), dict) else None
    inner = (deep or {}).get("evidence") or {}
    triggers = [t for t in inner.get("triggers") or [] if isinstance(t, dict)]
    loop = inner.get("loop") or {}
    reachability = evidence.get("reachability") or {}
    if deep is not None:
        fast = {"status": "UNRESOLVED", "stage": "reachability", "rule": reachability.get("rule"), "escalated": True}
    else:
        fast = {"status": package.get("status", verdict.get("status")), "stage": package.get("stage", verdict.get("stage")),
                "rule": package.get("rule", verdict.get("rule")), "escalated": bool(package.get("escalated"))}
    repair = (row or {}).get("repair")
    tree = evidence.get("tree") or {}
    return {
        "run": run_number, "status": verdict.get("status"), "stage": verdict.get("stage"), "rule": verdict.get("rule"),
        # The requested package's own stage and rule. The request-level rule of an all-VERIFIED request is always
        # ALL_CHECKS_PASSED; the package's is the rule that decided it (DEEP_RUN_CLEAN after the deep stage).
        "package_stage": package.get("stage"), "package_rule": package.get("rule"),
        "reason": verdict.get("reason"), "decision": report.get("decision"), "exit_code": code,
        "package": package.get("package"), "version": package.get("version"),
        "cache_hit": bool(package.get("cache_hit")), "cache": package.get("cache"),
        "analysis_from_cache": bool(evidence.get("analysis_from_cache")),
        "fast": fast,
        "deep": None if deep is None else {
            "status": deep.get("status"), "stage": deep.get("stage"), "rule": deep.get("rule"),
            "elapsed_seconds": deep.get("elapsed_seconds"), "runs": len(inner.get("runs") or []),
            "frontier": len(triggers), "explored": sum(1 for t in triggers if t.get("outcome") == "explored"),
            "budget_seconds": (loop.get("budget_used") or {}).get("seconds"), "stop": loop.get("stop"),
            "cause": (inner.get("causal") or {}).get("cause"), "image_id": inner.get("image_id"),
            "budget": inner.get("budget"), "from_cache": bool(evidence.get("analysis_from_cache"))},
        "deep_stage": deep_stage,
        "repair": None if not isinstance(repair, dict) else {
            "result": repair.get("result"), "rule": repair.get("rule"), "reason": repair.get("reason"), "pin": repair.get("pin"),
            "candidates_tried": len(repair.get("candidates_tried") or []),
            # Why each newer release was left out (rule, advisory ids), and the package-wide OSV answer it was judged on.
            "excluded": repair.get("excluded") or [], "advisory_screen": repair.get("advisory_screen"),
            "tried": [{key: c.get(key) for key in ("version", "outcome", "status", "stage", "rule")}
                      for c in repair.get("candidates_tried") or [] if isinstance(c, dict)]},
        "artifact": {key: (evidence.get("artifact") or {}).get(key) for key in ("filename", "sha256", "registry_sha256", "rule")},
        "tree": {"result": tree.get("result"), "rule": tree.get("rule"),
                 "nodes": [{key: node.get(key) for key in ("name", "version", "sha256")} for node in tree.get("nodes") or []]},
        "advisories": [{key: a.get(key) for key in ("name", "version", "result", "rule", "mode", "advisory_count",
                                                     "response_sha256", "retrieved_at")}
                       for a in evidence.get("advisories") or []],
        "timing_ms": {**stage_ms, "verify_request": verdict.get("fast_gate_ms"), "gate_run": gate_ms},
    }


def osv_snapshot(directory: Path) -> dict:
    """relative path -> parsed JSON of every answer file under the advisory cache directory."""
    files = {}
    for path in sorted(Path(directory).rglob("*.json")) if Path(directory).is_dir() else []:
        try:
            files[str(path.relative_to(directory))] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            files[str(path.relative_to(directory))] = {"unreadable": f"{type(exc).__name__}: {exc}"}
    return files


def write_gz(path: Path, value):
    """Gzip-compressed canonical JSON, with no timestamp in the gzip header (the same input gives the same bytes)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(value, indent=1, sort_keys=True).encode("utf-8")
    path.write_bytes(gzip.compress(data, mtime=0))


def read_gz(path: Path):
    return json.loads(gzip.decompress(Path(path).read_bytes()).decode("utf-8"))


def osv_only(nodes: list, snapshot: dict) -> dict:
    """What an OSV-only check (like pip-audit) says for these (name, version) nodes, from recorded answers only."""
    answers = {}
    for value in snapshot.values():
        query = value.get("query") if isinstance(value, dict) else None
        if isinstance(query, dict) and query.get("version") and isinstance(query.get("package"), dict):
            key = (canonicalize_name(str(query["package"].get("name"))), str(query["version"]))
            answers[key] = value
    per_node = []
    for name, version in nodes:
        answer = answers.get((canonicalize_name(name), version))
        if answer is None or not isinstance((answer.get("response") or {}).get("vulns"), list):
            per_node.append({"name": name, "version": version, "result": "NO_ANSWER", "ids": []})
            continue
        ids = sorted(v.get("id") for v in answer["response"]["vulns"] if isinstance(v, dict) and not v.get("withdrawn"))
        per_node.append({"name": name, "version": version, "result": "VULNERABLE" if ids else "PASS", "ids": ids,
                         "response_sha256": answer.get("response_sha256")})
    results = {node["result"] for node in per_node}
    overall = "VULNERABLE" if "VULNERABLE" in results else "NO_ANSWER" if ("NO_ANSWER" in results or not per_node) else "PASS"
    return {"result": overall, "nodes": per_node}


def tree_nodes(result: dict, item: dict) -> list:
    """(name, version) of every node of the tree; the root alone when no node could be loaded."""
    nodes = [(n["name"], n["version"]) for n in (result.get("tree") or {}).get("nodes") or [] if n.get("name")]
    if nodes:
        return nodes
    if item["kind"] == "wheel":
        return [("demo", "1.0")]
    return [pinned(item)]


def compare(item: dict, first: dict, second: dict | None = None) -> list[str]:
    """Every difference between the item's written expectation and run 1, and between run 1 and run 2's verdict."""
    expected, problems = item["expected"], []
    if "error" in first:
        return [f"run 1 failed: {first['error']}"]
    if first["status"] != expected["status"]:
        problems.append(f"status {first['status']} != expected {expected['status']}")
    if expected["rule"] is not None and decided(first)[1] != expected["rule"]:
        problems.append(f"rule {decided(first)[1]} != expected {expected['rule']}")
    if expected.get("stage") is not None and decided(first)[0] != expected["stage"]:
        problems.append(f"stage {decided(first)[0]} != expected {expected['stage']}")
    if bool(first["deep"]) != bool(expected["deep"]):
        problems.append(f"deep stage ran: {bool(first['deep'])} != expected {bool(expected['deep'])}")
    got_repair = (first["repair"] or {}).get("result")
    if got_repair != expected["repair"]:
        problems.append(f"repair {got_repair} != expected {expected['repair']}")
    for key in ("decision", "exit_code"):
        if first[key] != expected[key]:
            problems.append(f"{key} {first[key]} != expected {expected[key]}")
    if second is not None:
        if "error" in second:
            problems.append(f"run 2 failed: {second['error']}")
        elif (second["status"], decided(second)[1]) != (first["status"], decided(first)[1]):
            problems.append(f"run 2 gave {second['status']} {decided(second)[1]}, run 1 {first['status']} {decided(first)[1]}")
    return problems


def decided(result: dict) -> tuple:
    """(stage, rule) of the requested package: what the expectations name. Falls back to the request level."""
    return (result.get("package_stage") or result.get("stage"), result.get("package_rule") or result.get("rule"))


def unrecorded_answers(result: dict, snapshot: dict) -> list[str]:
    """Every OSV answer the run used (it has a response_sha256) that the recorded snapshot does not hold."""
    if "error" in result:
        return []
    held = {value.get("response_sha256") for value in snapshot.values() if isinstance(value, dict)}
    return [f"run {result['run']}: the OSV answer for {a['name']} {a['version']} ({a.get('mode')}) was not recorded"
            for a in result.get("advisories") or [] if a.get("response_sha256") and a["response_sha256"] not in held]


def run(out: Path, only=None, allow_dirty=False, world_for=live_world, sandbox=True) -> int:
    """The live run: every item twice, raw JSON and recordings under `out`. Exit code 3 when anything mismatched.

    `world_for` and `sandbox` replace the outside world in tests (a local index, a seeded OSV cache, no Docker)."""
    if not allow_dirty:
        require_clean_tree()
    corpus = load_corpus()
    items = [item for item in corpus["items"] if not only or item["id"] in only]
    if only and len(items) != len(only):
        raise SystemExit(f"unknown item id(s): {', '.join(sorted(set(only) - {item['id'] for item in items}))}")
    commit = git("rev-parse", "HEAD")  # the code that runs; checked again at the end
    identity = None
    if sandbox:
        from test_cavr_support import sandbox_identity
        identity = sandbox_identity()  # builds the image when it is missing or stale; a mismatch stops the run
    started = datetime.now(timezone.utc)
    rows = []
    for item in items:
        with tempfile.TemporaryDirectory(prefix="cavr-eval-") as directory:
            workdir = Path(directory)
            world = world_for(item, workdir)
            repo = make_repo(item, workdir)
            results, snapshots = [], []
            for number in RUNS:
                try:
                    results.append(gate_once(item, repo, workdir, world, number))
                except Exception as exc:  # recorded as this run's result, never a lost item
                    results.append({"run": number, "error": f"{type(exc).__name__}: {exc}"})
                snapshots.append(osv_snapshot(world["osv_dir"]))
                write_gz(out / "recordings" / "osv" / f"{item['id']}-run{number}.json.gz", snapshots[-1])
            write_gz(out / "recordings" / "pypi" / f"{item['id']}.json.gz", world["transport"].recording())
        first, second = results
        baseline = osv_only(tree_nodes(first, item), snapshots[0]) if "error" not in first else None
        mismatches = compare(item, first, second)
        unrecorded = [p for result, snapshot in zip(results, snapshots) for p in unrecorded_answers(result, snapshot)]
        rows.append({"id": item["id"], "set": item["set"], "group": group_of(item), "kind": item["kind"],
                     "requirement": item.get("requirement") or "demo==1.0", "reason": item["reason"],
                     "expected": item["expected"], "runs": results, "osv_only": baseline, "mismatches": mismatches,
                     "recording_problems": unrecorded})
        print(f"{item['id']}: {first.get('status')} {decided(first)[1]} (exit {first.get('exit_code')})"
              + (f"  MISMATCH: {'; '.join(mismatches)}" if mismatches else "")
              + (f"  NOT RECORDED: {'; '.join(unrecorded)}" if unrecorded else ""), file=sys.stderr)
    header = environment(identity, started, corpus, only, allow_dirty)
    if header["commit"] != commit:  # HEAD moved during the run: the header could name code that did not run
        header["commit_problem"] = f"HEAD was {commit} at the start and {header['commit']} at the end"
        header["commit"] = commit
    raw = {"schema": RAW_SCHEMA, **header, "items": rows}
    out.mkdir(parents=True, exist_ok=True)
    (out / RAW_NAME).write_text(json.dumps(raw, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    unrecorded = [row["id"] for row in rows if row["recording_problems"]]
    if unrecorded:  # a used answer that cannot be checked later: the run does not meet its own requirement
        print(f"{len(unrecorded)} item(s) have OSV answers that were not recorded: {', '.join(unrecorded)}", file=sys.stderr)
        return 4
    if header.get("commit_problem"):
        print(header["commit_problem"], file=sys.stderr)
        return 5
    mismatched = [row["id"] for row in rows if row["mismatches"]]
    if mismatched:
        print(f"{len(mismatched)} item(s) differ from their expectation: {', '.join(mismatched)}", file=sys.stderr)
        return 3
    return 0


def docker_output(*args):
    """(stdout, None) from `docker <args>`, or (None, reason) when the program is missing, cannot start, or fails."""
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True)
    except OSError as error:  # FileNotFoundError: not on PATH; PermissionError: not executable
        return None, f"{type(error).__name__}: {error.strerror or error}"
    if done.returncode != 0:
        last = (done.stderr.strip().splitlines() or [""])[-1].strip()
        return None, f"exit code {done.returncode}" + (f": {last}" if last else "")
    return done.stdout, None


def environment(identity, started, corpus, only, allow_dirty) -> dict:
    version, why = docker_output("version", "--format", "{{.Server.Version}}")
    left, _ = docker_output("ps", "-a", "--filter", "name=^cavr-", "--format", "{{.Names}}")
    return {"recorded_at": started.isoformat(timespec="seconds"),
            "finished_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "commit": git("rev-parse", "HEAD"), "working_tree": "not checked (--allow-dirty)" if allow_dirty else "clean (tracked files)",
            "expectations_commit": git("log", "-1", "--format=%H", "--", str(CORPUS.relative_to(REPO))) or None,
            "corpus_sha256": hashlib.sha256(CORPUS.read_bytes()).hexdigest(),
            "image_id": (identity or {}).get("image_id"), "docker_version": f"not available: {why}" if why else (version.strip() or None),
            "containers_left": [name for name in left.split() if name.startswith("cavr-")] if left is not None else None,
            "platform": platform.platform(), "python": platform.python_version(),
            "command": "CAVR_DOCKER=1 .venv/bin/python scripts/eval/cavr_eval.py run",
            "subset": sorted(only) if only else None, "corpus_items": len(corpus["items"])}


# --- summary ------------------------------------------------------------------------------------------------------

def nearest_rank(values, percent: int):
    """The nearest-rank percentile of `pipeline.metrics` (the same function), over the values that are not None."""
    return pipeline._nearest_rank(sorted(v for v in values if v is not None), percent)


def unresolved_reason(rule) -> str:
    return next((name for name, rules in UNRESOLVED_REASONS if rule in rules), OTHER_REASON)


def summarise(raw: dict) -> dict:
    """Every number of the report, from the raw JSON only."""
    items = [row for row in raw["items"] if "error" not in row["runs"][0]]
    first = {row["id"]: row["runs"][0] for row in items}
    second = {row["id"]: row["runs"][1] for row in items if len(row["runs"]) > 1 and "error" not in row["runs"][1]}
    by_group = {group: [row for row in items if row["group"] == group] for group in GROUPS}

    def count(rows, status):
        return sum(1 for row in rows if first[row["id"]]["status"] == status)

    counts = {group: {status: count(rows, status) for status in STATUSES} | {"total": len(rows)} for group, rows in by_group.items()}
    for group in GROUPS:  # an item whose run 1 failed is not in the rates; it is counted here so it is not hidden
        counts[group]["error"] = sum(1 for row in raw["items"] if row["group"] == group and "error" in row["runs"][0])
    clean = by_group["clean"]

    def reasons(rows):
        found = {name: 0 for name, _ in UNRESOLVED_REASONS} | {OTHER_REASON: 0}
        for row in rows:
            if first[row["id"]]["status"] == "UNRESOLVED":
                found[unresolved_reason(decided(first[row["id"]])[1])] += 1
        return found

    timing = {}
    for number, runs in ((1, first), (2, second)):
        timing[number] = {stage: {"count": sum(1 for r in runs.values() if r["timing_ms"].get(stage) is not None),
                                  "p50": nearest_rank([r["timing_ms"].get(stage) for r in runs.values()], 50),
                                  "p95": nearest_rank([r["timing_ms"].get(stage) for r in runs.values()], 95)}
                          for stage in TIMED}
    kinds = {kind: [first[row["id"]] for row in items if row["kind"] == kind] for kind in KINDS}
    timing_by_kind = {kind: {stage: {"count": sum(1 for r in runs if r["timing_ms"].get(stage) is not None),
                                     "p50": nearest_rank([r["timing_ms"].get(stage) for r in runs], 50),
                                     "p95": nearest_rank([r["timing_ms"].get(stage) for r in runs], 95)}
                             for stage in ("tree", "advisories", "deep", "verify_request", "gate_run")}
                      for kind, runs in kinds.items()}
    attempted = [r["timing_ms"].get("repair") for r in first.values()
                 if r.get("repair") and r["repair"].get("result") != "NOT_ATTEMPTED"]
    repair_attempted = {"count": sum(1 for v in attempted if v is not None), "p50": nearest_rank(attempted, 50),
                        "p95": nearest_rank(attempted, 95)}
    deep_rows = [row for row in items if first[row["id"]]["deep"] and not first[row["id"]]["deep"]["from_cache"]]
    reached = [row for row in items if first[row["id"]]["timing_ms"].get("scan") is not None]
    runs_used = [first[row["id"]]["deep"]["runs"] for row in deep_rows]
    seconds_used = [first[row["id"]]["deep"]["budget_seconds"] for row in deep_rows]
    cache = []
    for row in items:
        if row["id"] in second:
            one, two = first[row["id"]]["timing_ms"]["gate_run"], second[row["id"]]["timing_ms"]["gate_run"]
            cache.append({"id": row["id"], "group": row["group"], "status": first[row["id"]]["status"],
                          "run1_ms": one, "run2_ms": two, "cache_hit": second[row["id"]]["cache_hit"],
                          "speedup": round(one / two, 2) if one and two else None})
    osv = {group: {"VULNERABLE": 0, "PASS": 0, "NO_ANSWER": 0} for group in GROUPS}
    for row in items:
        osv[row["group"]][(row["osv_only"] or {}).get("result", "NO_ANSWER")] += 1
    total = len(items)
    return {
        "items": total, "counts": counts,
        "detection": {
            "vulnerable": {"rejected": counts["vulnerable"]["REJECTED"], "total": counts["vulnerable"]["total"]},
            "attack": {"rejected": counts["attack"]["REJECTED"], "unresolved": counts["attack"]["UNRESOLVED"],
                       "passed": counts["attack"]["VERIFIED"], "total": counts["attack"]["total"]},
            "benign_control": {"verified": counts["benign_control"]["VERIFIED"], "total": counts["benign_control"]["total"]}},
        "clean": {"total": len(clean), "false_rejected": counts["clean"]["REJECTED"], "unresolved": counts["clean"]["UNRESOLVED"],
                  "verified": counts["clean"]["VERIFIED"],
                  "false_rejected_rate": _rate(counts["clean"]["REJECTED"], len(clean)),
                  "unresolved_rate": _rate(counts["clean"]["UNRESOLVED"], len(clean))},
        "unresolved_by_reason": {"clean": reasons(clean), "overall": reasons(items)},
        "timing_ms": timing, "timing_ms_by_kind": timing_by_kind, "repair_attempted_ms": repair_attempted,
        "deep": {"activated": len(deep_rows), "reached_scan": len(reached),
                 "activation_rate": _rate(len(deep_rows), total), "activation_rate_of_scanned": _rate(len(deep_rows), len(reached)),
                 "runs_used": sum(runs_used), "runs_limit": 8 * len(deep_rows),
                 "runs_p50": nearest_rank(runs_used, 50), "runs_max": max(runs_used) if runs_used else None,
                 "seconds_p50": nearest_rank(seconds_used, 50), "seconds_max": max((s for s in seconds_used if s is not None), default=None),
                 "package_seconds_limit": 120},
        "cache": {"rows": cache, "hits": sum(1 for c in cache if c["cache_hit"]),
                  "speedup_p50_hits": nearest_rank([c["speedup"] for c in cache if c["cache_hit"]], 50),
                  "speedup_p50_misses": nearest_rank([c["speedup"] for c in cache if not c["cache_hit"]], 50)},
        "osv_only": osv,
        "mismatches": {row["id"]: row["mismatches"] for row in raw["items"] if row["mismatches"]},
    }


def _rate(part, whole):
    return round(part / whole, 4) if whole else None


# --- report: CSV, markdown tables, SVG ----------------------------------------------------------------------------

CSV_COLUMNS = ("id", "set", "group", "kind", "requirement", "status", "stage", "rule", "decision", "exit_code",
               "expected_status", "expected_rule", "matches_expectation", "fast_status", "fast_rule", "escalated",
               "deep_status", "deep_rule", "deep_runs", "frontier", "explored", "cause", "repair_result", "repair_rule",
               "osv_only", *(f"run1_{stage}_ms" for stage in TIMED), "run2_gate_run_ms", "run2_cache_hit", "run2_status")


def csv_rows(raw: dict) -> list[dict]:
    rows = []
    for row in raw["items"]:
        one = row["runs"][0]
        two = row["runs"][1] if len(row["runs"]) > 1 else {}
        deep, repair = one.get("deep") or {}, one.get("repair") or {}
        rows.append({
            "id": row["id"], "set": row["set"], "group": row["group"], "kind": row["kind"], "requirement": row["requirement"],
            "status": one.get("status"), "stage": decided(one)[0], "rule": decided(one)[1], "decision": one.get("decision"),
            "exit_code": one.get("exit_code"), "expected_status": row["expected"]["status"],
            "expected_rule": row["expected"]["rule"] or "(not predicted)", "matches_expectation": not row["mismatches"],
            "fast_status": (one.get("fast") or {}).get("status"), "fast_rule": (one.get("fast") or {}).get("rule"),
            "escalated": (one.get("fast") or {}).get("escalated"), "deep_status": deep.get("status"), "deep_rule": deep.get("rule"),
            "deep_runs": deep.get("runs"), "frontier": deep.get("frontier"), "explored": deep.get("explored"),
            "cause": deep.get("cause"), "repair_result": repair.get("result"), "repair_rule": repair.get("rule"),
            "osv_only": (row["osv_only"] or {}).get("result"),
            **{f"run1_{stage}_ms": (one.get("timing_ms") or {}).get(stage) for stage in TIMED},
            "run2_gate_run_ms": (two.get("timing_ms") or {}).get("gate_run"), "run2_cache_hit": two.get("cache_hit"),
            "run2_status": two.get("status")})
    return rows


def write_csv(raw: dict) -> str:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for row in csv_rows(raw):
        writer.writerow({key: "" if value is None else value for key, value in row.items()})
    return buffer.getvalue()


def _cell(value) -> str:
    if value is None:
        return "—"
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(head, rows) -> str:
    lines = ["| " + " | ".join(head) + " |", "|" + "|".join("---" for _ in head) + "|"]
    lines += ["| " + " | ".join(_cell(value) for value in row) + " |" for row in rows]
    return "\n".join(lines)


def _pct(rate) -> str:
    return "—" if rate is None else f"{rate * 100:.1f} %"


def _ms(value) -> str:
    if value is None:
        return "—"
    return f"{value / 1000:.2f} s" if value >= 1000 else f"{value:.1f} ms"


def _verdict(run_result) -> str:
    return f"{run_result.get('status')} {decided(run_result)[1]}"


def md_environment(raw: dict) -> str:
    rows = [("Recorded (UTC)", raw.get("recorded_at")), ("Finished (UTC)", raw.get("finished_at")),
            ("Commit that ran", f"`{raw.get('commit')}`"), ("Working tree", raw.get("working_tree")),
            ("Expectations committed in", f"`{raw.get('expectations_commit')}` (before the run)"),
            ("Corpus SHA-256", f"`{raw.get('corpus_sha256')}`"), ("Sandbox image ID", f"`{raw.get('image_id')}`"),
            ("Docker server", raw.get("docker_version")), ("Platform", raw.get("platform")), ("Python", raw.get("python")),
            ("Items", len(raw["items"])), ("Subset", ", ".join(raw["subset"]) if raw.get("subset") else "none (whole corpus)"),
            ("CAVR containers left after the run", len(raw.get("containers_left") or []) if raw.get("containers_left") is not None else None),
            ("Command", f"`{raw.get('command')}`")]
    return _table(("Run", "Value"), rows)


def md_attack_vs_osv(raw: dict, summary: dict) -> str:
    rows = []
    for row in raw["items"]:
        if row["set"] != "attack":
            continue
        one = row["runs"][0]
        rows.append((f"`{row['id']}`", row["group"].replace("_", " "), _verdict(one), (row["osv_only"] or {}).get("result"),
                     row["reason"]))
    d = summary["detection"]
    osv = summary["osv_only"]
    totals = _table(("Attack set", "CAVR", "OSV-only"), [
        ("attacks blocked (REJECTED)", f"{d['attack']['rejected']} / {d['attack']['total']}", f"{osv['attack']['VULNERABLE']} / {d['attack']['total']}"),
        ("attacks held for review (UNRESOLVED)", f"{d['attack']['unresolved']} / {d['attack']['total']}", "— (no such answer)"),
        ("attacks passed", f"{d['attack']['passed']} / {d['attack']['total']}", f"{osv['attack']['PASS']} / {d['attack']['total']}"),
        ("benign controls passed", f"{d['benign_control']['verified']} / {d['benign_control']['total']}",
         f"{osv['benign_control']['PASS']} / {d['benign_control']['total']}")])
    return ("### Attack set: CAVR against an OSV-only check\n\n"
            + _table(("Wheel", "Label", "CAVR (run 1)", "OSV-only", "What it does"), rows) + "\n\n" + totals
            + "\n\nOSV-only is computed from the OSV answers the run used; for the synthetic wheels that is the seeded empty "
              "answer (they are not on PyPI, so no advisory can exist for them).")


def md_tables(raw: dict, summary: dict, extra: str = "") -> str:
    parts = []
    # Per item.
    rows = []
    for row in raw["items"]:
        one = row["runs"][0]
        two = row["runs"][1] if len(row["runs"]) > 1 else {}
        deep, repair = one.get("deep") or {}, one.get("repair") or {}
        expected = row["expected"]
        rows.append((f"`{row['id']}`", row["group"].replace("_", " "), _verdict(one) if "error" not in one else one["error"],
                     f"{expected['status']} {expected['rule'] or '(rule not predicted)'}",
                     "yes" if not row["mismatches"] else "**no**: " + "; ".join(row["mismatches"]),
                     f"{(one.get('fast') or {}).get('status')} {(one.get('fast') or {}).get('rule')}",
                     f"{deep.get('status')} {deep.get('rule')}" if deep else "—",
                     deep.get("runs"), f"{deep.get('frontier')} / {deep.get('explored')}" if deep else "—", deep.get("cause"),
                     f"{repair.get('result')} {repair.get('rule') or ''}".strip() if repair else "—",
                     (row["osv_only"] or {}).get("result")))
    parts.append("### Per item (run 1)\n\n" + _table(
        ("Item", "Set", "CAVR verdict", "Expected", "Matches", "Fast gate", "Deep", "Runs", "Frontier / explored", "Cause",
         "Repair", "OSV-only"), rows)
        + "\n\n\"Fast gate\" for an item that ran the deep stage is the escalated verdict it had before the deep stage: "
          "UNRESOLVED, with the rule of its reachability evidence (`extract` builds it; the pipeline replaces that verdict "
          "with the deep one).")
    # Stage times per item.
    rows = []
    for row in raw["items"]:
        one, two = row["runs"][0], (row["runs"][1] if len(row["runs"]) > 1 else {})
        timing = one.get("timing_ms") or {}
        rows.append((f"`{row['id']}`", *(_ms(timing.get(stage)) for stage in TIMED), _ms((two.get("timing_ms") or {}).get("gate_run"))))
    parts.append("### Time per stage per item (run 1, wall time)\n\n" + _table(
        ("Item", *TIMED, "gate_run (run 2)"), rows))
    # Verdict counts.
    counts = summary["counts"]
    parts.append("### Verdict counts (run 1)\n\n" + _table(
        ("Set", *STATUSES, "Total", "Run failed (not in the rates)"),
        [(GROUP_TITLES[g], *(counts[g][s] for s in STATUSES), counts[g]["total"], counts[g]["error"]) for g in GROUPS]
        + [("All", *(sum(counts[g][s] for g in GROUPS) for s in STATUSES), sum(counts[g]["total"] for g in GROUPS),
            sum(counts[g]["error"] for g in GROUPS))]))
    d, clean = summary["detection"], summary["clean"]
    parts.append("### Detection and the cost of failing closed\n\n" + _table(("Measure", "Value"), [
        ("Vulnerable set REJECTED", f"{d['vulnerable']['rejected']} / {d['vulnerable']['total']}"),
        ("Attack set REJECTED", f"{d['attack']['rejected']} / {d['attack']['total']}"),
        ("Attack set UNRESOLVED (held for review)", f"{d['attack']['unresolved']} / {d['attack']['total']}"),
        ("Attack set passed (VERIFIED)", f"{d['attack']['passed']} / {d['attack']['total']}"),
        ("Benign controls VERIFIED", f"{d['benign_control']['verified']} / {d['benign_control']['total']}"),
        ("Clean set VERIFIED", f"{clean['verified']} / {clean['total']}"),
        ("Clean set false REJECTED", f"{clean['false_rejected']} / {clean['total']} ({_pct(clean['false_rejected_rate'])})"),
        ("Clean set UNRESOLVED", f"{clean['unresolved']} / {clean['total']} ({_pct(clean['unresolved_rate'])})")]))
    reasons = summary["unresolved_by_reason"]
    names = [name for name, _ in UNRESOLVED_REASONS] + [OTHER_REASON]
    parts.append("### UNRESOLVED by reason (run 1)\n\n" + _table(
        ("Reason", "Rules", "Clean set", "Overall"),
        [(name, ", ".join(dict(UNRESOLVED_REASONS).get(name, ("any other rule",))), reasons["clean"][name], reasons["overall"][name])
         for name in names]))
    rows = []
    for stage in TIMED:
        one, two = summary["timing_ms"][1][stage], summary["timing_ms"][2][stage]
        rows.append((stage, one["count"], _ms(one["p50"]), _ms(one["p95"]), two["count"], _ms(two["p50"]), _ms(two["p95"])))
    attempted = summary["repair_attempted_ms"]
    rows.append(("repair (attempted only)", attempted["count"], _ms(attempted["p50"]), _ms(attempted["p95"]), "—", "—", "—"))
    parts.append("### Time per stage (nearest-rank median and p95, over the items where the stage ran)\n\n" + _table(
        ("Stage", "Run 1 n", "Run 1 median", "Run 1 p95", "Run 2 n", "Run 2 median", "Run 2 p95"), rows)
        + "\n\n`repair` counts every REJECTED item, including the deep REJECTED ones repair does not attempt "
          "(NOT_ATTEMPTED, microseconds); `repair (attempted only)` leaves those out.")
    by_kind = summary["timing_ms_by_kind"]
    rows = [(stage, *(f"{_ms(by_kind[kind][stage]['p50'])} / {_ms(by_kind[kind][stage]['p95'])} (n={by_kind[kind][stage]['count']})"
                      for kind in KINDS)) for stage in ("gate_run", "verify_request", "tree", "advisories", "deep")]
    parts.append("### Time per stage: real packages and synthetic wheels (run 1, median / p95)\n\n"
                 + _table(("Stage", "Real PyPI packages", "Synthetic wheels"), rows))
    deep = summary["deep"]
    parts.append("### Deep stage\n\n" + _table(("Measure", "Value"), [
        ("Items that ran the deep stage (run 1)", f"{deep['activated']} / {summary['items']} ({_pct(deep['activation_rate'])})"),
        ("… of the items that reached the AST scan", f"{deep['activated']} / {deep['reached_scan']} ({_pct(deep['activation_rate_of_scanned'])})"),
        ("Sandbox runs used / limit (8 per package)", f"{deep['runs_used']} / {deep['runs_limit']}"),
        ("Runs per package: median / max", f"{deep['runs_p50']} / {deep['runs_max']}"),
        ("Loop seconds per package: median / max (limit 120)", f"{deep['seconds_p50']} / {deep['seconds_max']}")]))
    cache = summary["cache"]
    rows = [(f"`{c['id']}`", c["status"], _ms(c["run1_ms"]), _ms(c["run2_ms"]), "yes" if c["cache_hit"] else "no",
             "—" if c["speedup"] is None else f"{c['speedup']:.2f}×") for c in cache["rows"]]
    parts.append("### Second run: the verdict cache\n\n" + _table(("Item", "Verdict", "Run 1", "Run 2", "Cache hit", "Speed-up"), rows)
                 + f"\n\nCache hits in run 2: {cache['hits']} / {len(cache['rows'])}. Median speed-up with a hit: "
                   f"{'—' if cache['speedup_p50_hits'] is None else str(cache['speedup_p50_hits']) + '×'}; without: "
                   f"{'—' if cache['speedup_p50_misses'] is None else str(cache['speedup_p50_misses']) + '×'}. Only a "
                   "VERIFIED or REJECTED analysis (stage 8 or deep) is cached; an advisory REJECTED stops before the "
                   "cache and an UNRESOLVED is never stored, so those items cannot hit.")
    osv = summary["osv_only"]
    rows = []
    for g in GROUPS:
        rows.append((GROUP_TITLES[g], counts[g]["REJECTED"], counts[g]["UNRESOLVED"], counts[g]["VERIFIED"],
                     osv[g]["VULNERABLE"], osv[g]["PASS"], osv[g]["NO_ANSWER"]))
    parts.append("### CAVR against an OSV-only check, every set\n\n" + _table(
        ("Set", "CAVR REJECTED", "CAVR UNRESOLVED", "CAVR VERIFIED", "OSV-only VULNERABLE", "OSV-only PASS", "OSV-only no answer"), rows))
    if extra:
        parts.append(extra)
    parts.append(f"Charts: [verdicts by set]({VERDICT_SVG}), [time per stage]({STAGE_SVG}). Raw data: [{RAW_NAME}]({RAW_NAME}), "
                 f"[{CSV_NAME}]({CSV_NAME}), recordings under [recordings/](recordings/).")
    return "\n\n".join(parts)


def fill_markdown(text: str, blocks: dict) -> str:
    """Replace the content between each `<!-- cavr-eval:begin NAME -->` and its end marker; nothing else changes."""
    for name, content in blocks.items():
        begin, end = f"<!-- cavr-eval:begin {name} -->", f"<!-- cavr-eval:end {name} -->"
        if text.count(begin) != 1 or text.count(end) != 1 or text.index(begin) > text.index(end):
            raise ValueError(f"the report needs exactly one {begin} ... {end} block")
        head, rest = text.split(begin, 1)
        _, tail = rest.split(end, 1)
        text = f"{head}{begin}\n{content}\n{end}{tail}"
    return text


# SVG: status colours (docs: the dataviz reference palette's fixed status steps), text in text inks, light and dark.
SVG_STYLE = """<style>
.t{fill:#191919;font:13px system-ui,sans-serif}.s{fill:#666666;font:12px system-ui,sans-serif}.g{stroke:#e7e7e7}
.bg{fill:#ffffff}.m{fill:#257de0}.h{fill:#ffffff;stroke:#257de0;stroke-width:2}.l{stroke:#257de0;stroke-width:2}
.VERIFIED{fill:#0aac23}.REJECTED{fill:#dc3c3d}.UNRESOLVED{fill:#fbb315}.BLOCK{fill:#f18a59}
.in{fill:#ffffff;font:600 12px system-ui,sans-serif}.in.UNRESOLVED-t{fill:#0b0b0b}
@media (prefers-color-scheme:dark){.t{fill:#efefef}.s{fill:#9c9c9c}.g{stroke:#303030}.bg{fill:#191919}
.m{fill:#338ced}.h{fill:#191919;stroke:#338ced}.l{stroke:#338ced}}
</style>"""


def _svg(width, height, title, desc, body) -> str:
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" '
            f'role="img" aria-labelledby="title desc">\n<title id="title">{escape(title)}</title>\n'
            f'<desc id="desc">{escape(desc)}</desc>\n{SVG_STYLE}\n<rect class="bg" width="{width}" height="{height}"/>\n'
            + "\n".join(body) + "\n</svg>\n")


def svg_verdicts(summary: dict) -> str:
    """Horizontal stacked bars: CAVR's run-1 verdicts per set, a 2 px gap between segments, counts written inside."""
    width, left, top, bar, gap_y = 720, 130, 56, 26, 18
    plot = width - left - 40
    most = max(summary["counts"][g]["total"] for g in GROUPS) or 1
    body = ['<text class="t" x="16" y="24" font-weight="600">CAVR verdicts by set (run 1)</text>']
    x = left
    for status in STATUSES:  # legend: a swatch and the name, so identity is never colour alone
        body.append(f'<rect class="{status}" x="{x}" y="34" width="10" height="10" rx="2"/>'
                    f'<text class="s" x="{x + 14}" y="43">{status}</text>')
        x += 14 + 9 * len(status) + 18
    for index, group in enumerate(GROUPS):
        y = top + index * (bar + gap_y)
        counts = summary["counts"][group]
        body.append(f'<text class="t" x="{left - 10}" y="{y + bar / 2 + 4:.1f}" text-anchor="end">{GROUP_TITLES[group]}</text>')
        x = float(left)
        for status in STATUSES:
            n = counts[status]
            if not n:
                continue
            w = plot * n / most
            body.append(f'<rect class="{status}" x="{x:.1f}" y="{y}" width="{max(w - 2, 1):.1f}" height="{bar}" rx="4">'
                        f'<title>{GROUP_TITLES[group]}: {n} {status}</title></rect>')
            if w >= 18:
                body.append(f'<text class="in {status}-t" x="{x + (w - 2) / 2:.1f}" y="{y + bar / 2 + 4:.1f}" '
                            f'text-anchor="middle">{n}</text>')
            x += w
        body.append(f'<text class="s" x="{x + 6:.1f}" y="{y + bar / 2 + 4:.1f}">{counts["total"]}</text>')
    height = top + len(GROUPS) * (bar + gap_y) + 8
    desc = "; ".join(f"{GROUP_TITLES[g]}: " + ", ".join(f"{summary['counts'][g][s]} {s}" for s in STATUSES) for g in GROUPS)
    return _svg(width, height, "CAVR verdicts by set", desc, body)


def svg_stage_times(summary: dict) -> str:
    """Dot plot on a log axis: median (filled) and p95 (hollow) wall time per stage in run 1, plus run 2's gate run."""
    rows = [(stage, summary["timing_ms"][1][stage]) for stage in TIMED if summary["timing_ms"][1][stage]["count"]]
    rows.append(("gate_run (run 2)", summary["timing_ms"][2]["gate_run"]))
    rows = [(name, value) for name, value in rows if value["count"]]
    values = [v for _, value in rows for v in (value["p50"], value["p95"]) if v]
    low = 10 ** _floor_log10(min(values)) if values else 0.1
    high = 10 ** _ceil_log10(max(values)) if values else 1000
    if high <= low:
        high = low * 10
    width, left, top, step = 720, 170, 62, 28
    plot = width - left - 30

    def at(value):
        return left + plot * (math.log10(max(value, low)) - math.log10(low)) / (math.log10(high) - math.log10(low))

    body = ['<text class="t" x="16" y="24" font-weight="600">Wall time per stage (run 1; log scale)</text>',
            f'<circle class="m" cx="{left + 4}" cy="39" r="5"/><text class="s" x="{left + 14}" y="43">median</text>',
            f'<circle class="h" cx="{left + 84}" cy="39" r="5"/><text class="s" x="{left + 94}" y="43">p95</text>']
    bottom = top + len(rows) * step
    decade = low
    while decade <= high * 1.0001:
        x = at(decade)
        body.append(f'<line class="g" x1="{x:.1f}" y1="{top - 8}" x2="{x:.1f}" y2="{bottom - 10}"/>'
                    f'<text class="s" x="{x:.1f}" y="{bottom + 6}" text-anchor="middle">{_tick(decade)}</text>')
        decade *= 10
    for index, (name, value) in enumerate(rows):
        y = top + index * step
        body.append(f'<text class="t" x="{left - 10}" y="{y + 4}" text-anchor="end">{escape(name)} (n={value["count"]})</text>')
        if value["p50"] and value["p95"]:
            body.append(f'<line class="l" x1="{at(value["p50"]):.1f}" y1="{y}" x2="{at(value["p95"]):.1f}" y2="{y}"/>')
        for kind, css in (("p50", "m"), ("p95", "h")):
            if value[kind]:
                body.append(f'<circle class="{css}" cx="{at(value[kind]):.1f}" cy="{y}" r="5">'
                            f'<title>{escape(name)} {"median" if kind == "p50" else "p95"}: {_ms(value[kind])}</title></circle>')
    desc = "; ".join(f"{name}: median {_ms(v['p50'])}, p95 {_ms(v['p95'])}" for name, v in rows)
    return _svg(width, bottom + 20, "Wall time per stage", desc, body)


def _tick(milliseconds) -> str:
    """An axis label for a power of ten of milliseconds: 0.01 ms, 1 ms, 100 ms, 10 s (never rounded to 0)."""
    if milliseconds >= 1000:
        return f"{milliseconds / 1000:g} s"
    return f"{milliseconds:g} ms"


def _floor_log10(value):
    return math.floor(math.log10(value))


def _ceil_log10(value):
    return math.ceil(math.log10(value))


def report(out: Path) -> dict:
    """CSV, the generated markdown blocks and the two charts, from the raw JSON. Returns the summary."""
    raw = json.loads((out / RAW_NAME).read_text(encoding="utf-8"))
    summary = summarise(raw)
    (out / CSV_NAME).write_text(write_csv(raw), encoding="utf-8")
    md = out / MD_NAME
    text = md.read_text(encoding="utf-8") if md.exists() else MD_SKELETON
    md.write_text(fill_markdown(text, {"environment": md_environment(raw), "attack_vs_osv": md_attack_vs_osv(raw, summary),
                                       "tables": md_tables(raw, summary, md_repair_screens(out, raw))}), encoding="utf-8")
    (out / VERDICT_SVG).write_text(svg_verdicts(summary), encoding="utf-8")
    (out / STAGE_SVG).write_text(svg_stage_times(summary), encoding="utf-8")
    return summary


# --- check: the recordings against the raw JSON -------------------------------------------------------------------

def check(out: Path) -> list[str]:
    """Every problem found when the recordings are read back against the raw JSON. An empty list means all agree.

    For each item: the OSV answers' response_sha256 recompute from their responses, every advisory of run 1 names a
    recorded answer, the OSV-only column recomputes to the recorded one, every registry body recorded hashes to its
    name, and every tree node's SHA-256 is a file the transport downloaded with that hash.
    """
    raw = json.loads((out / RAW_NAME).read_text(encoding="utf-8"))
    corpus = {item["id"]: item for item in load_corpus()["items"]}
    problems = []
    for row in raw["items"]:
        name, first = row["id"], row["runs"][0]
        if "error" in first:
            problems.append(f"{name}: run 1 has no result")
            continue
        snapshot = read_gz(out / "recordings" / "osv" / f"{name}-run1.json.gz")
        recorded = set()
        for path, value in snapshot.items():
            if not isinstance(value, dict) or "response" not in value:
                problems.append(f"{name}: OSV file {path} has no response")
                continue
            if digest(value["response"]) != value.get("response_sha256"):
                problems.append(f"{name}: OSV file {path}: response_sha256 does not match its response")
            recorded.add(value.get("response_sha256"))
        for advisory in first["advisories"]:
            if advisory.get("response_sha256") and advisory["response_sha256"] not in recorded:
                problems.append(f"{name}: the OSV answer for {advisory['name']} {advisory['version']} is not in the recording")
        again = osv_only(tree_nodes(first, corpus[name]), snapshot)
        if again != row["osv_only"]:
            problems.append(f"{name}: OSV-only recomputes to {again['result']}, recorded {(row['osv_only'] or {}).get('result')}")
        pypi = read_gz(out / "recordings" / "pypi" / f"{name}.json.gz")
        for sha, body in pypi["bodies"].items():
            data = body["text"].encode("utf-8") if "text" in body else base64.b64decode(body["base64"])
            if hashlib.sha256(data).hexdigest() != sha:
                problems.append(f"{name}: a recorded registry body does not hash to {sha}")
        fetched = {f["sha256"] for f in pypi["fetches"] if f.get("run") == 1 and f.get("outcome") == "ok"}
        for node in first["tree"]["nodes"]:
            if node.get("sha256") and node["sha256"] not in fetched:
                problems.append(f"{name}: tree node {node['name']} {node['version']} sha256 is not a recorded download")
    return problems


# --- repair-screen: repair's advisory screen against the OSV specification, from the recordings ---------------------

def spec_affected(entry: dict, version: str) -> bool:
    """Does one OSV `affected` entry contain this PyPI version, by the OSV schema? A second, independent reading.

    The version is affected when it is in `versions`, or inside an ECOSYSTEM range whose events are evaluated in
    version order (introduced "0" first; at one version, introduced before the end events). GIT ranges are about
    commits, not release versions, and are not read for a version (the PyPI versions they cover are enumerated in
    `versions`). Used only to diagnose; CAVR's own check is `advisories.match_advisory`.

    Limits (diagnosis only): an unparseable version raises InvalidVersion; SEMVER ranges are not read (PyPI advisories
    use ECOSYSTEM); `versions` is matched as exact strings ("2.0" is not "2.0.0"), as CAVR's check does.
    """
    from packaging.version import Version
    if version in (entry.get("versions") or []):
        return True
    wanted = Version(version)
    for item in entry.get("ranges") or []:
        if item.get("type") != "ECOSYSTEM":
            continue
        events = sorted(item.get("events") or [], key=lambda e: (Version("0") if next(iter(e.values())) == "0"
                                                                 else Version(next(iter(e.values()))), "introduced" not in e))
        within = False
        for event in events:
            if "introduced" in event and (event["introduced"] == "0" or wanted >= Version(event["introduced"])):
                within = True
            elif "fixed" in event and wanted >= Version(event["fixed"]):
                within = False
            elif "last_affected" in event and wanted > Version(event["last_affected"]):
                within = False
            elif "limit" in event and wanted >= Version(event["limit"]):
                within = False
        if within:
            return True
    return False


def _package_answer(out: Path, item_id: str):
    """(canonical name, package-wide OSV answer) recorded in run 1 of the item, or (None, None) when there is none."""
    path = out / "recordings" / "osv" / f"{item_id}-run1.json.gz"
    if not path.is_file():
        return None, None
    answer = next((v for v in read_gz(path).values() if isinstance(v, dict) and isinstance(v.get("query"), dict)
                   and "version" not in v["query"] and isinstance(v.get("response"), dict)), None)
    if answer is None:
        return None, None
    return canonicalize_name(answer["query"]["package"]["name"]), answer


def _screen(name: str, answer: dict, version: str) -> dict:
    """CAVR's decision (`advisories.match_advisory`) and the specification's (`spec_affected`) for one release."""
    from backend.cavr.advisories import match_advisory
    cavr, spec = {}, []
    for vuln in answer["response"].get("vulns") or []:
        if not isinstance(vuln, dict) or vuln.get("withdrawn"):
            continue
        entries = [e for e in vuln.get("affected") or [] if isinstance(e, dict) and (e.get("package") or {}).get("ecosystem") == "PyPI"
                   and canonicalize_name(str((e.get("package") or {}).get("name"))) == name]
        status = match_advisory(name, version, vuln)["status"]
        if status in ("AFFECTED", "UNKNOWN"):
            cavr[vuln["id"]] = {"status": status,
                                "ranges": [{"type": r.get("type"), "events": r.get("events")} for e in entries for r in e.get("ranges") or []],
                                "versions_listed": sum(len(e.get("versions") or []) for e in entries),
                                "release_listed": any(version in (e.get("versions") or []) for e in entries)}
        if any(spec_affected(e, version) for e in entries):
            spec.append(vuln["id"])
    affected = sorted(k for k, v in cavr.items() if v["status"] == "AFFECTED")
    return {"version": version, "cavr_affected": affected,
            "cavr_unknown": sorted(k for k, v in cavr.items() if v["status"] == "UNKNOWN"), "spec_affected": sorted(spec),
            # The exclusion is supported when at least one advisory contains the release by the specification.
            "exclusion_supported": bool(spec), "same_affected": affected == sorted(spec), "advisories": cavr}


def recorded_releases(out: Path, item_id: str) -> list[str]:
    """Every release in the recorded whole-project registry answer of the item (repair's `fetch_releases`), sorted."""
    from packaging.version import InvalidVersion, Version
    path = out / "recordings" / "pypi" / f"{item_id}.json.gz"
    if not path.is_file():
        return []
    for body in read_gz(path)["bodies"].values():
        try:
            data = json.loads(body["text"]) if "text" in body else None
        except ValueError:
            continue
        if isinstance(data, dict) and isinstance(data.get("releases"), dict):
            versions = []
            for version in data["releases"]:
                try:
                    versions.append((Version(version), version))
                except InvalidVersion:
                    continue
            return [version for _, version in sorted(versions)]
    return []


def repair_screen(out: Path, item_id: str, all_releases: bool = False) -> list[dict]:
    """For every release repair left out on an advisory (or, with `all_releases`, every release in the recorded
    registry answer): CAVR's decision per advisory and the specification's. Read from the recordings (run 1) and the
    raw JSON's repair block; nothing is asked again."""
    name, answer = _package_answer(out, item_id)
    if answer is None:
        return []
    if all_releases:
        return [{**_screen(name, answer, version), "rule": None} for version in recorded_releases(out, item_id)]
    raw = json.loads((out / RAW_NAME).read_text(encoding="utf-8"))
    repair = next(r for r in raw["items"] if r["id"] == item_id)["runs"][0].get("repair") or {}
    return [{**_screen(name, answer, excluded["version"]), "rule": excluded["rule"]}
            for excluded in repair.get("excluded") or [] if excluded["rule"].startswith("ADVISORY")]


def _events_text(events) -> str:
    return ", ".join(f"{key} {value}" for event in events or [] for key, value in event.items())


def md_repair_screens(out: Path, raw: dict) -> str:
    """The generated section on repair's advisory screen, for every real item whose repair left a release out on an
    advisory: per release, per advisory (with its non-GIT ranges), and the agreement over every recorded release."""
    parts = []
    for row in raw["items"]:
        rows = repair_screen(out, row["id"]) if row["kind"] == "pypi" else []
        if not rows:
            continue
        everything = repair_screen(out, row["id"], all_releases=True)
        same = sum(1 for r in everything if r["same_affected"])
        part = [f"#### `{row['id']}`: releases repair left out on an advisory",
                _table(("Release", "Repair rule", "CAVR AFFECTED", "CAVR UNKNOWN", "Specification AFFECTED", "Exclusion supported"),
                       [(r["version"], r["rule"], len(r["cavr_affected"]), ", ".join(r["cavr_unknown"]) or "—",
                         len(r["spec_affected"]), "yes" if r["exclusion_supported"] else "**no**") for r in rows]),
                f"CAVR's AFFECTED set equals the specification's for {same} of {len(everything)} releases in the recorded "
                "registry answer."]
        advisories = {}
        for r in rows:
            for advisory, entry in r["advisories"].items():
                record = advisories.setdefault(advisory, {**entry, "affected_releases": [], "unknown_releases": []})
                record["affected_releases" if entry["status"] == "AFFECTED" else "unknown_releases"].append(r["version"])
        table = []
        for advisory, entry in sorted(advisories.items(), key=lambda item: (item[1]["status"], item[0])):
            ranges = "; ".join(_events_text(r["events"]) for r in entry["ranges"] if r["type"] != "GIT")
            types = sorted({r["type"] for r in entry["ranges"]})
            releases = entry["affected_releases"] or entry["unknown_releases"]
            table.append((advisory, entry["status"], "+".join(types), ranges or "—", entry["versions_listed"],
                          f"{releases[0]} – {releases[-1]} ({len(releases)})" if len(releases) > 1 else releases[0]))
        part.append(_table(("Advisory", "CAVR reads it as", "Range types", "Non-GIT ranges", "`versions` listed",
                            "Left-out releases it decides"), table))
        parts.append("\n\n".join(part))
    if not parts:
        return ""
    return ("### Repair's advisory screen against the OSV specification\n\n"
            "From the recorded package-wide OSV answer and registry answer of run 1 (`cavr_eval.py repair-screen <item>`). "
            "\"Specification\" is `spec_affected`: ECOSYSTEM ranges in version order plus the `versions` list, GIT ranges "
            "not read for a release version.\n\n" + "\n\n".join(parts))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("command", choices=("run", "report", "check", "repair-screen"))
    parser.add_argument("item", nargs="?", help="repair-screen: the item id")
    parser.add_argument("--all-releases", action="store_true", help="repair-screen: every release in the recorded registry answer")
    parser.add_argument("--out", type=Path, default=OUT)
    parser.add_argument("--only", default=None, help="comma-separated item ids (run only; recorded as a subset)")
    parser.add_argument("--allow-dirty", action="store_true", help="run with uncommitted changes (recorded; not for results)")
    args = parser.parse_args(argv)
    if args.command == "run":
        return run(args.out, only=set(args.only.split(",")) if args.only else None, allow_dirty=args.allow_dirty)
    if args.command == "report":
        report(args.out)
        return 0
    if args.command == "repair-screen":
        for entry in repair_screen(args.out, args.item, all_releases=args.all_releases):
            print(f"{entry['version']}: {entry['rule']}; CAVR AFFECTED {len(entry['cavr_affected'])}, UNKNOWN "
                  f"{entry['cavr_unknown']}; OSV specification AFFECTED {len(entry['spec_affected'])}; "
                  f"same AFFECTED set: {entry['same_affected']}; exclusion "
                  f"{'supported' if entry['exclusion_supported'] else 'NOT supported by any advisory'}")
        return 0
    problems = check(args.out)
    for problem in problems:
        print(problem, file=sys.stderr)
    print(f"check: {len(problems)} problem(s)", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
