"""Dashboard API of CAVR.

`POST /api/cavr/intercept` takes a request (`pip install name==version`), runs the one
verification path, `backend.cavr.pipeline.verify_request`, and publishes what that path found
as a stream of events. Nothing here computes a verdict: every status, hash, advisory id and
sink in an event is copied from the pipeline's verdict.

How one run goes:

1. `intercept_package_endpoint` makes a run id and starts `run_verification` in the background.
2. `run_verification` publishes the "request received" event, calls `verify_dashboard_request`
   in a worker thread (it downloads from PyPI and asks OSV), then publishes one event per
   pipeline stage that ran (`verdict_events`), the verdict, and the final event.
3. `GET /api/cavr/stream/{run_id}` replays the run's events from the first one and ends after
   the last, so a client that connects late misses nothing.
4. `GET /api/cavr/proof/{run_id}` returns the whole verdict, and `stages`: the page's timeline
   (`stage_summary`), which says for each stage whether it ran and which values it computed.
   A value that was not computed is null; the page prints a dash for it and never fills it in.

Every event is also appended to the run's hash chain (`assurance.EvidenceChain`).

The project the dashboard verifies for is `PROJECT_DIR` (the sample invoice project) with the
policy file `requirement_gate.POLICY_PATH`.

Demo conditions. A scenario may name a condition that changes the network between CAVR and
PyPI: "tampered_wheel" flips one bit of every downloaded wheel, "network_off" fails every
request. The pipeline then runs unchanged and gives the verdict it would give in that
situation. A condition can only make a verdict worse, never better, and it is written into
every event and into the proof (`demo_condition`). Such a run gets no store: it is not written
to the verdict log, so it is not in the report numbers of `/api/cavr/metrics`, and it neither
reads nor writes the verdict cache. It downloads into a directory of its own
(`demo_quarantine_dir`), so it cannot delete or change a wheel that a real run quarantined.

Repair (PR 15): after a REJECTED verdict, `dashboard_repair` asks `repair_proposal.propose_repair` for a
proposal (a newer pin re-checked by the pipeline on a copy of the project) and puts the block in the
verdict event's `repair` and in the proof. It is a proposal only: the verdict, the certificate and the
run's status are the pipeline's, and nothing is written to the project. Under a demo condition the same
condition applies to the candidates' downloads.

Recorded M2 runs (PR 19): `GET /api/cavr/recorded-runs` lists the real gate runs of the M2 demo wheels that
`tests/test_cavr_m2_wheels.py --record` wrote to `backend/cavr/recorded/m2-demo-runs.json` (CAVR sandbox, Docker).
`POST /api/cavr/recorded-runs/{name}` replays one of them without Docker or network: the recorded pipeline verdict goes
through the same `verdict_events`, `stage_summary` and certificate as a live run, and every event, the proof and the
certificate carry `recorded` (id, date, commit, image). A replay is never logged or cached. The name is looked up in
the fixed list loaded from that one file; no path is ever built from it.

The live chips run the fast gate only (the sample project has no escalated package). For a package with deep evidence
the events have a `deep_completed` event, and the proof has `packages` (`package_views`: each package's fast-gate
stages and its deep block) and `causal_graphs`. Without deep evidence the sandbox fields of the proof say NOT_RUN.
Not run on this path: project tests on the repair proposal and reconstruction.
"""
from __future__ import annotations
import asyncio
import copy
import json
import time
import uuid
from pathlib import Path
from typing import AsyncGenerator
from urllib.parse import urlsplit
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from pydantic import BaseModel

from backend.config import DATA
from backend.cavr import requirement_gate
from backend.cavr.advisories import FIRST_IDS, summarise_ids
from backend.cavr.assurance import EvidenceChain, certificate_for_verdict, generate_printable_html_certificate, verify_chain
from backend.cavr.capture import redact
from backend.cavr.dashboard_view import causal_graphs, package_views
from backend.cavr.context_extractor import SAMPLE_PROJECT_DIR
from backend.cavr.pipeline import default_quarantine_dir, metrics as pipeline_metrics, verify_request
from backend.cavr.pypi_client import FILES_HOST, HttpxTransport, TransportError
from backend.cavr.repair_proposal import no_repair, propose_repair
from backend.cavr.storage import CavrStorage
from backend.cavr.verdict_cache import KEY_FIELDS, lookup as cache_lookup

cavr_router = APIRouter()
storage = CavrStorage()

# What the pipeline is given. Tests replace these; None means the pipeline's own default.
PROJECT_DIR = SAMPLE_PROJECT_DIR
TRANSPORT = None
QUARANTINE_DIR = None
ADVISORY_CACHE_DIR = None
LIVE_ADVISORIES = True

# Per-run state, in memory. The oldest runs are dropped after MAX_RUNS.
MAX_RUNS = 200
RUN_EVENTS: dict[str, list[dict]] = {}
RUN_FINISHED: set[str] = set()
RUN_PROOFS: dict[str, dict] = {}
RUN_CHAINS: dict[str, EvidenceChain] = {}
RUN_CERTIFICATES: dict[str, dict] = {}

ALIASES = {"VERIFIED": "ALLOW", "REJECTED": "BLOCK", "BLOCK": "BLOCK", "UNRESOLVED": "NEEDS_REVIEW"}
NOT_RUN = "not available: no deep analysis ran for this request"
NOT_IN_EVIDENCE = "not in the deep evidence (it keeps the image, the lockdown flags' digest and each run's container)"
# The recorded M2 runs (PR 19): one fixed file, read once. A name is only ever a key of its "runs".
RECORDED_PATH = Path(__file__).resolve().parent / "recorded" / "m2-demo-runs.json"
RECORDED_ORDER = ("REJECTED", "VERIFIED", "UNRESOLVED")
RECORDED_KEYS = ("recorded_at", "commit", "image_id", "docker_version", "source", "label")
_RECORDED = None  # (header, runs) once loaded
# The stages of the page's timeline, in pipeline order.
STAGE_TITLES = {"capture": "Request (C1)", "gate": "Requirement gate (C2)", "artifact": "Artifact, tree and advisories (C3)",
                "cache": "Verdict cache lookup", "analysis": "Contract, AST scan and sinks (C4)", "verdict": "Verdict"}
# Whether the downloaded bytes equal the registry digest. Any other artifact rule means no comparison was made.
HASH_MATCHES = {"HASH_MATCH": True, "HASH_MISMATCH": False}

# The dashboard's scenario chips, in the order the page shows them. Each one is a real request;
# the page reads this list and sends the chosen id to POST /api/cavr/run. `expected_status` and
# `description` say what the chip is meant to show and are never used to compute anything.
SCENARIOS = [
    {"id": "verified", "display_name": "1. pypdf 6.21.4", "package": "pypdf", "version": "6.21.4", "condition": None,
     "expected_status": "VERIFIED",
     "description": "The real wheel from PyPI: hash, dependency tree, OSV, contract and sink reachability all pass."},
    {"id": "verified_again", "display_name": "2. pypdf 6.21.4 again", "package": "pypdf", "version": "6.21.4",
     "condition": None, "expected_status": "VERIFIED",
     "description": "The same request a second time. A cache hit when chip 1 has run before for the same file, tree, "
                    "contract, policy and analyzer; the wheel is still downloaded and hashed, and OSV is still asked."},
    {"id": "recent_advisories", "display_name": "3. pypdf 6.19.0 (OSV)", "package": "pypdf", "version": "6.19.0",
     "condition": None, "expected_status": "REJECTED",
     "description": "The earlier demo pin. Permitted by the policy, but OSV now lists advisories that affect this version."},
    {"id": "known_vulnerable", "display_name": "4. pypdf 5.1.0 (OSV)", "package": "pypdf", "version": "5.1.0", "condition": None,
     "expected_status": "REJECTED",
     "description": "Permitted by the policy, but OSV lists advisories that affect this version."},
    {"id": "not_on_allowlist", "display_name": "5. left-pad 1.0 (not allowed)", "package": "left-pad", "version": "1.0",
     "condition": None, "expected_status": "BLOCK",
     "description": "Not on the project allowlist: blocked by the requirement gate before anything is downloaded."},
    {"id": "tampered_wheel", "display_name": "6. Tampered wheel", "package": "pypdf", "version": "6.21.4",
     "condition": "tampered_wheel", "expected_status": "REJECTED",
     "description": "One bit of the downloaded wheel is flipped on the way: its SHA-256 no longer matches the registry."},
    {"id": "network_off", "display_name": "7. Network unavailable", "package": "pypdf", "version": "6.21.4",
     "condition": "network_off", "expected_status": "UNRESOLVED",
     "description": "PyPI cannot be reached: nothing can be established, so nothing is verified."},
]
CONDITIONS = {
    "tampered_wheel": "one bit of every downloaded wheel is flipped between PyPI and CAVR",
    "network_off": "every request to PyPI fails and OSV is not asked live",
}


class InterceptRequest(BaseModel):
    package: str = ""
    version: str = ""
    scenario_type: str = "custom"   # a key of CONDITIONS turns that condition on; any other value changes nothing
    request: str | None = None      # a whole pip command; when given it is used instead of package and version


class AlternativeApprovalRequest(BaseModel):
    run_id: str
    package: str
    alternative: str
    approved: bool
    user: str = "Security Operator (Admin)"
    reason: str = "Operator reviewed alternative dependency"


class TamperingTransport:
    """Demo condition "tampered_wheel": the real transport, with one bit flipped in every file from the files host."""

    def __init__(self, inner):
        self.inner = inner

    def stream(self, url):
        tamper = urlsplit(url).hostname == FILES_HOST
        for chunk in self.inner.stream(url):
            if tamper and chunk:
                chunk = chunk[:-1] + bytes([chunk[-1] ^ 0x01])
                tamper = False
            yield chunk


class OfflineTransport:
    """Demo condition "network_off": every request fails the way a lost connection does."""

    def stream(self, url):
        raise TransportError("ConnectError: the network is off (dashboard demo condition)")
        yield b""  # makes this a generator, like the real transport


def publish_event(run_id: str, step_index: int, phase: str, substep: str, event_type: str, status: str, payload: dict):
    """Append one event to the run: {run_id, seq, ts, step_index, phase, substep, type, status, payload}."""
    chain = RUN_CHAINS.get(run_id)
    seq = len(chain.records) + 1 if chain else 1
    ts = time.time()
    if chain:
        chain.add_record(phase=phase, event_type=event_type, data=payload, substep=substep)
    envelope = {"run_id": run_id, "seq": seq, "ts": ts, "step_index": step_index, "phase": phase, "substep": substep,
                "type": event_type, "status": status, "payload": payload,
                "data": payload, "timestamp": ts}  # the last two are the old names of payload and ts
    RUN_EVENTS.setdefault(run_id, []).append(envelope)

# ----------------- CAVR CORE API -----------------
@cavr_router.get("/api/cavr/scenarios")
def list_scenarios():
    return [{**scenario, "request": f"pip install {scenario['package']}=={scenario['version']}",
             "condition_description": CONDITIONS.get(scenario["condition"])} for scenario in SCENARIOS]

@cavr_router.get("/api/cavr/cache")
def get_cache():
    """What is in the 8-field verdict cache: one row per stored analysis, newest first.

    Every row is an analysis CAVR really did; `sha256` is the SHA-256 of the wheel it downloaded.
    Rows whose integrity digest does not match are left out, as the pipeline would ignore them.
    A row is not a promise for the next request: it is reused only when all eight key fields
    match again, and OSV is asked on every run. (The keys `source`, `status`, `capabilities`
    and `added_at` are the ones the dashboard's cache dialog reads.)
    """
    rows = []
    for row in storage.list_cached_verdicts():
        if cache_lookup(storage, {field: row[field] for field in KEY_FIELDS})["hit"]:
            rows.append({"name": row["name"], "version": row["version"], "sha256": row["artifact_sha256"],
                         "source": "CAVR verdict cache", "status": row["status"], "added_at": row["stored_at"],
                         "capabilities": f"analysis for contract {row['contract_digest'][:12]}, policy {row['policy_version'][:12]}",
                         "key_fields": {field: row[field] for field in KEY_FIELDS}})
    return rows

@cavr_router.get("/api/cavr/metrics")
def get_metrics():
    """The report numbers, from the verdict log: counts, cache hit rates, p50 / p95 of `fast_gate_ms` per status and per cache lookup."""
    report = pipeline_metrics(storage)
    report["recent"] = storage.get_verdict_log(limit=10)
    return report

@cavr_router.get("/api/cavr/evidence/{run_id}/verify")
def verify_run_evidence(run_id: str):
    chain = RUN_CHAINS.get(run_id)
    if not chain:
        raise HTTPException(404, f"No evidence ledger found for run_id '{run_id}'")
    return verify_chain(chain.records)

@cavr_router.get("/api/cavr/evidence/{run_id}/certificate.json")
def get_certificate_json(run_id: str):
    cert = RUN_CERTIFICATES.get(run_id)
    if not cert:
        raise HTTPException(404, f"No certificate found for run_id '{run_id}'")
    return cert

@cavr_router.get("/api/cavr/evidence/{run_id}/certificate.html", response_class=HTMLResponse)
def get_certificate_html(run_id: str):
    cert = RUN_CERTIFICATES.get(run_id)
    if not cert:
        raise HTTPException(404, f"No certificate found for run_id '{run_id}'")
    return generate_printable_html_certificate(cert)

@cavr_router.get("/api/cavr/evidence/{run_id}/records")
def get_evidence_records(run_id: str):
    chain = RUN_CHAINS.get(run_id)
    if not chain:
        raise HTTPException(404, f"No evidence ledger found for run_id '{run_id}'")
    return [{key: record[key] for key in ("seq", "phase", "substep", "type", "prev_hash", "sha256")} for record in chain.records]

@cavr_router.get("/api/cavr/proof/{run_id}")
def get_proof(run_id: str):
    if run_id in RUN_PROOFS:
        return RUN_PROOFS[run_id]
    raise HTTPException(404, "Proof not found for run")

@cavr_router.post("/api/cavr/approve-alternative")
def approve_alternative(body: AlternativeApprovalRequest):
    action = "APPROVE_ALTERNATIVE" if body.approved else "REJECT_ALTERNATIVE"
    storage.record_audit(body.run_id, body.package, action, body.user, f"{action} for {body.alternative}: {body.reason}")
    storage.update_quarantine_decision(body.run_id, "APPROVED_ALTERNATIVE" if body.approved else "REJECTED_ALTERNATIVE")
    
    publish_event(
        run_id=body.run_id,
        step_index=RUN_EVENTS[body.run_id][-1]["step_index"] if RUN_EVENTS.get(body.run_id) else 0,
        phase="P12",
        substep="CleanReconstructionApproved",
        event_type="alternative.decision",
        status="APPROVED" if body.approved else "REJECTED",
        payload={
            "run_id": body.run_id,
            "package": body.package,
            "alternative": body.alternative,
            "approved": body.approved,
            "user": body.user,
            "plain_explanation": f"Human operator {'approved' if body.approved else 'rejected'} alternative {body.alternative}. Recorded in the audit log; nothing was installed."
        }
    )
    return {"status": "SUCCESS", "action": action, "alternative": body.alternative, "approved": body.approved}

@cavr_router.get("/api/cavr/stream/{run_id}")
async def cavr_stream(run_id: str, request: Request):
    if run_id not in RUN_EVENTS:
        raise HTTPException(404, f"No run '{run_id}'")

    async def event_generator() -> AsyncGenerator[str, None]:
        sent, idle = 0, 0
        while True:
            events = RUN_EVENTS.get(run_id, [])
            if sent < len(events):
                yield f"data: {json.dumps(events[sent])}\n\n"
                sent, idle = sent + 1, 0
                continue
            if run_id in RUN_FINISHED or await request.is_disconnected():
                break
            idle += 1
            if idle % 10 == 0:
                yield ": heartbeat\n\n"
            await asyncio.sleep(0.1)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ----------------- RECORDED M2 RUNS (PR 19) -----------------
def _recorded():
    """(header, runs) of RECORDED_PATH, loaded once; ({}, {}) when the file is missing or not a recording."""
    global _RECORDED
    if _RECORDED is None:
        try:
            data = json.loads(RECORDED_PATH.read_text(encoding="utf-8"))
            runs = data.get("runs") if data.get("schema") == "cavr.recorded-runs.v1" else None
            _RECORDED = ({key: data.get(key) for key in RECORDED_KEYS}, runs if isinstance(runs, dict) else {})
        except (OSError, ValueError, AttributeError):
            _RECORDED = ({}, {})
    return _RECORDED


def recorded_runs() -> dict:
    """name -> recorded run. The fixed list; tests replace it."""
    return _recorded()[1]


def _recorded_run(name):
    """The recorded run called `name`, or None. A dictionary lookup only: no path is built from the name."""
    runs = recorded_runs()
    return runs.get(name) if isinstance(name, str) and name in runs else None


def recorded_label(name: str, run: dict) -> dict:
    return {"id": name, **_recorded()[0], "decision": run.get("decision"), "exit_code": run.get("exit_code"),
            "deep_line": run.get("deep_line")}


@cavr_router.get("/api/cavr/recorded-runs")
def list_recorded_runs():
    header, runs = _recorded()
    listed = [{"id": name, "display_name": f"Recorded: {name} ({(run.get('expected') or {}).get('status')})",
               "what": run.get("what"), "policy": run.get("policy"),
               "expected_status": (run.get("expected") or {}).get("status"), "decision": run.get("decision"),
               "exit_code": run.get("exit_code"), **header} for name, run in runs.items()]
    rank = lambda status: RECORDED_ORDER.index(status) if status in RECORDED_ORDER else len(RECORDED_ORDER)
    return sorted(listed, key=lambda item: (rank(item["expected_status"]), item["id"]))


@cavr_router.post("/api/cavr/recorded-runs/{name}")
async def replay_recorded_run(name: str):
    run = _recorded_run(name)
    if run is None:
        raise HTTPException(404, "No recorded run of that name")
    run_id = _new_run()
    label = recorded_label(name, run)
    asyncio.create_task(run_recorded(run_id, name))
    return {"run_id": run_id, "request": _recorded_request(run), "recorded": label, "status": "REPLAYING",
            "stream_url": f"/api/cavr/stream/{run_id}"}


def _recorded_request(run: dict) -> str:
    command = ((run.get("verdict") or {}).get("request") or {}).get("command")
    return request_text(command) if isinstance(command, list) and all(isinstance(part, str) for part in command) else "recorded gate run"


async def run_recorded(run_id: str, name: str) -> dict:
    """One replay: the recorded verdict, published like a live one, labelled `recorded`. Nothing is run."""
    run = _recorded_run(name)
    if run is None:
        raise HTTPException(404, "No recorded run of that name")
    label, verdict = recorded_label(name, run), copy.deepcopy(run["verdict"])
    shown = _recorded_request(run)
    publish_event(run_id, 0, "P1", "Capture", "state_change", "RUNNING", {
        "state": "INTERCEPTED", "step_index": 0, "request": shown, "demo_condition": None, "recorded": label,
        "message": f"Recorded run '{name}' (recorded {label.get('recorded_at')}): replayed, nothing is run now.",
        "plain_explanation": f"This is a recorded result of '{name}' from a real sandbox run; it is shown again, not re-run."})
    return publish_verdict(run_id, shown, verdict, None, copy.deepcopy(run.get("repair")), label)


# ----------------- THE VERIFICATION RUN -----------------
@cavr_router.post("/api/cavr/intercept")
async def intercept_package_endpoint(body: InterceptRequest):
    return await launch_cavr_pipeline(body)

@cavr_router.post("/api/cavr/run")
async def run_scenario_endpoint(scenario: str = "verified"):
    chosen = next((item for item in SCENARIOS if item["id"] == scenario), None)
    if chosen is None:
        raise HTTPException(404, f"No scenario '{scenario}'")
    return await launch_cavr_pipeline(InterceptRequest(package=chosen["package"], version=chosen["version"],
                                                       scenario_type=chosen["condition"] or chosen["id"]))

def _new_run() -> str:
    """A new run id with an empty event list and hash chain; the oldest runs are dropped after MAX_RUNS."""
    run_id = f"cavr-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
    for old in list(RUN_EVENTS)[:max(len(RUN_EVENTS) - MAX_RUNS + 1, 0)]:
        for runs in (RUN_EVENTS, RUN_PROOFS, RUN_CHAINS, RUN_CERTIFICATES):
            runs.pop(old, None)
        RUN_FINISHED.discard(old)
    RUN_EVENTS[run_id] = []
    RUN_CHAINS[run_id] = EvidenceChain(run_id)
    return run_id


async def launch_cavr_pipeline(body: InterceptRequest):
    run_id = _new_run()
    request = pip_request(body)
    asyncio.create_task(run_verification(run_id, body))
    return {"run_id": run_id, "request": request_text(request), "demo_condition": demo_condition(body),
            "status": "INTERCEPTED", "stream_url": f"/api/cavr/stream/{run_id}"}


def pip_request(body: InterceptRequest):
    """The pip command to verify: the given command, or `pip install <package>==<version>` as one requirement token.

    The package and version are joined into a single token, so text after a space in either
    cannot become a second argument or an option.
    """
    if body.request is not None:
        return body.request
    package, version = body.package.strip(), body.version.strip()
    return ["pip", "install", f"{package}=={version}" if version else package]


def request_text(request) -> str:
    return redact(request if isinstance(request, str) else " ".join(request))


def demo_condition(body: InterceptRequest):
    """{"id", "description"} of the condition this request turns on, or None."""
    if body.scenario_type in CONDITIONS:
        return {"id": body.scenario_type, "description": CONDITIONS[body.scenario_type]}
    return None


def demo_quarantine_dir(condition: str) -> Path:
    """Where a run under a demo condition keeps what it downloads: a directory of its own, beside the real quarantine.

    A hash mismatch removes an older file of the same name from the directory it downloaded
    into (`pypi_client.fetch_artifact`: that file is not what the registry serves now). In a
    shared directory that file was the genuine wheel of a real run, so a tampered demo run
    deleted it. With its own directory a demo run cannot read, replace or delete a real file.
    """
    if condition not in CONDITIONS:
        raise ValueError(f"not a demo condition: {condition!r}")
    real = Path(QUARANTINE_DIR) if QUARANTINE_DIR is not None else default_quarantine_dir()
    return real.with_name(real.name + "-demo") / condition


def _conditions(condition):
    """(transport, live advisories) of a run under `condition`; the demo conditions only make things worse."""
    if condition == "tampered_wheel":
        return TamperingTransport(TRANSPORT or HttpxTransport()), LIVE_ADVISORIES
    if condition == "network_off":
        return OfflineTransport(), False
    return TRANSPORT, LIVE_ADVISORIES


def dashboard_repair(verdict, condition):
    """The repair block of the run's first package when it is REJECTED, else None. Blocking (network); never raises."""
    package = next(iter(verdict.get("packages") or []), None)
    if not package or package.get("status") != "REJECTED":
        return None
    try:
        transport, live = _conditions(condition)
        return propose_repair(verdict, package, project_dir=PROJECT_DIR,
                              policy=requirement_gate.load_json_file(requirement_gate.POLICY_PATH), requirements_file=None,
                              transport=transport, advisory_cache_dir=ADVISORY_CACHE_DIR or Path(DATA) / "cavr" / "advisories",
                              live_advisories=live)
    except Exception as exc:
        return no_repair(package.get("package"), package.get("version"), package, "INTERNAL_ERROR",
                         f"repair failed: {type(exc).__name__}: {exc}")


def verify_dashboard_request(request, condition) -> dict:
    """Run the pipeline for the dashboard project. Blocking: it uses the network.

    Under a demo condition the pipeline gets no store. The outcome of such a run was arranged
    by the demo, so it must not count in the cache hit rate or the latency percentiles. It
    also gets its own quarantine directory (`demo_quarantine_dir`), so the tampered wheel is
    the demo's own download and the genuine wheel of a real run is never deleted or altered.
    """
    transport, live, store, quarantine = TRANSPORT, LIVE_ADVISORIES, storage, QUARANTINE_DIR
    try:
        if condition == "tampered_wheel":
            transport, store = TamperingTransport(TRANSPORT or HttpxTransport()), None
            quarantine = demo_quarantine_dir(condition)
        elif condition == "network_off":
            transport, live, store = OfflineTransport(), False, None
            quarantine = demo_quarantine_dir(condition)
        return verify_request(request, PROJECT_DIR, requirement_gate.load_json_file(requirement_gate.POLICY_PATH), store,
                              transport=transport, quarantine_dir=quarantine, advisory_cache_dir=ADVISORY_CACHE_DIR,
                              live_advisories=live)
    except Exception as exc:  # the pipeline returns verdicts and should not raise; if it does, that is "unknown"
        return {"status": "UNRESOLVED", "stage": "internal", "rule": "INTERNAL_ERROR",
                "reason": f"the pipeline failed: {type(exc).__name__}: {exc}", "fast_gate_ms": None, "cache_hit": False,
                "escalated": False, "escalation": None, "request": None, "gate": None, "lockfile": None, "project": None,
                "packages": [], "policy_version": None, "analyzer_version": None, "logged": False}


async def run_verification(run_id: str, body: InterceptRequest) -> dict:
    """One dashboard run: publish the request, run the pipeline, publish what it found. Returns the verdict."""
    request, condition = pip_request(body), demo_condition(body)
    shown = request_text(request)
    publish_event(run_id, 0, "P1", "Capture", "state_change", "RUNNING", {
        "state": "INTERCEPTED", "step_index": 0, "request": shown, "demo_condition": condition,
        "message": f"Request received: '{shown}'. Verification started; nothing is installed.",
        "plain_explanation": f"ASENT received the request '{shown}' and is checking it before anything is installed."})
    verdict = await asyncio.to_thread(verify_dashboard_request, request, condition["id"] if condition else None)
    repair = await asyncio.to_thread(dashboard_repair, verdict, condition["id"] if condition else None)
    return publish_verdict(run_id, shown, verdict, condition, repair)


def publish_verdict(run_id: str, shown: str, verdict: dict, condition, repair, recorded=None) -> dict:
    """Publish the events of one verdict, its certificate, its proof and the final event. Returns the verdict.

    `recorded` (a replay of a recorded run) is written into every event, the proof and the certificate.
    """
    views = package_views(verdict)
    for step_index, phase, substep, event_type, status, payload in verdict_events(verdict, condition, repair, views):
        publish_event(run_id, step_index, phase, substep, event_type, status, _labelled(payload, recorded))

    last_step = RUN_EVENTS[run_id][-1]["step_index"]
    chain = RUN_CHAINS[run_id]
    certificate = certificate_for_verdict(run_id, verdict, chain.last_hash, condition)
    if recorded is not None:
        certificate["recorded"] = recorded
    RUN_CERTIFICATES[run_id] = certificate
    artifact = _first_artifact(verdict)
    deep = next((view["deep"] for view in views if view["deep"]), None)
    RUN_PROOFS[run_id] = {
        "run_id": run_id, "request": shown, "demo_condition": condition, "recorded": recorded,
        "package": certificate["subject"]["package"], "version": certificate["subject"]["version"],
        "verdict": ALIASES.get(verdict["status"], "NEEDS_REVIEW"), "policy_state": verdict["status"],
        "cavr_verdict": verdict, "stages": stage_summary(verdict), "packages": views,
        "causal_graphs": causal_graphs(verdict),
        "hash_comparison": {"declared_or_expected": artifact.get("registry_sha256"), "actual_sha256": artifact.get("sha256"),
                            "rule": artifact.get("rule"), "matches": HASH_MATCHES.get(artifact.get("rule"))},
        # The sandbox fields: the first deep package's runs, or "not available" (never empty, never invented).
        "docker_command": NOT_IN_EVIDENCE if deep else NOT_RUN,
        "container_id": ", ".join(str(r.get("container")) for r in deep["runs"]) if deep and deep["runs"] else NOT_RUN,
        "image_digest": (deep.get("image_id") or NOT_RUN) if deep else NOT_RUN,
        "counterfactual_runs": deep["runs"] if deep else [],
        "evidence_chain_root": chain.last_hash, "evidence_records_count": len(chain.records),
        "certificate_id": certificate["certificate_id"], "repair": repair,
    }
    finished = "Replayed" if recorded is not None else "Finished"
    publish_event(run_id, last_step, "P13", "AssuranceFinalized", "state_change", "FINALIZED", _labelled({
        "state": "DECIDED", "step_index": last_step, "verdict": ALIASES.get(verdict["status"], "NEEDS_REVIEW"),
        "policy_state": verdict["status"], "certificate": certificate, "reconstruction": None, "demo_condition": condition,
        "evidence_chain_summary": {"total_blocks": len(chain.records), "terminal_hash": chain.last_hash},
        "message": f"{finished}: {verdict['status']}. Nothing was installed.",
        "plain_explanation": f"The check is finished: {verdict['status']}. Nothing was installed."}, recorded))
    RUN_FINISHED.add(run_id)
    return verdict


def _labelled(payload: dict, recorded) -> dict:
    return payload if recorded is None else {**payload, "recorded": recorded}


def verdict_events(verdict: dict, condition=None, repair=None, views=None) -> list[tuple]:
    """The events of one verdict, in pipeline order: (step_index, phase, substep, type, status, payload).

    A stage that did not run has no event, so the last step index is the last stage that ran:
    1 gate, 2 artifact / tree / advisories, 3 cache lookup, 4 contract / scan / sinks, 5 deep analysis (only for a
    package with deep evidence; `views` are its `package_views`).
    """
    events = []
    gate = verdict.get("gate") or {}
    capture = verdict.get("request") or {}
    rule = gate.get("rule") or verdict["rule"]
    result = gate.get("result") or "UNRESOLVED"
    reason = gate.get("reason") or verdict["reason"]
    events.append((1, "P2", "RequirementGate", "requirement_gate_evaluated",
                   {"PERMITTED": "PASSED", "BLOCK": "BLOCKED"}.get(result, "UNRESOLVED"), {
        "state": "REQUIREMENT_CHECK", "step_index": 1, "result": result, "rule": rule, "matched_rule": rule,
        "rule_checked": requirement_gate.RULE_TITLES.get(rule, rule), "reason": reason,
        "policy_version": verdict.get("policy_version"), "decisions": gate.get("decisions") or [],
        "policy_file_excerpt": json.dumps([decision.get("evidence") for decision in gate.get("decisions") or []], sort_keys=True),
        "capture": {key: capture.get(key) for key in ("source", "complete", "requirements", "unsupported", "errors", "files")},
        "lockfile": verdict.get("lockfile"), "demo_condition": condition,
        "message": f"Requirement gate: {result} ({rule}). {reason}",
        "plain_explanation": f"Checked the request against the project policy: {result}."}))

    packages = verdict.get("packages") or []
    last = 1
    if packages:
        package = packages[0]  # the dashboard shows one package; the proof holds all of them
        evidence = package.get("evidence") or {}
        artifact, tree = evidence.get("artifact") or {}, evidence.get("tree") or {}
        advisories = evidence.get("advisories") or []
        affected = [match for advisory in advisories for match in advisory.get("affected") or []]
        affected_ids = [str(match.get("id")) for match in affected]
        affected_count = _affected_count(advisories)
        if tree or artifact:
            last = 2
            events.append((2, "P5", "PackageResolution", "package_resolved", str(artifact.get("rule") or tree.get("rule")), {
                "state": "QUARANTINED", "step_index": 2, "demo_condition": condition,
                "resolution": {
                    "package": package.get("package"), "version": package.get("version"),
                    "sha256": artifact.get("sha256"), "registry_sha256": artifact.get("registry_sha256"),
                    "hash_rule": artifact.get("rule"), "hash_reason": artifact.get("reason"), "filename": artifact.get("filename"),
                    "tree": {"rule": tree.get("rule"), "reason": tree.get("reason"), "subtree_digest": tree.get("subtree_digest"),
                             "nodes": [{key: node.get(key) for key in ("name", "version", "sha256", "filename")}
                                       for node in tree.get("nodes") or []],
                             "edges": tree.get("edges") or [], "problems": tree.get("problems") or []},
                    "advisories": [{key: advisory.get(key) for key in ("name", "version", "result", "rule", "reason", "mode",
                                                                       "retrieved_at", "advisory_count")}
                                   for advisory in advisories],
                    "vulnerability_count": affected_count,  # None when OSV gave no answer for a package
                    # For one line on the page: the count and the first ids. `known_risk_signals` below is the whole list.
                    "first_advisory_ids": affected_ids[:FIRST_IDS],
                    "advisory_summary": (f"{len(affected)} advisories affect {package.get('package')} {package.get('version')}: "
                                         f"{summarise_ids(affected_ids)}") if affected else None,
                    "known_risk_signals": [{"cve": match.get("id"), "aliases": match.get("aliases"),
                                            "summary": match.get("summary"), "fixed_versions": match.get("fixed_versions")}
                                           for match in affected]},
                "message": f"Artifact: {artifact.get('rule')}. Tree: {tree.get('rule')}. " + (
                    "OSV gave no answer." if affected_count is None else f"{affected_count} OSV advisories affect it."),
                "plain_explanation": "Downloaded the real file, compared its SHA-256 with the registry, read its dependencies "
                                     "and asked the OSV vulnerability database."}))
        cache = package.get("cache") or {}
        if cache.get("lookup"):
            last = 3
            events.append((3, "P4", "CacheLookup", "cache_result", cache["lookup"], {
                "result": cache["lookup"], "package": package.get("package"), "sha256": artifact.get("sha256"),
                "key": cache.get("key"), "key_fields": package.get("key_fields"), "stored": cache.get("stored"),
                "reason": cache.get("reason"), "cache_hit": package.get("cache_hit"), "demo_condition": condition,
                "message": f"Verdict cache: {cache['lookup']} on the 8-field key. {cache.get('reason') or ''}",
                "plain_explanation": "Looked for an earlier analysis of exactly this file, tree, project and policy."}))
        contract = evidence.get("contract")
        if contract:
            last = 4
            reachability = evidence.get("reachability")
            scans = [{key: scan.get(key) for key in ("package", "version", "result", "rule", "reason", "python_files", "sinks",
                                                     "triggers", "dynamic_code", "parse_errors", "native_files",
                                                     "not_scanned_files")} for scan in evidence.get("scan") or []]
            sinks = (reachability or {}).get("sinks") or []
            events.append((4, "P3_P4_P6", "StaticActionInspection", "action_completed", str(contract.get("rule")), {
                "state": "INSPECTING", "step_index": 4, "project_context": verdict.get("project"),
                "capability_contract": contract, "scan": scans, "reachability": reachability,
                "analysis_from_cache": evidence.get("analysis_from_cache"), "demo_condition": condition,
                "message": f"Contract: {contract.get('rule')} ({len(contract.get('call_sites') or [])} call sites). "
                           f"Scan: {len(scans)} wheels, {len(sinks)} sink calls judged.",
                "plain_explanation": "Read how the project uses the package, scanned the package's code without running it, "
                                     "and judged each sensitive call against what the project allows."}))

    deep_views = [view for view in (package_views(verdict) if views is None else views) if view["deep"]]
    if deep_views:
        last = 5
        first = deep_views[0]["deep"]
        events.append((5, "P7_P9", "DeepAnalysis", "deep_completed", str(first["status"]), {
            "state": "DEEP_ANALYSIS", "step_index": 5, "packages": deep_views, "demo_condition": condition,
            "message": f"Deep analysis: {first['status']} {first['rule']} ({len(first['runs'])} sandbox run(s)). "
                       f"{first['reason']}",
            "plain_explanation": "The package was run in the CAVR sandbox: once with only fake canary secrets, then once "
                                 "per hidden trigger CAVR could set up, and each event was checked against the contract."}))

    status = verdict["status"]
    events.append((last, "VERDICT", "Verdict", "verdict_computed", ALIASES.get(status, "NEEDS_REVIEW"), {
        "verdict": ALIASES.get(status, "NEEDS_REVIEW"), "policy_state": status, "status": status, "stage": verdict["stage"],
        "rule": verdict["rule"], "reason": verdict["reason"], "honesty_wording": honesty_wording(verdict),
        "evidence_lines": [f"{verdict['stage']} / {verdict['rule']}: {verdict['reason']}"],
        "fast_gate_ms": verdict.get("fast_gate_ms"), "cache_hit": verdict.get("cache_hit"),
        "escalated": verdict.get("escalated"), "escalation": verdict.get("escalation"), "demo_condition": condition,
        "causal_graph": None, "violating_paths": [], "reverification": None,  # not run on this path
        "repair": repair,  # a proposal for a REJECTED package (dashboard_repair), else None
        "message": f"Verdict: {status} ({verdict['stage']} / {verdict['rule']}). {verdict['reason']}",
        "plain_explanation": honesty_wording(verdict)}))
    return events


def stage_summary(verdict: dict) -> list[dict]:
    """The timeline of one run: for each stage, whether it ran and the values it computed.

    Returns [{"id", "title", "ran", "values": [{"label", "value"}, ...]}, ...] in pipeline order.
    Every value is copied from the verdict, or is the length of one of its lists. A value that
    was not computed is None, and a stage none of whose values was computed has `ran: False`.
    There is no time per stage: the pipeline measures one time, `fast_gate_ms`, for the request.
    """
    capture, gate = _dict(verdict.get("request")), _dict(verdict.get("gate"))
    packages = _list(verdict.get("packages"))
    package = _dict(packages[0]) if packages else {}  # the page shows one package; the proof holds all of them
    evidence, cache = _dict(package.get("evidence")), _dict(package.get("cache"))
    artifact, tree, contract = (_dict(evidence.get(key)) for key in ("artifact", "tree", "contract"))
    reachability = _dict(evidence.get("reachability"))
    advisories = [item for item in _list(evidence.get("advisories")) if isinstance(item, dict)]
    scans = [item for item in _list(evidence.get("scan")) if isinstance(item, dict)]
    looked_up = cache.get("lookup") is not None
    decided = verdict.get("stage") is not None and verdict.get("rule") is not None
    values = {
        "capture": [("source", capture.get("source")), ("requirements captured", _count(capture, "requirements")),
                    ("complete", capture.get("complete"))],
        "gate": [("result", gate.get("result")), ("rule", gate.get("rule")),
                 ("policy version", verdict.get("policy_version") if gate else None)],
        "artifact": [("hash check", artifact.get("rule")), ("file", artifact.get("filename")),
                     ("sha256 of the download", artifact.get("sha256")), ("registry sha256", artifact.get("registry_sha256")),
                     ("dependency tree", tree.get("rule")), ("files in the tree", _count(tree, "nodes")),
                     ("advisories", ", ".join(sorted({str(advisory.get("rule")) for advisory in advisories})) or None),
                     ("advisories that affect it", _affected_count(advisories))],
        "cache": [("lookup", cache.get("lookup")), ("stored", cache.get("stored") if looked_up else None),
                  ("key", cache.get("key"))],
        "analysis": [("contract", contract.get("rule")), ("call sites", _count(contract, "call_sites")),
                     ("AST scan", ", ".join(sorted({str(scan.get("rule")) for scan in scans})) or None),
                     ("Python files scanned",
                      sum(scan["python_files"] for scan in scans if isinstance(scan.get("python_files"), int)) if scans else None),
                     ("sink judgement", reachability.get("rule")), ("sink calls judged", _count(reachability, "sinks")),
                     # False by default in the evidence, so it is a computed value only when a scan result exists.
                     ("analysis from the cache", evidence.get("analysis_from_cache") if scans else None)],
        "verdict": [("status", verdict.get("status")),
                    ("decided at", f"{verdict['stage']} / {verdict['rule']}" if decided else None),
                    ("fast_gate_ms", verdict.get("fast_gate_ms")), ("cache_hit", verdict.get("cache_hit")),
                    ("escalated", verdict.get("escalated")), ("escalation", verdict.get("escalation"))],
    }
    return [{"id": stage, "title": title, "ran": any(value is not None for _, value in values[stage]),
             "values": [{"label": label, "value": value} for label, value in values[stage]]}
            for stage, title in STAGE_TITLES.items()]


def _dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def _list(value) -> list:
    return value if isinstance(value, list) else []


def _count(mapping: dict, key: str):
    """How many items the list `mapping[key]` has, or None when there is no such list."""
    return len(mapping[key]) if isinstance(mapping.get(key), list) else None


def _affected_count(advisories: list):
    """How many advisories affect the checked packages, or None when that is not known.

    It is known only when OSV answered for every package (`advisory_count` is set). A record
    such as ADVISORIES_UNAVAILABLE has an empty `affected` list because nothing was asked,
    not because nothing was found, so it must not be counted as 0.
    """
    if not advisories or any(advisory.get("advisory_count") is None for advisory in advisories):
        return None
    return sum(len(_list(advisory.get("affected"))) for advisory in advisories)


def honesty_wording(verdict: dict) -> str:
    """One sentence that says what the verdict does and does not claim."""
    rule = verdict.get("rule")
    return {
        "VERIFIED": "Every fast-gate check passed for this file and this project. No package code was run; "
                    "this is not a claim that the package is safe.",
        "REJECTED": f"A check failed ({rule}). The request must not be installed.",
        "BLOCK": f"The project policy does not permit this request ({rule}). Nothing was downloaded.",
    }.get(verdict.get("status"), f"Something could not be established ({rule}). Unknown is not treated as a pass.")


def _first_artifact(verdict: dict) -> dict:
    packages = verdict.get("packages") or []
    return ((packages[0].get("evidence") or {}).get("artifact") or {}) if packages else {}
