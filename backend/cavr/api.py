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
4. `GET /api/cavr/proof/{run_id}` returns the whole verdict.

Every event is also appended to the run's hash chain (`assurance.EvidenceChain`).

The project the dashboard verifies for is `PROJECT_DIR` (the sample invoice project) with the
policy file `requirement_gate.POLICY_PATH`.

Demo conditions. A scenario may name a condition that changes the network between CAVR and
PyPI: "tampered_wheel" flips one bit of every downloaded wheel, "network_off" fails every
request. The pipeline then runs unchanged and gives the verdict it would give in that
situation. A condition can only make a verdict worse, never better, and it is written into
every event and into the proof (`demo_condition`).

Not run on this path: the sandbox, the counterfactual engine, the causal graph, repair,
re-verification and reconstruction (M2). Their fields in the events are null.
"""
from __future__ import annotations
import asyncio
import json
import time
import uuid
from pathlib import Path
from typing import AsyncGenerator
from urllib.parse import urlsplit
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from pydantic import BaseModel

from backend.cavr import requirement_gate
from backend.cavr.assurance import EvidenceChain, certificate_for_verdict, generate_printable_html_certificate, verify_chain
from backend.cavr.capture import redact
from backend.cavr.context_extractor import SAMPLE_PROJECT_DIR
from backend.cavr.pipeline import metrics as pipeline_metrics, verify_request
from backend.cavr.pypi_client import FILES_HOST, HttpxTransport, TransportError
from backend.cavr.storage import CavrStorage

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
NOT_RUN = "not run: the fast gate does not execute package code (deep analysis is M2)"

# The dashboard's scenario chips. Each is a real request; `expected_status` says what the chip
# is meant to show and is never used to compute anything.
SCENARIOS = [
    {"id": "verified", "display_name": "1. pypdf 6.19.0", "package": "pypdf", "version": "6.19.0", "condition": None,
     "expected_status": "VERIFIED",
     "description": "The real wheel from PyPI: hash, dependency tree, OSV, contract and sink reachability all pass."},
    {"id": "known_vulnerable", "display_name": "2. pypdf 5.1.0 (OSV)", "package": "pypdf", "version": "5.1.0", "condition": None,
     "expected_status": "REJECTED",
     "description": "Permitted by the policy, but OSV lists advisories that affect this version."},
    {"id": "denylisted", "display_name": "3. Denylisted name", "package": "requests-security", "version": "2.31.0",
     "condition": None, "expected_status": "BLOCK",
     "description": "On the project denylist: blocked by the requirement gate before anything is downloaded."},
    {"id": "tampered_wheel", "display_name": "4. Tampered wheel", "package": "pypdf", "version": "6.19.0",
     "condition": "tampered_wheel", "expected_status": "REJECTED",
     "description": "One bit of the downloaded wheel is flipped on the way: its SHA-256 no longer matches the registry."},
    {"id": "network_off", "display_name": "5. Network off", "package": "pypdf", "version": "6.19.0", "condition": "network_off",
     "expected_status": "UNRESOLVED",
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

# ----------------- PEP 503 PACKAGE INDEX -----------------
@cavr_router.get("/simple/", response_class=HTMLResponse)
def pep503_root():
    pkgs = storage.get_trusted_packages()
    links = "".join([f'<a href="/simple/{p["name"]}/">{p["name"]}</a>\n' for p in pkgs])
    return f"""<!DOCTYPE html>
<html>
<head><title>ASENT Local PEP 503 Package Index</title></head>
<body>
<h1>ASENT Secure Package Index</h1>
{links}
</body>
</html>"""

@cavr_router.get("/simple/{package}/", response_class=HTMLResponse)
def pep503_package_index(package: str):
    trusted = storage.get_trusted_package(package)
    if not trusted:
        return HTMLResponse(
            f"""<!DOCTYPE html><html><body><h1>Links for {package}</h1><p>No verified distributions available</p></body></html>""",
            status_code=404
        )
    filename = f"{trusted['name']}-{trusted['version']}-py3-none-any.whl"
    sha = trusted["sha256"]
    return f"""<!DOCTYPE html>
<html>
<head><title>Links for {package}</title></head>
<body>
<h1>Links for {package}</h1>
<a href="/simple/{package}/{filename}#sha256={sha}">{filename}</a>
</body>
</html>"""

@cavr_router.get("/simple/{package}/{filename}")
def pep503_download(package: str, filename: str):
    trusted = storage.get_trusted_package(package)
    if trusted:
        return JSONResponse({"status": "RELEASED", "package": package, "filename": filename, "sha256": trusted["sha256"]})
    
    raise HTTPException(
        status_code=403,
        detail={
            "error": "BLOCKED_BY_AGENT_SENTINEL",
            "package": package,
            "filename": filename,
            "reason": "Hostile/unverified package blocked by ASENT assurance gate. Unauthorized installation rejected."
        }
    )

# ----------------- CAVR CORE API -----------------
@cavr_router.get("/api/cavr/scenarios")
def list_scenarios():
    return [{**scenario, "request": f"pip install {scenario['package']}=={scenario['version']}",
             "condition_description": CONDITIONS.get(scenario["condition"])} for scenario in SCENARIOS]

@cavr_router.get("/api/cavr/cache")
def get_cache():
    return storage.get_trusted_packages()

@cavr_router.post("/api/cavr/cache")
def add_cache(name: str, version: str, sha256: str, source: str = "PyPI Verified", capabilities: str = ""):
    return storage.add_trusted_package(name, version, sha256, source, capabilities)

@cavr_router.get("/api/cavr/dialog/cache")
def dialog_cache():
    pkgs = storage.get_trusted_packages()
    return {
        "title": "Trusted Package Cache",
        "description": "Cryptographically pinned and verified Python packages safe for AI coding agents.",
        "packages": pkgs,
        "total_packages": len(pkgs),
        "explanation": "A Cache HIT occurs when both the package name and exact SHA-256 match a pre-verified entry, skipping hostile execution. A Hash Mismatch signals that the artifact bytes were modified, triggering immediate quarantine."
    }

@cavr_router.get("/api/cavr/dialog/action")
def dialog_action():
    return {
        "title": "Action: Static AST Inspection & Anomaly Detection",
        "subtitle": "Deep lexical, syntax tree, and metadata validation before sandbox dispatch",
        "inspection_steps": [
            {"step": "eval() / exec() Sinks", "detail": "Flags dynamic code compilation and runtime string evaluation.", "severity": "CRITICAL"},
            {"step": "Subprocess & Shell Calls", "detail": "Flags os.system, subprocess.Popen, and shell=True invocations.", "severity": "HIGH"},
            {"step": "Raw Socket Creation", "detail": "Flags socket.socket and raw outbound egress hooks.", "severity": "CRITICAL"},
            {"step": "Base64 & Hex Obfuscation", "detail": "Detects staged payloads decoded right before execution.", "severity": "HIGH"},
            {"step": "Setup.py Install Hooks", "detail": "Flags cmdclass install-time script execution.", "severity": "CRITICAL"},
            {"step": "Typosquatting & Homoglyphs", "detail": "Computes Levenshtein distance against trusted packages.", "severity": "CRITICAL"},
            {"step": "Metadata Sanity Checks", "detail": "Detects abnormal version leaps (>90) and empty descriptions.", "severity": "MEDIUM"}
        ],
        "priority_formula": {
            "formula": "priority = (sink_risk × reachability_confidence × novelty) / estimated_run_cost",
            "worked_example": "Trigger 'os.getenv(AWS_SECRET_ACCESS_KEY)' reaches socket.connect sink: (9.5 × 0.95 × 1.0) / 1.2 = 7.52 Priority Score"
        },
        "policy_states": [
            {"state": "VERIFIED", "alias": "ALLOW", "description": "No malicious behavior observed under our tests. Contract satisfied."},
            {"state": "RESTRICTED", "alias": "ALLOW with restrictions", "description": "Permitted with strictly narrowed sandbox capabilities and blocked syscalls."},
            {"state": "UNRESOLVED", "alias": "NEEDS_REVIEW", "description": "Fails closed. Ambiguous predicates or budget limit reached."},
            {"state": "REJECTED", "alias": "BLOCK", "description": "Decisive capability violation, credential read, or malicious egress detected."}
        ]
    }

@cavr_router.get("/api/cavr/dialog/environment")
def dialog_environment():
    return {
        "title": "Environment: Multi-Layer Hostile Code Sandbox",
        "subtitle": "Disposable containerized isolation preventing escape and monitoring syscalls",
        "dockerfile_summary": {
            "base_image": "python:3.12-slim",
            "user": "sandbox (UID: 10001, unprivileged non-root)",
            "observation_layer": "sys.addaudithook + optional strace syscall tracer",
            "harness": "/opt/asent/harness.py"
        },
        "lockdown_flags": [
            {"flag": "--network none", "name": "Network Isolation", "desc": "All socket creation and external egress is disabled."},
            {"flag": "--read-only", "name": "Read-Only Root Filesystem", "desc": "Container rootfs cannot be written to or modified."},
            {"flag": "--tmpfs /scratch:rw,noexec,nosuid,size=64m", "name": "Ephemeral Scratchpad", "desc": "Disposable memory-backed storage with execution disabled."},
            {"flag": "--user 10001:10001", "name": "Non-Root Context", "desc": "Prevents UID 0 privilege escalation attacks."},
            {"flag": "--cap-drop ALL", "name": "Drop All Linux Capabilities", "desc": "Removes NET_RAW, SYS_ADMIN, and raw system control capabilities."},
            {"flag": "--security-opt no-new-privileges", "name": "No Privilege Gain", "desc": "Disallows setuid / setgid binary privilege elevation."},
            {"flag": "--security-opt seccomp=asent-seccomp.json", "name": "Seccomp Filter", "desc": "Restricts allowable kernel syscalls to minimal safe set."},
            {"flag": "--memory 256m --cpus 0.5 --pids-limit 64", "name": "Resource Quotas", "desc": "Hard limits preventing denial-of-service, fork bombs, and CPU hogging."},
            {"flag": "timeout 30s", "name": "Hard Watchdog Timeout", "desc": "Process is forcibly killed if execution exceeds 30 seconds."}
        ],
        "counterfactual_conditions_synthesized": [
            "Fake Environment Variables (e.g. AWS_SECRET_ACCESS_KEY, CI, PROD_FLAG)",
            "Fake Credential Files (e.g. ~/.aws/credentials, ~/.ssh/id_rsa)",
            "Spoofed Hostname and User (socket.gethostname, getpass.getuser)",
            "Harness-level Time Shim & Warp (simulating delayed triggers)"
        ],
        "observation_method": "Python 3.12 Runtime Audit Hooks (sys.addaudithook) + seccomp filters",
        "tests_run": [
            "Artifact SHA-256 hash re-verification",
            "Planting fake honeytoken credentials (~/.aws/credentials, AWS_SECRET_ACCESS_KEY)",
            "Zero-index throwaway installation",
            "Import execution test and declared contract callable verification",
            "Adaptive multi-run counterfactual frontier exploration"
        ],
        "limitations": "Bounded by declared container isolation. eBPF kernel tracing is not accessible in rootless container environments. Conditions not triggered stay unresolved. Never claims universal absence of malware."
    }

@cavr_router.get("/api/cavr/metrics")
def get_metrics():
    """The report numbers, from the verdict log: counts by status, cache hit rate, p50 / p95 of `fast_gate_ms`."""
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

async def launch_cavr_pipeline(body: InterceptRequest):
    run_id = f"cavr-{int(time.time() * 1000)}-{uuid.uuid4().hex[:6]}"
    for old in list(RUN_EVENTS)[:max(len(RUN_EVENTS) - MAX_RUNS + 1, 0)]:
        for runs in (RUN_EVENTS, RUN_PROOFS, RUN_CHAINS, RUN_CERTIFICATES):
            runs.pop(old, None)
        RUN_FINISHED.discard(old)
    RUN_EVENTS[run_id] = []
    RUN_CHAINS[run_id] = EvidenceChain(run_id)
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


def verify_dashboard_request(request, condition) -> dict:
    """Run the pipeline for the dashboard project. Blocking: it uses the network."""
    transport, live = TRANSPORT, LIVE_ADVISORIES
    if condition == "tampered_wheel":
        transport = TamperingTransport(TRANSPORT or HttpxTransport())
    elif condition == "network_off":
        transport, live = OfflineTransport(), False
    try:
        return verify_request(request, PROJECT_DIR, requirement_gate.load_json_file(requirement_gate.POLICY_PATH), storage,
                              transport=transport, quarantine_dir=QUARANTINE_DIR, advisory_cache_dir=ADVISORY_CACHE_DIR,
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
    for step_index, phase, substep, event_type, status, payload in verdict_events(verdict, condition):
        publish_event(run_id, step_index, phase, substep, event_type, status, payload)

    last_step = RUN_EVENTS[run_id][-1]["step_index"]
    chain = RUN_CHAINS[run_id]
    certificate = RUN_CERTIFICATES[run_id] = certificate_for_verdict(run_id, verdict, chain.last_hash, condition)
    artifact = _first_artifact(verdict)
    RUN_PROOFS[run_id] = {
        "run_id": run_id, "request": shown, "demo_condition": condition,
        "package": certificate["subject"]["package"], "version": certificate["subject"]["version"],
        "verdict": ALIASES.get(verdict["status"], "NEEDS_REVIEW"), "policy_state": verdict["status"],
        "cavr_verdict": verdict,
        "hash_comparison": {"declared_or_expected": artifact.get("registry_sha256"), "actual_sha256": artifact.get("sha256"),
                            "matches": artifact.get("rule") == "HASH_MATCH" if artifact else None},
        "docker_command": NOT_RUN, "container_id": NOT_RUN, "image_digest": NOT_RUN, "counterfactual_runs": [],
        "evidence_chain_root": chain.last_hash, "evidence_records_count": len(chain.records),
        "certificate_id": certificate["certificate_id"],
    }
    publish_event(run_id, last_step, "P13", "AssuranceFinalized", "state_change", "FINALIZED", {
        "state": "DECIDED", "step_index": last_step, "verdict": ALIASES.get(verdict["status"], "NEEDS_REVIEW"),
        "policy_state": verdict["status"], "certificate": certificate, "reconstruction": None, "demo_condition": condition,
        "evidence_chain_summary": {"total_blocks": len(chain.records), "terminal_hash": chain.last_hash},
        "message": f"Finished: {verdict['status']}. Nothing was installed.",
        "plain_explanation": f"The check is finished: {verdict['status']}. Nothing was installed."})
    RUN_FINISHED.add(run_id)
    return verdict


def verdict_events(verdict: dict, condition=None) -> list[tuple]:
    """The events of one verdict, in pipeline order: (step_index, phase, substep, type, status, payload).

    A stage that did not run has no event, so the last step index is the last stage that ran:
    1 gate, 2 artifact / tree / advisories, 3 cache lookup, 4 contract / scan / sinks.
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
                    "vulnerability_count": len(affected),
                    "known_risk_signals": [{"cve": match.get("id"), "aliases": match.get("aliases"),
                                            "summary": match.get("summary"), "fixed_versions": match.get("fixed_versions")}
                                           for match in affected]},
                "message": f"Artifact: {artifact.get('rule')}. Tree: {tree.get('rule')}. {len(affected)} OSV advisories affect it.",
                "plain_explanation": "Downloaded the real file, compared its SHA-256 with the registry, read its dependencies "
                                     "and asked the OSV vulnerability database."}))
        cache = package.get("cache") or {}
        if cache.get("lookup"):
            last = 3
            events.append((3, "P4", "CacheLookup", "cache_result", cache["lookup"], {
                "result": cache["lookup"], "package": package.get("package"), "sha256": artifact.get("sha256"),
                "key": cache.get("key"), "key_fields": package.get("key_fields"), "stored": cache.get("stored"),
                "reason": cache.get("reason"), "cache_hit": package.get("cache_hit"),
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
                "analysis_from_cache": evidence.get("analysis_from_cache"),
                "message": f"Contract: {contract.get('rule')} ({len(contract.get('call_sites') or [])} call sites). "
                           f"Scan: {len(scans)} wheels, {len(sinks)} sink calls judged.",
                "plain_explanation": "Read how the project uses the package, scanned the package's code without running it, "
                                     "and judged each sensitive call against what the project allows."}))

    status = verdict["status"]
    events.append((last, "VERDICT", "Verdict", "verdict_computed", ALIASES.get(status, "NEEDS_REVIEW"), {
        "verdict": ALIASES.get(status, "NEEDS_REVIEW"), "policy_state": status, "status": status, "stage": verdict["stage"],
        "rule": verdict["rule"], "reason": verdict["reason"], "honesty_wording": honesty_wording(verdict),
        "evidence_lines": [f"{verdict['stage']} / {verdict['rule']}: {verdict['reason']}"],
        "fast_gate_ms": verdict.get("fast_gate_ms"), "cache_hit": verdict.get("cache_hit"),
        "escalated": verdict.get("escalated"), "escalation": verdict.get("escalation"), "demo_condition": condition,
        "causal_graph": None, "violating_paths": [], "repair": None, "reverification": None,  # not run on this path
        "message": f"Verdict: {status} ({verdict['stage']} / {verdict['rule']}). {verdict['reason']}",
        "plain_explanation": honesty_wording(verdict)}))
    return events


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
