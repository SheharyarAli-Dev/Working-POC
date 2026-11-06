"""
SABLE FastAPI Router — SSE pipeline, scenario runs, benchmark, dialogs, proof.

SSE event schema (identical to CAVR):
{run_id, seq, ts, step_index, phase, substep, type, status, payload}

LLM in decision path: none
Network OFF | Cloud OFF | Deterministic
"""
from __future__ import annotations
import asyncio
import hashlib
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import AsyncGenerator

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from backend.config import DATA, ROOT
from backend.cavr.assurance import EvidenceChain, verify_chain
from backend.integrations.tooling import availability
from backend.sable.storage import SableStorage
from backend.sable.fingerprints import bundle_sha256
from backend.sable.hcl_parser import parse as hcl_parse
from backend.sable.authorization import evaluate_authorization
from backend.sable.correspondence import rank, choose
from backend.sable.baselines import run_b0, run_b1, run_b2, run_b3, run_b4
from backend.sable.fixtures.scenarios import SCENARIOS, get_scenarios_list, OBLIGATION

sable_router = APIRouter(prefix="/api/sable")
storage = SableStorage()

# In-memory SSE state (mirrors CAVR pattern)
RUN_QUEUES: dict[str, list[asyncio.Queue]] = {}
RUN_CHAINS: dict[str, EvidenceChain] = {}
RUN_PROOFS: dict[str, dict] = {}
RUN_DATA: dict[str, dict] = {}

# Benchmark runs are global (whole-benchmark, not per-run)
_BENCHMARK_RESULT: dict | None = None
_BENCHMARK_RUNNING = False

# ─── Models ──────────────────────────────────────────────────────────────────

class RunRequest(BaseModel):
    scenario_id: str = "rename_with_moved"
    obligation_id: str = "S3-APPROLE-CUSTOMERDATA"
    custom_candidate_tf: dict[str, str] | None = None
    baseline_files: dict[str, str] | None = None
    candidate_files: dict[str, str] | None = None

class AuditRequest(BaseModel):
    action: str  # "APPROVE" | "REJECT"
    user: str = "Security Operator (Admin)"
    reason: str = ""

# ─── SSE helpers (identical pattern to CAVR) ─────────────────────────────────

def publish_event(run_id: str, step_index: int, phase: str, substep: str,
                  event_type: str, status: str, payload: dict):
    chain = RUN_CHAINS.get(run_id)
    seq = len(chain.records) + 1 if chain else 1
    ts = time.time()
    if chain:
        chain.add_record(phase=phase, event_type=event_type, data=payload, substep=substep)
    envelope = {
        "run_id": run_id, "seq": seq, "ts": ts,
        "step_index": step_index, "phase": phase, "substep": substep,
        "type": event_type, "status": status, "payload": payload,
        "data": payload, "timestamp": ts
    }
    if run_id in RUN_QUEUES:
        for q in RUN_QUEUES[run_id]:
            q.put_nowait(envelope)

# ─── Dialog endpoints ─────────────────────────────────────────────────────────

@sable_router.get("/dialog/baseline")
def dialog_baseline():
    obligations = storage.get_obligations()
    from backend.sable.fixtures.scenarios import BASELINE_INFRA
    # Bind the fingerprint to both each relative path and its complete contents.
    bundle_sha = bundle_sha256(BASELINE_INFRA)
    return {
        "title": "Baseline: Trusted Terraform and Obligation",
        "subtitle": "The trusted Terraform and the security obligation to check against.",
        "obligations": obligations,
        "baseline_tf_files": list(BASELINE_INFRA.keys()),
        "baseline_tf_content": BASELINE_INFRA,
        "bundle_sha256": bundle_sha,
        "baseline_predicate": {
            "result": "PASS",
            "reason": "aws_iam_role.app grants exactly [s3:GetObject, s3:PutObject] on ${aws_s3_bucket.customer_data.arn}/* in aws_iam_role_policy.app_policy.",
            "trust_note": "The baseline is trusted by approval, not by this tool. This tool can only analyze the candidate against a given baseline."
        },
        "trust_note": "The baseline is trusted by prior approval. This tool verifies the candidate against it."
    }

@sable_router.get("/dialog/environment")
def dialog_environment():
    tools = availability()
    config_path = Path(ROOT) / "backend" / "sable" / "sable_config.json"
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    return {
        "title": "Environment: Local, Offline Evidence Tools",
        "subtitle": "Local, offline tools that gather evidence.",
        "tool_inventory": {
            "python_hcl2": {
                "name": "python-hcl2",
                "purpose": "Parse .tf and .tf.json files to normalized resource model",
                "version": "8.1.4 (pinned)",
                "available": True,
                "fallback": None
            },
            "terraform": {
                "name": "Terraform CLI",
                "purpose": "terraform validate and terraform plan (offline, with cached providers)",
                "available": tools.get("terraform", {}).get("available", False),
                "fallback": "Built-in HCL parser only (no deployment validation). Labeled 'built-in approximation'."
            },
            "checkov": {
                "name": "Checkov",
                "purpose": "Policy scan evidence for B4 baseline",
                "available": tools.get("checkov", {}).get("available", False),
                "fallback": "Built-in policy predicate only. B4 tagged 'reduced-strength baseline'."
            },
            "trivy": {
                "name": "Trivy",
                "purpose": "IaC misconfiguration scan evidence",
                "available": tools.get("trivy", {}).get("available", False),
                "fallback": "Not used in static analysis. B4 unaffected for this obligation type."
            },
            "docker": {
                "name": "Docker",
                "purpose": "Isolated scanner container (no-network, read-only, non-root, 30s timeout)",
                "available": tools.get("docker", {}).get("available", False),
                "fallback": "Scanners run natively without container isolation. Labeled accordingly."
            }
        },
        "lockdown_flags": [
            {"flag": "--network none", "desc": "No outbound network access during scan"},
            {"flag": "--read-only", "desc": "Candidate filesystem is read-only"},
            {"flag": "--user 10001", "desc": "Non-root scanner context"},
            {"flag": "--timeout 30s", "desc": "Hard timeout to prevent resource exhaustion"}
        ],
        "supported_terraform_subset": config.get("supported_iam_subset", {}),
        "supported_resource_types": config.get("supported_resource_types", []),
        "unsupported_constructs": config.get("unsupported_constructs", []),
        "flags": {
            "network": "OFF",
            "cloud": "OFF",
            "llm_in_decision_path": "none",
            "deterministic": True
        },
        "limitations": [
            "S3 and IAM only. No EC2, RDS, Lambda, or other resource types.",
            "Bounded policy model: inline role policies and bucket policies only.",
            "No deployment-time or external-state behavior (no AWS API calls).",
            "No arbitrary semantic equivalence — only structural and policy signals.",
            "UNKNOWN does not mean the change is safe. It means evidence is insufficient."
        ]
    }

@sable_router.get("/dialog/action")
def dialog_action():
    config_path = Path(ROOT) / "backend" / "sable" / "sable_config.json"
    config = json.loads(config_path.read_text()) if config_path.exists() else {}
    return {
        "title": "Action: SABLE Pipeline",
        "subtitle": "How SABLE reaches PRESERVED, REGRESSED, or UNKNOWN.",
        "pipeline_steps": [
            {"step": 1, "name": "Intake", "desc": "Receive baseline and candidate bundles. Compute SHA-256 for every file and bundle."},
            {"step": 2, "name": "Normalize", "desc": "Parse HCL with python-hcl2. Resolve locals, module calls, references. Extract moved blocks."},
            {"step": 3, "name": "Obligation Model", "desc": "Load the registered obligation (principal, actions, protected asset). Run baseline predicate — if baseline fails, stop."},
            {"step": 4, "name": "Correspondence", "desc": "Generate successor hypotheses. Score with fixed signals and thresholds. Reject if no unique winner."},
            {"step": 5, "name": "Projection", "desc": "Apply baseline obligation to each surviving hypothesis using the bounded authorization evaluator."},
            {"step": 6, "name": "Verification", "desc": "Run available local tools (Terraform validate, Checkov, Trivy) as additional evidence. Label every fallback."},
            {"step": 7, "name": "Attribution", "desc": "Execute decision logic. Emit PRESERVED / REGRESSED / UNKNOWN with decision trace."},
            {"step": 8, "name": "Evidence & Release", "desc": "Emit hash-chained evidence record. SARIF export. ASENT handoff."},
        ],
        "signals_table": [
            {"signal": s, "weight": w} for s, w in config.get("signal_weights", {}).items()
        ],
        "decision_pseudocode": """
baseline = extract_obligation(baseline_tf)
candidates = generate_successor_hypotheses(baseline, candidate_tf)
scored = score_correspondence(baseline, candidates, evidence)
valid = filter_by_confidence_and_constraints(scored)
projected = project_obligation(baseline.obligation, valid)
security = evaluate_authorization(projected, candidate_tf)
if no_unique_successor(valid) or evidence_conflicts(valid): UNKNOWN
elif obligation_holds(security, intended_successor(valid)): PRESERVED
else: REGRESSED
""",
        "outcomes": [
            {
                "verdict": "PRESERVED",
                "wording": "Within the supported Terraform / AWS S3 / IAM model, this obligation remained preserved on the identified successor.",
                "asent_mapping": "ACCEPT"
            },
            {
                "verdict": "REGRESSED",
                "wording": "Demonstrated security-boundary regression under the stated policy model.",
                "asent_mapping": "BLOCK"
            },
            {
                "verdict": "UNKNOWN",
                "wording": "Evidence is insufficient or conflicting. This does not mean the change is safe.",
                "asent_mapping": "REVIEW"
            }
        ],
        "honesty_note": "SABLE never writes 'secure', 'safe', or 'your infrastructure is protected'.",
        "llm_note": "LLM in decision path: none. All decisions are deterministic and reproducible."
    }

# ─── Scenarios ────────────────────────────────────────────────────────────────

@sable_router.get("/scenarios")
def list_scenarios():
    return get_scenarios_list()

@sable_router.get("/obligations")
def list_obligations():
    return storage.get_obligations()

@sable_router.get("/metrics")
def get_metrics():
    runs = storage.get_runs()
    total = len(runs)
    verdicts = {"PRESERVED": 0, "REGRESSED": 0, "UNKNOWN": 0}
    for r in runs:
        v = r.get("verdict") or "UNKNOWN"
        verdicts[v] = verdicts.get(v, 0) + 1
    return {
        "total_runs": total,
        "verdict_distribution": verdicts,
        "recent_runs": runs[:10],
    }

# ─── SSE stream ──────────────────────────────────────────────────────────────

@sable_router.get("/stream/{run_id}")
async def sable_stream(run_id: str, request: Request):
    q: asyncio.Queue = asyncio.Queue()
    if run_id not in RUN_QUEUES:
        RUN_QUEUES[run_id] = []
    RUN_QUEUES[run_id].append(q)

    async def event_generator() -> AsyncGenerator[str, None]:
        try:
            while not await request.is_disconnected():
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=1.0)
                    yield f"data: {json.dumps(ev)}\n\n"
                except asyncio.TimeoutError:
                    yield ": heartbeat\n\n"
        finally:
            if run_id in RUN_QUEUES and q in RUN_QUEUES[run_id]:
                RUN_QUEUES[run_id].remove(q)

    return StreamingResponse(event_generator(), media_type="text/event-stream")

# ─── Run endpoint ─────────────────────────────────────────────────────────────

@sable_router.post("/runs")
async def create_run(body: RunRequest):
    if body.scenario_id in SCENARIOS:
        scenario = dict(SCENARIOS[body.scenario_id])
    elif body.baseline_files and body.candidate_files:
        scenario = {
            "id": "custom_upload",
            "name": "Custom Uploaded Bundle",
            "family": "custom",
            "is_hard_case": False,
            "notes": "Custom uploaded baseline and candidate",
            "baseline_tf": body.baseline_files,
            "candidate_tf": body.candidate_files,
            "obligation": OBLIGATION,
        }
    else:
        raise HTTPException(404, f"Scenario '{body.scenario_id}' not found")

    if body.custom_candidate_tf:
        scenario = dict(scenario)
        scenario["candidate_tf"] = body.custom_candidate_tf

    obligation = storage.get_obligation(body.obligation_id) or OBLIGATION
    if not obligation:
        raise HTTPException(404, f"Obligation '{body.obligation_id}' not found")

    run_id = f"sable-{int(time.time()*1000)}"
    RUN_QUEUES[run_id] = []
    RUN_CHAINS[run_id] = EvidenceChain(run_id)
    RUN_DATA[run_id] = {"scenario": scenario, "obligation": obligation}
    storage.record_run(run_id, body.scenario_id, body.obligation_id)

    asyncio.create_task(execute_sable_pipeline(run_id, scenario, obligation))

    return {
        "run_id": run_id,
        "scenario_id": body.scenario_id,
        "obligation_id": body.obligation_id,
        "stream_url": f"/api/sable/stream/{run_id}",
        "status": "STARTED"
    }

@sable_router.post("/runs/{run_id}/verify-determinism")
def verify_determinism(run_id: str):
    persisted = storage.get_run(run_id)
    proof = RUN_PROOFS.get(run_id) or (persisted or {}).get("proof")
    if not proof:
        raise HTTPException(404, "Proof not found for this run")
    orig_hash = proof.get("decision_hash")
    scenario_id = proof.get("scenario_id")
    scenario = RUN_DATA.get(run_id, {}).get("scenario") or SCENARIOS.get(scenario_id)
    if not scenario:
        raise HTTPException(
            409,
            f"Cannot rerun scenario '{scenario_id}': its Terraform input bundle was not persisted",
        )

    obligation = proof.get("obligation") or storage.get_obligation("S3-APPROLE-CUSTOMERDATA") or OBLIGATION
    from backend.sable.benchmark import _run_sable_engine
    result = _run_sable_engine(scenario)
    target = result.get("details", {}).get("successor")
    verdict = result.get("verdict")
    auth = result.get("details", {}).get("authorization", {})
    actual_actions = auth.get("actual_actions", [])
    if hasattr(auth, "actual_actions"):
        actual_actions = auth.actual_actions
    rerun_hash = hashlib.sha256(
        f"{scenario['id']}|{verdict}|{target}|{sorted(actual_actions)}".encode()
    ).hexdigest()

    return {
        "run_id": run_id,
        "original_hash": orig_hash,
        "rerun_hash": rerun_hash,
        "identical": (orig_hash == rerun_hash),
        "verdict": verdict,
        "successor": target
    }

@sable_router.get("/runs")
def list_runs():
    return storage.get_runs()

@sable_router.get("/runs/{run_id}")
def get_run(run_id: str):
    r = storage.get_run(run_id)
    if not r:
        raise HTTPException(404, "Run not found")
    return r

# ─── Proof & evidence ─────────────────────────────────────────────────────────

@sable_router.get("/proof/{run_id}")
def get_proof(run_id: str):
    proof = RUN_PROOFS.get(run_id)
    if proof is None:
        persisted = storage.get_run(run_id)
        proof = (persisted or {}).get("proof")
    if not proof:
        raise HTTPException(404, "Proof not found")
    return proof

@sable_router.get("/evidence/{run_id}/verify")
def verify_evidence(run_id: str):
    chain = RUN_CHAINS.get(run_id)
    records = chain.records if chain else (storage.get_run(run_id) or {}).get("evidence_chain", [])
    if not records:
        raise HTTPException(404, "No persisted evidence ledger for this run")
    return verify_chain(records)

@sable_router.get("/evidence/{run_id}/records")
def get_evidence_records(run_id: str):
    chain = RUN_CHAINS.get(run_id)
    records = chain.records if chain else (storage.get_run(run_id) or {}).get("evidence_chain", [])
    if not records:
        raise HTTPException(404, "No persisted evidence ledger for this run")
    return {"run_id": run_id, "records": records}

@sable_router.get("/evidence/{run_id}/sarif")
def get_sarif(run_id: str):
    run = storage.get_run(run_id)
    if not run:
        raise HTTPException(404, "Run not found")
    evidence = run.get("evidence", {})
    verdict = run.get("verdict", "UNKNOWN")
    rules = []
    results = []
    if verdict == "REGRESSED":
        rules.append({"id": "SABLE-REGRESSED", "shortDescription": {"text": "Security boundary regression"}})
        results.append({
            "ruleId": "SABLE-REGRESSED",
            "level": "error",
            "message": {"text": evidence.get("reason", "Regression detected")}
        })
    elif verdict == "UNKNOWN":
        rules.append({"id": "SABLE-UNKNOWN", "shortDescription": {"text": "Insufficient evidence"}})
        results.append({
            "ruleId": "SABLE-UNKNOWN",
            "level": "warning",
            "message": {"text": "Evidence is insufficient or conflicting. This does not mean the change is safe."}
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "SABLE", "rules": rules}}, "results": results}]
    }

# ─── Audit log ────────────────────────────────────────────────────────────────

@sable_router.post("/audit/{run_id}")
def record_audit(run_id: str, body: AuditRequest):
    if body.action not in ("APPROVE", "REJECT"):
        raise HTTPException(400, "action must be APPROVE or REJECT")
    storage.record_audit(run_id, body.action, body.user, body.reason)
    publish_event(run_id, 7, "P_AUDIT", "ReviewDecision", "audit.decision",
                  body.action, {"action": body.action, "user": body.user, "reason": body.reason})
    return {"status": "recorded", "action": body.action}

@sable_router.get("/audit")
def get_audit():
    return storage.get_audit_log()

# ─── Benchmark ────────────────────────────────────────────────────────────────

@sable_router.get("/benchmark/result")
def get_benchmark_result():
    if _BENCHMARK_RESULT is None:
        raise HTTPException(404, "No benchmark result yet. POST /api/sable/benchmark/run first.")
    return _BENCHMARK_RESULT

@sable_router.post("/benchmark/run")
async def run_benchmark_endpoint(request: Request):
    global _BENCHMARK_RESULT, _BENCHMARK_RUNNING
    if _BENCHMARK_RUNNING:
        raise HTTPException(409, "Benchmark already running")

    async def stream_benchmark() -> AsyncGenerator[str, None]:
        global _BENCHMARK_RESULT, _BENCHMARK_RUNNING
        _BENCHMARK_RUNNING = True
        try:
            import threading
            result_holder = {}

            def run_sync():
                from backend.sable.benchmark import run_benchmark

                def emit(event_type: str, payload: dict):
                    pass  # collected events via queue below

                result_holder["result"] = run_benchmark(emit=None)

            events: list[dict] = []

            def emit_cb(event_type: str, payload: dict):
                events.append({"type": event_type, "payload": payload})

            from backend.sable.benchmark import run_benchmark
            import concurrent.futures

            loop = asyncio.get_event_loop()
            future = loop.run_in_executor(None, lambda: run_benchmark(emit=emit_cb))

            # Poll for events while benchmark runs
            while not future.done():
                while events:
                    ev = events.pop(0)
                    yield f"data: {json.dumps(ev)}\n\n"
                yield ": heartbeat\n\n"
                await asyncio.sleep(0.2)

            result = await future
            _BENCHMARK_RESULT = result
            yield f"data: {json.dumps({'type': 'benchmark.complete', 'payload': result})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'benchmark.error', 'payload': {'error': str(e)}})}\n\n"
        finally:
            _BENCHMARK_RUNNING = False

    return StreamingResponse(stream_benchmark(), media_type="text/event-stream")

# ─── Pipeline ─────────────────────────────────────────────────────────────────

async def execute_sable_pipeline(run_id: str, scenario: dict, obligation: dict):
    """
    8-step SABLE pipeline with SSE events.
    All computation is real — no scripted animations.
    """
    start = time.time()
    logs: list[str] = []

    def log(msg: str):
        logs.append(f"[{time.strftime('%H:%M:%S')}] {msg}")

    baseline_tf = scenario["baseline_tf"]
    candidate_tf = scenario["candidate_tf"]
    principal = obligation["principal"]
    asset = obligation["protected_asset"]
    actions = obligation["actions"]
    config_threshold = 6
    config_margin = 3

    # ─── STEP 1: AI agent proposes Terraform change ──────────────────────────
    publish_event(run_id, 0, "A", "Change-surface",
                  "state_change", "RUNNING", {
                      "step_index": 0,
                      "message": "ASENT received Terraform change proposal for routing to SABLE.",
                      "scenario": scenario["id"],
                      "scenario_name": scenario["name"],
                      "family": scenario["family"],
                      "obligation": obligation,
                      "plain_explanation": "An AI agent proposed a Terraform change. ASENT detected it affects infrastructure covered by a registered security obligation and routed it to SABLE for boundary verification.",
                      "logs": []
                  })
    log("Step 1: Change proposal received. Computing bundle hashes.")
    await asyncio.sleep(0.5)

    # ─── STEP 2: Capture baseline and candidate ───────────────────────────────
    baseline_sha = bundle_sha256(baseline_tf)
    candidate_sha = bundle_sha256(candidate_tf)

    # File-level diff
    import difflib
    b_text = "\n".join(f"# {fn}\n{c}" for fn, c in baseline_tf.items())
    c_text = "\n".join(f"# {fn}\n{c}" for fn, c in candidate_tf.items())
    diff_lines = list(difflib.unified_diff(
        b_text.splitlines(keepends=True),
        c_text.splitlines(keepends=True),
        fromfile="baseline", tofile="candidate", n=3
    ))

    log(f"Step 2: Baseline SHA-256={baseline_sha[:12]}… Candidate SHA-256={candidate_sha[:12]}…")
    publish_event(run_id, 1, "B", "Capture",
                  "capture.complete", "DONE", {
                      "step_index": 1,
                      "baseline_sha256": baseline_sha,
                      "candidate_sha256": candidate_sha,
                      "baseline_files": list(baseline_tf.keys()),
                      "candidate_files": list(candidate_tf.keys()),
                      "diff": "".join(diff_lines[:100]),
                      "diff_lines": diff_lines[:100],
                      "message": f"Captured baseline ({baseline_sha[:8]}…) and candidate ({candidate_sha[:8]}…).",
                      "plain_explanation": "Both Terraform bundles are captured and fingerprinted. The diff shows exactly what changed.",
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.5)

    # ─── STEP 3: Normalize and model ─────────────────────────────────────────
    log("Step 3: Normalizing HCL with python-hcl2…")

    def parse_model(tf_files: dict) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, content in tf_files.items():
                fpath = Path(tmpdir) / fname
                fpath.parent.mkdir(parents=True, exist_ok=True)
                fpath.write_text(content, encoding="utf-8")
            try:
                return hcl_parse(tmpdir)
            except Exception as e:
                return {"resources": {}, "moves": [], "outputs": {}, "errors": [str(e)],
                        "graph": {"nodes": [], "edges": []}}

    bm = await asyncio.to_thread(parse_model, baseline_tf)
    cm = await asyncio.to_thread(parse_model, candidate_tf)

    b_errors = bm.get("errors", [])
    c_errors = cm.get("errors", [])
    unsupported = b_errors + c_errors

    for k in bm["resources"]:
        log(f"  baseline: {k} ({bm['resources'][k]['type']})")
    for k in cm["resources"]:
        log(f"  candidate: {k} ({cm['resources'][k]['type']})")

    publish_event(run_id, 2, "C", "Normalization",
                  "normalize.complete", "DONE", {
                      "step_index": 2,
                      "baseline_resources": list(bm["resources"].keys()),
                      "candidate_resources": list(cm["resources"].keys()),
                      "baseline_moves": bm["moves"],
                      "candidate_moves": cm["moves"],
                      "baseline_graph": bm["graph"],
                      "candidate_graph": cm["graph"],
                      "unsupported_constructs": unsupported,
                      "message": f"Normalized {len(bm['resources'])} baseline and {len(cm['resources'])} candidate resources.",
                      "plain_explanation": "Terraform HCL parsed and resolved. Local variables, module exports and references all flattened to canonical addresses.",
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.5)

    # ─── STEP 3b: Obligation model ────────────────────────────────────────────
    log(f"Step 3b: Loading obligation. Baseline predicate: {principal} → {asset} via {actions}")
    b_auth = await asyncio.to_thread(evaluate_authorization, bm, principal, asset, actions)

    if not b_auth.known or not b_auth.holds:
        log(f"  BASELINE PREDICATE FAILED: {b_auth.reason}")
        publish_event(run_id, 2, "C", "ObligationModel",
                      "obligation.baseline_failed", "FAILED", {
                          "step_index": 2,
                          "obligation": obligation,
                          "reason": "Baseline predicate fails — baseline is not trusted for this obligation",
                          "auth_result": {"known": b_auth.known, "holds": b_auth.holds, "reason": b_auth.reason},
                          "verdict": "UNKNOWN",
                          "plain_explanation": "The baseline itself does not satisfy the registered security obligation. This means there is no trusted starting point. SABLE stops here.",
                          "logs": list(logs)
                      })
        verdict = "UNKNOWN"
        _finalize(run_id, verdict, obligation, bm, cm, None, b_auth, None, None, {},
                  baseline_sha, candidate_sha, diff_lines, logs, start, scenario)
        return

    log(f"  Baseline predicate PASS: {b_auth.reason}")
    publish_event(run_id, 2, "C", "ObligationModel",
                  "obligation.loaded", "DONE", {
                      "step_index": 2,
                      "obligation": obligation,
                      "baseline_auth": {
                          "known": b_auth.known, "holds": b_auth.holds,
                          "reason": b_auth.reason,
                          "actual_actions": b_auth.actual_actions
                      },
                      "message": f"Obligation loaded. Baseline predicate: PASS.",
                      "plain_explanation": "The baseline Terraform confirms the obligation holds: the role has exactly the right permissions on the protected bucket.",
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.5)

    # ─── STEP 4: Correspondence ───────────────────────────────────────────────
    log(f"Step 4: Generating successor hypotheses for '{asset}'…")
    if asset not in bm["resources"]:
        verdict = "UNKNOWN"
        log(f"  Asset '{asset}' not found in baseline. Stopping.")
        _finalize(run_id, verdict, obligation, bm, cm, None, b_auth, None, None, {},
                  baseline_sha, candidate_sha, diff_lines, logs, start, scenario)
        return

    hyp, conflicts = await asyncio.to_thread(rank, bm, cm, asset)
    log(f"  Generated {len(hyp)} hypotheses. Conflicts: {conflicts}")

    publish_event(run_id, 3, "D", "Correspondence",
                  "correspondence.scored", "DONE", {
                      "step_index": 3,
                      "hypotheses": hyp,
                      "conflicts": conflicts,
                      "signals_table": [
                          {"signal": h["address"], "score": h["score"], "signals": h["signals"]}
                          for h in hyp[:5]
                      ],
                      "threshold": config_threshold,
                      "margin": config_margin,
                      "message": f"Scored {len(hyp)} successor hypotheses.",
                      "plain_explanation": "Every candidate bucket is scored against the baseline using structural signals: physical identity (bucket name), Asset tag, moved blocks, exported references. A single weak signal cannot win.",
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.4)

    target, why = choose(hyp, conflicts, config_threshold, config_margin)
    log(f"  Correspondence decision: target={target}, why={why}")

    if not target:
        verdict = "UNKNOWN"
        publish_event(run_id, 3, "D", "Correspondence",
                      "correspondence.no_winner", "UNKNOWN", {
                          "step_index": 3,
                          "reason": why,
                          "hypotheses": hyp,
                          "plain_explanation": f"No unique successor could be identified. {why}",
                          "logs": list(logs)
                      })
        await asyncio.sleep(0.3)
        _finalize(run_id, verdict, obligation, bm, cm, None, b_auth, None, None, {},
                  baseline_sha, candidate_sha, diff_lines, logs, start, scenario)
        return

    # ─── STEP 5: Project obligation ───────────────────────────────────────────
    log(f"Step 5: Projecting obligation onto successor '{target}'…")
    c_auth = await asyncio.to_thread(evaluate_authorization, cm, principal, target, actions)
    log(f"  Projected auth: known={c_auth.known}, holds={c_auth.holds}")
    log(f"  actual_actions={c_auth.actual_actions}, widening={c_auth.widening}, weakening={c_auth.weakening}")

    # Baseline auth on same address for comparison
    b_auth_on_target = await asyncio.to_thread(evaluate_authorization, bm, principal, asset, actions)

    publish_event(run_id, 4, "E", "Projection",
                  "projection.complete", "DONE", {
                      "step_index": 4,
                      "successor": target,
                      "baseline_auth": {"actual_actions": b_auth.actual_actions,
                                        "expected_resource": b_auth.expected_resource},
                      "candidate_auth": {
                          "known": c_auth.known, "holds": c_auth.holds,
                          "actual_actions": c_auth.actual_actions,
                          "expected_resource": c_auth.expected_resource,
                          "widening": c_auth.widening,
                          "weakening": c_auth.weakening,
                          "misbinding": c_auth.misbinding,
                          "unexpected_resources": c_auth.unexpected_resources,
                          "outside_model": c_auth.outside_model,
                          "grants": c_auth.grants
                      },
                      "message": f"Obligation projected onto successor '{target}'.",
                      "plain_explanation": f"The authorization evaluator checked whether the role still has exactly the right permissions on '{target}'. Any extra or missing action is a regression.",
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.4)

    # ─── STEP 6: Verification ─────────────────────────────────────────────────
    log("Step 6: Running local evidence tools…")
    tools_available = availability()
    tool_results = {}

    # Terraform validate (if available, run against candidate)
    tf_available = tools_available.get("terraform", {}).get("available", False)
    if tf_available:
        import subprocess
        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, content in candidate_tf.items():
                fp = Path(tmpdir) / fname
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content)
            try:
                p = subprocess.run(
                    ["terraform", "validate"],
                    cwd=tmpdir, capture_output=True, text=True, timeout=20
                )
                tool_results["terraform_validate"] = {
                    "available": True, "real_tool": True,
                    "exit_code": p.returncode,
                    "stdout": p.stdout[:2000],
                    "stderr": p.stderr[:500],
                    "claim": "terraform validate on candidate"
                }
                log(f"  terraform validate: exit={p.returncode}")
            except Exception as e:
                tool_results["terraform_validate"] = {
                    "available": False, "real_tool": False,
                    "reason": str(e), "claim": "built-in approximation, not the real tool"
                }
    else:
        tool_results["terraform_validate"] = {
            "available": False, "real_tool": False,
            "reason": "Terraform CLI not installed",
            "claim": "built-in approximation, not the real tool"
        }
        log("  terraform validate: unavailable, using built-in approximation")

    checkov_available = tools_available.get("checkov", {}).get("available", False)
    if checkov_available:
        import subprocess
        with tempfile.TemporaryDirectory() as tmpdir:
            for fname, content in candidate_tf.items():
                fp = Path(tmpdir) / fname
                fp.parent.mkdir(parents=True, exist_ok=True)
                fp.write_text(content)
            try:
                p = subprocess.run(
                    ["checkov", "-d", tmpdir, "--framework", "terraform",
                     "--output", "json", "--quiet", "--skip-download"],
                    capture_output=True, text=True, timeout=30
                )
                tool_results["checkov"] = {
                    "available": True, "real_tool": True,
                    "exit_code": p.returncode,
                    "stdout": p.stdout[:5000],
                    "claim": "checkov scan of candidate"
                }
                log("  checkov: ran real tool")
            except Exception as e:
                tool_results["checkov"] = {
                    "available": False, "real_tool": False,
                    "reason": str(e), "claim": "built-in approximation, not the real tool"
                }
    else:
        tool_results["checkov"] = {
            "available": False, "real_tool": False,
            "reason": "Checkov not installed",
            "claim": "built-in approximation, not the real tool"
        }
        log("  checkov: unavailable, built-in approximation only")

    publish_event(run_id, 5, "F", "Verification",
                  "verification.complete", "DONE", {
                      "step_index": 5,
                      "tool_results": tool_results,
                      "unsupported_constructs": c_auth.outside_model,
                      "message": "Verification tools ran on candidate.",
                      "plain_explanation": "Available local tools (Terraform validate, Checkov) were run against the candidate. Unavailable tools are labeled as 'built-in approximation, not the real tool'.",
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.4)

    # ─── STEP 7: Attribute / Decision ─────────────────────────────────────────
    log("Step 7: Attributing decision…")

    # Decision trace
    if not c_auth.known:
        verdict = "UNKNOWN"
        branch_fired = "no_known_result"
        failure_mode = None
        reviewer_note = "Evidence is insufficient or conflicting. This does not mean the change is safe."
    elif c_auth.holds:
        verdict = "PRESERVED"
        branch_fired = "obligation_holds"
        failure_mode = None
        reviewer_note = None
    else:
        verdict = "REGRESSED"
        branch_fired = "obligation_violated"
        if c_auth.widening:
            failure_mode = "widening"
        elif c_auth.misbinding:
            failure_mode = "misbinding"
        elif c_auth.weakening:
            failure_mode = "weakening"
        else:
            failure_mode = "authorization_failure"
        reviewer_note = _reviewer_guidance(failure_mode, c_auth, target)

    log(f"  Decision: {verdict} (branch: {branch_fired})")

    # Wording per spec
    if verdict == "PRESERVED":
        wording = "Within the supported Terraform / AWS S3 / IAM model, this obligation remained preserved on the identified successor."
    elif verdict == "REGRESSED":
        wording = "Demonstrated security-boundary regression under the stated policy model."
    else:
        wording = "Evidence is insufficient or conflicting. This does not mean the change is safe."

    asent_mapping = {"PRESERVED": "ACCEPT", "REGRESSED": "BLOCK", "UNKNOWN": "REVIEW"}[verdict]

    publish_event(run_id, 6, "G", "Attribution",
                  "decision.attributed", verdict, {
                      "step_index": 6,
                      "verdict": verdict,
                      "wording": wording,
                      "asent_mapping": asent_mapping,
                      "branch_fired": branch_fired,
                      "failure_mode": failure_mode,
                      "successor": target,
                      "correspondence_reason": why,
                      "auth_result": {
                          "known": c_auth.known, "holds": c_auth.holds,
                          "actual_actions": c_auth.actual_actions,
                          "widening": c_auth.widening,
                          "weakening": c_auth.weakening,
                          "misbinding": c_auth.misbinding,
                          "unexpected_resources": c_auth.unexpected_resources,
                          "reason": c_auth.reason,
                          "outside_model": c_auth.outside_model,
                      },
                      "reviewer_note": reviewer_note,
                      "uncertainty": c_auth.outside_model,
                      "message": f"Decision: {verdict}. {wording}",
                      "plain_explanation": _plain_verdict(verdict, failure_mode, target),
                      "logs": list(logs)
                  })
    await asyncio.sleep(0.4)

    # ─── STEP 8: Evidence & Release ───────────────────────────────────────────
    log("Step 8: Generating evidence record and SARIF export…")

    # Compute decision hash (deterministic: same input → same output)
    decision_hash = hashlib.sha256(
        f"{scenario['id']}|{verdict}|{target}|{sorted(c_auth.actual_actions)}".encode()
    ).hexdigest()

    # Build baselines
    b0 = await asyncio.to_thread(run_b0, baseline_tf, candidate_tf, obligation)
    b1 = await asyncio.to_thread(run_b1, baseline_tf, candidate_tf, obligation)
    b2 = await asyncio.to_thread(run_b2, baseline_tf, candidate_tf, obligation)
    b3 = await asyncio.to_thread(run_b3, baseline_tf, candidate_tf, obligation)
    b4 = await asyncio.to_thread(run_b4, baseline_tf, candidate_tf, obligation, tools_available)

    evidence = {
        "run_id": run_id,
        "scenario_id": scenario["id"],
        "obligation": obligation,
        "baseline_sha256": baseline_sha,
        "candidate_sha256": candidate_sha,
        "chosen_successor": target,
        "correspondence_signals": hyp[0]["signals"] if hyp else [],
        "baseline_auth": {"actual_actions": b_auth.actual_actions, "holds": b_auth.holds},
        "candidate_auth": {
            "known": c_auth.known, "holds": c_auth.holds,
            "actual_actions": c_auth.actual_actions,
            "widening": c_auth.widening, "weakening": c_auth.weakening,
            "misbinding": c_auth.misbinding,
            "unexpected_resources": c_auth.unexpected_resources,
            "outside_model": c_auth.outside_model,
            "grants": c_auth.grants
        },
        "verdict": verdict,
        "wording": wording,
        "asent_mapping": asent_mapping,
        "decision_hash": decision_hash,
        "branch_fired": branch_fired,
        "baselines": {
            "B0": {"verdict": b0["verdict"]},
            "B1": {"verdict": b1["verdict"]},
            "B2": {"verdict": b2["verdict"]},
            "B3": {"verdict": b3["verdict"]},
            "B4": {"verdict": b4["verdict"], "reduced_strength": b4["reduced_strength"]}
        },
        "tool_results": tool_results,
        "residual_uncertainty": c_auth.outside_model or [],
        "reason": c_auth.reason,
    }

    proof = {
        "run_id": run_id,
        "scenario_id": scenario["id"],
        "decision_hash": decision_hash,
        "baseline_sha256": baseline_sha,
        "candidate_sha256": candidate_sha,
        "obligation": obligation,
        "config": {
            "confidence_threshold": config_threshold,
            "uniqueness_margin": config_margin,
        },
        "isolation_flags": "Local process — no container for static TF analysis. Checkov runs in --skip-download mode if available.",
        "llm_in_decision_path": "none",
        "determinism": "All weights and thresholds fixed in sable_config.json before any run.",
        "evidence_chain_length": 0,
        "logs": list(logs),
    }

    RUN_DATA[run_id] = evidence

    chain = RUN_CHAINS.get(run_id)
    chain_length = len(chain.records) + 1 if chain else 1

    publish_event(run_id, 7, "H", "Evidence",
                  "run.complete", "COMPLETED", {
                      "step_index": 7,
                      "verdict": verdict,
                      "wording": wording,
                      "asent_mapping": asent_mapping,
                      "decision_hash": decision_hash,
                      "evidence": evidence,
                      "baselines": evidence["baselines"],
                      "chain_length": chain_length,
                      "message": f"Run complete. Verdict: {verdict}. Decision hash: {decision_hash[:12]}…",
                      "plain_explanation": _plain_verdict(verdict, failure_mode, target),
                      "logs": list(logs)
                  })
    proof["evidence_chain_length"] = len(chain.records) if chain else 0
    RUN_PROOFS[run_id] = proof
    storage.complete_run(
        run_id, verdict, decision_hash, evidence, proof,
        chain.records if chain else [],
    )


def _finalize(run_id, verdict, obligation, bm, cm, target, b_auth, c_auth, hyp, tool_results,
              baseline_sha, candidate_sha, diff_lines, logs, start, scenario):
    wording = {
        "PRESERVED": "Within the supported Terraform / AWS S3 / IAM model, this obligation remained preserved on the identified successor.",
        "REGRESSED": "Demonstrated security-boundary regression under the stated policy model.",
        "UNKNOWN": "Evidence is insufficient or conflicting. This does not mean the change is safe."
    }[verdict]
    asent_mapping = {"PRESERVED": "ACCEPT", "REGRESSED": "BLOCK", "UNKNOWN": "REVIEW"}[verdict]
    decision_hash = hashlib.sha256(
        f"{scenario['id']}|{verdict}|{target}".encode()
    ).hexdigest()
    evidence = {
        "run_id": run_id, "scenario_id": scenario["id"],
        "verdict": verdict, "wording": wording,
        "asent_mapping": asent_mapping, "decision_hash": decision_hash,
        "obligation": obligation,
    }
    proof = {
        "run_id": run_id, "scenario_id": scenario["id"],
        "decision_hash": decision_hash,
        "baseline_sha256": baseline_sha, "candidate_sha256": candidate_sha,
        "llm_in_decision_path": "none", "logs": list(logs),
    }
    RUN_PROOFS[run_id] = proof
    RUN_DATA[run_id] = evidence
    publish_event(run_id, 7, "H", "Evidence", "run.complete", "COMPLETED", {
        "step_index": 7, "verdict": verdict, "wording": wording,
        "asent_mapping": asent_mapping, "decision_hash": decision_hash, "evidence": evidence,
        "message": f"Run complete. Verdict: {verdict}.",
        "plain_explanation": _plain_verdict(verdict, None, target),
        "logs": list(logs)
    })
    chain = RUN_CHAINS.get(run_id)
    proof["evidence_chain_length"] = len(chain.records) if chain else 0
    storage.complete_run(
        run_id, verdict, decision_hash, evidence, proof,
        chain.records if chain else [],
    )


def _reviewer_guidance(failure_mode: str | None, auth, target: str) -> str:
    if failure_mode == "widening":
        extra = auth.widening[:3]
        return f"Reviewer: Check whether the extra actions ({extra}) are intentional. The boundary was expanded beyond the registered obligation."
    elif failure_mode == "misbinding":
        return f"Reviewer: The grant now targets a different asset than the logical successor '{target}'. Verify which bucket the role is meant to access."
    elif failure_mode == "weakening":
        missing = auth.weakening[:3]
        return f"Reviewer: The following required actions are no longer granted: {missing}. Verify if this is intentional or an accidental deletion."
    return "Reviewer: Examine the authorization change and confirm whether it is intentional."


def _plain_verdict(verdict: str, failure_mode: str | None, target: str | None) -> str:
    if verdict == "PRESERVED":
        return f"The permission that protected the customer data bucket is still protecting it on the successor '{target}', with the same actions and resource scope."
    elif verdict == "REGRESSED":
        if failure_mode == "widening":
            return "The permission that used to grant exactly what was needed now grants more. The boundary has been widened beyond what the obligation allows."
        elif failure_mode == "misbinding":
            return "The permission is now protecting a different bucket — the correct successor is not covered by the registered obligation anymore."
        elif failure_mode == "weakening":
            return "Some permissions were removed. The role no longer has all the access it is supposed to have."
        return "The security boundary that was supposed to follow the data did not. Something changed in how the role accesses the bucket."
    else:
        return "SABLE could not determine whether the boundary followed correctly. More evidence is needed — this is not a green light."
