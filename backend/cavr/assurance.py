"""
Phase 13: Assurance Evidence & Tamper-Evident Cryptographic Hash Chain.
Hash-chains every evidence transition event into an immutable ledger:
Record = {seq, ts, phase, type, data, prev_hash, sha256}
Provides verification function re-walking the chain.
Generates Certificate JSON and printable HTML report with bounded trust claim.

Since plan step 13 the certificate is built by `certificate_for_verdict` from a pipeline
verdict; it copies values and never fills in a result for a check that did not run.
"""
from __future__ import annotations
import hashlib
import json
import time
from html import escape

GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000"

def compute_record_hash(seq: int, phase: str, event_type: str, data: dict, prev_hash: str) -> str:
    raw = f"{seq}|{phase}|{event_type}|{json.dumps(data, sort_keys=True)}|{prev_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class EvidenceChain:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.records: list[dict] = []
        self.last_hash = GENESIS_HASH

    def add_record(self, phase: str, event_type: str, data: dict, substep: str = "") -> dict:
        seq = len(self.records) + 1
        ts = time.time()
        curr_hash = compute_record_hash(seq, phase, event_type, data, self.last_hash)
        record = {
            "seq": seq,
            "ts": ts,
            "phase": phase,
            "substep": substep,
            "type": event_type,
            "data": data,
            "prev_hash": self.last_hash,
            "sha256": curr_hash
        }
        self.records.append(record)
        self.last_hash = curr_hash
        return record

def verify_chain(records: list[dict]) -> dict:
    if not records:
        return {"intact": True, "total_records": 0, "verified_links": 0, "message": "Empty evidence ledger"}

    expected_prev = GENESIS_HASH
    for idx, r in enumerate(records):
        # 1. Check prev_hash link
        if r.get("prev_hash") != expected_prev:
            return {
                "intact": False,
                "broken_link_seq": r.get("seq", idx + 1),
                "error": "Link discontinuity: prev_hash does not match preceding block digest.",
                "expected_prev_hash": expected_prev,
                "actual_prev_hash": r.get("prev_hash"),
                "tampered_record_index": idx
            }

        # 2. Check record's own SHA-256
        data = r.get("data", {})
        computed = compute_record_hash(
            r.get("seq", idx + 1),
            r.get("phase", ""),
            r.get("type", ""),
            data,
            r.get("prev_hash", "")
        )
        if computed.lower() != r.get("sha256", "").lower():
            return {
                "intact": False,
                "broken_link_seq": r.get("seq", idx + 1),
                "error": "Digest mismatch: block content has been tampered with or altered.",
                "expected_sha256": computed,
                "actual_sha256": r.get("sha256"),
                "tampered_record_index": idx
            }

        expected_prev = r.get("sha256")

    return {
        "intact": True,
        "total_records": len(records),
        "verified_links": len(records),
        "terminal_digest": expected_prev,
        "message": f"Cryptographic evidence chain verified intact ({len(records)}/{len(records)} blocks verified)."
    }

CLAIMS = {
    "VERIFIED": "Every fast-gate check passed for this file and this project: registry SHA-256, dependency tree, OSV "
                "advisories, capability contract, AST scan and sink reachability. No package code was run. This is not a "
                "claim that the package is safe; it is bounded by the checks listed here.",
    "REJECTED": "A check failed. The request must not be installed.",
    "BLOCK": "The project policy does not permit this request. Nothing was downloaded.",
    "UNRESOLVED": "Something could not be established. Unknown is not treated as a pass.",
}
ALIASES = {"VERIFIED": "ALLOW", "REJECTED": "BLOCK", "BLOCK": "BLOCK", "UNRESOLVED": "NEEDS_REVIEW"}
NOT_REACHED = "NOT_REACHED"


def certificate_for_verdict(run_id: str, verdict: dict, terminal_hash: str, demo_condition=None) -> dict:
    """The certificate of one pipeline verdict. Every value is copied from the verdict.

    A check the pipeline did not reach is written as NOT_REACHED, never as passed. Each
    capability row is the contract's own decision (REQUIRED / OPTIONAL / DENIED) for the
    project, not an observation of the package.
    """
    status = verdict.get("status")
    packages = verdict.get("packages") or []
    package = packages[0] if packages else {}
    evidence = package.get("evidence") or {}
    artifact, tree, contract = (evidence.get(key) or {} for key in ("artifact", "tree", "contract"))
    reachability = evidence.get("reachability") or {}
    requested = ((verdict.get("request") or {}).get("requirements") or [{}])[0]
    requested = requested if isinstance(requested, dict) else {}
    advisories = evidence.get("advisories") or []
    scans = evidence.get("scan") or []
    return {
        "certificate_id": f"CERT-ASENT-{run_id}",
        "schema": "https://asent.dev/schema/assurance-certificate/v2.json",
        "timestamp": time.time(),
        "subject": {
            "package": package.get("package") or requested.get("canonical_name"),
            "version": package.get("version") or requested.get("version"),
            "artifact_sha256": artifact.get("sha256"),
            "registry_sha256": artifact.get("registry_sha256"),
            "subtree_digest": tree.get("subtree_digest"),
            "contract_digest": contract.get("digest"),
            "other_packages_in_request": [f"{other.get('package')}=={other.get('version')}" for other in packages[1:]],
        },
        "verdict": ALIASES.get(status, "NEEDS_REVIEW"),
        "status": status, "stage": verdict.get("stage"), "rule": verdict.get("rule"), "reason": verdict.get("reason"),
        "bounded_trust_claim": CLAIMS.get(status, CLAIMS["UNRESOLVED"]),
        "demo_condition": demo_condition,
        "fast_gate_ms": verdict.get("fast_gate_ms"), "cache_hit": verdict.get("cache_hit"),
        "escalated": verdict.get("escalated"), "escalation": verdict.get("escalation"),
        "policy_version": verdict.get("policy_version"), "analyzer_version": verdict.get("analyzer_version"),
        "capability_obligations": [{"obligation": row.get("capability"), "status": row.get("status"),
                                    "evidence": row.get("evidence")} for row in contract.get("contract_rows") or []],
        "security_checks": {
            "requirement_gate": (verdict.get("gate") or {}).get("rule") or NOT_REACHED,
            "artifact_sha256": artifact.get("rule") or NOT_REACHED,
            "dependency_tree": tree.get("rule") or NOT_REACHED,
            "osv_advisories": sorted({str(advisory.get("rule")) for advisory in advisories}) or NOT_REACHED,
            "capability_contract": contract.get("rule") or NOT_REACHED,
            "ast_scan": sorted({str(scan.get("rule")) for scan in scans}) or NOT_REACHED,
            "sink_reachability": reachability.get("rule") or NOT_REACHED,
            "sandbox_execution": "NOT_RUN (M2)",
        },
        "residual_uncertainty": [
            {"predicate": "package code was not executed", "file_line": "fast gate", "reason": "static checks only; deep analysis is M2"},
            *[{"predicate": proof.get("id"), "file_line": proof.get("file"), "reason": proof.get("limit")}
              for proof in reachability.get("proofs") or [] if proof.get("limit")],
        ],
        "evidence_chain_root": terminal_hash,
    }

def generate_printable_html_certificate(cert: dict) -> str:
    subject = cert.get("subject", {})
    obligations = cert.get("capability_obligations", [])
    checks = cert.get("security_checks", {})
    residuals = cert.get("residual_uncertainty", [])

    ob_rows = "".join([
        f"<tr><td><code>{escape(str(o.get('obligation')))}</code></td><td style='color:{'#ef4444' if o.get('status')=='DENIED' else '#22c55e'}'><strong>{escape(str(o.get('status')))}</strong></td><td>{escape(str(o.get('evidence')))}</td></tr>"
        for o in obligations
    ])
    check_rows = "".join(f"<tr><td>{escape(str(name))}</td><td><code>{escape(str(value))}</code></td></tr>" for name, value in checks.items())

    res_list = "".join([
        f"<li><strong>{escape(str(r.get('predicate')))}</strong> ({escape(str(r.get('file_line')))}): {escape(str(r.get('reason')))}</li>"
        for r in residuals
    ]) if residuals else "<li>None observed within declared scope.</li>"

    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>ASENT Assurance Certificate - {escape(str(cert.get('certificate_id')))}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0b0f17; color: #f8fafc; padding: 40px; margin: 0; line-height: 1.5; }}
  .cert-container {{ max-width: 860px; margin: 0 auto; border: 1px solid #1e293b; background: #0f172a; padding: 40px; border-radius: 12px; box-shadow: 0 20px 40px rgba(0,0,0,0.6); }}
  .badge {{ display: inline-block; padding: 4px 10px; border-radius: 6px; font-size: 11px; font-weight: 700; text-transform: uppercase; background: #1e293b; color: #38bdf8; }}
  h1 {{ font-size: 26px; margin: 12px 0 6px 0; color: #f8fafc; letter-spacing: -0.5px; }}
  .meta {{ font-size: 13px; color: #94a3b8; margin-bottom: 24px; }}
  .verdict-box {{ padding: 20px; border-radius: 8px; margin-bottom: 30px; border-left: 4px solid; }}
  .verdict-box.allow {{ background: rgba(34, 197, 94, 0.1); border-color: #22c55e; }}
  .verdict-box.block {{ background: rgba(239, 68, 68, 0.1); border-color: #ef4444; }}
  .honesty-text {{ font-size: 13px; color: #cbd5e1; margin-top: 8px; font-style: italic; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 13px; }}
  th, td {{ padding: 10px 12px; text-align: left; border-bottom: 1px solid #1e293b; }}
  th {{ color: #94a3b8; font-weight: 600; text-transform: uppercase; font-size: 11px; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; background: #1e293b; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #38bdf8; }}
  .footer {{ margin-top: 40px; padding-top: 20px; border-top: 1px solid #1e293b; font-size: 11px; color: #64748b; }}
  @media print {{ body {{ background: #fff; color: #000; padding: 0; }} .cert-container {{ border: none; background: #fff; color: #000; box-shadow: none; }} }}
</style>
</head>
<body>
<div class="cert-container">
  <div class="badge">ASENT CAVR · Tamper-Evident Assurance Record</div>
  <h1>Assurance Certificate</h1>
  <div class="meta">Certificate ID: <code>{escape(str(cert.get('certificate_id')))}</code> · Terminal Hash: <code>{escape(str(cert.get('evidence_chain_root'))[:16])}...</code></div>

  <div class="verdict-box {'allow' if cert.get('status')=='VERIFIED' else 'block'}">
    <strong style="font-size:18px; color:{'#22c55e' if cert.get('status')=='VERIFIED' else '#ef4444'};">
      VERDICT: {escape(str(cert.get('status')))} ({escape(str(cert.get('stage')))} / {escape(str(cert.get('rule')))})
    </strong>
    <p class="honesty-text">{escape(str(cert.get('reason')))}</p>
    <p class="honesty-text">"{escape(str(cert.get('bounded_trust_claim')))}"</p>
    <p class="honesty-text">fast_gate_ms: {escape(str(cert.get('fast_gate_ms')))} · cache_hit: {escape(str(cert.get('cache_hit')))} · escalated: {escape(str(cert.get('escalated')))} · escalation: {escape(str(cert.get('escalation')))} · demo condition: {escape(str((cert.get('demo_condition') or {}).get('id')))}</p>
  </div>

  <h3>Subject Artifact</h3>
  <table>
    <tr><th width="30%">Field</th><th>Value</th></tr>
    <tr><td>Package Name</td><td><strong>{escape(str(subject.get('package')))}</strong></td></tr>
    <tr><td>Version</td><td><code>{escape(str(subject.get('version')))}</code></td></tr>
    <tr><td>Artifact SHA-256 (downloaded file)</td><td><code>{escape(str(subject.get('artifact_sha256')))}</code></td></tr>
    <tr><td>Registry SHA-256</td><td><code>{escape(str(subject.get('registry_sha256')))}</code></td></tr>
    <tr><td>Subtree Digest</td><td><code>{escape(str(subject.get('subtree_digest')))}</code></td></tr>
    <tr><td>Contract Digest</td><td><code>{escape(str(subject.get('contract_digest')))}</code></td></tr>
  </table>

  <h3>Checks</h3>
  <table>
    <tr><th width="30%">Check</th><th>Result of this run</th></tr>
    {check_rows}
  </table>

  <h3>Capability Contract</h3>
  <table>
    <tr><th>Capability Scope</th><th>Contract</th><th>Source</th></tr>
    {ob_rows}
  </table>

  <h3>Residual Uncertainty Statement</h3>
  <div style="background: rgba(15, 23, 42, 0.6); padding: 15px; border-radius: 6px; font-size: 13px;">
    <p>What this run did not establish:</p>
    <ul>{res_list}</ul>
  </div>

  <div class="footer">
    ASENT CAVR fast gate · hash-chained event ledger · Root Digest: <code>{escape(str(cert.get('evidence_chain_root')))}</code>
  </div>
</div>
</body>
</html>"""
