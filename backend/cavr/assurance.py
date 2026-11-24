"""
Phase 13: Assurance Evidence & Tamper-Evident Cryptographic Hash Chain.
Hash-chains every evidence transition event into an immutable ledger:
Record = {hash_version, seq, ts, phase, substep, type, data, prev_hash, sha256}
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

HASH_VERSION = 2  # FR-10 (PR 19): the record hash covers every field, also ts and substep


def compute_record_hash(record: dict) -> str:
    """The SHA-256 of a version-2 record: seq, ts, phase, substep, type, data, prev_hash and hash_version.

    The fields go into one canonical JSON list, so no field can be moved into another (the old "|"-joined text
    could not tell `a|b` in one field from two fields). A float `ts` survives a JSON round trip exactly.
    """
    fields = [record.get("hash_version"), record.get("seq"), record.get("ts"), record.get("phase"), record.get("substep"),
              record.get("type"), record.get("data"), record.get("prev_hash")]
    return hashlib.sha256(json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def compute_record_hash_v1(record: dict) -> str:
    """The hash of a record written before PR 19 (no `hash_version`). It does not cover ts or substep."""
    raw = (f"{record.get('seq')}|{record.get('phase', '')}|{record.get('type', '')}|"
           f"{json.dumps(record.get('data', {}), sort_keys=True)}|{record.get('prev_hash', '')}")
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()

class EvidenceChain:
    def __init__(self, run_id: str):
        self.run_id = run_id
        self.records: list[dict] = []
        self.last_hash = GENESIS_HASH

    def add_record(self, phase: str, event_type: str, data: dict, substep: str = "") -> dict:
        seq = len(self.records) + 1
        ts = time.time()
        record = {
            "hash_version": HASH_VERSION,
            "seq": seq,
            "ts": ts,
            "phase": phase,
            "substep": substep,
            "type": event_type,
            "data": data,
            "prev_hash": self.last_hash,
        }
        record["sha256"] = compute_record_hash(record)
        self.records.append(record)
        self.last_hash = record["sha256"]
        return record

def verify_chain(records: list[dict]) -> dict:
    """Re-walk the chain: every prev_hash link and every record's own hash.

    A record with `hash_version: 2` is checked with `compute_record_hash` (every field). A record without
    `hash_version` was written before PR 19 (SABLE keeps its chains on disk) and is checked with the old hash; it is
    counted in `legacy_records`, because its ts and substep are not covered. Any other version is refused, and so is
    a legacy record after a version-2 record: a chain cannot go back to the weaker hash.
    """
    if not records:
        return {"intact": True, "total_records": 0, "verified_links": 0, "legacy_records": 0,
                "message": "Empty evidence ledger"}

    expected_prev, legacy, seen_v2 = GENESIS_HASH, 0, False
    for idx, r in enumerate(records):
        seq = r.get("seq", idx + 1)
        if r.get("prev_hash") != expected_prev:
            return {"intact": False, "broken_link_seq": seq,
                    "error": "Link discontinuity: prev_hash does not match preceding block digest.",
                    "expected_prev_hash": expected_prev, "actual_prev_hash": r.get("prev_hash"),
                    "tampered_record_index": idx}
        version = r.get("hash_version")
        if "hash_version" not in r:
            r = r if "seq" in r else {**r, "seq": idx + 1}  # as the old check did for a record without seq
            if seen_v2:
                return {"intact": False, "broken_link_seq": seq, "tampered_record_index": idx,
                        "error": "A legacy record (no hash_version) follows a version-2 record: refused."}
            computed, legacy = compute_record_hash_v1(r), legacy + 1
        elif version == HASH_VERSION and not isinstance(version, bool):
            computed, seen_v2 = compute_record_hash(r), True
        else:
            return {"intact": False, "broken_link_seq": seq, "tampered_record_index": idx,
                    "error": f"Unknown hash_version {version!r}: the record cannot be checked."}
        if computed.lower() != str(r.get("sha256", "")).lower():
            return {"intact": False, "broken_link_seq": seq,
                    "error": "Digest mismatch: block content has been tampered with or altered.",
                    "expected_sha256": computed, "actual_sha256": r.get("sha256"), "tampered_record_index": idx}
        expected_prev = r.get("sha256")

    message = f"Cryptographic evidence chain verified intact ({len(records)}/{len(records)} blocks verified)."
    if legacy:
        message += (f" {legacy} legacy record(s) written before hash version 2: their ts and substep are not "
                    "covered by the hash.")
    return {"intact": True, "total_records": len(records), "verified_links": len(records), "legacy_records": legacy,
            "terminal_digest": expected_prev, "message": message}

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
    # PR 19: the packages the deep stage ran for (sandbox runs), as (name==version, deep result).
    deeps = [(f"{p.get('package')}=={p.get('version')}", (p.get("evidence") or {}).get("deep")) for p in packages
             if isinstance(p, dict) and isinstance((p.get("evidence") or {}).get("deep"), dict)]
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
        "bounded_trust_claim": _claim(status, deeps),
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
            "sandbox_execution": "; ".join(_sandbox_line(name, deep) for name, deep in deeps) or "NOT_RUN (M2)",
        },
        "residual_uncertainty": [
            *(_deep_residual(deeps) if deeps else
              [{"predicate": "package code was not executed", "file_line": "fast gate", "reason": "static checks only; deep analysis is M2"}]),
            *[{"predicate": proof.get("id"), "file_line": proof.get("file"), "reason": proof.get("limit")}
              for proof in reachability.get("proofs") or [] if proof.get("limit")],
        ],
        "evidence_chain_root": terminal_hash,
    }

DEEP_VERIFIED_CLAIM = ("Every fast-gate check passed, and the deep analysis ran the package in the CAVR sandbox: {claim}. "
                       "Nothing outside the contract was observed in those runs. This is not a claim that the package is "
                       "safe; the conditions no run exercised are listed below.")


def _claim(status, deeps) -> str:
    """The bounded claim; for a VERIFIED verdict with deep runs, what those runs did (never "no code was run")."""
    if status == "VERIFIED" and deeps:
        claims = sorted({str((deep.get("evidence") or {}).get("claim") or "the runs listed") for _, deep in deeps})
        return DEEP_VERIFIED_CLAIM.format(claim="; ".join(claims))
    return CLAIMS.get(status, CLAIMS["UNRESOLVED"])


def _sandbox_line(name: str, deep: dict) -> str:
    evidence = deep.get("evidence") if isinstance(deep.get("evidence"), dict) else {}
    runs = evidence.get("runs") if isinstance(evidence.get("runs"), list) else []
    return (f"{name}: {deep.get('status')} {deep.get('rule')} ({len(runs)} sandbox run(s), image "
            f"{evidence.get('image_id') or 'unknown'})")


def _deep_residual(deeps) -> list:
    """What the deep runs did not exercise, per package (the deep evidence's `not_exercised`)."""
    out = []
    for name, deep in deeps:
        evidence = deep.get("evidence") if isinstance(deep.get("evidence"), dict) else {}
        items = [item for item in evidence.get("not_exercised") or [] if isinstance(item, str)]
        out += [{"predicate": item, "file_line": name, "reason": "not exercised by any sandbox run"} for item in items]
        out.append({"predicate": "outside the runs", "file_line": name,
                    "reason": "only the sandbox runs listed were observed; other environments, inputs and call paths were not"})
    return out


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

    recorded = cert.get("recorded") if isinstance(cert.get("recorded"), dict) else None
    recorded_block = "" if recorded is None else (
        "<div class=\"verdict-box block\" style=\"border-color:#d97706\"><strong>RECORDED RUN: replayed, not run now.</strong>"
        "<p class=\"honesty-text\">" + " · ".join(f"{escape(str(key))}: {escape(str(recorded.get(key)))}" for key in
                                                ("id", "recorded_at", "commit", "image_id", "index", "advisories")) +
        "</p><p class=\"honesty-text\">The checks below are the recorded run's; this certificate was issued for the replay.</p></div>")
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

  {recorded_block}
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
    <tr><th width="30%">Check</th><th>{'Result of the recorded run' if recorded else 'Result of this run'}</th></tr>
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
