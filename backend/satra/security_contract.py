import hashlib
import json
from pathlib import Path
from backend.satra.trust import read_policy, read_requirements

FAMILY_TO_CWE = {
    "AUTHZ.IDOR.001": "CWE-639",
    "AUTHZ.ROLE.001": "CWE-285",
    "AUTH.REQ.001": "CWE-306",
    "INJ.SQL.001": "CWE-89",
    "PATH.TRAV.001": "CWE-22",
    "INJ.CMD.001": "CWE-78",
    "DESER.INSEC.001": "CWE-502",
    "SSRF.WEBHOOK.001": "CWE-918",
    "XSS.STORED.001": "CWE-79",
    "AUTH.CSRF.001": "CWE-352",
}


def match_policy_route(policy, region_route):
    if not region_route:
        return None
    r_method = region_route.get("method", "").upper()
    r_path = region_route.get("path", "")

    for p_route in policy.get("routes", []):
        if p_route.get("method", "").upper() == r_method and p_route.get("path") == r_path:
            return p_route
    return None


def derive_contracts_for_regions(regions, policy=None, requirements_text=None):
    if policy is None:
        policy = read_policy()
    if requirements_text is None:
        requirements_text = read_requirements()

    contracts = []
    seen_ids = set()

    for reg in regions:
        route_info = reg.get("route")
        p_route = match_policy_route(policy, route_info)

        families = reg.get("families", [])
        if p_route and p_route.get("family") and p_route.get("family") not in families:
            families.append(p_route.get("family"))

        for fam in families:
            cwe = FAMILY_TO_CWE.get(fam, "CWE-699")
            req_id = p_route.get("requirement", "SRS-01") if p_route else "SRS-01"
            rule_id = p_route.get("id", f"RULE-{fam}") if p_route else f"RULE-{fam}"

            contract_seed = f"{fam}:{reg['file']}:{reg['function']}:{p_route['id'] if p_route else ''}"
            contract_id = f"SCC-{fam}-{hashlib.sha256(contract_seed.encode()).hexdigest()[:8]}"

            if contract_id in seen_ids:
                continue
            seen_ids.add(contract_id)

            contract = {
                "contractId": contract_id,
                "family": fam,
                "cwe": cwe,
                "subject": f"Operation {reg['function']}",
                "action": f"{route_info['method']} {route_info['path']}" if route_info else reg["function"],
                "preconditions": [
                    "Authenticated caller" if (p_route and p_route.get("authentication") == "required") else "Any caller"
                ],
                "expected_secure_outcome": {
                    "denied_status": p_route.get("denied_status", 403) if p_route else 403,
                    "state_effect": "No mutation and zero unauthorized data leakage"
                },
                "invariant": f"Strict adherence to {fam} boundary constraints",
                "region": {
                    "file": reg["file"],
                    "old_file": reg.get("old_file"),
                    "function": reg["function"],
                    "start_line": reg.get("start_line"),
                    "end_line": reg.get("end_line"),
                    "route": route_info
                },
                "source_of_authority": {
                    "policy_rule_id": rule_id,
                    "srs_requirement_id": req_id
                },
                "regression_notes": reg.get("regression_notes", []),
                "status_flags": {
                    "guard_dropped": any("removed" in n for n in reg.get("regression_notes", [])),
                    "sink_tampered": any("became" in n or "introduced" in n for n in reg.get("regression_notes", []))
                }
            }
            contracts.append(contract)

    return contracts


def build(context):
    # The contract authority is the trusted SRS and policy, not the candidate's own SRS.
    # If the candidate workspace has replaced or removed the relevant security requirements
    # (e.g. set srs to content that lacks ownership/invoice semantics), there is no supported
    # InvoiceHub security contract to enforce.
    srs_text = (context.srs or "").lower()
    required_keywords = ("invoice", "owner", "authoriz", "authenticat", "access")
    if not any(kw in srs_text for kw in required_keywords):
        return None
    p = context.policy.get("ownership", {}) if hasattr(context, "policy") and isinstance(context.policy, dict) else {}
    from backend.orchestrator.hashing import digest
    contract = {
        "rule_id": "AUTHZ.IDOR.001",
        "version": 1,
        **p,
        "route": "GET /invoices/{invoice_id}",
        "expected_status": p.get("denied_status", 403),
        "authority_sources": ["SRS.md#FR-03", "policy.json#ownership", "trusted baseline app/main.py"],
        "preconditions": ["authenticated normal user", "existing invoice owned by another user"],
        "counterfactual": "bypass can_access_invoice ownership guard",
        "scope": ["app/main.py", "app/security.py"]
    }
    contract["digest"] = digest(contract)
    return contract
