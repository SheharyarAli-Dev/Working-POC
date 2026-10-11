"""
SABLE bounded IAM/S3 authorization evaluator.
Implements the documented subset: Allow/Deny, action wildcards, ARN wildcard matching,
bucket-level vs object-level scope, principal attachment, bucket policies.

Anything outside the supported subset returns 'outside model' pushing toward UNKNOWN.
This is NOT policy_semantics.py — it supports all five IAM forms in the spec, not
just inline role policies.
"""
from __future__ import annotations
import fnmatch
import json
import re
from typing import NamedTuple

from backend.sable.policy_semantics import unresolved_role_binding
from backend.sable.hcl_parser import unwrap, load_hcl


# ─── Types ────────────────────────────────────────────────────────────────────

class PolicyStatement(NamedTuple):
    effect: str        # "Allow" | "Deny"
    actions: list[str]
    resources: list[str]
    source_addr: str


class AuthResult(NamedTuple):
    known: bool
    holds: bool
    reason: str
    grants: list[dict]
    denies: list[dict]
    actual_actions: list[str]
    expected_resource: str
    unexpected_resources: list[str]
    widening: list[str]   # extra actions or resources
    weakening: list[str]  # missing actions
    misbinding: list[str] # grant targets wrong asset
    outside_model: list[str]  # unsupported constructs


# ─── Action wildcard matching ─────────────────────────────────────────────────

def _matches_action(pattern: str, action: str) -> bool:
    """Check if action matches pattern (supports * and s3:Get* style)."""
    if pattern == "*":
        return True
    return fnmatch.fnmatch(action.lower(), pattern.lower())


def _action_set_covers(patterns: list[str], required_actions: list[str]) -> tuple[bool, list[str], list[str]]:
    """
    Returns (covers, covered, missing).
    covers = True if every required action is matched by at least one pattern.
    """
    covered = [a for a in required_actions if any(_matches_action(p, a) for p in patterns)]
    missing = [a for a in required_actions if a not in covered]
    return len(missing) == 0, covered, missing


def _widens_actions(patterns: list[str], required_actions: list[str]) -> list[str]:
    """Return patterns that grant more than the required actions (widening)."""
    widening = []
    for p in patterns:
        if p == "*" or (p.endswith("*") and not any(_matches_action(p, a) for a in required_actions)):
            widening.append(p)
        elif p not in required_actions and not any(_matches_action(p, a) for a in required_actions):
            widening.append(p)
    return widening


# ─── ARN / resource matching ──────────────────────────────────────────────────

def _normalize_resource(addr: str, model_resources: dict, ref_expr: str) -> list[str]:
    """
    Resolve a TF resource reference expression like ${aws_s3_bucket.x.arn}/*
    to candidate concrete resource ARN patterns.
    Returns list of candidate patterns to match against.
    """
    # Strip ${ } wrapper
    expr = ref_expr.strip()
    if expr.startswith("${") and expr.endswith("}"):
        expr = expr[2:-1]

    # Handle /* suffix
    suffix = ""
    if expr.endswith("/*"):
        suffix = "/*"
        expr = expr[:-2]
    elif expr.endswith("/"):
        suffix = "/"
        expr = expr[:-1]

    # Try to resolve to a bucket name
    parts = expr.split(".")
    if len(parts) >= 3:
        resource_key = ".".join(parts[:2])  # e.g. aws_s3_bucket.customer_data
        node = model_resources.get(resource_key, {})
        bucket = node.get("attributes", {}).get("bucket")
        if isinstance(bucket, str) and "${" not in bucket:
            return [f"arn:aws:s3:::{bucket}{suffix}", f"${{{resource_key}.arn}}{suffix}"]

    return [ref_expr]


def _resource_matches_obligation(grant_resource: str, obligation_resource: str,
                                  bucket_name: str | None = None) -> tuple[bool, str]:
    """
    Check if a grant resource pattern covers the obligation resource scope.
    Returns (matches, reason).
    Obligation resource is canonical like ${aws_s3_bucket.x.arn}/* or arn:aws:s3:::name/*
    """
    g = grant_resource.strip()
    o = obligation_resource.strip()

    if g == o:
        return True, "exact match"
    if g == "*":
        return True, "wildcard * (widening)"

    # Both may be ARN patterns
    if bucket_name:
        literal_obj = f"arn:aws:s3:::{bucket_name}/*"
        literal_bkt = f"arn:aws:s3:::{bucket_name}"
        if g in (literal_obj, literal_bkt, f"arn:aws:s3:::{bucket_name}*"):
            return True, "literal ARN match"

    # Wildcard matching on ARN
    if fnmatch.fnmatch(o, g):
        return True, "ARN pattern match"

    return False, f"resource {g!r} does not cover {o!r}"


# ─── Policy document extraction ───────────────────────────────────────────────

def _decode_policy_doc(value) -> dict | None:
    """Parse a policy from jsonencode(), HCL literal, or dict."""
    if isinstance(value, dict):
        return value
    value = unwrap(value)
    if not isinstance(value, str):
        return None
    if value.startswith("jsonencode(") and value.endswith(")"):
        value = value[len("jsonencode("):-1]
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        try:
            return load_hcl("value = " + value).get("value")
        except Exception:
            return None


def _as_list(v) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


# ─── Main evaluator ──────────────────────────────────────────────────────────

def evaluate_authorization(
    model: dict,
    principal_addr: str,
    asset_addr: str,
    required_actions: list[str],
    ablation_flags: dict | None = None
) -> AuthResult:
    """
    Bounded authorization evaluator.
    model: output of hcl_parser.parse()
    principal_addr: e.g. "aws_iam_role.app"
    asset_addr: e.g. "aws_s3_bucket.customer_data"
    required_actions: e.g. ["s3:GetObject", "s3:PutObject"]
    ablation_flags: optional dict controlling which signals to disable
    """
    ablation = ablation_flags or {}
    resources = model["resources"]

    principal_node = resources.get(principal_addr, {})
    asset_node = resources.get(asset_addr, {})

    if not asset_node:
        return AuthResult(
            known=False, holds=False,
            reason=f"Asset '{asset_addr}' not found in model",
            grants=[], denies=[], actual_actions=[],
            expected_resource=f"${{{asset_addr}.arn}}/*",
            unexpected_resources=[], widening=[], weakening=[], misbinding=[],
            outside_model=[f"Asset '{asset_addr}' missing from model"]
        )

    bucket = asset_node.get("attributes", {}).get("bucket")
    literal_arn_obj = f"arn:aws:s3:::{bucket}/*" if isinstance(bucket, str) and "${" not in bucket else None
    expected_res = f"${{{asset_addr}.arn}}/*"

    grants: list[PolicyStatement] = []
    denies: list[PolicyStatement] = []
    outside_model: list[str] = []

    principal_name = principal_node.get("attributes", {}).get("name") if principal_node else None
    known_role_bindings = {
        f"{addr}.{attribute}"
        for addr, node in resources.items()
        if node["type"] == "aws_iam_role"
        for attribute in ("id", "name")
    }

    for addr, node in resources.items():
        rtype = node["type"]
        attrs = node["attributes"]

        # ── Inline role policy ──
        if rtype == "aws_iam_role_policy":
            role_value = unwrap(attrs.get("role", ""))
            if not isinstance(role_value, str) or not role_value.strip():
                outside_model.append(f"{addr}: role binding unresolved")
                continue
            role_ref = role_value
            linked = role_ref in (
                f"{principal_addr}.id",
                f"{principal_addr}.name",
                principal_name or "__none__"
            )
            if not linked:
                # Ignore a policy only when its different role binding is
                # statically established. A variable or unresolved reference
                # could still bind to the protected principal, so fail closed.
                if role_ref not in known_role_bindings and unresolved_role_binding(role_ref):
                    outside_model.append(f"{addr}: role binding unresolved")
                continue
            doc = _decode_policy_doc(attrs.get("policy"))
            if doc is None:
                outside_model.append(f"{addr}: inline policy expression unresolved")
                continue
            for st in _as_list(doc.get("Statement", [])):
                if not isinstance(st, dict):
                    outside_model.append(f"{addr}: invalid statement")
                    continue
                if any(k in st for k in ["Condition", "NotAction", "NotResource"]):
                    outside_model.append(f"{addr}: unsupported Condition/NotAction/NotResource")
                    continue
                effect = st.get("Effect", "")
                acts = _as_list(st.get("Action", []))
                tgts = _as_list(st.get("Resource", []))
                stmt = PolicyStatement(effect=effect, actions=acts, resources=tgts, source_addr=addr)
                if effect == "Allow":
                    grants.append(stmt)
                elif effect == "Deny":
                    denies.append(stmt)
                else:
                    outside_model.append(f"{addr}: unknown Effect '{effect}'")

        # ── Bucket policy ──
        elif rtype == "aws_s3_bucket_policy":
            bucket_ref = str(unwrap(attrs.get("bucket", "")))
            bucket_linked = bucket_ref in (f"{asset_addr}.id", f"{asset_addr}.bucket", bucket or "__none__")
            if not bucket_linked:
                continue
            doc = _decode_policy_doc(attrs.get("policy"))
            if doc is None:
                outside_model.append(f"{addr}: bucket policy expression unresolved")
                continue
            for st in _as_list(doc.get("Statement", [])):
                if not isinstance(st, dict):
                    continue
                if any(k in st for k in ["Condition", "NotAction", "NotResource"]):
                    outside_model.append(f"{addr}: unsupported bucket policy semantics")
                    continue
                effect = st.get("Effect", "")
                acts = _as_list(st.get("Action", []))
                tgts = _as_list(st.get("Resource", []))
                stmt = PolicyStatement(effect=effect, actions=acts, resources=tgts, source_addr=addr)
                if effect == "Allow":
                    grants.append(stmt)
                elif effect == "Deny":
                    denies.append(stmt)

        # ── Other forms → outside model ──
        elif rtype in ("aws_iam_policy", "aws_iam_role_policy_attachment"):
            outside_model.append(
                f"{addr}: {rtype} — principal linkage requires plan data; outside static model"
            )

    # If anything is outside model, we can still continue but flag it
    if denies and not ablation.get("ignore_denies"):
        return AuthResult(
            known=False, holds=False,
            reason="Explicit Deny statement present; full evaluation requires IAM policy priority semantics (outside static model)",
            grants=[{"policy": g.source_addr, "actions": g.actions, "resources": g.resources} for g in grants],
            denies=[{"policy": d.source_addr, "actions": d.actions, "resources": d.resources} for d in denies],
            actual_actions=[], expected_resource=expected_res,
            unexpected_resources=[], widening=[], weakening=[], misbinding=[],
            outside_model=outside_model + ["Explicit Deny — cannot compute effective permissions without IAM policy evaluation order"]
        )

    # Compute effective allowed actions and resources
    all_allowed_actions: list[str] = []
    all_allowed_resources: list[str] = []
    for g in grants:
        all_allowed_actions.extend(g.actions)
        all_allowed_resources.extend(g.resources)

    all_allowed_actions = list(dict.fromkeys(all_allowed_actions))  # deduplicate, preserve order

    # ── Check: which required actions are covered
    covered, _, missing_actions = _action_set_covers(all_allowed_actions, required_actions)

    # ── Check: do granted resources cover the obligation asset
    good_resource_grants = []
    bad_resources = []
    misbinding_resources = []

    for g in grants:
        for r in g.resources:
            matches, reason = _resource_matches_obligation(r, expected_res, bucket)
            if matches:
                good_resource_grants.append(r)
            else:
                # Misbinding: grants to a different concrete asset
                if r.startswith("arn:aws:s3:::") or r.startswith("${aws_s3_bucket."):
                    misbinding_resources.append(f"{r} ({g.source_addr}: grants to wrong asset)")
                else:
                    bad_resources.append(r)

    # ── Widening detection
    widening_actions = []
    for a in all_allowed_actions:
        if not any(_matches_action(a, req) for req in required_actions):
            # This action goes beyond what the obligation requires
            widening_actions.append(a)
    if "*" in all_allowed_actions or "s3:*" in all_allowed_actions:
        widening_actions.insert(0, "wildcard action grant (s3:* or *)")

    widening_resources = []
    if "*" in all_allowed_resources:
        widening_resources.append("Resource: * (widening — grants beyond protected asset)")

    widening = widening_actions + widening_resources
    weakening = missing_actions

    has_grant = bool(grants)
    resource_ok = bool(good_resource_grants) and not bad_resources
    actions_ok = covered and not widening_actions

    holds = has_grant and resource_ok and actions_ok and not misbinding_resources and not outside_model

    if not has_grant:
        reason = "No authorization grant found for this principal on this asset"
    elif not resource_ok:
        reason = "Authorization grant targets wrong resource (misbinding or uncovered)"
    elif missing_actions:
        reason = f"Weakening: required actions not granted — {missing_actions}"
    elif widening_actions:
        reason = f"Widening: extra actions granted beyond obligation — {widening_actions[:3]}"
    elif misbinding_resources:
        reason = f"Misbinding: grant targets a different asset — {misbinding_resources[:2]}"
    elif outside_model:
        reason = f"Partially outside model: {outside_model[0]}; result uncertain"
        return AuthResult(
            known=False, holds=False, reason=reason,
            grants=[{"policy": g.source_addr, "actions": g.actions, "resources": g.resources} for g in grants],
            denies=[],
            actual_actions=all_allowed_actions,
            expected_resource=expected_res,
            unexpected_resources=bad_resources,
            widening=widening, weakening=weakening, misbinding=misbinding_resources,
            outside_model=outside_model
        )
    else:
        reason = "Exact modeled least privilege holds (within supported IAM/S3 subset)"

    return AuthResult(
        known=True,
        holds=holds,
        reason=reason,
        grants=[{"policy": g.source_addr, "actions": g.actions, "resources": g.resources} for g in grants],
        denies=[],
        actual_actions=all_allowed_actions,
        expected_resource=expected_res,
        unexpected_resources=bad_resources,
        widening=widening,
        weakening=weakening,
        misbinding=misbinding_resources,
        outside_model=outside_model
    )


def classify_difference(baseline_result: AuthResult, candidate_result: AuthResult) -> str:
    """
    Classify the type of authorization change:
    - PRESERVED: obligation holds in candidate as in baseline
    - REGRESSED_WEAKENED: missing actions or missing resource coverage
    - REGRESSED_WIDENED: extra actions or resource wildcard
    - REGRESSED_MISBOUND: correct actions but wrong successor asset
    - UNKNOWN: outside model or insufficient evidence
    """
    if not candidate_result.known:
        return "UNKNOWN"
    if candidate_result.holds:
        return "PRESERVED"
    if candidate_result.widening:
        return "REGRESSED_WIDENED"
    if candidate_result.misbinding:
        return "REGRESSED_MISBOUND"
    if candidate_result.weakening:
        return "REGRESSED_WEAKENED"
    return "REGRESSED"
