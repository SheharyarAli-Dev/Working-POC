"""Per-module rows of a gate report, and `asent-summary.md`.

A module's `result` is one of:

    pass                                       assessed, and its evidence is acceptable
    block                                      assessed, and its evidence blocks
    review                                     assessed with an uncertain result, or it applies but its
                                               config is missing/invalid, or nothing is known
    not assessed (disabled by base config)     the base config disables it (never shown as passed)
    not applicable                             its inputs are not in this project

`pass` comes only from a current, acceptable evidence record of an assessed module.
"""
from __future__ import annotations

from backend.orchestrator.final_gate import ACCEPTABLE, BLOCKING
from backend.project_config.frozen import NOT_ASSESSED

MODULES = ("CAVR", "SATRA", "SABLE")
NEEDS = {
    "CAVR": "`.asent/cavr/policy.json` (approved and denied packages, allowed capability scopes, task description) and pinned pip requirements files",
    "SATRA": "`.asent/satra/` security contract, trusted tests and counterfactual target; these cannot be inferred from the code",
    "SABLE": "`.asent/sable/obligations.json` (principal, protected asset, allowed actions, Terraform root)",
}
BOUNDED = ("Bounded claim: only the assessed modules' supported obligations were checked for this exact head commit; "
           "this is not a statement of general safety.")


def module_rows(run, evidence):
    coverage = getattr(run, "coverage", None) or {}
    rows = {}
    for module in MODULES:
        entry = coverage.get(module) or {}
        current = [e for e in evidence if e.get("analyzer") == module and not e.get("stale")]
        record = current[-1] if current else None
        status = record.get("status") if record else None
        if entry.get("assessed"):
            result = ("pass" if status in ACCEPTABLE[module] else "block" if status in BLOCKING[module] or (record or {}).get("blocking")
                      else "review")
        elif entry.get("state") == "disabled":
            result = NOT_ASSESSED
        elif entry and not entry.get("inputs_present") and entry.get("state") != "invalid":
            result = "not applicable"
        else:
            result = "review"
        reason = ((record or {}).get("details") or {}).get("reason") if record else entry.get("reason")
        rows[module] = {"result": result, "status": status, "assessed": bool(entry.get("assessed")),
                        "label": entry.get("label"), "state": entry.get("state"), "inputs_present": entry.get("inputs_present"),
                        "reason": reason, "evidence_id": (record or {}).get("evidence_id")}
    return rows


def _cell(value, limit=300) -> str:
    text = " ".join(str(value if value is not None else "—").split())
    text = text if len(text) <= limit else text[:limit - 1] + "…"
    return text.replace("|", "\\|")


def render_summary(report: dict) -> str:
    decision = report["decision"]
    base, head = report["base"], report["head"]
    short = lambda sha: (sha or "unresolved")[:12]
    lines = [f"# ASENT gate: {decision}", "",
             f"Exit code **{report['exit_code']}** (0 ACCEPT, 1 BLOCK, 2 REVIEW).  ",
             f"Repository `{report['repository']}`: base `{base['ref']}` (`{short(base['sha'])}`) → head `{head['ref']}` (`{short(head['sha'])}`).",
             "", "## Modules", "", "| Module | Result | Status | Reason |", "|---|---|---|---|"]
    rows = report["modules"]
    for module in MODULES:
        row = rows[module]
        lines.append(f"| {module} | {_cell(row['result'])} | {_cell(row['status'])} | {_cell(row['reason'])} |")
    unassessed = [m for m in MODULES if rows[m]["result"] in (NOT_ASSESSED, "review") and not rows[m]["assessed"]]
    if decision == "ACCEPT" and any(rows[m]["result"] == NOT_ASSESSED for m in MODULES):
        lines += ["", "Accepted for the assessed modules only; modules marked "
                  f"\"{NOT_ASSESSED}\" were not checked."]
    lines += ["", "## Reasons", ""] + [f"- {_cell(reason, 600)}" for reason in report["reasons"] or ["(none)"]]
    config = report["config"]
    lines += ["", "## Configuration", "",
              f"- Authority: {config.get('source') or 'base .asent/ (not loaded)'}",
              f"- Digest: `{config.get('digest') or 'none'}`",
              f"- Changed in head: {config.get('changed_in_head')}"]
    lines += [f"- Problem: {_cell(problem, 600)}" for problem in config.get("problems") or []]
    if unassessed:
        lines += ["", "## Needs project input", ""] + [f"- **{m}**: {NEEDS[m]}" for m in unassessed]
    lines += ["", f"_{BOUNDED}_", ""]
    return "\n".join(lines)
