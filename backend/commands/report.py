"""`asent report`: read and print the `asent-report.json` that `asent gate` wrote.

Default file: `asent-report.json` at the top level of the current git repository (where `asent gate`
with no arguments writes it), else in the current folder. `load` refuses anything that is not an
ASENT gate report (`schema` asent.gate.v1) with a plain message instead of printing guesses.
"""
from __future__ import annotations

import json
from pathlib import Path

from backend.gate.defaults import top_level
from backend.gate.runner import REPORT_NAME

SCHEMA = "asent.gate.v1"


class ReportError(Exception):
    pass


def default_path() -> Path:
    return (top_level(Path.cwd()) or Path.cwd()) / REPORT_NAME


def load(path: Path) -> dict:
    if not path.is_file():
        raise ReportError(f"No ASENT report at {path}. Run `asent gate` first, or pass --file PATH.")
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise ReportError(f"{path} is not an ASENT gate report ({type(exc).__name__}: {exc}).") from None
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ReportError(f"{path} is not an ASENT gate report (expected schema {SCHEMA}).")
    return report


def render(report: dict, path: Path) -> str:
    short = lambda sha: (sha or "unresolved")[:12]
    base, head = report.get("base") or {}, report.get("head") or {}
    config = report.get("config") or {}
    lines = [f"ASENT gate: {report.get('decision')} (exit {report.get('exit_code')})",
             f"Repository: {report.get('repository')}",
             f"Base: {base.get('ref')} ({short(base.get('sha'))})   Head: {head.get('ref')} ({short(head.get('sha'))})",
             f"Generated: {report.get('generated_at')} by ASENT {report.get('asent_version')}",
             f"Config: {config.get('source') or 'base .asent/ (not loaded)'}; digest {config.get('digest') or 'none'}",
             "", "Modules:"]
    for module, row in (report.get("modules") or {}).items():
        reason = " ".join(str(row.get("reason") or "").split())
        lines.append(f"  {module:<6} {row.get('result')!s:<40} {reason[:160]}")
    lines += cavr_deep(report)
    repairs = cavr_repairs(report)
    if repairs:
        lines += ["", "CAVR repair proposals (not applied; for a person to approve):"] + repairs
    lines += ["", "Reasons:"] + [f"  - {reason}" for reason in report.get("reasons") or ["(none)"]]
    lines += [f"  config problem: {problem}" for problem in config.get("problems") or []]
    lines += ["", f"Report: {path}"]
    return "\n".join(lines) + "\n"


def _cavr_packages(report: dict):
    """(requirements entry, package row) of every package in the CAVR evidence record the CAVR module row names."""
    row = (report.get("modules") or {}).get("CAVR") or {}
    records = ((report.get("assurance") or {}).get("evidence")) or []
    record = next((r for r in records if isinstance(r, dict) and r.get("evidence_id") == row.get("evidence_id")), None)
    for entry in ((record or {}).get("details") or {}).get("pipeline") or []:
        for package in entry.get("packages") or []:
            yield entry, package


def cavr_deep(report: dict) -> list[str]:
    """One line per package that had a CAVR deep result (docs/cavr-m2-plan.md PRs 9, 12, 13): verdict, rule, first key
    event and its cause from the causal graph (e.g. "caused by CI=true").

    Display only, read from the CAVR evidence record; a report without deep results gives no lines.
    """
    lines = []
    for _, package in _cavr_packages(report):
        deep = package.get("deep")
        if not isinstance(deep, dict):
            continue
        line = f"  CAVR deep: {package.get('name')}=={package.get('version')} {deep.get('status')} {deep.get('rule')}"
        key = (deep.get("key_events") or [None])[0]
        if isinstance(key, dict):
            address = key.get("address") or {}
            target = key.get("path") or (f"{address.get('host')}:{address.get('port')}" if address.get("host")
                                         else address.get("path")) or " ".join((key.get("argv") or [])[:3])
            line += f" - {key.get('capability') or key.get('rule')} {key.get('syscall')} {target} = " \
                    f"{'ok' if key.get('ok') else key.get('errno')}"
            cause = (deep.get("causal") or {}).get("cause")
            if cause:
                line += f" {cause}"
        elif deep.get("status") == "VERIFIED":
            runs = [r for r in deep.get("runs") or [] if isinstance(r, dict)]
            counter = sum(1 for r in runs if r.get("kind") == "counterfactual")
            driven = len((deep.get("drives") or {}).get("driven") or [])
            line += (f" ({len(runs)} run(s): canary-only + {counter} counterfactual, {driven} call site(s) driven; "
                     "nothing outside the contract)")
        else:
            missed = next((r for r in deep.get("escalation_reasons") or [] if isinstance(r, dict) and not r.get("exercised")), None)
            residual = next((e for e in (deep.get("residual") or {}).get("entries") or [] if isinstance(e, dict)), None)
            guard = next((g for g in deep.get("unexplored_guards") or [] if isinstance(g, dict)), None)
            if missed:
                line += f" - not exercised: {missed.get('file')}:{missed.get('line')} {missed.get('sink')} ({missed.get('placement')})"
            elif residual:
                line += f" - {residual.get('file')}:{residual.get('line')} `{residual.get('predicate')}`: {residual.get('outcome')}"
            elif guard:
                line += (f" - unevaluable guard {guard.get('file')}:{guard.get('line')} `{guard.get('predicate')}` gates "
                         f"{', '.join(guard.get('capabilities') or [])} ({guard.get('risk')} risk), no run showed it")
        lines.append(line)
    return lines


def cavr_repairs(report: dict) -> list[str]:
    """Text lines for the `repair` block of every REJECTED CAVR package (backend/cavr/repair_proposal.py).

    Display only: read from the CAVR evidence record that the CAVR module row names. A report without such
    a record, or without a block, gives no lines.
    """
    row = (report.get("modules") or {}).get("CAVR") or {}
    records = ((report.get("assurance") or {}).get("evidence")) or []
    record = next((r for r in records if isinstance(r, dict) and r.get("evidence_id") == row.get("evidence_id")), None)
    details = (record or {}).get("details") or {}
    lines = []
    for entry in details.get("pipeline") or []:
        for package in entry.get("packages") or []:
            block = package.get("repair")
            if not isinstance(block, dict):
                continue
            rejected = block.get("rejected") or {}
            lines.append(f"  {package.get('name')}=={package.get('version')} ({rejected.get('status')} {rejected.get('stage')} "
                         f"{rejected.get('rule')}) in {entry.get('file')}: {block.get('result')} {block.get('rule')}")
            if block.get("result") != "PROPOSED":
                lines.append(f"      {block.get('reason')}")
            pin = block.get("pin")
            if isinstance(pin, dict):
                recheck = pin.get("recheck") or {}
                checked = recheck.get("package") or {}
                lines.append(f"      pin {pin.get('requirement')}: re-check {recheck.get('status')} {recheck.get('rule')}, "
                             f"wheel sha256 {str(checked.get('sha256'))[:12]} (registry {str(checked.get('registry_sha256'))[:12]})")
                lines += _patch_lines(pin)
            removal = block.get("removal")
            if isinstance(removal, dict):
                lines.append(f"      remove {removal.get('name')}: re-check {(removal.get('recheck') or {}).get('status')} "
                             f"{(removal.get('recheck') or {}).get('rule')}")
                lines += _patch_lines(removal)
            elif block.get("removal_reason"):
                lines.append(f"      removal not proposed: {block.get('removal_reason')}")
            skipped = [c for c in block.get("candidates_tried") or [] if c.get("outcome") != "PROPOSED"]
            for candidate in skipped:
                lines.append(f"      skipped {candidate.get('version')}: {candidate.get('status')} {candidate.get('rule')}")
            lines += [f"      limitation: {item}" for item in block.get("limitations") or []]
    return lines


def _patch_lines(part: dict) -> list[str]:
    lines = []
    diff = part.get("requirements_diff")
    if diff:
        lines.append(f"        {part.get('requirements_file')}:")
        lines += [f"          {line}" for line in diff.splitlines() if line[:1] in "+-" and line[:3] not in ("---", "+++")]
    elif part.get("pip_command"):
        lines.append(f"        command: {part.get('pip_command')}")
    lock = part.get("lockfile_entry")
    if not lock:
        lines.append("        lockfile: none in the project")
    else:
        after = lock.get("after")
        lines.append(f"        {lock.get('file')}: " + (f"{after.get('name')} {after.get('version')} sha256 {after.get('sha256')}"
                                                       if after else f"remove {(lock.get('before') or {}).get('name')}"))
    policy = part.get("policy") or {}
    changes = [f"+ {item}" for item in policy.get("added") or []] + [f"- {item}" for item in policy.get("removed") or []]
    lines.append("        policy approved_requirements: " + (", ".join(changes) if changes else "no change needed"))
    return lines
