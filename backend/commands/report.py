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
    lines += ["", "Reasons:"] + [f"  - {reason}" for reason in report.get("reasons") or ["(none)"]]
    lines += [f"  config problem: {problem}" for problem in config.get("problems") or []]
    lines += ["", f"Report: {path}"]
    return "\n".join(lines) + "\n"
