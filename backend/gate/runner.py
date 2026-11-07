"""`asent gate`: decide one change (base -> head) of a git repository, without a server.

`run_gate(repository, base, head, output_dir, data_dir=None, keep_workdir=False) -> (exit_code, report)`

1. Resolve both refs to commit SHAs in the repository (`git_adapter.resolve_commit`).
2. Export the exact blobs of both commits (`git_adapter.export_commit`; no checkout, no hooks).
3. `Service.create_gate_run(base export, head export)`: baseline = base, candidate = head,
   authority = base `.asent/` frozen into the run (missing or invalid -> REVIEW).
4. `Service.analyze` runs the applicable modules synchronously (gate runs are never repaired).
5. Write `asent-report.json` and `asent-summary.md` to `output_dir`.

Exit codes: 0 ACCEPT, 1 BLOCK, 2 REVIEW. Every failure (unknown ref, unsafe tree, internal error,
config problem) is REVIEW with the reason in the report; if the report cannot be written the exit
code is 2 whatever the decision, so a pipeline never passes without its evidence.

Work files live in a temporary directory that is deleted afterwards, unless `data_dir` is given
(its `runtime/` with the run database and CAVR verdict cache is kept and reused) or `keep_workdir`.
"""
from __future__ import annotations

import json
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from backend.config import VERSION
from backend.gate.summary import module_rows, render_summary
from backend.integrations.git_adapter import export_commit, resolve_commit

EXIT_CODES = {"ACCEPT": 0, "BLOCK": 1, "REVIEW": 2}
REPORT_NAME = "asent-report.json"
SUMMARY_NAME = "asent-summary.md"


def _tools():
    try:
        from backend.integrations.tooling import availability
        return {name: bool(info.get("available")) for name, info in availability().items()}
    except Exception as exc:  # tool probing must never decide anything
        return {"error": f"{type(exc).__name__}: {exc}"}


def run_gate(repository, base, head, output_dir=".", data_dir=None, keep_workdir=False):
    repository = Path(repository).expanduser()
    report = {"schema": "asent.gate.v1", "asent_version": VERSION, "generated_at": datetime.now(timezone.utc).isoformat(),
              "repository": str(repository.resolve()), "base": {"ref": base, "sha": None}, "head": {"ref": head, "sha": None},
              "decision": "REVIEW", "exit_code": 2, "reasons": [], "modules": module_rows(None, []),
              "config": {"digest": None, "source": None, "problems": [], "changed_in_head": None},
              "coverage": {}, "tools": {}, "data_dir": None, "run_id": None, "assurance": None}
    if data_dir is not None:
        work = Path(data_dir).expanduser().resolve()
        work.mkdir(parents=True, exist_ok=True)
        report["data_dir"] = str(work)
    else:
        work = Path(tempfile.mkdtemp(prefix="asent-gate-"))
        if keep_workdir:
            report["data_dir"] = str(work)
    exports = work / "exports" / uuid.uuid4().hex[:12]
    try:
        for side, ref in (("base", base), ("head", head)):
            report[side]["sha"] = resolve_commit(repository, ref)
        export_commit(repository, report["base"]["sha"], exports / "base")
        export_commit(repository, report["head"]["sha"], exports / "head")
        from backend.orchestrator.service import Service
        service = Service(work / "runtime")
        run = service.create_gate_run(exports / "base", exports / "head",
                                      {"repository": report["repository"], "base": report["base"], "head": report["head"]},
                                      title=f"ASENT gate {base} -> {head}")
        report["run_id"] = run.run_id
        service.analyze(run.run_id)
        run = service.store.run(run.run_id)
        evidence = service.store.evidence(run.run_id)
        report.update(decision=run.final_decision if run.lifecycle == "COMPLETE" else "REVIEW", reasons=list(run.reasons),
                      modules=module_rows(run, evidence), coverage=run.coverage,
                      config={"digest": run.config_digest, "source": f"base commit {report['base']['sha']}: .asent/",
                              "problems": run.config_problems, "changed_in_head": run.config_changed_in_head},
                      assurance=service.report(run.run_id))
        if run.lifecycle != "COMPLETE":
            report["reasons"].append(f"run ended in lifecycle {run.lifecycle}: {run.error}")
    except Exception as exc:  # anything unexpected: REVIEW with the reason, never a silent pass
        report["decision"] = "REVIEW"
        report["reasons"].append(f"{type(exc).__name__}: {exc}" if not isinstance(exc, ValueError) else str(exc))
    finally:
        shutil.rmtree(exports, ignore_errors=True)
        if data_dir is None and not keep_workdir:
            shutil.rmtree(work, ignore_errors=True)
    report["tools"] = _tools()
    report["exit_code"] = EXIT_CODES.get(report["decision"], 2)
    try:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / REPORT_NAME).write_text(json.dumps(report, indent=2, default=str) + "\n", encoding="utf-8")
        (out / SUMMARY_NAME).write_text(render_summary(report), encoding="utf-8")
    except OSError as exc:
        print(f"asent gate: could not write {REPORT_NAME}/{SUMMARY_NAME} to {output_dir}: {exc}", file=sys.stderr)
        report["exit_code"] = 2
        return 2, report
    return report["exit_code"], report
