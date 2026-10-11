import asyncio
import pytest
from backend.satra.settings import load_settings
from backend.satra import ingest
from backend.satra.live_pipeline import run_live_pipeline
from backend.satra.test_validator import run_tests_in_worktree


def test_host_execution_refused_without_docker(tmp_path, monkeypatch):
    monkeypatch.setattr("backend.satra.test_validator.shutil.which", lambda _n: None)
    monkeypatch.delenv("SATRA_ALLOW_HOST_EXEC", raising=False)
    res = run_tests_in_worktree(tmp_path, ["tests"])
    assert res["passed"] is False and res["backend"] == "none"


def test_live_pipeline_executes_real_engine():
    settings = load_settings()
    repo = ingest.ensure_repository(settings)
    sha = ingest.list_recent_commits(repo, limit=1)[0]["sha"]
    events, evidence = [], {}
    publish = lambda rid, kind, data: events.append((kind, data))
    asyncio.run(run_live_pipeline("t-live", sha, publish,
                                  lambda rid, rec: evidence.update(rec), lambda rid, rec: None))
    kinds = [k for k, _ in events]
    assert "run_error" not in kinds, events[-1]
    assert kinds[-1] == "run_completed"
    assert evidence["simulated"] is False and evidence["commit"] == sha
    assert len([k for k in kinds if k == "verification_gate_ticking"]) == 7
    assert evidence["executions"]["candidate"].get("backend") in ("docker", "podman", "HASH_PINNED_BUILTIN_SUBPROCESS", "host", None)
    assert ("candidate_validated" in kinds) or ("ollama_skipped" in kinds), "Ollama outcome must be reported"
    for kind, data in events:
        if kind == "candidate_validated":
            assert data["verdict_badge"] in ("ACCEPTED", "REJECTED")
            if data["verdict_badge"] == "ACCEPTED":
                assert all(c["passed"] for c in data["checklist"])
    print("DECISION", evidence["decision"], "OLLAMA", evidence["ollama"].get("called"), "REPAIR", bool(evidence["repair"]))
