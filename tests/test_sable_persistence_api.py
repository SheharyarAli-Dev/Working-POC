from __future__ import annotations

import hashlib

import pytest
from fastapi import HTTPException

from backend.sable import api, storage as storage_module
from backend.sable.benchmark import _run_sable_engine
from backend.sable.fixtures.scenarios import OBLIGATION, SCENARIOS


class PersistedRunStore:
    def __init__(self, proof):
        self.proof = proof

    def get_run(self, run_id):
        return {"run_id": run_id, "proof": self.proof} if run_id == self.proof["run_id"] else None

    def get_obligation(self, obligation_id):
        return OBLIGATION if obligation_id == OBLIGATION["obligation_id"] else None


def _real_persisted_store(tmp_path, monkeypatch, proof):
    monkeypatch.setattr(storage_module, "DATA", tmp_path)
    store = storage_module.SableStorage()
    store.record_run(proof["run_id"], proof["scenario_id"], OBLIGATION["obligation_id"])
    store.complete_run(proof["run_id"], "PRESERVED", proof["decision_hash"], {}, proof, [])
    return store


def _fixture_proof(run_id: str, scenario_id: str) -> dict:
    scenario = SCENARIOS[scenario_id]
    result = _run_sable_engine(scenario)
    successor = result.get("details", {}).get("successor")
    authorization = result.get("details", {}).get("authorization", {})
    actual_actions = authorization.get("actual_actions", [])
    decision_hash = hashlib.sha256(
        f"{scenario['id']}|{result['verdict']}|{successor}|{sorted(actual_actions)}".encode()
    ).hexdigest()
    return {"run_id": run_id, "scenario_id": scenario_id, "decision_hash": decision_hash, "obligation": OBLIGATION}


def test_proof_endpoint_falls_back_to_sqlite_after_process_restart(tmp_path, monkeypatch):
    proof = _fixture_proof("run-after-restart", "rename_with_moved")
    monkeypatch.setattr(api, "RUN_PROOFS", {})
    monkeypatch.setattr(api, "RUN_DATA", {})
    monkeypatch.setattr(api, "storage", _real_persisted_store(tmp_path, monkeypatch, proof))

    assert api.get_proof(proof["run_id"]) == proof


def test_determinism_check_can_rerun_sqlite_fixture_after_restart(tmp_path, monkeypatch):
    proof = _fixture_proof("fixture-after-restart", "rename_with_moved")
    monkeypatch.setattr(api, "RUN_PROOFS", {})
    monkeypatch.setattr(api, "RUN_DATA", {})
    monkeypatch.setattr(api, "storage", _real_persisted_store(tmp_path, monkeypatch, proof))

    result = api.verify_determinism(proof["run_id"])
    assert result["identical"] is True
    assert result["original_hash"] == result["rerun_hash"] == proof["decision_hash"]


def test_custom_bundle_determinism_after_restart_reports_missing_input(monkeypatch):
    proof = {"run_id": "custom-after-restart", "scenario_id": "custom_upload", "decision_hash": "hash"}
    monkeypatch.setattr(api, "RUN_PROOFS", {})
    monkeypatch.setattr(api, "RUN_DATA", {})
    monkeypatch.setattr(api, "storage", PersistedRunStore(proof))

    with pytest.raises(HTTPException) as error:
        api.verify_determinism(proof["run_id"])
    assert error.value.status_code == 409
    assert "Terraform input bundle was not persisted" in error.value.detail
