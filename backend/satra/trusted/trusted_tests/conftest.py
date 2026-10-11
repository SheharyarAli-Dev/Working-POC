import json
import types
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

TRUST_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="session")
def policy():
    return json.loads((TRUST_ROOT / "policy.json").read_text())


@pytest.fixture
def world(tmp_path, policy):
    from app.main import create_app

    client = TestClient(create_app(tmp_path), raise_server_exceptions=False)
    headers = {name: {"Authorization": "Bearer " + info["token"]} for name, info in policy["subjects"].items()}
    return types.SimpleNamespace(client=client, headers=headers, data_dir=tmp_path, subjects=policy["subjects"], seeds=policy["seed_invoices"])


def rule_of(policy, family):
    return next(item for item in policy["routes"] if item["family"] == family)
