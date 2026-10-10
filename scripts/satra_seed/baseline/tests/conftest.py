import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def client(tmp_path):
    return TestClient(create_app(tmp_path))


def auth(token):
    return {"Authorization": "Bearer " + token}
