"""Fixtures for the trusted InvoiceHub tests.

SATRA copies this directory to <project>/asent_assurance/, so parents[1] is the project root.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import create_app

PASSWORD = "demo-password"  # create_app(seed=True) seeds alice, bob (user) and admin (admin) with it
PDF = Path(__file__).resolve().parents[1] / "fixtures" / "invoice.pdf"


def bearer(client, name, password=PASSWORD):
    r = client.post("/auth/login", json={"username": name, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["access_token"]}


def upload(client, headers, name="invoice.pdf"):
    r = client.post("/invoices", headers=headers, files={"file": (name, PDF.read_bytes(), "application/pdf")})
    assert r.status_code == 201, r.text
    return r.json()["id"]


@pytest.fixture(name="bearer")
def bearer_fixture():
    return bearer


@pytest.fixture(name="upload")
def upload_fixture():
    return upload


@pytest.fixture(scope="module")
def case(tmp_path_factory):
    """(client, alice, bob, admin, id of an invoice owned by alice)."""
    client = TestClient(create_app(tmp_path_factory.mktemp("invoice"), seed=True))
    alice, bob, admin = bearer(client, "alice"), bearer(client, "bob"), bearer(client, "admin")
    return client, alice, bob, admin, upload(client, alice)
