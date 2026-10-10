"""Live checks against the real PyPI and OSV. Skipped unless CAVR_LIVE=1.

    CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py
"""
import os

import pytest

from backend.cavr.pypi_client import fetch_artifact
from test_cavr_support import PYPDF_SHA256, sha256_file

pytestmark = pytest.mark.skipif(os.environ.get("CAVR_LIVE") != "1", reason="live network test; set CAVR_LIVE=1")


def test_live_pypi_pypdf_wheel_matches_the_registry_digest(tmp_path):
    result = fetch_artifact("pypdf", "6.19.0", tmp_path / "quarantine")
    assert (result["result"], result["rule"]) == ("OK", "HASH_MATCH"), result["reason"]
    # The same file that is checked in under artifacts/, so the digest is known in advance.
    assert result["sha256"] == result["registry_sha256"] == PYPDF_SHA256
    assert sha256_file(result["path"]) == PYPDF_SHA256


def test_live_pypi_unknown_release_is_unresolved(tmp_path):
    result = fetch_artifact("pypdf", "0.0.0.dev987654321", tmp_path / "quarantine")
    assert (result["result"], result["rule"]) == ("UNRESOLVED", "RELEASE_NOT_FOUND"), result["reason"]
