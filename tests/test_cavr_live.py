"""Live checks against the real PyPI and OSV. Skipped unless CAVR_LIVE=1.

    CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py
"""
import os

import pytest

from backend.cavr.advisories import check_advisories
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


def test_live_osv_pypdf_5_1_0_is_rejected(tmp_path):
    result = check_advisories("pypdf", "5.1.0", tmp_path / "osv", live=True)
    assert (result["result"], result["rule"]) == ("REJECTED", "KNOWN_VULNERABILITY"), result["reason"]
    assert result["mode"] == "LIVE"
    # 97 advisories were recorded on 2026-10-10. One of them is checked by id; the count is not
    # asserted because an advisory can be withdrawn later.
    assert "GHSA-7hfw-26vp-jp8m" in [entry["id"] for entry in result["affected"]]
    # The live answer is now in the dated cache and is read back offline.
    again = check_advisories("pypdf", "5.1.0", tmp_path / "osv", live=False)
    assert again["mode"] == "DATED CACHE" and again["result"] == "REJECTED"


def test_live_osv_pypdf_6_19_0_gets_an_answer(tmp_path):
    # Not asserted to be clean: a new advisory for 6.19.0 may be published after this was written.
    result = check_advisories("pypdf", "6.19.0", tmp_path / "osv", live=True)
    assert result["mode"] == "LIVE" and result["rule"] != "ADVISORIES_UNAVAILABLE", result["reason"]
