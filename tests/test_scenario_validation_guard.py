"""Guard: ordinary test execution must not mutate the committed evidence artifact.

``reports/scenario-validation.json`` is committed historical validation evidence.
The session teardown of ``tests/conftest.py::integration_runs`` used to rewrite
it on every full-suite run, dirtying the working tree and churning a committed
artifact. That teardown now writes the freshly generated report to the pytest
session temp directory, and asserts in-session that the committed artifact is
byte-identical. This test additionally pins the artifact's protected SHA-256 so
any future writer that leaks into the repository fails loudly in any run.
"""
import hashlib
from pathlib import Path

# Protected original SHA-256 of reports/scenario-validation.json. Update ONLY in
# an explicit, reviewed commit that intentionally replaces the artifact.
PROTECTED_SHA256 = "00D6237839C2B71A899CD1D75EBBA62AE74A54846E22BD64892155A818F3CD61"


def test_committed_scenario_validation_artifact_is_not_rewritten_by_tests():
    artifact = Path(__file__).resolve().parents[1] / "reports" / "scenario-validation.json"
    assert artifact.is_file(), "the committed evidence artifact is missing"
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest().upper()
    assert digest == PROTECTED_SHA256, (
        "reports/scenario-validation.json changed on disk; test execution must never "
        f"rewrite it (found {digest}, expected {PROTECTED_SHA256})"
    )
