import pytest
import asyncio
from backend.satra.ollama_adapter import OllamaClient
from backend.satra.test_validator import validate_generated_test


@pytest.fixture
def mock_contract():
    return {
        "rule_id": "AUTHZ.IDOR.001",
        "expected_status": 403,
        "resource": "invoice"
    }


def test_validator_rejects_syntax_error(mock_contract):
    bad_code = "def test_invalid(: assert 403"
    result = validate_generated_test(bad_code, mock_contract)
    assert not result["valid"]
    assert result["failing_check"] == 1


def test_validator_rejects_missing_assertion(mock_contract):
    no_assert = "def test_vacuous(client):\n    client.get('/invoices/1')\n"
    result = validate_generated_test(no_assert, mock_contract)
    assert not result["valid"]
    assert result["failing_check"] == 2


def test_validator_rejects_weakened_assertion(mock_contract):
    weak_code = "def test_weak(client):\n    resp = client.get('/invoices/1')\n    assert resp.status_code in [200, 403]\n"
    result = validate_generated_test(weak_code, mock_contract)
    assert not result["valid"]
    assert result["failing_check"] == 3


def test_validator_rejects_misaligned_contract(mock_contract):
    unaligned = "def test_unrelated(client):\n    resp = client.get('/health')\n    assert resp.status_code == 200\n"
    result = validate_generated_test(unaligned, mock_contract)
    assert not result["valid"]
    assert result["failing_check"] == 4


def test_validator_accepts_valid_test(mock_contract):
    good_code = "def test_idor_blocked(client):\n    resp = client.get('/invoices/1')\n    assert resp.status_code == 403\n"
    base_res = {"available": True, "exit_code": 0, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}
    mut_res = {"available": True, "exit_code": 1, "passed": 0, "failed": 1, "errors": 0, "skipped": 0}
    rep_res = {"available": True, "exit_code": 0, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}

    result = validate_generated_test(good_code, mock_contract, base_res, mut_res, rep_res)
    assert result["valid"]
    assert result["failing_check"] is None


def test_ollama_client_fallback_or_live():
    async def _run():
        client = OllamaClient()
        avail = await client.is_available()
        assert isinstance(avail, bool)

        res = await client.generate_structured("Return a JSON object with key 'status' equal to 'ready'")
        assert "available" in res
        assert "prompt_fingerprint" in res
        assert "latency_ms" in res
        await client.client.aclose()

    asyncio.run(_run())


def test_killed_distinguishes_error_vs_failure():
    from backend.satra.test_validator import killed, judge

    # Setup / import crash (status == 'ERROR' in JUnit XML) is NOT a mutation kill
    import_crash_mutant = {
        "available": True,
        "exit_code": 1,
        "passed": 0,
        "failed": 0,
        "errors": 1,
        "tests": [{"name": "test_idor", "status": "ERROR", "message": "ModuleNotFoundError: No module named 'target'"}]
    }
    assert killed(import_crash_mutant) is False

    # Assertion failure (status == 'FAIL' in JUnit XML) IS a genuine mutation kill
    assert_fail_mutant = {
        "available": True,
        "exit_code": 1,
        "passed": 0,
        "failed": 1,
        "errors": 0,
        "tests": [{"name": "test_idor", "status": "FAIL", "message": "AssertionError: assert 200 == 403"}]
    }
    assert killed(assert_fail_mutant) is True

    # If every mutant is an infrastructure error, judge must produce INCONCLUSIVE, never PRESERVED_WITHIN_MODEL
    baseline_pass = {"available": True, "exit_code": 0, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}
    repeat_pass = {"available": True, "exit_code": 0, "passed": 1, "failed": 0, "errors": 0, "skipped": 0}
    res = judge(baseline=baseline_pass, mutant=import_crash_mutant, repeat=repeat_pass, feasible=True)
    assert res["diagnosis"] == "INCONCLUSIVE"
    assert res["diagnosis"] != "PRESERVED_WITHIN_MODEL"
    assert res["accepted"] is False

    # With genuine assertion kill, judge accepts and produces PRESERVED_WITHIN_MODEL
    res_valid = judge(baseline=baseline_pass, mutant=assert_fail_mutant, repeat=repeat_pass, feasible=True)
    assert res_valid["diagnosis"] == "PRESERVED_WITHIN_MODEL"
    assert res_valid["accepted"] is True


def test_preflight_rejects_vacuous_assertions():
    from backend.satra.test_validator import preflight

    vacuous_examples = [
        "def test_t(client):\n    assert True\n",
        "def test_f(client):\n    assert False\n",
        "def test_one(client):\n    assert 1\n",
        "def test_zero(client):\n    assert 0\n",
        "def test_empty(client):\n    assert ''\n",
    ]
    for code in vacuous_examples:
        ok, reason = preflight(code)
        assert not ok, f"Expected vacuous rejection for: {code}"
        assert "Vacuous assertion" in reason

    # Genuine assertion is accepted
    ok_real, reason_real = preflight("def test_ok(client):\n    assert client.get('/x').status_code == 403\n")
    assert ok_real
    assert "Passed syntax preflight" in reason_real


def test_missing_contract_produces_inconclusive_never_not_applicable(tmp_path):
    from backend.satra.security_contract import build
    from backend.satra.analyzer import analyze
    from backend.threat_repo.repository import seeds

    class MockContext:
        def __init__(self, srs_text):
            self.srs = srs_text
            self.policy = {}
            self.baseline = str(tmp_path)
            self.path = str(tmp_path)
            self.knowledge = {"records": seeds()}

    # SRS lacks ownership / invoice / authorization keywords
    blank_ctx = MockContext("This is an unrelated documentation file with no security rules.")
    assert build(blank_ctx) is None

    # Run analyzer with missing contract
    verdict, details, unc = analyze(blank_ctx, tmp_path / "out", lambda *a: None)
    assert verdict == "INCONCLUSIVE"
    assert verdict != "NOT_APPLICABLE"
    assert "InvoiceHub security contract" in details.get("reason", "")


def test_pytest_runner_lf_digest_cross_platform_invariance():
    from backend.satra.pytest_runner import _lf_digest

    crlf_bytes = b"import sys\r\n\r\ndef test_something():\r\n    assert True\r\n"
    lf_bytes = b"import sys\n\ndef test_something():\n    assert True\n"

    # Both must produce identical hash digests
    assert _lf_digest(crlf_bytes) == _lf_digest(lf_bytes)

