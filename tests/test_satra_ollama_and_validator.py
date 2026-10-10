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

