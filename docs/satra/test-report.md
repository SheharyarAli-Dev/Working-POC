# SATRA Verification & Test Report

## Test Suite Execution Summary

- **Total Test Cases Executed:** 70 unit and integration tests across 9 test modules
- **Total Passed:** 70 passed (100% success rate)
- **Execution Platform:** Linux (Ubuntu 24.04 via WSL2) & Docker Sandbox
- **Python Version:** 3.14.4 (isolated venv `.venv-satra`)
- **Docker Image:** `asent-sandbox-app` / `asent-sandbox:local`
- **LLM Engine:** Local Ollama (`qwen2.5-coder:1.5b`)

### Breakdown by Module

| Module | Test File | Tests | Status |
|---|---|---|---|
| Ingestion & Worktrees | `tests/test_satra_ingest.py` | 25 | PASS |
| Trust & Manifest Seed | `tests/test_satra_trust_and_seed.py` | 19 | PASS |
| AST Diff Localizer | `tests/test_satra_localize.py` | 3 | PASS |
| Security Dictionary | `tests/test_satra_dictionary.py` | 3 | PASS |
| Counterfactuals & Oracle | `tests/test_satra_counterfactuals.py` | 3 | PASS |
| Hardened Docker Sandbox | `tests/test_satra_sandbox.py` | 4 | PASS |
| Ollama Adapter & Validator | `tests/test_satra_ollama_and_validator.py` | 6 | PASS |
| Decision Matrix & Repair | `tests/test_satra_decision_and_repair.py` | 4 | PASS |
| Recommit & Signed Trailers | `tests/test_satra_recommit.py` | 3 | PASS |

### Frontend Verification
- TypeScript type-check and Vite production bundle (`tsc -b && vite build`) passed cleanly in 16.39s with 0 errors.
