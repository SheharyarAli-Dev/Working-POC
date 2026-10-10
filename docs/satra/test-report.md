# SATRA Verification & Test Report

## Test Suite Execution Summary

- **Total Test Cases Executed:** 72 unit tests across 10 SATRA test modules
- **Total Passed:** 72 passed (100% of SATRA unit tests)
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
| Live pipeline (real engine) + host-exec refusal | `tests/test_satra_live_pipeline.py` | 2 | PASS |

### Frontend Verification
- TypeScript type-check and Vite production bundle (`tsc -b && vite build`) passed with 0 errors.

### Known issues (honest disclosure)
- `tests/test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies` fails with `CAVR: UNRESOLVED` (CAVR-owned; SATRA evidence is not the cause). The other 3 SATRA integration tests pass.
- Scenario dropdown entries marked `[SIMULATED]` are UI fixtures, not engine output; only the `LIVE` mode executes the real pipeline.
- The live pipeline does not yet synthesize repairs or call Ollama; those engines are unit-tested but not yet wired into the live run.
