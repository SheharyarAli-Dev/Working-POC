# SATRA-RV baseline report (Phase 0)

Date: 2026-10-10. Branch: `satra-feature` (base `39d113f`). Run in WSL2 Ubuntu, repo at `~/projects/Working-POC`.

## 1. Environment findings

| Item | Finding |
|---|---|
| WSL | Ubuntu, kernel 6.18.33.2-microsoft-standard-WSL2 |
| Python | 3.14.4 (venv `.venv-satra`) |
| Node | v24.21.0 via nvm (installed during Phase 0) |
| pytest / fastapi / flask / httpx | 9.1.1 / 0.143.0 / 3.1.3 / 0.28.1 |
| Docker | 29.8.2, works from WSL after enabling Docker Desktop WSL integration; `hello-world` pulled and ran |
| Sandbox image | `asent-sandbox-app` MISSING. `asent-sandbox:local` (name used by `pytest_runner.py`) MISSING. Phase 6 builds it |
| Ollama | Installed on Windows (v0.40.2), was not running. Started with `OLLAMA_HOST=0.0.0.0:11434` (user env var set) |
| Model | `qwen2.5-coder:1.5b` pulled, digest `d7372fd828518a4d38b1eb196c673c31a85f2ed302b3d1e406c4c2d1b64a0668`, 986 MB |
| WSL to Ollama | `http://localhost:11434` UNREACHABLE from WSL. `http://172.27.0.1:11434` (Windows host IP from `ip route`) WORKS |
| Generation test | prompt "Reply with the single word: ok" returned `ok`, wall latency 3.21 s (includes model load of 2.66 s) |

Fix needed for Ollama from WSL: Windows Ollama must listen on 0.0.0.0 (done) and `OLLAMA_HOST` for SATRA in WSL must be the Windows host IP (`ip route | awk '/default/{print $3}'`). That IP can change after a WSL restart, so `settings.py` will resolve it at runtime when `OLLAMA_HOST` is unset.

## 2. Existing test results (before any change)

Command: `python -m pytest -q -p no:cacheprovider` in WSL.

Result: `10 failed, 61 passed, 1 warning, 1 error in 26.21s`.

Failures: `test_api_replay::test_real_recorded_replay`, two in `test_cavr_targeted`, five in `test_integration` (including `test_weak_oracle_is_real_discrimination`, `test_ownership_regression`, `test_satra_repair_differential`), `test_modules::test_controlled_dormant_execution`, plus an error in `test_threat_repository::test_genuine_public_advisory_range`.

Observed cause (partly inferred): `pytest_runner.run_pytest` selects `docker` whenever Docker is available and runs image `asent-sandbox:local`, which does not exist. The CAVR failure message shows `backend: docker, available: False`. The SATRA integration failures are consistent with this. Not yet confirmed by running with the image present.

There are no `tests/test_satra_*` files. No test targets SATRA directly.

## 3. Component classification

| Component | Class | Evidence |
|---|---|---|
| `analyzer.py` | PARTIAL | Runs real pytest executions via `run_pytest` (baseline, candidate, mutant) on the bundled InvoiceHub. Paths `app/main.py`, `app/security.py`, `tests/test_security.py` are hardcoded. Used by the orchestrator (`service.py:65`), not by `api.py` |
| `api.py` (incl. SSE) | FAKE | `SCENARIOS` dict (lines 64+) holds hardcoded commit hashes (`e4f8109`, `9c82b17`), diffs, regions, contracts. `run_satra_pipeline` (562+) emits scripted events with `asyncio.sleep`. Dictionary cell status is set by `scenario["id"]=="idor_bypass"` (619-637). Findings are hardcoded per scenario id (740-767). Recommit builds `commit_sha`/`pr_url` locally with no git call; the only `subprocess` mention in the file is a docstring. Only `/status` makes a real call (Ollama tags, line 365) |
| `diff_localizer.py` | PARTIAL | Real `ast` parse, but tests function text for substrings (`TOKENS`), diffs whole files with difflib, no baseline/candidate function-span mapping, no deletion handling, families hardcoded |
| `security_contract.py` | PARTIAL | Derived from policy/SRS and AST of `app/main.py`, but only one contract (AUTHZ.IDOR.001) and only for the InvoiceHub route |
| `dictionary.py` | FAKE (definitions only) | `RULES` entries hold `pytest_template` strings. `analyzer.py` only uses them to detect unsupported rules and never runs them; executed tests are in `trusted_security.py`. Template routes (`/api/invoices/...`) differ from those tests (`/invoices/...`). Only 3 of the rule ids were read in Phase 0 |
| `counterfactuals.py` | PARTIAL | One real AST operator: body of `can_access_invoice` becomes `return True`. Function name hardcoded |
| `test_validator.py` | PARTIAL | `preflight` is real AST screening, `judge` is real logic over run results. The 7-check validator does not exist; `analyzer.py` applies about 4 checks |
| `pytest_runner.py` | PARTIAL | Subprocess mode works, restricted to hash-pinned bundled sources. Container mode is FAILING (image missing), mounts the work dir `rw`, sets no `--user`, no timeout kill of the container, no container id or digest evidence |
| `repair.py` | PARTIAL | Real AST patch for the IDOR function only. Applied by `service.py:156`. It overwrites `tests/test_security.py` with the trusted tests, which Phase 8 must replace (R6/8.3) |
| `trusted_security.py` and trusted fixtures | PARTIAL | Executable and independent of candidate tests, but cover InvoiceHub only, live outside `trusted/`, no manifest |
| `ollama_adapter.py` (in `backend/integrations/`) | PARTIAL | Real HTTP call to `127.0.0.1:11434`, `stream:false`, enabled only if `ASENT_OLLAMA_MODEL` is set, no digest/latency capture, unreachable from WSL via localhost. Not in `backend/satra/` |
| `SatraModule.tsx` | FAKE (by dependency) | 1513 lines. Fetches `/api/satra/*` and consumes the scripted SSE events above, so it displays the fake data. Only lines 1-120 and the fetch/SSE call sites were read in Phase 0 |
| Sandbox | MISSING | No image, no SATRA Dockerfile |
| Ingestion of real commits | MISSING | No git clone/fetch/diff anywhere in SATRA |

## 4. Wiring and conflict risk (0.7)

- `backend/main.py:28-29` includes `satra_router`.
- `backend/orchestrator/service.py:24-26,65,155-156` imports `satra.analyzer` and `satra.repair.propose` and calls `analyze(context,out,emit)` and `propose(branch, evidence)`.
- `backend/orchestrator/scenarios.py:6` imports `satra.counterfactuals.mutate_ownership`.
- `backend/threat_repo/satra_rules.py:2` imports `satra.dictionary.RULES`.
- `backend/config.py`, `final_gate.py`, `event_router.py` and `context_service.py` reference the module name `SATRA`.

Risk: any signature change to `analyze`, `propose`, `mutate_ownership` or `RULES` breaks the shared orchestrator and CAVR/SABLE runs. Plan: keep those entry points backward compatible and add new code beside them. Any needed shared change goes in its own `chore(shared):` commit. `backend/integrations/ollama_adapter.py` is outside the allowed paths, so the new adapter goes in `backend/satra/`.

## 5. Proposed ordered gap list

1. Real ingestion from Threat-Repository (Phase 1).
2. Trusted assets with manifest and seeded scenarios (Phase 2).
3. Structural localizer and contracts (Phase 3).
4. Executable dictionary, Tier 1 first (Phase 4).
5. Counterfactual operators and oracle-weakening judge (Phase 5).
6. Sandbox image and container runner with evidence (Phase 6).
7. Live Ollama client and the 7-check validator (Phase 7).
8. Correlator, repair, 7-gate matrix, decision (Phase 8).
9. Replace scripted `api.py` and the UI data source (Phase 9).
10. Approval and local recommit (Phase 10).

Open item: the 11 failing existing tests are mostly CAVR (out of scope, R1) and are expected to clear once the sandbox image exists; this is unverified.
