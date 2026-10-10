# Phase 4 walkthrough: Executable Dictionary & Contract Runner

Files: `backend/satra/dictionary.py`, `backend/satra/contract_runner.py`, `docs/satra/dictionary-coverage.md`, `tests/test_satra_dictionary.py`.

## dictionary.py

Analogy: a formal statutory penal code. Instead of vague descriptions of vulnerabilities, each entry has an exact statutory ID, CWE, severity tier, precondition criteria, safety invariant, counterfactual mutation operator, and executable test suite reference.

| Function / Structure | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `RULES` table | Tier 1 (IDOR, SQLi, Path Traversal, Auth) with executable test files; Tier 2 with honest static/stub classifications | `AUTHZ.IDOR.001` -> `trusted_tests/test_authz_idor.py` | SATRA has no standard rules or obligations |
| `get_coverage_matrix` | Machine-readable status of all 8 core families | Returns list of dicts with tier and runnable statuses | UI and reports cannot show rule capability matrix |
| `generate_coverage_markdown` | Formats a comprehensive Markdown table documenting rule coverage | Generates `docs/satra/dictionary-coverage.md` | Supervisor cannot verify honest status of Tier 1 vs Tier 2 |

## contract_runner.py

Analogy: the court magistrate presiding over an evidence hearing. Executes the independent pytest test against the candidate repository while verifying the cryptographic seal (the SHA-256 manifest).

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `run_contract_test` | Runs test file, validates `test_sanity_*` preconditions, returns `SATISFIED`, `VIOLATED`, or `INCONCLUSIVE` | IDOR test against `scenario/idor-bypass` -> `VIOLATED` | No way to deterministically evaluate a contract against code |

## Evidence
- `tests/test_satra_dictionary.py`: passed 3/3 in 29.73s (verifies Tier 1 completeness, ensures sanity failure produces INCONCLUSIVE, and verifies IDOR, SQLi, and Path Traversal produce SATISFIED on `main` and VIOLATED on vulnerable branches).
