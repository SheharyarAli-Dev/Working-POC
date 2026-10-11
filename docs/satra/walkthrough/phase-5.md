# Phase 5 walkthrough: Counterfactual Mutation & Test Oracle Weakening Detection

Files: `backend/satra/counterfactuals.py`, `backend/satra/test_validator.py`, `backend/satra/cli.py`, `tests/test_satra_counterfactuals.py`.

## counterfactuals.py

Analogy: an intentional sabotage drill. Introduces synthetic, syntactically valid security defects into a disposable copy of the code (such as replacing authorization predicates with `False`/bypass or dropping path containment checks) to verify whether tests actually fail when they ought to.

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `mutate_file_ast` | Applies an AST mutation operator safely and ensures result parses | Mutates `if row['owner_id'] != user['id']:` | Mutants could be syntactically invalid |
| `op_replace_ownership_predicate` | Disables authorization conditions | Replaces guard condition with `False` | Cannot generate IDOR mutants |
| `op_remove_containment_check` | Drops `is_relative_to` checks from file handlers | Removes path confinement block | Cannot test path traversal oracle strength |
| `op_parameterized_to_fstring` | Rewrites parameterized queries into unsafe literal statements | Strips `?` parameterization | Cannot test SQL injection oracle strength |

## test_validator.py

Analogy: the lie detector for security tests. Evaluates whether the test suite accurately flags code mutations, and statically inspects test files for tampered or weakened assertions (`assert resp.status_code in [200, 403]`), skipped markers, or vacuous assertions (`assert True`).

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `check_static_test_integrity` | AST checks candidate test files against baseline test files | Flags `in [200, 403]` at `tests/test_security.py:6` | Tampered/weakened assertions go undetected |
| `judge_counterfactual_oracles` | Runs candidate tests against mutated copies to produce kill matrix | `scenario/weakened-test` -> `ORACLE_WEAKENED` | SATRA cannot tell if green CI is an illusion |

## Real CLI Output
Running `python -m backend.satra.cli judge --sha <sha>`:
- `scenario/weakened-test`: verdict `ORACLE_WEAKENED`, reason: `Candidate test oracle failed to kill valid counterfactual mutant (or assertion weakened)`, reports exact location `tests/test_security.py:6 -> Assertion broadened to accept insecure status: reply.status_code in [200, 403]`.
- `scenario/secure-refactor`: verdict `PRESERVED_WITHIN_MODEL`, reason: `Candidate tests successfully discriminate against counterfactual mutation`.
