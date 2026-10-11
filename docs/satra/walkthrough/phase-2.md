# Phase 2 walkthrough: trusted assets and the Threat-Repository seed

Files: `backend/satra/trusted/` (policy, SRS, ini, five trusted test files, manifest), `backend/satra/trust.py`, `scripts/satra_seed_threat_repo.sh`, `scripts/satra_seed/` (baseline app, its own tests, `apply_scenario.py`), `tests/test_satra_trust_and_seed.py`.

## Trusted assets

Analogy: the answer key kept in the teacher's office. Students (candidate repositories) never see or edit it, and a seal (the manifest) shows if anyone touched it.

- `policy.json`: subjects (alice, bob, admin with tokens), seed invoices, and one rule per route (`owner_or_admin`, denied status 403, unauthenticated status 401).
- `SRS.md`: SRS-01 to SRS-05, each mapped to a policy rule.
- `trusted_tests/`: pytest files written without reading the target repo. Each file starts with sanity tests (so a broken setup gives INCONCLUSIVE, never VIOLATED) followed by the security assertions.
- `trusted.manifest.json`: SHA-256 of each file (line endings normalized).

## trust.py

| Function | What it does | Example | Breaks if deleted |
|---|---|---|---|
| `fingerprint_bytes` | SHA-256 after CRLF to LF | `b"a\r\n"` and `b"a\n"` hash equal | hashes differ between Windows and WSL checkouts |
| `tracked_files` / `compute_table` | Sorted list and hash table of the trusted directory | 8 files | nothing to compare against |
| `write_manifest` | Rewrites the manifest (a deliberate human action) | used once after editing trusted files | manifest cannot be refreshed |
| `verify_manifest` | Reports mismatched, missing and unlisted files | adding `test_extra.py` gives `unlisted` | tampering goes unnoticed (R6) |
| `read_policy` / `read_requirements` | Load trusted data | used by contracts in Phase 3 | contracts cannot cite authority |

## Seed

`satra_seed_threat_repo.sh` refuses a dirty tree, a missing git identity or existing scenario branches, commits the baseline on `main`, then creates six scenario branches with `apply_scenario.py`, which aborts if its anchor text is not found exactly once. It never pushes.

Real results (own suite / trusted suite):

| Branch | Own suite | Trusted suite |
|---|---|---|
| main | 12 passed | 25 passed |
| scenario/idor-bypass | 1 failed | 2 failed (IDOR) |
| scenario/weakened-test | 12 passed | 2 failed (IDOR) |
| scenario/sqli-fstring | 1 failed | 3 failed (SQLi) |
| scenario/path-traversal | 1 failed | 3 failed (path) |
| scenario/docs-only | 12 passed | 25 passed |
| scenario/secure-refactor | 12 passed | 25 passed |

The `weakened-test` row is the signature case: ordinary CI is green while the trusted tests fail.

## What breaks if deleted

Without `policy.json` and the trusted tests there is no independent authority and SATRA would have to trust the candidate's own tests (circular). Without the manifest, anyone could weaken the trusted tests silently. Without the seed script there are no reproducible scenarios.

## How to review and push the seed branches yourself

```
cd ~/projects/Threat-Repository
git log --oneline --all --decorate
git diff main scenario/idor-bypass
git push origin main
git push origin scenario/idor-bypass scenario/weakened-test scenario/sqli-fstring scenario/path-traversal scenario/docs-only scenario/secure-refactor
```

SATRA does not need the push: with `SATRA_TARGET_SOURCE=~/projects/Threat-Repository` it reads the local branches.
