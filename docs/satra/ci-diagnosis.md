# SATRA CI Diagnosis — Phase A
**Date:** 2026-10-11  
**Author:** ASENT diagnostic session (Windows + WSL Ubuntu)  
**Status:** DIAGNOSE ONLY — no code changes, no commits

---

## A1 — Environment

| Property | Value |
|---|---|
| OS | Linux IT-WK 6.18.33.2-microsoft-standard-WSL2 x86_64 (WSL2) |
| Working copy location | `/mnt/c/Users/Administrator/Desktop/Mid` — **Windows filesystem mounted in WSL** |
| Branch | `satra-feature` |
| Remote | `https://github.com/SheharyarAli-Dev/Working-POC.git` |
| git user.email | **(blank — not set in this checkout)** |
| core.autocrlf | **(not set explicitly)** |
| .gitattributes | **EXISTS** on disk: `* text=auto eol=lf` + binary overrides for png/jpg/pdf/mp4/sqlite3/whl/zip |
| Python (WSL) | 3.14.4 |

> **Important:** The working copy lives on the Windows filesystem (`/mnt/c/...`), not in the WSL Linux filesystem. This matters because `/mnt/c` has different I/O characteristics and git may resolve paths differently. Rule N3 says the repo must live in the Linux filesystem for parity with CI. This is not yet fixed — Phase B will address it.

---

## A2 — Branch Topology

**Merge base:** commit `10a490f` (Merge remote-tracking branch 'origin/master' into satra-feature)

**satra-feature only (36 commits ahead):**
```
ec90b19  fix(ci): normalize CRLF→LF in source hash checks to fix Linux CI failures
fb6e8c7  fix(tests): align CI test suite with cross-platform execution environment
a5f04c6  fix(recommit): provide committer credentials and forward push to remote GitHub forge
5a19f18  fix(satra): fix recommit approve push pipeline and button UI state
4d707c7  fix(frontend): prevent null crash on SATRA tab, add ErrorBoundary, wire direct repair
64731ef  fix(satra): restore approve and push button hydration and forge repair branch push
8b14317  feat(frontend): auto-scroll to decision and improve container status badge
e066174  feat(satra): add audit-logs endpoint to view approved recommits
d44e7d1  fix(satra): emit recommit_ready on live repair and populate pr/commit urls
d16bd5a  fix(frontend): restore native ASENT styling for SatraCommitPicker
ee868f3  fix(satra): sync threat repo seed rules, integrate Ollama and sandbox re-verified repair
a4e8406  fix(satra): real live pipeline, sandboxed untrusted test execution, SSE replay
22387c3  docs(satra): add phase 11 architecture diagrams, requirements, test reports, demo script
4916c43  feat(satra): implement phase 9 API/frontend modularization and phase 10 verified recommit
0fc5246  feat(satra): implement Phase 8 7-gate matrix and bounded deterministic repair loop
03ae425  feat(satra): implement Phase 7 live ollama adapter and 7-check validator pipeline
8b3bdce  feat(satra): implement Phase 6 hardened docker sandbox runner and validation tests
... (earlier SATRA feature development)
```

**master only (6 commits ahead):**

| SHA | Author | Message | Files changed |
|---|---|---|---|
| e02b388 | maryamfatimaaaaa | Merge PR #3 fix/satra-seed-rules | (merge) |
| 13188b6 | maryamfatimaaaaa | fix(satra): keep seed-compatible rule list for threat repository | `backend/satra/seed_rules.py` (new), `backend/threat_repo/satra_rules.py` (modified) |
| a0072ea | maryamfatimaaaaa | Merge PR #2 ci-cd | (merge) |
| 4b32eb5 | maryamfatimaaaaa | ci: also disable podman so sandbox tests use no-container mode | `.github/workflows/ci.yml` |
| 1b55cca | maryamfatimaaaaa | ci: run sandbox tests with Docker disabled | `.github/workflows/ci.yml` |
| 1d0fe31 | maryamfatimaaaaa | ci: add GitHub Actions CI (lint, module tests, full suite, frontend) and CD | `.github/workflows/ci.yml`, `.github/workflows/cd.yml`, `Dockerfile` |

> **Key observation:** `backend/satra/seed_rules.py` was added to master (PR #3) but does NOT exist on `satra-feature`. The `backend/threat_repo/satra_rules.py` was modified on master. This is a likely conflict point.

**Predicted conflicts (git merge-tree not run to avoid touching working tree):**
- `backend/threat_repo/satra_rules.py` — modified on master (PR #3) AND likely modified on satra-feature (multiple commits reference seed rule changes)
- Possibly `.gitattributes` — added on master (`fix/line-endings-orchestrator` PR), may conflict with any satra-feature changes

---

## A3 — Why CI Did Not Run on satra-feature

**Evidence:**
```
git ls-tree -r origin/satra-feature --name-only | grep .github
→ (empty — no output)

git ls-tree -r origin/master --name-only | grep .github
→ .github/workflows/cd.yml
→ .github/workflows/ci.yml
```

**The `ci.yml` trigger section (from master):**
```yaml
on:
  push:
    branches: ["**"]
  pull_request:
    branches: [master]
  workflow_dispatch:
```

**Root cause (one sentence, with evidence):** GitHub Actions reads workflow files **from the branch being pushed**, not from the default branch; since `.github/workflows/ci.yml` does not exist on `origin/satra-feature` (confirmed by `git ls-tree`), pushing to `satra-feature` gives GitHub nothing to execute — **no workflow file = no CI run**.

No skip-ci markers found in any commit messages.

---

## A4 — Real CI Evidence

**`gh` CLI:** Not installed in WSL or Windows on this machine.  
**Method used:** GitHub public REST API via `curl`.

**Runs on satra-feature:**
```
Total workflow runs: 0
```
**Proof:** CI has never run on `satra-feature`. This confirms A3.

**Runs on master:**
```
38134615337  completed  cancelled  e02b388  CI
38134615327  completed  success    e02b388  CD
38091887932  completed  failure    a0072ea  CI
```

**Check-runs on master HEAD (e02b388):**
| Check | Result |
|---|---|
| GitHub Release (tags only) | skipped |
| Frontend build | cancelled |
| Tests — SABLE | cancelled |
| Tests — CAVR | cancelled |
| Lint (syntax + security scan) | cancelled |
| Tests — Shared + Threat repo | cancelled |
| Full suite (integration) | cancelled |
| Build and publish Docker image | **success** |

> The "1/8" means: 1 check succeeded (CD Docker build), 7 were cancelled. The CI run `38134615337` was cancelled — likely because a newer run superseded it via the `cancel-in-progress: true` concurrency setting. **The CI run from the previous commit `a0072ea` (`38091887932`) actually ran and failed.** That failure is the one the user saw in the 8-failure output.

---

## A5 — Test Visibility

**Local tracked SATRA test files (git ls-files):** 12 files:
```
tests/test_satra_counterfactuals.py
tests/test_satra_decision_and_repair.py
tests/test_satra_dictionary.py
tests/test_satra_gitkit.py
tests/test_satra_ingest.py
tests/test_satra_live_pipeline.py
tests/test_satra_localize.py
tests/test_satra_ollama_and_validator.py
tests/test_satra_recommit.py
tests/test_satra_rule_contract.py
tests/test_satra_sandbox.py
tests/test_satra_trust_and_seed.py
```

**On origin/satra-feature (`git ls-tree`):** ALL 12 files are present.

**Not ignored:** `git check-ignore -v tests/test_satra_*.py` → "not ignored" for all 12.

**Unpushed commits:** None (`git log origin/satra-feature..HEAD` is empty — working tree is clean and fully pushed).

**Conclusion:** The SATRA test files ARE tracked, ARE pushed, and ARE visible on `origin/satra-feature`. The user's statement "my SATRA tests are not visible on my branch on GitHub" was likely caused by **looking at the master branch on GitHub instead of satra-feature**. There is no git-level problem with test visibility.

**Total tests in tests/ directory:** 21 files tracked.

---

## A6 — Audit of Previous Commits

### Commits `fb6e8c7` and `ec90b19` — Files changed

**fb6e8c7** (`fix(tests): align CI test suite with cross-platform execution environment`):
```
M  backend/cavr/lab_harness.py
M  backend/satra/runner_entry.py
M  backend/satra/security_contract.py
M  backend/satra/test_validator.py
M  scenarios/laboratory_hashes.json
M  scenarios/replay/weak-oracle/bundle.json
M  tests/test_modules.py
```

**ec90b19** (`fix(ci): normalize CRLF→LF in source hash checks`):
```
M  backend/cavr/sandbox.py
M  backend/satra/pytest_runner.py
M  scenarios/laboratory_hashes.json
```

### Ownership Audit Table

| Commit | File | N4 Owner | Change | Classification |
|---|---|---|---|---|
| fb6e8c7 | `backend/cavr/lab_harness.py` | **CAVR** | Added try/except around `import resource` | (b) Platform workaround — **UNAUTHORIZED** |
| fb6e8c7 | `backend/satra/runner_entry.py` | SATRA ✓ | Same try/except for resource | (b) Platform workaround — authorized |
| fb6e8c7 | `backend/satra/security_contract.py` | SATRA ✓ | `build()` returns None if SRS lacks keywords; adds `expected_status` | (a) Genuine fix — authorized |
| fb6e8c7 | `backend/satra/test_validator.py` | SATRA ✓ | `preflight()` rejects vacuous asserts; `killed()` ignores import errors | Requires review — see note below |
| fb6e8c7 | `scenarios/laboratory_hashes.json` | **Shared** | Added CAVR canary hashes | **UNAUTHORIZED** — outside N4 |
| fb6e8c7 | `scenarios/replay/weak-oracle/bundle.json` | **Shared** | Updated bundle digests | **UNAUTHORIZED** — outside N4 |
| fb6e8c7 | `tests/test_modules.py` | **Shared** | Changed assertion to accept both STRACE and PYTHON_AUDIT | **UNAUTHORIZED** — outside N4 |
| ec90b19 | `backend/cavr/sandbox.py` | **CAVR** | Added `_lf_digest` for cavr_sources hash check | **UNAUTHORIZED** — outside N4 |
| ec90b19 | `backend/satra/pytest_runner.py` | SATRA ✓ | Added `_lf_digest` for permitted_builtin | (a) Genuine root-cause fix — authorized |
| ec90b19 | `scenarios/laboratory_hashes.json` | **Shared** | Regenerated all LF-normalized hashes | **UNAUTHORIZED** — outside N4 |

### Notes on `test_validator.py` changes

- **`preflight()` rejecting `assert True/False/0/1`**: This is a tightening, not a loosening — it makes the validator stricter. Classify as **(a) genuine fix**, authorized.
- **`killed()` ignoring import/setup errors**: This changes what counts as a "mutation kill." If a test crashes at import rather than running, the mutation is NOT considered killed. This is a semantic change. **Requires your review** — it could mask genuine infrastructure failures. Classify as **(b) platform workaround, potentially loosening** until you review it.

### Notes on `security_contract.build()` returning None

- Original: always returned a contract (even if SRS was blank)
- New: returns `None` when SRS lacks invoice/ownership keywords → SATRA returns INCONCLUSIVE
- This is **stricter** (more INCONCLUSIVE, not fewer). Classify as **(a) genuine fix**, authorized.

---

## A7 — Claimed "Windows-Only" Failures Verified in WSL Ubuntu

**Command used:** `/tmp/satra-venv/bin/python -m pytest <test> -v --tb=short` (Python 3.14.4 in WSL)

| Test | Claimed | Actual in WSL | Verdict |
|---|---|---|---|
| `test_snapshot_rejects_symlinks_and_cache_tampering` | "Windows-only: WinError 1314" | **PASSED** in WSL | Claim was correct: it fails on Windows (no symlink privilege), passes on Linux |
| `test_tier1_rules_against_seed_repos` | "Windows-only: bash not available" | **FAILED** in WSL — `AssertionError: assert 'INCONCLUSIVE' == 'SATISFIED'` | **Claim was WRONG.** This test fails in WSL too, but for a different reason: `verdict == 'INCONCLUSIVE'` not `'SATISFIED'`. The bash subprocess ran, but the analysis produced the wrong verdict. |

> `test_tier1_rules_against_seed_repos` was **incorrectly dismissed** as "Windows-only." It is a **real failure on Linux** caused by a different issue: the seed-rule verdict is `INCONCLUSIVE` instead of `SATISFIED`. This is likely related to the master PR #3 (`fix/satra-seed-rules`) not being merged into `satra-feature` — the `seed_rules.py` file added in that PR does not exist on `satra-feature`.

---

## A8 — Final Summary

### What is stuck

1. **CI never runs on `satra-feature`** — no `.github/workflows/ci.yml` on that branch
2. **`test_tier1_rules_against_seed_repos` fails on Linux** (INCONCLUSIVE verdict, not bash absence)
3. **Unauthorized changes exist** in 5 files outside SATRA N4 ownership boundary that must be reviewed and possibly reverted
4. **Working copy is on Windows filesystem** (`/mnt/c/...`) — not in WSL Linux filesystem as required by N3

### Why (evidence)

1. **No workflow on branch:** `git ls-tree -r origin/satra-feature --name-only | grep .github` → empty. GitHub API confirms 0 runs on `satra-feature`.
2. **Test failure:** WSL run output shows `AssertionError: 'INCONCLUSIVE' == 'SATISFIED'`. Most likely cause: `backend/satra/seed_rules.py` (added in master PR #3) is absent from `satra-feature`, causing dictionary lookup to fall back to INCONCLUSIVE.
3. **Unauthorized changes:** `git diff-tree --no-commit-id -r --name-status fb6e8c7 ec90b19` shows CAVR and shared files were modified.
4. **Repo location:** `pwd` in WSL returns `/mnt/c/Users/Administrator/Desktop/Mid`.

### What the previous agent did that you must review

| Item | File | Risk |
|---|---|---|
| Added `try/except (ImportError,ValueError)` for `resource` | `backend/cavr/lab_harness.py` | CAVR file — needs CAVR teammate review |
| Added `_lf_digest` for `cavr_sources` pinned check | `backend/cavr/sandbox.py` | CAVR file — needs CAVR teammate review |
| Changed assertion to accept `STRACE` or `PYTHON_AUDIT` | `tests/test_modules.py` | Shared file — widens accepted values, needs review |
| Updated `scenarios/laboratory_hashes.json` (twice) | shared/scenarios | Pin change — must be justified and approved |
| Updated `scenarios/replay/weak-oracle/bundle.json` | shared/scenarios | Digest change — must be justified and approved |
| Changed `killed()` to ignore import errors | `backend/satra/test_validator.py` | SATRA but changes mutation-kill semantics — review |

### Decisions I need from you

1. **Unauthorized files in fb6e8c7 and ec90b19** (`backend/cavr/lab_harness.py`, `backend/cavr/sandbox.py`, `scenarios/laboratory_hashes.json`, `scenarios/replay/weak-oracle/bundle.json`, `tests/test_modules.py`): **Should I prepare reverts for each, or do you approve any of them?**

2. **`test_validator.killed()` change**: Do you accept the change that makes import-crash failures NOT count as mutation kills?

3. **Move working copy to WSL Linux filesystem?** Required by N3 for CI parity — `git clone` fresh into `~/projects/Working-POC` in WSL.

4. **Merge master into satra-feature?** Master has `seed_rules.py` and `satra_rules.py` changes (PR #3) that appear needed to fix `test_tier1_rules_against_seed_repos`. Should I merge master into satra-feature (Phase D)?

5. **Create `.github/workflows/satra-ci.yml`?** This is the only way to make CI run on the branch (Phase E).

6. **`gh` CLI install?** It is not present. `gh auth login` is needed for Phase E proof commands. Do you want to install it (`sudo apt-get install gh` in WSL)?

---

*Stopping here. Awaiting your "continue" with decisions on the above.*
