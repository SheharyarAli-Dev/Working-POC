# SATRA-RV Merge Readiness Checklist

**Branch:** `satra-feature`  
**Target:** `origin/master`  
**Policy Note:** *The engineering owner decides when to merge into master. Antigravity will NOT merge automatically.*

---

## 1. Readiness Gate Verification

| Check | Requirement | Current Status | Evidence / Verification |
|---|---|---|---|
| **Gate 1: Test Suite & CI** | 100% green on SATRA suite | **READY** ✅ | 83/83 passed in WSL (`0:03:21`), `.github/workflows/satra-ci.yml` committed. |
| **Gate 2: Conflict Resolution** | Clean merge from `origin/master` | **READY** ✅ | Merged `origin/master` (commit `7d4de6e`) with 0 merge conflicts. |
| **Gate 3: Boundary Isolation** | No unauthorized edits in CAVR/SABLE/shared | **READY** ✅ | All 5 shared/CAVR files reverted to `origin/master` (commits `bc4c140`, `7dd9c07`, `7ef661c`, `798f032`, `c94d60d`). Zero shared diff. |
| **Gate 4: Cross-Platform Line Endings** | Line ending agreement across OS | **READY** ✅ | Normalization encapsulated in SATRA's `_lf_digest`. Formal handoff delivered in `docs/satra/handoff-cavr.md`. |
| **Gate 5: Traceability & Inventory** | Test inventory up to date and checked in CI | **READY** ✅ | `docs/satra/test-inventory.md` generated with 69 test functions; CI step enforces `--check`. |
| **Gate 6: Recommit Flow Hardening** | No `-f`, policy gates, audit trail | **READY** ✅ | Force push eliminated, human approval enforced, hash-chained `audit_trail.py` verified. |
| **Gate 7: Walkthroughs & Defense Prep** | Complete walkthrough docs for all phases | **READY** ✅ | Phases 1 through 10 walkthroughs written under `docs/satra/walkthrough/`. |
| **Gate 8: Release Tags** | Release and evaluation git tags | **READY** ✅ | Tags `proposal-poc` and `fyp1-mid` ready to be applied on final evaluation commit. |

---

## 2. Pre-Merge Verification Commands

Before merging `satra-feature` into `master`, run these verification commands in WSL:

```bash
# 1. Verify working tree is clean
git status

# 2. Verify diff against origin/master touches only SATRA-owned files
git diff origin/master --name-only | grep -v -E '^(backend/satra/|docs/satra/|tests/test_satra|scripts/satra|\.github/workflows/satra-ci\.yml|frontend/src/components/satra|frontend/src/components/SatraModule\.tsx)'

# 3. Verify all 83 tests pass
python -m pytest tests/test_satra*.py tests/test_api_replay.py -v

# 4. Verify test inventory is in sync
python scripts/satra_test_inventory.py --check
```

---

## 3. Merge Procedure (When Authorized by Owner)

```bash
# Checkout master and pull latest changes
git checkout master
git pull origin master

# Merge satra-feature with merge commit (not rebase, not squash)
git merge --no-ff satra-feature -m "Merge branch 'satra-feature' into master (SATRA-RV Phase 1-11)"

# Tag evaluation milestone
git tag -a fyp1-mid -m "FYP-1 Mid Evaluation: SATRA-RV Engine Complete and Verified"

# Push to remote
git push origin master --tags
```
