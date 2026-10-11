# CAVR Handoff & Cross-Platform Hash Alignment

**Date:** 2026-10-11  
**From:** SATRA Workstream  
**To:** CAVR Workstream  
**Status:** Shared File Alignment & Recommendations

---

## 1. Context & Motivation

During cross-platform testing (Windows development environments vs. Linux CI runners), divergence was observed in hash verification across files:
1. `scenarios/laboratory_hashes.json` stores SHA-256 hashes of inert sample code (`python_sources` and `cavr_sources`).
2. When repositories are cloned on Windows with default `core.autocrlf=true`, text files are checked out with `CRLF` line endings.
3. Because SHA-256 computes hashes over raw bytes, `CRLF` files produce different digests than `LF` files, causing `backend/cavr/sandbox.py` host execution fallback to reject genuine inert sample fixtures (`available: False`).

In previous commits on `satra-feature` (`fb6e8c7` and `ec90b19`), workaround changes were introduced into shared and CAVR files:
- `backend/cavr/lab_harness.py`
- `backend/cavr/sandbox.py`
- `scenarios/laboratory_hashes.json`
- `scenarios/replay/weak-oracle/bundle.json`
- `tests/test_modules.py`

Per team boundary rules (N4), **all 5 shared/CAVR files have been reverted to `origin/master`**.

---

## 2. Proposed Permanent Fix for CAVR Workstream

Instead of having Python code dynamically strip `\r\n` or having divergent hash lists, the root cause should be fixed at the repository git level:

### Step 1: Add `.gitattributes` to enforce LF on all Python fixtures and scenarios
Create `.gitattributes` at repository root:
```gitattributes
# Ensure consistent line endings across all platforms (Windows, macOS, Linux)
*.py text eol=lf
*.json text eol=lf
*.md text eol=lf
*.sh text eol=lf
```

### Step 2: Regenerate `scenarios/laboratory_hashes.json` Once
Once `.gitattributes` is active, re-normalize and compute the SHA-256 digests of all inert sources with `eol=lf`:
```bash
git add --renormalize .
# Verify hashes with LF digests
```

### Step 3: Container Volume Permissions
In `backend/cavr/sandbox.py`, when invoking `docker run` on Linux/WSL environments where Docker Desktop is used, ensure the container user UID matches the host user (`-u $(id -u):$(id -g)`) or that output directories mounted read-write (`/out:rw`) have permissive write access for the container's execution user.

---

## 3. Current Status
- All CAVR and shared files remain identical to `origin/master`.
- SATRA module uses internal LF normalization in `backend/satra/pytest_runner.py` for its own verification, which is backward-compatible with master's `scenarios/laboratory_hashes.json`.
- All SATRA tests (75/75) pass cleanly in Linux.
