# SATRA CI Fix Log & Justification Record

**Date:** 2026-10-11  
**Module:** SATRA (Security Assurance Through Regenerative Assurance)  
**Author:** ASENT / SATRA Team

---

## 1. Summary of Changes in SATRA Workstream

All fixes below are strictly within SATRA ownership boundaries (`backend/satra/`, `tests/test_satra*.py`, `docs/satra/`). No shared or external files were modified.

---

## 2. Fix 1: Cross-Platform Line-Ending Normalization (`_lf_digest`) in `pytest_runner.py`

- **File:** `backend/satra/pytest_runner.py`
- **Rationale:** 
  In multi-developer environments where checkouts occur across Windows (defaulting to CRLF) and Linux (LF), raw byte SHA-256 hashes differ for identical source code. SATRA's `permitted_builtin` function validates candidate files against pinned hashes in `scenarios/laboratory_hashes.json`.
- **Implementation:**
  `_lf_digest(data: bytes)` normalizes `\r\n` to `\n` prior to computing SHA-256:
  ```python
  def _lf_digest(data: bytes) -> str:
      import hashlib
      return hashlib.sha256(data.replace(b'\r\n', b'\n')).hexdigest()
  ```
  On Linux, files already have `\n`, so `_lf_digest` is an exact no-op that matches existing pinned hashes. On Windows, it eliminates spurious rejection of unchanged test files.
- **Verification:** Unit tested in `tests/test_satra_ollama_and_validator.py::test_pytest_runner_lf_digest_cross_platform_invariance` (PASSED).

---

## 3. Fix 2: Unix Resource Limit Guard in `runner_entry.py`

- **File:** `backend/satra/runner_entry.py`
- **Rationale:**
  The Python standard library `resource` module is POSIX-only. On Windows, attempting to `import resource` raises `ImportError`, crashing test runners during local Windows development or debugging sessions.
- **Implementation:**
  ```python
  try:
      import resource
      resource.setrlimit(resource.RLIMIT_AS, (768*1024*1024, 768*1024*1024))
      resource.setrlimit(resource.RLIMIT_CPU, (30, 30))
      resource.setrlimit(resource.RLIMIT_FSIZE, (32*1024*1024, 32*1024*1024))
      resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
  except (ImportError, ValueError):
      pass  # resource limits unavailable on Windows; audit hook still enforces subprocess/network restrictions
  ```
  On Linux/CI/Docker, `resource` is present and all hard limits are fully enforced. On Windows, execution safely proceeds while the mandatory Python audit hook (`sys.addaudithook`) continues to block network (`socket.connect`) and subprocess spawning.
- **Verification:** Tested on both Windows native Python and Ubuntu WSL2.

---

## 4. Fix 3: Mutation Kill Classification via JUnit XML Status (`killed` in `test_validator.py`)

- **File:** `backend/satra/test_validator.py`
- **Rationale:**
  Previously, distinguishing whether a mutant was "killed" by a test or simply crashed due to a broken test harness (e.g. missing import, syntax error, environment fault) relied on crude string matching against error messages.
- **Implementation:**
  Replaced string matching with standard JUnit XML element classification:
  - `<failure>` (mapped to test status `"FAIL"`) represents an assertion failure where the test executed and actively caught the mutation.
  - `<error>` (mapped to test status `"ERROR"`) represents an infrastructure/import/setup crash, which is **not** a valid mutation kill.
  - If every mutant produces infrastructure errors, `judge()` returns `INCONCLUSIVE`, never `PRESERVED_WITHIN_MODEL`.
- **Verification:** Unit tested in `tests/test_satra_ollama_and_validator.py::test_killed_distinguishes_error_vs_failure` (PASSED).

---

## 5. Fix 4: Vacuous Assertion Preflight Tightening

- **File:** `backend/satra/test_validator.py`
- **Rationale:**
  Trivial assertions such as `assert True`, `assert 1`, `assert False`, `assert 0`, or `assert ""` do not discriminate secure from insecure behavior and must be rejected at preflight.
- **Implementation:**
  AST check inspects `n.test`:
  ```python
  if isinstance(n, ast.Assert):
      if isinstance(n.test, ast.Constant) and n.test.value in (True, False, 1, 0, "", None):
          return False, "Vacuous assertion cannot discriminate secure from insecure behaviour"
      rendered = ast.unparse(n.test)
      if rendered in ("True", "1", "False", "0"):
          return False, "Vacuous assertion cannot discriminate secure from insecure behaviour"
  ```
- **Verification:** Unit tested in `tests/test_satra_ollama_and_validator.py::test_preflight_rejects_vacuous_assertions` (PASSED).

---

## 6. Fix 5: Missing Security Contract Handling

- **File:** `backend/satra/security_contract.py` & `backend/satra/analyzer.py`
- **Rationale:**
  When a candidate repository SRS lacks keywords representing InvoiceHub ownership/authorization invariants, `build(context)` returns `None`.
- **Behavior:**
  SATRA analyzer explicitly produces `verdict = "INCONCLUSIVE"` (with reason `"No independently supported InvoiceHub security contract"`), and **never** reports `NOT_APPLICABLE` (since Python files are present, making SATRA applicable).
- **Verification:** Unit tested in `tests/test_satra_ollama_and_validator.py::test_missing_contract_produces_inconclusive_never_not_applicable` (PASSED).
