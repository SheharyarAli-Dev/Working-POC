# Phase 7 Walkthrough: Ollama LLM Integration, 7-Check Validator, & JUnit Classification

**Primary Files:** `backend/satra/ollama_adapter.py`, `backend/satra/test_validator.py`, `tests/test_satra_ollama_and_validator.py`

---

## 1. Plain English Analogy
Imagine an airport customs screening checkpoint. A traveler arrives with a proposed security test. 
- You do not trust the traveler simply because they speak fluently (LLM fluency).
- First, the baggage scanner checks for prohibited contraband like hidden explosives or fake IDs (`preflight()` syntax and vocabulary check: no `eval`, `open`, or vacuous `assert True`).
- Next, you test the passenger's credentials against a legitimate passport (`is_pass(baseline)`: the test must pass on secure code).
- Then, you test their alarm response against a known simulated intrusion (`killed(mutant)`: when an unauthorized IDOR bypass mutant is introduced, the test must actively sound the alarm with an assertion failure). If the scanner broke down during setup (an `ImportError` or `<error>`), that does **not** count as catching the intruder!
- Finally, you re-verify the check to ensure it wasn't a fluke (`is_pass(repeat)`).

---

## 2. Function-by-Function Explanation

### `preflight(source: str) -> tuple[bool, str]`
- **Purpose:** Fast, safe AST-level static analysis before any candidate code is executed.
- **How it works:**
  - Parses code with Python's native `ast.parse()`.
  - Enforces vocabulary boundaries: only permitted imports (`pytest`).
  - Blocks dangerous execution sinks (`eval`, `exec`, `open`, `compile`, `getattr`, `__import__`).
  - **Vacuous Assertion Elimination:** Rejects constant assertions (`assert True`, `assert 1`, `assert False`, `assert 0`, `assert ""`). A test asserting `True` cannot discriminate secure from insecure behavior.

### `is_pass(result: dict) -> bool`
- **Purpose:** Confirms that a test run passed completely without warnings, skips, or errors.
- **Criteria:** `available == True`, `exit_code == 0`, `passed > 0`, `skipped == 0`, `errors == 0`.

### `killed(result: dict) -> bool`
- **Purpose:** Distinguishes genuine mutant kills from infrastructure or environment crashes.
- **JUnit XML Element Classification:**
  - Instead of fragile string matching on error text, inspects the JUnit XML status:
  - `<failure>` (test status `"FAIL"`): The test executed and its security assertion failed because the mutant bypassed security. This is a **valid kill**.
  - `<error>` (test status `"ERROR"`): The test crashed during module import, fixture setup, or collection (e.g. `ModuleNotFoundError`). This is an infrastructure error, **not a kill**.
  - If all non-passing tests have status `"ERROR"`, `killed()` returns `False`.

### `judge(baseline: dict, mutant: dict, repeat: dict, feasible: bool) -> dict`
- **Purpose:** Synthesizes the final verdict for an adaptive test.
- **Verdicts:**
  - If mutant is killed (`killed(mutant) == True`): Returns `PRESERVED_WITHIN_MODEL`.
  - If mutant passes (`is_pass(mutant) == True`): Returns `ORACLE_WEAKENED` (the test failed to catch the breach).
  - If mutant crashed with infrastructure error: Returns `INCONCLUSIVE` (`reason: "Execution failure is not a mutant kill"`). It **never** returns `PRESERVED_WITHIN_MODEL`.

### `validate_generated_test(test_code, contract, ...) -> dict`
- **Purpose:** Orchestrates the full 7-check pipeline for generated tests.

---

## 3. Worked Defense Example

**Scenario:** An LLM generates a candidate test for an invoice endpoint:
```python
def test_invoice_access(client):
    resp = client.get("/invoices/2")
    assert resp.status_code in [200, 403]
```

**Evaluation Step-by-Step:**
1. `preflight()` passes syntax check.
2. `check_static_test_integrity()` flags `ASSERTION_WEAKENED`: The assertion broadened to accept HTTP 200 (insecure data leak) alongside HTTP 403.
3. The validator immediately rejects the test at Step 3 (`failing_check: 3`), preventing a weakened oracle from slipping into the test suite.
