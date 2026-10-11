# Phase 10 Walkthrough: Verified Recommit Flow, Policy Gating, & Append-Only Audit Trail

**Primary Files:** `backend/satra/recommit.py`, `backend/satra/audit_trail.py`, `tests/test_satra_recommit.py`

---

## 1. Plain English Analogy
Think of a bank vault transaction ledger:
- When a teller processes an authorized deposit, they stamp the receipt with explicit metadata (the run ID, operator name, timestamp: `prepare_trailer_tagged_commit_message`). Notice this is an official ledger stamp (trailer tag), **not** an electronic cryptographic signature (GPG). Calling it a "signed commit" without a cryptographic key would be false.
- If the vault door opens to deposit money into a safe (`git push`), the teller must verify:
  1. We are not running a drill or simulation (`PYTEST_CURRENT_TEST` is unset).
  2. The vault manager explicitly turned on the transfer switch (`SATRA_ALLOW_PUSH=1`).
  3. The branch is a registered account (`allowlist` check).
  4. A human supervisor signed the approval voucher (`approval_record`).
  5. The transfer uses standard delivery—**never force-clearing existing boxes** (no `-f` or `--force`).
- Every completed action is recorded in an immutable bound ledger (`AuditTrail`). Each row contains the cryptographic SHA-256 hash of the previous row. If anyone tears out a page or alters a digit later, the hash chain breaks instantly, alerting the auditors.

---

## 2. Function-by-Function Explanation

### `prepare_trailer_tagged_commit_message(msg, run_id, approved_by, approved_at) -> str`
- **Purpose:** Formats standard Git commit messages with structured audit trailers.
- **Trailer Tags Included:**
  - `ASENT-Verified-By: SATRA-RV`
  - `ASENT-Run-ID: <run_id>`
  - `ASENT-Approved-By: <operator>`
  - `ASENT-Approved-At: <timestamp>`
- **Honesty Note:** Uses the term "trailer-tagged", never "signed", unless verified by `git verify-commit`.

### `get_unique_repair_branch_name(repo, base_sha, run_id) -> str`
- **Purpose:** Prevents accidental branch overwriting or destructive history manipulation.
- **How it works:**
  - Default candidate name is `satra/repair/<sha7>`.
  - Queries local branches and `git ls-remote origin` for collisions.
  - If the branch already exists, it derives a unique name: `satra/repair/<sha7>-<run8>`.

### `push_repair_branch_if_allowed(repo_dir, branch_name, settings, approval_record) -> dict`
- **Purpose:** The final security gate before any network push to the remote forge.
- **Strict Verification Gates:**
  1. **Test Environment Guard:** If `PYTEST_CURRENT_TEST` is detected in the environment, push is blocked immediately.
  2. **Push Policy Flag:** `settings.push_enabled` must be True AND `os.environ["SATRA_ALLOW_PUSH"] == "1"`.
  3. **Human Approval:** `approval_record` must be non-null and `approval_record["approved"] == True`.
  4. **Allowlist:** Remote URL must match `settings.allowlist`.
  5. **No Force Push:** Invokes standard `git push -u origin branch_name` without `-f`.

### `AuditTrail.append(run_id, operator, action, branch, commit_sha, details) -> dict`
- **Purpose:** Writes an immutable record to `satra_audit.jsonl`.
- **Implementation:**
  - Opens the file in strict append mode (`"a"`).
  - Fetches `prev_hash` from the prior entry (or `0`*64 for genesis).
  - Computes `entry_hash = sha256(canonical_json(entry))`.
  - Calls `flush()` and `os.fsync()` to ensure persistent disk commitment.

### `AuditTrail.verify_chain() -> dict`
- **Purpose:** Validates the cryptographic integrity of the audit log.
- **Verification:** Recomputes every entry hash and confirms matching `prev_hash` linkages. Returns `valid: False` and identifies the exact tampered index if modified.

---

## 3. Worked Defense Example

**Scenario:** A human lead reviews run `run-repair-890` targeting commit `0ea2ab3`.
1. The lead clicks "Approve & Push" in the UI.
2. The API creates branch `satra/repair/0ea2ab3`.
3. If an earlier repair of `0ea2ab3` already exists on GitHub, `get_unique_repair_branch_name` detects the remote ref and creates `satra/repair/0ea2ab3-repair890`, leaving the existing repair intact.
4. `push_repair_branch_if_allowed` validates that `SATRA_ALLOW_PUSH=1` and that human approval was provided, executing a non-forced push.
5. `AuditTrail.append` logs entry #1 with `prev_hash` linking to entry #0.
6. When an audit inspection runs `trail.verify_chain()`, the chain validates as 100% integral.
