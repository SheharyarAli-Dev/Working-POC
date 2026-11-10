# ASENT SABLE — Phase 6: Mutation Demonstration Evidence (Continuation Record)

**Date**: November 9, 2026 (post-Phase 5 continuation)
**Owner**: Muhammad Ali Sajjad (23I-0110), SABLE module
**Context**: Continuation of `reports/SABLE_PHASE5_INDEPENDENT_VERIFICATION.md`. This record closes Phase 5's top outstanding item: *target-application mutation demonstration (clean refactor vs. privilege regression)*.

---

## 1. What was performed

The two SABLE-relevant mutation experiments that Phase 5 listed as outstanding were executed against a **disposable local clone** of the public target application `asent-target-flask`. The pre-existing clone at `<original-target-clone>` (which holds the recorded baseline evidence) was **not modified**; a fresh clone was created at `<disposable-target-clone>`, and all mutations were committed on two local branches:

- **`demo-sable-refactor`** (commit `e10db46`): logical rename of the bucket resource address `aws_s3_bucket.user_uploads` → `aws_s3_bucket.uploads` in `infra/main.tf`, with all references updated (public access block, policy resource interpolation, output) and an explicit `moved { from = aws_s3_bucket.user_uploads; to = aws_s3_bucket.uploads }` block added in `infra/moved.tf`. The **physical bucket identity is unchanged** (`var.uploads_bucket_name` / default `flask-backend-user-uploads`). This mirrors the supported catalog fixture shape (`rename_with_moved`).
- **`demo-sable-regression`** (commit `e3fb8ac`): the same refactor plus privilege widening — the inline policy's `Action` list `["s3:GetObject", "s3:PutObject"]` replaced by `["s3:*"]`.

Gate authority remained the base commit `e0a1766124ac90cbeafeb87b1fafa39c156925b0` (`main`), which carries the SABLE obligation `user-uploads-least-privilege` (principal `aws_iam_role.app`, protected asset `aws_s3_bucket.user_uploads`, actions GetObject+PutObject, scope objects, min score 6, margin 3).

## 2. Exact commands

```
wsl -d Ubuntu -e bash <temp-script>/sable_mutation_demo.sh   # clone + commits
cd <repository-root>
<python-environment> -m backend.cli gate \
  --repository <disposable-target-clone> \
  --base main --head demo-sable-refactor \
  --output-dir <local-run-directory>/gate-flask-mutation-safe-out        # exit code: 2
<python-environment> -m backend.cli gate \
  --repository <disposable-target-clone> \
  --base main --head demo-sable-regression \
  --output-dir <local-run-directory>/gate-flask-mutation-regressed-out   # exit code: 1
```

(Stage-set confirmation: the script printed `demo-sable-refactor` at one commit ahead of `main`; `demo-sable-regression` at two.)

## 3. Results

| Case | Head | Overall gate | Exit code | CAVR | SATRA | SABLE |
|---|---|---|---|---|---|---|
| Clean refactor | `demo-sable-refactor` (`e10db46`) | **REVIEW** | 2 | pass / VERIFIED | review / INCONCLUSIVE | **pass / PRESERVED** — "Every registered obligation is preserved" |
| Privilege regression | `demo-sable-regression` (`e3fb8ac`) | **BLOCK** | 1 | pass / VERIFIED | review / INCONCLUSIVE | **block / REGRESSED** — "user-uploads-least-privilege: REGRESSED: Missing, widened or misbound role-to-asset authorization" |

Evidence artifacts (inspectable, with per-module evidence IDs and `changed_surfaces` = `infra/main.tf`, `infra/moved.tf` recorded in `asent.assurance.v1`):

- `<local-run-directory>/gate-flask-mutation-safe-out/asent-summary.md` and `asent-report.json`
- `<local-run-directory>/gate-flask-mutation-regressed-out/asent-summary.md` and `asent-report.json`

## 4. Honest interpretation and limitations

- **What is proven**: On a real, non-fixture target application, SABLE (a) attributed the renamed bucket's obligation to the correct successor through the explicit `moved` block + physical identity (verdict PRESERVED), and (b) failed closed and detected the `s3:*` widening (verdict REGRESSED), which the shared gate escalated to a BLOCK decision with the SABLE reason surfaced.
- **What is NOT claimed**: The clean-refactor case produced an overall **REVIEW**, not ACCEPT (exit 0), because SATRA's runner image (`asent-satra-runner:local`) is unavailable in this environment (no Docker image built). Phase 5's hypothesis ("clean move → ACCEPT exit 0") is therefore **not verified in this environment**; when SATRA is unavailable, REVIEW is the correct fail-safe outcome and SABLE's PRESERVED verdict is still independently visible in the module row. An ACCEPT exit-0 result on the clean case additionally requires a SATRA-capable environment (or a configuration in which SATRA is not applicable for the changed surface).
- The regression experiment was performed on a disposable clone only; no remote was pushed, `asent-target-flask` on GitHub and the recorded evidence clone were untouched.
- These runs are local reproductions by the module author; they do not constitute independent review.
