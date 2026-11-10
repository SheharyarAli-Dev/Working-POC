# SABLE Author-Review Evidence (HUMAN AUTHOR-REVIEW) — 2026-11-10

**Document class:** HUMAN AUTHOR-REVIEW evidence record (NOT independent external validation)
**Dataset:** `sable-independent-oracle-v1` (see `reports/SABLE_INDEPENDENT_REVIEW_PACKAGE.json`)
**Date of review:** 2026-11-10
**Reviewer:** Muhammad Ali Sajjad (GitHub: `muhammadalisajjad-dev`)
**Reviewer role:** AUTHOR / CONTRIBUTOR to SABLE (owned SABLE implementation and delivery, PR #18, merged as `05a4bea`)

## Required disclosure

- The reviewer is a **SABLE author/contributor**. This review is recorded as **provenance only** and is **NOT independent external validation** of the SABLE oracle.
- The independent-review attestation fields inside `reports/SABLE_INDEPENDENT_REVIEW_PACKAGE.json`
  remain **`UNREVIEWED`** and were **not modified** to mark these six cases as independently reviewed.
- This record does **not** claim 6/6 independent reviews; the independent review status remains
  **0/6 INDEPENDENT** and PENDING (`current_status: PENDING_INDEPENDENT_REVIEW`).
- All precision/recall/correspondence metrics remain **UNMEASURED**. No metrics were recalculated
  from this author-review.
- AI-assisted test execution was used only to retrieve the deterministic engine outputs quoted
  below; the engine outputs are observations, not reviewer conclusions.

## Review method

The reviewer explicitly re-examined all six benchmark cases on 2026-11-10 and agreed with all six
authored case assessments (outcomes and successor attributions below). Technical rationale for each
case is recorded here verbatim as the reviewer's accepted reasoning, cross-checked against the
deterministic engine output recorded in this document.

## Agreed case assessments (author-review)

| # | Scenario | Outcome (author-review) | Successor (author-review) |
|---|---|---|---|
| 1 | `rename_with_moved` | PRESERVED | `aws_s3_bucket.cdata` |
| 2 | `split_to_two` | UNKNOWN | unresolved (`null`) |
| 3 | `resource_wildened` | REGRESSED | `aws_s3_bucket.customer_data` |
| 4 | `wrong_binding_regressed` | REGRESSED | unresolved (`null`) |
| 5 | `ambiguous_set_three_candidates` | UNKNOWN | unresolved (`null`) |
| 6 | `replacement_wrong_bucket` | UNKNOWN | unresolved (`null`) |

### 1. `rename_with_moved` — PRESERVED, successor `aws_s3_bucket.cdata`

**Technical rationale.** The candidate contains an explicit Terraform `moved {}` block mapping the
protected bucket address `aws_s3_bucket.customer_data` to `aws_s3_bucket.cdata`. Physical bucket
identity (`customer-data`) is retained, and the IAM policy statement is updated to target the moved
address with the same least-privilege scope (`s3:GetObject`, `s3:PutObject` on `arn:aws:s3:::customer-data/*`).
Logical asset continuity is uniquely and explicitly established, so the obligation survives the
refactor: PRESERVED on a unique resolved successor.

**Engine observation (recorded, not a reviewer conclusion):** engine verdict PRESERVED with reason
"Exact modeled least privilege holds (within supported IAM/S3 subset)". Engine agrees.

### 2. `split_to_two` — UNKNOWN, successor unresolved

**Technical rationale.** The protected bucket is split into `customer_data_hot` and
`customer_data_cold`. Two candidate successors each hold plausible logical kinship, and the case
provides no rule that selects a unique logical successor (no `moved {}`, no unique tag, and the
obligation scope is divided). Because least-privilege obligation preservation cannot be attributed
to either half, the honest verdict is UNKNOWN, not PRESERVED.

**Engine observation:** engine verdict UNKNOWN, reason "Successor scores are too close for a unique
attribution". Engine agrees.

### 3. `resource_wildened` — REGRESSED, successor `aws_s3_bucket.customer_data`

**Technical rationale.** The original logical bucket remains present and unrenamed, so the unique
successor is the resource itself. The IAM policy keeps the required actions but the resource scope
is widened from the bucket-specific scope to `*`. This widens the authorization beyond the protected
asset: REGRESSED on a clearly resolved successor.

**Engine observation:** engine verdict REGRESSED ("Widening: resource scope exceeds the protected
asset"). Engine agrees.

### 4. `wrong_binding_regressed` — REGRESSED, successor unresolved

**Technical rationale.** The protected address `aws_s3_bucket.customer_data` is gone in the
candidate. The candidate policy re-binds the *exact* required action set
(`s3:GetObject`, `s3:PutObject` for `aws_iam_role.app`) to `aws_s3_bucket.logs_bucket`, a bucket
whose stable asset tag (`Asset = "logs"`) is semantically incompatible with the customer-data
obligation. A distractor bucket `aws_s3_bucket.customer_data_new` (`Asset = "customer-data-new"`,
different bucket name, different tag) exists but is **not** referenced by the policy. Together:
the authorization obligation is **clearly violated** (the required grant now protects a wrong,
unrelated asset), even though no residual continuity evidence is strong enough to declare
`customer_data_new` the logical successor. Therefore: **REGRESSED with unresolved successor
(`null`)**. The wrong binding and the unresolved successor are distinct facts and both are true.

**Engine observation:** engine verdict UNKNOWN, reason "No successor reaches the fixed confidence
threshold" (two hypotheses `logs_bucket` (score 3, policy-referenced) and `customer_data_new`
(score 3, unreferenced), both below the fixed threshold). See the engine audit section below for the
full discrepancy analysis, comparator outputs, and the proposed fix. The outcome REGRESSED is
retained by author-review and by the oracle; the successor is `null`.

### 5. `ambiguous_set_three_candidates` — UNKNOWN, successor unresolved

**Technical rationale.** Three S3 buckets carry the same `Asset = "candidate"`-family tagging and
stage with equal correspondence scores; no uniqueness evidence (no `moved {}`, no distinguishing
reference, no distinct physical identity) selects one. Successor attribution is impossible from the
case: UNKNOWN.

**Engine observation:** engine verdict UNKNOWN, reason "Successor scores are too close for a unique
attribution". Engine agrees.

### 6. `replacement_wrong_bucket` — UNKNOWN, successor unresolved

**Technical rationale.** The candidate replaces the protected bucket with
`aws_s3_bucket.new_storage` (`bucket = "new-application-storage"`, `Asset = "new-storage"`), which
has different physical identity from the protected bucket and no `moved {}`, no matching tag, and no
application reference evidence establishing it as the successor. The intended successor cannot be
established from the case materials: UNKNOWN. The engine's binding of the policy to `new_storage`
leaves the logical successor attribution open rather than provably wrong (contrast with case 4,
where the binding target is categorically incompatible with the obligation).

**Engine observation:** engine verdict UNKNOWN, reason "No successor reaches the fixed confidence
threshold". Engine agrees.

## Engine audit for `wrong_binding_regressed` (Task B — recorded honestly)

The audit found a genuine semantic discrepancy between the oracle/human expectation (REGRESSED) and
the current engine output (UNKNOWN):

| Evaluator | Verdict on `wrong_binding_regressed` | Reason |
|---|---|---|
| SABLE engine (correspondence-gated) | **UNKNOWN** | "No successor reaches the fixed confidence threshold" |
| B0 candidate-only | UNKNOWN | "Asset 'aws_s3_bucket.customer_data' not found in model" |
| B1 before/after | UNKNOWN | Added [], removed ['s3:GetObject', 's3:PutObject'] |
| B2 moved-only (SABLE) | UNKNOWN | "No moved block evidence for this asset" |
| B3 (SABLE) | UNKNOWN | "No successor reaches the fixed confidence threshold" |
| B4 composite ablation | UNKNOWN | (composite of the above) |
| `independent_moved_only` | UNKNOWN | "No unique explicit moved-block target; policy and authorization are not checked." |

**Root cause.** The shared verdict layer is successor-first: when the protected asset is absent from
the candidate and no unique successor can be resolved (two hypotheses at score 3, threshold higher),
every evaluator fails closed to UNKNOWN. The activation evidence for REGRESSED — the required
actions re-bound to a wrong, categorically incompatible asset (`Asset = "logs"` for a customer-data
obligation) — is real but is not consumed by the misbinding verdict logic in this unresolved-successor
situation.

**What was NOT changed.**
- The oracle outcome for this case **remains REGRESSED** (`fixtures/ground_truth.py` untouched).
- The engine and comparators were **not modified**; no security semantics were loosened.
- `backend/threat_repo` (sable_rules) was not touched.

**Correction applied in this task (metadata only).** The oracle's
`wrong_binding_regressed.authored_expectation.expected_successor` previously claimed
`aws_s3_bucket.customer_data_new`. There is no continuity evidence for that address (different
bucket name `customer-data-new`, different tag `customer-data-new`, no `moved {}`, and the policy
does not reference it), so claiming it as the *expected* successor was an over-attribution. The
oracle now records `expected_successor: null` (unresolved), outcome unchanged at REGRESSED, with an
updated rationale. A focused regression test pins this.

**Proposed smallest defensible engine fix (NOT implemented in this task; requires owner review).**
Extend the analyzer verdict layer with a misbinding amendment that fires **only** when all of the
following hold:
1. successor resolution has already failed closed (no unique successor), and
2. the candidate's principal policy binds the exact required action set to a resource whose stable
   `Asset` tag is present and categorically contradicts the protected asset's tag family
   (e.g., `Asset = "logs"` vs a customer-data obligation), and
3. a candidate bucket carrying the protected asset's own tag family exists but is policy-unbound
   (the distractor), strengthening that the binding itself went wrong rather than being an intended
   replacement; and
4. no continuity evidence (`moved {}`, matching tag, application reference) connects the misbound
   resource to the protected asset (which would point to an intended successor instead).

Verdict under this rule: REGRESSED with `successor: null` and a reason naming the misbound resource.
This preserves the distinction required by the review protocol: an unresolved-successor UNKNOWN stays
UNKNOWN (case 6), while a *clearly violated authorization obligation* is REGRESSED even without a
resolved successor (case 4). It does not claim repair, does not fabricate a successor, and stays
within the supported IAM/S3 subset (fails closed to UNKNOWN whenever the discriminator evidence is
absent). It must never be used to raise `false_safe_rate` defenses.

## Review-tier status after this record (Task C)

| Tier | Status | Feeds metrics? |
|---|---|---|
| Independent human review | **0/6** completed; protocol PENDING | Yes (only this tier) |
| HUMAN AUTHOR-REVIEW (this document) | 6/6 recorded by an author/contributor | **No — provenance only** |
| AI-assisted evaluation (engine outputs) | Recorded as observations above | **No** |

`backend/sable/research_eval.py`'s `REVIEW_PROTOCOL` now records these tiers explicitly (with
`may_feed_metrics` flags), and the evaluation tooling continues to refuse metrics without a completed
*independent* review attestation (`test_experiment_refuses_metrics_without_external_review`).
