# SABLE Independent Review Handoff — Dataset `sable-independent-oracle-v1`

**Status: AWAITING INDEPENDENT HUMAN REVIEW — all six cases are `UNREVIEWED` and every metric is `UNMEASURED`.**
Nothing in SABLE marks these cases reviewed; only the signed attestation returned below can change them (`backend/sable/research_eval.py::validate_dataset`, lines 138-155: `REVIEWED` is accepted **only** when reviewer name, date, successor, outcome and rationale are all filled).

## What the reviewer must do

For each of the six cases in **`reports/SABLE_INDEPENDENT_REVIEW_PACKAGE.json`**:

1. Read the case's `baseline_tf` and `candidate_tf` (exact raw Terraform) and the `obligation` (principal, protected asset, required actions, scope).
2. **Independently** decide, from the Terraform alone:
   - whether the protected logical asset (the S3 bucket) has a unique logical successor in the candidate;
   - whether the candidate IAM policy still satisfies the least-privilege obligation (identical actions bound to the same logical asset);
   - whether the honest outcome is `PRESERVED`, `REGRESSED` or `UNKNOWN`.
3. Do **not** look at SABLE's own verdict for the case before deciding. The package deliberately includes no predictor output. (Run-order disclosure: case IDs are scenario names; SABLE's stored predictions for these six cases currently exist in `backend/sable/research_eval.py:: CASES` rationale strings as *authored expectations* — they are authorship, not review, and are shown under `authored_expectation`.)

## How to return the review

Fill in for every case:

```json
"independent_attestation_template": {
  "review_status": "REVIEWED",
  "reviewer": "<real name, title, institution>",
  "reviewed_at": "<YYYY-MM-DD>",
  "reviewed_successor": "<e.g. aws_s3_bucket.cdata, or null>",
  "reviewed_outcome": "<PRESERVED | REGRESSED | UNKNOWN>",
  "reviewed_rationale": "<technical reasoning: which evidence establishes or refuses the successor, and which policy facts establish or refuse least-privilege preservation>"
}
```

Return the completed JSON to the SABLE owner (Muhammad Ali Sajjad, 23I-0110) for entry into
`backend/sable/research_eval.py::CASES`. `validate_dataset()` refuses any incomplete attestation, and
`run_experiment()` refuses to compute any metric until **all six** cases are `REVIEWED`
(`_metric_status`), so partial returns cannot be presented as measurements.

## Review criteria (from `REVIEW_PROTOCOL` in the same module)

- The reviewer must not be an author or contributor of SABLE code.
- The reviewer inspects the raw baseline and candidate Terraform independently.
- The reviewer independently determines successor existence and obligation preservation.
- Every case needs explicit technical rationale.

## Comparator honesty (why metrics don't exist yet)

- **B4** is classified `INTERNAL_ABLATION_COMPOSITE` with `REUSES_SABLE_CORE`: it shares SABLE's parser, correspondence ranking and authorization engine. It must never be described as an independent comparator. Only `independent_moved_only` is `INDEPENDENT_BASELINE` / `ZERO_SABLE_COUPLING`, and it cannot evaluate policy semantics (it can only predict PRESERVED/UNKNOWN from explicit `moved` blocks — never REGRESSED).
- Until the six signed attestations above are returned and integrated, the readiness check prints
  `Dataset 'sable-independent-oracle-v1': 0/6 cases reviewed` and all metric statuses remain `UNMEASURED`. That is the correct, honest state; do not represent it as complete evaluation.
