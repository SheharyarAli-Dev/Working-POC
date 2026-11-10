# ASENT — Final Technical Completion Audit (SABLE)

**Project**: ASENT — Integrated Security Assurance for AI-Assisted Software Development (F26-033-ASENT)
**Module owner**: Muhammad Ali Sajjad (23I-0110), FAST-NUCES Islamabad — SABLE (Terraform/IAM infrastructure security)
**Teammates**: Maryam Fatima (CAVR), Syed Sheharyar Ali (SATRA-RV)
**Date**: November 9, 2026
**Status**: technical completion audit for the final demonstration; distinguishes newly rerun evidence (2026-11-09) from historical phase reports.

> Claim discipline: items marked **[rerun today]** were executed during this session with exact commands and exit codes recorded in Section 3. Items marked **[historical]** come from earlier phase reports and were re-verified only where explicitly stated. Nothing here claims live AWS validation, Terraform `apply`, automatic repair, universal Terraform/IAM coverage, or calibrated probabilities. Ambiguous or unsupported SABLE inputs remain UNKNOWN/REVIEW by design.

---

## 1. Repository state (2026-11-09)

- **Repository root**: `<repository-root>` (the parent `ASENT` folder is not a Git root).
- **Branch**: `sable` → `origin/sable`, **ahead 106 commits**. HEAD `b377a96` (merge of PR #16; identical to `origin/master` at the time of writing).
- **Stash / worktrees**: none / one (the primary checkout).
- **Recovery backup**: `<recovery-backup-directory>` present and untouched.
- **`reports/scenario-validation.json`**: tracked, SHA256 `00D6237839C2B71A899CD1D75EBBA62AE74A54846E22BD64892155A818F3CD61` before validation; unchanged after every SABLE test batch (re-verified by hash after each batch). A full-suite run rewrites this file at session teardown by design (`tests/conftest.py:52-61`); its pre-run bytes were backed up outside the repository (`..\scenario-validation.json.bak20261109`) and it was restored after the run (Section 3, row "full suite").
- **Debug artifacts**: `process` `asent_dashboard_20261109.log` etc. live outside the repository (WSL home / Windows Temp); nothing generated has been committed or staged.

## 2. What was present vs. what changed

**Present before this session (authored by the previous Gemini agent, verified and preserved, nothing staged):**
10 modified working-tree files (all SABLE-owned: `backend/sable/{api,storage,research_eval}.py`; `frontend/src/components/SableModule.tsx`, `frontend/src/components/sable/types.ts`, `frontend/src/components/sable/tabs/{Benchmark,TerraformDiff}.tsx`; `tests/test_sable_{persistence_api,policy_shapes,research_eval}.py`) plus 4 untracked phase reports. See Phase 5 report for their content.

**Changed by this session (one file edited, three files added):**

| File | Change | Why |
|---|---|---|
| `tests/test_gate_cli.py` | +1 test `test_terraform_only_change_keeps_satra_active_and_routes_surfaces` (modified file) | Pins the verified applicability behavior: applicability is project-surface + base-config based, never changed-file based. Terraform-only change with application `.py` code and SATRA enabled keeps SATRA assessed (INCONCLUSIVE without an engine here) and the gate stays REVIEW even though SABLE preserves the obligation; `changed_surfaces` routes the `.tf` change to SABLE only. |
| `reports/SABLE_PHASE6_MUTATION_DEMO_EVIDENCE.md` | new (untracked) | Records the real-target mutation demonstration (Section 4). |
| `reports/SABLE_INDEPENDENT_REVIEW_PACKAGE.json` | new (untracked, 22.2 KB) | Generated review package for all six reference cases: raw baseline/candidate Terraform, obligation, authored expectation, empty attestation template per case. Generation asserts and contains no predictor output per case. |
| `reports/SABLE_REVIEWER_HANDOFF.md` | new (untracked) | Instructions for the independent human reviewer (Section 6). |

**Nothing else touched**: Maryam's CAVR, Sheharyar's SATRA-RV, target-project configurations, shared gate policy code, hooks, Git config, and branch state are unchanged. No staging, commits, pushes, merges, rebases, or branch switches were performed.

## 3. Commands, tests and build results (2026-11-09) — **[rerun today]**

Python environment: WSL Ubuntu, `<python-environment>` (the established environment for all previous phase runs). Frontend: Windows Node v22.23.2.

| # | Command | Result | Exit |
|---|---|---|---|
| 1 | `pytest tests/test_sable_policy_shapes.py -q` | **52 passed** in 4.75 s | 0 |
| 2 | `pytest tests/test_gate_cli.py -k sable` | 5 passed, 15 deselected | 0 |
| 3 | 46-parity re-verification | included in row 1 (`52 passed`); the "46 parity" count is **46 verdict-pair comparisons** (13 edge-policy pairs ×3 asserts + 33 fixture-scenario pairs), not tests | |
| 4 | `pytest tests/test_gate_cli.py -k 'terraform_only or sable'` (new test) | **6 passed**, 15 deselected in 37.32 s | 0 |
| 5 | `pytest tests/test_sable_persistence_api.py tests/test_sable_policy_shapes.py tests/test_sable_research_eval.py -q` | **65 passed** in 21.55 s | 0 |
| 6 | `pytest tests/test_gate_cli.py -q` (whole file) | **21 passed** in 101.03 s | 0 |
| 7 | `pytest tests/test_integration.py -k sable -q` | **15 passed, 7 deselected** in 79.07 s | 0 |
| 8 | `npm run build` equivalents: `npx vite build` + `npx tsc --noEmit` (frontend) | build: 1615 modules, built in 11.28 s; typecheck clean. One pre-existing chunk-size warning (>500 kB, informational) | 0 |
| 9 | `pytest tests/ -q --tb=line` (full suite, 2132 tests, WSL) | **26 failed, 2096 passed, 9 skipped, 1 xfailed, 1 warning in 2086.96 s** (34:46).pytest exit convention for failures ⇒ exit 1. Failures are two isolated clusterres, both environmental and pre-existing; full diagnosis below (Section 3a). | 1 |

`reports/scenario-validation.json`: before the full-suite run hash `00D623…`; the session-teardown fixture rewrote it (`tests/conftest.py:60-61`, generating "Actual executions from pytest" report → final run hash `A942BB…`); the preserved pre-run bytes (backed up outside the repository before the run) were restored after the run; final hash `00D623…` confirmed. The generated variant was a timestamp-fresh regeneration of the same deterministic scenario executions (the fixture's own note); not adopting it avoids unrelated tracked-file churn. Git status after all work and restore: identical to the baseline plus only this session's additions (Section 2).

### 3a. Full-suite failure diagnosis (all 26, two clusters — **environmental, pre-existing, unrelated to today's changes**)

Hyphens removed: none of the 26 failures touches SABLE-owned code or the shared gate; each cluster is a known environment precondition, reproduced and root-caused by rerun (representative full tracebacks captured).

**Cluster 1 — 19 failures in `tests/test_cavr_frontend.py` (CAVR dashboard render tests, Maryam's module area):**
- Mechanism (confirmed by direct probe): the test harness renders the real React dashboard via esbuild (`tests/test_cavr_data/render_cavr.mjs`), which resolves `frontend/node_modules/esbuild`. `node_modules` was installed **on Windows**, so only `@esbuild/win32-x64` exists; under WSL Linux, esbuild throws *"You installed esbuild for another platform than the one you're currently using… the '@esbuild/win32-x64' package is present but this platform needs '@esbuild/linux-x64'"* → renderer exits 1 → `assert done.returncode == 0` fails at `tests/test_cavr_frontend.py:130` for every render-based test (19 total, incl. parameterized timeline cases). Every one of the 19 tracebacks is the identical mechanism.
- Fix owner: environment/setup (create `frontend/node_modules` with linux prebuilds — e.g. `npm --prefix frontend install` *inside* WSL — or run these tests on Windows). Not a SABLE change; not done without approval because node_modules is a dependency-management action in a teammate-owned area.

**Cluster 2 — 7 failures in `tests/test_satra_project_image_docker.py` (SATRA Docker tests, Sheharyar's module area):**
- Mechanism (confirmed by tracebacks): require the locally built Docker runner image `asent-satra-runner:local` (e.g. `test_real_gate_run_uses_an_approved_dependency_and_kills_the_mutant` → `assert status == "ACCEPT"` got `INCONCLUSIVE`, "No approved gate image for this project"). The image was never built here.
- Fix owner: the approved Docker build decision (blocked on user approval to run `scripts/satra_build_sandbox.sh`).

**Coverage statement:** everything SABLE-owned today is green: the three SABLE test files (65 passed), all 21 gate-CLI tests (incl. the new SATRA applicability pin), the SABLE integration subset (15 passed), plus everything else outside the two clusters above.

**Environment limitation (not a code defect):** SATRA's per-project runner image `asent-satra-runner:local` is not built in this environment, so SATRA executes to INCONCLUSIVE in gate runs rather than ACCEPT/REJECT. Building it requires Docker image construction, which was explicitly deferred pending approval (not a missing dependency of the current contract).

## 4. Mutation demonstration on the real target application — **[rerun today]**

Target: public repo `maryamfatimaaaaa/asent-target-flask`, base `e0a1766` (its `.asent/` config and obligation `user-uploads-least-privilege` are authoritative). Experiments ran on a **disposable clone** (`<disposable-target-clone>`); the recorded original clone and the GitHub repo were untouched; nothing pushed.

**Case A — clean logical refactor** (branch `demo-sable-refactor`, commit `e10db46`):
Input diff: `infra/main.tf` renames the resource block `aws_s3_bucket "user_uploads"` → `"uploads"`, restates the public-access-block reference and the policy `${aws_s3_bucket.uploads.arn}/*`; `infra/moved.tf` adds `moved { from = aws_s3_bucket.user_uploads; to = aws_s3_bucket.uploads }`. Physical bucket identity (`var.uploads_bucket_name`) unchanged.
- Command: `python -m backend.cli gate --repository target-flask-mutation --base main --head demo-sable-refactor --output-dir gate-flask-mutation-safe-out`
- **Overall: REVIEW, exit 2. Run ID `234f6b2eea86`.** CAVR pass/VERIFIED; **SATRA INCONCLUSIVE (runner image unavailable)**; **SABLE pass/`PRESERVED`** ("Every registered obligation is preserved"). `changed_surfaces → {'SABLE': ['infra/main.tf', 'infra/moved.tf']}`.
- REVIEW is the **correct, honest** outcome here: SATRA is applied to this project (it has application `.py` code and SATRA is enabled in the base config; see Section 5), and when it cannot produce trustworthy evidence the fail-safe shared gate cannot ACCEPT. The SABLE PRESERVED verdict is independently visible in the module row and its evidence (`evidence_id 862bacd551cc4b7695b95b8eab5618f1`). This is not relabeled ACCEPT. Evidence: `<local-run-directory>/gate-flask-mutation-safe-out/asent-report.json` (+ summary).

**Case B — authorization regression** (branch `demo-sable-regression`, commit `e3fb8ac5`; same refactor  then `Action ["s3:GetObject","s3:PutObject"] → ["s3:*"]`):
- Command: same CLI, `--head demo-sable-regression --output-dir gate-flask-mutation-regressed-out`
- **Overall: BLOCK, exit 1. Run ID `2f22f3e825c9`.** CAVR pass/VERIFIED; SATRA INCONCLUSIVE; **SABLE block/`REGRESSED`** ("user-uploads-least-privilege: REGRESSED: Missing, widened or misbound role-to-asset authorization"). Evidence IDs recorded (`SABLE: 903e22037f074681b3ecd2e9dbe4920e`).

**Fail-closed bonus [observed while developing the new test]:** when a rename's `moved` block points at a resource that does not exist (malformed refactor), SABLE returns UNKNOWN with reason *"Move evidence conflicts with physical asset identity"* and the shared gate returns REVIEW (exit 2). Ambiguity does not become acceptance.

## 5. SATRA applicability (verified source-level, [rerun today])

Plain English: whether SATRA runs depends on **what the project is** and **what its base commit's frozen config declares**, never on which files changed base→head (`backend/orchestrator/context_service.py:43-55`, dispatch at `backend/orchestrator/service.py:115-129`). `route()` (`backend/orchestrator/event_router.py`) computes `changed_surfaces` for evidence binding/reporting only.

Three distinct states, **[all distinguished in code and tests]**:

| State | Meaning | Code | Label |
|---|---|---|---|
| **NOT_APPLICABLE** ("not applicable (no inputs in this project)") | The candidate has no supported input surface for the module at all (e.g. SATRA on a project with no non-test `.py` file) | `context_service.py:64` | "not applicable (no inputs in this project)" |
| **NOT_ASSESSED** | The module's surface exists but the authoritative frozen base config says `disabled` (a mandatory reason is enforced by `schema.py:77`) | `loader.py:58-65`; label `frozen.py:27` | "not assessed (disabled by base config)" |
| **INCONCLUSIVE** | The module applies but cannot produce trustworthy evidence (no runner image, no engine, missing contract, harness suspicion…) | e.g. `gate_mode.py:59-98` | "review / INCONCLUSIVE" |

They are not interchangeable; a disabled or out-of-scope module is never counted as passing (`final_gate.py`: disabled modules never reach ACCEPT; absent-with-surface adds an "applies but is not configured" reason → REVIEW).

Test evidence **[rerun today]**:
- New: `tests/test_gate_cli.py::test_terraform_only_change_keeps_satra_active_and_routes_surfaces` — pins all three behaviors at once for a Terraform-only change.
- Existing: `tests/test_gate_cli.py:149` (SABLE-only scope → ACCEPT, exit 0), `:176` (disabled modules shown NOT_ASSESSED, never as pass), `:109` (SATRA enabled, engine absent → INCONCLUSIVE/REVIEW), `tests/test_orchestrator_config.py:143-176` (coverage states; absent ⇒ REVIEW; all-disabled ⇒ REVIEW), `tests/test_gate_end_to_end.py:40`, `tests/test_integration.py:105-113` (SABLE-only applicability in the shared workflow).

**Legitimate ACCEPT demonstration**: the existing fixture-based gate tests prove the honest ACCEPT path (Terraform-only project, SATRA disabled by the base config with a reason, CAVR acceptable, SABLE PRESERVED → ACCEPT exit 0 with "Accepted for the assessed modules only" in the summary, `backend/gate/summary.py:73`). **The real target-flask repository's configuration was NOT modified to manufacture ACCEPT.** Making the real target-flask produce an ACCEPT would require a decision and change of its authoritative base configuration (owner: Maryam) — pending, an external blocker, not a code change. The dedicated full-suite run also confirms that the only failing SATRA tests are those needing the external runner image (Section 3a) — no shared-gate change is implied.

## 6. Research evaluation — six reference cases — **[rerun today]**

- Readiness (exact output): `Dataset 'sable-independent-oracle-v1': 0/6 cases reviewed.` All six cases (`rename_with_moved`, `split_to_two`, `resource_wildened`, `wrong_binding_regressed`, `ambiguous_set_three_candidates`, `replacement_wrong_bucket`) are `UNREVIEWED`; every metric is `UNMEASURED` (`sable_outcomes`, `moved_only_outcomes`, `correspondence_accuracy`). This is **correct state, not a failure to complete work**: presenting them as completed evaluation would be misrepresentation.
- Tooling completed: `generate_review_package()` produces the self-contained reviewer package (raw Terraform per case, obligation, authored expectation clearly labeled authorship, empty attestation template). The artifact `reports/SABLE_INDEPENDENT_REVIEW_PACKAGE.json` **[22.2 KB]** was asserted against invariants during generation (nothing auto-marked REVIEWED; template statuses `UNREVIEWED`), and `reports/SABLE_REVIEWER_HANDOFF.md` tells the human reviewer exactly what to inspect and sign.
- **B4 classification [verification]**: `COMPARATOR_TAXONOMY` carries `B4_composite_ablation: { classification: "INTERNAL_ABLATION_COMPOSITE", implementation_independence: "REUSES_SABLE_CORE" }`, and any graph/metric for B4 carries those labels in the code paths consumed by the dashboard. B4 reuses SABLE's correspondence ranker and authorization engine, so it is an internal ablation/composite and must never be presented as an independent comparator or independent validation. The only independent comparator is `independent_moved_only` (`INDEPENDENT_BASELINE`, `ZERO_SABLE_COUPLING`), and it cannot check policy semantics.
- Test evidence: `backend/sable/tests/test_sable_research_eval.py` included in the 65 passing tests [rerun today] (guarding taxonomy honesty + refuse-to-measure behavior).

## 7. End-to-end demonstration story (one coherent narrative) — **[rerun today]**

1. **Real target input (REVIEW path, canonical CLI evidence)**: target-flask base `e0a1766` → head refactor: gate REVIEW/exit 2 — CAVR VERIFIED, SATRA INCONCLUSIVE (image unavailable), SABLE PRESERVED (Case A). Same input + `s3:*` → gate BLOCK/exit 1 — SABLE REGRESSED (Case B). Exact commands in Section 4; reports written by the gate.
2. **Scoped fixture (ACCEPT path, controlled)**: the existing, verified gate-CLI fixture proves what ACCEPT means: only the "right" modules enabled (e.g., Terraform-only project where application review is excluded by the authoritative base config) and every applicable module with current acceptable evidence → ACCEPT exit 0 (`test_cavr_only_accept_with_disabled_modules_never_shown_as_passed`, `test_sable_preserved_is_accept`). **This does not claim the target-flask repository is ACCEPT.**
3. **Live dashboard verification [this session, local only]**: dashboard served on 127.0.0.1:8000 (WSL). Page loads with **zero console errors and zero failed API calls**; the SABLE module UI rendered all its evidence tabs (Overview, Specification, Terraform Diff, Resource Graph, Correspondence, Projection, Verification, Decision, Benchmark, Evidence) with the full scenario catalog. A standalone SABLE pipeline run from the UI completed with a full inspectable chain: decision hash `b6969a6ab2486dc10950…`, chosen successor `aws_s3_bucket.cdata` ("Unique supported successor; resource-name similarity is not used"), authorization known/holds/no widening. The integrated `RUN WORKFLOW` run (ID `ac3df094f1b5`, controlled reproduction of the ambiguous `sable_unknown` scenario) settled at **"FINAL ASENT DECISION: REVIEW — CAVR: UNRESOLVED · SABLE: UNKNOWN"** with per-module statuses, changed-surface routing, and evidence-integrity envelopes displayed — i.e., the gate refuses ACCEPT when evidence is missing/ambiguous, which is the intended honest behavior (the dashboard works on the committed advisory corpus, correctly refusing stale evidence outside the test clock).
    - **Honest limitation on visual proof**: a pixel screenshot could not be captured because the desktop app window was not visible to the session's browser (the Review-pane focus prerequisite). Visual verification is therefore documented by accessibility snapshot + DOM text/metadata + API request log + console checks, not by a saved screenshot image. Screenshot capability remains available for a future session where the user has the desktop window open.
    - Also on UI runs in this environment: CAVR reports UNRESOLVED on the live dashboard because committed advisory evidence ages out (30-day max; test suites freeze the clock deliberately). This is disclosed as expected behavior of the evidence-freshness rule, not a defect. (The dashboard server run is session-local; it was started via `$PY -m backend.cli dashboard` in WSL and stopped after capture.)

## 8. Official final-evaluation requirements — **external blocker**

- The repository and all accessible project materials contain **no official final-evaluation GCR date, final-specific rubric, demo duration, or submission format**. The submitted artifacts in `deliverables/` are the FYP-1 midterm package only. Historical documents consistently flag exactly this gap (e.g., `reports/SABLE_PHASE3_VERIFICATION_AND_DEMO_REPORT.md` P3: "Awaiting official FYP-1 Final GCR date and grading rubric from department"). The proposal re-defense (F26-033-ASENT) passed per the team's recollection recorded in the report chapters, but the re-defense email's "optimize test selection based on PR" recommendation is not found verbatim as an implemented artifact; `asent gate` analyzes unseen PR/base..head diffs, which satisfies the spirit but the specific implementation claim cannot be verified from the repository.
- Required, obtained-from-faculty items: (1) official GCR date/time and venue; (2) the new-evaluation rubric; (3) any format/duration constraints. Without them, the demonstration cannot be adapted to grading emphasis; any dates would be invention.

## 9. Remaining technical / team blockers (prioritized)

1. **SATRA runner image build (Docker)** — needed for the real target-flask REVIEW to become a *provable* ACCEPT/REJECT on the application-code axis instead of INCONCLUSIVE-in-this-environment. Requires user approval to build (`scripts/satra_build_sandbox.sh`), i.e. a Docker image above the "small container" threshold, per safety rules.
2. **Maryam's configuration decision** for target-flask (acceptance path) and the `asent-target-invoicehub` collaborator invite — teammate decision, cannot be created by us.
3. **Six-case independent review** — the review package and handoff are ready; the signed attestation needs a human reviewer external to SABLE authorship.
4. **Official final-evaluation GCR date/rubric** — faculty requirement, missing.
5. **Final branch/PR/commit** — intentionally not performed (not authorized).
6. **`tests/test_cavr_frontend.py` cross-platform `node_modules`** — the 19 render failures clear once `frontend/node_modules` carries a Linux esbuild binary (install inside WSL) or the suite is run on Windows. Setup task, see Section 3a; not attempted (teammate environment).

## 10. Exact reproduction steps (final demonstration)

```bash
# Env: WSL Ubuntu, python=<python-environment>
cd <repository-root>
PY=<python-environment>

# SABLE test evidence
$PY -m pytest tests/test_sable_policy_shapes.py -q                          # 52 passed
$PY -m pytest tests/test_sable_persistence_api.py tests/test_sable_research_eval.py tests/test_sable_policy_shapes.py -q  # 65 passed
$PY -m pytest tests/test_gate_cli.py -q                                     # 21 passed
$PY -m pytest tests/test_integration.py -k sable -q                         # 15 passed

# Real target mutation demo (disposable clone)
$PY -m backend.cli gate --repository <disposable-target-clone> \
  --base main --head demo-sable-refactor \
  --output-dir <local-run-directory>/gate-flask-mutation-safe-out        # exit 2 REVIEW, SABLE PRESERVED
$PY -m backend.cli gate --repository <disposable-target-clone> \
  --base main --head demo-sable-regression \
  --output-dir <local-run-directory>/gate-flask-mutation-regressed-out   # exit 1 BLOCK, SABLE REGRESSED

# Research review package + honest readiness
$PY -m backend.sable.research_eval --check-readiness                        # 0/6 reviewed; all UNMEASURED

# Dashboard (optional UI verification)
$PY -m backend.cli dashboard                                                # http://127.0.0.1:8000
```

## 11. What remains for humans

- Reviewer: perform the six-case independent review via `reports/SABLE_INDEPENDENT_REVIEW_PACKAGE.json` + `reports/SABLE_REVIEWER_HANDOFF.md`.
- Teammate: SATRA image build approval; Maryam's target-project decisions; official GCR/rubric from faculty.
- (Optional) Future pixel-level dashboard screenshots for the defense deck; current verification stands on DOM/a11y/API evidence.
