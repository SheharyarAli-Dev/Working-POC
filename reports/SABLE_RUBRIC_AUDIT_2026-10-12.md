# SABLE Mid-Evaluation Rubric Audit — 2026-10-12

This is an evidence map for SABLE against the official Form 2 and Form 3 criteria, not a score prediction. The only rubric source found in the repository is the extracted text `report/sources/mid_guidelines_rubrics.txt` on the report worktree; no official PDF was found in the repository. Statuses are `MET`, `PARTIAL`, `UNMET`, or `NOT VERIFIABLE` and apply only to the stated scope. Code/CI evidence does not prove live demonstration, panel performance, or other members' ownership.

## Audited snapshot and scope

- Current integration code commit: `83e204cb917d8830c908f85217b950cf6178ce00` on PR #5 branch `integration/sable-satra-cavr`, based on source commit `84f91a933984bdbf21e43b72dc8bad7c59e92f4f`. PR #5 remains open and unmerged. All 18 check runs passed on exact code commit `83e204c`; this commit contains the UI-label correction, its regression test, the runbook correction, and the initial audit update. The audit text below was then reconciled with those results; the current audit-only change does not alter implementation code.
- Scope: static analysis of supported local Terraform/HCL, S3 buckets, inline IAM role policies, and the registered baseline obligation. No Terraform apply, AWS deployment, or live AWS authorization was performed. The deterministic analyzer does not call an LLM.
- At inspection, root `sable` had pre-existing changes to two workflow files, `backend/sable/authorization.py`, and `tests/test_modules.py`; the null-binding correction is already present in integration. Two stashes remain untouched. The separate report worktree has eight uncommitted chapter/runbook edits; this integration commit did not include or alter them. No report commit or merge was made.
- Test commands used the existing root Python 3.12 virtual environment. Sandboxed attempts could not create/clean pytest temporary directories under Windows ACLs; elevated reruns executed.

## Core mechanism verification

| Case | Executed path and evidence | Result / limit |
|---|---|---|
| Terraform rename with a valid `moved` block | `tests/test_modules.py::test_sable_refactor_and_correspondence_cases[rename_with_moved-PRESERVED]`; historical dedicated SABLE UI capture on `665b224` shows `PRESERVED / ACCEPT`, chain 9/9, documented in `report/chapters/chapter9_development_evidence.tex`. | Unit path returns `PRESERVED`; UI capture is prior verified code, not a new browser session on local `347e468`. |
| Wrong protected target / binding | `tests/test_modules.py::test_sable_real_hcl[sable_regressed-REGRESSED]`, `test_sable_refactor_and_correspondence_cases[policy_rewrite_wrong_target-REGRESSED]`; shared-service parameter `sable_regressed` checks emitted evidence, snapshot, input hash, integrity, and final `BLOCK`. | `REGRESSED / BLOCK`; the workflow test isolates SABLE so another module does not mask the mapping. |
| Privilege widening | `test_sable_real_hcl[sable_widened-REGRESSED]`; historical dedicated SABLE UI capture on `665b224` shows `REGRESSED / BLOCK`, chain 9/9. | `REGRESSED`; no claim beyond modeled action/resource scope. |
| Ambiguous/split successor | `test_sable_refactor_and_correspondence_cases[ambiguous_set_three_candidates-UNKNOWN]`; `test_shared_sable_evidence_drives_final_gate[sable_unknown-UNKNOWN-REVIEW]`; historical split UI capture on `665b224`, chain 7/7. | `UNKNOWN / REVIEW`; no unique attribution is forced. |
| Null, blank, and unresolved role binding | `test_sable_standalone_evaluator_fails_closed_on_null_role_binding`, `test_empty_role_binding_is_unknown_in_both_evaluators` (empty and whitespace), `test_sable_unresolved_role_binding_with_valid_policy_is_unknown`, and shared-service parameter `sable_unresolved_role_binding`. | `UNKNOWN`; valid known grants remain in the evidence while unresolved extra binding prevents a safe conclusion. |
| Missing/unverified baseline | `test_sable_unverified_baseline_and_empty_baseline`; integrated `test_shared_gate_reviews_missing_sable_baseline`. | A failing or empty baseline is now `UNKNOWN`; the shared decision is `REVIEW`. This corrects a verified false-safe path described under changes below. |
| Unsupported/malformed input | `test_sable_unknown_parse_and_disabled`, `test_sable_unsupported_iam_stays_unknown`, `test_sable_unsupported_terraform_stays_unknown`. | Parse or unsupported policy/model semantics do not produce `PRESERVED`. A literal malformed role value is not a separately named test; empty/null and unresolved expressions are covered. |
| Empty, incomplete, stale, or tampered evidence | `tests/test_shared.py::test_context_evidence_integrity`, `test_sable_final_gate_rejects_untrusted_evidence`, `test_sable_final_gate_requires_explicit_integrity_evidence`, and `test_shared_sable_evidence_drives_final_gate`. | Tampering, missing explicit integrity, absent current evidence, stale candidate/input bindings yield `REVIEW`; current persisted SABLE evidence is the source of the tested gate result. |
| Determinism / tool boundary | Decision path in `backend/sable/analyzer.py`, `hcl_parser.py`, `correspondence.py`, `policy_semantics.py`; bounded parser/evaluator tests. Optional scanners are advisory only. | No LLM call in the decision path. No real AWS deployment or live authorization test was performed. |

### Changes required by this audit

Inspection found two false-safe defaults on the integration branch:

1. An applicable Terraform candidate with an empty baseline emitted SABLE `NOT_APPLICABLE`; `backend/orchestrator/final_gate.py` treated that result as acceptable. It could therefore reach `ACCEPT` without a trusted baseline. The analyzer now returns `UNKNOWN`, and SABLE `NOT_APPLICABLE` now maps to `REVIEW`. New unit and integrated-gate regression assertions cover this path.
2. The final gate defaulted a missing `integrity_valid` field to `True`. It now requires the field to be exactly `True` and uses safe `.get()` checks for snapshot/input binding. A missing-integrity regression is added.
3. The shared dashboard badge treated SABLE `NOT_APPLICABLE` as `ACCEPTABLE` even though the final gate returns `REVIEW`. `frontend/src/components/RunWorkflowModule.tsx` now labels only `PRESERVED` as acceptable; a focused contract regression is in `tests/test_sable_frontend_contract.py` and is added to `.github/workflows/sable-shared.yml`.

The report worktree's `chapter4_requirements.tex` FR-S2/FR-S5, `chapter6_iteration1.tex`, and `evidence/SABLE_MID_DEMO_RUNBOOK.md` were corrected locally to match the current fail-closed behavior. Those report-owner edits remain uncommitted and require review/build before publication.

## Rubric evidence cross-reference

The complete Form 2 and Form 3 status map is in the official-rubric reconciliation below. The SABLE chapter tables above are retained as implementation/test evidence; `report/evidence/` contains historical UI captures. Those images do not replace the required live demonstration, and the captures predate source commit `84f91a9`.

## Commands and observed checks

Executed on the local integration worktree with the existing root Python 3.12 environment:

```powershell
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_modules.py -k sable tests/test_sable_isolation.py tests/test_shared.py tests/test_integration.py::test_shared_sable_evidence_drives_final_gate tests/test_integration.py::test_shared_gate_reviews_missing_sable_baseline --basetemp <fresh-%TEMP%-directory>
```

Result: **39 passed, 37 deselected**. The command selected SABLE-named module tests, isolation tests, SABLE gate tests, and both shared SABLE integration functions. The `test_shared_sable_evidence_drives_final_gate` parameter cases are `sable_preserved`, `sable_regressed`, `sable_unknown`, and `sable_unresolved_role_binding`; the new test deletes all baseline Terraform files and verifies SABLE `UNKNOWN` with final `REVIEW`. A separate complete `tests/test_shared.py` run passed **35/35**, including final-gate status matrix, explicit evidence integrity, and missing-evidence cases.

The five integrated cases were also run verbosely through the shared `Service` path:

```powershell
.venv\Scripts\python.exe -m pytest -v tests/test_integration.py::test_shared_sable_evidence_drives_final_gate tests/test_integration.py::test_shared_gate_reviews_missing_sable_baseline --basetemp <fresh-%TEMP%-directory>
```

Output: **5 passed** — `sable_preserved` → `PRESERVED/ACCEPT`; `sable_regressed` → `REGRESSED/BLOCK`; `sable_unknown` → `UNKNOWN/REVIEW`; `sable_unresolved_role_binding` → `UNKNOWN/REVIEW`; missing/empty baseline → `UNKNOWN/REVIEW`. These tests use the shared runtime, persisted evidence, and final gate; they are not standalone helper-only assertions or a browser presentation.

Also attempted:

```powershell
.venv\Scripts\python.exe -m pytest -q --tb=short tests/test_modules.py tests/test_sable_isolation.py tests/test_shared.py tests/test_integration.py::test_shared_sable_evidence_drives_final_gate tests/test_integration.py::test_shared_gate_reviews_missing_sable_baseline --basetemp <fresh-%TEMP%-directory>
```

Result: **71 passed, 1 failed**. The single failure is `tests/test_modules.py::test_controlled_dormant_execution`: the native Windows environment reports `PINNED_INERT_LAB_PYTHON_AUDIT` unavailable and returns `UNRESOLVED`, while this test expects `REJECTED`.

The full local command was:

```powershell
.venv\Scripts\python.exe -m pytest -q --tb=short --basetemp <fresh-%TEMP%-directory>
```

Result: **1,400 passed, 36 failed, 10 skipped, 12 errors, one warning**. The errors in `test_satra_trust_and_seed.py` invoke a Bash script using a Windows path that Git Bash interpreted without drive separators. Other failures include unavailable Docker Desktop engine, symlink privilege/Windows Developer Mode, POSIX-only `os.geteuid`, Windows newline/path differences, unavailable pinned inert runtime, and SATRA sandbox tests requiring Docker. `test_real_recorded_replay` and six broader integration assertions returned REVIEW because SATRA was `INCONCLUSIVE` in the native Windows execution. During pytest fixture teardown, the generated run data showed the safe run had CAVR `VERIFIED`, SABLE `PRESERVED` with integrity true, and SATRA `INCONCLUSIVE`; the cross-module run had SABLE `PRESERVED`, CAVR `UNRESOLVED`, SATRA `INCONCLUSIVE`. That generated file was restored to its clean committed version after the test to preserve the pre-existing historical evidence artifact. `test_restricted_requires_enforcement` failed in that run because its synthetic CAVR evidence omitted the now-required integrity flag; the fixture has since been corrected and `tests/test_shared.py` passed 35/35 afterward. These are not counted as passes. Initial sandboxed attempts that errored while pytest created/cleaned temp directories are excluded.

Frontend build executed in `frontend/` with `npm run build`: **passed**, 1,614 modules transformed; output bundle was approximately 498.13 kB JavaScript (Vite size advisory only).

Previously verified on parent implementation snapshot `665b224` and carried in `347e468`: core CI, SATRA CI, and SABLE shared CI passed; SATRA had 84 passes; focused SABLE/shared assurance had 46 passes; the Docker-enabled full suite had 1,427 passed, 26 skipped, one warning, and all four required Docker checks ran without skips. The 26 skips were 19 frontend-render cases in the Docker job without Node/frontend dependencies and seven opt-in CAVR live-network cases. Those runs predate the local gate fixes and are not CI evidence for this audit's local changes.

Post-fix GitHub Actions completed successfully on source commit `84f91a933984bdbf21e43b72dc8bad7c59e92f4f` (PR #5 head):

- Core CI run [38220597702](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38220597702) — all jobs succeeded. The no-container full-suite JUnit artifact recorded **1,428 passed, 30 skipped, 0 failed, 0 errors**; the four Docker checks are intentionally skipped in this job. The separate frontend-render artifact recorded **26 passed, 0 skipped**; frontend production build succeeded.
- SATRA CI run [38220597564](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38220597564) — all jobs succeeded. SATRA recorded **84 passed, 0 skipped**, and the four required Docker sandbox checks (network isolation, read-only root, isolated tmpfs, timeout) each passed. The Docker-enabled full-suite JUnit artifact recorded **1,432 passed, 26 skipped, 0 failed, 0 errors**. Its 26 skips were 19 frontend-render cases because that job did not install Node/frontend dependencies and seven opt-in CAVR live-network cases.
- SABLE shared assurance run [38220597576](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38220597576) — **48 passed**.

The runs above validate the bounded SABLE/security fixes at source commit `84f91a9`. The former exact-head checks on `9319cc9` were successful but predate the UI-label correction. Follow-up CI now validates the UI correction and regression test at `83e204c` as listed below.

## Branch / merge gate

Live GitHub refs at verification were `master` `36671ee8540c5f72614121681b760efb55e28d29`, `integration/sable-satra-cavr` `83e204cb917d8830c908f85217b950cf6178ce00`, `sable` `753a55b1daedc370f04a493eca31169e5083dc1a`, and `report` `1e74c93650bf463f23fa20379d0930d826c64e8d`. PR #5 is open, targets `master`, and GitHub reports `CLEAN` merge state. No repository rulesets were listed; the classic branch-protection endpoint returned 404, so formal branch protection is not confirmed. The old `sable` branch has not been updated; its ancestry must be reviewed after the PR merge.

The native-Windows full-suite failures and setup errors remain as listed above; they are not erased by Linux CI. The integration changes are committed and pushed at `83e204c`, with all 18 exact-head checks passing. Report corrections in `.worktrees/report` remain local and uncommitted; no report-branch merge was performed.


## Official rubric reconciliation and complete criterion coverage

The extracted official rubric text records FYP-1 Mid as a formative, supervisor-only evaluation worth 20% of the overall FYP-1 grade, conducted around Week 8. Its purpose is developmental: verify implementation momentum and proposal corrections before the final panel. The original PDF was not available in the repository or connected Library for this pass. This is not a SABLE score prediction. SABLE can provide module evidence, but the team and supervisor own several required records and action gates.

### Form 2 criteria 1 to 8

| Criterion (official title, CLO, marks) | Status | SABLE evidence / remaining owner action |
|---|---|---|
| 1. Previous Proposal Actions Addressed (FYP1-CLO6, 10) | **NOT VERIFIABLE** | `report/chapters/chapter3_iteration_plan.tex` and `appendix_action_register.tex` have blank action rows; the checklist requests actual Form 10/panel feedback. Team/report owner must add the authentic register and evidence links. |
| 2. Iteration Plan & Work Breakdown Progress (FYP1-CLO2, 10) | **PARTIAL** | SABLE milestones I1 through I4 and progress are in `chapter3_iteration_plan.tex`; ownership is in `report/OWNERS.md`. An authoritative team schedule, owner/date recovery plan, and complete task log were not verified. |
| 3. Live Prototype with Core Module Demo (FYP1-CLO4, 25) | **PARTIAL** | Earlier UI captures are in `report/evidence/sable-trace-sable_{preserved,regressed,unknown,unresolved_role_binding}.png`; `SABLE_MID_DEMO_RUNBOOK.md` records shared run IDs and separates SABLE verdict from overall `REVIEW`/`BLOCK`. Captures predate source `84f91a9`; no fresh post-fix browser demo is verified. Student must demonstrate preserved and regressed/unknown cases live. |
| 4. Requirements & Acceptance Criteria Quality (FYP1-CLO2, 10) | **PARTIAL** | SABLE FR-S1 through FR-S5 are in `chapter4_requirements.tex`; tests are named in it and `appendix_requirements.tex`. Local FR-S2/FR-S5 corrections match `backend/sable/analyzer.py` and shared-gate tests but await report-owner review/build. |
| 5. Design Artefacts & Design Evolution (FYP1-CLO3, 15) | **PARTIAL** | `chapter5_design.tex` contains Figure `sable-current-process`, component/interface and domain/data models, and decision rationale; local text records baseline/integrity corrections. Report owner must review the rendered diagram and evolution account. |
| 6. Repository, Milestone & Member Evidence (FYP1-CLO6, 10) | **PARTIAL** | `appendix_repository.tex`, `chapter9_development_evidence.tex`, `report/OWNERS.md`, and Git history link SABLE commits `9a4dc3d`, `58b0a3d`, and source `84f91a9`. The full team task log and member-by-member contribution records are not verified; shared work is not attributed solely to SABLE. |
| 7. Testing & Early Validation (FYP1-CLO4, 10) | **MET for the bounded SABLE test slice** | `tests/test_modules.py`, `tests/test_sable_isolation.py`, `tests/test_shared.py`, and `tests/test_integration.py`; 48 focused SABLE/shared tests passed on source `84f91a9`; the UI correction selection passed 11/11 locally. All 18 checks passed on `83e204c`. Docker-enabled CI recorded SATRA 84/84 with no skips and full suite 1,433 passed, 26 skipped, 0 failures/errors. Preserve the native-Windows full-suite failures/errors listed above. |
| 8. Presentation, Q&A, Team & Tool Ownership (FYP1-CLO5, 10) | **NOT VERIFIABLE** | Screenshots and `report/evidence/SABLE_MID_DEMO_RUNBOOK.md` aid preparation but cannot establish oral defense, balanced participation, or full team tool disclosure. Each member must defend their module and provide their own tool/privacy record. |

### Form 3 criteria 1 to 8

| Criterion (official title, CLO, marks) | Status | SABLE evidence / remaining owner action |
|---|---|---|
| 1. Report Format & Artefacts Present (FYP1-CLO2, 5) | **PARTIAL** | `report/main.tex` includes chapters, appendices, and bibliography; `TEAM_REVIEW_CHECKLIST.md` still requires signatures, declarations, administrative fields, and final format/build review. Report owner action remains. |
| 2. Problem Formulation, R&D & Gap Analysis (FYP1-CLO1, 15) | **PARTIAL** | `chapter2_research.tex`, `references/references.bib`, and `sources/SABLE_design.txt` contain problem and gap material. Independent source/citation verification and full team literature defense remain unverified. |
| 3. Project Vision, Scope & Success Criteria (FYP1-CLO2, 10) | **PARTIAL** | SABLE boundaries appear in `chapter1_introduction.tex`, `chapter4_requirements.tex`, and the runbook: supported local Terraform/HCL, S3, inline IAM, no AWS apply/live authorization. Overall scope and success criteria need team confirmation. |
| 4. Requirements & Acceptance Criteria (FYP1-CLO2, 15) | **PARTIAL** | `chapter4_requirements.tex` and `appendix_requirements.tex` map SABLE FR-S1 through FR-S5 to tests; FR-S2/FR-S5 were corrected locally. Full cross-module SRS validation and report build/review remain. |
| 5. Architecture & Component/Interface Design (FYP1-CLO3, 15) | **MET for the bounded SABLE slice** | `chapter5_design.tex`, Figure `sable-current-process`, and `backend/orchestrator/service.py` / `final_gate.py` describe module boundaries and the shared evidence path. Verify the rendered figure; team-wide architecture sign-off is separate. |
| 6. Data / Process / Behavior Design (FYP1-CLO3, 10) | **MET for the bounded SABLE slice** | Chapter 5 describes the obligation/resource/successor/evidence flow and fail-closed baseline/integrity transitions; shared tests exercise them. Report owner must verify the built figure/text. |
| 7. Implementation Documentation (FYP1-CLO4, 15) | **MET for the bounded SABLE slice** | `chapter9_development_evidence.tex` and `report/evidence/SABLE_MID_DEMO_RUNBOOK.md` give setup, core files, decision sequence, commands, demo evidence, and limits; implementation is in `backend/sable/{analyzer,correspondence,policy_semantics,authorization}.py`. |
| 8. Testing Plan & Tool / Risk Disclosure (FYP1-CLO5, 15) | **PARTIAL** | `chapter8_testing.tex` records exact-head CI links, source-run counts, skips, Windows failures/errors, Docker limitation, and scope risks. Complete team GenAI/external-tool and privacy disclosure is not established; current local edits have no CI run. |

### Additional official supervisory action gates (page 4)

These are supervisor/team processes, not statuses SABLE can satisfy by itself:

- Sudden code volume without matching understanding: ask the student to explain recent code live at line/function level and what happens if a core function is removed; inability to explain caps Form 2 implementation marks and triggers a mandatory re-demo before FYP-1 Final, recorded in the meeting log.
- Stagnant prototype momentum: compare the live demo with proposal notes and ask what core logic is new; if momentum is flat, set three specific weekly demonstrable milestones and warn of FYP-1 Final risk.
- Generic/GenAI R&D text: ask the student to explain a selected research paragraph unaided; poor explanation requires a mandatory evidence-backed report rewrite.
- Uneven team contribution: hold a one-on-one check-in with the quieter member; inability to defend their module triggers Form 11, an individual two-week milestone, and meeting-log entry.
- Dishonest milestone logging: require live output for each completed milestone; failure is recorded in the meeting log and triggers a Form 10 Panel Action Register entry requiring evidence before FYP-1 Final.
- Ignored proposal-panel actions: verify the Panel Action Register against meeting observations and report evidence; ignored actions cap Form 2 Criterion 1 progress marks and require evidence at the next weekly meeting.

### Exact-head CI verification and local-change boundary

PR #5 was open and unmerged at head `83e204cb917d8830c908f85217b950cf6178ce00` when its checks completed. All 18 check runs passed on that exact SHA: [Core CI push run 38259626143](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38259626143) and [PR run 38259632484](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38259632484); [SATRA CI push run 38259626163](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38259626163) and [PR run 38259632736](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38259632736); [SABLE shared assurance push run 38259626152](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38259626152) and [PR run 38259632525](https://github.com/SheharyarAli-Dev/Working-POC/actions/runs/38259632525). The prior native-Windows suite still has the recorded failures/errors/skips; these remain disclosed and are not counted as passes. The code changes verified at `83e204c` have no subsequent implementation edits.
