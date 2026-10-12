# SABLE Mid-Evaluation Rubric Audit — 2026-10-12

This is an evidence audit of the SABLE contribution, not a score prediction. Rubric wording is taken from `report/sources/mid_guidelines_rubrics.txt` on the `report` worktree. “Proven” means the named code/test artifact supports the bounded SABLE claim; it does not prove live-cloud behavior, panel performance, or work owned by another member.

## Audited snapshot and scope

- Integration base inspected: `integration/sable-satra-cavr` at `347e468aab03e476defe8d82e7a4b5c0d39290c8`, based on `origin/master` `36671ee8540c5f72614121681b760efb55e28d29` (15 commits ahead, 0 behind at audit start). The fixes below were validated locally; this audit does not claim post-fix remote CI or merge status.
- Scope: static analysis of supported local Terraform/HCL, S3 buckets, inline IAM role policies, and the registered baseline obligation. No Terraform apply, AWS deployment, or live AWS authorization was performed. The deterministic analyzer does not call an LLM.
- Other branches and worktrees were inspected and left untouched. The root `sable` checkout had pre-existing edits and two stashes; the separate `report` worktree and its deliverables were clean and left untouched.
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

The report worktree was intentionally not changed. Its SABLE requirement FR-S2 (`chapter4_requirements.tex`) and runbook text (`evidence/SABLE_MID_DEMO_RUNBOOK.md`) still say an empty baseline is `NOT_APPLICABLE` / acceptable. That text is now stale against this code correction and must be reconciled by the report owner before the next report release. It must not be presented as the current behavior.

## Form 2 — Presentation / prototype evidence

| Criterion and exact expectation | Status | Evidence | Remaining work |
|---|---|---|---|
| **3. Live Prototype with Core Module Demo (25):** “Meaningful core module works live (not UI screenshots/video); edge/failure cases shown.” | **PARTIAL** | SABLE is executable code, not scenario cards: `backend/sable/analyzer.py` parses baseline/candidate HCL, verifies the obligation, ranks successors, evaluates projected authorization, and emits a result. The shared service/gate integration test executes preserved, regressed, ambiguous, unresolved-binding, and (new) missing-baseline cases. Prior actual SABLE UI captures are documented in the report, but no fresh browser/UI session was verified against the audit's local post-fix commit. | Personally rerun a preserved rename-with-moved case, a wrong-target or widening case, and an ambiguous case in the integrated app; show trace and chain details. The screenshots alone do not meet “works live.” |
| **4. Requirements and Acceptance Criteria Quality (10):** “User interactions, FRs/NFRs, and acceptance checks are technically correct and aligned.” | **PARTIAL** | `report/chapters/chapter4_requirements.tex` contains SABLE FR-S1–FR-S5 and tests; `appendix_requirements.tex` provides mapping. Most acceptance outcomes have executable checks. FR-S2 and the runbook currently misstate empty-baseline behavior, so the written acceptance contract does not yet match the audited fix. | Report owner should update FR-S2, acceptance text, and runbook to say empty/missing baseline → `UNKNOWN` / `REVIEW`, then rebuild report. |
| **5. Design Artefacts & Design Evolution (15):** “Architecture plus data/process/behavior artefacts match code; architectural changes justified.” | **PARTIAL** | `report/chapters/chapter5_design.tex` has a SABLE process diagram, component table, domain/data model, interfaces, and rationale for separating asset correspondence from authorization. It also explains the unresolved-role correction. The diagram predates the missing-baseline and required-integrity corrections; no updated design evolution entry records them yet. | Reconcile the two corrected fail-safe transitions in design and acceptance artefacts; rehearse explaining why baseline authority precedes successor projection and why ambiguity abstains. |
| **6. Repository, Milestone & Member Evidence (10):** “Tagged code, commit timeline, task log, and member ownership visible in repo.” | **PARTIAL** | Git history and the published `sable` and integration branches show incremental SABLE implementation/test work. `report/chapters/chapter9_development_evidence.tex` describes SABLE vs shared/team evidence. A complete current member/date task log and balanced contributions by all members cannot be established from this module audit. | SABLE owner should confirm personal commits/tasks and link actual milestone records; team-owned member logs and other modules require their owners. Do not claim sole ownership of shared orchestrator/report work. |
| **7. Testing & Early Validation (10):** “Tests/validation checks exist for current module; failure or edge case discussed.” | **PROVEN** for the executed SABLE slice | The focused local run after fail-safe changes: 39 passed, 37 deselected. It includes the real shared Service-to-evidence-to-gate path and unit/model edges. The broad run across `tests/test_modules.py`, isolation, shared, and shared integration cases was 71 passed, 1 failed; `test_controlled_dormant_execution` expected `REJECTED` but local Windows fallback returned `UNRESOLVED` because the pinned inert sandbox runtime was unavailable. The full local run completed with 1,400 passed, 36 failed, 10 skipped, 12 setup errors, one warning. The failures/errors are predominantly Windows/POSIX and missing-Docker limitations; detail follows. | Keep the local runtime limitation explicit. Explain at least one `REGRESSED` and one `UNKNOWN` case live. Use the Linux CI results for POSIX/Docker-backed coverage, but rerun CI on the post-fix SHA before merge. |
| **8. Presentation, Q&A, Team & Tool Ownership (10):** “Team coordination clear; tool-assisted outputs defended and thoroughly understood.” | **PARTIAL** | Code, tests, bounded-scope documentation, and test/CI records support technical ownership. They cannot establish the student's live explanation, team coordination, or complete team-wide tool disclosure. | Personally rehearse the decision path, evidence binding, limitations, and tool use; team members must defend their own modules and disclose their own tools. |

## Form 3 — Report evidence for SABLE

| Criterion and exact expectation | Status | Evidence | Remaining work |
|---|---|---|---|
| **4. Requirements & Acceptance Criteria (15):** “User interactions, FRs/NFRs, and SRS acceptance checks are precise and testable.” | **PARTIAL** | Report FR-S1–FR-S5 and test links are concrete and mostly executable. The empty-baseline claim in FR-S2 contradicts the corrected code, and post-fix evidence-integrity requirements are not yet represented in the report. | Reconcile the SRS to the local fix and add explicit acceptance: absent integrity metadata or missing baseline cannot yield ACCEPT. |
| **5. Architecture & Component/Interface Design (15):** “Architecture, components, dependencies, and interfaces are clear and justified.” | **PROVEN** for the bounded SABLE slice | Chapter 5 names analyzer/parser/correspondence/evaluator/orchestrator/final gate, key dependencies, and the verified decision order. Chapter 9 distinguishes standalone SABLE UI from shared workflow. | Update component/decision notes to include the new no-baseline and no-integrity fail-safe conditions. |
| **6. Data / Process / Behavior Design (10):** “Appropriate ERD/schema/data flow/activity/sequence/state diagram included and explained.” | **PROVEN** for the bounded SABLE slice | Chapter 5 Figure `sable-current-process` is a project-specific process/data flow; domain/data sections describe obligation, normalized resource, successor hypotheses, authorization result, evidence bindings, and final gate. | Add the two audit corrections to the behavior description so the artefact remains current. |
| **7. Implementation Documentation (15):** “Completed module described with setup, main files/classes/functions, and technical decisions.” | **PROVEN** for the bounded SABLE slice | Report Chapter 5 and Chapter 9, plus `evidence/SABLE_MID_DEMO_RUNBOOK.md`, identify setup, core file responsibilities, supported local-HCL/IAM subset, design rationale, commands, and limitations. | Correct stale empty-baseline description; include fresh post-fix SHA and CI/test result when available. |
| **8. Testing Plan & Tool / Risk Disclosure (15):** “Test plan, early results, external dependency/tool disclosure, and risks documented.” | **PARTIAL** | Chapter 8 records focused/CI results, edge cases, Windows Docker limitation, and scope risks; chapter 9 and runbook document the local workflow and no-AWS boundary. This audit adds current local results. A new post-fix CI result and complete team-wide tool/privacy disclosure are not yet verified. | Run CI on the post-fix commit, then update the report-owned copy with exact pass/skip counts and verified team tool/privacy disclosure. |

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

## Branch / merge gate

At audit start and after re-fetch, `origin/master` was `36671ee8540c5f72614121681b760efb55e28d29`; `origin/integration/sable-satra-cavr` was `347e468aab03e476defe8d82e7a4b5c0d39290c8`; `origin/sable` was `753a55b1daedc370f04a493eca31169e5083dc1a`; and `origin/report` was `1e74c93650bf463f23fa20379d0930d826c64e8d`. Integration is 15 commits ahead/0 behind master; report is 17 ahead/0 behind. Remote `sable` is 11 ahead/101 behind master at merge base `a0072ea9e13f6dcbed98b17987adcf396de57066`, and is an ancestor of integration (0 ahead/105 behind). Thus its history is included in integration; replacement is only safe after master contains the verified implementation. No open PR was found in the last repository API check. Branch protection details could not be read with the available GitHub permissions.

The local SABLE-focused tests, shared-gate tests, demo cases, frontend build, and byte-compilation pass. The cross-module full suite is not green on native Windows for the reasons above. Post-fix GitHub CI and a supported PR/review path are required before merge. The report owner must reconcile the stale acceptance statement before the next report release. No branch was merged into `master` or renamed during this audit.
