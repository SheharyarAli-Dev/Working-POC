# SABLE Mid Evaluation Demo Runbook

This runbook describes the shared ASENT Run Workflow demonstration on the Windows validation host. The recorded verdicts below are from completed live UI runs; catalog expectations and unit-test outcomes are not substituted for those runs.

## Start ASENT on Windows

Open PowerShell in the repository root.

For a fresh checkout, run setup once. The repository's `scripts/setup.ps1` creates `.venv` with Python 3.12, installs `requirements.lock.txt`, installs frontend dependencies with `npm ci`, and builds the dashboard. It requires the Python 3.12 launcher (`py -3.12`) and Node/npm.

```powershell
.\scripts\setup.ps1
```

Start the application in that PowerShell window:

```powershell
.\scripts\start.ps1
```

That script starts `backend.main:app` with Uvicorn bound to `127.0.0.1:8000`. Leave the terminal open while presenting. The root-level `START_ASENT.ps1` is an alternative self-provisioning launcher: it creates the virtual environment and installs Python requirements if needed, builds the frontend if `frontend/dist/index.html` is missing, then starts the same backend. The setup-plus-start pair is the clearer repeatable path because setup also installs frontend dependencies.

When finished, `STOP_ASENT.ps1` stops the process listening on port 8000.

## Open and run the integrated workflow

1. Open `http://127.0.0.1:8000` in a browser.
2. Choose **RUN WORKFLOW** in the dashboard navigation.
3. Select a scenario from **Select Candidate AI-Change Scenario**.
4. Click **Execute Assurance Workflow** and wait for the run to complete. The page shows persisted module evidence and the overall ASENT decision.

Run these four catalog scenarios one at a time:

| Scenario ID | How to identify it in the selector | Purpose |
|---|---|---|
| `sable_preserved` | Select the entry with this scenario ID. | Refactor the protected S3 bucket into a local module while retaining the registered access obligation. |
| `sable_regressed` | Select the entry with this scenario ID. | Attach precise S3 permissions to the archive bucket instead of the protected active bucket. |
| `sable_unknown` | Select the entry with this scenario ID. | Present two similarly supported successor candidates so SABLE cannot make a unique attribution. |
| `sable_unresolved_role_binding` | Select the entry with this scenario ID; its title contains "unresolved role binding." | Keep a valid policy for the registered principal and add a broad inline policy with `role = var.additional_role`. |

These runs use the shared `POST /api/runs` workflow behind the page. They do not use the standalone `/api/sable` engine.

## Observed live results

These values came from the completed integrated UI runs captured in the screenshots below. The SABLE verdict is the module result; the final-gate column is the separate overall ASENT decision.

| Scenario | Run ID | SABLE verdict and reason | Overall ASENT decision and reason |
|---|---|---|---|
| `sable_preserved` | `ce3ede9ac9f3` | `PRESERVED` - exact modeled least privilege holds. | `REVIEW` - SATRA was `INCONCLUSIVE`. SABLE was not the reason for this review. |
| `sable_regressed` | `d4fbcbe4d3c5` | `REGRESSED` - permissions target the archive instead of the protected active bucket. | `BLOCK` - SABLE `REGRESSED`; SATRA was also `INCONCLUSIVE`. |
| `sable_unknown` | `2564be702861` | `UNKNOWN` - successor scores were too close for a unique attribution. | `REVIEW` - SABLE `UNKNOWN` and SATRA `INCONCLUSIVE`. |
| `sable_unresolved_role_binding` | `11e5ae828344` | `UNKNOWN` - persisted authorization finding: `aws_iam_role_policy.dynamic_extra: role binding unresolved`. | `REVIEW` - SABLE `UNKNOWN` and SATRA `INCONCLUSIVE`. |

For these recorded runs, the SABLE evidence integrity field was valid, the evidence candidate snapshot matched the run snapshot, and the SABLE input hash matched the SABLE `module.started` event's input hash. The page displays the snapshot and input hashes in the SABLE card and trace. The run's final-gate reasons remain separate from each module's verdict and reason.

## Latest live rehearsal on the `sable` checkout

The integrated Run Workflow was run on branch `sable`, commit `753a55b1daedc370f04a493eca31169e5083dc1a`. These are completed persisted runs from `POST /api/runs`; each has current SABLE evidence with valid integrity, a candidate snapshot matching the run, and an input hash matching its SABLE `module.started` event.

| Scenario | Run ID | SABLE result | Final ASENT gate | SABLE evidence binding |
|---|---|---|---|---|
| `sable_preserved` | `b107fd8f0f2f` | `PRESERVED` ? exact modeled least privilege holds. | `REVIEW` ? SATRA was `INCONCLUSIVE`; this is not an overall `ACCEPT`. | Integrity valid; snapshot and input hash match. |
| `sable_regressed` | `5c6fe1aa3a96` | `REGRESSED` ? authorization targets the wrong bucket. | `BLOCK` ? SABLE `REGRESSED`; SATRA was also `INCONCLUSIVE`. | Integrity valid; snapshot and input hash match. |
| `sable_unknown` | `b6d3588ec006` | `UNKNOWN` ? successor scores were too close for a unique attribution. | `REVIEW` ? SABLE `UNKNOWN` and SATRA `INCONCLUSIVE`. | Integrity valid; snapshot and input hash match. |

The current-checkout captures are `reports/evidence/sable_mid_rehearsal_sable_preserved.png`, `reports/evidence/sable_mid_rehearsal_sable_regressed.png`, and `reports/evidence/sable_mid_rehearsal_sable_unknown.png`. The first two show the completed decisions. The unknown capture is an **intermediate UI state**: it displays SABLE `UNKNOWN`, valid evidence binding, and a `REVIEW` gate headline, but its gate explanation still reads `Candidate frozen; waiting for current evidence`, and CAVR still reads `NO CURRENT EVIDENCE`. The persisted run later reached `COMPLETE`; its final gate record is `REVIEW` for `SATRA: INCONCLUSIVE` and `SABLE: UNKNOWN`. A fresh browser capture was attempted, but the browser runtime failed to initialize (`failed to write kernel assets: The system cannot find the path specified`). Do not present the existing unknown image as a completed final-gate explanation capture.

## What to point out in the SABLE trace

The **SHARED SABLE EXECUTION TRACE** uses the selected run's persisted shared-orchestrator SABLE evidence. Its Terraform excerpt comes from that run's `workspace.snapshot` event.

1. Expand **Terraform input excerpt from this run's shared snapshot event**. For the unresolved-role case, point to the `aws_iam_role_policy.dynamic_extra` block and its dynamic `role = var.additional_role` binding.
2. **Baseline verification** shows whether the registered principal/action/protected-asset obligation was known to hold on the trusted baseline. If evidence has no baseline verification, the UI says it was not recorded.
3. **Terraform parsing** reports graph node counts or parser issues from the recorded baseline/candidate graphs and parse errors.
4. **Correspondence / successor** shows the selected successor and recorded hypothesis count, or the actual correspondence reason when no successor was selected. In the ambiguous case, no projection is inferred after successor resolution fails.
5. **Obligation projection** reports the recorded `known`, `holds`, and reason values when projection evidence exists.
6. **Authorization evaluation** shows recorded policy grant details or the exact unresolved/unknown finding. The unresolved-role finding includes the policy resource address.
7. **Evidence binding** shows the evidence integrity result, candidate-snapshot match, the input hash, and its comparison with the SABLE start event.
8. Read the **SABLE verdict** separately from **Overall final gate** and the CAVR/SATRA/SABLE module outcomes. The preserved run is the clearest example: SABLE is `PRESERVED`, while the overall gate is `REVIEW` because SATRA is `INCONCLUSIVE`.

## Shared orchestrator and final gate

The shared Service determines applicable modules from candidate inputs and routes changed files to module input surfaces. CAVR analyzes dependency/security inputs, SATRA analyzes application/test-integrity inputs, and SABLE analyzes Terraform inputs. The Service runs applicable analyzers concurrently and publishes their evidence through the shared evidence store and event stream. The final gate consumes those module results; there is no direct sequential CAVR-to-SATRA-to-SABLE chain.

The final gate checks current evidence integrity and its candidate-snapshot and module-input-hash bindings. SABLE `PRESERVED` and `NOT_APPLICABLE` are acceptable outcomes, `REGRESSED` blocks, and `UNKNOWN` requires review. Other applicable module results also affect the aggregate decision.

## Screenshots and verified checks

These are captures of the actual rendered integrated Run Workflow page:

- `reports/sable-trace-sable_preserved.png`
- `reports/sable-trace-sable_regressed.png`
- `reports/sable-trace-sable_unknown.png`
- `reports/sable-trace-sable_unresolved_role_binding.png`

Checks actually verified for this vertical slice:

- `.venv/Scripts/python.exe -m pytest tests/test_modules.py -k sable -q` - **11 passed, 10 deselected**.
- `.venv/Scripts/python.exe -m pytest tests/test_integration.py::test_shared_sable_evidence_drives_final_gate -q` - **4 passed**.
- `npm run build` from `frontend/` - **passed**. Vite emitted a bundle-size advisory for the approximately 501 kB main JavaScript chunk.
- `git diff --check` - **passed**.

## Limits and unresolved role behavior

- On the native-Windows live runs represented here, SATRA returned `INCONCLUSIVE` with the recorded reason `Required knowledge disabled or template semantics unsupported`. This affects the overall gate: even the preserved SABLE run was `REVIEW`.
- SABLE's implemented scope is bounded to local Terraform modules, S3 buckets, inline IAM role policies, and the registered baseline obligation. Unsupported or unresolved semantics remain `UNKNOWN`.
- This is local static analysis of Terraform input. No AWS resources were created, and no deployed AWS state or live authorization behavior was verified.
- Terraform/Checkov are optional scans; their availability does not expand the supported SABLE semantics.

The unresolved case contains a valid inline policy for the registered role that satisfies the modeled obligation. It also contains a second broad inline policy whose role binding is the expression `var.additional_role`. The analyzer cannot establish whether that policy is unrelated to the registered principal, so it cannot safely ignore the policy or treat its permissions as absent. Persisted evidence records `aws_iam_role_policy.dynamic_extra: role binding unresolved`; SABLE therefore fails closed with `UNKNOWN`, and the shared final gate returns `REVIEW`.

## FYP-1 Mid rubric readiness audit — 2026-10-11

The criterion names and marks below come from `C:\Users\hp\Downloads\FYP-1-Mid-Assessment-Guidelines-and-Rubrics.pdf` (Form 2, pp. 1–2; Form 3, pp. 2–3). This is a SABLE contribution evidence audit, not a score or a claim that the team report is complete. “Satisfied” means the repository evidence covers that criterion for this bounded SABLE contribution; meeting-room performance and supervisor decisions remain for the supervisor to assess.

### Form 2 - Presentation and Demo

| Criterion | Status | Existing evidence | Smallest next action |
|---|---|---|---|
| 1. Previous proposal actions addressed (CLO6, 10) | **Unverified** | No completed Panel Action Register/Form 10 or authoritative panel action record was found in the repository, report source, or locally checked project documents. Appendix A remains explicitly pending. | Obtain the actual panel action list and record each action, owner, status, response, and evidence link. |
| 2. Iteration plan and work breakdown progress (CLO2, 10) | **Partially evidenced** | `reports/fyp1_mid_report/chapters/chapter3_iteration_plan.tex` identifies SABLE I1-I4 and completed prototype work; the runbook and report record the current rehearsal. No authoritative owner/date schedule or recovery log was found. | Confirm planned/completed dates, owners, and any recovery dates against the team's approved schedule. |
| 3. Live prototype with core module demo (CLO4, 25) | **Partially evidenced** | Three completed shared workflow runs are recorded above: `b107fd8f0f2f` PRESERVED/REVIEW, `5c6fe1aa3a96` REGRESSED/BLOCK, and `b6d3588ec006` UNKNOWN/REVIEW. Evidence integrity, candidate snapshot, and input hash are valid for all three. The retained UNKNOWN screenshot is an intermediate state, and an in-person live demonstration remains to be performed. | In the evaluation, rerun or open the persisted cases live and explain the SABLE result separately from the final gate. |
| 4. Requirements and acceptance criteria quality (CLO2, 10) | **Satisfied for the SABLE scope** | `chapter4_requirements.tex` defines numbered FR-S1-FR-S8 and acceptance checks. `test_sable_real_hcl`, `test_sable_refactor_and_correspondence_cases`, `test_sable_unsupported_iam_stays_unknown`, and `test_shared_sable_evidence_drives_final_gate` assert the required outcomes. | Be ready to explain one passing, one regression, and one uncertainty assertion. |
| 5. Design artefacts and design evolution (CLO3, 15) | **Partially evidenced** | `chapter5_design.tex` contains the SABLE architecture/process model and explains baseline verification, correspondence, authorization projection, evidence binding, and the final gate. The latest PDF pages could not be visually rendered in this audit because the available renderer files are inaccessible. | Visually verify the architecture and process pages with an accessible PDF renderer before relying on their layout in the presentation. |
| 6. Repository, milestone, and member evidence (CLO6, 10) | **Partially evidenced** | Chapter 9 and Appendix D connect SABLE changes to commits and the current `753a55b` head; the report attributes the SABLE contribution to its author. No team-wide task-owner log or confirmed contribution record for other modules was found. | Confirm task ownership and dates against authoritative team task/review records. |
| 7. Testing and early validation (CLO4, 10) | **Satisfied for the selected SABLE validation** | The correction-containing local selection reports 27 passed, 10 deselected; the earlier dedicated SABLE CI job reports 44 passed on `9a4dc3d`. The broader full-CI run had eight failures; its run link and per-failure details were not present in local records checked here. | Disclose that the broader CI was not green and avoid claiming a full-suite pass; verify the run and triage its failures before making broader readiness claims. |
| 8. Presentation, Q&A, team, and tool ownership (CLO5, 10) | **Unverified for team defense** | The report records Codex assistance for the SABLE work and report update. Repository records cannot establish live Q&A, balanced participation, or other members' tool use and independent understanding. | Each member should confirm their own tools and prepare to defend their own work; do not infer others' disclosures. |

### Form 3 - Report Evaluation

The current 84-page report PDF and editable source are in `reports/fyp1_mid_report/`; the compiled PDF and SABLE-specific runbook/evidence are also in `reports/ASENT_FYP1_Mid_Report_Team_Review.zip`. Report status below is limited to SABLE contribution evidence. Administrative completeness and team-wide claims remain pending where the checklist identifies them.

| Criterion | Status | Existing evidence | Smallest next action |
|---|---|---|---|
| 1. Report format and artefacts present (CLO2, 5) | **Partially evidenced** | `main.tex` builds an 82-page report and the package contains the editable sources, figures, PDF, runbook, and selected evidence. Signatures, declarations, coordinator/supervisor records, and other administrative fields still require confirmation. | Complete required institutional fields and confirm the prescribed submission artefacts. |
| 2. Problem formulation, R&D, and gap analysis (CLO1, 15) | **Partially evidenced** | `chapter1_introduction.tex` and `chapter2_research.tex` explain the refactoring-induced S3/IAM boundary problem and bounded research gap with cited related work. Independent verification of the sources and completeness of the team literature review remain open. | Verify bibliographic details and strengthen the comparative synthesis using authoritative sources. |
| 3. Project vision, scope, and success criteria (CLO2, 10) | **Partially evidenced** | Chapters 3-4 define SABLE I1-I4, the supported S3/IAM scope, explicit out-of-scope limits, and observable outcome criteria. Approved proposal actions and team-wide feasibility/schedule records were not located. | Confirm alignment against the approved proposal and actual panel decisions. |
| 4. Requirements and acceptance criteria (CLO2, 15) | **Satisfied for SABLE requirements** | Chapter 4 provides FR-S1-FR-S8 and acceptance checks traced to test names and expected PRESERVED, REGRESSED, UNKNOWN, and gate outcomes. | Keep the mapping synchronized if the supported scope changes. |
| 5. Architecture and component/interface design (CLO3, 15) | **Partially evidenced** | `chapter5_design.tex` includes a project-specific editable architecture diagram and component responsibility rationale tied to current implementation. Latest-page visual inspection is blocked because the available PDF renderer's package directories deny access. | Render and visually inspect the architecture page with an accessible renderer. |
| 6. Data/process/behavior design (CLO3, 10) | **Partially evidenced** | The design chapter documents the baseline-to-candidate flow, successor selection, authorization projection, evidence binding, and final-gate process. Visual rendering of the latest diagram page could not be completed in this environment. | Visually inspect the process/data model and confirm its page layout before submission. |
| 7. Implementation documentation (CLO4, 15) | **Satisfied for SABLE content** | Chapter 6 documents reproducible Windows setup/run commands, implementation files, algorithms, the chosen fail-closed decision, and supported-scope limits; Chapters 8-9 report actual validation. | Rehearse the documented setup on the presentation machine. |
| 8. Testing plan and tool/risk disclosure (CLO5, 15) | **Partially evidenced** | Chapter 8 records the exact 27-pass/10-deselected command, earlier 44-test SABLE CI, known limitations, and the broader run's eight failures. Chapter 9 discloses Codex use for this SABLE contribution and optional dependencies/risks. A local full-CI run link/details and other members' tool disclosures are unavailable. | Verify and record the broader CI failure details and collect each member's own tool/privacy disclosure. |

### SABLE mid milestones and acceptance trace

| Mid outcome | Implemented behavior | Acceptance evidence |
|---|---|---|
| I1 — candidate snapshot and evidence binding | Shared evidence records the candidate snapshot and SABLE input hash; the final gate checks current snapshot, input binding, and integrity. | `test_shared_sable_evidence_drives_final_gate` asserts snapshot equality, the recomputed SABLE input hash, `integrity_valid`, and the final decision. |
| I2 — supported Terraform/HCL normalization | Parses local modules, outputs/references, S3 buckets, and inline IAM role policies; unsupported constructs remain visible as uncertainty. | `test_sable_real_hcl`, `test_sable_refactor_and_correspondence_cases`, `test_sable_unsupported_iam_stays_unknown`, and `test_sable_unsupported_terraform_stays_unknown`. |
| I3 — baseline obligation verification | Verifies the registered role/action/protected-asset obligation on the trusted baseline before attributing a candidate result. | `test_sable_real_hcl` asserts baseline holds; `test_sable_unverified_baseline_and_empty_baseline` verifies an unproven baseline does not become a safe result. |
| I4 — successor correspondence and verdict | Uses structural/move evidence to select a successor; projects the obligation there and returns `PRESERVED`, `REGRESSED`, or `UNKNOWN`. | `test_sable_refactor_and_correspondence_cases` covers moves, wrong target, weakened action, and ambiguity; the shared final-gate test covers preserved/regressed/unknown/unresolved outcomes. |

Expected acceptance outcomes: supported, unique successor plus exact required actions/resources yields SABLE `PRESERVED`; a wrong target or missing required action yields `REGRESSED`; an ambiguous successor, unresolved role binding, unverified baseline, or unsupported policy semantics yields `UNKNOWN`. In the shared gate these map to `ACCEPT`/`BLOCK`/`REVIEW` only when other applicable evidence also permits that decision; another module can independently cause `REVIEW` or `BLOCK`.

### Architecture decision, reproducibility, and disclosure

The implemented decision chain is **trusted baseline verification → candidate HCL normalization → protected-asset correspondence → authorization projection on the selected successor → evidence publication → shared final gate**. This ordering is deliberate: checking whether a candidate policy is locally valid on some bucket can falsely call a refactor safe when the policy followed the wrong asset. The baseline obligation is therefore verified first, and candidate authorization is tested against its selected successor. `backend/orchestrator/service.py` binds and publishes the result; `backend/orchestrator/final_gate.py` rejects stale/invalid bindings and maps SABLE `REGRESSED` to `BLOCK` and unresolved `UNKNOWN` to `REVIEW`.

The two authorization evaluators have separate roles: `policy_semantics.evaluate` powers the shared analyzer and is limited to inline role policies; `authorization.evaluate_authorization` powers the standalone SABLE engine and covers additional policy forms. The audit found that the standalone evaluator ignored unresolved nonmatching role expressions such as `var.additional_role`, while the shared evaluator returned `UNKNOWN`. It now marks such a binding outside-model/unknown, while still ignoring a binding that resolves to a known different `aws_iam_role`. Regression coverage is in `test_sable_standalone_evaluator_fails_closed_on_unresolved_role_binding` and `test_sable_explicitly_unrelated_role_binding_is_ignored`.

On Windows, setup is `powershell -ExecutionPolicy Bypass -File .\scripts\setup.ps1`; start with `powershell -ExecutionPolicy Bypass -File .\scripts\start.ps1` and open `http://127.0.0.1:8000`. The focused verification command is:

```powershell
$testTemp = Join-Path $PWD ('.venv\.pytest-sable-' + [guid]::NewGuid().ToString('N'))
.venv\Scripts\python.exe -m pytest tests/test_modules.py tests/test_sable_isolation.py tests/test_integration.py::test_shared_sable_evidence_drives_final_gate -k sable --basetemp $testTemp -q
```

The fresh `--basetemp` is only needed on hosts where pytest's default temporary directory is inaccessible; use a new writable path for each run. Do not run Terraform `apply` or provide cloud credentials for this demo. Optional `terraform validate` and Checkov scans do not deploy anything and do not broaden the analyzer's supported semantics.

**Executed 2026-10-11:** `.venv\Scripts\python.exe -m pytest tests/test_modules.py tests/test_sable_isolation.py tests/test_integration.py::test_shared_sable_evidence_drives_final_gate -k sable --basetemp .venv\.pytest_sable_mid_audit_20261011_c -q` — **27 passed, 10 deselected in 47.26s; exit code 0**. The passing selection includes the four shared final-gate parameter cases. The default pytest temp root on this host was inaccessible, so this run used a fresh writable pytest temp directory. `git diff --check` was also run after the code edits.

**Tool disclosure for this audit/update only:** OpenAI Codex assisted with repository/rubric inspection, the narrowly scoped unresolved-role-binding correction and regression test, and this runbook update. The implementation decision and test outcomes were checked against the repository and executed tests. No generated screenshots, cloud credentials, AWS API calls, or Terraform apply were used for this update. This is not a complete disclosure of earlier work by every team member; the report's tool-use statement must be confirmed by the team.

### Proposal-action register and report blocker

The checked repository has no completed proposal action register. The downloaded report PDF is a template with empty action-register rows; that does not establish whether the proposal panel issued actions. The student/team must obtain the actual panel feedback or Form 10 and complete the register before claiming Form 2 Criterion 1 or Form 3 Appendix A is satisfied. Likewise, the actual FYP-1 mid report must be completed from the template before any Form 3 criterion can be represented as fully evidenced by this runbook.
