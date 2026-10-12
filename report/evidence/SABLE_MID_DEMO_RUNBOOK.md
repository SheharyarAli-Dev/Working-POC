# SABLE Mid Evaluation Demo Runbook

This runbook describes the shared ASENT Run Workflow demonstration on the Windows validation host. The recorded verdicts below are from completed live UI runs; catalog expectations and unit-test outcomes are not substituted for those runs.

## Start ASENT on Windows

The verified post-merge demo used `.worktrees/integration-test` at PR #5 head `554b6d51acca29f99c396c3040362015ee460262`, with the root Python 3.12 environment and an isolated data directory. From PowerShell in the repository root, start that same checkout and data set on port 4173:

```powershell
Set-Location .worktrees\integration-test
$env:ASENT_DATA = Join-Path $env:TEMP 'asent-codex-sable-c317a49dfbfb4fe3943587f157facbb8'
..\..\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 4173
```

Leave that terminal open while presenting and open `http://127.0.0.1:4173`. This isolated data directory preserves the two verified run records; it is temporary and may be cleared by Windows cleanup. For a fresh checkout without the prepared root environment, run `scripts/setup.ps1` from the project root, then use the integration worktree's launcher after confirming its dependencies and dashboard build are present. The standard root launcher binds port 8000 and runs the root checkout, so it is not the post-merge demo command documented here.

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

The final gate checks that each applicable module has current evidence with `integrity_valid` exactly `true` and matching candidate-snapshot and module-input-hash bindings. For SABLE, only `PRESERVED` is acceptable; `REGRESSED` blocks, while `UNKNOWN`, `NOT_APPLICABLE`, missing evidence, or failed bindings require review. A missing or empty baseline is reported as SABLE `UNKNOWN`, so it cannot authorize `ACCEPT`. Other applicable module results also affect the aggregate decision, and no applicable security surface yields `REVIEW`.

## Screenshots and verified checks

### Fresh post-merge browser demonstration — 2026-10-12

The React Run Workflow page was opened in Edge against the clean integration worktree at PR #5 head `554b6d51acca29f99c396c3040362015ee460262`, subsequently merged as `ffe8aa91ca89702e5db65b8f7ff129aa72f761cc`. Each scenario was selected and started with the dashboard controls. The completed runs and persisted evidence were then checked through the same local application.

| Scenario | Run ID | SABLE result | Overall ASENT gate | Persisted evidence check |
|---|---|---|---|---|
| `sable_preserved` | `21adc601d6b7` | `PRESERVED` — the baseline obligation holds, the unique successor is `module.storage.aws_s3_bucket.active_invoices`, and the modeled least-privilege grant holds. | `REVIEW` — SATRA was `INCONCLUSIVE`; this is not an overall `ACCEPT`. | Integrity valid; candidate snapshot matches; SABLE input hash matches the `module.started` event. |
| `sable_regressed` | `0849603bfc16` | `REGRESSED` — the candidate grant targets `module.storage.aws_s3_bucket.archive_invoices`, so the registered active-asset obligation does not hold. | `BLOCK` — SABLE `REGRESSED`; SATRA was also `INCONCLUSIVE`. | Integrity valid; candidate snapshot matches; SABLE input hash matches the `module.started` event. |

The preserved run's candidate snapshot is `061e827a28e19f5ff48fccb1743c0f317eb6c95438b34cab5981585d1f77b1a6`; its SABLE input hash is `96eba5d3cda77cb146829ed830019289665227d911d5a704bdb81b97d496a0a8`. The regressed run's candidate snapshot is `0221f7c23d207069ad1d52836b7e23f6a379c2a03fb399e973fbc423ff5d41c8`; its SABLE input hash is `ca4a063e06ecde6cd5b58c84d08019fc81188e06d08413d9da88bfcd1fbddf5b`. Both rendered traces showed baseline verification, parsed graphs, selected successor, obligation projection, authorization record, evidence integrity, snapshot/input-hash binding, module outcomes, and the separate final-gate reason.

The fresh rendered captures were saved outside the report evidence directory: `%TEMP%\asent-sable-preserved-live.png`, `%TEMP%\asent-sable-preserved-live-input.png`, and `%TEMP%\asent-sable-regressed-live.png`. They support the recorded live interactions; screenshots alone are not a substitute for the live demonstration.

SATRA was inconclusive on this Windows host. Its persisted evidence records `OSError: [WinError 10106] The requested service provider could not be loaded or initialized` while importing `asyncio.windows_events` / `_overlapped`. This explains the aggregate `REVIEW` and additional `BLOCK` reason; it does not change the SABLE verdicts. No AWS credentials, AWS API calls, or Terraform apply were used.

### Earlier rendered screenshots and checks

These are earlier captures of the actual rendered integrated Run Workflow page:

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

## FYP-1 Mid rubric readiness audit — 2026-10-12

The criterion names and marks below were checked against the official PDF `C:\Users\hp\Downloads\FYP-1-Mid-Assessment-Guidelines-and-Rubrics.pdf` (Form 2, pp. 1–2; Form 3, pp. 2–3); `report/sources/mid_guidelines_rubrics.txt` is only an extraction. This is a SABLE contribution evidence audit, not a score or a claim that the team report is complete. Statuses are `MET`, `PARTIAL`, `UNMET`, or `NOT VERIFIABLE` for the stated SABLE scope; supervisor scoring, team performance, and missing authentic records remain outside this evidence map.

### Form 2 - Presentation and Demo

| Criterion | Status | Existing evidence | Smallest next action |
|---|---|---|---|
| 1. Previous proposal actions addressed (CLO6, 10) | **PARTIAL for SABLE based on member confirmation** | The SABLE contributor reports that the proposal re-defense passed without remarks or major/minor modifications and that no SABLE-specific action was communicated. No written action record/Form 10 was found. This supervisor Form 2 criterion concerns the earlier proposal/re-defense; the current mid-evaluation is supervisor-assessed, not panel-assessed. | Ask the supervisor to confirm whether any earlier SABLE action was assigned; if none, record that confirmation. If an action was assigned, document its response and evidence. |
| 2. Iteration plan and work breakdown progress (CLO2, 10) | **MET for SABLE I1-I4 progress** | `chapter3_iteration_plan.tex` defines SABLE I1-I4 and records their implementation, focused test evidence, merged CI provenance, and live dashboard verification. This is the SABLE module contribution; it does not assert a team-wide dated schedule. | Present the four SABLE milestones and point to their implementation and acceptance evidence. |
| 3. Live prototype with core module demo (CLO4, 25) | **MET for the bounded SABLE demo** | The fresh browser runs above demonstrate preserved and wrong-target cases through the shared dashboard, including the trace and persisted evidence. The preserved case is SABLE `PRESERVED` / overall `REVIEW`; the wrong-target case is SABLE `REGRESSED` / overall `BLOCK`. | During evaluation, repeat the interaction and explain why SATRA also affects the aggregate gate. |
| 4. Requirements and acceptance criteria quality (CLO2, 10) | **MET for the bounded SABLE requirements** | `chapter4_requirements.tex` defines FR-S1–FR-S8 and traces them to named acceptance tests; the I1–I4 map below records observable outcomes. | Keep the requirement/test links current as scope changes. |
| 5. Design artefacts and design evolution (CLO3, 15) | **PARTIAL** | `chapter5_design.tex` contains the SABLE architecture/process model and explains baseline verification, correspondence, authorization projection, evidence binding, and the final gate. The latest PDF pages have not been visually inspected. | Rebuild and visually inspect the architecture and process pages before relying on their layout in the presentation. |
| 6. Repository, milestone, and member evidence (CLO6, 10) | **MET for SABLE contribution evidence** | Chapter 9 and Appendix D identify the SABLE milestones, author attribution, exact merged PR head, and passing checks. This status covers SABLE's contribution only and makes no claim about other members' records. | Show the SABLE commit history and merged PR provenance. |
| 7. Testing and early validation (CLO4, 10) | **MET for bounded SABLE validation** | The historical focused selection reports 27 passed, 10 deselected; all 18 checks passed on exact merged PR head `554b6d5`. The native-Windows full suite remains 1,400 passed, 36 failed, 10 skipped, and 12 setup errors; failures/errors are not passes. | Explain known limits and scope broader readiness claims to successful CI evidence. |
| 8. Presentation, Q&A, team, and tool ownership (CLO5, 10) | **NOT VERIFIABLE** | The report records Codex assistance for the SABLE work and report update. Repository records cannot establish live Q&A, balanced participation, or other members' tool use and independent understanding. | Each member should confirm their own tools and prepare to defend their own work; do not infer others' disclosures. |

### Form 3 - Report Evaluation

The report branch `report` contains the editable draft and eight uncommitted chapter/runbook edits for Maryam to review. A prior 162-page PDF build succeeded, but the latest edits have not been rebuilt or visually inspected; signatures, declarations, and team-wide administrative evidence remain pending. The statuses below concern only SABLE contribution evidence, not completion of the team report.

| Criterion | Status | Existing evidence | Smallest next action |
|---|---|---|---|
| 1. Report format and artefacts present (CLO2, 5) | **PARTIAL** | The editable draft and a prior 162-page PDF build are available; the latest eight local edits have not been rebuilt or visually inspected. Signatures, declarations, coordinator/supervisor records, and other administrative fields still require confirmation. | Rebuild and inspect the report, complete required institutional fields, and confirm prescribed artefacts. |
| 2. Problem formulation, R&D, and gap analysis (CLO1, 15) | **PARTIAL for SABLE** | The current report identifies SABLE's problem and intended research direction, but its research synthesis and source verification are not complete in the report. Earlier pre-redéfense design documents are unconfirmed background, not evidence of an approved or complete literature review. | Have the report owner complete and verify the SABLE-relevant research synthesis in the report; keep B0-B4 evaluation described as future work until performed. |
| 3. Project vision, scope, and success criteria (CLO2, 10) | **MET for SABLE scope and success criteria** | Chapters 1, 3, and 4 state the S3/IAM obligation, supported Terraform subset, out-of-scope boundaries, I1-I4, and testable PRESERVED/REGRESSED/UNKNOWN outcomes. | Explain the bounded scope and its relationship to the approved proposal. |
| 4. Requirements and acceptance criteria (CLO2, 15) | **MET for SABLE requirements** | Chapter 4 provides FR-S1–FR-S8 and acceptance checks traced to test names and expected PRESERVED, REGRESSED, UNKNOWN, and gate outcomes. | Keep the mapping synchronized if the supported scope changes. |
| 5. Architecture and component/interface design (CLO3, 15) | **PARTIAL** | `chapter5_design.tex` includes an editable architecture diagram and component rationale tied to implementation. The latest report pages and diagram have not been visually inspected. | Rebuild and visually inspect the architecture page before submission. |
| 6. Data/process/behavior design (CLO3, 10) | **PARTIAL** | The design chapter documents baseline verification, successor selection, authorization projection, evidence binding, and final-gate behavior. The latest diagram page has not been visually inspected. | Rebuild and visually inspect the process/data model and page layout. |
| 7. Implementation documentation (CLO4, 15) | **MET for SABLE content** | Chapter 6 documents Windows setup/run commands, implementation files, algorithms, the fail-closed decision, and supported-scope limits; Chapters 8-9 report validation. | Rehearse the documented setup on the presentation machine. |
| 8. Testing plan and tool/risk disclosure (CLO5, 15) | **PARTIAL for SABLE pending author disclosure confirmation** | Chapter 8 records focused validation, merged exact-head CI, native-Windows results, and SABLE's model limits. Chapter 9 and this runbook record Codex, Edge, and GitHub Actions use for the SABLE contribution; the SABLE author must confirm completeness of earlier tool and data-handling disclosures. | Confirm the SABLE author's full tool-use and data-handling statement before submission. |

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

**Tool disclosure for this continuation:** OpenAI Codex assisted with repository/rubric inspection, the live dashboard demonstration, and this evidence update. Edge rendered the dashboard and completed the two recorded workflows; screenshots were saved under `%TEMP%` as listed above. No AWS credentials, AWS API calls, or Terraform apply were used. This does not disclose earlier work by every team member; the report's tool-use and privacy statements still require team confirmation.

### Prior proposal actions (supervisor verification)

The SABLE contributor reports that the proposal re-defense passed without remarks or major/minor modifications and that no SABLE-specific action was communicated. Chapter 3 records this as member recollection, not as an official action record. Form 2 is assessed by the supervisor at mid-evaluation; Criterion 1 concerns earlier proposal actions, not a panel convened for the mid-evaluation. The supervisor should confirm whether any earlier SABLE action was assigned. Other members' feedback and actions remain their responsibility; blank template rows are not evidence either way.
