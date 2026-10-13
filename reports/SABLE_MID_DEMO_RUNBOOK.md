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

### Form 2 — Presentation and Demo

| Criterion | Status | Existing evidence | Smallest next action |
|---|---|---|---|
| 1. Previous proposal actions addressed (CLO6, 10) | **Unverified** | No completed Panel Action Register/Form 10 was found in the repository or local report files checked. The mid-report template's Appendix A is an instruction, not a populated register. | Obtain the supervisor/panel's actual action list; record each action, status, owner, and evidence link. Do not infer that there were no actions. |
| 2. Iteration plan and work breakdown progress (CLO2, 10) | **Partially evidenced** | SABLE scope and scenario coverage are recorded in this runbook; the supplied SABLE research design is at `C:\Users\hp\Downloads\SABLE_Final_Research_Design_and_Architecture_FINAL.docx`. No current owner/date/recovery task log is in the repository. | Add actual planned/complete dates, owners, and any recovery dates to the report from the team's plan. |
| 3. Live prototype with core module demo (CLO4, 25) | **Partially evidenced** | Windows setup/run steps and prior rendered Run Workflow captures are listed above; current code exposes the integrated workflow and the four SABLE cases. The rubric requires a live demonstration, so screenshots are supporting evidence only. | During evaluation, execute preserved, regressed, and unknown cases live; show SABLE evidence and the separate final-gate decision. |
| 4. Requirements and acceptance criteria quality (CLO2, 10) | **Partially evidenced** | `tests/test_modules.py` and `tests/test_integration.py` verify specific SABLE outcomes; the runbook records observable scenario outcomes. A numbered SABLE FR/NFR-to-test trace is not in the report. | Add a short requirement/acceptance table to the report using the I1–I4 mapping below. |
| 5. Design artefacts and design evolution (CLO3, 15) | **Partially evidenced** | `backend/sable/analyzer.py`, `backend/sable/hcl_parser.py`, `backend/sable/correspondence.py`, `backend/sable/policy_semantics.py`, and `backend/orchestrator/final_gate.py` show the implemented components; `docs/implementation-notes.md` records a design decision. No completed SABLE design model was found in the mid-report PDF. | Add one current component/process diagram and explain the baseline-to-correspondence-to-projection decision in the report. |
| 6. Repository, milestone, and member evidence (CLO6, 10) | **Partially evidenced** | Git history includes the `proposal-poc` tag and SABLE feature/fix/test commits (for example `7794c61`, `cc86b30`, `7a965b8`, `da8ac29`); this shows code history, not a complete member task log. | Add verified member-owned tasks and evidence links; confirm member attribution against the team's records. |
| 7. Testing and early validation (CLO4, 10) | **Satisfied for the SABLE test evidence** | The focused run recorded below executes HCL/refactor, fail-closed, isolation, and shared final-gate cases. Regression tests cover preserved, wrong-target, weakened, ambiguous, and unresolved cases. | In the meeting, explain at least one failure/unknown case and its limitation; cite this run's exact output. |
| 8. Presentation, Q&A, team, and tool ownership (CLO5, 10) | **Unverified** | Code history and this runbook support technical ownership; they cannot establish balanced live participation or each member's independent defense. | Agree who explains each owned module and have each member independently defend their code, test, tool use, and limits. |

### Form 3 — Report Evaluation

The local file named `F26_FYP1_Mid_Report_LaTeX_Complete.pdf` is a report template, not a completed SABLE mid report: it still has a placeholder abstract (p. 14), section instructions (for example pp. 24–27 and 34–40), and an empty Appendix A action-register table (p. 26). No completed SABLE report was found in this repository. The statuses below therefore describe supporting repository evidence, not report completion.

| Criterion | Status | Existing evidence | Smallest next action |
|---|---|---|---|
| 1. Report format and artefacts present (CLO2, 5) | **Unverified** | The local PDF remains a template with placeholder title/signature and unfilled sections; the repository contains this runbook, not the prescribed completed report. | Complete the prescribed report, required declarations/signatures, and referenced appendices. |
| 2. Problem formulation, R&D, and gap analysis (CLO1, 15) | **Partially evidenced** | The supplied SABLE research design records the proposed gap and contribution; `docs/implementation-notes.md` states evidence-boundary decisions. Those materials are not a completed critical literature synthesis in the mid report. | Write the report's project-specific literature comparison, defensible gap, and complex computing challenge with cited sources. |
| 3. Project vision, scope, and success criteria (CLO2, 10) | **Partially evidenced** | This runbook bounds SABLE to local Terraform modules, S3, inline IAM role policies, and the registered obligation; the tests establish measurable outcomes. The report scope/success section is still a prompt. | Add a scope table with in-scope/out-of-scope cases and testable success measures consistent with the approved proposal. |
| 4. Requirements and acceptance criteria (CLO2, 15) | **Partially evidenced** | The runbook and tests provide executable outcome checks, but the report template's requirements and traceability sections are unfilled. | Add numbered SABLE FR/NFR requirements and link each to its acceptance test below. |
| 5. Architecture and component/interface design (CLO3, 15) | **Partially evidenced** | The current component boundaries and shared API path are visible in code and described above; the supplied design is external to this checkout. No completed report diagram/interface contract was found. | Draw the current component/interface diagram from the implemented flow and explain changes from the approved design. |
| 6. Data/process/behavior design (CLO3, 10) | **Partially evidenced** | The workflow trace and evidence records expose snapshots, hashes, correspondence, projection, and gate decisions; the report has no completed process/data artefact. | Add and explain one project-specific process/sequence or evidence-data model in the report. |
| 7. Implementation documentation (CLO4, 15) | **Partially evidenced** | The Windows run instructions, SABLE component paths, shared flow, design rationale, and test command are documented in this runbook. The report's implementation chapter remains a placeholder. | Transfer the concise setup, file/algorithm description, and design trade-off below into the report's implementation chapter. |
| 8. Testing plan and tool/risk disclosure (CLO5, 15) | **Partially evidenced** | Executed results and bounded-scope risks are recorded here and in `docs/external-tool-checks.md`. This update discloses its own Codex assistance below; the full team GenAI/external-tool history and privacy statement are not verified. | Add the complete team-confirmed test plan/results, external dependencies/tools, GenAI use by author, privacy handling, and limitations to the report. |

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
