# CAVR report notes

## Step 0 — Refuse host execution of unpinned package source (2026-10-10)

Plan commit 0, `fix(cavr): refuse host execution of unpinned package source`.
Status: committed by Maryam on 2026-10-10 as `3be14db`.
Four reviewer passes were run. Pass 4 reviewed the pass-3 fixes; its findings and their outcomes
are listed under "Reviewer pass 4" below. The pass-4 changes (one test and these notes) have not
been reviewed again.

### Ch 6 Implementation

| File | Function / field | What it does |
|---|---|---|
| `backend/cavr/sandbox_runner.py` | `SandboxRunner.run` | Host fallback removed. The only processes it can start are `docker --version` and `docker run`. No Docker, or no usable report from the container, returns an UNRESOLVED report. The old made-up fallback report (`network_attempts: 1`, verdict BLOCK) is deleted. A `timed_out` flag is set when the container is killed at the deadline; the report is then not read at all. The timeout log prints the real `timeout_seconds`. |
| | `get_docker_command` | Ends with the image name and `/pkg` only, because the image `ENTRYPOINT` already is `python /opt/asent/harness.py`. The seccomp profile is passed as an absolute path. |
| | `SECCOMP_PROFILE` | Module constant: `<repo>/docker/asent-seccomp.json`, built from `__file__`. |
| | `_docker_available` | The Docker probe, moved into its own method so tests can replace it. |
| | `_unresolved_report` | Builds the not-observed report: `verdict: "UNRESOLVED"`, `metrics: None`, `hash: None`, one `NOT_OBSERVED` event. |
| | `_extract_report` | Returns a report only if the output has exactly one START and one END marker, START comes before END, and the JSON between them is an object; otherwise `None`. |
| | `_has_duplicate_markers` | True when more than one START or END marker is present; `run` then logs a security alert. |
| | result fields `observed`, `isolation` | `observed = bool(report)`, the same test used to decide replacement. `isolation` is `"none"` without Docker, `"container"` only when `observed` is true, otherwise `"container_failed"`. |
| | imports | Unused `os`, `shutil`, `sys`, `tempfile` and `from backend.config import ROOT` removed. |
| `backend/cavr/counterfactual.py` | `baseline_behaviors(report)` | New module-level function; turns one sandbox report into behaviours. Replaces the inline check that read only two metrics. Each counter must be an `int` that is `>= 0`. |
| | `_not_observed`, `_violation` | Small builders for the two behaviour shapes. |
| | `CounterfactualEngine.run_exploration_loop` | If the baseline run is not observed, runs 1..n are skipped, `stop_reason` is `"baseline not observed"`, and every trigger is listed as residual uncertainty with that reason. An unobserved baseline has `cumulative_coverage` 0.0, and NOT_OBSERVED is left out of `new_behaviors`, `new_count`, `cumulative_count` and the `comparison` counts (it stays in `behaviors_found`). |
| `backend/cavr/causal_graph.py` | `build_causal_graph` | Default is UNRESOLVED. Any `VIOLATION` behaviour gives REJECTED. An `UNRESOLVED` behaviour or a `verdict_impact` outside `KNOWN_VERDICT_IMPACTS` gives UNRESOLVED. VERIFIED needs at least one `NEUTRAL` behaviour. `clean_message` is returned only for VERIFIED. A third `honesty_wording` for UNRESOLVED. |
| | `KNOWN_VERDICT_IMPACTS` | `("NEUTRAL", "VIOLATION", "UNRESOLVED")`. |
| `tests/test_cavr_sandbox_runner.py` | new, 483 lines | 33 test functions, 76 cases. |
| `docs/cavr-m1-plan.md` | | One line under commit 0 (`sandbox.py` out of scope), `docs/report-notes/` added to the allowed paths, and a "Known issues deferred" section. |
| `CLAUDE.md` | | "Report notes" section; `docs/report-notes/` added to the scope line. |
| `.claude/commands/cavr-step.md` | | Report-notes step added, placed above "Do not start the next commit." |
| `.claude/agents/cavr-reviewer.md` | | Reviewer classifies findings as BLOCKER or MINOR; "OK to commit" is allowed with MINOR items open. Maryam's edit. |

Key algorithm, `baseline_behaviors`:

1. Report is not a dict, `metrics` is not a dict, any of the five metric keys is missing, or a value has the wrong type or is negative (four counters must be `int >= 0`, `honeytoken_accessed` must be `bool`) -> `NOT_OBSERVED`.
2. Any counter above zero, `honeytoken_accessed` true, or report verdict `BLOCK` -> `VIOLATION`.
3. Otherwise `test_passed` is not `True` or verdict is not `ALLOW` -> `NOT_OBSERVED`.
4. Only then: one `NEUTRAL` clean-import behaviour.

Verdict order in `build_causal_graph`: REJECTED (any violation, or the two hardcoded package
names), then UNRESOLVED (unobserved run or unknown impact), then VERIFIED (at least one NEUTRAL),
else the default UNRESOLVED.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| No Docker -> UNRESOLVED, package not executed | Keep the host run with the Python audit hook | The audit hook is not isolation; untrusted code ran with the user's rights. CLAUDE.md: unknown -> UNRESOLVED. |
| `metrics: None` in the unresolved report | Zeros | Zero would claim "observed, and nothing happened". |
| A missing metric key is "not observed" | `.get(key, 0)` as before | A missing key is not a measurement of zero. |
| A negative counter is "not observed" | Treat as zero; treat as a violation | `-1` is not a count, so the report is malformed. Nothing bad was observed either, so not REJECTED. |
| Failed import or non-ALLOW verdict -> NOT_OBSERVED | REJECTED | Nothing bad was seen, but the package was not exercised either; REJECTED needs an observed violation. |
| Forged report: reject output with more than one marker | (a) take the last marker pair, (b) per-run random marker with a small `harness.py` edit, (c) runner-only random marker | Chosen by Maryam. No `harness.py` change; catches a forged report printed before or after the real one, which last-pair alone misses. Per-run marker deferred to M2. |
| Timed-out run: do not read the report at all | Read it if it looks complete | A run that had to be killed did not finish; a report printed before the kill may be the package's own. |
| `isolation` has three values | Two values (`container` / `none`) | "container" claimed isolation for runs where no container produced anything (image missing, launch failed). |
| VERIFIED needs a NEUTRAL behaviour; default UNRESOLVED | Keep VERIFIED as the default | VERIFIED was reachable with no runs, no behaviours, or an impact the builder does not know. |
| Seccomp path built from `__file__` | Relative `asent-seccomp.json`; path from an environment variable | The relative path only works when the current directory is `docker/`. |
| NOT_OBSERVED kept in `behaviors_found`, dropped from counts | Drop it everywhere | The verdict needs it; the counts and coverage are about observed behaviour. |
| Stop the loop when the baseline is not observed | Keep running 1..n | Those runs never call the sandbox and would add "evaluated safely" evidence for something never observed. |
| `backend/cavr/sandbox.py` keeps its host mode | Remove it too | Maryam's decision: it is the hash-pinned inert lab path, covered elsewhere. Recorded in the plan. |

Removed from `build_causal_graph` while making UNRESOLVED the default: the branch
`len(triggers) > 2 and not observed_runs -> UNRESOLVED` (now covered by the default) and the branch
that set VERIFIED when a contract row had `status == "REQUIRED"` (VERIFIED without any observed run).

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository. The only CAVR requirement list is FR-1..FR-10
and NFR-1..NFR-2 in `frontend/src/components/cavr/RequirementsTab.tsx`. The IDs below are from that
list; **Maryam to confirm them against the SRS.**

| ID (RequirementsTab.tsx) | Name there | What this step does for it | Acceptance check |
|---|---|---|---|
| FR-4 | Adaptive Counterfactual Activation | An unobserved baseline stops the loop and reports no coverage and no behaviours | `test_unobserved_baseline_stops_the_loop_and_leaves_all_triggers_residual`, `test_unobserved_baseline_reports_zero_coverage_and_zero_counts` |
| FR-6 | Fail-Closed Security Policy | Unobserved, unknown or missing evidence gives UNRESOLVED, never VERIFIED | `test_unobserved_run_makes_the_verdict_unresolved`, `test_without_observed_neutral_evidence_the_verdict_is_unresolved` |
| NFR-1 | Non-Root Isolation | Package code runs only inside the container; never on the host | `test_no_docker_executes_nothing_and_is_unresolved`, `test_docker_launch_failure_does_not_fall_back_to_host` |

Plan commit 0 also asks for "no-Docker run executes nothing" (the autouse `no_real_processes`
fixture records zero process launches) and "failed container run does not fall back to the host"
(exactly one launch attempt, and it is `docker`).

### Ch 7 Test cases

All in `tests/test_cavr_sandbox_runner.py`. Result column: run on 2026-10-10 after the pass-4 change.

- `.venv/bin/python -m pytest -q tests/test_cavr_*.py` -> 82 passed (76 in this file, 6 in `test_cavr_targeted.py`). Re-run after the pass-4 change.
- `.venv/bin/python -m pytest -q` -> 140 passed, 7 failed. Last run during pass 4, before the pass-4 test change; not re-run after it.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_no_docker_executes_nothing_and_is_unresolved` | No host execution without Docker | Docker probe false | No process started; UNRESOLVED; `isolation` "none" | pass |
| `test_docker_launch_failure_does_not_fall_back_to_host` | No fallback when launch fails | `Popen` raises `OSError` | One `docker` attempt only; UNRESOLVED; `isolation` "container_failed" | pass |
| `test_container_output_without_report_is_unresolved` | Output with no report | "Unable to find image" text | UNRESOLVED; `isolation` "container_failed" | pass |
| `test_docker_command_matches_the_image_entrypoint` | Command matches the Dockerfile | `get_docker_command` | Ends `asent-sandbox /pkg`; no `python`; seccomp path absolute and an existing file | pass |
| `test_container_report_is_passed_through_unchanged` | Real report is not altered | Framed BLOCK report | Same report; `observed` true; `isolation` "container"; `--network none` in command | pass |
| `test_timeout_kills_the_container_and_is_unresolved` | Timeout path | Process never exits, `timeout_seconds = -1` | `kill()` called; UNRESOLVED; log says "timeout of -1 seconds" | pass |
| `test_report_printed_before_the_deadline_then_hang_is_unresolved` | Forged report then hang | Full clean report read, then the clock passes the deadline | Whole report was read; `kill()` called; UNRESOLVED; "container_failed" | pass |
| `test_unusable_report_is_unresolved` (8 cases) | Bad report framing | Malformed JSON, list, string, START only, END only, `{}`, END before START (2) | UNRESOLVED | pass |
| `test_forged_report_printed_by_the_package_is_not_trusted` (2) | Forged report | Forged clean report before / after the real one | UNRESOLVED and alert logged | pass |
| `test_docker_probe_is_false_when_binary_is_missing` | Probe failure | `FileNotFoundError` | `False` | pass |
| `test_docker_probe_follows_the_return_code` (3) | Probe return code | Return codes 0, 1, 127 | `True`, `False`, `False` | pass |
| `test_complete_clean_report_is_a_clean_import` | Happy path | Complete ALLOW report | One NEUTRAL behaviour | pass |
| `test_missing_or_non_dict_report_or_metrics_is_not_observed` (8) | Report shape | `None`, list, string, `{}`, metrics `None` / `{}` / list / string | NOT_OBSERVED | pass |
| `test_each_missing_metric_key_is_not_observed` (5) | Missing key | Each of the five keys removed in turn | NOT_OBSERVED | pass |
| `test_metric_of_the_wrong_type_is_not_observed` (4) | Wrong type | `None`, `"0"`, `True` as counter, `0` as flag | NOT_OBSERVED | pass |
| `test_each_nonzero_metric_is_a_violation_and_rejects` (5) | Each violation | One metric non-zero, verdict BLOCK | VIOLATION; graph REJECTED | pass |
| `test_nonzero_metric_is_a_violation_even_when_the_report_says_allow` (3) | Metrics beat the verdict string | One metric non-zero, verdict ALLOW | VIOLATION | pass |
| `test_negative_counter_is_not_observed` (4) | Negative counter | Each counter set to `-1` | NOT_OBSERVED | pass |
| `test_verdict_block_with_zero_metrics_is_a_violation` | Harness BLOCK respected | Verdict BLOCK, zero metrics | `SANDBOX_BLOCK`; REJECTED | pass |
| `test_failed_or_unallowed_run_with_zero_metrics_is_not_observed` (5) | Not exercised | `test_passed` false / `1`; verdict NEEDS_REVIEW / `None` | NOT_OBSERVED | pass |
| `test_unobserved_baseline_is_not_reported_as_clean_import` | Engine, no Docker | Probe false | Baseline is NOT_OBSERVED | pass |
| `test_unobserved_baseline_reports_zero_coverage_and_zero_counts` | Coverage and counts | No Docker, no triggers | Coverage 0.0; `new_count`, `cumulative_count` and all three `comparison` counts 0 | pass |
| `test_unobserved_baseline_with_triggers_reports_zero_coverage` | Coverage with triggers | No Docker, 2 triggers | Coverage 0.0 | pass |
| `test_observed_clean_baseline_keeps_its_coverage_and_counts` | Fix does not over-fire | Clean report, no triggers | Coverage 100.0; counts 1 | pass |
| `test_container_report_with_empty_metrics_is_not_reported_as_clean_import` | Empty metrics | Report with `"metrics": {}` | NOT_OBSERVED; graph UNRESOLVED | pass |
| `test_unobserved_baseline_stops_the_loop_and_leaves_all_triggers_residual` | Loop guard | 2 triggers, `max_runs=4`, no Docker | 1 run; stop reason "baseline not observed"; T1, T2 residual | pass |
| `test_observed_clean_baseline_still_explores_triggers` | Guard does not over-fire; pins that run 1 is not a sandbox run | Clean report, 1 trigger (T2) | 2 runs; no residual; exactly 1 `docker` launch (run 1 is legacy fabricated evidence, removed in step 13) | pass |
| `test_unobserved_run_makes_the_verdict_unresolved` | Graph rule | One NOT_OBSERVED behaviour | UNRESOLVED / NEEDS_REVIEW; no `clean_message` | pass |
| `test_observed_violation_still_wins_over_unobserved_run` | Rule order | NOT_OBSERVED + SECRET_ACCESS | REJECTED | pass |
| `test_observed_clean_run_is_verified` | Positive evidence verifies | One NEUTRAL behaviour | VERIFIED | pass |
| `test_without_observed_neutral_evidence_the_verdict_is_unresolved` (7) | No default VERIFIED | No runs; no behaviours; no `behaviors_found` key; unknown impact; missing impact; clean + unknown; clean + missing | UNRESOLVED / NEEDS_REVIEW | pass |
| `test_required_contract_row_alone_does_not_verify` | Removed contract branch | `REQUIRED` contract row, no runs | UNRESOLVED | pass |
| `test_violation_still_wins_over_unknown_impact` | Rule order | Unknown impact + SECRET_ACCESS | REJECTED | pass |

The 7 full-suite failures are `tests/test_api_replay.py` (1) and `tests/test_integration.py` (6).
They were failing before this step (plan baseline: 64 passed, 7 failed; 64 + 76 new cases = 140)
and are outside the CAVR scope.

No test starts a real process or uses the network. The real Docker path is not exercised by any
test. The pass-3 tests were written together with the fixes; they were not first run against the
unfixed code.

### Defects found and fixed

**Before review.** Empty metrics (`"metrics": {}`) still read as a clean import. Fixed, with a test.

**Reviewer pass 1** (verdict: changes needed, small; 11 tests passed at that point).
The pass-1 report is not stored in the repository, so this table **cannot be checked from the repo**;
it is recorded as written during the session.

| # | Finding | Outcome |
|---|---|---|
| 1 | Partly observed run still became "Clean module import" then VERIFIED: only two metrics were read; verdict, `test_passed`, `processes_spawned`, `writes_outside_scratch`, `secrets_touched` ignored; missing keys read as zero | Fixed: `baseline_behaviors` |
| 2 | Non-dict report or metrics raised an exception instead of resolving | Fixed: `_extract_report` returns a dict or `None`; non-dict metrics -> NOT_OBSERVED |
| 3 | `observed` could be true on an UNRESOLVED report | Fixed: same truthiness test for both |
| 4 | `clean_message` said "No prohibited path found" for UNRESOLVED | Fixed: only for VERIFIED |
| 5 | `isolation` was "container" when the launch itself failed | Fixed with a `started` flag; replaced in pass 3 |
| 6 | Consumers show NOT_OBSERVED as clean (`CounterfactualTab.tsx`, `normalizer.py`, `api.py` wording) | Deferred to step 13 |
| 7 | Runs 1..n never call the sandbox and recorded "evaluated safely" after an unobserved baseline | Fixed: loop stops; triggers become residual uncertainty |
| 8–12 | Test weaknesses: marker-file assertions proved nothing; only `Popen` patched; `hasattr(sys)` proxy; missing cases; legacy default pinned without comment | Fixed: launchers patched and checked at teardown; cases added. 11 -> 50 tests |
| S | Suspected: report forgery through shared stdout | Partly fixed: more than one marker -> UNRESOLVED. Remainder deferred to M2 |
| S | Suspected: timeout not enforced on a silent container; kill stops the docker CLI, not the container | Deferred to M2 sandbox |
| S | Suspected: `harness.py` never imports a `.whl` yet reports `test_passed: True`; `image_digest` is a hardcoded constant | Deferred to step 13 / M2 |

Also added while fixing, not asked for by the reviewer: `build_causal_graph` rejects on any
VIOLATION (before, only SECRET_ACCESS and NETWORK_CONNECT rejected, so the new violations from
item 1 would still have come out VERIFIED), and the metric type checks.

**Reviewer pass 2** (verdict: changes needed; 50 passed; full suite 114 passed, 7 failed).
Findings checked by reading the code, not by execution. All were still open at pass 3 and are
closed by the pass-3 fixes below.

**Reviewer pass 3** (verdict: needs changes; 56 CAVR tests passed; full suite 114 passed, 7 failed).
Item numbers are the ones Maryam used when asking for the fixes.

| # | Finding | Outcome |
|---|---|---|
| 1 | A timed-out run whose report was already printed was still trusted | Fixed: `timed_out` flag, report not read. Test: `test_report_printed_before_the_deadline_then_hang_is_unresolved` |
| 2, 3, 12 | Report notes: no FR/NFR IDs cited; baseline written as 74 passed (it is 64); wording on reviewer passes, step 13, Q&A and pass-1 history | Fixed in these notes |
| 4 | `isolation` was "container" whenever the docker CLI launched | Fixed: "container" only when `observed`; else "container_failed"; "none" without Docker. Pinned assertion updated |
| 5 | Command repeated `python /opt/asent/harness.py` after an image whose `ENTRYPOINT` already runs it; seccomp path was relative | **Fixed by reading; not yet executed against Docker.** Test: `test_docker_command_matches_the_image_entrypoint` |
| 6 | Unobserved baseline reported coverage 100.0 and counted NOT_OBSERVED | Fixed: coverage 0.0, NOT_OBSERVED out of the counts |
| 7 | Negative counters passed as clean | Fixed: every counter must be `int >= 0`. Test: `test_negative_counter_is_not_observed` |
| 8 | Marker order not checked | Fixed: `None` unless START comes before END |
| 9 | `build_causal_graph` defaulted to VERIFIED for empty runs, empty behaviours, unknown impact | Fixed: default UNRESOLVED; VERIFIED needs a NEUTRAL behaviour |
| 10 | The plan's forgery bullet understated the single-forged-report gap | Fixed in `docs/cavr-m1-plan.md` |
| 11 | Tests: launchers not patched (`os.posix_spawn`, `os.spawn*`, `os.exec*`, `os.fork`), unused import, hardcoded "30 seconds", missing cases | Fixed: fixture patches them (and `os.popen`); the `sandbox_runner` import is now used; log prints `timeout_seconds`; cases added. 50 -> 76 cases |
| 13 | Invalid UTF-8 in container output: no kill, no wait | Deferred to M2 (plan, "Known issues deferred") |

Also raised in pass 3 and **not** changed in this step:

- `api.py` and `normalizer.py` still describe an unobserved run as executed ("Ran the package in isolated containers", `triggers_exercised: 1`, NOT_OBSERVED normalised to `FILE_READ`). The verdict is correct. Deferred to step 13 (first item of the plan's deferred list).
- `reports/scenario-validation.json` is rewritten by `tests/conftest.py` on every full-suite run. It is outside the scope and must not be staged with this step.

**Reviewer pass 4** (verdict: commit after fixes; 82 CAVR tests passed; full suite 140 passed, 7 failed).
Pass 4 reviewed the pass-3 fixes. It found no path in the changed code where a missing or broken
container ends in VERIFIED. Findings 1 and 3 were confirmed by reading the code, not by execution.

| # | Finding | Outcome |
|---|---|---|
| 1 | These notes claimed "nothing unobserved becomes VERIFIED", but two routes in the legacy dashboard path of `counterfactual.py` still give VERIFIED without observation (the `dormant-exfil` hardcoded baseline; fabricated trigger runs 1..n) | Code **not** changed (Maryam's decision). Notes reworded: guarantee line, Q&A 2, Known limitations. Both routes added to the plan's deferred list -> step 13 |
| 2 | Changed files outside the CLAUDE.md scope: `CLAUDE.md`, `.claude/commands/cavr-step.md`, `.claude/agents/cavr-reviewer.md`, `reports/scenario-validation.json` | The `CLAUDE.md` and `.claude/` edits are Maryam's, authorised by her, and are committed separately. `reports/scenario-validation.json` is a test side effect and was restored, not staged |
| 3 | The docker command fix has never been run; `docker/asent-sandbox/Dockerfile` copies `harness.py`, which is not in that directory | Recorded here and in the plan with the build command (not yet run). Real Docker verification deferred to M2 |
| 4 | `test_observed_clean_baseline_still_explores_triggers` pinned 2 runs and no residual without showing that run 1 never reaches the sandbox, and used `TRIGGERS[1:]` without explanation | Fixed: asserts exactly one `docker` launch; comment explains `TRIGGERS[1:]` and that run 1 is legacy fabricated evidence removed in step 13 |
| 5 | Notes inaccuracies: removed-imports line incomplete; `cavr-reviewer.md` missing from the Ch 6 table and tool disclosure; "pass-3 fixes not re-reviewed" out of date | Fixed in these notes |
| 6 | Proof drawer in `api.py` shows a stale docker command and a relative seccomp path | Deferred to step 13 (plan) |
| 7 | Harness `events` are ignored by `baseline_behaviors` | Deferred: metrics are authoritative for now; harness events to be used from M2 (plan) |
| 8 | Nits: long dict-literal line in `causal_graph.py`; absolute seccomp host path reaches the dashboard through `lockdown_flags` and `docker_command` | Not changed (Maryam's decision) |

### Known limitations / deferred

Recorded in `docs/cavr-m1-plan.md`, "Known issues deferred":

- NOT_OBSERVED displayed as clean by `CounterfactualTab.tsx`, `normalizer.py` and `api.py` wording. The verdict itself is correct. -> step 13. The plan gives the frontend only "small updates" in step 13, so this display fix has to be done there explicitly; it does not come for free.
- Timeout on a silent container and container kill. Needs sandbox work (`--name`, `docker kill`). -> M2 sandbox.
- `harness.py` `.whl` handling and the hardcoded `image_digest`. Maryam ruled out `harness.py` changes in this commit. -> step 13 / M2.
- Robust anti-forgery (per-run marker, out-of-band report channel). A single forged report is accepted when the harness's own is suppressed. Needs a `harness.py` change. -> M2 sandbox.
- Invalid UTF-8 in container output: no kill, no wait. -> M2 sandbox.
- `RequirementsTab.tsx` shows NFR-1 as a hardcoded PASS. -> step 13.
- **Two routes to VERIFIED without observation remain.** In the `sandbox_runner` path nothing unobserved becomes VERIFIED, but the legacy dashboard path in `counterfactual.py` still has two routes to VERIFIED without observation: the `dormant-exfil` hardcoded baseline (run 0 is a hardcoded NEUTRAL behaviour and the sandbox is never called) and the fabricated trigger runs 1..n (each records "Branch evaluated safely" without calling the sandbox). Both are removed in step 13. -> step 13.
- **The docker command fix is unexecuted.** `docker/asent-sandbox/Dockerfile` copies `harness.py`, which only exists in `backend/cavr`, so the image must be built with `backend/cavr` as the build context. Believed-correct command, from the repository root, **not yet run**: `docker build -f docker/asent-sandbox/Dockerfile -t asent-sandbox backend/cavr`. Real Docker verification is deferred until Docker is installed. -> M2.
- The proof drawer shows a stale command: `api.py` hardcodes `asent-sandbox python /opt/asent/harness.py /pkg/<name>.py` and a relative `seccomp=asent-seccomp.json`; neither matches what the runner executes. -> step 13.
- Harness `events` are ignored: `baseline_behaviors` reads only the five metrics, so zero metrics with non-empty `events` is a clean import. Metrics are authoritative for now; harness events are to be used from M2. -> M2.

Not on that list but true today:

- `README.md` builds a differently tagged image, `asent-sandbox:local`, from `docker/sandbox.Dockerfile`, which has no `ENTRYPOINT`. Which Dockerfile the `asent-sandbox` image on a given machine was built from is not checked anywhere; a mismatch ends UNRESOLVED.
- `backend/cavr/sandbox.py` still runs on the host for hash-pinned inert lab sources (deliberate).
- Pass 2 also listed more consumers that describe an unobserved run as executed (`StageDetailPanel.tsx`, `api.py` "Completed N container runs", certificate `triggers_exercised`), and that a REJECTED from the three new violation types carries no evidence line in `api.py`.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the edits to `sandbox_runner.py`, `counterfactual.py`, `causal_graph.py`, all of `tests/test_cavr_sandbox_runner.py`, the additions to `docs/cavr-m1-plan.md`, the scope line in `CLAUDE.md`, the line order in `.claude/commands/cavr-step.md`, and these notes. All four reviews were produced by the `cavr-reviewer` agent, a read-only Claude Code subagent.
- **Reviewed / decided by Maryam:** asked for the empty-metrics fix; ruled `sandbox.py` out of scope; read the reviewer reports; chose which pass-1 findings to fix and which to defer; chose "reject duplicate markers" out of four options for the forgery fix; ruled out changes to the frontend, `harness.py`, timeout behaviour and `image_digest`; for pass 3, wrote the list of items to fix and the fix for each (items 1–13 above). For pass 4, decided the outcome of each finding (table above), including leaving `counterfactual.py` unchanged. The edits to `CLAUDE.md`, `.claude/commands/cavr-step.md`, `.claude/commands/cavr-review.md` and `.claude/agents/cavr-reviewer.md` are Maryam's own, authorised by her, and are committed separately from this step. No hand-written changes by Maryam to the `backend/cavr/` code are recorded for this step. This account of who decided what comes from the sessions and cannot be checked from the repository.
- **Verified by:** pytest (76 cases in the new file, numbers above), full-suite comparison against the 7 pre-existing failures, and four reviewer passes; pass 4 reviewed the pass-3 fixes. Not verified: the real Docker path (the image has not been built and the docker command has not been run), and the pass-4 changes have not been reviewed again.

### Supervisor Q&A prep

1. **If the package shares stdout with the harness, why trust any report, and what does rejecting duplicate markers buy?**
   It turns a forged report printed before or after the real one into UNRESOLVED (two tests cover both orders), and a report followed by a hang is not read at all. It does not stop a package that prints one forged report and suppresses the harness's own; that needs a report channel the package cannot write to, deferred to M2.
2. **With Docker absent or the image misbuilt, every package is UNRESOLVED. How do you show the sandbox path ever gives a real VERIFIED?**
   Today we cannot: every test replaces `Popen`. The command was corrected to match the Dockerfile by reading, not by running Docker. What this step guarantees is the safe direction only, and only for the `sandbox_runner` path: there, nothing unobserved becomes VERIFIED, and nothing runs on the host. The legacy dashboard path in `counterfactual.py` still has two routes to VERIFIED without observation (the `dormant-exfil` hardcoded baseline and fabricated trigger runs 1..n); both are removed in step 13.
3. **Why is a failed import or a timeout NOT_OBSERVED rather than REJECTED?**
   REJECTED needs an observed violation. A failed import or a timeout shows the package was not exercised, which is "unknown", and the branch rule is unknown -> UNRESOLVED.

## Step 0b — Accept either monitor mode in controlled dormant execution (2026-10-10)

Plan commit 0b. One test changed; no product code changed.

### Ch 6 Implementation

| File | Change |
|---|---|
| `tests/test_modules.py::test_controlled_dormant_execution` | Two assertions that pinned `execution_mode == 'PINNED_INERT_LAB_PYTHON_AUDIT'` and `monitor == 'PYTHON_AUDIT'` are replaced by a lookup table `monitor_for` and a loop over both runs. Net +6 / -2 lines. |

No function, class or module was added. Key logic of the new check:

1. `monitor_for` lists the four execution modes `backend/cavr/sandbox.py::run_counterfactual` can produce
   (`PINNED_INERT_LAB_PYTHON_AUDIT`, `PINNED_INERT_LAB_STRACE`, `docker`, `podman`) and the monitor each one must report
   (`PYTHON_AUDIT` for the first, `strace` for the other three).
2. For the normal run and the counterfactual run: the `execution_mode` must be one of the four keys.
3. For the same two runs: `monitor` must equal the value listed for that `execution_mode`.

Unchanged, as the plan requires: `status == 'REJECTED'`, both exit codes 0, equal `functional_text`,
canary not received in the normal run and received in the counterfactual run, no `SECRET_ACCESS` in the
normal run, `causal_confirmed`, causal-graph `kind`, and trace files exist.

### Design decisions

| Decision | Alternatives | Why |
|---|---|---|
| Check the (execution mode, monitor) pair, not two independent "one of" lists | `assert mode in {...}` and `assert monitor in {'PYTHON_AUDIT','strace'}` separately | Separate lists would accept an inconsistent result such as Python-audit mode labelled `strace`. The pair check is as permissive about the machine and stricter about consistency. |
| Check both runs | Keep checking only the normal run, as before | Both runs are produced with the same `backend` and `use_strace` values in `sandbox.py`, so this costs nothing. The loop applies the same mode/monitor check to each run separately; it does not compare the two runs with each other. The old test did not check the counterfactual run's mode at all. |
| Do not force a mode by patching `availability()` | Monkeypatch tool availability so the test always runs Python-audit mode | The plan asks to accept either mode. Forcing one would hide the other mode's behaviour on machines that have strace or Docker. |
| Leave `causal_confirmed` as it is, although it fails under strace (see Defects) | Relax it to make the test green under strace | The plan says to change only the mode assertions. The failure is a real defect in `runtime_monitor.py`, not a test problem. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository (see Step 0). This step implements no requirement;
it changes how an existing test for FR-4 "Adaptive Counterfactual Activation" (ID from
`frontend/src/components/cavr/RequirementsTab.tsx`, **Maryam to confirm against the SRS**) treats the
machine it runs on. Acceptance check: `test_controlled_dormant_execution` no longer fails on the mode
assertions when strace is on `PATH`.

### Ch 7 Test cases

This machine has no strace, docker or podman installed. To exercise strace mode, a real strace 6.19
binary (Ubuntu package `strace_6.19+ds-0ubuntu5_amd64.deb`, with `libunwind8`) was unpacked into a
temporary directory with `apt-get download` + `dpkg -x` and put on `PATH` for single test runs. Nothing
was installed system-wide and nothing from it is in the repository.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_controlled_dormant_execution` (old assertions, no strace) | Baseline | Python-audit mode | pass | pass |
| `test_controlled_dormant_execution` (old assertions, strace on `PATH`) | Show the old test fails on a machine with strace | strace mode | fail on the mode assertion | fail, line 30: `'PINNED_INERT_LAB_STRACE' == 'PINNED_INERT_LAB_PYTHON_AUDIT'` |
| `test_controlled_dormant_execution` (new assertions, no strace) | Python-audit mode still accepted | Python-audit mode | pass | pass |
| `test_controlled_dormant_execution` (new assertions, strace on `PATH`) | strace mode accepted | strace mode | mode assertions pass | mode assertions pass; **the test still fails** later, at the unchanged `causal_confirmed` assertion (see Defects) |
| docker / podman pairs in `monitor_for` | Container modes accepted | Docker or Podman available | pass | **not run** (neither is installed) |

Suite runs after the change, without strace (the normal state of this machine):

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 82 passed.
- `.venv/bin/python -m pytest -q` -> 140 passed, 7 failed. The 7 are the baseline failures
  (`tests/test_api_replay.py` 1, `tests/test_integration.py` 6). No new failures.

Full suite with strace on `PATH`, run twice: 138 passed / 9 failed, then 139 passed / 8 failed. Both
include the 7 baseline failures and `test_controlled_dormant_execution`. The first run also failed
`tests/test_cavr_targeted.py::test_pinned_fixture_runtime_modes_and_counterfactual`; its failing
assertion was not captured. That test passed in the second full run, 4 of 4 times alone, and in a run of
the whole file (6 passed), all under strace.

### Defects found and fixed

Found while doing the step:

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Running the old test with real strace | The test required Python-audit mode, so it failed on any machine with strace | Fixed by this step (mode assertions only) |
| 2 | Running the new test with real strace | In strace mode no `NETWORK_CONNECT` event is recorded, so no threat correlation is produced and `causal_confirmed` is false. Events per run, lab package `scenarios/cavr_controlled/invoice_pdf_lab.py`: strace counterfactual = `EXECUTE_BINARY` 1, `FILE_READ` 203, `FILE_WRITE` 2, `SECRET_ACCESS` 1; Python-audit counterfactual = `FILE_READ` 116, `FILE_WRITE` 1, `SECRET_ACCESS` 1, `NETWORK_CONNECT` 1. Cause: `backend/cavr/runtime_monitor.py::normalize` skips every trace line containing ` = -1 `, and the connect in the real trace is `connect(4, {sa_family=AF_INET, sin_port=htons(18765), sin_addr=inet_addr("127.0.0.1")}, 16) = -1 EINPROGRESS`, a non-blocking connect that is in progress, not a failed one. The canary was still received (`canary_received` true) and the verdict was still `REJECTED`. | **Not fixed.** Outside commit 0b (test-only). Needs Maryam's decision on where it goes |
| 3 | Full suite with strace | `test_pinned_fixture_runtime_modes_and_counterfactual` failed once in two full runs under strace | **Not diagnosed.** Not reproduced alone |

Reviewed by cavr-reviewer (2 passes); verdict: fix first, BLOCKERs fixed; test change confirmed correct; 9 MINOR open, listed below.

| # | Level | Finding | Outcome |
|---|---|---|---|
| M1 | MINOR | 0b does not make the test green on a strace machine (still fails at `tests/test_modules.py:39`), and the plan's deferred list has no entry for it. Suggested a deferred entry or a new commit 0c | Open, no decision yet |
| M2 | MINOR | Defect 2 is wider than stated: `runtime_monitor.py:6` drops every failed syscall, so in a `--network none` container a failed connect or a failed open of a secret file leaves no event (from reading, not run) | Open, no decision yet. Notes wording not changed |
| M3 | MINOR | The cause of defect 2 is stated as proven, but no fix was tried, so it is not shown that it alone makes the test pass | Open. Notes wording not changed |
| M4 | MINOR | "no threat correlation is produced" should be "no correlation with `causal_confirmed` true"; the seed rules were not read | Open. Notes wording not changed |
| M5 | MINOR | Lead for defect 3, unverified: `lab_harness.py` listener has a 1.5 s accept timeout that may expire under `strace -f` or full-suite load | Open, not investigated |
| M6 | MINOR | `.claude/commands/cavr-batch.md` contradicts the plan's Working rules (Claude never commits; one commit at a time) | Open, Maryam's decision. Not part of 0b |
| M7 | MINOR | `reports/scenario-validation.json` was rewritten by the reviewer's full-suite run | Not staged; to be restored before staging |
| M8 | MINOR | The pair check is nearly tautological (both values come from the same variables in `sandbox.py`); no test feeds a recorded strace trace through `normalize` | Open, suggested with the defect-2 fix |
| M9 | MINOR | FR-4 mapping is loose: `RequirementsTab.tsx` ties FR-4 to `counterfactual.py`, this test exercises `analyzer.py` and `sandbox.py` | Open; "Maryam to confirm" kept |

### Known limitations / deferred

- `test_controlled_dormant_execution` is still red on a machine with strace, now for defect 2 instead of
  the mode check. The plan's sentence that the test "fails on any machine with strace or Docker" stays
  true until `normalize` handles `EINPROGRESS`.
- Docker and Podman modes were not executed. `sandbox.py` runs the same `strace` inside the container
  and uses the same `normalize`, so defect 2 is expected there too; this is read from the code, not run.
- The `monitor_for` table repeats mode names that `sandbox.py` holds as string literals. A new mode
  added there fails this test until the table is updated.
- This commit does not tick the 0b progress box in `docs/cavr-m1-plan.md`.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the edit to `tests/test_modules.py`, the strace experiment (downloading
  and unpacking the package into a temporary directory, the probe run that counted events per mode), the
  diagnosis of defect 2, and these notes.
- **Reviewed / decided by Maryam:** approved commit 0b and its limits in the plan; read both reviewer
  reports; chose to fix the BLOCKERs and the three pass-2 wording items only, and set the wording of the
  review line. Has not decided on defects 2 and 3 or on M1-M6, M8 and M9.
- **Verified by:** pytest runs listed above, in Python-audit mode and with a real strace 6.19. Not
  verified: docker and podman modes. The `cavr-reviewer` agent (read-only Claude Code subagent) did not
  run strace mode.

### Supervisor Q&A prep

1. **Why does a test accept several monitor modes instead of fixing one?**
   The lab picks the strongest monitor the machine has: a container, else strace, else Python audit
   events. The security claims the test checks (canary only in the counterfactual run, `REJECTED`) must
   hold in every mode. Pinning one mode made the test pass only on machines without strace or Docker.
2. **Does accepting more modes weaken the test?**
   The mode check is stricter in one way: the monitor must match the execution mode, and both runs are
   checked. Every behavioural assertion is unchanged.
3. **Is the lab verdict the same under strace and under Python audit?**
   The verdict was `REJECTED` and the canary was received in both. The evidence differs: under strace
   the network connect is missing from the events because `normalize` drops the `EINPROGRESS` line, so
   `causal_confirmed` is false there. This is an open defect, found by this step and not yet fixed.

## Step 1 — C1 parse pip install commands into capture records (2026-10-10)

Plan commit 1, `feat(cavr): C1 parse pip install commands into capture records`.
Reviewed by cavr-reviewer (1 batch pass over steps 1-3); verdict: fix first; no BLOCKER in this step's own code (`conflicting_requirements` changed for the step 2 BLOCKER); 5 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/capture.py` (new, 422 lines) | `parse_pip_command(command, cwd=".")` | Entry point. Takes a command string or token list, finds the pip launcher, finds the subcommand, and fills a capture record. Only `install` is captured. |
| | `parse_requirement(text, origin)` | Classifies one requirement string as `requirement`, `unsupported` (VCS, URL, local path) or `error` (malformed). Sets `pinned` and `version`. |
| | `parse_requirements_text(text, source)` | Classifies every line of a requirements file without reading any other file. `-r`/`-c` lines come back as `include` entries. |
| | `conflicting_requirements(requirements)` | One error per name asked for with two different specifiers (requirements with a marker are skipped). |
| | `_pip_arguments` | Recognises `pip`, `pip3`, `pip3.12`, a path to pip, and `python[3[.x]] ... -m pip` / `py -m pip`. Anything else is "not a pip command". |
| | `_split_options` | Splits tokens into positionals and options using three tables. Handles `--opt=value`, `--opt value`, `-rfile` and flag clusters such as `-qU`. |
| | `_apply`, `_add`, `_option_line_entries` | File each item under `requirements`, `constraints`, `unsupported`, `errors` or `options`. |
| | `_read_file` | Reads one `-r`/`-c` file (size cap, UTF-8 check, SHA-256 of the bytes) and recurses into its includes, relative to the including file. |
| | `_logical_lines` | Joins `\` continuations, drops comments and blank lines, keeps the first physical line number. |
| | `FLAG_OPTIONS`, `VALUE_OPTIONS`, `UNSUPPORTED_OPTIONS`, `SHORT_OPTIONS` | The option tables. `UNSUPPORTED_OPTIONS` maps each custom-source option to the reason recorded. |
| | `MAX_REQUIREMENTS_FILE_BYTES` | 1,000,000. A larger file is an error and is not parsed. |
| `tests/test_cavr_capture.py` (new, 405 lines) | | 41 test functions, 102 cases. |
| `docs/cavr-m1-plan.md` | | Progress box 1 ticked. |

Capture record fields: `source`, `command`, `action`, `options`, `requirements`, `constraints`,
`unsupported`, `errors`, `files`, `complete`. A requirement has `name`, `canonical_name`, `specifier`,
`version`, `pinned`, `extras`, `marker`, `hashes`, `raw`, `origin`.

Key algorithm, `parse_pip_command`:

1. Split the command (`shlex.split`); find the tokens after `pip` or `python -m pip`. None -> error "not a pip command".
2. Split those tokens into options and positionals. The first positional is the subcommand; if it is not `install`, record one `unsupported` entry and stop.
3. For each remaining item: positional -> `parse_requirement`; `-r`/`-c` -> `_read_file`; custom-source option -> `unsupported`; unknown option -> `unsupported`; known neutral option -> `options`.
4. `_read_file` keeps a stack of the files being read; a file already on the stack is an error ("includes itself"), so nested includes always terminate.
5. `_finish` adds conflict errors and sets `complete = not unsupported and not errors`.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| The record is a plain dict | Dataclasses | The rest of `backend/cavr/` passes dicts and they go straight to JSON evidence. |
| One `complete` flag, false if anything is unsupported or unreadable | Raise an exception on the first problem | The record must list everything that was asked for, including the parts not verified, so a later stage can report them and answer UNRESOLVED. |
| Unpinned requirement (`a>=1`) is captured, with `pinned: False` | Treat it as a capture error | Capture writes down what was asked; refusing it is the gate's rule (step 3). |
| Unknown option -> `unsupported`, next token not consumed | Guess that it takes a value; ignore it | We cannot know if the next token is its value. Guessing either way could hide or invent a package, so the record is marked incomplete. |
| Explicit option tables | Skip every token that starts with `-` (old `pip_shim.parse_pip_command`) | The old way read the value of `-i`, `-t`, `--index-url` as a package name. |
| Path/URL/VCS checked before `packaging` parses the text | Parse first | `Requirement("a-1-py3-none-any.whl")` parses as a package called `a-1-py3-none-any.whl`. |
| `--no-binary` is unsupported | Record it as neutral | It asks pip to build from source; the plan verifies wheels only. |
| `--platform`, `--python-version`, `--abi`, `--implementation` are neutral, kept in `options` | Unsupported | They change which wheel pip picks, but step 12 installs with `--require-hashes` on the verified files, so a different wheel fails to install. Step 4 can read them from `options`. |
| Nested `-r` resolved relative to the including file | Relative to `cwd` | This is what pip does. |
| Files nested inside a constraints file stay constraints | Follow the nested option's own role | A `-r` inside a `-c` file must not add an install request. |
| A requirement line with a bad `--hash` is rejected whole | Keep the requirement, drop the hash | A wrong hash is a wrong line; half of it should not be trusted. |
| `pip download`, `pip wheel`, `pip uninstall`, bare `pip` -> one `unsupported` entry | Treat as "nothing to verify" (complete) | `download` and `wheel` also fetch packages; step 12 decides which subcommands may pass through, using `action`. |
| Only `==` with no wildcard counts as pinned; `===` does not | Accept `===` | The plan says pinned with `==`. `===` is string equality for legacy versions. |
| No dependency on `manifest_parser.py` | Reuse its `parse_requirements_txt` | That parser has the regex fallback step 2 removes, and does not know `-r`, `-c`, `--hash`. Step 2 makes `manifest_parser` use this module instead. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; the IDs are from
`frontend/src/components/cavr/RequirementsTab.tsx`. **Maryam to confirm them against the SRS.**

| ID | Name there | What this step does for it | Acceptance check |
|---|---|---|---|
| FR-1 | Intercept Before Execution | A real `pip install` command becomes a structured record before anything is downloaded (CLAUDE.md goal C1, command half) | `test_pip_install_with_two_pins`, `test_pip_launcher_forms`, `test_nested_requirement_files_resolve_relative_to_the_including_file` |
| FR-6 | Fail-Closed Security Policy | Unsupported or unreadable input makes `complete` false instead of being dropped | `test_unsupported_forms_are_recorded_not_captured`, `test_missing_requirement_file_is_an_error`, `test_malformed_requirement_is_an_error_not_a_package` |

### Ch 7 Test cases

All in `tests/test_cavr_capture.py`. Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 184 passed (102 in this file).
- `.venv/bin/python -m pytest -q` -> 242 passed, 7 failed (the 7 baseline failures, unchanged).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_pip_install_with_two_pins` | Basic form | `pip install a==1 b==2` | Two pinned requirements, `complete` true | pass |
| `test_command_can_be_given_as_an_argument_list` | List input | `["pip","install","a==1"]` | Same record; `command` kept | pass |
| `test_pip_launcher_forms` (8) | Launchers | `python -m pip`, `python3.12 -I -m pip`, `pip3.12`, a path to pip, `py -m pip` | `a==1` captured | pass |
| `test_known_options_do_not_become_requirements` (7) | Option values | `--target out`, `-t out`, `-qU`, `--timeout 5` before the subcommand | Only `a==1` captured | pass |
| `test_recognised_options_are_recorded` | Options kept | `--upgrade --target out` | `[["--upgrade", None], ["--target", "out"]]` | pass |
| `test_name_is_canonicalised_but_the_written_name_is_kept` | Names | `Foo_Bar==1.0` | `name` `Foo_Bar`, `canonical_name` `foo-bar` | pass |
| `test_extras_and_marker_are_recorded` | Extras, marker | `a[x,b]==1; python_version >= "3"` | Extras `["b","x"]`, marker kept, pinned | pass |
| `test_anything_but_one_exact_pin_is_recorded_as_unpinned` (7) | Pin rule | `a`, `a>=1`, `a==1.*`, `a~=1.0`, `a>=1,<2`, `a===1`, `a!=1` | `pinned` false, `version` None, still `complete` | pass |
| `test_unsupported_forms_are_recorded_not_captured` (24) | Unsupported forms | URL, `git+`, local paths, wheel/sdist file names, `-e`, `-i`, `--index-url`, `--extra-index-url`, `-f`, `--no-index`, `--trusted-host`, `--no-binary`, unknown options | Matching reason in `unsupported`; `complete` false | pass |
| `test_direct_reference_is_unsupported_not_a_named_requirement` | PEP 508 URL | `a @ https://...whl` | No requirement; "direct URL" | pass |
| `test_unsupported_entry_keeps_what_was_written` | Evidence text | `-e ./pkg a==1` | `raw` is `-e ./pkg`; `a==1` still captured | pass |
| `test_value_of_a_custom_index_option_is_not_read_as_a_requirement` | Option value | `--index-url URL a==1` | One requirement, one unsupported | pass |
| `test_other_pip_subcommands_capture_no_requirements` (5) | Other subcommands | `uninstall`, `download`, `wheel`, `--version`, bare `pip` | No requirements; `complete` false | pass |
| `test_non_pip_commands_are_errors` (6) | Not pip | `ls -la`, `python script.py install a==1`, `python -m venv`, `sudo pip`, empty string, empty list | Error "not a pip command" | pass |
| `test_unbalanced_quotes_are_an_error` | Bad quoting | `pip install "a==1` | Error "cannot split" | pass |
| `test_install_without_any_requirement_is_an_error` | Empty install | `pip install --upgrade` | Error "no requirement" | pass |
| `test_malformed_requirement_is_an_error_not_a_package` (8) | Malformed | `a==`, `==1`, `a=1`, `a==1 b`, `a b==1`, `a==abc!`, `[x]==1`, `a==1;` | No requirement; one error with `raw` | pass |
| `test_option_missing_its_value_is_an_error` | Missing value | `pip install a==1 -r` | Error "needs a value" | pass |
| `test_conflicting_pins_for_one_name_are_an_error` | Conflict | `a==1 A==2` | Error "conflicting" | pass |
| `test_same_pin_twice_is_not_a_conflict` | No false conflict | `a==1 a==1` | No error | pass |
| `test_requirement_file_is_read_and_expanded` | `-r` | File with comments, blank line, 2 pins; plus `c==3` | 3 requirements; `origin` is `path:line` | pass |
| `test_requirement_file_hash_is_the_sha256_of_its_real_bytes` | Real hash | File bytes `a==1\n` | `sha256` equals `hashlib.sha256` of those bytes | pass |
| `test_all_spellings_of_the_requirement_option` (4) | Spellings | `-r f`, `--requirement f`, `--requirement=f`, `-rf` | `a==1` captured | pass |
| `test_nested_requirement_files_resolve_relative_to_the_including_file` | Nested `-r`, 3 levels | `top.txt` -> `sub/mid.txt` -> `leaf.txt` | 3 requirements; 3 files in order | pass |
| `test_requirement_file_that_includes_itself_is_an_error_and_terminates` | Include cycle | `a.txt` <-> `b.txt` | Both pins captured; error "includes itself" | pass |
| `test_missing_requirement_file_is_an_error` | Missing file | `-r nope.txt a==1` | Error "cannot read"; `files` empty; `complete` false | pass |
| `test_missing_nested_requirement_file_names_the_including_line` | Missing nested file | `top.txt` line 2: `-r gone.txt` | Error `origin` is `top.txt:2` | pass |
| `test_requirement_path_that_is_a_directory_is_an_error` | Directory | `-r reqs` (a directory) | Error "cannot read" | pass |
| `test_requirement_file_that_is_not_utf8_is_an_error` | Encoding | Bytes `\xff\xfe` | No requirements; error "not UTF-8" | pass |
| `test_oversized_requirement_file_is_an_error` | Size cap | Cap set to 8 bytes, 10-byte file | No requirements; error "larger than" | pass |
| `test_malformed_line_in_a_file_is_reported_with_its_line_number` | Malformed line | Line 2: `this is not a requirement` | Lines 1 and 3 captured; error at `:2` | pass |
| `test_unsupported_lines_inside_a_file` | Unsupported in file | `--index-url`, `-e`, `git+`, a wheel path, `a==1` | 4 unsupported, 1 requirement | pass |
| `test_line_continuation_and_bom` | `\` and BOM | BOM, `a==1 \` + `--hash=...`, `b==2` | 2 requirements; hash attached to `a`; `b` at line 3 | pass |
| `test_hash_options_are_recorded_and_bad_ones_are_errors` | `--hash` | Two good hashes; `--hash=md5:abc` | Hashes kept; bad line is an error and not captured | pass |
| `test_constraint_file_entries_are_kept_apart_from_requirements` | `-c` | `a==1 -c cons.txt` | `a` in `requirements`; `b`, `c` in `constraints` | pass |
| `test_constraint_included_from_a_requirement_file` | `-c` inside `-r` | `reqs.txt` has `-c cons.txt` | Same split | pass |
| `test_files_nested_inside_a_constraint_file_stay_constraints` | `-r` inside `-c` | `cons.txt` has `-r more.txt` | `b` is a constraint, not a requirement | pass |
| `test_missing_constraint_file_is_an_error` | Missing `-c` file | `-c nope.txt` | Error "cannot read" | pass |
| `test_conflict_between_command_line_and_file` | Conflict across sources | `a==1` and file `a==2` | Error "conflicting" | pass |
| `test_same_name_with_different_markers_is_not_a_conflict` | Marker split | Two `a` lines with opposite markers | Both captured; no error | pass |
| `test_parse_requirement_kinds` | Classifier | `a==1`, `git+...`, `not a requirement`, empty | requirement / unsupported / error / error | pass |

### Defects found and fixed

- None in the new code: the 102 cases passed on the first run.
- Found in existing code while reading it, **not fixed in this step**: `backend/cavr/pip_shim.py::parse_pip_command`
  skips only `-r`/`-c` values, so `pip install -i URL a` reports the URL as a package; it also drops the
  contents of `-r` files. It is replaced in step 12.

### Known limitations / deferred

- Nothing calls `capture.py` yet. The pipeline (step 11) and the pip wrapper (step 12) do.
- Launchers not recognised, reported as "not a pip command": `sudo pip`, `uv pip`, `pipx`, `env X=1 pip`,
  and `python` with an option that takes a value before `-m` (`python -W ignore -m pip`).
- The command string is split with POSIX rules, so an unquoted Windows path with backslashes is misread.
- `${VAR}` in a requirements file is not expanded; such a line is reported as malformed or unsupported.
- Markers are recorded, not evaluated. Extras are recorded, not expanded. Both are for step 6.
- pip configuration outside the command (`pip.conf`, `PIP_INDEX_URL`, `PIP_REQUIREMENT`) is not read, so a
  custom index set there is not seen. -> step 12 (the wrapper controls pip's environment).
- The option tables are written by hand from pip's documented options; a real option missing from them is
  reported as "unknown option" (incomplete capture), never ignored.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `backend/cavr/capture.py`, `tests/test_cavr_capture.py`, these notes, the
  commit. Run as part of `/cavr-batch 1, 2, 3` without a stop between steps.
- **Reviewed / decided by Maryam:** the plan step and the batch workflow (approved 2026-10-10). The code
  of this step has not yet been read by Maryam; that review is still to do.
- **Verified by:** the two pytest runs above; one `cavr-reviewer` pass over the batch diff.

### Supervisor Q&A prep

1. **Why not let pip parse the command (import pip's own parser)?**
   pip's internals are not a public API and change between releases, and importing them would tie the
   gate to the pip version installed. The capture needs only to recognise what it can verify and to mark
   everything else as unsupported, which a small explicit table does.
2. **What happens with a form the parser does not know?**
   It is written into `unsupported` or `errors` and `complete` becomes false. Nothing is silently
   skipped, so the pipeline answers UNRESOLVED for it.
3. **Does capture touch the network or run package code?**
   No. It reads the command and the requirements/constraints files named in it, nothing else.

## Step 2 — C1 capture requirements.txt edits (2026-10-10)

Plan commit 2, `feat(cavr): C1 capture requirements.txt edits`.
Reviewed by cavr-reviewer (1 batch pass over steps 1-3); verdict: fix first; 1 BLOCKER, fixed in the batch fix commit; 3 MINOR open.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `backend/cavr/manifest_parser.py` (70 -> 165 lines) | `snapshot_requirements(path)` | New. Records the file as it is now: `path`, `exists`, `sha256` of its bytes, `content`, `error`. A missing file is a valid snapshot (`exists: False`). |
| | `capture_requirements_edit(before, after)` | New. Compares two snapshots of the same file and returns a capture record with `source: "requirements_edit"`. `requirements` holds only the added and changed lines; `removed` holds the removed ones. |
| | `read_manifest(content, source)` | New. Sorts the lines into `requirements`, `options`, `unsupported`, `errors`, using `capture.parse_requirements_text`. `-r`/`-c` lines go to `unsupported`. Adds conflict errors. |
| | `parse_requirements_txt(content)` | Rewritten. The regex fallback is removed; returns only the named requirements from `read_manifest`. Old keys `name`, `specifier` (`"*"` when empty), `raw` are kept. |
| | `detect_manifest_changes(before, after, manifest_type)` | Same signature. Now matches lines on canonical name + marker, adds the `MODIFIED` action, and carries the new requirement record under `requirement`. |
| | `_diff(before, after)` | The diff itself, shared by `detect_manifest_changes` and `capture_requirements_edit`. |
| | `parse_pyproject_toml` | Not changed. |
| `backend/cavr/capture.py` | `read_requirements_bytes(path)` | New, moved out of `_read_file` so the snapshot uses the same size cap and UTF-8 check. Returns `(bytes, text, None)` or `(None, None, reason)`. |
| | `new_record` | Renamed from `_new_record` (now used by `manifest_parser.py`). |
| `tests/test_cavr_manifest.py` (new, 305 lines) | | 33 test functions, 40 cases. |
| `docs/cavr-m1-plan.md` | | Progress box 2 ticked. |

Extra fields of an edit record, on top of the step 1 fields: `path`, `before_sha256`, `after_sha256`,
`changed`, `changes`, `removed`.

Key algorithm, `capture_requirements_edit`:

1. Refuse snapshots of two different paths (`ValueError`).
2. Earlier snapshot unreadable -> add an error and treat the old state as empty, so every line counts as ADDED. New snapshot unreadable -> add an error and return with no requirements.
3. `read_manifest` on both contents; key each requirement by (canonical name, marker).
4. In the new file's order: key not in old -> ADDED; specifier differs -> VERSION_CHANGED; extras or hashes differ -> MODIFIED. Then, in the old file's order: key not in new -> REMOVED.
5. `complete = not unsupported and not errors`, judged on the whole new file, not only on the changed lines.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Unparseable line -> `errors`, never a package | Keep the regex fallback | The fallback turned `git+https://x/a.git` into a package named `git` and `this is not a requirement` into a package named `this`. A made-up name could be allowlisted by accident. |
| `manifest_parser.py` uses the line classifier in `capture.py` | Its own parser | One definition of "what is a requirement line" for commands, `-r` files and edits. |
| Edit capture lives in `manifest_parser.py`, not `capture.py` | Put it in `capture.py` and import the diff | The plan says the diff is `detect_manifest_changes`; `capture.py` importing `manifest_parser.py` while it imports `capture.py` would be a circular import. |
| A snapshot is a dict the caller keeps | The module writes snapshot files itself | No storage decision is needed yet; the pipeline or wrapper that watches the file (steps 11-12) decides where to keep it. The dict is JSON-serialisable. |
| Lines matched on canonical name + marker | `name.lower()` (old code) | `Foo_Bar` and `foo-bar` are the same PyPI project. The marker is in the key because one name can legitimately appear once per marker. |
| `MODIFIED` action for extras/hash edits | Report only specifier changes | A changed `--hash` accepts a different file, and a new extra pulls in new dependencies; both must be verified again. |
| `-r`/`-c` lines are `unsupported` in an edit | Follow the include from disk | Only the edited file has a "before" state; the included file's earlier content is unknown, so its changes cannot be diffed. |
| Errors are judged on the whole new file | Only on lines that changed | An unparseable line is still in the file pip will read, whether or not this edit touched it. |
| Unreadable earlier snapshot -> everything ADDED and an error | Refuse to produce a record | Fail closed: with no known old state, nothing is assumed already verified. |
| Missing file is a normal snapshot | An error | Creating and deleting `requirements.txt` are real edits. |

### Requirements covered

IDs from `frontend/src/components/cavr/RequirementsTab.tsx`. **Maryam to confirm them against the SRS.**

| ID | Name there | What this step does for it | Acceptance check |
|---|---|---|---|
| FR-1 | Intercept Before Execution | A requirements.txt edit becomes a capture record listing what was added or changed (CLAUDE.md goal C1, requirements.txt half) | `test_added_requirement`, `test_version_changed`, `test_removed_requirement` |
| FR-6 | Fail-Closed Security Policy | Unparseable and unsupported lines are reported and make the record incomplete | `test_unparseable_line_is_reported_and_is_not_a_package`, `test_lines_the_old_regex_fallback_accepted_are_no_longer_packages` |

### Ch 7 Test cases

All in `tests/test_cavr_manifest.py`. Every edit test writes a real file under `tmp_path`, snapshots it,
rewrites it and snapshots it again. Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 224 passed (40 in this file).
- `.venv/bin/python -m pytest -q` -> 282 passed, 7 failed (the 7 baseline failures).

| Test ID | Purpose | Input (before -> after) | Expected | Result |
|---|---|---|---|---|
| `test_added_requirement` | Added | `a==1` -> `a==1`, `b==2` | ADDED b; `requirements` is `b==2` with origin `path:2` | pass |
| `test_version_changed` | Version changed | `b==2` -> `b==3` | VERSION_CHANGED, old `==2`, new `==3` | pass |
| `test_removed_requirement` | Removed | `a`, `b` -> `a` | REMOVED b; `requirements` empty; `removed` has `b==2` | pass |
| `test_unparseable_line_is_reported_and_is_not_a_package` | Unparseable | adds `this is not a requirement` and `b==2` | Only ADDED b; one error at `path:2`; `complete` false | pass |
| `test_unpinned_requirement_is_captured_as_unpinned` | Unpinned | adds `b>=2`, `c` | Both ADDED with `pinned` false; `complete` true | pass |
| `test_lines_the_old_regex_fallback_accepted_are_no_longer_packages` (8) | Fallback removed | free text, `git+`, URL, path, `-e .`, `a==`, `a==1 b==2`, `--index-url` | No requirement; exactly one unsupported/error entry; no change reported | pass |
| `test_parse_requirements_txt_keeps_its_old_keys` | Old return shape | `Foo_Bar==1.0`, `b` | `name`, `specifier` (`"*"` for none), `raw` | pass |
| `test_no_edit_gives_no_changes` | No edit | same text | No changes; `changed` false | pass |
| `test_comment_and_order_edits_change_the_file_but_not_the_requirements` | Cosmetic edit | reorder, add comments | `changed` true; `changes` empty | pass |
| `test_respelling_a_name_is_not_a_change` | Canonical names | `Foo_Bar==1` -> `foo-bar==1` | No changes | pass |
| `test_respelled_name_with_a_new_version_is_one_change_not_add_plus_remove` | Canonical names | `Foo_Bar==1` -> `foo.bar==2` | One VERSION_CHANGED | pass |
| `test_pin_loosened_to_a_range_is_a_change_to_an_unpinned_requirement` | Pin removed | `a==1` -> `a>=1` | VERSION_CHANGED; `pinned` false | pass |
| `test_hash_change_with_the_same_version_is_reported` | Hash edit | `--hash` value changed | MODIFIED with the new hash | pass |
| `test_extras_change_with_the_same_version_is_reported` | Extras edit | `a==1` -> `a[x]==1` | MODIFIED with extras `["x"]` | pass |
| `test_same_name_under_two_markers_is_tracked_per_marker` | Markers | one of two marker lines changes version | One VERSION_CHANGED; no conflict error | pass |
| `test_conflicting_lines_for_one_name_are_an_error` | Conflict | adds `a==2` next to `a==1` | Error "conflicting"; `complete` false | pass |
| `test_include_lines_are_unsupported_in_an_edit` | Includes | adds `-r other.txt`, `-c other.txt` | 2 unsupported "not followed"; file not read | pass |
| `test_url_vcs_and_custom_index_lines_are_unsupported` | Unsupported lines | adds `git+`, `--extra-index-url`, `-e` | 3 unsupported; no requirement | pass |
| `test_unparseable_line_that_was_already_there_is_still_reported` | Old bad line | `???` in both, `b==2` added | ADDED b; error for `???` | pass |
| `test_unparseable_line_that_was_fixed_is_not_reported` | Bad line removed | `???` only before | No error; `complete` true | pass |
| `test_neutral_option_lines_are_kept_as_options` | Option line | adds `--pre` | `options` is `[["--pre", None]]` | pass |
| `test_snapshot_hash_is_the_sha256_of_the_real_bytes` | Real hash | CRLF file bytes | `sha256` equals `hashlib.sha256` of the bytes | pass |
| `test_snapshot_of_a_missing_file` | Missing file | no file | `exists` false, `sha256` None, no error | pass |
| `test_file_created_means_every_line_is_added` | File created | none -> 2 lines | 2 ADDED; `before_sha256` None | pass |
| `test_file_deleted_means_every_line_is_removed` | File deleted | 2 lines -> none | 2 REMOVED; `files` empty | pass |
| `test_edited_file_that_is_not_utf8_is_an_error` | Bad encoding | new file has `\xff` | No requirements; error "not UTF-8" | pass |
| `test_unreadable_earlier_snapshot_means_everything_is_treated_as_added` | Unknown old state | old snapshot not UTF-8 | ADDED a; error "earlier snapshot"; `complete` false | pass |
| `test_oversized_file_is_an_error` | Size cap | cap 8 bytes, 10-byte file | Error "larger than" | pass |
| `test_directory_in_place_of_the_file_is_an_error` | Directory | path is a directory | Snapshot error "cannot read" | pass |
| `test_snapshots_of_two_different_files_are_refused` | Wrong pair | snapshots of `a.txt` and `b.txt` | `ValueError` | pass |
| `test_record_lists_the_file_with_its_hash` | Evidence | `a==1` -> `a==2` | `files[0].sha256` equals SHA-256 of the new bytes | pass |
| `test_detect_manifest_changes_shape` | Text API | 3 lines -> 3 lines | VERSION_CHANGED b, ADDED d (`"*"`), REMOVED c | pass |
| `test_pyproject_branch_still_works` | pyproject path | `dependencies` list edited | VERSION_CHANGED b, ADDED c | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Reading the old code | Regex fallback in `parse_requirements_txt` accepted any line starting with a name-like word as a package | Fixed (the step's purpose); `test_lines_the_old_regex_fallback_accepted_are_no_longer_packages` |
| 2 | Reading the old code | `detect_manifest_changes` keyed on `name.lower()`, so `Foo_Bar` -> `foo-bar` showed as REMOVED + ADDED | Fixed; `test_respelling_a_name_is_not_a_change` |
| 3 | Reading the old code | Two lines for one name under different markers overwrote each other in the diff | Fixed (marker is part of the key); `test_same_name_under_two_markers_is_tracked_per_marker` |

No test failed during this step.

### Known limitations / deferred

- Nothing watches a requirements file yet. The caller must take the two snapshots; steps 11-12 do that.
- `-r`/`-c` lines inside an edited file are not followed; the record is incomplete (UNRESOLVED later).
  A project that uses `-c constraints.txt` needs each file captured separately.
- An unparseable line keeps every later edit capture of that file incomplete until the line is fixed.
- `parse_pyproject_toml` is unchanged: it still finds `dependencies` with a regex and silently drops
  entries it cannot parse. `pyproject.toml` edits are not an M1 goal. No caller uses that branch.
- A marker edit on a line shows as REMOVED + ADDED, because the marker is part of the key.
- Each ADDED/VERSION_CHANGED/MODIFIED change repeats the requirement record that is also in
  `requirements` (same object), so the JSON evidence has it twice.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the rewrite of `backend/cavr/manifest_parser.py`, the helper moved in
  `backend/cavr/capture.py`, `tests/test_cavr_manifest.py`, these notes, the commit.
- **Reviewed / decided by Maryam:** the plan step and the batch workflow. The code of this step has not
  yet been read by Maryam.
- **Verified by:** the two pytest runs above; one `cavr-reviewer` pass over the batch diff.

### Supervisor Q&A prep

1. **Why is only the changed part of the file verified?**
   Lines that did not change were captured when they were added. The record still checks the whole new
   file for unparseable or unsupported lines, because pip reads the whole file.
2. **What did the regex fallback do wrong?**
   It took the first word of any line as a package name, so a URL or a typo became a "package". Now a
   line is either a valid named requirement or it is reported and the capture is incomplete.
3. **How do you know the file really changed?**
   Each snapshot stores the SHA-256 of the file's bytes; `changed` compares the two digests.

## Step 3 — C2 fail-closed requirement gate (2026-10-10)

Plan commit 3, `feat(cavr): C2 fail-closed requirement gate`.
Reviewed by cavr-reviewer (1 batch pass over steps 1-3); verdict: fix first; 1 BLOCKER, fixed in the batch fix commit; 8 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/requirement_gate.py` (rewritten, 84 -> 307 lines) | `evaluate_requirement(requirement, policy, lockfile=None)` | Judges one requirement (string or capture record) against a parsed policy and an optional parsed lockfile. Returns `result`, `rule`, `reason`, `package`, `version`, `requested`, `policy_version`, `evidence`. |
| | `evaluate_capture(record, policy, lockfile=None)` | Judges a whole capture record; adds `decisions` (one per requirement). |
| | `gate_from_files(target, policy_path, lockfile_path=None)` | Reads the policy and lockfile from disk, then calls one of the two functions above. |
| | `load_json_file(path)` | Parsed JSON; `None` when the file does not exist; an `Unreadable` object when it exists but is not usable JSON (or is `null`). |
| | `policy_problems(policy)`, `lockfile_problems(lockfile)` | Lists of what is wrong. Empty list = usable. |
| | `policy_version(policy)` | `backend.orchestrator.hashing.digest(policy)`: SHA-256 of the canonical JSON. |
| | `check_requirement_gate(package_name, version)` | Kept for `backend/cavr/api.py`. Now calls `gate_from_files` on `project_policy.json` and adds the old keys `status`, `matched_rule`, `rule_checked`, `policy_file_excerpt`. |
| | `RULE_TITLES` | Rule id -> readable title, used for `rule_checked`. |
| | `_approved_entry`, `_denied_name`, `_requirement_text`, `_decision`, `_is_pypi`, `_version` | Small helpers: parse one allowlist entry, one denylist entry, the request; build the result dict. |
| `backend/cavr/api.py` | `execute_full_cavr_pipeline` | 2 lines. `is_gate_denied` is now `result != "PERMITTED"` (was `== "BLOCK"`), and the evidence line prints the real result, rule and reason instead of the fixed text "Matched explicit denylist rule". |
| `tests/test_cavr_requirement_gate.py` (new, 433 lines) | | 50 test functions, 118 cases. |
| `docs/cavr-m1-plan.md` | | Progress box 3 ticked. |

Key algorithm, `evaluate_requirement` (first rule that applies decides):

1. `policy is None` -> UNRESOLVED `POLICY_MISSING`. `policy_problems(policy)` not empty -> UNRESOLVED `POLICY_INVALID`.
2. Parse the request again with `capture.parse_requirement(name + specifier)`. Not a named requirement -> UNRESOLVED `REQUIREMENT_INVALID`.
3. Canonical name in `denied_packages` -> BLOCK `DENYLIST`. Not exactly one `==` clause -> BLOCK `NOT_PINNED`.
4. No `approved_requirements` entry with the same canonical name whose specifier contains the requested version -> BLOCK `NOT_ON_ALLOWLIST`.
5. Lockfile given: not well formed -> UNRESOLVED `LOCKFILE_INVALID`; no PyPI entry with this canonical name and an equal version -> BLOCK `NOT_IN_LOCKFILE`.
6. Only here: PERMITTED `ALLOWED`. This is the only `PERMITTED` for a requirement in the module.

`evaluate_capture`: any BLOCK -> BLOCK; else capture not `complete` -> UNRESOLVED `CAPTURE_INCOMPLETE`;
else any UNRESOLVED -> UNRESOLVED; else no requirements (an edit that only removes lines) -> PERMITTED
`NOTHING_TO_VERIFY`; else PERMITTED.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Missing or invalid policy -> UNRESOLVED | PERMITTED (old code); BLOCK | The plan's rule. The gate does not know whether the package is allowed, which is UNRESOLVED, not a refusal by policy. |
| Unlisted package -> BLOCK | "Permit for deep analysis" (old code) | An allowlist that lets unlisted names through is not an allowlist. |
| Allowlist entry = name + specifier, version must satisfy it | Name match only (old code: `req.split("==")[0] == name` permitted any version of an approved name) | The plan: "canonical name + specifier". `test_wrong_version_of_an_allowed_name_is_blocked`. |
| `allowlist_patterns` (regex on names) is no longer read | Keep it | A name-only regex permits every version. All 14 patterns in the shipped file repeat names that are already in `approved_requirements`. The key still counts in `policy_version`. |
| Denylist is checked before pinning and allowlist | Allowlist first | A denied name must be refused with the denylist reason even if someone also allowlists it. |
| One invalid entry makes the whole policy invalid | Skip the bad entry | Skipping a bad denylist entry would be fail-open; treating both lists the same way is simpler to explain. |
| The gate parses `name` + `specifier` itself | Trust the record's `pinned` and `version` | The record is input; `test_pinned_flag_in_the_record_is_not_trusted`. |
| Versions compared as `packaging.version.Version` | String compare | `1.0` and `1.0.0` are the same release. |
| Only lockfile entries with `ecosystem` "PyPI" count | Any entry with the name | A package locked as a LOCAL vendored file must not authorise downloading the same name from PyPI (dependency confusion). |
| No lockfile -> rule skipped; unreadable lockfile -> UNRESOLVED | Missing lockfile -> BLOCK | The plan: "lockfile present and name/version not in it -> BLOCK". A project without a lockfile is a normal case; a broken one is unknown state. |
| BLOCK reasons are decided before the lockfile is validated | Validate everything first | A denied or unlisted package is refused whatever state the lockfile is in; the more definite answer wins. |
| For a capture: BLOCK beats UNRESOLVED | UNRESOLVED beats BLOCK | Both stop the install; BLOCK carries the concrete policy reason. |
| `policy_version` = digest of the whole policy, including keys the gate does not read | Digest of the two lists only | The plan: "digest of the canonical policy JSON". Step 9 reads other policy keys, and any policy change must change the cache key. |
| `policy_version` is `None` when the policy is missing or invalid | Digest of whatever was read | There is no policy to name; UNRESOLVED is never cached. |
| `check_requirement_gate` kept as a thin wrapper | Change `api.py` to the new functions now | `api.py` is replaced in step 13; the wrapper keeps the dashboard running until then. |
| `api.py`: any non-PERMITTED gate result ends in the final BLOCK | Leave `== "BLOCK"` | With the old line, an UNRESOLVED gate (policy missing) would let the dashboard run reach VERIFIED. |

### Requirements covered

IDs from `frontend/src/components/cavr/RequirementsTab.tsx`. **Maryam to confirm them against the SRS.**

| ID | Name there | What this step does for it | Acceptance check |
|---|---|---|---|
| FR-2 | Requirement Gate Enforcement | Allowlist (name + specifier), denylist, pin and lockfile rules; immediate BLOCK when not permitted (CLAUDE.md goal C2) | `test_denylisted_name_is_blocked_even_when_it_is_also_on_the_allowlist`, `test_wrong_version_of_an_allowed_name_is_blocked`, `test_unpinned_requirement_is_blocked`, `test_name_missing_from_the_lockfile_is_blocked` |
| FR-6 | Fail-Closed Security Policy | Missing/invalid policy, invalid lockfile, invalid request, incomplete capture -> UNRESOLVED | `test_missing_policy_is_unresolved`, `test_invalid_policy_is_unresolved_even_for_an_entry_that_looks_allowed`, `test_dashboard_gate_no_longer_fails_open_without_a_policy` |

The description of FR-2 in `RequirementsTab.tsx` still mentions "allowlist patterns". -> step 13.

### Ch 7 Test cases

All in `tests/test_cavr_requirement_gate.py`. Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 342 passed (118 in this file).
- `.venv/bin/python -m pytest -q` -> 400 passed, 7 failed (the 7 baseline failures: 1 in `tests/test_api_replay.py`, 6 in `tests/test_integration.py`).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_missing_policy_is_unresolved` | No policy | `policy=None` | UNRESOLVED `POLICY_MISSING`; `policy_version` None | pass |
| `test_invalid_policy_is_unresolved_even_for_an_entry_that_looks_allowed` (17) | Invalid policy | Wrong types, missing key, unparseable entry, URL/marker/extras entry, denylist entry that is a string / has no name / has a specifier | UNRESOLVED `POLICY_INVALID` with `problems` | pass |
| `test_invalid_policy_does_not_block_or_permit_a_denied_name_either` | Invalid policy, denied name | Bad allowlist entry + denied name requested | UNRESOLVED | pass |
| `test_valid_policy_has_no_problems` | Valid policy | Test policy; two empty lists | No problems | pass |
| `test_denylisted_name_is_blocked_even_when_it_is_also_on_the_allowlist` | Deny wins | `evil-pkg==1`, on both lists | BLOCK `DENYLIST`, reason in text | pass |
| `test_denylist_matches_on_the_canonical_name_whatever_the_version` (5) | Deny by name | `Evil_Pkg==1`, `evil.pkg==9`, `EVIL-PKG`, `evil-pkg>=1`, `bad-name==1` | BLOCK `DENYLIST` | pass |
| `test_unpinned_requirement_is_blocked` (9) | Pin rule | `a`, `a>=1.0`, `a==1.*`, `a~=1.0`, `a>=1.0,<=1.0`, `a===1.0`, `a===`, `a!=2`, `c` | BLOCK `NOT_PINNED` | pass |
| `test_pinned_flag_in_the_record_is_not_trusted` | Forged record | `specifier: ">=1.0"`, `pinned: True` | BLOCK `NOT_PINNED` | pass |
| `test_name_not_on_the_allowlist_is_blocked` | Unlisted name | `zzz==1.0` | BLOCK `NOT_ON_ALLOWLIST` | pass |
| `test_wrong_version_of_an_allowed_name_is_blocked` | Wrong version | `a==2.0`, policy `a==1.0` | BLOCK; evidence lists `a==1.0` | pass |
| `test_exact_allowed_pin_is_permitted` | Happy path | `a==1.0` | PERMITTED `ALLOWED` | pass |
| `test_requested_version_must_satisfy_an_allowlist_specifier` (12) | Specifier match | `1` vs `1.0`; range `>=1,<2` at 1, 1.9.9, 2, 0.9; entry with no specifier; two entries for one name | PERMITTED / BLOCK as listed in the test | pass |
| `test_allowlist_name_is_canonicalised_on_both_sides` (4) | Name canonicalisation | `foo-bar`, `Foo_Bar`, `FOO.BAR`, `foo__bar` vs policy `Foo_Bar==1.0` | PERMITTED; `package` is `foo-bar` | pass |
| `test_capture_record_is_accepted_as_input` | Record input | Record from `parse_pip_command` | PERMITTED | pass |
| `test_no_lockfile_skips_the_lockfile_rule` | No lockfile | `lockfile=None` | PERMITTED | pass |
| `test_name_and_version_in_the_lockfile_is_permitted` | In lockfile | `a==1.0` | PERMITTED; lock entry in evidence | pass |
| `test_lockfile_names_and_versions_are_normalised` | Normalisation | `foo_bar==1.0` vs lock `Foo.Bar` `1` | PERMITTED | pass |
| `test_name_missing_from_the_lockfile_is_blocked` | Not locked | `b==1.5` | BLOCK `NOT_IN_LOCKFILE` | pass |
| `test_other_version_in_the_lockfile_is_blocked` | Other version locked | lock has `a` `0.9` | BLOCK; `locked_versions` `["0.9"]` | pass |
| `test_lockfile_entry_of_another_ecosystem_does_not_count` | Ecosystem | `c==7`, locked as LOCAL | BLOCK `NOT_IN_LOCKFILE` | pass |
| `test_empty_lockfile_blocks_everything` | Empty lockfile | `{"packages": []}` | BLOCK | pass |
| `test_invalid_lockfile_is_unresolved` (9) | Invalid lockfile | Wrong types, entry without version / ecosystem, bad version | UNRESOLVED `LOCKFILE_INVALID` | pass |
| `test_rule_order_block_reasons_come_before_the_lockfile_check` | Rule order | Denied / unpinned / unlisted with a broken lockfile | BLOCK with the earlier rule | pass |
| `test_request_that_is_not_a_named_requirement_is_unresolved` (11) | Bad request | Empty, free text, VCS, path, URL, `{}`, record without name, `a==`, non-string name, `None`, `7` | UNRESOLVED `REQUIREMENT_INVALID` | pass |
| `test_policy_version_is_a_sha256_of_the_canonical_json_and_is_on_every_decision` | Digest | 5 different outcomes | 64 hex chars; same value on each | pass |
| `test_policy_version_ignores_key_order_and_whitespace` | Canonical JSON | Keys reordered, re-indented | Same digest | pass |
| `test_policy_version_changes_with_any_change_to_the_policy` (5) | Sensitivity | Entry added / changed, deny entry removed, reason changed, unread key added | Different digest | pass |
| `test_capture_with_only_permitted_requirements_is_permitted` | Capture, all allowed | `pip install a==1.0 b==1.5` | PERMITTED; 2 decisions | pass |
| `test_one_blocked_requirement_blocks_the_capture` | Capture, one blocked | `a==1.0 zzz==1` | BLOCK `NOT_ON_ALLOWLIST` | pass |
| `test_unpinned_requirement_from_a_capture_is_blocked` | Capture, unpinned | `pip install a` | BLOCK `NOT_PINNED` | pass |
| `test_incomplete_capture_is_unresolved_even_when_its_named_requirements_are_allowed` | Incomplete capture | `a==1.0` + a `git+` URL | UNRESOLVED `CAPTURE_INCOMPLETE` | pass |
| `test_incomplete_capture_with_a_denied_name_is_blocked` | BLOCK beats UNRESOLVED | denied name + local path | BLOCK `DENYLIST` | pass |
| `test_capture_with_no_requirements_and_incomplete_is_unresolved` | Other subcommand | `pip download a==1.0` | UNRESOLVED | pass |
| `test_capture_without_the_complete_flag_is_unresolved` | Malformed record | `complete` deleted; `{}`; `None` | UNRESOLVED `CAPTURE_INCOMPLETE` | pass |
| `test_capture_is_unresolved_without_a_policy_and_judges_nothing` | No policy | `policy=None` | UNRESOLVED; no decisions | pass |
| `test_capture_with_an_invalid_lockfile_is_unresolved` | Bad lockfile | `{"packages": {}}` | UNRESOLVED `LOCKFILE_INVALID` | pass |
| `test_edit_that_only_removes_lines_has_nothing_to_verify` | Removal-only edit | real file, one line removed | PERMITTED `NOTHING_TO_VERIFY` | pass |
| `test_edit_that_adds_an_unlisted_package_is_blocked` | Edit adds unlisted | real file, `zzz==1` added | BLOCK | pass |
| `test_gate_from_files_permits_with_a_real_policy_and_lockfile` | Files on disk | policy + lockfile written to `tmp_path` | PERMITTED; `b==1.5` -> `NOT_IN_LOCKFILE` | pass |
| `test_missing_policy_file_is_unresolved` | No policy file | path does not exist | UNRESOLVED `POLICY_MISSING` | pass |
| `test_unreadable_policy_file_is_unresolved` (5) | Bad policy file | empty, broken JSON, `[]`, `null`, not UTF-8 | UNRESOLVED `POLICY_INVALID` | pass |
| `test_policy_path_that_is_a_directory_is_unresolved` | Directory | a directory path | UNRESOLVED `POLICY_INVALID` | pass |
| `test_missing_lockfile_file_skips_the_rule` | No lockfile file | path does not exist | PERMITTED | pass |
| `test_unreadable_lockfile_file_is_unresolved` | Bad lockfile file | broken JSON | UNRESOLVED `LOCKFILE_INVALID` (requirement and capture) | pass |
| `test_lockfile_containing_json_null_is_unresolved_not_skipped` | `null` lockfile | file content `null` | UNRESOLVED `LOCKFILE_INVALID` | pass |
| `test_real_project_lockfile_format_is_understood` | Real lockfile | `demo_project/InvoiceHub/dependencies.lock.json` | `pypdf==6.19.0` PERMITTED; `6.18.0` -> `NOT_IN_LOCKFILE` | pass |
| `test_shipped_policy_file_is_valid` | Shipped policy | `backend/cavr/project_policy.json` | No problems | pass |
| `test_dashboard_gate_with_the_shipped_policy` | Wrapper | `requests-security`, `pdf-clean-extractor==1.0.0`, `dormant-exfil==1.2.0`, `requests==2.0.0` | BLOCK `DENYLIST`; PERMITTED; BLOCK `NOT_ON_ALLOWLIST` (2); old keys present | pass |
| `test_dashboard_gate_no_longer_fails_open_without_a_policy` | Wrapper, no policy | `POLICY_PATH` points to a missing file | UNRESOLVED, `status` FAIL | pass |
| `test_dashboard_gate_no_longer_fails_open_on_a_broken_policy` | Wrapper, broken policy | broken JSON file | UNRESOLVED, `status` FAIL | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Reading the old code | Missing or unparseable policy returned PERMITTED | Fixed; `test_dashboard_gate_no_longer_fails_open_without_a_policy`, `..._on_a_broken_policy` |
| 2 | Reading the old code | An unlisted package returned PERMITTED (`R1_UNLISTED_PASS_TO_ANALYSIS`) | Fixed; now BLOCK `NOT_ON_ALLOWLIST` |
| 3 | Reading the old code | Any version of an approved name was PERMITTED (`req.split("==")[0] == name`) | Fixed; `test_wrong_version_of_an_allowed_name_is_blocked` |
| 4 | Reading the old code | Names compared with `.lower()` only, so `Requests_Security` did not match the denylist entry `requests-security` | Fixed; `test_denylist_matches_on_the_canonical_name_whatever_the_version` |
| 5 | First test run (2 of 118 failed) | Two test inputs were wrong, not the gate: `packaging` 26.3 accepts `a===` (empty version) as a valid requirement, so `"broken ==="` was a valid allowlist entry and `{"name": "a", "specifier": "==="}` was a valid, unpinned request. Inputs changed to `==` (really unparseable); `a===` added to the unpinned cases, where it is BLOCK `NOT_PINNED`. No assertion was weakened. | Fixed in the tests |
| 6 | Reading `api.py` | `is_gate_denied` was true only for BLOCK, so an UNRESOLVED gate would not stop a dashboard run | Fixed (2 lines in `api.py`). **No automated test runs `execute_full_cavr_pipeline`**; checked by reading and by `import backend.cavr.api` |

### Known limitations / deferred

- **Dashboard behaviour changed.** With the shipped `project_policy.json`, the chips `dormant-exfil==1.2.0`
  (`trigger_dependent`) and `invoice-utils==2.0.1` (`transitive_risk`) are now BLOCK at the gate
  (`NOT_ON_ALLOWLIST`) and end in a final BLOCK; before, they passed the gate. The later phases still
  run and are shown. The chips are replaced by real requests in step 13.
- **The shipped policy approves `pypdf==4.2.0` only**, so `pypdf==6.19.0` (the plan's VERIFIED case) and
  `pypdf==5.1.0` (the OSV case) are BLOCK `NOT_ON_ALLOWLIST` today. The policy file was not changed in
  this step; which versions to approve is Maryam's decision, needed by step 11.
- `project_policy.json` still contains `allowlist_patterns`; the gate does not read it.
- `OverviewTab.tsx` still prints "Matched explicit denylist rule" for every gate BLOCK. -> step 13.
- An allowlist entry with a range (`pypdf>=6,<7`) also admits pre-releases inside the range.
- Constraints (`-c`) are captured but not judged by the gate; they matter when children are pinned (step 6).
- The gate is not called by a pipeline yet (step 11); `check_requirement_gate` passes no lockfile.
- Extras and markers on the request are ignored by the gate (the name and version are judged).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the rewrite of `backend/cavr/requirement_gate.py`, the 2-line change in
  `backend/cavr/api.py`, `tests/test_cavr_requirement_gate.py`, these notes, the commit.
- **Reviewed / decided by Maryam:** the plan step and the batch workflow. The code of this step has not
  yet been read by Maryam. Open for her: the two dashboard chips that now BLOCK, and the pypdf versions
  in the shipped policy.
- **Verified by:** the two pytest runs above; one `cavr-reviewer` pass over the batch diff.

### Supervisor Q&A prep

1. **What does "fail closed" mean in this gate?**
   The function returns PERMITTED from one place only, after every rule passed. A missing policy, a
   broken policy, a broken lockfile or a request it cannot parse gives UNRESOLVED; nothing unknown is
   let through.
2. **Why is a missing policy UNRESOLVED and an unlisted package BLOCK?**
   BLOCK means the policy was read and says no. With no readable policy the gate has no rule to apply,
   so it cannot say yes or no; both stop the install.
3. **What is `policy_version` for?**
   It is the SHA-256 of the policy as canonical JSON and is one of the 8 fields of the verdict-cache key
   (step 10). If the policy changes in any way, old cached verdicts no longer match.

## Steps 1-3 — batch review fixes (2026-10-10)

The fix commit after `c018f30`, `fix(cavr): close two fail-open paths found in the batch review`.
Steps 1-3 were committed as `73f7892`, `4c053b6`, `c018f30`. The sections above describe the code as
committed there; this section lists what the fix commit changed. The fixes have not been reviewed again.

### Ch 6 Implementation

| File | Function | Change |
|---|---|---|
| `backend/cavr/requirement_gate.py` (307 -> 317 lines) | `evaluate_capture` | (a) A record that is not a dict, or whose `requirements` is not a list, is UNRESOLVED `CAPTURE_INCOMPLETE` (before: treated as an empty list). (b) Completeness is computed in the gate: `complete is True` and `unsupported == []` and `errors == []` (before: the `complete` flag alone). (c) A record with no requirements is PERMITTED `NOTHING_TO_VERIFY` only when `source == "requirements_edit"`; otherwise UNRESOLVED. |
| | `_malformed_capture` | New. Builds the UNRESOLVED result for (a). |
| `backend/cavr/capture.py` (427 -> 426 lines) | `conflicting_requirements(requirements, fields=("specifier",))` | Entries are now grouped by (canonical name, marker); before, every entry with a marker was skipped. New `fields` argument: which fields must be equal. |
| `backend/cavr/manifest_parser.py` (165 -> 167 lines) | `read_manifest` | Calls `conflicting_requirements` with `("specifier", "extras", "hashes")`, so two lines for the same (name, marker) that differ in any of the three are an error. |
| `tests/test_cavr_capture.py`, `tests/test_cavr_manifest.py`, `tests/test_cavr_requirement_gate.py` | | +1, +3, +6 test functions (+1, +6, +18 cases). |
| `docs/cavr-m1-plan.md` | | Commit hashes in the progress list; the 16 MINOR items under "Known issues deferred". |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| The gate recomputes completeness from `unsupported` and `errors` | Trust `complete` | Same reason the gate re-parses `name` + `specifier`: the record is input. A missing `unsupported` or `errors` key also counts as incomplete. |
| Empty request is PERMITTED only for a requirements edit | PERMITTED for any complete record | A pip command always names something; an empty one means the record is wrong. An edit can really add nothing. |
| Differing duplicate lines are an error; identical ones are not | Error for every duplicate; make the diff keep all lines | Identical lines lose nothing when the diff keeps one. Keeping every line would need a different diff key and is not needed to fail closed. |
| For a pip command only the specifier is compared | Compare extras and hashes there too | `pip install a==1 a[x]==1` is a normal command and both entries stay in `requirements`; nothing is hidden there. Only the edit diff collapses lines. |

### Requirements covered

FR-6 (Fail-Closed Security Policy, ID from `RequirementsTab.tsx`, Maryam to confirm): a malformed capture
record and a hidden duplicate line now give UNRESOLVED. Acceptance checks:
`test_capture_whose_requirements_are_not_a_list_is_unresolved`,
`test_differing_lines_for_the_same_requirement_are_an_error`.

### Ch 7 Test cases

Run on 2026-10-10 after the fixes:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 367 passed (`test_cavr_capture.py` 103, `test_cavr_manifest.py` 46, `test_cavr_requirement_gate.py` 136, plus the 82 older cases).
- `.venv/bin/python -m pytest -q` -> 425 passed, 7 failed (the same 7 baseline tests).
- Before the fixes the 25 new cases were run against the committed code: 21 failed, 4 passed (the 4 that
  check behaviour that was already right: 2 non-dict records, identical duplicates, one error per name).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_capture_whose_requirements_are_not_a_list_is_unresolved` (7) | Malformed record | `requirements` a tuple / `None` / a string / missing; record a list / a string | UNRESOLVED `CAPTURE_INCOMPLETE`; no decisions | pass |
| `test_gate_from_files_does_not_permit_a_record_with_a_string_of_requirements` | Same, through files | `requirements: "evil-pkg==1"` | UNRESOLVED | pass |
| `test_complete_flag_is_not_trusted_when_the_record_lists_problems` (4) | Forged `complete` | `complete: True` with a non-empty `unsupported` / `errors`, or with `None` / a string there | UNRESOLVED `CAPTURE_INCOMPLETE` | pass |
| `test_capture_without_its_problem_lists_is_unresolved` (2) | Missing keys | `unsupported` or `errors` deleted | UNRESOLVED | pass |
| `test_empty_capture_is_permitted_only_for_a_requirements_edit` (3) | Empty request | `source` `pip_command` / `None` / other, then `requirements_edit` | UNRESOLVED, then `NOTHING_TO_VERIFY` | pass |
| `test_edit_with_a_hidden_duplicate_line_is_not_permitted` | End to end | file gains `a==2.0; M` above the old `a==1.0; M` | UNRESOLVED (was PERMITTED) | pass |
| `test_differing_lines_for_the_same_requirement_are_an_error` (4) | Hidden line | same (name, marker) with a different version / extras / hash; `a==1` + `A==1 --hash` | One error "conflicting" naming lines 1 and 2; `complete` false | pass |
| `test_identical_duplicate_lines_are_not_an_error` | No false alarm | `a==1`, `A==1`, `b==2`, `b==2` | No error; ADDED b | pass |
| `test_read_manifest_reports_one_error_per_duplicated_requirement` | One error per name | `a==1`, `a==2`, `a==3` | 1 error | pass |
| `test_conflicting_pins_under_the_same_marker_are_an_error` | pip `-r` file | two `a` pins under one marker | Error "conflicting" | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | cavr-reviewer (BLOCKER, step 3) | `evaluate_capture` returned PERMITTED `NOTHING_TO_VERIFY` for a record whose `requirements` was not a list, e.g. `{"requirements": ("zzz==1",), "complete": True}`, and trusted `complete: True` on a record that listed unsupported entries | Fixed |
| 2 | cavr-reviewer (BLOCKER, step 2) | The edit diff keeps one line per (name, marker), and conflicts were not checked for lines with a marker or for extras/hash differences. A new line such as `a==2.0; M` placed above the old `a==1.0; M` was in the file but in no part of the record, with `complete: True` | Fixed |

The reviewer derived both from reading the code; they were reproduced here as failing tests before the fix.

### Known limitations / deferred

The 16 MINOR items of the review are listed in `docs/cavr-m1-plan.md` under "Known issues deferred"
(found in the batch 1-3 review). None was fixed in this commit.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the review (the read-only `cavr-reviewer` subagent), the two fixes, the
  25 new test cases, these notes, the commit.
- **Reviewed / decided by Maryam:** nothing in this commit yet. The fixes were made without a stop, as
  the `/cavr-batch` command says for BLOCKERs.
- **Verified by:** the pytest runs above. The reviewer did not see the fixes.

### Supervisor Q&A prep

1. **The gate re-parses the requirement because the record is input. Does it trust anything else in the record?**
   After this fix, no decision rests on a flag alone: `requirements` must be a list, and `complete`
   counts only when `unsupported` and `errors` are both empty lists.
2. **Two lines for the same package under the same marker: which one is verified?**
   If they are identical, the one line. If they differ in version, extras or hash, neither is silently
   chosen: the record gets an error and is not complete, so the answer is UNRESOLVED.
3. **An edit that only removes lines is permitted without verifying anything. Is that safe?**
   Nothing new is installed by it, so there is nothing for CAVR to download and check. Removing a
   `--hash` on a kept line is reported as MODIFIED. Removing an option line such as `--require-hashes`
   is not reported yet; it is in the deferred list.

## Step 4 — C3 fetch PyPI release metadata and verify artifact SHA-256 (2026-10-10)

Plan commit 4, `feat(cavr): C3 fetch PyPI release metadata and verify artifact SHA-256`.
Reviewed by cavr-reviewer (1 batch pass over steps 4-8, by reading the code; the reviewer ran pytest only); batch verdict: fix first; 0 BLOCKER; 6 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/pypi_client.py` (new, 296 lines) | `fetch_artifact(name, version, quarantine_dir, transport=None, max_bytes=…, deadline_seconds=…, supported_tags=None)` | Reads `https://pypi.org/pypi/{name}/{version}/json`, picks the wheel, streams it into `quarantine_dir`, hashes the file on disk and compares with the registry digest. Returns `result` (OK / REJECTED / UNRESOLVED), `rule`, `reason` and the evidence fields `registry_url`, `files_listed`, `filename`, `url`, `registry_sha256`, `registry_size`, `sha256`, `size`, `path`, `upload_time`, `requires_python`. |
| | `select_wheel(entries, name, version, supported_tags=None)` | Chooses one wheel: among wheels whose tags the running interpreter supports (`packaging.tags.sys_tags()`), the best-ranked one; filename breaks ties. A wheel entry with a wrong name, version or a directory part makes the response invalid. |
| | `HttpxTransport.stream(url)` | Default transport: HTTPS GET with `httpx`, 15 s timeout, no redirects, status other than 200 -> `TransportError`. |
| | `TransportError`, `registry_url(name, version)` | The one exception a transport raises; the JSON URL builder (name and version are percent-quoted). |
| | `_chunks`, `_read_capped` | Read a body chunk by chunk with a byte cap (`_TooLarge`) and a wall-clock deadline. |
| | `_parse_release`, `_request_problem`, `_allowed_file_url`, `_sha256_of_file`, `_result` | Validate the response / the request / the file URL; hash a file by reading it back; build the result dict. |
| | `MAX_REGISTRY_BYTES` 20 MiB, `MAX_ARTIFACT_BYTES` 200 MiB, `DEADLINE_SECONDS` 120 | Budgets. |
| `tests/test_cavr_support.py` (new, 126 lines) | `build_wheel`, `file_entry`, `registry_response`, `FakeIndex`, `pypdf_registry_response`, `sha256_file` | Test helpers shared by steps 4-8, no tests. `build_wheel` writes a real zip; `FakeIndex` is a transport that serves real file bytes and a response whose digest is computed from them. |
| `tests/test_cavr_pypi_client.py` (new, 442 lines) | | 35 test functions, 82 cases, all offline. |
| `tests/test_cavr_live.py` (new, 25 lines) | | 2 live tests, skipped unless `CAVR_LIVE=1`. |
| `docs/cavr-m1-plan.md` | | Progress box 4 ticked; the deferred item "Gate, local versions" marked as handled here. |

Key algorithm, `fetch_artifact`:

1. Validate the request (name pattern, version parses with `packaging`, no local version). Bad -> UNRESOLVED, no network call.
2. Read the JSON (capped). 404 -> `RELEASE_NOT_FOUND`; any other failure -> `REGISTRY_UNAVAILABLE`; the response must name the same canonical name and an equal version, else `REGISTRY_INVALID`. `info.yanked` must be exactly `false`.
3. `select_wheel`, then check the chosen entry before any download: not yanked, URL is `https://files.pythonhosted.org/...`, a 64-hex `sha256` exists, `size` is a whole number and under the cap.
4. Stream to `<filename>.<random>.part` inside the quarantine directory; stop over the cap or the deadline; the part file is deleted on every failure.
5. Re-open the part file, SHA-256 it, rename it to `<filename>` (match -> OK `HASH_MATCH`) or `<filename>.rejected` (mismatch -> REJECTED `HASH_MISMATCH`).

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Stage result is `OK`, not `VERIFIED` | Reuse VERIFIED | VERIFIED is the final verdict of the whole pipeline (step 11). A matching hash alone must not read as a verdict. |
| Hash the file after it is written, by reading it back | Hash the chunks while streaming | The plan asks for the digest of the bytes on disk. The evidence then describes the exact file later stages open. Cost: the file is read twice. |
| Transport = one method `stream(url)` | Pass an `httpx.Client`; mock `httpx` in tests | A one-method interface lets tests serve real local files without patching a library. |
| No redirects; file host must be exactly `files.pythonhosted.org` over https | Follow redirects; accept any URL in the JSON | The registry response is input. A response pointing at another host, `http://` or `file://` is refused before anything is fetched. |
| A mismatching file is kept as `<name>.rejected` | Delete it; keep the `.whl` name | Kept as evidence, but no later stage can open it by its wheel name. |
| `yanked` must be exactly `false` | Treat a missing flag as not yanked | Unknown -> UNRESOLVED (CLAUDE.md fail-closed rule). |
| A broken wheel entry invalidates the whole response | Skip that entry and use another wheel | A response that lists a file of another package is not trustworthy as a whole. |
| Wheel chosen for the running interpreter | Verify every wheel of the release; only accept `py3-none-any` | This is the file pip would install on this machine. Verifying all files is more downloads for no M1 benefit; pure-only would make packages with native wheels always UNRESOLVED. |
| Local versions (`1.0+local`) -> UNRESOLVED here | Add a BLOCK rule to the gate | PyPI does not host local versions, so the fetch stage is where this is certain. The gate still permits it (pinned by a test); nothing is downloaded. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; the IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| none listed | CLAUDE.md goal C3 (no FR in `RequirementsTab.tsx` covers artifact integrity; an ID is needed) | Real SHA-256 of the downloaded file vs the registry digest | `test_real_pypdf_wheel_matches_the_recorded_registry_digest`, `test_one_flipped_byte_is_rejected` |
| FR-6 | Fail-Closed Security Policy | Network error, yanked, no wheel, bad response -> UNRESOLVED | `test_timeout_reading_the_registry_is_unresolved`, `test_yanked_release_is_unresolved`, `test_sdist_only_release_is_unresolved` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 449 passed, 2 skipped (367 before + 82 new; the 2 skipped are the live tests).
- `.venv/bin/python -m pytest -q` -> 507 passed, 7 failed, 2 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py` -> 2 passed (real pypi.org, 8.6 s).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_real_pypdf_wheel_matches_the_recorded_registry_digest` | Match on a real artifact | `artifacts/pypdf-6.19.0-py3-none-any.whl` + recorded `advisories/registry-*.json` | OK `HASH_MATCH`; `sha256` = `7e5d6e73…e48d14` = digest of the file in quarantine; 395480 bytes | pass |
| `test_one_flipped_byte_is_rejected` | Tampered artifact | Same wheel with one bit flipped in the middle | REJECTED `HASH_MISMATCH`; file kept as `….whl.rejected` | pass |
| `test_truncated_download_is_rejected` | Short file | Last byte missing | REJECTED; sizes 395479 vs 395480 | pass |
| `test_tmp_built_wheel_matches`, `test_registry_digest_of_another_file_is_rejected` | tmp-built wheel | Wheel built in the test; then registry digest `000…0` | OK; then REJECTED | pass |
| `test_name_is_canonicalised_for_the_registry_url`, `test_version_is_compared_as_a_version_not_as_text` | Name / version forms | `PyPDF`; request `1.0.0` vs response `1.0` | OK | pass |
| `test_invalid_request_is_unresolved_without_any_network_call` (11) | Bad request | empty / `../demo` / `demo/x` / `>=1.0` / `1.*` / `None` / a float | UNRESOLVED `INVALID_REQUEST`; zero calls | pass |
| `test_local_version_is_unresolved_even_though_the_gate_permits_it` | Deferred gate item | `demo==1.0+local` | Gate PERMITTED; fetch UNRESOLVED; zero calls | pass |
| `test_timeout_reading_the_registry_is_unresolved`, `test_transport_that_fails_with_an_os_error_is_unresolved` | Network loss | Transport raises | UNRESOLVED `REGISTRY_UNAVAILABLE` | pass |
| `test_unknown_release_is_unresolved` | 404 | Unknown version | UNRESOLVED `RELEASE_NOT_FOUND` | pass |
| `test_unusable_registry_response_is_unresolved` (13) | Bad response | HTML, empty, `[]`, `null`, no `urls`, other name, other version, invalid UTF-8 | UNRESOLVED `REGISTRY_INVALID`; no download | pass |
| `test_oversized_registry_response_is_unresolved` | JSON cap | Cap set to 50 bytes | UNRESOLVED `REGISTRY_INVALID` | pass |
| `test_yanked_release_is_unresolved`, `test_yanked_file_is_unresolved`, `test_yanked_flag_that_is_not_exactly_false_is_unresolved` (3) | Yanked | `yanked: true` on release / file; `None`, `"false"`, `0` | UNRESOLVED `YANKED`; no download | pass |
| `test_sdist_only_release_is_unresolved`, `test_release_with_no_files_is_unresolved` | No wheel | Only a `.tar.gz`; empty `urls` | UNRESOLVED `NO_WHEEL` | pass |
| `test_only_incompatible_platform_wheels_is_unresolved`, `test_select_wheel_takes_the_best_ranked_compatible_tag` | Wheel choice | `cp27-cp27m-win32` only; three wheels with a given tag order | `NO_COMPATIBLE_WHEEL`; best-ranked tag chosen | pass |
| `test_wheel_entry_with_a_bad_filename_is_unresolved` (8) | Path / identity | `../x.whl`, `sub/x.whl`, other name, other version, `demo.whl`, a number | UNRESOLVED `REGISTRY_INVALID`; nothing written | pass |
| `test_file_url_outside_the_pypi_file_host_is_unresolved` (8) | URL check | `http://`, other host, look-alike host, userinfo, port, `file://`, empty, `None` | UNRESOLVED `URL_NOT_ALLOWED`; only the JSON was requested | pass |
| `test_missing_or_malformed_registry_digest_is_unresolved` (6), `test_uppercase_registry_digest_still_matches` | Registry digest | none / md5 only / short / non-hex / a number; upper case | `REGISTRY_DIGEST_MISSING`; upper case -> OK | pass |
| `test_declared_size_over_the_cap_is_unresolved_before_downloading`, `test_stream_longer_than_the_cap_is_cut_off_and_unresolved`, `test_registry_size_that_is_not_a_whole_number_is_unresolved` (5) | Size cap | Cap 10; declared 5 but server sends more than 64; size `None`/`"12"`/`-1`/`1.5`/`True` | `TOO_LARGE` (no file left); `REGISTRY_INVALID` | pass |
| `test_timeout_during_the_download_is_unresolved_and_leaves_no_file`, `test_missing_file_on_the_file_host_is_unresolved`, `test_download_slower_than_the_deadline_is_unresolved`, `test_quarantine_that_cannot_be_created_is_unresolved` | Download failure | Error after 10 bytes; 404 on the file; clock jumps 50 s per chunk; a file where the directory should be | UNRESOLVED `DOWNLOAD_FAILED`; quarantine empty | pass |
| `test_second_fetch_replaces_the_quarantined_file`, `test_every_result_has_the_same_keys`, `test_recorded_response_is_the_real_registry_shape` | Shape / repeat | Two fetches; three different outcomes; the recorded file | Same path, one file; same key set; recorded digest = real wheel digest | pass |
| `test_live_pypi_pypdf_wheel_matches_the_registry_digest`, `test_live_pypi_unknown_release_is_unresolved` (live) | Real network | `pypdf==6.19.0`; `pypdf==0.0.0.dev987654321` | OK with `7e5d6e73…`; `RELEASE_NOT_FOUND` | pass (with `CAVR_LIVE=1`) |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Own check while writing the code | `test_download_slower_than_the_deadline_is_unresolved` advanced the fake clock during the registry read too, so it would have ended in `REGISTRY_UNAVAILABLE` and not tested the download deadline | Test fixed before its first run: the clock moves only once the file download has started |

The tests were written before `pypi_client.py` but first run after it; all 82 passed on that first run.

### Known limitations / deferred

- Trust is in the registry JSON over TLS: the digest and the file both come from PyPI. A compromised PyPI
  serving a matching pair is not detected here. The project lockfile hash is compared in step 6.
- The wheel is chosen for the interpreter that runs CAVR, not for the project's target interpreter. -> step 12.
- Wheels only; an sdist-only release is UNRESOLVED (plan). No custom index, no mirror.
- `requires_python` is recorded, not enforced. -> step 6.
- Quarantine files are not cleaned up; a second fetch of the same file replaces the first. -> step 11.
- No retry on a network error: one failure is UNRESOLVED.
- `upload_time` is recorded as given by the registry and is not checked.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `pypi_client.py`, the three test files, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet; the batch ran without stops as `/cavr-batch` says.
- **Verified by:** the three pytest runs above, including the live run against pypi.org on 2026-10-10.

### Supervisor Q&A prep

1. **Where does the hash come from? Is anything faked?**
   From the bytes written to the quarantine directory: the file is re-opened and SHA-256'd
   (`_sha256_of_file`). In the offline test the bytes are the real pypdf wheel and the expected digest
   is from a recorded pypi.org response; the live test does the same against pypi.org.
2. **Why is a hash mismatch REJECTED but a timeout UNRESOLVED?**
   A mismatch is positive evidence that the file is not the one the registry describes. A timeout is
   missing evidence; CAVR does not know, so it says UNRESOLVED. Neither lets the install continue.
3. **What stops a huge or endless download?**
   The declared size is checked against the cap before downloading, the stream is cut when the received
   bytes pass the cap (the declared size is not trusted), and a 120 s wall-clock deadline applies.

## Step 5 — C3 read wheel metadata safely (2026-10-10)

Plan commit 5, `feat(cavr): C3 read wheel metadata safely`.
Reviewed by cavr-reviewer (1 batch pass over steps 4-8, by reading the code; the reviewer ran pytest only); batch verdict: fix first; 0 BLOCKER; 3 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/wheel_meta.py` (new, 260 lines) | `read_wheel(path, expected_name=None, expected_version=None)` | Opens the wheel as a zip, checks all entries, then reads METADATA, WHEEL and top_level.txt or RECORD. Returns `result` (OK / REJECTED / UNRESOLVED), `rule`, `reason`, `name` (canonical), `metadata_name`, `version`, `requires_python`, `requires_dist`, `provides_extra`, `dist_info`, `entry_count`, `total_uncompressed`, `wheel_tags`, `root_is_purelib`, `import_names`, `import_names_source`, `undeclared_import_names`, `native_files`, `pth_files`. |
| | `check_entries(archive)` | Budget and path checks over the zip directory, before any entry is read: entry count, total declared uncompressed size, compression ratio, unsafe paths, symlinks, encrypted entries, duplicate names. |
| | `read_member(archive, info, limit=None)` | Bytes of one entry, refused when its declared size is over the limit. |
| | `_read` | The body of `read_wheel`: finds the one top-level `*.dist-info`, parses METADATA, compares the three identities, reads WHEEL, derives import names. |
| | `_requirement`, `_single`, `_version`, `_headers`, `_text` | Parse one `Requires-Dist`; require exactly one `Name` / `Version`; parse a version; parse an RFC 822 header block; decode UTF-8. |
| | `_import_names(paths)`, `_unsafe_path(name)` | Top-level importable names in a list of paths; the path rule. |
| | `MAX_ENTRIES` 20 000, `MAX_TOTAL_UNCOMPRESSED` 500 MiB, `MAX_MEMBER_BYTES` 8 MiB, `MAX_RATIO` 200, `RATIO_FLOOR_BYTES` 10 MiB | The zip budget. |
| `tests/test_cavr_wheel_meta.py` (new, 336 lines) | | 38 test functions, 57 cases. |
| `tests/test_cavr_support.py` | `build_wheel` | Entries are now really deflated (see defects). |
| `docs/cavr-m1-plan.md` | | Progress box 5 ticked. |

Key algorithm, `read_wheel`:

1. `check_entries`: over budget -> UNRESOLVED `ZIP_BUDGET`; an entry that is absolute, has `..`, `.`, an empty part, a backslash, a drive letter, or is a symlink -> REJECTED `UNSAFE_PATH`; same name twice (ignoring case) -> UNRESOLVED `DUPLICATE_ENTRY`.
2. Exactly one top-level `X.dist-info/` with a `METADATA` file, else `METADATA_MISSING` / `DIST_INFO_AMBIGUOUS`.
3. METADATA header block: exactly one `Name` and one `Version`; every `Requires-Dist` must parse with `packaging` and must not be a URL, else `METADATA_INVALID`.
4. METADATA name/version must equal the dist-info directory name and, when given, the requested name/version (canonical name, `Version` equality), else REJECTED `METADATA_MISMATCH`.
5. Import names from `top_level.txt`, else `RECORD`, else the entry names; names present in the archive but not declared go to `undeclared_import_names`. `.so/.pyd/.dll/.dylib` -> `native_files`; `.pth` -> `pth_files`.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Read from the zip in memory; extract nothing | `zipfile.extractall` into a temp directory | Nothing is written, so a hostile path cannot land anywhere. The path check still runs because pip would extract the file later. |
| Check the whole zip directory before reading any entry | Check only the entries that are read | A bomb or an escaping path in an entry CAVR does not read still reaches pip at install time. |
| Budget on declared sizes | Count bytes while decompressing everything | `zipfile` returns at most the declared size and raises on a CRC mismatch, so the declared sizes bound the reads. Decompressing 500 MiB just to count is slow. |
| Ratio rule only above 10 MiB uncompressed | Ratio rule always | A tiny file of repeated characters has a high ratio and is harmless (`test_small_highly_compressible_wheel_is_not_a_bomb`). |
| Unsafe path / symlink / identity mismatch -> REJECTED; everything unreadable -> UNRESOLVED | All UNRESOLVED | The first group is positive evidence that the file is not an honest wheel of that package. The second group is missing knowledge. |
| Duplicate entry names -> UNRESOLVED | Use the last one, like `zipfile` | Two tools may pick different copies; CAVR cannot say which one would be installed. |
| Parse METADATA with `email.parser.HeaderParser` | `packaging.metadata`; a regex | METADATA is defined as RFC 822 headers. The parser stops at the first blank line, the same boundary pip uses (`test_requires_dist_after_the_header_block_is_not_a_dependency`). |
| `Requires-Dist` with a URL -> UNRESOLVED | Record it and continue | A URL dependency is not on PyPI and cannot be hash-checked by step 4. |
| Declared import names + `undeclared_import_names` | Trust `top_level.txt` only | `top_level.txt` is written by the package author. A wheel that ships a `requests/` directory without declaring it is reported; step 9 decides what to do with it. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| none listed | CLAUDE.md goal C3, "transitive tree from real metadata (Requires-Dist)" | The real `Requires-Dist` lines of the real wheel | `test_pypdf_wheel_metadata`, `test_requires_dist_is_read_with_markers_and_extras` |
| FR-6 | Fail-Closed Security Policy | Unreadable, over-budget or ambiguous wheel -> UNRESOLVED | `test_missing_metadata_is_unresolved`, `test_zip_bomb_is_stopped_by_the_compression_ratio`, `test_duplicate_entry_is_unresolved` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 506 passed, 2 skipped (449 + 57 new).
- `.venv/bin/python -m pytest -q` -> 564 passed, 7 failed, 2 skipped (the same 7 baseline tests).
- Before `wheel_meta.py` existed the test file failed at import (1 collection error).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_pypdf_wheel_metadata` | Real wheel | `artifacts/pypdf-6.19.0-py3-none-any.whl`, expected `pypdf` `6.19.0` | OK; 64 entries; 1 722 604 bytes uncompressed; 23 `Requires-Dist`; import name `pypdf` from RECORD; no native files | pass |
| `test_name_or_version_mismatch_is_rejected` (3) | Name mismatch | pypdf wheel, expected `pypdf2` / `6.19.1` / `requests 2.0` | REJECTED `METADATA_MISMATCH` | pass |
| `test_metadata_naming_another_package_than_its_dist_info_is_rejected`, `test_metadata_version_differing_from_its_dist_info_is_rejected` | Inner mismatch | `demo-1.0.dist-info/METADATA` says `requests` / `2.0` | REJECTED | pass |
| `test_expected_name_and_version_are_compared_canonically` | No false alarm | `Foo_Bar 1.0` asked as `foo-bar 1.0.0` and `foo.BAR 1` | OK | pass |
| `test_requires_dist_is_read_with_markers_and_extras`, `test_wheel_without_dependencies` | Dependencies | 4 lines with a marker, an extra marker, extras; none | Parsed fields; empty list | pass |
| `test_unparseable_or_url_requires_dist_is_unresolved` (5) | Bad dependency line | garbage, empty, URL, `dep==`, `../dep` | UNRESOLVED `METADATA_INVALID` | pass |
| `test_missing_metadata_is_unresolved`, `test_wheel_without_any_dist_info_is_unresolved` | Missing METADATA | Wheel built without it; zip with only code | UNRESOLVED `METADATA_MISSING` | pass |
| `test_two_dist_info_directories_is_unresolved`, `test_nested_dist_info_is_not_the_wheels_metadata` | Which dist-info | Two top-level; one nested inside the package | `DIST_INFO_AMBIGUOUS`; OK with the top-level one | pass |
| `test_unusable_metadata_is_unresolved` (8) | Bad METADATA | no Name, no Version, two Names, two Versions, bad version, `../demo`, empty, invalid UTF-8 | UNRESOLVED `METADATA_INVALID` | pass |
| `test_requires_dist_after_the_header_block_is_not_a_dependency` | Header boundary | `Requires-Dist` after a blank line | OK, no dependency | pass |
| `test_file_that_is_not_a_zip_is_unresolved`, `test_missing_file_and_directory_are_unresolved`, `test_truncated_wheel_is_unresolved`, `test_corrupted_metadata_bytes_are_unresolved`, `test_missing_wheel_file_is_unresolved` | Not a wheel | text file; no file / a directory / `None`; last 30 bytes cut; one byte of METADATA changed (CRC); no WHEEL file | UNRESOLVED `NOT_A_WHEEL` | pass |
| `test_zip_bomb_is_stopped_by_the_compression_ratio` | Zip bomb | 30 MiB of zero bytes in a wheel under 100 KiB | UNRESOLVED `ZIP_BUDGET` ("ratio") | pass |
| `test_total_uncompressed_size_budget`, `test_entry_count_budget`, `test_oversized_metadata_member_budget`, `test_small_highly_compressible_wheel_is_not_a_bomb` | Other budgets | Budgets lowered to 1000 bytes / 5 entries / 10 bytes; 200 KB of newlines | `ZIP_BUDGET` x3; OK | pass |
| `test_entry_that_escapes_the_install_directory_is_rejected` (7), `test_symlink_entry_is_rejected` | Path checks | `../evil.py`, `demo/../../evil.py`, `/etc/cron.d/evil`, `C:/…`, backslashes, `./`, `//`; a symlink entry | REJECTED `UNSAFE_PATH` | pass |
| `test_duplicate_entry_is_unresolved`, `test_entries_differing_only_in_case_are_unresolved`, `test_directory_entries_are_allowed` | Duplicates | Same name twice; `__INIT__.py`; a `demo/sub/` entry | `DUPLICATE_ENTRY` x2; OK | pass |
| `test_import_names_from_top_level_txt`, `…_from_record_when_there_is_no_top_level_txt`, `…_from_the_archive_when_there_is_neither`, `test_data_directory_purelib_counts_and_scripts_do_not`, `test_importable_code_missing_from_top_level_txt_is_reported` | Import names | `python-dateutil` with `top_level.txt`; `PyYAML` with RECORD; neither; a `.data` directory; an undeclared `requests/` | The three sources; `hidden` and `speed` counted, scripts not; `undeclared_import_names == ["requests"]` | pass |
| `test_native_and_pth_files_are_listed` | Native list | `.so`, `.pyd`, `.dll`, `.dylib`, `libz.so.1`, a `.pth`, `notes.so.txt` | 5 native files, 1 pth, the `.txt` not listed | pass |
| `test_pypdf_wheel_without_expectations_still_reads`, `test_invalid_expected_version_is_unresolved`, `test_every_result_has_the_same_keys` | Shape | | Same key set on every outcome | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | `test_zip_bomb_is_stopped_by_the_compression_ratio` (first run) | The test helper `build_wheel` wrote every entry uncompressed: `ZipFile.writestr(ZipInfo, …)` uses the `ZipInfo`'s own compression type, not the archive's. The "bomb" was a 31 MB file, so the ratio rule was not exercised | Helper fixed (`info.compress_type = ZIP_DEFLATED`); the test asserts the wheel is under 100 KiB |
| 2 | `test_pypdf_wheel_metadata` (first run) | The test expected the dependency text in the registry's form (`typing_extensions>=4.0; python_version < "3.11"`); the wheel's own METADATA says `typing_extensions >= 4.0; python_version < '3.11'` | Test corrected to the real line; `raw` is kept as written in the wheel |

### Known limitations / deferred

- RECORD hashes are not compared with the entries. The whole file's SHA-256 is already checked in step 4.
- A legitimate wheel over 500 MiB uncompressed (large ML wheels) is UNRESOLVED.
- `Requires-Python` is recorded, not enforced. -> step 6.
- Nested archives inside the wheel are not opened.
- `undeclared_import_names` is evidence only in this step. -> step 9.
- Entry names are not checked for Windows reserved names or trailing dots.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `wheel_meta.py`, `tests/test_cavr_wheel_meta.py`, the helper fix, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet; the batch ran without stops.
- **Verified by:** the pytest runs above; the real pypdf wheel numbers (64 entries, 1 722 604 bytes, 23 dependency lines) were read from the file with `zipfile` before the test was written.

### Supervisor Q&A prep

1. **How do you read an untrusted zip safely?**
   Nothing is extracted. `check_entries` first walks the zip directory: entry count, total size and
   compression ratio against a budget, and every name against a path rule. Only then four small
   metadata files are read, each with a size limit.
2. **What is a zip bomb and how is it caught?**
   A small file that expands to a huge one. The test wheel is under 100 KiB and declares 30 MiB; the
   ratio (over 200:1 above 10 MiB) gives UNRESOLVED `ZIP_BUDGET` before anything is decompressed.
3. **Why does the import name matter?**
   The project writes `import yaml`, the package is called `PyYAML`. Step 9 needs the wheel's own list
   (`top_level.txt` or RECORD) to connect project imports to the distribution that was verified.

## Step 6 — C3 transitive tree and subtree digest (2026-10-10)

Plan commit 6, `feat(cavr): C3 transitive tree and subtree digest`.
Reviewed by cavr-reviewer (1 batch pass over steps 4-8, by reading the code; the reviewer ran pytest only); batch verdict: fix first; 0 BLOCKER; 2 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/dep_tree.py` (new, 232 lines) | `build_tree(name, version, lockfile, quarantine_dir, transport=None, environment=None, extras=())` | Builds the tree under one pinned requirement. Returns `result` (OK / REJECTED / UNRESOLVED), `rule`, `reason`, `root`, `environment`, `nodes`, `edges`, `excluded`, `problems`, `subtree_digest`. |
| | `subtree_digest(root, nodes, edges)` | `hashing.digest` of `{"root", "nodes": sorted set of (name, version, sha256), "edges": sorted set of (parent name, parent version, child name, child version)}`. |
| | `_load(key, pins, …)` | One node: `fetch_artifact` (step 4), `read_wheel` (step 5), then the lockfile hash and `Requires-Python` checks. |
| | `_expand(key, node, extras, pins, env)` | One node's `Requires-Dist` lines: evaluate the marker, then pin the child from the lockfile. Returns edges, excluded lines, problems, children. |
| | `_pins(lockfile)` | Lockfile -> `{canonical name: [(Version, sha256)]}` for PyPI entries; uses `requirement_gate.lockfile_problems`. |
| | `MAX_NODES` 200 | Tree budget. |
| `backend/cavr/pypi_client.py` | `request_problem` | Renamed from `_request_problem` (now also called by `dep_tree.py`). No behaviour change. |
| `tests/test_cavr_dep_tree.py` (new, 399 lines) | | 35 test functions, 38 cases. |
| `docs/cavr-m1-plan.md` | | Progress box 6 ticked. |

Key algorithm, `build_tree`:

1. Work list starts with the root; always take the smallest (name, version) next. A node is loaded once (`loaded`), so a cycle ends.
2. `_load`: download + SHA-256, then METADATA. A failure is recorded as a problem and that node is not expanded.
3. `_expand`: a line whose marker is false for this interpreter (with `extra = ""` and each extra asked for by a parent) goes to `excluded`. Otherwise the child must have exactly one lockfile version that satisfies the line; else `CHILD_NOT_PINNED` / `CHILD_PIN_CONFLICT`.
4. If a node is reached again with new extras, it is expanded again (not downloaded again).
5. Any REJECTED problem -> REJECTED; else any problem -> UNRESOLVED; else OK with the subtree digest.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Children pinned from the project lockfile (approved plan change) | Take the newest version on PyPI that fits; run pip's resolver | "Newest that fits" is a guess and changes over time. The resolver (`pip install --dry-run --report`) is the accurate answer and is named as future work in the module docstring. |
| An exact `==` in `Requires-Dist` is still not a pin without the lockfile | Accept `leaf==1.0` from the parent's metadata | The pin must come from the project, not from the package being judged. |
| Visit all nodes, then decide (REJECTED before UNRESOLVED) | Stop at the first problem | The verdict does not depend on visiting order, and a tampered leaf is not reported as a mere timeout elsewhere (`test_rejected_wins_over_unresolved`). |
| Lockfile hash differs from the downloaded file -> UNRESOLVED | REJECTED | The lockfile has one hash per package; a release can have several wheels, so the lock may pin another platform's file. The registry digest mismatch (step 4) is the REJECTED case. Open for Maryam: make it REJECTED once the lockfile lists all files. |
| Extras: off for the root, on for a child exactly as its parent asks | Ignore all extras (plan wording "extras off"); UNRESOLVED on any extra | pip installs `mid[fast]`'s extra dependencies; leaving them out would verify a smaller tree than the one installed. |
| `Requires-Python` not satisfied -> UNRESOLVED | Ignore | pip would refuse the wheel; the tree is for an interpreter that cannot use it. |
| Digest over sorted sets of nodes and edges, plus the root | Hash a nested tree; hash only the nodes | A nested tree cannot represent a cycle. Nodes alone miss a changed edge (`test_subtree_digest_covers_the_edges_not_only_the_nodes`). The root is included so that the same set seen from another root is a different subtree. |
| Markers evaluated for the running interpreter, with an `environment` override | Evaluate for a configured target | Same choice as wheel selection in step 4; the override makes the rule testable for other platforms. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| none listed | CLAUDE.md goal C3, "transitive tree from real metadata" and the `subtree digest` cache-key field | Tree from each wheel's real `Requires-Dist`; every node hashed | `test_three_level_tree`, `test_every_node_is_downloaded_and_hashed`, `test_subtree_digest_changes_when_a_leafs_bytes_change` |
| FR-6 | Fail-Closed Security Policy | Unpinned child, invalid lockfile, unreachable node -> UNRESOLVED | `test_child_missing_from_the_lockfile_is_unresolved`, `test_invalid_lockfile_is_unresolved_before_any_download`, `test_network_loss_on_a_leaf_is_unresolved` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 544 passed, 2 skipped (506 + 38 new).
- `.venv/bin/python -m pytest -q` -> 602 passed, 7 failed, 2 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 2 passed (after the `request_problem` rename).
- The tests were written before `dep_tree.py` and first run after it; all 38 passed on that run.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_three_level_tree` | tmp-built 3-level tree | `app 1.0 -> mid>=1,<2 -> leaf`, lockfile `mid==1.5`, `leaf==2.0` | OK; 3 nodes; 2 edges; 64-hex digest | pass |
| `test_every_node_is_downloaded_and_hashed` | Every node through step 4 | Same | 3 downloads; each node's `sha256` = digest of its file | pass |
| `test_subtree_digest_changes_when_a_leafs_bytes_change` | Digest sensitivity | Same tree, leaf source gains one line | Root and mid hashes equal, leaf hash and subtree digest differ | pass |
| `test_subtree_digest_covers_the_edges_not_only_the_nodes` | Edges and root in the digest | Same nodes, edge `app->c` replaced by `b->c`; another root; reversed input | Different; different; equal | pass |
| `test_subtree_digest_is_stable_and_does_not_depend_on_requires_dist_order`, `test_cycle_digest_is_the_same_from_two_runs` | Stability | Two runs; `Requires-Dist` order swapped | Same digest; same sorted nodes and edges | pass |
| `test_dependency_cycle_terminates` | Cycle | `a->b->c->a`, `c->c` | OK; 3 nodes; 4 edges; 3 downloads | pass |
| `test_marker_excluded_dependency_is_not_followed_and_needs_no_pin`, `test_the_same_dependency_is_followed_when_its_marker_holds` | Markers | `win-only==1.0; sys_platform == "win32"` on linux / win32 | Excluded, never requested; on win32 UNRESOLVED `CHILD_NOT_PINNED` | pass |
| `test_extras_are_off_for_the_root`, `test_extra_asked_for_by_a_parent_turns_on_the_childs_extra_dependencies`, `test_extra_that_arrives_after_the_node_was_first_seen_is_still_applied` | Extras | `extra == "fast"` line on the root; `mid[fast]`; `mid` first plain then `[fast]` | Excluded; `speedup` followed and `docs-tool` excluded; `speedup` followed, 5 downloads | pass |
| `test_real_pypdf_wheel_has_no_dependencies_on_this_interpreter` | Real wheel | pypdf wheel + `demo_project/InvoiceHub/dependencies.lock.json` | OK; 1 node with `7e5d6e73…`; lockfile hash equal; 23 lines excluded | pass |
| `test_real_pypdf_wheel_on_python_3_10_needs_typing_extensions_pinned` | Real marker | Same wheel, `python_version` 3.10 | UNRESOLVED `CHILD_NOT_PINNED` (typing-extensions) | pass |
| `test_child_missing_from_the_lockfile_is_unresolved`, `test_child_without_any_lockfile_is_unresolved` | Unpinned child | `leaf>=1` not in the lockfile; `leaf==1.0` with no lockfile | UNRESOLVED `CHILD_NOT_PINNED`; no digest; leaf not downloaded | pass |
| `test_lockfile_version_outside_the_childs_specifier_is_unresolved`, `test_two_lockfile_versions_that_both_fit_are_unresolved`, `test_two_lockfile_versions_of_which_one_fits_is_pinned` | Pin rules | `leaf>=2` vs lock 1.0; lock 1.0 and 2.0 for `leaf`; for `leaf<2` | `CHILD_PIN_CONFLICT`; `CHILD_NOT_PINNED`; OK with 1.0 | pass |
| `test_lockfile_names_are_matched_canonically_and_other_ecosystems_are_ignored` | Names | `Left_Pad` vs lock `left.PAD`; an `npm` entry | left-pad pinned; npm-thing not pinned | pass |
| `test_invalid_lockfile_is_unresolved_before_any_download` (4) | Bad lockfile | list; `packages` a string; entry without version; invalid version | UNRESOLVED `LOCKFILE_INVALID`; zero calls | pass |
| `test_tampered_leaf_rejects_the_whole_tree`, `test_tampered_root_is_rejected` | Hash per node | One byte flipped in leaf / root | REJECTED `HASH_MISMATCH`; problem names the node | pass |
| `test_network_loss_on_a_leaf_is_unresolved`, `test_rejected_wins_over_unresolved` | Mixed failures | Timeout on leaf; timeout on `aaa` + tampered `zzz` | UNRESOLVED; REJECTED with both problems listed | pass |
| `test_leaf_wheel_whose_metadata_names_another_package_is_rejected`, `test_leaf_wheel_without_metadata_is_unresolved` | Step 5 per node | Leaf METADATA says `other`; leaf without METADATA | REJECTED `METADATA_MISMATCH`; UNRESOLVED `METADATA_MISSING` | pass |
| `test_lockfile_hash_that_differs_from_the_downloaded_file_is_unresolved`, `test_lockfile_hash_that_matches_is_recorded` | Lockfile hash | lock sha `000…0`; the real sha in upper case | UNRESOLVED `LOCKFILE_HASH_MISMATCH`; OK with `lockfile_sha256` | pass |
| `test_wheel_that_needs_a_newer_python_is_unresolved`, `test_unparseable_requires_python_is_unresolved` | Requires-Python | `>=3.99`; `whatever` | UNRESOLVED `PYTHON_INCOMPATIBLE` | pass |
| `test_node_budget`, `test_invalid_root_is_unresolved`, `test_root_without_dependencies_needs_no_lockfile`, `test_every_result_has_the_same_keys` | Budget / shape | `MAX_NODES` 2; bad root; a root with no dependencies and no lockfile | `TREE_BUDGET` after 2 downloads; `INVALID_REQUEST`; OK; same keys | pass |

### Defects found and fixed

None found by the tests in this step.

### Known limitations / deferred

- The tree is as good as the lockfile: a child missing from it is UNRESOLVED even when PyPI has an
  obvious single candidate. Resolver-accurate pins (`pip install --dry-run --report`) are future work.
- Markers and `Requires-Python` are evaluated for the interpreter that runs CAVR. -> step 12.
- Root extras (`pip install pkg[extra]`) are supported by the `extras` argument but nothing passes it
  yet. -> step 11.
- If the lockfile pins another version of the root's own name and a cycle leads back to that name, the
  tree contains both versions; pip would report a conflict. Not detected.
- Nodes are downloaded one after the other; no parallel downloads, no reuse of files already in quarantine.
- The lockfile's own `edges` list is not compared with the edges found in the wheels.
- The full step 4 and step 5 results are kept in every node (`artifact`, `metadata`), so the tree is large
  for big dependency sets. -> trim in step 11 if needed.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `dep_tree.py`, `tests/test_cavr_dep_tree.py`, the rename in `pypi_client.py`, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet. Two choices go beyond the plan's wording and need her
  decision: child extras are followed (plan: "extras off"), and a lockfile hash mismatch is UNRESOLVED.
- **Verified by:** the pytest runs above.

### Supervisor Q&A prep

1. **What is the subtree digest and why is it in the cache key?**
   One SHA-256 over every (name, version, file hash) reachable from the package plus the edges. If any
   dependency's bytes change, the digest changes and a cached verdict no longer matches
   (`test_subtree_digest_changes_when_a_leafs_bytes_change`).
2. **How do you handle a dependency cycle?**
   Each (name, version) is loaded once; the edge back is still recorded. The digest is over sorted sets,
   not a recursive walk, so `a->b->a` gives the same digest on every run.
3. **Why UNRESOLVED when a dependency is not in the lockfile, instead of picking the newest version?**
   CAVR would be verifying a version it guessed, and pip might install another. Unknown -> UNRESOLVED.

## Step 7 — C3 OSV check with real version ranges (2026-10-10)

Plan commit 7, `feat(cavr): C3 OSV check with real version ranges`.
Reviewed by cavr-reviewer (1 batch pass over steps 4-8, by reading the code; the reviewer ran pytest only); batch verdict: fix first; 0 BLOCKER; 2 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/advisories.py` (new, 188 lines) | `check_advisories(name, version, cache_dir, live=False, max_age_days=30, osv=None)` | Asks `backend.integrations.osv_adapter.OSV` (imported, not edited) and judges each advisory. Returns `result` (OK / REJECTED / UNRESOLVED), `rule`, `reason`, `mode`, `source`, `retrieved_at`, `age_days`, `response_sha256`, `live_error`, `advisory_count`, `affected`, `unknown`, `not_affected`, `withdrawn`. |
| | `match_advisory(name, version, vuln)` | One OSV advisory -> `status` AFFECTED / NOT_AFFECTED / UNKNOWN / WITHDRAWN / OTHER_PACKAGE, with `id`, `aliases`, `summary`, `fixed_versions`. Range logic is `backend.threat_repo.package_records.affected` (imported, not edited). |
| | `_entry_affects`, `_ranges`, `_is_for` | Call `affected` for one `affected[]` entry after a shape check; pick the entries for this PyPI package (canonical name). |
| | `_age_days`, `_cached_age_days` | Age of an answer; age of the adapter's cache file (to tell "stale" from "missing"). |
| `tests/test_cavr_advisories.py` (new, 402 lines) | | 37 test functions, 77 cases, offline. |
| `tests/test_cavr_data/osv-pypdf-5.1.0.json`, `osv-pypdf-6.19.0.json` (new) | | Real api.osv.dev answers recorded on 2026-10-10: 97 advisories for pypdf 5.1.0 (trimmed to id, aliases, summary, dates, `affected[].package/ranges/versions`; 121 KB) and the empty object for 6.19.0. |
| `tests/test_cavr_live.py` | | +2 live OSV tests (4 live tests in total). |
| `docs/cavr-m1-plan.md` | | Progress box 7 ticked. |

Key algorithm, `check_advisories`:

1. `OSV.query(canonical name, version, "PyPI", live, max_age_days)`. Any exception, or `available` not true -> UNRESOLVED (`ADVISORIES_STALE` when the adapter's cache file exists and is too old, else `ADVISORIES_UNAVAILABLE`).
2. The adapter's PyPI-registry fallback mode is not an OSV answer -> UNRESOLVED. An answer dated in the future -> `ADVISORIES_STALE`.
3. `match_advisory` on every advisory: `affected()` walks the events of each ECOSYSTEM range (`introduced` inclusive, `fixed` exclusive, `last_affected` inclusive).
4. Any AFFECTED -> REJECTED `KNOWN_VULNERABILITY`. Else any UNKNOWN -> UNRESOLVED `RANGE_UNSUPPORTED`. Else any NOT_AFFECTED / OTHER_PACKAGE -> UNRESOLVED `RANGE_DISAGREEMENT`. Else OK.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Wrap `OSV` and `affected`, edit neither | Write a new client / matcher in `backend/cavr/` | The plan lists both under "Reuse (import, do not edit)"; `backend/integrations/` needs permission to touch. |
| The range check is a second reading of what OSV returned | Trust OSV's answer alone; trust the range check alone | OSV answers per version. Agreement -> REJECTED. If the local check says "not affected" for an advisory OSV returned, one of the two is wrong, so the result is UNRESOLVED, not clean. |
| GIT-only / unknown range type -> UNRESOLVED | Count as affected; ignore | CLAUDE.md: unknown -> UNRESOLVED. Ignoring it would fail open. |
| AFFECTED beats UNKNOWN | UNRESOLVED whenever anything is unknown | One confirmed advisory is enough to reject; the unknown ones are still listed. |
| PyPI registry fallback -> UNRESOLVED | Use PyPI's `vulnerabilities` list as the answer | That list has no ranges, so there is nothing to check, and the plan asks for OSV with real ranges. |
| Stale has its own rule `ADVISORIES_STALE` | One rule for all "no answer" cases | The user's remedy differs: stale means "run once with network", unavailable may mean a damaged cache. |
| Future-dated answer -> stale | Accept (the adapter does) | A cache file dated next year would otherwise never expire. |
| `max_age_days` default 30 | A shorter default | It is the adapter's own default; the pipeline can pass a smaller value. Open for Maryam. |
| Real recorded OSV data in `tests/test_cavr_data/`, trimmed; synthetic advisories only for shapes it lacks, ids `SYNTH-n` | Only hand-written advisories | The REJECTED case rests on real data; the synthetic ones test range arithmetic and are labelled. |
| Tests set `retrieved_at` themselves | Store dated cache files | A stored file would go stale 30 days after recording and the tests would start failing. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| none listed | CLAUDE.md goal C3, "OSV with correct version-range checks" | Event-based range matching; REJECTED with advisory ids | `test_recorded_pypdf_5_1_0_is_rejected_with_the_advisory_ids`, `test_introduced_fixed_range`, `test_last_affected_range`, `test_multi_range` |
| FR-6 | Fail-Closed Security Policy | No data, stale data, unsupported range -> UNRESOLVED | `test_no_data_is_unresolved`, `test_stale_cache_is_unresolved`, `test_git_only_range_is_unresolved` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 621 passed, 4 skipped (544 + 77 new; the 4 skipped are live tests).
- `.venv/bin/python -m pytest -q` -> 679 passed, 7 failed, 4 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 4 passed. Live on 2026-10-10: pypdf 5.1.0 REJECTED; pypdf 6.19.0 OK, 0 advisories.
- Before `advisories.py` existed the test file failed at import (1 collection error).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_recorded_pypdf_5_1_0_is_rejected_with_the_advisory_ids` | Real affected version | Recorded OSV answer, 97 advisories | REJECTED `KNOWN_VULNERABILITY`; 97 affected, ids sorted; `GHSA-php9-fj8v-98fj` fixed in 6.19.0 | pass |
| `test_recorded_pypdf_6_19_0_has_no_known_vulnerability` | Real clean version | Recorded empty answer | OK `NO_KNOWN_VULNERABILITY` | pass |
| `test_every_recorded_advisory_matches_5_1_0_and_most_do_not_match_6_19_0` | Range check on real data | The 97 advisories vs 5.1.0 and vs 6.19.0 | All AFFECTED; all NOT_AFFECTED | pass |
| `test_introduced_fixed_range` (8) | introduced/fixed, just outside | Real advisory (introduced 0, fixed 6.19.0) vs 0.1, 5.1.0, 6.18.1, 6.19.0rc1, 6.19.0, 6.19, 6.19.0.post1, 7.0.0 | First four AFFECTED, last four NOT_AFFECTED | pass |
| `test_introduced_above_zero` (4) | Lower bound | SYNTH: introduced 2.0, fixed 3.0 vs 1.9, 2.0, 2.5, 3.0 | NOT / AFFECTED / AFFECTED / NOT | pass |
| `test_last_affected_range` (6) | last_affected | SYNTH: introduced 1.0, last_affected 1.5 vs 1.0, 1.4.9, 1.5, 1.5.0, 1.5.1, 0.9 | Inclusive at 1.5; 1.5.1 and 0.9 not affected | pass |
| `test_the_old_rule_that_any_less_or_equal_range_affects_every_version_is_gone` | Old dashboard bug | SYNTH: last_affected 3.5.21 vs 3.5.21 and 4.0.0 | AFFECTED; NOT_AFFECTED | pass |
| `test_multi_range` (7), `test_several_affected_entries_any_match_counts` | Multi-range | SYNTH: two intervals in one range + an open range; two `affected` entries | Inside any interval -> AFFECTED; gaps -> NOT_AFFECTED | pass |
| `test_git_only_range_is_unknown`, `test_git_only_range_is_unresolved`, `test_git_range_next_to_a_matching_ecosystem_range_is_affected` | GIT-only | SYNTH: GIT range alone; GIT + ECOSYSTEM | UNKNOWN; UNRESOLVED `RANGE_UNSUPPORTED`; AFFECTED inside, UNKNOWN outside | pass |
| `test_range_that_cannot_be_evaluated_is_unknown` (5), `test_unknown_event_after_introduced_counts_as_affected` | Odd ranges | Unparseable `fixed`, unknown type, no ranges and no versions, `events` / `ranges` a string; an unknown event name | UNKNOWN x5; AFFECTED (errs to the affected side) | pass |
| `test_explicit_versions_list`, `test_advisory_for_another_package_or_ecosystem`, `test_package_name_is_matched_canonically`, `test_withdrawn_advisory_is_not_a_finding` | Other statuses | `versions` list; other name / npm / no `affected`; `Foo_Bar`; `withdrawn` set | AFFECTED/NOT; OTHER_PACKAGE; AFFECTED; WITHDRAWN and OK | pass |
| `test_affected_wins_over_unknown`, `test_advisory_osv_returned_but_whose_range_excludes_the_version_is_unresolved`, `test_advisory_for_another_package_in_the_answer_is_unresolved` | Decision | GIT-only + affected; a real advisory fixed in 6.19.0 returned for 6.19.0; an advisory for another package | REJECTED; UNRESOLVED `RANGE_DISAGREEMENT` x2 | pass |
| `test_no_data_is_unresolved` | No data | Empty cache directory, offline | UNRESOLVED `ADVISORIES_UNAVAILABLE` | pass |
| `test_stale_cache_is_unresolved`, `test_cache_just_inside_the_age_limit_is_used`, `test_max_age_can_be_tightened`, `test_cache_dated_in_the_future_is_unresolved` | Stale | Cache 31 days old; 29.9 days; 2 days with limit 1; dated 400 days ahead | `ADVISORIES_STALE`; OK; `ADVISORIES_STALE` x2 | pass |
| `test_cache_whose_content_was_edited_is_unresolved`, `test_cache_entry_for_another_version_is_not_used`, `test_unreadable_cache_file_is_unresolved` (4) | Damaged cache | Advisory removed without updating the digest; file of 2.0 renamed to 1.0's key; not JSON / `[]` / `{}` / bad date | UNRESOLVED `ADVISORIES_UNAVAILABLE` | pass |
| `test_pypi_registry_fallback_is_not_osv_data` | Fallback mode | Only a `registry-*.json` file in the cache | UNRESOLVED `ADVISORIES_UNAVAILABLE` | pass |
| `test_malformed_advisory_list_is_unresolved` (6), `test_adapter_failure_is_unresolved` (5) | Bad answers | `vulnerabilities` a string / `None` / `[5]` / no id / numeric id / a dict; adapter returns `None`, a string, `{}`, unavailable, or raises | `ADVISORIES_INVALID`; `ADVISORIES_UNAVAILABLE` | pass |
| `test_live_answer_is_used_and_live_flag_is_passed_on`, `test_live_failure_falls_back_to_a_fresh_cache_and_says_so`, `test_live_failure_without_a_cache_is_unresolved` | Live path (offline) | Stub answer; `httpx.Client` made to fail with and without a 1-day-old cache | REJECTED, flags passed; OK with `live_error`; UNRESOLVED | pass |
| `test_invalid_request_is_unresolved` (4), `test_every_result_has_the_same_keys` | Request / shape | empty name, bad version, `None` | UNRESOLVED `INVALID_REQUEST`, adapter not called; same keys | pass |
| `test_live_osv_pypdf_5_1_0_is_rejected`, `test_live_osv_pypdf_6_19_0_gets_an_answer` (live) | Real OSV | Live query; then the same from the cache it wrote | REJECTED live and from cache; a live answer for 6.19.0 | pass (with `CAVR_LIVE=1`) |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Reading `package_records.affected` while writing the tests | A range with an event name it does not know (`{"until": …}`) after `introduced` is reported as affected, not as unknown. The first draft of the test expected UNKNOWN | Not a code defect: it errs to REJECTED. The expectation was corrected and the behaviour is pinned by `test_unknown_event_after_introduced_counts_as_affected` |
| 2 | Reading `osv_adapter.py` | The adapter accepts a cache file dated in the future (negative age passes `age <= max_age_days`) and raises on an unreadable cache file | Handled in the wrapper: future date -> `ADVISORIES_STALE`; any adapter exception -> `ADVISORIES_UNAVAILABLE`. The adapter was not edited (Ali's area) |

### Known limitations / deferred

- Offline with no cache younger than `max_age_days`, every package is UNRESOLVED. The first run needs network.
- The dashboard's `backend/cavr/osv_snapshot.json` and the `<=` rule in `resolver.py` are still in the
  dashboard path. -> step 13.
- Only the root package is checked by this function; the pipeline has to call it for every tree node. -> step 11.
- Advisory severity is not read: any affecting advisory rejects, whatever its severity.
- The recorded 5.1.0 file is trimmed (details, references, severity removed); the full answer is not stored.
- `match_advisory` compares the explicit `versions` list as text, as `affected` does (`"1.0"` does not equal `"1.0.0"` there).
- The two adapter weaknesses in defect 2 remain in `backend/integrations/osv_adapter.py` for its other callers.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `advisories.py`, `tests/test_cavr_advisories.py`, the two live tests, the recording and trimming of the two OSV answers (`curl` to api.osv.dev on 2026-10-10), these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet; the batch ran without stops.
- **Verified by:** the pytest runs above, including the live OSV run.

### Supervisor Q&A prep

1. **What was wrong with the old OSV check and what is "correct" now?**
   The dashboard path marked every version affected whenever a range contained `<=`. Now each range is
   walked event by event: `introduced` opens it, `fixed` closes it (exclusive), `last_affected` closes it
   (inclusive). pypdf 6.18.1 is affected by an advisory fixed in 6.19.0; 6.19.0 is not.
2. **A cached VERIFIED verdict exists. Why ask OSV again?**
   The wheel's bytes never change, but a new advisory can be published tomorrow. So the advisory answer
   is not part of the cached verdict and is checked on every request (plan design step 7).
3. **What happens offline?**
   The adapter's dated cache is used if it is at most 30 days old and its digest still matches.
   Otherwise the result is UNRESOLVED; CAVR never reports "no vulnerabilities" without an OSV answer.

## Step 8 — C3 light AST risk scan of wheel sources (2026-10-10)

Plan commit 8, `feat(cavr): C3 light AST risk scan of wheel sources`.
Reviewed by cavr-reviewer (1 batch pass over steps 4-8, by reading the code; the reviewer ran pytest only); batch verdict: fix first; 1 BLOCKER, fixed in the batch fix commit; 3 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/ast_scan.py` (new, 227 lines) | `scan_wheel(path, knowledge=None)` | Reads every `.py` entry of the wheel, parses it with `ast`, runs `trigger_discovery.scan` (imported, not edited) on it, and reports what it could not cover. Returns `result` (OK / UNRESOLVED / REJECTED), `rule`, `reason`, `analyzer_version`, `rules_digest`, `python_files`, `files_scanned`, `bytes_scanned`, `findings`, `sinks`, `triggers`, `dynamic_code`, `parse_errors`, `native_files`, `bytecode_files`, `pth_files`, `coverage`. |
| | `_scan` | The body: archive checks (`wheel_meta.check_entries`), per-file decode + parse + rule scan, `.pth` handling, sorting, findings. |
| | `_alias_pass(name, tree, rules)` | Per module: maps import aliases (`import socket as s`, `from subprocess import run`) to full names and reports sink calls the literal rule scan misses (`via_alias: true`), plus `compile` / `__import__` / `importlib.import_module` calls. |
| | `_decode` | Source bytes -> text using the PEP 263 encoding (`tokenize.detect_encoding`). |
| | `ANALYZER_VERSION` `"cavr-ast-scan/1"`, `MAX_SOURCE_BYTES` 5 MiB, `MAX_TOTAL_SOURCE_BYTES` 100 MiB, `INCOMPLETE` | Version for the cache key; budgets; finding kind -> rule, in priority order. |
| `backend/cavr/wheel_meta.py` | `WheelProblem` | Renamed from `_Stop` (now also caught by `ast_scan.py`). No behaviour change. |
| `tests/test_cavr_ast_scan.py` (new, 280 lines) | | 27 test functions, 42 cases. |
| `docs/cavr-m1-plan.md` | | Progress box 8 ticked. |

Key algorithm, `scan_wheel`:

1. `check_entries` (step 5): budget and path rules first; a zip bomb is never decompressed.
2. Every `.py` entry, in name order: over budget -> `SOURCE_TOO_LARGE`; decode; `ast.parse`; `scan({name: source})`; `_alias_pass`. A failure in any of these is a `PARSE_ERROR` finding for that file only.
3. `.pth` files: lines starting with `import` are code that Python runs at start-up -> `PTH_EXECUTABLE`, and those lines are scanned like a source file (line numbers kept). Path-only `.pth` -> `PTH_FILE`.
4. Native files (`.so/.pyd/.dll/.dylib`) -> `NATIVE_EXTENSION`; `.pyc` -> `BYTECODE_ONLY`.
5. Result: UNRESOLVED when any finding means "not covered" (`SCAN_BUDGET`, `SOURCE_NOT_PARSED`, `PTH_EXECUTES_CODE`, `COMPILED_CODE_NOT_SCANNED`, first in that order); otherwise OK `SCAN_COMPLETE`. Sinks, triggers and dynamic-code calls never change the result.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| `result` answers "was all code covered?", not "is it safe?" | REJECTED/UNRESOLVED as soon as a sink is found | The plan judges sinks by reachability in step 11 (pypdf has two `subprocess.run` calls and must still reach VERIFIED). The scan only supplies the evidence. |
| Native extension / `.pyc` -> UNRESOLVED | List it and stay OK | An AST scan cannot see compiled code; saying "complete" would be claiming knowledge CAVR does not have. Cost: packages with native wheels are UNRESOLVED in M1. Open for Maryam. |
| Executable `.pth` -> UNRESOLVED, and its code is scanned | Treat it as an ordinary file | It runs at every interpreter start without any call site, so the call-site reachability rule of step 11 cannot clear it. |
| One file at a time through `scan` | One `scan` call with all sources | `scan` only catches `SyntaxError`; any other failure on one file would lose the whole wheel. Per file, the others are still scanned (`test_scanner_crash_on_one_file_is_unresolved_not_an_exception`). |
| Alias pass added here, `trigger_discovery.py` untouched | Edit `scan`; no alias handling | The plan says import, do not edit. Without it `from subprocess import run; run(...)` is not a sink and the wheel would look clean. |
| `compile`, `__import__`, `importlib.import_module` are findings only | UNRESOLVED on any of them | They are common in honest code; they are recorded so the pipeline and a reader can see them. `exec` and `eval` are already rule sinks. |
| `rules_digest` in the result | Analyzer version alone | The sink list comes from the threat repository; a rule change must invalidate cached verdicts (step 10). |
| Sorted output, no timings | Report scan time | The same wheel gives an identical result dict (`test_same_wheel_gives_the_same_result`). |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| none listed | CLAUDE.md goal C3, "light AST risk scan" | Sink calls and gated branches in real wheel sources | `test_pypdf_wheel_scan`, `test_env_gated_socket_is_a_trigger_and_a_sink`, `test_sink_called_through_an_import_alias_is_still_found` |
| FR-6 | Fail-Closed Security Policy | Unparseable source, native code, executable `.pth` -> UNRESOLVED | `test_syntax_error_is_an_explicit_finding_and_unresolved`, `test_so_present_is_an_explicit_finding_and_unresolved`, `test_pth_file_that_executes_code_is_unresolved_and_its_code_is_scanned` |
| NFR-2 | (deterministic AST, no LLM; title to confirm) | Pure `ast`; same input -> same output | `test_same_wheel_gives_the_same_result` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 663 passed, 4 skipped (621 + 42 new).
- `.venv/bin/python -m pytest -q` -> 721 passed, 7 failed, 4 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 4 passed.
- Before `ast_scan.py` existed the test file failed at import (1 collection error); all 42 passed on the first run with the code.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_clean_module_has_no_findings`, `test_wheel_without_python_files_is_complete_and_empty` | Clean module | A module that only uses `json`; a wheel with no `.py` | OK `SCAN_COMPLETE`; no findings | pass |
| `test_env_gated_socket_is_a_trigger_and_a_sink` | Env-gated socket | `if os.getenv("DEPLOY_ENV") == "prod": socket.create_connection(...)` | OK; 1 sink (line 7, `NETWORK_CONNECT`); 1 trigger (line 6, input `DEPLOY_ENV`) | pass |
| `test_ungated_sinks_are_listed_with_their_capability` | Plain sinks | `os.system`, `subprocess.run`, `eval` | 3 sinks with `PROCESS_CREATE` / `NATIVE_EXEC` | pass |
| `test_sink_called_through_an_import_alias_is_still_found` (7) | Aliases | `import socket as s`; `from subprocess import run`; `from os import system as sh`; `import urllib.request as r`; `from urllib import request`; alias inside a function; `builtins.exec` | The real sink name, right line, `via_alias: true` | pass |
| `test_a_local_function_with_a_sink_like_name_is_not_a_sink` | No false alarm | A local `run()` and `system` class, no imports | No sinks | pass |
| `test_dynamic_import_and_compile_are_reported` | Dynamic code | `importlib.import_module`, `__import__`, `compile` | 3 `DYNAMIC_CODE` findings; result OK | pass |
| `test_pypdf_wheel_scan` | Real wheel | `artifacts/pypdf-6.19.0-py3-none-any.whl` | OK; 59 Python files; 2 sinks: `pypdf/filters.py` lines 774 and 804, `subprocess.run`; no triggers, parse errors, native or `.pth` files | pass |
| `test_syntax_error_is_an_explicit_finding_and_unresolved` | Syntax error | One broken file between two good ones | UNRESOLVED `SOURCE_NOT_PARSED`; the good files are still scanned | pass |
| `test_source_that_cannot_be_parsed_is_unresolved` (5) | Other unparseable | NUL byte; invalid UTF-8; unknown codec; Python 2 `print`; 5000 nested parentheses | UNRESOLVED `SOURCE_NOT_PARSED` | pass |
| `test_source_with_a_declared_encoding_is_decoded_with_it` | Encoding | latin-1 source with a coding line | OK; sink on line 4 | pass |
| `test_so_present_is_an_explicit_finding_and_unresolved`, `test_other_compiled_files_are_unresolved_too` (6) | `.so` present | `.so`; `.pyd`, `.dll`, `.dylib`, `libz.so.1`, `.pyc` | UNRESOLVED `COMPILED_CODE_NOT_SCANNED`; `NATIVE_EXTENSION` finding | pass |
| `test_pth_file_that_executes_code_is_unresolved_and_its_code_is_scanned`, `test_pth_file_with_only_paths_is_a_finding_but_the_scan_is_complete`, `test_pth_import_line_that_does_not_parse_is_unresolved` | `.pth` | `import os; os.system('id')` on line 3; paths only (one line starts with `important_dir`); a broken import line | `PTH_EXECUTES_CODE` with the sink at line 3; OK with `PTH_FILE`; `SOURCE_NOT_PARSED` | pass |
| `test_several_problems_are_all_listed_and_the_rule_is_the_first_in_order` | Priority | Broken file + `.so` + executable `.pth` | All three findings; rule `SOURCE_NOT_PARSED` | pass |
| `test_source_file_over_the_size_budget_is_unresolved`, `test_total_source_budget` | Budgets | Per-file budget 50 bytes; total budget 30 bytes | UNRESOLVED `SCAN_BUDGET` | pass |
| `test_not_a_wheel_is_unresolved`, `test_archive_checks_of_step_5_apply`, `test_zip_bomb_is_not_decompressed` | Archive | Not a zip / missing / `None`; a `../evil.py` entry; 30 MiB of `#` in one `.py` | `NOT_A_WHEEL`; REJECTED `UNSAFE_PATH`; `ZIP_BUDGET` with 0 bytes scanned | pass |
| `test_scanner_crash_on_one_file_is_unresolved_not_an_exception` | Isolation | `scan` made to raise for one file | UNRESOLVED; the other file's sink is reported | pass |
| `test_scanning_does_not_execute_the_package` | No execution | A module that would create a marker file; a `.pth` importing it | Marker file does not exist | pass |
| `test_same_wheel_gives_the_same_result`, `test_rules_digest_changes_with_the_rules`, `test_every_result_has_the_same_keys` | Determinism / shape | Two scans; empty rule set | Equal dicts, sorted sinks; different digest and no sinks; same keys | pass |

### Defects found and fixed

None found by the tests in this step. One simplification after the first green run: `bytes_scanned` is now
simply the total size of the files in `files_scanned`.

### Known limitations / deferred

- Syntactic only: no data flow and no call graph. A sink reached through `getattr`, a re-export in another
  module, a string passed to `exec`, or a method on an object (`sock.connect(...)`) is not found.
- A sink found through an alias inside a gated branch is reported as a sink but not as a trigger.
- A local name that shadows an imported sink name is still reported (errs to "found").
- Native wheels are always UNRESOLVED in M1; so is any package shipping a `.pyc` or a test file with
  deliberate syntax errors. Deep analysis is M2.
- The verdict rule for the findings (contract and reachability, `fast_gate.disabled_jbig2_sinks`) is not
  here. -> step 11. `DYNAMIC_CODE` findings have no consumer yet. -> step 11.
- Only the wheel given is scanned; the pipeline must call this for every tree node. -> step 11.
- Parsing uses the interpreter that runs CAVR: syntax newer than it is a parse error.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `ast_scan.py`, `tests/test_cavr_ast_scan.py`, the rename in `wheel_meta.py`, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet; the batch ran without stops. Open for her: native code and
  executable `.pth` are UNRESOLVED here rather than plain findings.
- **Verified by:** the pytest runs above; the pypdf numbers (59 files, sinks at `pypdf/filters.py:774` and `:804`)
  were first obtained by running `trigger_discovery.scan` directly on the wheel's sources.

### Supervisor Q&A prep

1. **The scan finds `subprocess.run` in pypdf. Why is pypdf not rejected?**
   The scan result only says the code was fully read. Whether a sink matters is decided later from the
   project's call sites: for pypdf the two calls are behind a configuration guard that the project
   disables (`fast_gate.disabled_jbig2_sinks`), so they are evidence, not a failure (plan step 11).
2. **What can a "light" AST scan not see?**
   Compiled code, code built at run time, and calls it cannot name syntactically. Compiled code and
   executable `.pth` lines make the result UNRESOLVED; the rest is listed under `coverage` and in the
   limitations, and is the reason deep analysis exists as M2.
3. **Does scanning run any package code?**
   No. Files are read from the zip into memory and given to `ast.parse`; nothing is imported or
   extracted (`test_scanning_does_not_execute_the_package`).

## Steps 4-8 — batch review fix (2026-10-10)

The fix commit after `c72b56a`, `fix(cavr): read .pth files the way site.py does`.
Steps 4-8 were committed as `00b9332`, `3ba4970`, `3cb1a35`, `b7c98cf`, `c72b56a`. The sections above describe
the code as committed there; this section lists what the fix commit changed. The fix has not been reviewed again.

### Ch 6 Implementation

| File | Function | Change |
|---|---|---|
| `backend/cavr/ast_scan.py` (227 -> 236 lines) | `_scan` | A `.pth` file is decoded with `utf-8-sig` (UTF-8, optional BOM), as `site.addpackage` does. Before, it went through `_decode`, which honours a PEP 263 coding line. Not UTF-8 -> `PARSE_ERROR` finding -> UNRESOLVED `SOURCE_NOT_PARSED`. `.py` files still use `_decode`. |
| `tests/test_cavr_ast_scan.py` (280 -> 301 lines) | | +2 test functions, +5 cases. |
| `docs/cavr-m1-plan.md` | | Commit hashes in the progress list; the 15 MINOR items under "Known issues deferred". |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Decode `.pth` exactly as the interpreter does | Keep the cookie-aware decode and also try UTF-8 | The scan must see the same lines Python would execute. One decoding, taken from `site.py`, is the only one that matters. |
| `.pth` that is not UTF-8 -> UNRESOLVED | Decode with the locale encoding like `site.py`'s fallback | The fallback depends on the machine that installs the package; CAVR cannot know it, so the content is unknown. |

### Requirements covered

FR-6 (Fail-Closed Security Policy, ID from `RequirementsTab.tsx`, Maryam to confirm): an executable `.pth`
can no longer be reported as a completed scan. Acceptance check:
`test_pth_is_decoded_as_site_py_does_whatever_its_coding_cookie_says`.

### Ch 7 Test cases

Run on 2026-10-10 after the fix:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 668 passed, 4 skipped (663 + 5 new).
- `.venv/bin/python -m pytest -q` -> 726 passed, 7 failed, 4 skipped (the same 7 baseline tests).
- Before the fix the 5 new cases were run against the committed code: 2 failed, 3 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_pth_is_decoded_as_site_py_does_whatever_its_coding_cookie_says` (4) | Hidden import line | `# coding: cp037` + `import os; os.system('id')`; the same with `utf-16`; a UTF-8 BOM before `import`; `import<TAB>os` | UNRESOLVED `PTH_EXECUTES_CODE`; sink `os.system` | pass (cases 1 and 2 failed before the fix: OK `SCAN_COMPLETE`, and `SOURCE_NOT_PARSED`) |
| `test_pth_that_is_not_utf8_is_unresolved` | Unknown encoding | `import os # \xff\xfe` | UNRESOLVED `SOURCE_NOT_PARSED` | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | cavr-reviewer (BLOCKER, step 8, by reading) | A `.pth` file starting with `# coding: cp037` was decoded as EBCDIC, so its `import os; os.system('id')` line was not seen: the scan returned OK `SCAN_COMPLETE` with a harmless `PTH_FILE` finding, while Python would run the line at start-up | Reproduced here against `c72b56a` (result OK), then fixed |

### Known limitations / deferred

The 15 MINOR items of the review are listed in `docs/cavr-m1-plan.md` under "Known issues deferred" (found in
the batch 4-8 review). One of them was a wrong line count in the Step 4 notes (443 -> 442), corrected in this
commit. The others were not changed. The reviewer derived every finding by reading and did not run the full
suite or open the recorded OSV file.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the review (the read-only `cavr-reviewer` subagent), the fix, the 5 new test cases, these notes, the commit.
- **Reviewed / decided by Maryam:** nothing in this commit yet. The fix was made without a stop, as `/cavr-batch` says for BLOCKERs.
- **Verified by:** the pytest runs above. The reviewer did not see the fix.

### Supervisor Q&A prep

1. **How do you know the scanner reads a `.pth` file the way the interpreter will?**
   It uses the same decoding as `site.addpackage` (UTF-8 with an optional BOM) and the same rule for an
   executable line (starts with `import` + space or tab). A file that is not UTF-8 is UNRESOLVED.
2. **Why was this a fail-open and not just a wrong label?**
   The result was OK `SCAN_COMPLETE`, so the pipeline would have had no reason to stop, while the file
   runs a shell command at every interpreter start.
3. **Is the same true for `.py` files?**
   No. For `.py` the interpreter itself honours the coding line, so `_decode` (PEP 263) is the matching
   decoding there (`test_source_with_a_declared_encoding_is_decoded_with_it`).

## Step 9 — C4 capability contract from real imports and call sites (2026-10-10)

Plan commit 9, `feat(cavr): C4 capability contract from real imports and call sites` (`a188cb6`).
Reviewed by cavr-reviewer (1 batch pass over steps 9-11; it ran both suites, findings derived by reading); batch verdict: fix first; 1 BLOCKER in this step, fixed in the batch fix commit; 3 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/context_extractor.py` (rewritten, 92 -> 233 lines) | `extract_project_context(project_dir=None)` | Reads every `.py` file of the project, parses it with `ast` (bytes in, so a PEP 263 coding line is honoured), and returns `result`, `rule`, `reason`, `project_dir`, `files` (path + SHA-256), `sources_digest`, `imports`, `call_sites`, `references`, `star_imports`, `parse_errors`, `not_read`, `skipped_directories`. The old `git diff` subprocess and the `used_apis` / `files_touched` / `git_diff` / `project_name` keys are gone (nothing read them). |
| | `usage_of(context, import_names)` | The imports, call sites, references and star imports whose top-level module is one of `import_names`. Relative imports never match. |
| | `_Uses` (an `ast.NodeVisitor`) | Per file: builds `local name -> real dotted name` from the import statements, then records each use of such a name once: `call`, `decorator` (a bare `@name`), or `reference`. |
| | `_python_files` | `os.walk` without following links. Skips dot-directories, `__pycache__`, `node_modules` and virtual environments (a directory holding `pyvenv.cfg`); a symbolic link is listed under `not_read`. |
| | `MAX_FILES` 5000, `MAX_FILE_BYTES` 2 MiB, `MAX_TOTAL_BYTES` 50 MiB | Budgets. |
| `backend/cavr/capability_contract.py` (`infer_capability_contract` rewritten, 143 -> 247 lines) | `infer_capability_contract(distribution, context=None, policy=None, knowledge=None)` | The contract of one distribution in one project. Returns `result`, `rule`, `reason`, `package`, `version`, `import_names`, `import_names_source`, `imports`, `call_sites`, `references`, `star_imports`, `entry_modules`, `allowed`, `denied`, `conflicts`, `capability_rules`, `task_description`, `vocabulary`, `sources_digest`, `authority`, `contract_rows`, `summary`, `digest`. |
| | `vocabulary(knowledge=None)` | The capability names of the threat-repository behaviour rules, in one spelling (`behavior_rules.normalize_name`). 10 names with the seed rules. |
| | `_capabilities` | Policy `allowed_scopes` + matching capability rules -> `allowed`, `denied`, `conflicts`. |
| | `_import_names`, `_entry_modules`, `_is_context`, `_contract` | Import names from the wheel metadata; dotted entry names for step 11; context shape check; one place that builds the result and its digest. |
| | `infer(context, node)` | Unchanged (orchestrator path, replaced in step 14). |
| `backend/cavr/wheel_meta.py` (260 -> 265 lines) | `_headers` | A METADATA or WHEEL header block with parser defects is UNRESOLVED (`METADATA_INVALID` / `NOT_A_WHEEL`). Deferred item from the batch 4-8 review. |
| `backend/cavr/api.py` | 2 lines | Passes `project_policy.json` to `infer_capability_contract`. |
| `frontend/src/components/cavr/CapabilityContractTab.tsx` | 4 lines | The confidence figure is shown only when a row has one (the new rows have none). |
| `tests/test_cavr_contract.py` (new, 478 lines) | | 43 test functions, 64 cases. |
| `tests/test_cavr_wheel_meta.py` | | +2 test functions. |

Key algorithm, `infer_capability_contract`:

1. Capabilities: each `allowed_scopes` entry `CAPABILITY:scope` is a grant, or a denial when the scope is `none`. A capability rule applies when every word of its `task` is in the policy's `project_task_description`. Allowed = granted by the policy and not denied by an applying rule; everything else in the vocabulary is denied.
2. Import names = the wheel's `import_names` + `undeclared_import_names` (step 5), never the distribution name.
3. `usage_of` selects the project's imports and uses of those names. No import, or an import that is never used -> UNRESOLVED `NO_CALL_SITE_AUTHORITY`; `from pkg import *` -> UNRESOLVED `STAR_IMPORT`; a project that was not fully read -> UNRESOLVED with the context's rule.
4. `digest` = SHA-256 of the canonical JSON of the contract (lists sorted) including `sources_digest`; `reason`, `version` and the dashboard rows are left out.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Import names from the wheel (`top_level.txt`, else RECORD, else the archive) plus undeclared names | Guess from the distribution name; the alias table in `context_service.py` | `invoice-tools` may install `invtools`. A guess attributes the wrong project code (`test_import_name_comes_from_top_level_txt_not_from_the_distribution_name`). |
| `sources_digest` (all project `.py` files) is part of the contract digest | Hash only imports and call sites | The verdict also depends on the code around a call site: changing `apply_configuration(jbig2dec_binary=None)` to another value keeps every call site the same. Without the sources the cache would return the old VERIFIED (`test_digest_changes_when_the_guard_changes_but_the_call_sites_do_not`). Cost: any `.py` edit in the project is a cache miss. |
| Allowed = policy grant minus task-rule denial; default deny | Rule `required` list alone; policy alone; the hardcoded PDF rule of the old code | The policy is the project owner's statement; the rule is a floor the policy cannot lift. A conflict is recorded in `conflicts`, the stricter side wins. |
| Rule chosen by the words of its `task` in `project_task_description` | A rule id per package in the policy; `if name == "pypdf"` as before | No policy change and no package names in code. Open for Maryam: an explicit policy key would be easier to defend than word matching. |
| Imported but never used -> UNRESOLVED | Treat the import as authority | An unused import says nothing about what the project needs from the package. |
| A reference (base class, `except` clause, bare decorator) counts as a use | Calls only | `class M(pkg.Base)` is real use without a call. |
| Star import of the package -> UNRESOLVED | Follow the names | The names it binds are decided by the package, not visible in the project source. |
| Symbolic link or unparseable project file -> context UNRESOLVED | Skip the file | An unread file may hold the call site that breaks the guard; `hashing.files` (orchestrator) also refuses links. |
| Malformed `allowed_scopes` -> UNRESOLVED; a missing key grants nothing | Ignore bad entries | A typo in a grant must not silently become something else; "no grants" is a definite, safe contract. |
| A bare package name is accepted as `distribution` | Raise | `api.py` has no wheel until step 13; it gets the policy rows and an UNRESOLVED authority instead of a guessed one. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| FR-3 | Capability Contract Inference | Required / denied capabilities from AST call sites, the policy and the threat-repository rules | `test_invoicehub_contract_for_pypdf`, `test_policy_grants_and_task_rule_denies` |
| FR-6 | Fail-Closed Security Policy | Unused package, star import, unread project, unknown import names, bad policy -> UNRESOLVED | `test_unused_package_has_no_call_site_authority`, `test_unresolved_project_context_makes_the_contract_unresolved`, `test_malformed_allowed_scopes_is_unresolved` |
| NFR-2 | Deterministic & No Paid LLM | Pure `ast`; stable digest | `test_digest_is_stable_across_reordering` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 734 passed, 4 skipped (668 + 66 new).
- `.venv/bin/python -m pytest -q` -> 792 passed, 7 failed, 4 skipped (the same 7 baseline tests).
- All 64 contract cases passed on the first run with the code. To check that they can fail, 8 one-line faults were put into the code one at a time (sources left out of the digest, rule denial ignored, import name guessed from the distribution name, unused import accepted, alias not resolved, symlink followed, parse error ignored, call sites not sorted); each made at least one test fail, and the files were restored.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_plain_import_and_call_site` | Basic record | `import pypdf` + `pypdf.PdfReader('a.pdf')` | 1 import, call site `app/read.py:3 pypdf.PdfReader` | pass |
| `test_aliased_import_is_resolved_to_the_real_module` | Aliased import | `import pypdf as p`; `p.PdfReader(x)` | symbol `pypdf.PdfReader`, expression `p.PdfReader` | pass |
| `test_from_x_import_y_as_z` | `from x import y as z` | `from pypdf import PdfReader as R`; `R(...)` | symbol `pypdf.PdfReader`, expression `R` | pass |
| `test_submodule_imports`, `test_decorator_and_base_class_uses`, `test_a_chain_is_recorded_once_and_arguments_are_visited` | Other forms | `import a.b`, `import a.b as g`, `except` clause, `@functools.cache`, base class, nested calls | Right symbol and kind, each chain once | pass |
| `test_local_names_and_relative_imports_are_not_attributed` | No false attribution | Local `PdfReader`, `from .helpers import PdfReader`, `self.reader.PdfReader(3)` | No call sites | pass |
| `test_virtualenvs_caches_and_hidden_directories_are_not_project_code` | File selection | `.venv`, `venv/pyvenv.cfg`, `node_modules`, `__pycache__`, `.git`, `build` | Only `app/a.py`, `build/b.py` read | pass |
| `test_missing_project_directory_is_unresolved`, `test_a_project_file_that_cannot_be_parsed_makes_the_context_unresolved` (5), `test_symbolic_links_are_not_followed_and_make_the_context_unresolved`, `test_symlinked_directory_is_not_followed`, `test_budgets` | Failure cases | Missing dir; syntax error, NUL, unknown codec, bad bytes, 5000 parentheses; link to a file / directory outside; small budgets | UNRESOLVED `PROJECT_MISSING` / `SOURCE_NOT_PARSED` / `SOURCE_NOT_READ` / `PROJECT_BUDGET` | pass |
| `test_reading_a_project_does_not_run_it` | No execution | A file that creates a marker when run | No marker after reading; marker appears when the file is really executed | pass |
| `test_invoicehub_contract_for_pypdf` | Real project + real wheel | `demo_project/InvoiceHub`, `artifacts/pypdf-6.19.0-py3-none-any.whl` | OK; call sites `app/pdf_adapter.py:7 pypdf.apply_configuration`, `:8 pypdf.PdfReader`; allowed `FILE_READ`, `FILE_WRITE`; rule `CAP-PDF-001` | pass |
| `test_import_name_comes_from_top_level_txt_not_from_the_distribution_name`, `test_undeclared_import_names_in_the_wheel_are_attributed_too` | Import-name mapping | Wheel `invoice-tools` with `top_level.txt` = `invtools`; a wheel with an undeclared package | `import invtools` attributed; `import invoice_tools` not | pass |
| `test_distribution_without_usable_import_names_is_unresolved` (7) | Unknown mapping | Name only, empty list, a string, a non-identifier, no name, `None` | UNRESOLVED `IMPORT_NAMES_UNKNOWN` | pass |
| `test_unused_package_has_no_call_site_authority`, `test_package_named_only_in_a_string_or_comment_is_not_imported`, `test_imported_but_never_used_has_no_call_site_authority` | Unused package | Project that only uses `json`; name in a comment / string; import without use | UNRESOLVED `NO_CALL_SITE_AUTHORITY` | pass |
| `test_star_import_of_the_package_is_unresolved` | Star import | `from pypdf import *` | UNRESOLVED `STAR_IMPORT`; a star import of `os.path` does not matter | pass |
| `test_policy_grants_and_task_rule_denies`, `test_without_a_matching_task_rule_only_the_policy_decides`, `test_http_client_task_selects_the_http_rule`, `test_disabled_rule_is_not_applied` | Capability derivation | Policy grants `NETWORK_CONNECT` for a PDF task; a task no rule matches; an HTTP-client task; `CAP-PDF-001` disabled | Grant refused with a `conflicts` entry; policy alone; `CAP-HTTP-001`; rule not applied | pass |
| `test_malformed_allowed_scopes_is_unresolved` (9), `test_unusable_policy_is_unresolved` (4), `test_policy_without_allowed_scopes_grants_nothing` | Policy errors | Not a list, no scope, unknown capability, same capability twice; no policy | UNRESOLVED `CAPABILITY_POLICY_INVALID`; no key -> 0 allowed, 10 denied | pass |
| `test_digest_is_stable_across_reordering` | Digest stable | Shuffled context lists, reversed policy keys and scopes, same project in another directory | Same digest | pass |
| `test_digest_changes_when_a_new_call_site_appears`, `test_digest_changes_when_a_call_site_moves_or_is_removed` | Digest sensitive | `pypdf.PdfWriter()` added; a blank line added; a file removed | Different digests | pass |
| `test_digest_changes_when_the_guard_changes_but_the_call_sites_do_not` | Cache safety | `jbig2dec_binary=None` -> `'x'` | Same call sites, different digest | pass |
| `test_digest_changes_with_the_policy_the_rules_and_the_import_names` | Digest inputs | Fewer scopes; a rule edited; one more import name; an unrelated policy key | 4 different digests; unrelated key -> same digest | pass |
| `test_a_line_that_is_not_a_header_inside_the_header_block_is_unresolved`, `test_malformed_wheel_file_is_unresolved` (`test_cavr_wheel_meta.py`) | Header defects | METADATA / WHEEL with a non-header line before a later field | UNRESOLVED `METADATA_INVALID` / `NOT_A_WHEEL` | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Design, before coding | A contract digest made only of call sites would let the cache return a VERIFIED that was judged with the pypdf guard in place after the guard's argument was changed | `sources_digest` added to the digest; covered by a test |
| 2 | Deferred item (batch 4-8 review) | `wheel_meta._headers` ignored parser defects, so a `Requires-Dist` after a non-header line was silently dropped | Fixed here with 2 tests |

### Known limitations / deferred

- Syntactic and per file: no scopes, no data flow. A call on an object (`reader.pages`), through `getattr`, or on a name re-exported by another project module is not a call site.
- A project module with the same name as the package's import name is counted as the package.
- A namespace package shared by several distributions (`google`) is attributed to each of them.
- A name listed in `top_level.txt` but not shipped in the wheel is still matched.
- The dashboard (`api.py`) shows the policy-derived rows with an UNRESOLVED authority until step 13.
- Rule selection by task words is coarse; only two capability rules exist in the seed data.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `context_extractor.py`, the new `infer_capability_contract`, the `wheel_meta._headers` fix, the `api.py` and `.tsx` lines, the tests, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet; the batch ran without stops. Open for her: the rule-selection method and the "imported but unused -> UNRESOLVED" choice.
- **Verified by:** the pytest runs above and the 8 fault injections; the InvoiceHub call sites (`app/pdf_adapter.py:7` and `:8`) match the file.

### Supervisor Q&A prep

1. **How does CAVR know which package an `import` belongs to?**
   From the wheel itself: `top_level.txt` (or RECORD, or the archive) lists the import names. The distribution name is never used as a guess.
2. **Why is a package that the project never imports UNRESOLVED and not VERIFIED?**
   The contract is "what this project needs from the package". With no call site there is nothing to derive it from, so no capability can be justified.
3. **Why does the contract digest include all project source files?**
   The verdict depends on the code around a call site, not only on the call site. Hashing the sources guarantees a cached verdict is only reused for the exact project state it was judged against.

## Step 10 — 8-field verdict cache (2026-10-10)

Plan commit 10, `feat(cavr): 8-field verdict cache` (`d8e6367`).
Reviewed by cavr-reviewer (1 batch pass over steps 9-11); batch verdict: fix first; 0 BLOCKERs and 0 MINOR in this step.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/verdict_cache.py` (new, 149 lines) | `KEY_FIELDS` | The eight fields: `ecosystem`, `name`, `version`, `artifact_sha256`, `subtree_digest`, `contract_digest`, `policy_version`, `analyzer_version`. |
| | `cache_key(fields)` | Returns `(key, normalised fields, None)` or `(None, None, reason)`. Exactly the eight keys, every value a non-empty string, ecosystem PyPI, a valid name and non-local version, four 64-hex digests. The key is the SHA-256 of the canonical JSON of the normalised values, with the version in canonical form. |
| | `lookup(storage, fields)` | `hit`, `rule` (`HIT`, `MISS`, `KEY_INCOMPLETE`, `ROW_TAMPERED`, `CACHE_UNAVAILABLE`), `reason`, `key`, `verdict`, `stored_at`, `fields`. |
| | `store(storage, fields, verdict)` | `stored`, `rule` (`STORED`, `NOT_CACHEABLE`, `KEY_INCOMPLETE`, `CACHE_UNAVAILABLE`), `reason`, `key`, `stored_at`. Only a JSON object whose `status` is VERIFIED or REJECTED, at most `MAX_VERDICT_BYTES` (2 MiB). |
| | `row_integrity(row)` | SHA-256 over `cache_key`, the eight fields, `status`, `verdict_json`, `stored_at`. |
| | `_sound(row, key)` | A row is used only if its integrity digest matches, its own eight columns give the key it is filed under, its status is cacheable, and its verdict JSON has that status. |
| `backend/cavr/storage.py` (247 -> 281 lines) | table `verdict_cache`, `get_cached_verdict(cache_key)`, `put_cached_verdict(row)` | One row per key (`INSERT OR REPLACE`). The table is created with `CREATE TABLE IF NOT EXISTS`, so an existing database gets it on the next start. |
| `backend/cavr/dep_tree.py` (232 -> 250 lines) | `build_tree`, `_expand`, `subtree_digest`, `_canonical` | One node per release however the version is written (`known` maps `(name, Version)` to the node key in use); the subtree digest uses canonical versions. Deferred items from the batch 1-3 and 4-8 reviews. |
| `tests/test_cavr_verdict_cache.py` (new, 298 lines) | | 27 test functions, 102 cases. |
| `tests/test_cavr_dep_tree.py` | | +2 test functions; 1 test renamed to say what it checks (deferred item). |

Key algorithm:

1. `cache_key`: refuse unless all eight fields are usable; normalise (canonical name, `str(Version)`, lower-case digests); hash, with the version as `canonicalize_version` gives it.
2. `store`: refuse anything but VERIFIED / REJECTED; serialise the verdict as canonical JSON; write the row with `row_integrity`.
3. `lookup`: no key -> `KEY_INCOMPLETE`; no row -> `MISS`; a row that fails `_sound` -> `ROW_TAMPERED`; otherwise `HIT` with a fresh copy of the verdict.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| A missing or malformed field gives no key | Hash `None` as a value | Two requests whose tree or contract is unknown would otherwise share one entry. |
| UNRESOLVED and BLOCK are never stored | Cache everything with a short lifetime | UNRESOLVED means "not known"; storing it would freeze a network failure. BLOCK is decided before any artifact exists, so there is nothing to key on. |
| The row holds the eight fields as columns, and the key is recomputed from them on read | Store the key only | A row copied under another key is detected even if its digest was recomputed (`test_a_forged_row_whose_fields_do_not_give_its_key_is_ignored`). |
| Integrity digest is a plain SHA-256 | HMAC with a secret outside the database | Detects damage and single-column edits. A keyed digest needs key management (M2). The limit is stated in the module docstring. |
| `1.0` and `1.0.0` give one key | Version text as written | They are one release on PyPI; the deferred review item asked for it. |
| Cache errors are a miss, never an exception | Let `sqlite3.Error` propagate | A broken cache must cost time (a full analysis), not a verdict. |
| `analyzer_version` is an opaque string here | Build it in this module | The pipeline knows which analyser code and rule set judged the artifact (step 11). |
| New table in `storage.py`, logic in `verdict_cache.py` | All in `storage.py` | The plan names both files; the storage class stays plain SQL. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| none listed | CLAUDE.md goal C3, "verdict cache keyed on the 8-field digest" | Key, store, lookup | `test_hit_on_identical_inputs`, `test_miss_when_one_field_changes` (8) |
| FR-6 | Fail-Closed Security Policy | Tampered row ignored; UNRESOLVED not stored; incomplete key not used | `test_tampered_row_is_ignored` (6), `test_only_verified_and_rejected_are_stored` (7), `test_incomplete_key_is_neither_looked_up_nor_stored` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 838 passed, 4 skipped (734 + 104 new).
- `.venv/bin/python -m pytest -q` -> 896 passed, 7 failed, 4 skipped (the same 7 baseline tests).
- Fault injection, one line at a time, files restored after each: integrity not checked, UNRESOLVED made cacheable, contract digest left out of the key, a missing field accepted, row status not checked, `stored_at` left out of the integrity digest, version not canonicalised -> each made 1 to 9 tests fail. "Key not recomputed from the row" first made no test fail; `test_a_forged_row_whose_fields_do_not_give_its_key_is_ignored` was added and now fails with that fault.
- The 2 new `dep_tree` tests failed against the committed `dep_tree.py` and pass with the change.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_the_key_has_exactly_the_eight_fields` | Key shape | The eight fields, in two orders | 64-hex key, same for both | pass |
| `test_spellings_of_the_same_release_give_the_same_key` (7), `test_name_canonicalisation_in_the_key` | Normalisation | `PyPDF`, `6.19`, `6.19.0.0`, `pypi`, upper-case digest; `Foo_Bar` / `foo-bar` | Same key | pass |
| `test_hit_on_identical_inputs`, `test_hit_through_another_spelling_of_the_same_release` | Hit | Store, then look up the same fields | `HIT` with the stored verdict | pass |
| `test_miss_when_one_field_changes` (8), `test_each_field_changes_the_key` (8) | Miss per field | Each of the 8 fields changed, one at a time | `MISS` (`KEY_INCOMPLETE` for another ecosystem); the original entry still hits | pass |
| `test_a_missing_or_malformed_field_gives_no_key` (32), `test_unusable_values_give_no_key` (9), `test_a_missing_or_extra_field_gives_no_key`, `test_incomplete_key_is_neither_looked_up_nor_stored` | Incomplete key | `None`, `""`, a number, a list in each field; `npm`, a local version, a short digest; 7 or 9 fields | No key; nothing stored | pass |
| `test_only_verified_and_rejected_are_stored` (7), `test_unresolved_does_not_replace_a_stored_verdict` | UNRESOLVED not stored | `UNRESOLVED`, `BLOCK`, `PERMITTED`, `OK`, `verified`, `""`, `None` | `NOT_CACHEABLE`; 0 rows; an existing VERIFIED stays | pass |
| `test_rejected_is_cached_too`, `test_a_new_verdict_for_the_same_key_replaces_the_old_one`, `test_the_cache_survives_a_new_storage_object`, `test_the_returned_verdict_is_a_copy` | Normal use | REJECTED; two stores; a second `CavrStorage` on the file; mutating the returned dict | Stored; 1 row; hit; cache unchanged | pass |
| `test_a_verdict_that_is_not_a_json_object_is_not_stored` (6), `test_an_oversized_verdict_is_not_stored` | Bad verdicts | `None`, a string, a set inside, NaN; over the size limit | `NOT_CACHEABLE` | pass |
| `test_tampered_row_is_ignored` (6) | Tampered row | Verdict JSON + status rewritten to VERIFIED; status column; a key column; `stored_at`; integrity; broken JSON | `ROW_TAMPERED`; a new verdict can be stored over it | pass |
| `test_a_row_moved_under_another_key_is_ignored`, `test_a_forged_row_whose_fields_do_not_give_its_key_is_ignored`, `test_a_row_with_a_status_that_is_never_cached_is_ignored` | Forged rows | A genuine row copied under another key; the same with the digest recomputed; an UNRESOLVED row with the digest recomputed | `ROW_TAMPERED` | pass |
| `test_database_failure_is_a_miss_not_an_exception`, `test_storage_without_the_cache_methods_is_a_miss`, `test_the_table_is_created_in_an_existing_database` | Storage errors | Table dropped; `None` storage; an old database file | `CACHE_UNAVAILABLE`; table created | pass |
| `test_the_same_release_written_two_ways_is_one_node`, `test_subtree_digest_does_not_depend_on_how_a_version_is_written` (`test_cavr_dep_tree.py`) | Version spelling | Request `app==1.0`, lockfile `app==1.0.0`, a cycle back to `app` | One `app` node, fetched once; same digest for `1.0` and `1.0.0` | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Fault injection | Removing the "row fields give the key" check failed no test: the integrity digest alone caught the copied row | Test added for a forged row with a recomputed digest |
| 2 | Deferred items (batch 1-3 and 4-8 reviews) | The version as written fed the key; `1.0` and `1.0.0` could be two tree nodes | Canonical version in the key; one node per release in `dep_tree` |

### Known limitations / deferred

- The integrity digest is not keyed. Someone who can write the database can store a complete, consistent forged row. Mitigation in step 11: the artifact hash and the advisories are checked again on every hit. A keyed digest -> M2.
- No expiry and no size limit on the table; old rows stay until overwritten.
- The request spelling of the root version (`1.0` vs `1.0.0`) is kept in the tree's labels; only keys and digests are canonical.
- The cache is not called by anything until step 11.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `verdict_cache.py`, the table and two methods in `storage.py`, the `dep_tree.py` change, the tests, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet; the batch ran without stops.
- **Verified by:** the pytest runs and the fault injections above.

### Supervisor Q&A prep

1. **Why eight fields and not just name, version and hash?**
   The verdict also depends on the dependency tree under the package, on how this project uses it, on the project policy, and on the analyser that judged it. If any of them changes, the old verdict was for a different question.
2. **What stops someone editing the cache to say VERIFIED?**
   Each row carries a digest of its content and is checked against its own key; an edited row is ignored. The digest is not secret, so a full rewrite is possible for someone with database access; that is why a hit still re-checks the artifact hash and OSV.
3. **Why is UNRESOLVED not cached?**
   It means the answer is not known (for example the network was down). Caching it would keep answering "unknown" after the cause is gone.

## Step 11 — single verify_request pipeline (2026-10-10)

Plan commit 11, `feat(cavr): single verify_request pipeline` (`c5c0ef4`).
Reviewed by cavr-reviewer (1 batch pass over steps 9-11); batch verdict: fix first; 6 BLOCKERs in this step, fixed in the batch fix commit; 8 MINOR open.
This section describes the code as committed in `c5c0ef4`; the sink judgement and the pypdf proof were changed by the fix commit (next section).

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/pipeline.py` (new, 347 lines) | `verify_request(request, project_dir, policy, store, *, transport, quarantine_dir, advisory_cache_dir, live_advisories, osv, knowledge, environment, lockfile_name)` | Runs the nine stages in the plan's order and returns `status` (VERIFIED / REJECTED / UNRESOLVED / BLOCK), `stage`, `rule`, `reason`, `fast_gate_ms`, `cache_hit`, `escalated`, `escalation`, `request`, `gate`, `lockfile`, `project`, `packages`, `policy_version`, `analyzer_version`, `logged`. |
| | `_verify_package` | Stages 3-9 for one permitted requirement: `build_tree`, contract, cache `lookup`, `check_advisories` for every tree node, then the cached analysis or `_analyse`. |
| | `_analyse` | Re-hashes each wheel in quarantine, `scan_wheel` on every tree node, `judge_sinks`. This result is what is cached. |
| | `analyzer_version(knowledge)` | `cavr-pipeline/1;cavr-ast-scan/1;rules:<digest of the sink rules>`; the 8th key field. |
| | `metrics(store)` | Verdict count, cache hits, hit rate, p50 / p95 of `fast_gate_ms` (nearest rank), counts by status, from the verdict log. |
| | `ESCALATION` | `"deep analysis required (M2)"`. |
| `backend/cavr/reachability.py` (new, 274 lines) | `judge_sinks(nodes, scans, contract, context)` | Each sink gets ALLOWED, GUARD_DISABLED, UNREACHABLE or REACHABLE; any REACHABLE -> UNRESOLVED `SINK_REACHABLE`. |
| | `import_graph`, `module_name`, `_closure` | Import graph over all wheels of the tree; the closure from the contract's `entry_modules`. |
| | `_pypdf_proof`, `_unseen_use`, `_guard_problem`, `ProjectSources` | Calls `fast_gate.disabled_jbig2_sinks` (not edited) through an adapter and accepts its answer only under two extra conditions (see Defects). |
| `backend/cavr/storage.py` | table `verdict_log`, `record_verdict`, `get_verdict_log` | One row per `verify_request` call. |
| `backend/cavr/dep_tree.py` | `failed_nodes` in the tree result | Keeps the full download / metadata result of a node that failed (the evidence of a hash mismatch). |
| `backend/cavr/ast_scan.py` | `.pyw` scanned; `NOT_SCANNED` finding -> UNRESOLVED `CODE_NOT_SCANNED`; star imports in `_alias_pass`; `not_scanned_files` | Deferred items of the batch 4-8 review. |
| `backend/cavr/pypi_client.py` | `select_wheel` (duplicate filename, NUL -> `REGISTRY_INVALID`), `NAME.fullmatch`, `HttpxTransport(transport=)`, stale good file removed on `HASH_MISMATCH` | Deferred items. |
| `backend/cavr/wheel_meta.py` | NFC + casefold in the duplicate-name check, `NAME.fullmatch` | Deferred items. |
| `backend/cavr/requirement_gate.py` | `load_json_file` catches `RecursionError`; docstring reworded | Deferred items. |
| Tests | `test_cavr_pipeline.py` (new, 626 lines, 43 functions), `test_cavr_reachability.py` (new, 304 lines, 18 functions), additions in `test_cavr_ast_scan.py`, `test_cavr_pypi_client.py`, `test_cavr_wheel_meta.py`, `test_cavr_requirement_gate.py`, `test_cavr_dep_tree.py`, `test_cavr_live.py`, helpers in `test_cavr_support.py` | |

Key algorithm, verdict of one package: tree REJECTED -> REJECTED; any advisory REJECTED -> REJECTED (also on a cache hit and also when the contract is unknown); tree / request-hash / contract / advisory unknown -> UNRESOLVED; cache hit -> the stored analysis; otherwise scan + sink judgement, stored if VERIFIED or REJECTED.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Only the scan + sink analysis is cached; the advisory result never is | Cache the final verdict | A cached REJECTED-by-OSV would stay after the advisory is withdrawn; a cached VERIFIED must turn REJECTED when OSV changes. |
| OSV is asked for every node of the tree, and before the UNRESOLVED checks | Root only; stop at the first unknown | A vulnerable dependency, or a vulnerable package the project does not import yet, is REJECTED rather than UNRESOLVED. |
| "Call-site path" = import closure from the contract's entry modules | Every sink reachable once the package is used; a real call graph | Follows every `import` statement from what the project imports, needs no execution, and leaves a real "unreachable" class (a `cli.py` nobody imports). It is a bound only while a module's path in the wheel is its import name; the cases where it is not were found in the review and are in the next section. |
| The pypdf guard is accepted only with two extra conditions | Trust `disabled_jbig2_sinks` alone | On its own it accepts five project shapes where a reader is unguarded (tests below). The plan says not to edit it, so the conditions are added around it. |
| `build_tree` does stages 3 and 4 together | Download the root twice | One download per file; the root's download result is still reported as stage `artifact`. |
| A fault inside a stage -> UNRESOLVED `INTERNAL_ERROR` | Let it raise | Unknown must never become a pass, and the caller always gets the metric fields. |
| A project without a lockfile is allowed (stated in `lockfile.present`) | Require a lockfile | `pip install` in a new project is a normal M1 case; any dependency then makes the tree UNRESOLVED. Open for Maryam. |
| Hit rate = hits / all logged verdicts | hits / verdicts that reached the lookup | Simple and stated; a BLOCK counts as "not a hit". |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| FR-2 | Requirement Gate Enforcement | BLOCK before any download | `test_gate_block_makes_zero_downloads` (7) |
| FR-3 | Capability Contract Inference | Sinks judged against the contract | `test_sink_allowed_by_the_policy_is_evidence`, `test_reachable_denied_sink_is_unresolved_and_escalated` |
| FR-6 | Fail-Closed Security Policy | Network loss, unknown advisories, unread project, stage fault -> UNRESOLVED | `test_registry_unreachable_is_unresolved`, `test_advisories_unavailable_is_unresolved`, `test_a_fault_inside_a_stage_is_unresolved_not_an_exception` |
| none listed | CLAUDE.md "Output VERIFIED / REJECTED / UNRESOLVED with evidence"; plan fields `fast_gate_ms`, `cache_hit`, `escalated` | One path, evidence per stage, metric fields on every status | `test_pypdf_6_19_0_is_verified_with_the_guard_evidence`, `test_metric_fields_are_present_on_every_status` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 968 passed, 5 skipped (838 + 130 new).
- `.venv/bin/python -m pytest -q` -> 1026 passed, 7 failed, 5 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 5 passed, including the whole pipeline against the real PyPI and OSV.
- Fault injection, one line at a time, files restored: 11 faults in `reachability.py` and 13 in `pipeline.py` (gate result ignored, OSV ignored on a hit, unresolved contract / advisories / tree / scan ignored, no re-hash before the scan, no escalation, request hash ignored, contract digest not in the key, dependencies not OSV-checked, proof conditions removed, dynamic import not widening, ...). Every one made at least one test fail.
- The tests of the deferred fixes were run against the previously committed modules: 24 failed there, all pass now (the 7 `HttpxTransport` cases failed only because the `transport=` argument did not exist).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_pypdf_6_19_0_is_verified_with_the_guard_evidence` | End to end | Real pypdf wheel + recorded registry JSON, InvoiceHub `app/`, recorded OSV answer | VERIFIED; SHA-256 `7e5d6e73…8d14`; sinks `pypdf/filters.py:774`, `:804` GUARD_DISABLED; proof accepted; stored under the 8-field key | pass |
| `test_the_same_project_with_a_reader_outside_the_guard_is_unresolved_and_escalated` | Guard removed | The same project plus an unguarded `PdfReader` | UNRESOLVED `SINK_REACHABLE`; `escalation` set, `escalated: true`; nothing cached | pass |
| `test_verified_then_guard_removed_is_not_served_from_the_cache` | Cache safety | VERIFIED run, then `jbig2dec_binary=None` changed | UNRESOLVED, `cache_hit: false` | pass |
| `test_gate_block_makes_zero_downloads` (7), `test_missing_or_invalid_policy_is_unresolved_with_zero_downloads` (3), `test_requests_that_cannot_be_captured_are_unresolved_with_zero_downloads` (11) | Before any download | Denylist, not allowlisted, unpinned, not in lockfile; no policy; non-pip command, URL, custom index, missing `-r` file | BLOCK / UNRESOLVED; the index was never asked | pass |
| `test_one_flipped_byte_is_rejected` | Hash | One bit of the served wheel flipped | REJECTED `HASH_MISMATCH`; file kept as `.rejected`; no scan, no cache row | pass |
| `test_known_vulnerability_is_rejected_with_the_advisory_id`, `..._even_when_the_project_never_imports_the_package`, `test_vulnerable_dependency_rejects_the_request` | OSV | tmp-built wheels with `SYNTH-` advisories | REJECTED `KNOWN_VULNERABILITY` with the id | pass |
| `test_registry_unreachable_is_unresolved`, `test_download_cut_off_is_unresolved`, `test_advisories_unavailable_is_unresolved`, `test_everything_offline_is_unresolved_not_an_exception` | Network loss | Transport errors; no advisory data | UNRESOLVED | pass |
| `test_second_run_is_a_cache_hit_that_still_checks_osv` | Cache hit | Two runs | Second: `cache_hit: true`; scan ran once, OSV asked twice, artifact hashed twice | pass |
| `test_cached_verified_turns_rejected_when_the_advisory_data_changes`, `test_cache_hit_with_advisories_unavailable_is_unresolved` | Hit + OSV | Advisory added after a VERIFIED; advisory data removed | REJECTED with `cache_hit: true`, back to VERIFIED when it is withdrawn; UNRESOLVED | pass |
| `test_policy_change_is_a_cache_miss`, `test_rule_change_is_a_cache_miss`, `test_another_project_does_not_share_the_verdict`, `test_tampered_cache_row_is_ignored_and_the_package_is_analysed_again`, `test_without_a_store_every_run_is_a_full_analysis` | Cache misses | Policy, sink rules, project, row edited, no store | Miss; full analysis | pass |
| `test_metric_fields_are_present_on_every_status`, `test_verdicts_are_logged_and_the_report_numbers_come_from_the_log` | Metrics | One verdict of each status; 4 logged runs | Three fields everywhere, same keys; hit rate 0.5, p50 / p95 from the log | pass |
| `test_unreachable_sink_is_evidence_and_the_package_is_verified`, `test_native_code_is_unresolved_without_escalation`, `test_artifact_changed_between_hashing_and_scanning_is_unresolved`, `test_unpinned_dependency_makes_the_tree_unresolved`, `test_lockfile_hash_that_differs_from_the_download_is_unresolved`, `test_project_without_a_lockfile`, `test_project_that_cannot_be_read_is_unresolved`, `test_local_version_is_unresolved_before_any_download` | Edge cases | As named | VERIFIED with UNREACHABLE evidence; otherwise UNRESOLVED with the stage's rule | pass |
| `test_several_requirements_the_worst_one_decides`, `test_requirements_file_with_the_right_hash_and_with_a_wrong_one`, `test_requirements_edit_*` (2), `test_bad_requirements_snapshots_are_unresolved_not_an_exception` (5), `test_a_captured_record_can_be_passed_in` | Request forms | Two packages; `--hash`; edits; bad snapshots | Worst status wins; `REQUEST_HASH_MISMATCH`; `NOTHING_TO_VERIFY`; `CAPTURE_FAILED` | pass |
| `test_verifying_does_not_install_or_run_the_package` | No execution | A module that creates a marker when imported | No marker, not importable; marker appears when really run | pass |
| `test_cavr_reachability.py` (18 functions, 36 cases) | Sink judgement | Module names, import graph, entry modules, dependency sinks, dynamic import, unreadable wheel, the pypdf proof | As named | pass |
| `test_the_proof_is_refused_when_the_project_enters_pypdf_in_a_way_the_guard_does_not_see` (5) | Reused guard is too lenient | `pypdf.PdfReader(p)` in another file; `PdfReader as R`; `PdfWriter(clone_from=p)`; `FACTORY = PdfReader`; nested guards + one unguarded reader | `disabled_jbig2_sinks` alone returns `[774, 804]`; the pipeline does not accept it -> UNRESOLVED | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Reading `fast_gate.disabled_jbig2_sinks` | It matches only the text `PdfReader(` and counts a reader once per enclosing guard, so it reports the sinks as disabled for five kinds of project that have an unguarded entry into pypdf | Not edited (plan). `reachability.py` accepts the proof only when every contract use of pypdf is a bare `PdfReader(...)` / `apply_configuration(...)` call and its own AST check finds every reader inside exactly the `jbig2dec_binary=None` guard. 5 tests show the difference |
| 2 | Tests | `dep_tree` dropped the download result of a failed node, so a hash mismatch had no SHA-256 in the evidence | `failed_nodes` added |
| 3 | Deferred review items | 10 items of the batch 1-3 and 4-8 reviews marked "-> step 11" | Fixed with tests (listed in `docs/cavr-m1-plan.md`) |

### Known limitations / deferred

- **The pypdf proof, as committed in this step, was about where the reader is created.** A page decoded after the `with` block had ended was not covered and the project was still VERIFIED. Narrowed in the batch fix commit (next section).
- The import closure cannot see imports built at run time other than `__import__` / `importlib.import_module`, nor `exec` of a string (that is itself a sink).
- A root requirement's marker is ignored (the package is verified whether or not the marker applies).
- Every run downloads the tree again; the cache saves the scan, not the network.
- Still deferred: the download deadline under a slow drip (`pypi_client._chunks`), removed option lines of a requirements edit, the test-name item in `test_cavr_advisories.py`, the `manifest_parser.py` docstring.
- `api.py` and `analyzer.py` do not call the pipeline yet (steps 13, 14); the pip wrapper is step 12.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `pipeline.py`, `reachability.py`, the changes in the other modules, all tests, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet.
- **Verified by:** the pytest runs, the live run and the 24 fault injections above; then the cavr-reviewer pass (next section).

### Supervisor Q&A prep

1. **Why is pypdf VERIFIED although it calls `subprocess.run`?**
   The contract denies process execution, so the two calls are judged by reachability. The project creates every reader inside `apply_configuration(jbig2dec_binary=None)`, and pypdf's decoder returns before the call when that setting is None; that proof is in the evidence. Remove the guard and the verdict is UNRESOLVED with an escalation.
2. **What does a cache hit skip, and what does it not skip?**
   It skips the AST scan and the sink judgement. The download, the SHA-256 check, the tree, the contract and the OSV query run every time, because the first four make the key and advisories change.
3. **How are the report numbers produced?**
   Every call writes one row (status, `fast_gate_ms`, `cache_hit`, `escalated`) to `verdict_log`; `pipeline.metrics(store)` computes the hit rate and the p50 / p95 from those rows.

## Steps 9-11 — batch review fix (2026-10-10)

The fix commit after `c5c0ef4`, `fix(cavr): close fail-open paths in the sink judgement and the pypdf proof`.
Steps 9-11 were committed as `a188cb6`, `d8e6367`, `c5c0ef4`. The sections above describe the code as committed
there; this section lists what the fix commit changed. The fix has not been reviewed again.

### Ch 6 Implementation

| File | Function | Change |
|---|---|---|
| `backend/cavr/reachability.py` (274 -> 409 lines) | `judge_sinks` | (1) A sink is ALLOWED only when its capability is granted with the scope `*`; a grant with any other scope does not clear it. (2) Entry modules are every module of the tree that the project imports or uses, not only those of the requested package, plus `sitecustomize` / `usercustomize`. (3) No sink is UNREACHABLE when the project imports no module of the wheels, or a `.pth` file adds an import path. |
| | `_project_entries` (new) | Entry names from all imports, call sites, references and star imports of the project. |
| | `import_graph` | Also returns `owners` (which package ships a module). |
| | `_pypdf_proof`, `_other_callers`, `_foreign_names`, `_guard_around`, `_reader_problem` (new), `_guard_problem` (rewritten) | The proof is accepted only when: pypdf is the requested package and no other wheel imports it; `PdfReader` and `apply_configuration` are imported only as `from pypdf import ...`, never defined, assigned or reached as an attribute, and every call of them is a contract call site; the reader is created as `name = PdfReader(...)` inside the guard and that name is only used inside a guard block, as `name.<attribute>`, in code that runs there. The proof carries `limit`. |
| `backend/cavr/context_extractor.py` (233 -> 238 lines) | `_python_files` | `os.walk(..., onerror=...)`: a directory that cannot be listed goes to `not_read` -> UNRESOLVED `SOURCE_NOT_READ`. |
| `backend/cavr/pipeline.py` (347 -> 348 lines) | `PIPELINE_VERSION` | `cavr-pipeline/1` -> `cavr-pipeline/2`, so verdicts cached under the old sink judgement are not served. |
| `tests/test_cavr_reachability.py` (304 -> 461 lines), `tests/test_cavr_pipeline.py` (626 -> 644), `tests/test_cavr_contract.py` (478 -> 493) | | 26 / 45 / 44 test functions, 64 / 68 / 65 cases. |

Key algorithm, `_reader_problem` (one `PdfReader(...)` call): it must be the value of `name = PdfReader(...)`; walking up
the AST from that statement must reach a guard `with` before a nested function, a lambda, or the lazy part of a generator
expression; then every other occurrence of `name` in the enclosing function must be a read of the form `name.<attribute>`
that passes the same walk.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Only a `*` grant clears a sink | Keep "capability name granted" and mark `scope_checked: false` | The scan sees that code connects, not where to. With a scoped grant the destination is unknown, and unknown is UNRESOLVED. Cost: a scoped grant never clears a reachable sink in M1. Open for Maryam. |
| The reader object must not leave the guard block | Keep the proof and state the limit in the evidence only | pypdf decodes pages when they are read, so "created inside, read after" is the usual shape and was VERIFIED. The limit that remains (an object taken from the reader and used later) is in the evidence. |
| Names are tied to contract call sites | Match by name as the reused function does | A local or third-party `apply_configuration` that does nothing was accepted as the guard. |
| The proof is refused when pypdf is a dependency | Check the other wheel's source for guards too | A guard in the project does not govern calls made inside another wheel. |
| `.pth` path line or no entry module -> every sink reachable | Map `.pth` paths to module names | One simple rule that cannot be wrong; a wheel that moves its import root is rare. |
| `fast_gate.disabled_jbig2_sinks` still called, still not edited | Replace it | The plan fixes it as the proof and wants its result in the evidence (`guard_result`). It now only supplies the wheel-side check and the line numbers. |

### Requirements covered

FR-6 (Fail-Closed Security Policy, ID from `RequirementsTab.tsx`, Maryam to confirm): five routes to VERIFIED with
a reachable sink are closed, and an unreadable project directory is UNRESOLVED. Acceptance checks:
`test_project_shapes_the_first_version_of_the_proof_accepted` (18),
`test_no_entry_module_in_the_wheels_means_nothing_can_be_called_unreachable`,
`test_a_grant_limited_to_a_scope_does_not_clear_a_sink`,
`test_directory_that_cannot_be_listed_makes_the_context_unresolved`.

### Ch 7 Test cases

Run on 2026-10-10 after the fix:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 999 passed, 5 skipped (968 + 31 new).
- `.venv/bin/python -m pytest -q` -> 1057 passed, 7 failed, 5 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 5 passed.
- Before the fix the new cases were run against `c5c0ef4`: 27 failed (26 in `test_cavr_reachability.py`, 1 in `test_cavr_contract.py`); the 3 "proof holds" cases among them failed only because `limit` did not exist.
- Fault injection on the fix, one line at a time, files restored: 16 faults; 15 made a test fail at once. "Call not checked against the contract" failed no test; the case "names that cannot be traced to pypdf" was added and now fails with that fault.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_a_grant_limited_to_a_scope_does_not_clear_a_sink`, `test_sink_under_a_scoped_grant_is_unresolved_and_escalated` | Scoped grant | Policy `NETWORK_CONNECT:billing.example.com`; the wheel connects to `example.invalid` | REACHABLE -> UNRESOLVED, escalated (was ALLOWED / VERIFIED) | pass |
| `test_a_sink_whose_capability_is_granted_without_a_scope_limit_is_evidence`, `test_sink_granted_without_a_scope_limit_is_evidence` | `*` grant | Policy `NETWORK_CONNECT:*` | ALLOWED, VERIFIED | pass |
| `test_dependency_that_the_project_imports_directly_is_an_entry` (3 project forms) | Entries | Root `top` never imports `helper`; the project does (`import`, `from ... import`, star) | `helper`'s `os.system` REACHABLE (was UNREACHABLE) | pass |
| `test_no_entry_module_in_the_wheels_means_nothing_can_be_called_unreachable` | Import root moved | `top_level.txt` = `nice`, code at `_src/nice/`, `x.pth` = `_src`; and the same without the `.pth` | REACHABLE (was UNREACHABLE -> VERIFIED) | pass |
| `test_a_pth_path_line_makes_every_sink_reachable` | `.pth` path | `demo.pth` = `_vendor`, sink in `_vendor/extra.py` | REACHABLE; without the `.pth` line UNREACHABLE | pass |
| `test_modules_python_runs_at_start_up_are_always_reached` (2) | Start-up modules | `sitecustomize.py` / `usercustomize.py` with `os.system` | REACHABLE | pass |
| `test_project_shapes_the_first_version_of_the_proof_accepted` (18) | Proof refused | Local or foreign `apply_configuration`; guard hidden by a local function; reader re-exported (attribute, alias, star); names from a project star import; reader in a lambda, nested function, generator expression; pages read after the block; reader returned, stored on `self`, passed on, not bound, used lazily, captured by a closure, made global | Proof not accepted -> UNRESOLVED `SINK_REACHABLE` | pass |
| `test_project_shapes_for_which_the_proof_holds` (3) | Proof kept | The real InvoiceHub adapter; a reader used in two guard blocks; two readers in two functions | Accepted, lines `[774, 804]`, `limit` present | pass |
| `test_pypdf_as_a_dependency_is_not_covered_by_the_projects_own_guard` | Other caller | Root `top` calls `PdfReader` itself; the project has its own guarded reader | Proof refused | pass |
| `test_pages_read_after_the_guard_block_are_unresolved_and_escalated` (pipeline) | End to end | Reader created in the block, pages read after it | UNRESOLVED, `escalation` set | pass |
| `test_directory_that_cannot_be_listed_makes_the_context_unresolved` | Unreadable directory | A project directory with mode 000 | UNRESOLVED `SOURCE_NOT_READ` (was OK) | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | cavr-reviewer (BLOCKER, step 11, shown by a passing test) | A sink was ALLOWED when its capability name was granted, whatever the scope | Fixed; only `*` clears a sink |
| 2 | cavr-reviewer (BLOCKER, step 11, by reading) | Entry modules came only from the requested package: a dependency the project imports directly was UNREACHABLE with a false reason | Reproduced, fixed |
| 3 | cavr-reviewer (BLOCKER, step 11, by reading) | With no entry module in the wheels (import root moved by a `.pth` line) every sink was UNREACHABLE -> VERIFIED; `sitecustomize` was never an entry | Reproduced, fixed |
| 4 | cavr-reviewer (BLOCKER, step 11, by reading) | The pypdf proof was accepted with a guard that is not pypdf's, a reader re-exported by a project module, pypdf as a dependency of the requested wheel, and a reader written inside the block but run later | Reproduced (all four), fixed |
| 5 | cavr-reviewer (BLOCKER, step 11; listed in step 11 as a known limit) | Pages read after the guard block were VERIFIED with the sink marked `GUARD_DISABLED` | Fixed: the reader must stay in the block |
| 6 | cavr-reviewer (BLOCKER, step 9, by reading) | A directory that cannot be listed was skipped silently and the context was OK | Reproduced, fixed |
| 7 | cavr-reviewer (BLOCKER, notes) | Step 11 notes said 46 reachability cases; the file had 36 | Corrected |

### Known limitations / deferred

- The 11 MINOR items of the review are in `docs/cavr-m1-plan.md` under "Known issues deferred" (found in the batch 9-11 review). None was changed.
- Still not followed by the proof: an object taken from the reader (a page, a stream) and used after the block; a name rebound through `globals()` or `setattr`.
- The proof now refuses some safe projects (a reader passed to a helper function, two readers with one name in one function). They get UNRESOLVED with an escalation, not a wrong VERIFIED.
- The reviewer could not open the pypdf wheel; lines 774 / 804 and pypdf's lazy decoding rest on the tests and on general pypdf behaviour.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the review (the read-only `cavr-reviewer` subagent), the fixes, the 31 new test cases, these notes, the commit.
- **Reviewed / decided by Maryam:** nothing in this commit yet. Open for her: only `*` grants clear a sink; the proof's remaining limit.
- **Verified by:** the pytest runs, the live run and the 16 fault injections above. The reviewer did not see the fix.

### Supervisor Q&A prep

1. **pypdf decodes pages lazily. What if the reader is created inside the guard and the pages are read after it?**
   The proof is refused: the reader's name is used outside the guard block, so the two `subprocess.run` calls count as reachable and the verdict is UNRESOLVED with an escalation (`test_pages_read_after_the_guard_block_are_unresolved_and_escalated`).
2. **The policy grants `NETWORK_CONNECT:billing.example.com`. Where is that scope compared with what the code connects to?**
   Nowhere in M1, and that is why such a grant does not clear a sink: the scan cannot see the destination. Only an unrestricted grant (`*`) does; a scoped one leaves the sink to reachability and, if reachable, to deep analysis.
3. **Can UNREACHABLE be wrong?**
   It follows `import` statements. It is not used when reached code imports at run time, when a `.pth` file changes the import path, or when the project imports nothing that is a module of the wheels. Imports made through `runpy`, `pkgutil` or `sys.path` edits are not seen; that is a stated limit.

## Step 12 — pip wrapper runs the pipeline before pip (2026-10-10)

Plan commit 12, `feat(cavr): pip wrapper runs the pipeline before pip` (`1e17034`).
Reviewed by cavr-reviewer (1 batch pass over steps 12-13; it ran both suites, findings derived by reading); batch verdict: fix first; 0 BLOCKERs in this step's code, 1 wrong count in these notes (corrected); 5 MINOR open.

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/pip_shim.py` (rewritten, 59 -> 280 lines) | `main(argv, *, pip_runner, out, store, **verify_options)` | Splits the arguments, reads the policy, calls `pipeline.verify_request(["pip", *arguments], project, policy, store)`, prints the verdict and evidence, and returns the exit code: 0 VERIFIED, 1 REJECTED, 2 UNRESOLVED, 3 BLOCK, 4 when `--install` was given, the verdict is VERIFIED and pip did not succeed. |
| | `split_arguments(argv)` | Takes out the wrapper's own options (`--install`, `--cavr-project`, `--cavr-policy`, `--cavr-python`, `--cavr-json`); the rest is the pip command. An unknown `--cavr-*` option is a usage error (exit 2, nothing verified). Everything from `--` on belongs to pip. |
| | `install_plan(verdict)` | One line `name==version --hash=sha256:<digest>` per node of every verified tree, or a reason why not. Refuses unless the verdict and every package are VERIFIED and every tree is `TREE_BUILT`, and checks each name, version and digest again with a strict pattern. |
| | `_install` | Without `--install`: does nothing. With it: writes the plan to a file in a new temporary directory, runs `<python> -m pip install <PIP_INSTALL_OPTIONS> -r <file>` once, removes the directory. |
| | `PIP_INSTALL_OPTIONS` | `--isolated --disable-pip-version-check --no-input --index-url https://pypi.org/simple/ --require-hashes --no-deps --only-binary :all:` |
| | `render`, `_render_package` | The verdict as text: status, stage, rule, reason, request, the three metric fields, gate, and per package the artifact digests, tree, contract, advisories, scan, sinks and cache result. |
| `backend/cavr/capture.py` (426 -> 460 lines) | `redact`, `URL_CREDENTIALS` | `https://user:password@host` becomes `https://***@host` in the command, every `raw`, every reason and option values. |
| | `_read_file` | A `-r` / `-c` file is read only when it is inside the directory the command ran in (after resolving symlinks) and is not a URL; at most `MAX_REQUIREMENTS_FILES` (100) files per command. |
| | `read_requirements_bytes` | Something that exists and is not a regular file (directory, FIFO, device) is refused before `open`. |
| | `parse_pip_command` | A command that is not a string, list or tuple gives an error record instead of `TypeError`. |
| `backend/cavr/pipeline.py` (348 -> 375 lines) | `verify_request`, `_asked` | The same release asked for twice: identical lines are verified once; lines that differ in extras, `--hash` values or marker give a second package verdict UNRESOLVED `DUPLICATE_REQUIREMENT`. |
| | `_verify_package`, `ANALYSIS_KEYS` | A sound cache row that is not a complete analysis is a miss (`ROW_INCOMPLETE`); the package is analysed again and the row replaced. |
| | `_log`, `MAX_LOGGED_REQUEST` | Built entirely inside the `try`; the logged request is redacted and cut to 500 characters. |
| `backend/cavr/manifest_parser.py` (167 -> 170 lines) | `capture_requirements_edit` | New field `removed_options`: option lines of the old file that are not in the new one. Docstring corrected (`_diff`). |
| Tests | `tests/test_cavr_pip_shim.py` (new, 394 lines, 33 functions, 73 cases); additions in `test_cavr_capture.py` (+11 functions, 19 cases), `test_cavr_pipeline.py` (+5 functions, 9 cases), `test_cavr_manifest.py` (+1), `test_cavr_live.py` (+1 live test); `World` and its constants moved from `test_cavr_pipeline.py` to `test_cavr_support.py` unchanged | |

Key algorithm (`main`): (1) wrapper options out, usage error -> exit 2; (2) `verify_request` on the remaining pip command;
(3) if `--install` and `install_plan(verdict)` gives lines, write them to a file and run pip with the fixed options;
(4) print; (5) exit code from the verdict status, or 4 when the install was asked for and did not succeed.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Decide only by default; install only with `--install` (plan, approved change) | Always install on VERIFIED | The wrapper can be used as a check without changing the environment. |
| The user's arguments are never passed to pip; pip gets a fixed option list and the generated file | Append `--require-hashes` to the user's command | An option the capture does not model could otherwise change what pip does. With a fixed command there is nothing to model. |
| The generated file pins every node of the tree by the SHA-256 the pipeline computed; `--no-deps` | Let pip resolve dependencies; install from the quarantine directory with `--no-index` | pip downloads again, but only the analysed bytes can pass `--require-hashes`, and nothing outside the verified tree is installed. Installing from quarantine would avoid the second download; the plan asked for the hash-pinned file. |
| `--isolated` and an explicit `--index-url` | Leave pip's environment and configuration alone | `PIP_*` variables and the user's pip configuration cannot add an index or an option. Cost: a proxy set only in pip's configuration is ignored. |
| `--only-binary :all:` | Rely on the hash alone | The pipeline verifies wheels only; this also stops pip from ever building an sdist. |
| `install_plan` validates name, version and digest again | Trust the verdict | Each line is parsed by pip; a newline or a space in a value would be a second requirement or an option. |
| Policy: `--cavr-policy`, else `$CAVR_POLICY`, else `<project>/cavr-policy.json`; missing -> UNRESOLVED | Fall back to `backend/cavr/project_policy.json` | That file is the dashboard's policy; a project without a policy must not be judged by another project's. |
| Only `pip install` is handled; other pip commands are UNRESOLVED and not passed on | Pass `pip list` etc. through | `pip download` / `pip wheel` can run build code; a pass-through list is future work. |
| `-r` files only inside the project directory | Truncate `raw` in error entries | The lines of a file outside the project never enter the record. A file inside the project is still read (see limitations). |
| Duplicate release with different extras / hashes -> UNRESOLVED | Merge the two lines | Simple and fail-closed; merging hashes has pip-specific semantics. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| FR-1 | Intercept Before Execution | The wrapper verifies before pip runs, and pip runs only on VERIFIED with `--install` | `test_default_prints_the_verdict_and_never_invokes_pip`, `test_install_on_verified_invokes_pip_once_with_the_hash_pinned_file` |
| FR-2 | Requirement Gate Enforcement | BLOCK: no download, no pip | `test_install_on_block_never_invokes_pip_and_downloads_nothing` (3) |
| FR-6 | Fail-Closed Security Policy | REJECTED / UNRESOLVED / missing policy / usage error / pipeline fault -> no install | `test_install_on_rejected_never_invokes_pip`, `test_install_on_unresolved_never_invokes_pip`, `test_no_policy_file_is_unresolved_and_downloads_nothing`, `test_a_fault_in_the_pipeline_call_is_unresolved_not_a_traceback` |
| none listed | CLAUDE.md C1 "pip wrapper/gateway that captures real `pip install X==Y`" | The command line is captured by `capture.parse_pip_command` through the pipeline | `test_module_runs_as_a_program_and_fails_closed` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 1101 passed, 6 skipped (999 + 102 new; the 6 skips are the live tests).
- `.venv/bin/python -m pytest -q` -> 1159 passed, 7 failed, 6 skipped (the same 7 baseline tests in `test_api_replay.py` and `test_integration.py`).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 5 passed before this step's test was added; the new test, run alone, passed: real PyPI, real OSV, real pip, a new venv; pip printed `Successfully installed pypdf-6.19.0`.
- The 23 new cases for the deferred items were run against the previously committed `capture.py`, `pipeline.py` and `manifest_parser.py`: all 23 failed there, all pass now.
- Fault injection in `pip_shim.py`, one change at a time, file restored: 17 faults (install without the flag, verdict status / package status / tree rule ignored, `--require-hashes` removed, `--no-deps` removed, name / version / digest not validated, two files for one package accepted, pip failure ignored, exit 0 for every status, only the root listed, missing policy falling back to the dashboard policy, usage error ignored, `--` not honoured, generated file not removed). All 17 made a test fail. An 18th injected change turned out to change nothing and is not counted.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_default_prints_the_verdict_and_never_invokes_pip` | Default decides only | `install pypdf==6.19.0` | exit 0; pip never called; output has the SHA-256 `7e5d6e73…8d14`, `HASH_MATCH`, the two sinks, the metric fields | pass |
| `test_default_exit_code_is_non_zero_unless_verified` (6) | Exit codes | denylisted, unpinned, missing `-r` file, `list`, `--version`, no arguments | 3 / 3 / 2 / 2 / 2 / 2; no pip, no download | pass |
| `test_install_on_verified_invokes_pip_once_with_the_hash_pinned_file` (3) | `--install` + VERIFIED | `--install` at three positions | pip called once: `[python, -m, pip, install, *PIP_INSTALL_OPTIONS, -r, file]`; file is `pypdf==6.19.0 --hash=sha256:7e5d…8d14`; file gone afterwards | pass |
| `test_install_lists_the_whole_verified_tree`, `test_two_requested_packages_are_one_pip_call` | Exact tree | `top==1.0` needing `helper>=2`; two packages | Both files listed with the SHA-256 of their real bytes; one pip call | pass |
| `test_the_users_own_pip_options_never_reach_pip` | Fixed command | `--upgrade --no-cache-dir --target somewhere` | None of them in the pip command | pass |
| `test_install_on_rejected_never_invokes_pip`, `..._on_a_known_vulnerability_...`, `..._on_unresolved_...`, `..._on_an_escalated_verdict_...`, `..._on_block_...` (3), `test_one_verified_and_one_rejected_installs_neither` | `--install` on anything else | flipped byte; `SYNTH-1201`; registry unreachable; unguarded reader; denylist / allowlist / unpinned; one good + one vulnerable | exit 1 / 1 / 2 / 2 / 3 / 1; pip never called | pass |
| `test_requests_the_capture_does_not_support_are_never_installed` (6) | Unsupported requests | custom index, `--no-binary`, URL, `-e .`, `pip download`, `-- --install` | exit 2; no pip; no download | pass |
| `test_pip_failing_is_a_non_zero_exit`, `test_pip_that_cannot_be_started_is_a_non_zero_exit` | pip fails | stub returns 1; stub raises `FileNotFoundError` | exit 4 | pass |
| `test_no_policy_file_is_unresolved_and_downloads_nothing`, `test_a_policy_that_is_not_json_is_unresolved`, `test_policy_option_and_environment_variable` | Policy | no file; `{broken`; option / variable / named but missing | `POLICY_MISSING`, `POLICY_INVALID`; option wins; no fallback | pass |
| `test_split_arguments`, `test_bad_wrapper_options_are_a_usage_error` (6), `test_a_usage_error_verifies_and_installs_nothing` | Wrapper options | as named | usage error -> exit 2, nothing verified or logged | pass |
| `test_install_plan_refuses_a_verdict_that_is_not_a_fully_verified_tree` (16), `test_install_plan_refuses_two_files_for_one_package`, `test_install_plan_of_something_that_is_not_a_verdict` (7), `test_a_verified_verdict_without_a_usable_plan_is_not_installed` | Defence in depth | status changed; no nodes; digest `7e5d` / None / upper case; name with a newline and `--index-url`; version with `--hash`; two digests | No plan, with the reason; exit 4 without calling pip | pass |
| `test_credentials_in_a_request_are_not_printed_or_logged`, `test_url_passwords_are_not_kept_in_the_record`, `test_url_passwords_do_not_reach_the_verdict_log` | Secrets | `https://alice:hunter2@…` in the command, a requirements file, `--proxy` | `hunter2` nowhere in the record, the output or `verdict_log` | pass |
| `test_requirement_file_outside_the_project_directory_is_not_read`, `test_symlink_…`, `test_nested_include_…`, `test_requirement_file_given_as_a_url_is_unsupported` (2), `test_named_pipe_as_a_requirement_file_does_not_block`, `test_number_of_requirement_files_is_capped`, `test_long_include_chain_is_an_error_not_a_recursion_error`, `test_file_included_twice_counts_twice_towards_the_cap` | `-r` limits | absolute path, `../`, symlink, URL, FIFO, 6-file and 1200-file chains, diamond | unsupported / error; nothing of the outside file in the record; returns within 10 s | pass |
| `test_command_that_is_not_text_or_a_token_list_is_an_error_record` (4), `test_command_forms_noted_in_the_review` (5) | Command forms | `None`, `5`, `{}`, bytes; `&&`, `PIP_INDEX_URL=… pip`, `--`, `-qr` | error record; fail closed | pass |
| `test_the_same_line_twice_is_verified_once`, `test_one_release_asked_for_twice_in_different_ways_is_unresolved` (3) | Duplicates | same line twice; second line with a wrong hash / an extra | VERIFIED once; UNRESOLVED `DUPLICATE_REQUIREMENT` | pass |
| `test_a_cache_row_that_is_not_a_complete_analysis_is_a_miss_and_is_replaced` (3), `test_a_caller_made_record_with_an_odd_command_is_still_logged` | Cache row, log | row without `scan` / `reachability`; `command` = 5, None, a string, a dict | `ROW_INCOMPLETE`, analysed, next run a HIT; logged | pass |
| `test_removed_option_lines_are_listed` | Edit | `--require-hashes` deleted | in `removed_options` | pass |
| `test_module_runs_as_a_program_and_fails_closed` | Real process | `python -m backend.cavr.pip_shim install pypdf==6.19.0 --install` in an empty directory | exit 2, `POLICY_MISSING`, "install: refused" | pass |
| `test_live_pip_wrapper_installs_only_with_the_flag_and_only_the_verified_wheel` (`CAVR_LIVE=1`) | Real PyPI, OSV and pip | denylisted name; decide only; `--install` | exit 3 and nothing installed; nothing installed; `pypdf.__version__ == "6.19.0"` in the venv, second run a cache hit | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Reading the old `pip_shim.py` | It ran real pip for every command with the user's arguments plus `--index-url http://127.0.0.1:8000/simple/`, verified nothing first, and parsed option values as package names | Rewritten; pip is reached only after VERIFIED and with a fixed command |
| 2 | Deferred review items (batch 1-3) | `-r` could read any file on disk into the record; no limit on nested `-r`; a FIFO blocked; `parse_pip_command(None)` raised; removed option lines were invisible | Fixed in `capture.py` and `manifest_parser.py`, each with a test |
| 3 | Deferred review items (batch 9-11) | A second line for the same release was skipped; `_log` could raise and stored URL passwords; an incomplete cache row gave `INTERNAL_ERROR` on every run | Fixed in `pipeline.py`, each with a test |
| 4 | Writing the capture tests | `-r https://user:pass@host/reqs.txt` was reported as a missing local file and the reason contained the password | Reported as "requirements file given as a URL"; reasons are redacted too |

### Known limitations / deferred

- pip downloads the files a second time. Only bytes with the verified SHA-256 can be installed, but the network is used twice.
- The pipeline picks the wheel and evaluates markers for the interpreter that runs the wrapper. With `--cavr-python` pointing at a different Python version or platform, pip may want another file; `--require-hashes` then makes pip fail (nothing unverified is installed).
- pip's global (machine-wide) configuration file is still read by pip under `--isolated`; the index is set explicitly on the command line, other settings from that file are not controlled.
- Only `pip install` is handled. `pip list`, `pip uninstall` and the rest return UNRESOLVED and are not passed to pip.
- A requirements file inside the project directory is read whatever it is: `-r .env` would copy the lines of `.env` into `errors[].raw`.
- `removed_options` is evidence only; removing `--require-hashes` from a requirements file does not change the verdict.
- A root requirement's marker is still ignored (`pkg==1; python_version < "3"` is verified and would be installed).
- The wrapper is not put on `PATH` as `pip` by anything in this repository; it runs as `python -m backend.cavr.pip_shim`.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `pip_shim.py`, the changes in `capture.py`, `pipeline.py`, `manifest_parser.py`, all tests, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet.
- **Verified by:** the pytest runs, the run of the new cases against the old sources, the 17 fault injections and the live run with real pip listed above.

### Supervisor Q&A prep

1. **pip downloads the package again after CAVR verified it. How do you know it installs the same file?**
   The generated requirements file carries the SHA-256 that the pipeline computed from the bytes it analysed, and pip runs with `--require-hashes`, so pip refuses any file with another digest. `--no-deps` stops it from adding anything that is not in the file.
2. **What if the user adds `--index-url` or `--no-binary` to the command?**
   The capture marks the request as not fully captured, so the verdict is UNRESOLVED and pip is not run. Even on a VERIFIED verdict the user's arguments are not given to pip; it gets the fixed option list.
3. **What does the wrapper do when the project has no policy file?**
   UNRESOLVED `POLICY_MISSING`, exit code 2, before any download. It does not borrow another policy.

## Step 13 — dashboard API uses the pipeline (2026-10-10)

Plan commit 13, `refactor(cavr): dashboard API uses the pipeline` (`ca5a0e2`).
Reviewed by cavr-reviewer (1 batch pass over steps 12-13); batch verdict: fix first; 3 BLOCKERs in this step, fixed in the batch fix commit (see "Steps 12-14 — batch review"); 1 BLOCKER in `CavrModule.tsx` (outside the scope) open for Maryam; 11 MINOR open.
This section describes the code as committed in `ca5a0e2`.
**Not complete as the plan words it:** the five scenario chips, the timeline labels and the proof drawer are in
`frontend/src/components/CavrModule.tsx`, which is outside the allowed scope and was not edited. See "Known limitations".

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/api.py` (835 -> 585 lines) | `intercept_package_endpoint`, `launch_cavr_pipeline` | `POST /api/cavr/intercept` makes a run id and starts `run_verification` in the background. No source string is hashed and nothing is written to a per-run quarantine file any more. |
| | `pip_request(body)` | The request to verify: the given pip command, or `["pip", "install", "<package>==<version>"]` with package and version in one token. |
| | `verify_dashboard_request(request, condition)` | Calls `pipeline.verify_request` for `PROJECT_DIR` (the sample project) with the policy `project_policy.json`; picks the transport for a demo condition; a raised exception becomes UNRESOLVED `INTERNAL_ERROR`. |
| | `run_verification(run_id, body)` | Publishes the "request received" event, runs the pipeline in a worker thread, publishes `verdict_events`, builds the certificate and the proof, publishes the final event, marks the run finished. |
| | `verdict_events(verdict, condition)` | One event per stage that ran: gate (step 1), artifact / tree / advisories (2), cache lookup (3), contract / scan / sinks (4), then the verdict. Every value is copied from the verdict. A stage that did not run has no event. |
| | `TamperingTransport`, `OfflineTransport`, `CONDITIONS`, `demo_condition` | The two demo conditions: one bit of every file from `files.pythonhosted.org` flipped; every request failing. Only the exact names `tampered_wheel` and `network_off` turn one on. |
| | `SCENARIOS`, `list_scenarios` | The five chips as data: package, version, condition, `expected_status` (documentation only). |
| | `cavr_stream` | Replays the run's events from the first one and ends after the last; a late client misses nothing. Queues are gone. |
| | `get_metrics` | `pipeline.metrics(storage)` plus the last 10 rows of the verdict log. The in-memory list and the constant `repair_success_rate` are gone. |
| | `get_evidence_records` | New: the real records of a run's hash chain. |
| | `ALIASES`, `honesty_wording` | VERIFIED -> ALLOW, REJECTED and BLOCK -> BLOCK, UNRESOLVED -> NEEDS_REVIEW (the old dashboard's three words); `policy_state` is the pipeline status itself. |
| `backend/cavr/assurance.py` (205 -> 251 lines) | `certificate_for_verdict` (replaces `generate_certificate`) | The certificate copies the verdict: digests, per-check rule or `NOT_REACHED`, the contract rows, the metric fields, the demo condition. The old function wrote "MET 98%", "honeytoken CLEAN" and "EXFILTRATION_OBSERVED" from the verdict word alone. |
| | `generate_printable_html_certificate` | Shows the new fields; every value goes through `html.escape`. |
| `backend/cavr/pipeline.py` | `verify_request` | `project.skipped_directories` added to every verdict (deferred item). |
| `backend/cavr/sample_project/invoice_extractor/reader.py`, `requirements.txt` | | The dashboard's project now creates and uses every `PdfReader` inside `apply_configuration(jbig2dec_binary=None)` and asks for `pypdf==6.19.0`. |
| `backend/cavr/project_policy.json` | `approved_requirements` | `pypdf==4.2.0` -> `pypdf>=5,<7`, so both scenario versions pass the gate and OSV decides about 5.1.0. |
| `frontend/src/components/cavr/` (11 files) | `types.ts`, `OverviewTab`, `RequirementsTab`, `CapabilityContractTab`, `TriggersTab`, `CounterfactualTab`, `CausalGraphTab`, `RepairTab`, `AssuranceTab`, `MetricsTab`, `StageDetailPanel` | Read the new evidence (`proofData.cavr_verdict`, `resolution`, `actionData`, `certificate`) and show `fast_gate_ms`, `cache_hit`, `escalated`, `escalation`. The built-in sample data was removed from every branch that can render on this path: a tab without data says so. `RepairTab.tsx` still has default values inside its repair branch (a default cost breakdown and three fixed ticks per candidate), which cannot render while `repair` is null. |
| Tests | `tests/test_cavr_api.py` (new, 28 functions, 48 cases), one live test in `tests/test_cavr_live.py` | |

No longer imported by `api.py`: `fixtures/scenarios.py`, `resolver.py`, `reverifier.py`, `reconstructor.py`, `triggers.py`,
`counterfactual.py`, `normalizer.py`, `causal_graph.py`, `repair_engine.py`, `check_requirement_gate`. The files are still
in the repository.

Key algorithm (`run_verification`): request event -> `verify_request` in a thread -> for each stage present in the verdict,
one event -> certificate with the chain hash so far -> proof -> final event -> run marked finished, which ends the stream.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| The API computes nothing; events are projections of the verdict | Keep per-phase logic in `api.py` | One verdict path. What the dashboard shows cannot differ from what the pip wrapper or the orchestrator would get. |
| Demo conditions change the transport only | Scenario-specific code paths; fixture wheels | The pipeline runs unchanged. A condition can only make a verdict worse, and it is written into every event, the proof and the certificate. |
| The dashboard project is `backend/cavr/sample_project`, with no lockfile | `demo_project/InvoiceHub` | InvoiceHub's lockfile holds only pypdf 6.19.0, so 5.1.0 would be a gate BLOCK and never reach OSV; that directory is also outside this branch. The verdict states `lockfile.present: false`. |
| Step index of an event = the last stage that ran (0-4) | Keep the old 8 steps | The old steps 5-7 (sandbox, causal graph, reconstruction) do not exist on this path. With an index above 4 the timeline would mark a sandbox run as done. |
| Stream replays stored events and then ends | Per-client queues | Events published before the browser connects were lost with queues. |
| Old three-word alias kept, `policy_state` = pipeline status | New field names only | `CavrModule.tsx` reads `verdict` and `policy_state` and cannot be changed here. |
| Tabs show "not run" instead of sample data | Leave the fallbacks | The fallbacks showed a "CLEAN" run, a certificate with the SHA-256 of an empty string, fixed chain hashes and "all obligations passed" for runs that never happened. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this step covers | Acceptance check |
|---|---|---|---|
| FR-1 | Intercept Before Execution | The dashboard request goes through the same capture and pipeline | `test_intercept_then_stream_then_proof_over_http` |
| FR-2 | Requirement Gate Enforcement | BLOCK shown as BLOCK, before any download | `test_denylisted_name_is_blocked_before_any_download` |
| FR-3 | Capability Contract Inference | The real contract of the sample project on the dashboard | `test_pypdf_6_19_0_is_verified_for_the_shipped_project_and_policy` |
| FR-6 | Fail-Closed Security Policy | Missing policy, network off, pipeline fault -> UNRESOLVED on the dashboard | `test_missing_or_broken_policy_is_shown_as_unresolved_not_rejected` (2), `test_network_off_is_unresolved_and_the_real_transport_is_never_asked`, `test_a_pipeline_fault_is_an_unresolved_run_that_still_finishes` |
| FR-10 | Tamper-Evident Evidence Ledger | Every event in the chain; certificate copies the verdict | `test_every_event_is_in_the_hash_chain_and_tampering_is_detected`, `test_certificate_copies_the_verdict_and_invents_nothing` |
| none listed | Supervisor report: cache hit rate, p50 / p95 `fast_gate_ms` | `/api/cavr/metrics` from the verdict log | `test_metrics_come_from_the_verdict_log` |

### Ch 7 Test cases

Run on 2026-10-10:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 1149 passed, 7 skipped (1101 + 48 new; the 7 skips are the live tests).
- `.venv/bin/python -m pytest -q` -> 1207 passed, 7 failed, 7 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py -k dashboard` -> 1 passed: the five scenarios against the real PyPI and OSV, including the real `pypdf-5.1.0-py3-none-any.whl` (HASH_MATCH, then REJECTED with `GHSA-7hfw-26vp-jp8m` among the advisories).
- Frontend: `npx tsc -b` exit 0; `npx vite build` into a scratch directory succeeded. **The pages were not opened in a browser.**
- Fault injection, one change at a time, files restored: 17 in `api.py`, 3 in `assurance.py` (condition not applied, network-off keeping the real transport or asking OSV live, UNRESOLVED shown as ALLOW, BLOCK shown as REJECTED, proof hash always matching, cache always HIT, package and version joined by a space, pipeline fault not caught, stream not replaying, request not redacted, any scenario name acting as a condition, tampering the registry answer too, old runs kept, event not chained, a docker command reported, escalation dropped, a check reported as passed when not reached, HTML not escaped, certificate verdict constant). 19 made a test fail at once; the last one was caught after two assertions were added.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_scenario_list_is_five_real_requests` | Chips as data | `list_scenarios()` | five requests, no `source_code` | pass |
| `test_pypdf_6_19_0_is_verified_for_the_shipped_project_and_policy` | Scenario 1 | pypdf 6.19.0, shipped sample project and policy | VERIFIED; SHA-256 `7e5d6e73…8d14` = registry; 4 call sites in `invoice_extractor/reader.py`; sinks 774 and 804 GUARD_DISABLED; events at steps 0,1,2,3,4,4,4; sandbox fields `not run` | pass |
| `test_pypdf_5_1_0_is_rejected_by_osv_with_the_recorded_advisory_ids` | Scenario 2 | stand-in wheel (synthetic) + the 97 recorded OSV advisories (real) | gate PERMITTED; REJECTED `KNOWN_VULNERABILITY`; 97 ids incl. `GHSA-7hfw-26vp-jp8m` | pass |
| `test_denylisted_name_is_blocked_before_any_download` | Scenario 3 | `requests-security==2.31.0` | BLOCK `DENYLIST`; index never asked; certificate checks `NOT_REACHED` | pass |
| `test_tampered_wheel_is_rejected_on_the_hash_of_the_bytes_that_arrived` | Scenario 4 | condition `tampered_wheel` | REJECTED `HASH_MISMATCH`; the kept file differs from the real wheel in exactly one bit; condition in every event | pass |
| `test_network_off_is_unresolved_and_the_real_transport_is_never_asked`, `test_what_the_pipeline_is_given_under_each_condition` | Scenario 5 | condition `network_off` | UNRESOLVED `REGISTRY_UNAVAILABLE`; zero calls to the index; `live_advisories` false | pass |
| `test_expected_status_of_a_scenario_is_not_used`, `test_no_scenario_type_turns_a_block_into_anything_else` (6), `test_only_the_two_named_conditions_change_the_transport` (5), `test_tampering_transport_flips_one_bit_of_files_only` | A scenario cannot improve a verdict | chip "verified" with a `SYNTH-` advisory; six scenario names on a denylisted package | REJECTED; always BLOCK; conditions only for the two exact names | pass |
| `test_second_run_is_a_cache_hit`, `test_reader_outside_the_guard_is_unresolved_with_the_escalation` | Metric fields | two runs; project copy with an unguarded reader | `cache_hit` true, cache event HIT; UNRESOLVED, `escalated` true, `escalation` text in event and certificate | pass |
| `test_package_and_version_are_one_requirement_token`, `test_requests_that_are_not_a_permitted_pinned_install` (8), `test_a_marker_in_the_version_field_does_not_change_what_is_reported` | Request building | version `6.19.0 --index-url …`; empty fields; the old chips' packages; `rm -rf /` | UNRESOLVED / BLOCK; no download; proof reports `pypdf 6.19.0` | pass |
| `test_url_passwords_are_not_in_events_proof_or_log` | Secrets | `--index-url https://alice:hunter2@…` | `hunter2` in none of events, proof, certificate, log, chain | pass |
| `test_every_event_is_in_the_hash_chain_and_tampering_is_detected`, `test_certificate_copies_the_verdict_and_invents_nothing`, `test_certificate_of_a_verdict_without_evidence_claims_no_check` (4), `test_printable_certificate_shows_the_real_values_and_escapes_them` | Chain and certificate | a run; one record changed; empty verdicts; `<script>` in a reason | 7 records = 7 events; break at record 3; all checks `NOT_REACHED`; escaped | pass |
| `test_intercept_then_stream_then_proof_over_http`, `test_scenario_endpoint_and_unknown_runs_over_http`, `test_metrics_come_from_the_verdict_log`, `test_old_runs_are_dropped` | HTTP | FastAPI test client | 7 events, stream ends, replay equal; 404s; hit rate 0.25, p50 / p95 from the log; oldest run dropped | pass |
| `test_api_imports_none_of_the_fixture_or_simulation_modules` | Fixtures out of the verdict path | AST of `api.py` | none of the nine modules, no `hashlib`, no `source_code` | pass |
| `test_live_dashboard_scenarios_are_real_requests` (`CAVR_LIVE=1`) | Real PyPI + OSV | the five scenarios | as planned (scenario 1 may become REJECTED if OSV lists 6.19.0) | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Reading `api.py` | The "artifact hash" was the SHA-256 of a fixture source string; a trusted-package row made a run a "cache hit" and released it; a gate UNRESOLVED was shown as REJECTED; any non-ALLOW was worded as "hostile behaviors detected" | All removed with the old path |
| 2 | Reading `assurance.generate_certificate` | Capability rows, confidences and "honeytoken / counterfactual" results were constants chosen by the verdict word | Replaced by `certificate_for_verdict` |
| 3 | Reading the tabs | Eight tabs showed built-in sample data when they had none: a "CLEAN" baseline run, made-up metrics, a certificate with the hash of an empty string, seven fixed chain blocks, a "Tamper Demo" that printed a detection without checking anything, "all obligations passed", a substitute `pypdf==4.2.0`; `AssuranceTab` reported the chain as intact when the request failed; NFR-1 and NFR-2 were always PASS | Sample data removed; unreachable ledger is "not verified"; NFR-1 follows the sandbox data, NFR-2 is "NOT EVALUATED" |
| 4 | Tests | `test_dashboard_call_without_a_wheel…` docstring referred to the old `api.py` | Reworded |
| 5 | Deferred items "-> step 13" | NOT_OBSERVED chip "CLEAN" (`CounterfactualTab`), stale docker command, both routes to VERIFIED without observation in the dashboard path, version string with a marker, `skipped_directories` | Fixed or removed with the old path; `counterfactual.py` itself is unchanged but no longer called by the dashboard |

### Known limitations / deferred

- **`frontend/src/components/CavrModule.tsx` was not edited (outside the allowed scope).** Consequences, all visible on the dashboard:
  the five chips still carry the old labels and send the old requests (`pdf-clean-extractor==1.0.0`, `reportlab-legacy==3.5.21`,
  `dormant-exfil==1.2.0`, `invoice-utils==2.0.1`, `requests-security==2.31.0`), which now get real verdicts (UNRESOLVED or
  BLOCK) and never the five planned scenarios; the timeline still names eight steps with fixed timings such as "680ms";
  the proof drawer prints "VERIFIED MATCH" whatever `hash_comparison.matches` says and "Counterfactual Container Runs (1)"
  for an empty list; the sandbox console panel appears after every verdict. The new scenarios are served by
  `GET /api/cavr/scenarios` and run by `POST /api/cavr/run?scenario=<id>`. Needs Maryam's decision.
- The frontend was type-checked and built, not looked at in a browser.
- As committed in `ca5a0e2`: `/api/cavr/cache`, `/simple/…` and the three `/api/cavr/dialog/*` texts still served the old trusted-package list and sandbox texts. Changed by the batch fix commit (next section). The seed hashes in `storage.SEED_PACKAGES` were not checked against PyPI; they are no longer served.
- The legacy modules listed above are dead code for the dashboard; removing them is a separate change.
- Run state is in memory (last 200 runs); a restart loses streams and proofs, not the verdict log.
- One package per run is shown in the events; a request with several packages has all of them in the proof only.
- `storage.record_quarantine` is no longer called; wheels are kept in the pipeline's quarantine directory.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the new `api.py`, `certificate_for_verdict`, the tab changes, the sample-project and policy changes, all tests, these notes, the commit.
- **Reviewed / changed by Maryam:** nothing yet. Open for her: `CavrModule.tsx`; the policy entry `pypdf>=5,<7`; the sample project as the dashboard project.
- **Verified by:** the pytest runs, the live run of the five scenarios, the 20 fault injections, `tsc` and `vite build`. No browser check.

### Supervisor Q&A prep

1. **Are the dashboard scenarios still fixtures?**
   No. Each is a real request through `verify_request`. Two of them change only the network between CAVR and PyPI (one bit flipped, or no connection) and are labelled as a demo condition in every event; the verdict is what the pipeline gives in that situation.
2. **Can a scenario make a package look better than it is?**
   No. A condition replaces the transport, so it can only cause a hash mismatch or a network failure. `expected_status` is text for the chip; `test_expected_status_of_a_scenario_is_not_used` shows a "verified" chip returning REJECTED.
3. **Where do the cache hit rate and the latency numbers on the Metrics tab come from?**
   From `verdict_log`, one row per `verify_request` call, through `pipeline.metrics`. Nothing is kept in memory and there are no default numbers. Runs under a demo condition are not logged (since the batch fix commit), so they are not in these numbers. BLOCK rows are in them and download nothing, which lowers the percentiles; that is stated as a limit.

## Step 14 — orchestrator analyzer delegates to the pipeline: NOT implemented, stopped for a decision (2026-10-10)

Plan commit 14, `refactor(cavr): orchestrator analyzer delegates to the pipeline`. No code was changed and nothing was
committed for this step. `backend/cavr/analyzer.py` is as it was.

### Why it stopped

The plan says about `tests/test_modules.py`: "If commit 14 needs any other expectation in that file changed, stop and ask first."
It does. Measured on 2026-10-10 with the repository's own data:

| Question | Call | Answer |
|---|---|---|
| What advisory evidence does `analyze()` accept today for pypdf 6.19.0? | `OSV().query("pypdf", "6.19.0", live=False, max_age_days=30)` | `available: True`, mode `PYPI ADVISORY METADATA (dated)`, `age_days` 14.82, `vulnerabilities: []` |
| What does the pipeline say for the same data? | `advisories.check_advisories("pypdf", "6.19.0", ROOT / "advisories", live=False)` | UNRESOLVED `ADVISORIES_UNAVAILABLE`: "OSV could not be asked; only PyPI's advisory list is available, which has no version ranges to check" |

`tests/test_modules.py::test_cavr_safe_cache_and_advisory` asserts `first[0] == 'VERIFIED'` for the safe scenario, offline.
The only advisory data in `advisories/` (the directory `analyze()` reads) for that scenario is the recorded registry response
`advisories/registry-f9283cc3….json` (retrieved 2026-09-25), which the current analyzer accepts and the pipeline, by
design (step 7), does not. (`tests/test_cavr_data/osv-pypdf-6.19.0.json` is a recorded OSV answer for the same release;
it is test data and `analyze()` does not read it.) If `analyze()` delegates its PyPI nodes to `verify_request`, that scenario becomes UNRESOLVED and
the test fails; the orchestrator's decision for the safe scenario would change with it.

### What is needed from Maryam (one of)

- **A.** Delegate and accept UNRESOLVED when no OSV answer is available; change the expectation in
  `tests/test_modules.py` (and tell the orchestrator's owner that the safe scenario is no longer accepted offline).
- **B.** Delegate and give the orchestrator path a real, dated OSV answer for pypdf 6.19.0 in `advisories/`
  (a new file outside this branch's scope; like every dated answer it stops counting after 30 days).
- **C.** Delegate everything except the advisory step, keeping the analyzer's acceptance of PyPI's advisory list.
  This keeps a second, weaker advisory rule and is not what "one path" means.
- **D.** Leave `analyze()` alone for M1.

### Other findings while reading (no change made)

- The recorded registry response is accepted for 30 days (`advisory_max_age_days`). From 2026-10-25 the current
  `analyze()` returns UNRESOLVED for the safe scenario too, and `test_cavr_safe_cache_and_advisory` fails without any code change.
- A delegated `analyze()` still needs its own handling of `ecosystem: LOCAL` lab nodes (the sandbox counterfactual path of
  `test_controlled_dormant_execution`), the "required rule coverage" check (`TRIG-ENV` disabled -> UNRESOLVED), a policy
  mapping from `policy.json` (`dependencies.allowed`) to the gate's `approved_requirements`, and an offline transport
  that serves the lockfile's local artifact and the recorded registry response. None of this is written.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** this note and the two measurements above. No code.
- **Reviewed / decided by Maryam:** the decision is open.

## Steps 12-14 — batch review (2026-10-10)

One cavr-reviewer pass over `git diff 6823387..HEAD` (steps 12 and 13; step 14 has no code). Verdict: fix first.
This section lists what the fix commit, `fix(cavr): keep demo runs out of the report numbers and drop the old trusted-package endpoints`, changed.
The fix has not been reviewed again.

### Ch 6 Implementation

| File | Function | Change |
|---|---|---|
| `backend/cavr/api.py` (585 -> 478 lines) | `verify_dashboard_request` | A run under a demo condition gets `store=None`: it is not written to `verdict_log`, and it neither reads nor writes the verdict cache. |
| | `get_cache` | `GET /api/cavr/cache` now lists the sound rows of the 8-field verdict cache (name, version, SHA-256 of the analysed wheel, status, stored time, key fields). It no longer serves the seeded "trusted packages". |
| | removed | `GET /simple/`, `GET /simple/{package}/`, `GET /simple/{package}/{filename}`, `POST /api/cavr/cache`, `GET /api/cavr/dialog/cache`, `/action`, `/environment`. No caller in the repository (searched `*.py`, `*.ts`, `*.tsx`, `*.js`, `*.json`, `*.sh`, `*.html`); `README.md` line 168 still mentions `/simple/`. |
| | `verdict_events` | `demo_condition` is now in the cache and the contract / scan event too, so every event carries it. |
| `backend/cavr/storage.py` | `list_cached_verdicts(limit=200)` | Rows of `verdict_cache`, newest first. |
| `frontend/src/components/cavr/AssuranceTab.tsx` | chain blocks | The constant `isBroken = false` and the "valid" styling are gone; only "Verify Chain" says whether the chain is intact. |
| `tests/test_cavr_api.py` (28 -> 31 functions, 48 -> 58 cases) | | See below. |

Key algorithm (`get_cache`): for each stored row, `verdict_cache.lookup` on the row's own eight fields; the row is listed only when that lookup is a hit, which means its integrity digest and key are consistent.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Demo runs get no store | Log them under a `demo:<id>` source that `metrics` skips | The numbers are for the supervisor's report; an arranged hash mismatch or a 1 ms "network off" run is not a measurement. No store also means such a run cannot touch the cache. Cost: demo runs are not in "Last verdicts". |
| Old endpoints deleted | Escape the HTML and relabel the rows | `/simple/` served no files, `pip_shim.py` no longer uses it, and the dialog texts are not fetched by the frontend. Less code to defend. |
| `/api/cavr/cache` shows the verdict cache | Return an empty list | The dashboard's cache dialog then shows what CAVR really analysed, with real hashes. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this fix covers | Acceptance check |
|---|---|---|---|
| none listed | Supervisor report: cache hit rate, p50 / p95 `fast_gate_ms` | Only real requests are counted | `test_runs_under_a_demo_condition_are_not_in_the_log_the_cache_or_the_metrics` |
| none listed | CLAUDE.md "No fixture-faked results" | No seeded list presented as verified | `test_cache_endpoint_lists_the_real_verdict_cache_and_no_seed_rows` |

### Ch 7 Test cases

Run on 2026-10-10 after the fix:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 1159 passed, 7 skipped.
- `.venv/bin/python -m pytest -q` -> 1217 passed, 7 failed, 7 skipped (the same 7 baseline tests).
- `CAVR_LIVE=1 … tests/test_cavr_live.py` -> 7 passed (real PyPI, OSV and pip).
- `npx tsc -b` exit 0. Not opened in a browser.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_runs_under_a_demo_condition_are_not_in_the_log_the_cache_or_the_metrics` | BLOCKER 1 | tampered and network-off runs, then a plain run, then network-off again | `logged` false; log and cache empty; after the plain run exactly 1 verdict, `{"VERIFIED": 1}` | pass |
| `test_what_the_pipeline_is_given_under_each_condition` (changed) | BLOCKER 1 | three runs | stores given: `[store, None, None]` | pass |
| `test_metrics_come_from_the_verdict_log` (changed) | BLOCKER 1 | 2 verified, 2 blocked, 2 demo runs | 4 verdicts, hit rate 0.25, `{"BLOCK": 2, "VERIFIED": 2}` | pass |
| `test_cache_endpoint_lists_the_real_verdict_cache_and_no_seed_rows` | BLOCKER 2 | empty; one verified run; one BLOCK; a row edited in SQLite | `[]`; one row with SHA-256 `7e5d6e73…8d14`; still one; `[]` | pass |
| `test_endpoints_of_the_old_trusted_package_list_are_gone` (8) | BLOCKER 2 | the seven removed routes, one with `<img …>` in the path | 404 (405 for `POST /api/cavr/cache`) | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | cavr-reviewer | Demo-condition runs were written to `verdict_log` like real results and counted in the hit rate and p50 / p95 | No store for such runs |
| 2 | cavr-reviewer | Endpoints kept from the old `api.py`: a seeded list served as "PyPI Verified / TRUSTED" with hashes nobody checked, a POST that let anyone add to it, and `/simple/{package}/` writing the URL parameter into HTML unescaped (read, not executed) | Endpoints removed; `/api/cavr/cache` serves the real verdict cache |
| 3 | cavr-reviewer | Notes: "20 cases" for the capture additions (it is 19); "every built-in sample value was removed" (defaults remain in `RepairTab.tsx`'s repair branch and `AssuranceTab` styled every block as valid) | Notes corrected; `AssuranceTab` cleaned |
| 4 | cavr-reviewer | `frontend/src/components/CavrModule.tsx` prints "VERIFIED MATCH" for every run, "Counterfactual Container Runs (1)" for an empty list, "Matches" on a timer for the Re-verify button, fixed timings, the sandbox panel after every verdict, and the old chips | **Not fixed: outside the allowed scope.** Open for Maryam |

### Known limitations / deferred

- BLOCKER 4 above is open. Until `CavrModule.tsx` is changed the page shows false text around real results; step 13 stays unchecked in the plan.
- 18 MINOR items are listed in `docs/cavr-m1-plan.md` under "Found in the batch 12-13 review". The ones to know for the report: the run is not marked finished if something fails after the pipeline (the stream would then never end); p50 / p95 include BLOCK rows; `--proxy user:pass@host` without a scheme is not redacted; a demo "tampered" run shares the quarantine directory with real runs; the wrapper does not print which policy file it used; `python -m pip` runs with the current directory on `sys.path`.
- The table `trusted_packages` and `storage.SEED_PACKAGES` still exist; nothing serves them.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the review (the read-only `cavr-reviewer` subagent), the fixes, the 10 new test cases, these notes, the commit.
- **Reviewed / decided by Maryam:** nothing in this commit yet. Open for her: `CavrModule.tsx`; step 14 (options A-D).
- **Verified by:** the pytest runs and the live run above. The reviewer did not see the fix.

### Supervisor Q&A prep

1. **Is VERIFIED for pypdf 6.19.0 a property of CAVR or of a demo project written to pass?**
   Of both inputs, and the tests show each direction: the same wheel with a reader outside the guard is UNRESOLVED with an escalation (`test_reader_outside_the_guard_is_unresolved_with_the_escalation`), and the same project with an advisory for the version is REJECTED. The sample project was changed to use the guard and the policy to `pypdf>=5,<7`; both are stated as set-up choices.
2. **Why does the dashboard policy allow pypdf 5.1.0, a version with 97 advisories?**
   So that the scenario shows the advisory check working after the allowlist: the gate permits it and OSV rejects it. An allowlist entry is a range the project accepts, not a statement that every version in it is free of advisories.
3. **The wrapper lets the caller name the policy file and the project. What stops an agent from pointing it at a permissive policy?**
   Nothing in M1; the policy location is an input. `policy_version` (the digest of the policy) is in every verdict and in the cache key, but the path of the file is not printed. That is a listed limit.

## Demo polish — six demo issues from the mid demo script (2026-10-11)

Not a plan step: six issues Maryam listed after reading `docs/cavr-demo.md`, one commit each, on top of `82d2bd9`.
Maryam named `frontend/src/components/CavrModule.tsx` and `docs/cavr-demo.md` in the request, so both were edited
(they are outside the usual scope). With issues 1 and 2 the open part of plan step 13 (chips, timeline, proof drawer) is done.
Reviewed by cavr-reviewer (1 pass over `82d2bd9..cdbfa27` and the uncommitted notes); verdict: fix first; 3 BLOCKERs, fixed in the fix commit `fix(cavr): no "nothing found" without a scan, no advisory count without an OSV answer` (not reviewed again); 16 MINOR, 4 fixed there, 12 open.

| # | Issue | Commit |
|---|---|---|
| 1 | Chips are real requests through the real pipeline | `384ec4f` `feat(cavr): dashboard chips are six real requests from the scenario API` |
| 2 | No hardcoded result string; a dash when a value was not computed | `f705496` `fix(cavr): CAVR tab shows only values of the API response, a dash when not computed` |
| 3 | `fast_gate_ms` per verdict and per cache lookup | `02104d4` `fix(cavr): report fast_gate_ms per verdict and per cache lookup, not one p50` |
| 4 | Long advisory lists | `03d627f` `fix(cavr): long advisory lists show the count and the first three OSV ids` |
| 5 | Tampered-wheel run on its own copy | `42e2524` `fix(cavr): tampered-wheel demo run works on its own copy, never the genuine wheel` |
| 6 | Build step first; cases 1-6 re-recorded through the dashboard API | `cdbfa27` `docs(cavr): demo script starts with the frontend build; cases 1-6 re-recorded through the dashboard API` |

### Ch 6 Implementation

| File | Function / constant | What it does |
|---|---|---|
| `backend/cavr/api.py` (478 -> 589 lines) | `SCENARIOS` | Six chips as data, in page order: `verified`, `verified_again`, `known_vulnerable`, `not_on_allowlist` (`left-pad==1.0`, replaces `denylisted`), `tampered_wheel`, `network_off`. `expected_status` and `description` are text for the chip only. |
| | `stage_summary(verdict)`, `STAGE_TITLES` | The page's timeline: six stages (capture, gate, artifact, cache, analysis, verdict), each `{id, title, ran, values: [{label, value}]}`. Every value is copied from the verdict or is the length of one of its lists; not computed -> `None`; a stage with no value -> `ran: False`. Served as `stages` in `GET /api/cavr/proof/{run_id}`. |
| | `HASH_MATCHES`, `run_verification` | `hash_comparison` carries the artifact `rule`; `matches` is `True` / `False` only for `HASH_MATCH` / `HASH_MISMATCH`, else `None`. |
| | `verdict_events` | `resolution.first_advisory_ids` (first 3) and `resolution.advisory_summary`; `known_risk_signals` stays the whole list. |
| | `demo_quarantine_dir(condition)`, `verify_dashboard_request` | A run under a demo condition downloads into `<quarantine>-demo/<condition>`; a name that is not a condition raises `ValueError`. Review fix: the call is inside the `try`, so a directory that cannot be named is UNRESOLVED `INTERNAL_ERROR`, not a run that never finishes. |
| | `_affected_count(advisories)` (review fix) | The number of advisories that affect the packages, or `None` unless OSV answered for every package. Used for `vulnerability_count` and the timeline. |
| `backend/cavr/pipeline.py` (377 -> 436 lines) | `metrics(store)`, `_time_summary`, `_nearest_rank`, `STATUSES`, `CACHE_LOOKUPS` | p50 / p95 of `fast_gate_ms` by status, by cache lookup and by the pair; two hit rates (`cache_hits` of all verdicts, `cache_lookup_hits` of `cache_lookups`). The keys `fast_gate_ms_p50` / `_p95` are removed. |
| | `cache_lookup_of(verdict)`, `_log` | `HIT` / `MISS` / `NOT_REACHED` for the whole request, written to the verdict log. |
| | `default_quarantine_dir()` | The one place the default quarantine path is written. |
| `backend/cavr/storage.py` | `verdict_log.cache_lookup`, `record_verdict(..., cache_lookup=None)`, `init_db` | New column; an existing database gets it with `ALTER TABLE` (old rows keep `NULL`). |
| `backend/cavr/advisories.py` | `summarise_ids(ids)`, `FIRST_IDS = 3` | `A, B, C and 94 more`. Used by the three reasons that list ids (they named five). The result's lists are not shortened. |
| `backend/cavr/pip_shim.py` | `_render_package` | `advisories: pypdf 5.1.0 KNOWN_VULNERABILITY: 97 advisories: A, B, C and 94 more (every id: --cavr-json)`. |
| `frontend/src/components/CavrModule.tsx` (1189 -> 669 lines) | `CavrModule`, `runScenario`, `handlePipelineEvent` | Chips from `GET /api/cavr/scenarios`, run with `POST /api/cavr/run?scenario=<id>`. Removed: the five fixture names, the eight-step timeline with fixed timings, the sandbox / honeytoken panel, "VERIFIED MATCH", the Re-verify "Matches" timer, the browser-side typosquat detector, the invented "7.52 Priority Score". The three dialogs print fields of the proof. |
| `frontend/src/components/cavr/` (new) | `ScenarioChips.tsx`, `Timeline.tsx`, `ProofDrawer.tsx`, `AdvisoryList.tsx`, `runState.ts` (`EMPTY_RUN`, `applyEvent`) | The parts of the page that print API values, as components that take their data as props. `applyEvent` copies one stream event into the run state. |
| `frontend/src/components/cavr/` (changed) | `types.ts` (`NOT_COMPUTED = '—'`, `shown()`, `StageSummary`, `Scenario`), `ExpandableStep.tsx`, `MetricsTab.tsx` (`MetricsReport`), `OverviewTab.tsx`, `RequirementsTab.tsx`, `StageDetailPanel.tsx`, `AssuranceTab.tsx`, `CausalGraphTab.tsx` | One constant for a missing value. Requirements tab: last column is what the stage returned, no PASS / FAIL of the page's own. Metrics tab: three tables in place of the p50 / p95 cards. |
| `docs/cavr-demo.md` | | Step 1 is the frontend build; cases 1-6 are the six chips with re-recorded outputs; wrapper runs W1, W3, W4, W6 re-recorded. |
| Tests | `tests/test_cavr_frontend.py` (new, 21 functions, 26 cases), `tests/test_cavr_data/render_cavr.mjs` (new), `test_cavr_api.py` (31 -> 48 functions, 58 -> 81 cases), `test_cavr_pipeline.py` (50 -> 55), `test_cavr_advisories.py` (37 -> 40), `test_cavr_pip_shim.py` (33 -> 35), `test_cavr_live.py` (1 changed) | |

Key algorithm (`stage_summary`): take the first package of the verdict; for each of the six stages build a fixed list of
(label, value) by reading the verdict (`evidence.artifact.rule`, `cache.lookup`, ...); `ran` = at least one value is not
`None`. The page prints `shown(value)`, which is the dash for `None`.

Key algorithm (`metrics`): read every row of `verdict_log`; put its `fast_gate_ms` into three groups (status, cache
lookup, the pair); for each group sort the times and take the nearest-rank p50 and p95, `rank = ceil(percent * n / 100)`
computed in whole numbers.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Chips are fetched from the backend | Six names written into the page | The page then has no package name of its own; the list a chip sends is the list the tests check (`test_every_scenario_gives_the_verdict_its_chip_names`). |
| Chip 2 is the same request as chip 1, with no condition | A scenario that forces a hit | A forced hit would be a faked result. It is a hit only when chip 1 stored an analysis; clicked first it is a miss, and a test says so. |
| Chip 4 is `left-pad==1.0` (`NOT_ON_ALLOWLIST`) | Keep `requests-security` (`DENYLIST`) | Maryam's list. The denylist case keeps its test, through the request body. |
| `fixtures/scenarios.py` is checked to be unloaded, not deleted | Delete it and `resolver.py` | The request was "from any path the page can trigger". Importing `backend.main` in a fresh interpreter does not load it (test), and no file under `backend/` except `resolver.py` imports it (grep). The test sees import-time loading only, not an import inside a function. Deleting dead modules is a separate change. |
| The timeline is computed in the backend | Derive it in the page from the events | It can be tested in pytest, and the page only prints. The pipeline is one blocking call, so the stages are known together, at the verdict. |
| No time per stage | Keep the fixed "12ms" labels, or time each stage | Only `fast_gate_ms` for the request is measured. Showing stage times would be inventing them. |
| One dash constant (`NOT_COMPUTED`) | Words such as "pending", "not downloaded", "n/a" | Four tabs used eleven different words; one sign means "not computed" everywhere. |
| No overall p50 / p95 | Keep it beside the per-status rows | It is the number that misled (2.72 ms). Leaving it invites quoting it. |
| The cache lookup is logged per request | Derive "miss" from `cache_hit = 0` | A BLOCK or a failed download never looks anything up; counting it as a miss is wrong. Costs one nullable column. |
| Old log rows are `NOT_RECORDED`, hits included | Count old hits as `HIT`; guess `MISS` for the rest | Old misses cannot be told from BLOCKs. Counting only the old hits made the lookup rate too high (reviewer). All of them are left out of `cache_hit_rate_of_lookups`. |
| First 3 ids in reasons too (was 5) | Shorten only the display | One rule for the wrapper line, the reason and the page. The evidence lists are never shortened. |
| Demo runs get their own quarantine directory | Stop `fetch_artifact` deleting the older file | Removing a stale file after a mismatch is right for real runs (added in step 11 with a test). The fault was sharing the directory. |
| Render tests with `react-dom/server` | Add a JS test runner; source checks only | No new dependency (`esbuild` and `react-dom` are already installed for the build), and the real components are exercised with real API answers. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this work covers | Acceptance check |
|---|---|---|---|
| FR-1 | Intercept Before Execution | Every chip is a captured `pip install` request through the pipeline | `test_every_scenario_gives_the_verdict_its_chip_names` |
| FR-2 | Requirement Gate Enforcement | `left-pad==1.0` blocked before any download, shown as BLOCK with dashes after the gate | `test_left_pad_is_blocked_as_not_on_the_allowlist_before_any_download`, `test_a_stage_that_did_not_run_has_no_value_at_all` (4) |
| FR-6 | Fail-Closed Security Policy | A value that was not computed is never shown as a result; no hash result when nothing was hashed | `test_timeline_of_a_verdict_without_evidence_claims_nothing` (4), `test_the_proof_drawer_prints_the_hash_result_of_each_run` |
| none listed | Supervisor report: cache hit rate, p50 / p95 `fast_gate_ms` | Per verdict and per cache lookup | `test_blocks_do_not_move_the_latency_reported_for_verified_requests`, `test_percentiles_are_nearest_rank` (5) |
| none listed | CLAUDE.md "No fixture-faked results" | No fixture name and no fixed result string on the page; demo runs cannot touch real files | `test_no_old_fixture_name_is_left_in_the_page`, `test_no_fixed_result_string_is_left_in_the_page`, `test_a_tampered_run_never_deletes_or_alters_the_genuine_wheel_in_quarantine` |

### Ch 7 Test cases

Run on 2026-10-11 after the review fix:

- `.venv/bin/python -m pytest tests/test_cavr_*.py -q` -> 1227 passed, 7 skipped (was 1159 before this work; the 7 skips are the live tests).
- `.venv/bin/python -m pytest -q` -> 1285 passed, 7 failed, 7 skipped (the same 7 baseline tests; was 1217 passed).
- `CAVR_LIVE=1 .venv/bin/python -m pytest -q tests/test_cavr_live.py` -> 7 passed (real PyPI, OSV and pip).
- `npm --prefix frontend run build` (`tsc -b && vite build`) succeeds.
- Live, through the running app (`uvicorn backend.main:app`, fresh `runtime-demo`), at `42e2524`: the six chips in order gave
  VERIFIED (miss, 3912.65 ms), VERIFIED (hit, 2117.81 ms), REJECTED `KNOWN_VULNERABILITY` (97 advisories), BLOCK
  `NOT_ON_ALLOWLIST` (2.17 ms), REJECTED `HASH_MISMATCH`, UNRESOLVED `REGISTRY_UNAVAILABLE`. Outputs are in `docs/cavr-demo.md`.
- Mutation check of the render tests (files restored): "VERIFIED MATCH" put back in the proof drawer and "did not run"
  changed to "done" in the timeline -> 5 of the then 18 frontend cases failed (done before the review; not repeated for the review fix).
- **Not checked in a browser** (none installed here). See "Known limitations".

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_scenario_list_is_six_real_requests` | Issue 1 | `list_scenarios()` | the six requests in order, labels "1." to "6." | pass |
| `test_every_scenario_gives_the_verdict_its_chip_names` | Issue 1 | the six chips in order, offline index | VERIFIED miss, VERIFIED hit, REJECTED OSV, BLOCK, REJECTED hash, UNRESOLVED | pass |
| `test_the_again_chip_is_the_same_request_and_hits_the_cache_only_when_an_analysis_is_stored` | Issue 1, edge | chip 2 first on an empty cache, then again | MISS, then HIT | pass |
| `test_left_pad_is_blocked_as_not_on_the_allowlist_before_any_download` | Issue 1 | `left-pad==1.0` | BLOCK `NOT_ON_ALLOWLIST`; index never asked; no quarantine directory | pass |
| `test_the_running_app_loads_none_of_the_fixture_or_simulation_modules` | Issue 1 | `import backend.main` in a new interpreter | `fixtures.scenarios`, `resolver` and six more not in `sys.modules` | pass |
| `test_no_old_fixture_name_is_left_in_the_page`, `test_the_page_names_no_package_of_its_own`, `test_chips_are_loaded_from_the_api_and_run_through_the_scenario_endpoint`, `test_the_chips_are_the_scenarios_of_the_backend` | Issue 1, page | sources; chips rendered from `list_scenarios()` | no old name, no package name; six labels of the backend | pass |
| `test_timeline_of_a_verified_run_copies_the_verdict` | Issue 2 | verified run, then again | every stage ran with the verdict's values; second run: lookup HIT | pass |
| `test_a_stage_that_did_not_run_has_no_value_at_all` (4), `test_timeline_values_of_the_failing_scenarios` | Issue 2, failure cases | BLOCK, tampered, network off, OSV-rejected | stages after the stop: `ran` false, every value `None`; OSV case: contract present, scan `None` | pass |
| `test_no_stage_carries_a_time_of_its_own` | Issue 2 | verified run | the only time is `fast_gate_ms` | pass |
| `test_timeline_of_a_verdict_without_evidence_claims_nothing` (4), `test_a_pipeline_fault_shows_only_the_verdict_stage` | Issue 2, edge | empty and malformed verdicts; a raising pipeline | no computed value; only the verdict stage ran | pass |
| `test_network_off_is_unresolved_and_the_real_transport_is_never_asked` (changed) | Issue 2 | network off | `hash_comparison.matches` is `None`, not `False` | pass |
| `test_no_fixed_result_string_is_left_in_the_page`, `test_a_value_that_was_not_computed_is_printed_as_a_dash` | Issue 2, page sources | 17 fixed strings, 11 old placeholders | none left; the dash is written in `types.ts` only | pass |
| `test_the_page_before_any_run_shows_no_result` | Issue 2, render | the whole module, nothing fetched | no status word, target and all six stages a dash | pass |
| `test_the_timeline_prints_what_each_stage_returned_and_a_dash_for_the_rest` (6) | Issue 2, render | the proof of each chip | every value printed; dashes = values not computed; "did not run" per stage | pass |
| `test_the_proof_drawer_prints_the_hash_result_of_each_run` | Issue 2, render | verified, tampered, network off, BLOCK | `HASH_MATCH` true; `HASH_MISMATCH` false; rule and dashes; all dashes | pass |
| `test_the_overview_shows_the_verdict_and_dashes_for_what_was_not_computed`, `test_the_overview_of_a_run_without_a_download_names_the_rule_and_no_hash`, `test_the_requirements_tab_prints_what_a_stage_returned_and_no_pass_of_its_own` | Issue 2, render | BLOCK, verified, network off | dash for the hash of a BLOCK; no PASS / FAIL anywhere | pass |
| `test_verdicts_are_logged_and_the_report_numbers_come_from_the_log` (changed) | Issue 3 | miss, hit, BLOCK, hit | three groupings; lookups 3; rate of lookups 2/3; no overall percentile | pass |
| `test_blocks_do_not_move_the_latency_reported_for_verified_requests` | Issue 3 | 2 VERIFIED (3000, 2000 ms), 5 BLOCK (1-4 ms) | VERIFIED p50 2000, p95 3000; BLOCK p50 2 | pass |
| `test_percentiles_are_nearest_rank` (5) | Issue 3, edge | 1, 2, 20, 21, 100 rows | p50 / p95 by rank | pass |
| `test_which_cache_lookup_is_logged_for_each_kind_of_verdict`, `test_a_rejection_by_osv_before_any_stored_analysis_is_logged_as_a_miss` | Issue 3 | network down, BLOCK, miss, hit, hit then OSV rejects | `NOT_REACHED`, `NOT_REACHED`, `MISS`, `HIT`, `HIT`; OSV first: `MISS` | pass |
| `test_a_verdict_log_made_before_the_lookup_was_logged_is_still_read` | Issue 3, edge | a database with the old table and 3 rows (one a hit), then one new miss | column added; the 3 old rows `NOT_RECORDED`; 0 hits of 1 lookup | pass |
| `test_a_run_rejected_before_the_scan_does_not_say_that_the_scan_found_nothing`, `test_a_run_whose_scan_ran_still_shows_what_it_found` | Review BLOCKER 1, render | pypdf 5.1.0 (no scan); verified; verified with its sinks removed (constructed) | no "nothing found" sentence and a dash; the two sinks; the sentence only when a scan result exists | pass |
| `test_no_advisory_count_is_shown_when_osv_gave_no_answer`, `test_the_advisory_card_shows_no_count_when_osv_gave_no_answer` | Review BLOCKER 2 | network off with no saved OSV answer | count `None` / a dash, rule `ADVISORIES_UNAVAILABLE`; with a saved answer a real 0 | pass |
| `test_a_demo_directory_that_cannot_be_named_is_an_unresolved_run_that_finishes` | Review MINOR 9 | quarantine directory `/` | UNRESOLVED `INTERNAL_ERROR`, run finished, nothing downloaded | pass |
| `test_metrics_come_from_the_verdict_log` (changed), `test_the_metrics_tab_lists_the_time_per_verdict_and_per_cache_lookup`, `test_the_metrics_tab_with_an_empty_log_shows_dashes` | Issue 3, API and render | 5 logged runs and 2 demo runs; empty log | demo runs not counted; three tables; empty groups are dashes | pass |
| `test_a_long_advisory_list_is_a_count_and_the_first_three_ids_in_the_reason_and_whole_in_the_result`, `test_summarise_ids_names_the_first_three_and_counts_the_rest` (6), `test_the_other_reasons_that_list_ids_are_summarised_the_same_way` | Issue 4 | 97 recorded advisories; 0-97 ids; GIT-only and out-of-range lists | "… A, B, C and 94 more"; result keeps all 97 | pass |
| `test_a_long_advisory_list_is_one_short_line_and_whole_in_the_json`, `test_a_short_advisory_list_is_printed_whole` | Issue 4, wrapper | 40 synthetic advisories; 2; none | one line under 200 characters; `--cavr-json` has all 40 | pass |
| `test_pypdf_5_1_0_is_rejected_by_osv_with_the_recorded_advisory_ids` (changed), `test_advisory_summary_is_null_when_no_advisory_affects_the_version` | Issue 4, API | pypdf 5.1.0; 6.19.0 | first 3 ids and summary; proof has 97; `None` when clean | pass |
| `test_a_long_advisory_list_is_a_count_three_ids_and_a_closed_section_with_all_of_them`, `test_the_advisory_card_without_advisories` | Issue 4, render | pypdf 5.1.0; verified; BLOCK | one closed `<details>` with 97 ids; only 3 outside it; link to the proof JSON; dash when OSV was not asked | pass |
| `test_a_tampered_run_never_deletes_or_alters_the_genuine_wheel_in_quarantine` | Issue 5 | verified, tampered, chip 2 | same bytes, modification time and inode; nothing added beside it; still a cache hit | pass |
| `test_a_tampered_run_in_the_middle_of_a_real_run_does_not_change_the_real_verdict` | Issue 5, failure case | a tampered run between the real run's download and its scan | real run VERIFIED (before the fix: UNRESOLVED `ARTIFACT_CHANGED`) | pass |
| `test_tampered_runs_before_and_after_leave_one_evidence_file_and_no_genuine_looking_wheel`, `test_demo_directory_is_beside_the_real_quarantine_and_only_for_a_named_condition`, `test_what_the_pipeline_is_given_under_each_condition` (changed) | Issue 5, edge | two tampered runs; names that are not conditions | one `.rejected` file; real quarantine never created; `ValueError` | pass |
| `test_live_dashboard_scenarios_are_real_requests` (`CAVR_LIVE=1`, changed) | Issues 1 and 5, real PyPI + OSV | the six chips | as above; genuine wheel `7e5d6e73…8d14` after the tampered run | pass |

### Defects found and fixed

| # | Found by | Finding | Outcome |
|---|---|---|---|
| 1 | Demo script, item 2 | `hash_comparison.matches` was `False` for a run in which nothing was hashed | `None` unless the rule is `HASH_MATCH` / `HASH_MISMATCH` (issue 2) |
| 2 | Demo script, item 6; new test | After a tampered run the genuine wheel was gone; a real run interleaved with it ended UNRESOLVED `ARTIFACT_CHANGED` (reproduced by the test before the fix) | Own directory for demo runs (issue 5) |
| 3 | Reading `CavrModule.tsx` | Side effects (`fetch`, other `setState` calls) inside the `setRunState` updater; the run was only marked finished by the stream's error event | `applyEvent` is a pure function; `DECIDED` ends the run and reloads the cache box |
| 4 | Reading `CavrModule.tsx` | Before any run the page showed `pip install dormant-exfil==1.2.0` as the intercepted target | A dash until the backend reports a request |
| 5 | Running the live tests at the end | `test_live_dashboard_scenarios_are_real_requests` still read `outcome["denylisted"]`; it is skipped without `CAVR_LIVE=1`, so the offline suite did not show it | Test updated for the six chips; 7 live tests pass |
| 6 | Rendering the page parts from the live answers | Overview printed "REGISTRY_UNAVAILABLE against the registry digest"; package and version came only from the clicked chip | "Hash check: <rule>"; package and version from the proof |
| 7 | Own render test | The test listed the statuses in another order than `pipeline.STATUSES` | Test imports the constant |
| 8 | cavr-reviewer (BLOCKER 1) | After chip 3 (`pypdf==5.1.0`) the stage panel, the Capability Contract tab and the Triggers tab said "no sink call found" / "Nothing found", although OSV rejected the request before any wheel was scanned (`scan: []`, `reachability: null`) | Those sentences are printed only when a sink judgement exists; otherwise a dash or "The AST scan did not run" |
| 9 | cavr-reviewer (BLOCKER 2) | "0 advisories affect it" was shown when OSV gave no answer (network off on a fresh data directory): an `ADVISORIES_UNAVAILABLE` record has an empty `affected` list | `_affected_count` returns `None` unless OSV answered for every package |
| 10 | cavr-reviewer (BLOCKER 3) | On a database with rows from before the `cache_lookup` column, old hits were counted as lookups and old misses were not, so the lookup hit rate was too high; these notes and the Q&A said the opposite | Every old row is `NOT_RECORDED`; `cache_lookup_hits` added and shown beside the rate; notes, Q&A and demo script corrected |
| 11 | cavr-reviewer (MINOR 2-4, 9) | Demo script: an extra chip-2 click in the recorded metrics was not a command of the script and was said to show the genuine wheel survived (it cannot); "W1-W6" for four runs. `demo_quarantine_dir` was called outside the `try` | Reworded; call moved inside the `try`, with a test |

### Known limitations / deferred

- **The page was not opened in a browser.** Checked instead: the TypeScript build; the app serving the new bundle;
  the six cases through the endpoints the page calls; the page's components rendered to HTML with `react-dom/server`
  from offline runs (tests) and from the live answers. Not exercised: clicks, the `EventSource` stream in a browser,
  layout and CSS. `runScenario`, `handlePipelineEvent` and the three dialogs have no automated test.
- The render tests need Node.js and `frontend/node_modules`; without them every case that renders is skipped (19 of the 26).
- What the frontend tests cannot show (reviewer): the fixed-string check is a list of 17 literals, so it cannot show that no other invented sentence exists (BLOCKER 1 was one); no test renders an intermediate state such as a verdict without a proof; the harness draws the stages with `ExpandableStep` itself and does not render `Timeline`; the `assurance` view is unused.
- 12 MINOR items of the review are open and listed in `docs/cavr-m1-plan.md` ("Found in the demo-polish review"). The ones to know: a green tick in the timeline means "ran", not "passed"; "Cache hit: no" is shown for a BLOCK that never reached the cache; `advisory_summary` names the requested package even when a dependency is the affected one (not reachable with the shipped policy: pypdf has one node).
- `frontend/tsconfig.tsbuildinfo` is tracked and rewritten by every build; it was restored and not committed (outside the scope).
- The timeline fills in when the verdict is known, not stage by stage; there is no time per stage.
- The header text of the module ("adaptively triggers dormant paths via counterfactual synthesis ...") and the box titles
  ("STEP 3 · HOSTILE SANDBOX") were left as they are: they describe the project, not a run. The box now shows a dash.
- `fixtures/scenarios.py`, `resolver.py` and the other legacy modules are still in the repository, unused by the app.
- `project_policy.json` still approves `pdf-clean-extractor==1.0.0`, a name with no release on PyPI. Anyone could
  register it. Not changed (it changes the policy version and the cache key). -> Maryam.
- Metrics are over very few rows in the demo (1-3 per group): observations, not statistics. A cache hit was once
  slower than the miss (4524.49 ms against 3912.65 ms): both download the wheel and ask OSV.
- `api.approve_alternative`, the unfinished-run case in `run_verification` and the other MINOR items of the batch
  12-13 review are unchanged.
- Wrapper output for an UNRESOLVED download still prints `artifact: None`, `sha256 None`, `cache: None`.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** all code and test changes of the six commits, the render harness, the rewritten
  `docs/cavr-demo.md` (its recorded blocks are real outputs of the commands shown), these notes, the commits.
- **Reviewed / changed by Maryam:** she wrote the list of six issues and the expected verdict of each chip. Nothing in
  the commits has been reviewed by her yet. Open for her: the wording left in the page header; the `pdf-clean-extractor`
  policy entry; a browser dry run.
- **Verified by:** the pytest runs above, the live tests, the live run of the six chips through the running app, the
  mutation check of the render tests, `tsc` and `vite build`. No browser check.

### Supervisor Q&A prep

1. **How do you know the page shows what the pipeline found and not text written into the page?**
   The page has no package name of its own (source tests), and its components are rendered in tests from real API
   answers: every printed stage value equals the proof's value, and a value that was not computed is a dash. Putting
   "VERIFIED MATCH" back makes those tests fail. The limit: a blocklist cannot prove that no invented sentence is left;
   the reviewer found one ("no sink call found" when no scan ran), now fixed and tested.
2. **Why is there no single p50 for the fast gate?**
   Because a BLOCK takes about 2 ms and downloads nothing. With five BLOCKs in ten rows the median was 2.72 ms, which
   says nothing about verifying a package. The times are given per verdict and per cache lookup, with the count beside them.
3. **Is the cache-hit chip a real cache hit?**
   Yes. It sends the same request as chip 1 and nothing else. It is a hit only because chip 1 stored an analysis under
   the same eight key fields; on an empty cache the same chip is a miss
   (`test_the_again_chip_is_the_same_request_and_hits_the_cache_only_when_an_analysis_is_stored`).

## Integration fix — pypdf call sites reached through a vendored LOCAL artifact (2026-10-11)

Not a plan step. Maryam asked for `tests/test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies` to be
fixed in CAVR code or in the test, without weakening the test. The test is unchanged.

Why it failed: the scenario `cross_module` turns `app/pdf_adapter.py` into
`from vendor.invoice_pdf_lab import extract_invoice_text`, so `PdfReader` is called in `vendor/`. The older contract
`capability_contract.infer` takes its call sites from `ContextService.dependency_context` (orchestrator), which reads
`app/*.py` only. No pypdf call site -> `confidence: insufficient` -> every node "Capability contract lacks
task/call-site authority" (UNRESOLVED). The repair candidate (`vendor/invoice_pdf_safe.py`) was therefore UNRESOLVED in
`Service._repair`, which promotes a repair only on VERIFIED: no `repair.applied`, final decision BLOCK.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `backend/cavr/capability_contract.py` (247 -> 347 lines) | `use_through_local_artifacts(context)` (new) | Returns one attribution per pypdf call site that the application reaches through a LOCAL lock artifact, with the chain in `through` (`local_package`, `artifact`, `sha256`, `imported_at`, `called_at`). `[]` when a link is missing. |
| | `_application_call(context, project, module)` (new) | Link 3: the first call in `app/` of a name imported from the artifact's module, in the importing file or one relative re-export away. |
| | `_relative_target(record)`, `_in_app(record)` (new) | The project file a `from .x import name` reads; whether a record is in `app/`. |
| | `infer(context, node)` | `is_pdf` now also accepts the records of `use_through_local_artifacts`; the contract has a new key `local_artifact_use` (inside the digest). Nothing else changed. |
| `tests/test_cavr_vendored_use.py` (new, 15 functions, 31 cases) | | See below. |

Key algorithm (`use_through_local_artifacts`):
1. Lock must pin pypdf and hold a LOCAL `.py` artifact; `extract_project_context(context.path)` must be `OK`.
2. Link 1: the artifact file's SHA-256 (from the project context) equals the lock's `sha256`.
3. Link 2: a file in `app/` imports the artifact's module (`vendor/x.py` -> `vendor.x`).
4. Link 3: `app/` calls what was imported (a call site with that module's symbol, or a call of the name in an `app/` file that imports it relatively from the importing file).
5. Link 4: the artifact's own source has pypdf call sites (`usage_of(project, ["pypdf"])`); one record per site.

### Design decisions

| Decision | Alternative | Why |
|---|---|---|
| Fix in `backend/cavr/capability_contract.py` | Make `ContextService.dependency_context` read `vendor/` | `backend/orchestrator/` is outside this branch; the plan says to work around it inside `backend/cavr/`. |
| Keep the test as it is | Accept UNRESOLVED / REVIEW in the test | That would weaken it: the test is the proof that a verified repair is promoted and re-verified. |
| Require all four links, `[]` otherwise | Count any pypdf call anywhere in the project | "Imported but never used" is no authority in C4 either (`NO_CALL_SITE_AUTHORITY`); a call in `tests/` or in a file the app does not import says nothing about the application. |
| Check the artifact's SHA-256 against the lock here | Rely on `read_artifact` | For the pypdf node the vendored file has not been hash-checked yet when its contract is inferred. |
| Reuse `extract_project_context` / `usage_of` | A second AST walker | Same parser, same budgets, same fail-closed results (unparsed file, symlink) as C4. |
| New contract key `local_artifact_use`, `evidence` untouched | Append to `evidence.dependency_attributions` | `evidence` stays exactly what the orchestrator returned; the extra records are visibly CAVR's. Cost: every contract digest (and so every cache key of `analyze`) changes once. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-3 | Capability Contract Inference | Call-site authority for a package used through a vendored module | `test_cross_module_scenario_reaches_pypdf_through_the_vendored_lab_file`, `test_reexported_name_called_in_another_app_file` |
| FR-6 | Fail-Closed Security Policy | A missing link, a changed artifact, an unparsed project file -> no authority | `test_a_missing_link_gives_no_authority` (10), `test_artifact_whose_bytes_are_not_the_locked_ones_gives_no_authority`, `test_project_source_that_cannot_be_parsed_gives_no_authority` |
| none listed | Repair is promoted only after re-verification, and invalidates SATRA evidence | End to end | `tests/test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies` |

### Ch 7 Test cases

Run on 2026-10-11. `tests/test_cavr_vendored_use.py`: 31 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_cross_module_scenario_reaches_pypdf_through_the_vendored_lab_file` | Real scenario, before repair | `cross_module` candidate | orchestrator finds 0 pypdf attributions; chain `app/pdf_adapter.py:1` -> `app/main.py:87` -> `vendor/invoice_pdf_lab.py:10,11`; both contracts `rule-grounded`, SECRET_ACCESS and NETWORK_CONNECT still denied | pass |
| `test_repaired_cross_module_scenario_reaches_pypdf_through_the_safe_file` | Real scenario, after `replace_lab` | repaired candidate | chain through `vendor/invoice_pdf_safe.py`; `rule-grounded` | pass |
| `test_safe_scenario_has_no_local_artifact_and_keeps_its_direct_call_sites` | No change for a project without a LOCAL artifact | `safe` candidate | `[]`, `rule-grounded` from the direct call sites | pass |
| `test_reexported_name_called_in_another_app_file` | Link 3 through a relative re-export | tmp project | 2 records, `called_at` `app/main.py:5` | pass |
| `test_name_called_in_the_file_that_imports_it` (4) | Link 3 in one file: `from`, `as`, `import a.b`, `import a.b as c` | tmp project | `called_at` in `app/pdf_adapter.py` | pass |
| `test_renamed_reexport_is_followed_by_the_name_the_adapter_binds` | `as` on both imports | tmp project | `called_at` `app/main.py:3` | pass |
| `test_a_missing_link_gives_no_authority` (10) | Edge / failure: imported never called; named never called; same name from another module; another name; local function of the same name; artifact not imported; another vendored file imported; artifact without pypdf; pypdf imported never called; pypdf called by a file that is not the artifact | tmp project | `[]`, contract `insufficient`, `required == []` | pass |
| `test_a_call_outside_app_is_not_the_applications_call` | Call only in `tests/` | tmp project | `[]` | pass |
| `test_the_recorded_import_is_the_applications_not_another_directorys` | `admin/tool.py` imports and calls too | tmp project | chain names `app/` files only | pass |
| `test_artifact_whose_bytes_are_not_the_locked_ones_gives_no_authority` | Failure: file edited after the lock | lock hash of other bytes | `[]`; the matching lock gives records | pass |
| `test_lock_entries_that_cannot_carry_the_chain` (6) | Failure: no pypdf pin; no LOCAL entry; `.py` entry not LOCAL; artifact missing; `../` path; empty lock | tmp project | `[]` | pass |
| `test_project_source_that_cannot_be_parsed_gives_no_authority` | Failure: `app/broken.py` | tmp project | `[]` | pass |
| `test_srs_without_a_pdf_task_is_still_insufficient` | The SRS condition of `infer` still holds | SRS without "pdf" | records found, contract `insufficient` | pass |
| `test_contract_digest_follows_the_chain` | Digest covers the chain | same project twice; call moved one line | equal; then different | pass |
| `tests/test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies` | The asked test, unchanged | `cross_module`, `auto_repair=True` | ACCEPT, `repair.applied`, SATRA invalidated and rerun, stale CAVR REJECTED, current CAVR VERIFIED | pass (failed before: `BLOCK`) |

- Before the fix (2026-10-11, same tree): `tests/test_integration.py` + `tests/test_api_replay.py` -> 1 failed, 9 passed. The other 6 of the former 7 baseline failures already passed after the merge of `origin/master`.
- `.venv/bin/python -m pytest -q` -> 1323 passed, 0 failed, 7 skipped (the 7 skips are `tests/test_cavr_live.py` without `CAVR_LIVE=1`); was 1285 passed, 7 failed.
- Mutation check (7 mutations of the new code, run by hand, not kept): link 3 skipped -> 13 failed; hash not compared -> 1; relative target not compared -> 1; unparsed project accepted -> 1; `infer` without the new records -> 3; link 4 in any file and link 2 in any directory -> 0 at first, 1 each after two cases were added.

### Defects found and fixed

- The mutation check showed two unchecked conditions (pypdf call in a file that is not the artifact; import outside `app/`). Added the tenth case of `test_a_missing_link_gives_no_authority` and `test_the_recorded_import_is_the_applications_not_another_directorys`.
- Review: 0 passes of cavr-reviewer (not requested for this fix), no verdict, 0 MINOR recorded.

### Known limitations / deferred

- Syntactic only. Link 4 is per file, not per function: a pypdf call anywhere in the artifact counts, also outside the function the application calls. A re-export is followed one file deep, and only for `from .x import name` (not `from . import x`, not a package `__init__.py`).
- Only `app/` is the application, and the import name `pypdf` is fixed, as in the orchestrator's alias map. C4 proper (`infer_capability_contract`) reads import names from the wheel; `infer` is replaced by it in plan step 14.
- A contract is not a verdict: with the contract `rule-grounded`, the lab file is still REJECTED by what the sandbox observes, and `pypdf` in the lab run is now VERIFIED instead of UNRESOLVED.
- `extract_project_context` now runs once per locked package when the lock has a LOCAL artifact (twice per analysis in the scenario).
- The run rewrites the tracked file `reports/scenario-validation.json` (fixture teardown in `tests/conftest.py`); it was restored and not committed (outside the scope).
- From 2026-10-25 the stored PyPI advisory record is older than 30 days (see the Step 14 note); the integration tests that need pypdf VERIFIED will then fail for that separate reason.
- `docs/cavr-m1-plan.md` still names 7 baseline failures; today's count is 0.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the diagnosis (a reproduction script that printed the run's events, not kept), the change in `capability_contract.py`, `tests/test_cavr_vendored_use.py`, these notes, the study Q&A entry, the commit.
- **Reviewed / changed by Maryam:** nothing yet. She set the constraint (CAVR code or the test, test not weakened).
- **Verified by:** the asked test and the full suite (numbers above), the run without the fix, the mutation check. No cavr-reviewer pass.

### Supervisor Q&A prep

1. **Did you make the test pass by loosening CAVR?**
   No. The test is untouched, and authority needs four links read from real files: a LOCAL artifact with the locked SHA-256, an import in `app/`, a call of the imported name in `app/`, a pypdf call in the artifact. Ten missing-link cases stay `insufficient`.
2. **Why was the first analysis REJECTED and the repair still not applied?**
   REJECTED came from the sandbox (the lab file sent the canary). The repair candidate had nothing to reject, but its contract was `insufficient`, so it was UNRESOLVED, and `Service._repair` promotes only a VERIFIED candidate.
3. **Why not fix the orchestrator's reader?**
   It belongs to another member. CAVR adds its own evidence next to the orchestrator's (`local_artifact_use`) and leaves `evidence` as returned.

## Defects found by CI (2026-10-11)

GitHub Actions run 38135800645 on `fd276d7` (Python 3.12, Docker and Podman disabled by the workflow): 2 failed, 1302 passed, 26 skipped.
Both tests pass on the development machine (Python 3.14.4, no strace, no Docker). Both were reproduced locally with Python 3.12.15
(`/usr/bin/python3.12`, a venv from `requirements.lock.txt`) and a strace 6.19 binary put on PATH, then fixed.

| # | Test | Cause | Reproduced with |
|---|---|---|---|
| 1 | `tests/test_cavr_contract.py::test_directory_that_cannot_be_listed_makes_the_context_unresolved` | `context_extractor._python_files` called `(path / "pyvenv.cfg").is_file()` on a directory of mode 0. `Path.is_file()` raises `PermissionError` on Python 3.12 and returns False on 3.14. | Python 3.12, with or without strace |
| 2 | `tests/test_modules.py::test_controlled_dormant_execution` | Not the Python-audit mode. With strace available the sandbox runs in `PINNED_INERT_LAB_STRACE`; `runtime_monitor.normalize` dropped every line with ` = -1 `, and the lab file's `socket.create_connection(..., timeout=1)` is a non-blocking connect that strace prints as `connect(...) = -1 EINPROGRESS`. No `NETWORK_CONNECT` event, so no SECRET_READ -> NETWORK_CONNECT pair and no `causal_confirmed`. | Python 3.12 and 3.14 with strace on PATH; passes on both without strace |

The CI log does not print the execution mode, so "the runner has strace" is concluded from the reproduction, not read from the log.
The test now prints the mode in its assertion message. Defect 2 was already written down as deferred in `docs/cavr-m1-plan.md`
("Found in commit 0b"); the EINPROGRESS part is now fixed.

### Ch 6 Implementation

| File | Function | Change |
|---|---|---|
| `backend/cavr/context_extractor.py` (238 -> 273 lines) | `_is_symlink(path)`, `_is_virtualenv(directory)` (new) | `os.lstat` / `os.stat` with `stat.S_ISLNK` / `S_ISREG`. "Not found" is False; any other `OSError` is raised to the caller. |
| | `_python_files` | The checks of a directory are inside `try / except OSError`: the directory is added to `not_read` and is not entered. The symlink check of a `.py` file is caught the same way. |
| | `extract_project_context` | The check of the project directory itself uses `os.stat`: missing -> `PROJECT_MISSING` as before; exists but may not be examined -> `SOURCE_NOT_READ` with `not_read == [{"file": "."}]` (on 3.12 this raised, on 3.14 it said "does not exist"). |
| `backend/cavr/runtime_monitor.py` (18 -> 20 lines) | `normalize` | A line with ` = -1 ` is still skipped, except `connect(` with ` = -1 EINPROGRESS`. Whether it becomes an event is decided by the unchanged rule below it (`AF_INET` only). |
| `tests/test_cavr_runtime_monitor.py` (new, 5 functions, 9 cases) | | See below. |
| `tests/test_cavr_contract.py` (+4 functions, 6 cases, and the helper `refuse`) | | See below. |
| `tests/test_modules.py` | `test_controlled_dormant_execution` | Two assertions added (a `NETWORK_CONNECT` event in the activated run, none in the normal run) and the mode in two assertion messages. Nothing removed. |

Key algorithm (walk): for each directory `os.walk` offers: symlink -> `not_read`; hidden / cache / virtualenv -> `skipped`;
a check that raises `OSError` -> `not_read`, not entered; otherwise entered. Any `not_read` entry makes the result UNRESOLVED `SOURCE_NOT_READ`.

### Design decisions

| Decision | Alternative | Why |
|---|---|---|
| `os.stat` / `os.lstat` with our own `except` | Keep `pathlib` and wrap it in `try` | `pathlib` hides the error on 3.14, so the unreadable directory was treated as "no virtualenv" there. With `os.stat` both versions do the same and the tests can show it. |
| A directory whose check fails is `not_read` and not entered | Enter it and let `os.walk` report it | One entry per directory on every version (entering reports it a second time, or lists files that cannot be read). |
| Fix `normalize` so the correlation is produced | Change the test to expect no confirmation under strace | The confirmation is valid in strace mode: the trace has the read of `canary.txt`, then the connect to `127.0.0.1:18765`, and the harness received the exact marker. Only the parser lost the connect. It also lost the `NETWORK_CONNECT` violation. |
| Keep only EINPROGRESS for `connect` | Keep every failed `connect`, or check `getsockopt(SO_ERROR)` afterwards | EINPROGRESS means "started", not "failed". A refused connect made no connection, and counting attempts is the M2 sandbox decision already in the plan. Following `getsockopt` needs per-descriptor state across `<unfinished ...>` lines. |
| Change in `runtime_monitor.py`, not in `threat_repo/source_sink_rules.py` | Make `correlate` accept a received marker without a connect event | `correlate` is right to require the ordered events; it is also outside this branch. |

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Project source that cannot be examined is UNRESOLVED on every Python version, never a crash and never "no virtualenv" | `test_directory_that_cannot_be_searched_is_reported_once_whatever_its_mode` (3), `test_virtualenv_check_that_fails_makes_the_directory_not_read_on_every_python` |
| none listed | Runtime observation: a network connection is observed in every monitor mode | strace: non-blocking connect | `test_recorded_lab_trace_has_the_secret_read_and_then_the_connection`, `tests/test_modules.py::test_controlled_dormant_execution` |

### Ch 7 Test cases

Run on 2026-10-11.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_directory_that_cannot_be_listed_makes_the_context_unresolved` (existing) | CI defect 1 | directory of mode 0 | UNRESOLVED `SOURCE_NOT_READ`, `not_read == ["locked"]` | pass on 3.12 and 3.14 (3.12 before: `PermissionError`) |
| `test_directory_that_cannot_be_searched_is_reported_once_whatever_its_mode` (3) | Edge: modes 000, 444, 200, with a nested directory | real `chmod` | one `not_read` entry "locked", only `a.py` read | pass |
| `test_virtualenv_check_that_fails_makes_the_directory_not_read_on_every_python` | The 3.12 behaviour on any Python | `os.stat` refuses `pyvenv.cfg` | `not_read == ["pkg"]`, nothing skipped | pass |
| `test_symlink_check_that_fails_is_not_read` | Failure of `lstat` on a file, and on a directory with an I/O error | `os.lstat` refuses `b.py`, then `pkg` | that name in `not_read` with the error text | pass |
| `test_project_directory_that_may_not_be_examined_is_not_called_missing` | The project directory under a closed parent; a file and a path under a file as "project" | real `chmod` | `SOURCE_NOT_READ` with `"."`; then OK; `PROJECT_MISSING` for the two non-directories | pass |
| `test_recorded_lab_trace_has_the_secret_read_and_then_the_connection` | CI defect 2 on recorded strace lines | 8 lines of the real trace | FILE_WRITE, SECRET_ACCESS, NETWORK_CONNECT `127.0.0.1:18765` | pass |
| `test_recorded_lab_trace_gives_the_confirmed_correlation_and_the_network_violation` | Correlation and violations from those events | events + received marker | one confirmed SECRET_ACCESS -> NETWORK_CONNECT hit; violations SECRET_ACCESS, NETWORK_CONNECT, CANARY_FLOW | pass |
| `test_the_connection_alone_is_not_a_confirmed_flow` | Failure cases of the confirmation | nothing received; another payload; no read; connect before read | not confirmed / no hit | pass |
| `test_connect_results` (5) | Which connect results are events | `= 0`, EINPROGRESS, ECONNREFUSED, ENETUNREACH, EACCES | event for the first two only | pass |
| `test_einprogress_is_an_exception_for_connect_only` | Edge: EINPROGRESS on `openat`; failed `openat` / `execve`; `AF_UNIX` connect; non-loopback address | single lines | no event, except the `AF_INET` connect ("unresolved socket") | pass |
| `tests/test_modules.py::test_controlled_dormant_execution` | The CI test, with two more assertions | `cavr_canary` scenario | REJECTED, canary received only when activated, NETWORK_CONNECT only when activated, `causal_confirmed` | pass in `PINNED_INERT_LAB_PYTHON_AUDIT` and `PINNED_INERT_LAB_STRACE`, on 3.12 and 3.14 |

- Old code against the new tests: Python 3.14 without strace -> 9 failed; Python 3.12 with strace -> 13 failed, among them the two CI failures.
- `.venv/bin/python -m pytest -q` (Python 3.14.4, no strace) -> 1338 passed, 0 failed, 7 skipped (was 1323 passed).
- Python 3.12.15 with strace on PATH, no Docker / Podman -> 1338 passed, 0 failed, 7 skipped. CI has 26 skips because the frontend render tests need Node modules there.
- Not run: the docker and podman modes (not installed here, disabled in CI).

### Defects found and fixed

- Defect 1 and defect 2 above.
- Found while fixing 1: on Python 3.14 the old code did not report a directory of mode 444 as one unreadable directory (case `[292]` failed on the old code), and called a project directory under a closed parent "does not exist". Both fixed by the same change.
- Found while fixing 2: under strace the lab run also had no `NETWORK_CONNECT` violation (only SECRET_ACCESS and CANARY_FLOW). It has one now.
- Review: 0 passes of cavr-reviewer (not requested), no verdict, 0 MINOR recorded.

### Known limitations / deferred

- Every other failed syscall is still skipped by `normalize`: a refused or blocked connect and a failed open of a secret file leave no event (plan, "Found in commit 0b"). -> M2 sandbox.
- An EINPROGRESS connect is recorded without checking that it completed.
- The file-level `lstat` failure can only happen when permissions change during the walk; it is tested by replacing `os.lstat`, not with a real file system.
- `os.walk` decides "directory or file" itself; on a file system without entry types, a subdirectory of a directory that may be listed but not searched could be taken for a file. Its parent is already `not_read` in that case (the `pyvenv.cfg` check fails first).
- The fix is confirmed on GitHub only when the next CI run is green; here it is confirmed with Python 3.12 and a local strace.
- `reports/scenario-validation.json` was rewritten by the runs, restored, not committed.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the reproduction (Python 3.12 venv and a strace binary in a scratch directory, not kept), both fixes, the tests, the plan line, these notes, the study Q&A entry, the commit.
- **Reviewed / changed by Maryam:** she reported the two CI failures and set the rule for defect 2 (produce the confirmation if it is valid, do not weaken REJECTED and the canary assertions). Nothing reviewed yet.
- **Verified by:** the CI log of run 38135800645 (read with `gh`), old code against new tests, the two full-suite runs above. No cavr-reviewer pass.

### Supervisor Q&A prep

1. **Why did the tests pass on your machine and fail in CI?**
   Two differences: Python 3.12 against 3.14 (`Path.is_file()` raises on a permission error only in 3.12), and strace present against absent (a different monitor, with a parser that lost one line).
2. **Is the confirmed flow under strace real, or did you make the test pass?**
   Real: the trace holds the read of `canary.txt`, then the connect to the harness port, and the harness received the exact marker. Without a received marker, with another payload, without the read, or in the wrong order, there is no confirmation (`test_the_connection_alone_is_not_a_confirmed_flow`).
3. **Was a wrong verdict ever given?**
   No. The lab file was REJECTED in both modes. What was missing under strace was one event, its violation and the causal confirmation; what was wrong on 3.12 was a crash instead of UNRESOLVED.

## Step 1 — `.asent/` config schema and loader (2026-11-07)

Plan: `docs/dev-env-plan.md` (generic ASENT gate), step 1.

### Ch 6 Implementation

- `backend/project_config/schema.py` (new): pydantic models `AsentConfig` (`.asent/config.json`, with `CavrModule`, `SatraModule`, `SableModule`), `SatraContract` (`satra/contract.json`), `SableObligations` (`sable/obligations.json`); `export_schemas()` produces the committed JSON Schemas.
- `backend/project_config/loader.py` (new): `load(asent_dir) -> ConfigResult(valid, problems, config, digest, files, documents)`; `tree_digest(asent_dir)`; `ConfigResult.module_state(name)` = enabled / disabled / absent.
- `backend/project_config/__main__.py` (new): `python -m backend.project_config --write docs`.
- `backend/cavr/capability_contract.py`: new public `capability_policy_problem(policy, knowledge=None)`, the same check `infer_capability_contract` makes (it calls the existing `_capabilities`).
- `docs/asent-config.md` (new) and the generated `docs/asent-config.schema.json`, `docs/asent-satra-contract.schema.json`, `docs/asent-sable-obligations.schema.json`.
- Algorithm of `load`: (1) walk `.asent/` without following links; any symlink or non-regular file -> UNSAFE, over 200 files / 1 MiB -> BUDGET (stops before reading further); (2) hash every file, digest = SHA-256 of {path: sha256}; (3) parse `config.json` (UTF-8, duplicate keys refused) and validate strictly; (4) for each enabled module, read and validate its own document (CAVR policy through `requirement_gate.policy_problems` + `capability_policy_problem` + non-blank task description); (5) `valid` only if no problem was recorded.

### Design decisions

- **pydantic models, not jsonschema:** pydantic is already locked, jsonschema is not; the JSON Schema is generated from the models and a test fails on drift, so the document and the check cannot differ.
- **strict mode + `extra="forbid"`:** lax pydantic turns `"403"` into 403 and `"yes"` into true; a config value that is not exactly right must be a problem, not a guess.
- **`schema_version` is a strict int 1, not `Literal[1]`:** `Literal` compares with `==`, so `true` and `1.0` were accepted (found in self-review, see defects).
- **No `mode` field for CAVR:** a real repository must not be able to select the old lockfile analyzer; the demo scenarios choose it by run mode (step 4/5). Alternative (a `mode` field limited to demos) rejected because the config cannot prove it is a demo.
- **Absent module section is valid at load time:** whether a module applies depends on head's files; step 4 turns "applies but absent" into REVIEW. Disabled modules need a reason and their files are not read.
- **Digest over raw bytes, also for an invalid config:** base and head are exported by the same `git archive` on the same machine, so raw bytes are consistent; the digest of an invalid config is still needed to detect a head change. Alternative LF-normalised digest (as `satra/trust.py`) not needed here.
- **Duplicate JSON keys refused:** `{"enabled": true, "enabled": false}` would otherwise silently keep the last value.
- **Task description required non-blank:** `capability_contract` accepts a missing one (no threat rule applies then); for an external project that weakens the contract silently, so the loader refuses it.

### Requirements covered

No `FR-CAVR-NN` identifiers exist in this repository; IDs are from `RequirementsTab.tsx` (Maryam to confirm).

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Missing, unsafe, unreviewed or invalid project config is `valid=False` with a named code | `test_missing_directory`, `test_unreviewed_starter_is_invalid`, `test_invalid_cavr_policy` (7) |
| none listed | Per-project policy for external repositories (dev-env plan) | Documented, versioned `.asent/` schema | `test_committed_schemas_match_the_models` |

### Ch 7 Test cases

All in `tests/test_project_config.py`; result of `.venv/bin/python -m pytest -q tests/test_project_config.py`: 75 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_full_valid_config_loads` | Valid config | all three modules with files | valid, documents parsed, defaults filled | pass |
| `test_disabled_module_with_reason_is_valid_and_its_files_are_not_required` | Disabled module | SABLE off with reason, no obligations file | valid, state "disabled", reason kept | pass |
| `test_absent_module_section_is_valid_at_load_time` | Absent section | no SATRA key | valid, state "absent" | pass |
| `test_defaults_are_filled_in` | Defaults | `{"enabled": true}` only | default policy path, requirements.txt, verify all | pass |
| `test_missing_directory`, `test_asent_is_a_file_not_a_directory`, `test_missing_config_json` | Missing | no folder / a file / no config.json | MISSING, digest None | pass |
| `test_bad_json_or_not_an_object` (6) | Unreadable | `{not json`, empty, null, [], "text", non-UTF-8 | JSON or SCHEMA | pass |
| `test_duplicate_json_keys_are_rejected` | Edge | repeated key | JSON | pass |
| `test_unknown_top_level_key`, `test_unknown_module_name` | Extras | extra key / module NEWMOD | SCHEMA | pass |
| `test_cavr_mode_key_is_rejected_so_a_repository_cannot_pick_the_lockfile_analyzer` | Decision 1 | `"mode": "lockfile"` | SCHEMA naming `mode` | pass |
| `test_wrong_schema_version` (6) | Version | 0, 2, "1", null, true, 1.0 | SCHEMA | pass |
| `test_enabled_must_be_a_boolean` | Strict | `"yes"` | SCHEMA | pass |
| `test_disabled_without_reason` (3) | Decision 3 | no / empty / blank reason | SCHEMA naming `reason` | pass |
| `test_unsafe_or_empty_paths` (9), `test_sable_terraform_dir_escaping_repo` | Path safety | `..`, absolute, `C:\`, backslash, empty, `.git`, empty list | SCHEMA | pass |
| `test_unreviewed_starter_is_invalid`, `test_starter_false_is_accepted` | Starter | `_starter` true / false | STARTER only / valid | pass |
| `test_enabled_module_whose_file_is_missing`, `test_trusted_tests_directory_without_tests`, `test_configured_pytest_ini_missing` | Referenced files | missing policy / no test_*.py / missing ini | FILE_MISSING | pass |
| `test_invalid_cavr_policy` (7), `test_invalid_cavr_policy_json` | CAVR policy | bad lists, extras, unknown/duplicate scope, missing/blank task, bad JSON | POLICY with the field named | pass |
| `test_invalid_satra_contract` (7) | Contract | bad operator, no `::`, `..`, empty lists, `"403"`, extra key | CONTRACT | pass |
| `test_invalid_sable_obligations` (6) | Obligations | empty, no actions, no principal, duplicate id, margin -1, a list | OBLIGATIONS | pass |
| `test_several_problems_are_all_reported` | Reporting | two broken documents | both codes | pass |
| `test_symlinked_file_inside_asent`, `test_symlinked_directory_inside_asent`, `test_asent_itself_is_a_symlink` | Unsafe tree | real symlinks | UNSAFE | pass |
| `test_too_many_files`, `test_too_many_bytes` | Budget | 201 extra files / 1 MiB + 1 | BUDGET | pass |
| `test_digest_is_stable_and_changes_on_a_one_byte_edit`, `test_digest_is_independent_of_location`, `test_digest_is_computed_for_an_invalid_config` | Digest | repeated load, one-byte edit, two locations, starter | stable / changes / same / present | pass |
| `test_capability_policy_problem_matches_contract_rules` | Reused check | valid, string scopes, None | None / message / message | pass |
| `test_committed_schemas_match_the_models`, `test_committed_schema_documents_starter_and_rejects_extras` | Documented schema | docs/*.schema.json | equal to generated; `_starter` listed; no extras | pass |

### Defects found and fixed

- Self-review: `schema_version: Literal[1]` accepted `true` and `1.0` (`True == 1`). Two cases added to `test_wrong_schema_version` (2 failed on the old code), fixed with a strict int `ge=1, le=1`.
- `python -m backend.project_config.schema` printed a runpy RuntimeWarning (module imported by the package first); moved the entry point to `backend/project_config/__main__.py`.
- Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- The loader does not know the project's files: "module applies but has no section" -> step 4; trusted-test content is only listed, it runs in step 6.
- The CAVR policy is checked against the seed threat-repository vocabulary; the pipeline checks it again against the live snapshot at gate time.
- The digest is over raw bytes: a CRLF and an LF checkout of the same `.asent/` have different digests (only affects comparisons across machines, not the gate, which exports base and head the same way).
- No `asent init` yet (step 2); `_starter` is only recognised.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the schema and loader modules, `capability_policy_problem`, the tests, `docs/asent-config.md`, the generated schemas, these notes.
- **Reviewed / changed by Maryam:** the plan decisions this step follows (no CAVR `mode`, disabled modules need a reason); the code itself not yet reviewed.
- **Verified by:** tests written before the code; printed problem messages for 8 sample cases checked by hand; the two `schema_version` cases failed before the fix; full suite `.venv/bin/python -m pytest -q`: 1559 passed, 30 skipped, 0 failed (was 1484 passed; `reports/scenario-validation.json` restored after the run).

### Supervisor Q&A prep

1. **Why is the config read from the base commit and not from the pull request?** The pull request is what is being judged; if it could edit its own policy it could approve itself. This step only loads a folder; step 8 always loads base's, and a head change to `.asent/` gives REVIEW.
2. **What happens with a config you cannot understand?** `valid=False` with a code per problem (`ASENT_CONFIG_*`); the gate turns that into REVIEW, never ACCEPT. Unknown keys and loosely typed values are problems too.
3. **Why can't a project choose the old CAVR analyzer?** There is no field for it (`test_cavr_mode_key_is_rejected_...`); it reads ASENT-specific lock files and is only kept so the built-in demos and their tests stay unchanged.

## Step 2 — `asent init` starter config (2026-11-07)

### Ch 6 Implementation

- `backend/project_config/starter.py` (new): `detect(root)` (root `requirements*.txt`, Python outside `tests/`, directories with `.tf`, skipping dot/venv/build directories and symlinks); `init_project(repository, force=False)` writes `.asent/config.json` (`"_starter": true`), `.asent/cavr/policy.json`, `.asent/README.md`.
- `backend/cli.py`: `main(argv=None)`; new local `init` subcommand (`--repository`, `--force`) handled before the HTTP client is opened; exit 0 on success, 2 when `.asent` exists or is a symlink.
- Algorithm: detect surfaces; CAVR enabled only with requirements files, approved = exact `name==version` pins (extras/markers dropped, name canonicalised), everything else listed as not copied; SATRA and SABLE written disabled with a reason; write files; nothing is overwritten without `--force`, nothing written through a symlink.

### Design decisions

- **SATRA and SABLE disabled in the starter:** a contract or obligation guessed from code would be an invented authority; disabled with a reason, the gate reports them "not assessed (disabled by base config)". Alternative (placeholder contract) rejected: after removing `_starter` it would load as valid while meaning nothing.
- **Only exact pins approved:** a range copied into `approved_requirements` would approve versions nobody looked at.
- **`allowed_scopes: []`:** default deny; the reviewer grants capabilities explicitly.
- **TODO task description:** non-blank so the reviewed starter loads, but visibly a placeholder; the README lists it as review item 1.
- **Symlinked `.asent` refused even with `--force`:** `rmtree` through a link would delete files outside the project.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | An unreviewed starter can only produce REVIEW | `test_empty_project`, `test_python_project_copies_exact_pins_only` (only ASENT_CONFIG_STARTER) |
| none listed | Onboarding of external repositories (dev-env plan) | `asent init` writes a schema-valid starter | `reviewed(...)` is valid in 3 tests |

### Ch 7 Test cases

`tests/test_gate_init.py`: 9 passed (with `tests/test_project_config.py`: 84 passed).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_empty_project` | Empty project | empty dir | STARTER only; all modules disabled with reason; valid after review | pass |
| `test_python_project_copies_exact_pins_only` | Pins | `==` pins with marker/extras, `>=`, `-r`, VCS URL, comment | 3 approved without marker/extras; 3 not copied; SATRA disabled | pass |
| `test_terraform_project` | Terraform | `infra/`, nested module, `.terraform/` | dirs `infra`, `infra/modules/s3` (not `.terraform`); SABLE disabled | pass |
| `test_existing_asent_is_not_overwritten` | Edge | existing `.asent/config.json` | FileExistsError, file unchanged | pass |
| `test_force_replaces_existing_asent` | `--force` | old `.asent/` | old content gone, starter | pass |
| `test_symlinked_asent_is_refused_even_with_force` | Failure | `.asent` -> outside dir | ValueError, outside file kept | pass |
| `test_not_a_directory` | Failure | missing path | ValueError | pass |
| `test_project_name_is_the_directory_name` | Name | `Invoice-Service/` | name kept | pass |
| `test_cli_init_then_refuses_second_time` | CLI | init, init, init --force | 0, 2 ("already exists"), 0 | pass |

### Defects found and fixed

- None found by the tests. Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- Only root-level `requirements*.txt` are detected; `pyproject.toml`, Poetry, uv and npm are not (CAVR reports those UNRESOLVED at gate time, step 5).
- `-r` includes are not followed by `init` (they are listed as not copied); the gate's pip capture follows them.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `starter.py`, the CLI change, the tests, these notes. **Reviewed by Maryam:** not yet. **Verified by:** tests written first; the step 1 loader is the oracle for every starter.

### Supervisor Q&A prep

1. **Can `asent init` make a project pass the gate?** No: its output carries `_starter` and loads as invalid, so the decision is REVIEW until a person edits and accepts it.
2. **Why not generate a SATRA contract from the routes?** The contract is the authority the test is judged against; deriving it from the code under test would make the code its own oracle.

## Step 3 — git ref resolution and exact commit export (2026-11-07)

### Ch 6 Implementation

- `backend/integrations/git_adapter.py` `[owner review: integrations]`: new `resolve_commit(repository, ref)`, `export_commit(repository, sha, dest)`, helpers `_git_env`, `_git_raw`, constants `EXPORT_MAX_FILES`/`EXPORT_MAX_BYTES` (same budget as `orchestrator.hashing.files`); `init_repo` commit message is now "Trusted baseline".
- Algorithm of `export_commit`: `git ls-tree -r -l -z --full-tree <sha>` lists every entry with mode and size; a symlink (120000), submodule (160000), non-UTF-8 or unsafe path, or a tree over budget raises ValueError before anything is read; the blobs are read in one `git cat-file --batch`, each header is checked (sha, type, size), and the bytes are written as they are, with the exec bit from mode 100755.
- `resolve_commit`: the directory must be the top level of a repository (`--show-toplevel`, discovery above it disabled with `GIT_CEILING_DIRECTORIES`); refs that are empty, start with `-` or contain `:` are refused; `rev-parse --verify --end-of-options REF^{commit}`.

### Design decisions

- **`ls-tree` + `cat-file`, not `git archive` (changed from the plan):** `archive` applies the tree's own `.gitattributes`, so a pull request could add `export-ignore` to hide a file from every analyzer, or `export-subst` to rewrite one. Reading blobs gives exactly the committed bytes. `checkout` was also rejected: it runs eol conversion, filters and hooks.
- **Symlinks and submodules refused:** their content is not analysed, so analysing the rest and accepting would be a pass on unseen code; ValueError -> REVIEW.
- **Ref looks like an option -> refused**, plus `--end-of-options`: a ref such as `--output=/tmp/x` must never reach git as an option.
- **Top-level check:** a plain directory inside some other repository must not silently resolve to that outer repository.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Unknown refs, symlinks, submodules, unsafe/over-budget trees are errors, never a partial export | `test_unknown_or_unsafe_ref` (5), `test_symlink_in_commit_is_refused`, `test_submodule_is_refused`, `test_budget_is_checked_before_reading` |
| none listed | Evidence binding to real commits (dev-env plan) | The analysed files are the committed bytes | `test_export_is_byte_exact_and_keeps_the_exec_bit`, `test_repository_attributes_cannot_hide_or_rewrite_files` |

### Ch 7 Test cases

`tests/test_gate_git_export.py`: 18 passed. `tests/test_integration.py` + `tests/test_shared.py` (use `init_repo`): 57 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_resolve_branch_tag_and_sha` | Refs | branch, tag, short sha, `HEAD~1` | full SHAs | pass |
| `test_unknown_or_unsafe_ref` (5) | Failure | unknown, empty, `--output=…`, `HEAD:a.txt`, 40 zeros | ValueError | pass |
| `test_not_a_repository` | Failure | plain dir, missing dir | ValueError | pass |
| `test_export_is_byte_exact_and_keeps_the_exec_bit` | Exactness | CRLF text, 256-byte binary, empty file, `.asent/`, exec script | identical bytes, exec bit only on the script | pass |
| `test_export_of_an_older_commit_ignores_the_worktree` | Exactness | old sha, newer commit, uncommitted file | only the old file | pass |
| `test_repository_attributes_cannot_hide_or_rewrite_files` | Attack | `export-ignore`, `export-subst`, `eol=crlf` | files present and unchanged | pass |
| `test_hooks_are_not_run` | Attack | four hooks writing a marker | no marker | pass |
| `test_symlink_in_commit_is_refused`, `test_submodule_is_refused` | Unsupported | committed symlink / submodule | ValueError | pass |
| `test_budget_is_checked_before_reading` | Budget | limits lowered to 9 bytes / 1 file | ValueError "budget" | pass |
| `test_destination_must_be_new` | Edge | non-empty destination | ValueError | pass |
| `test_base_equal_to_head`, `test_empty_tree` | Edge | same sha twice / empty commit | equal trees / empty dir | pass |
| `test_baseline_commit_message_is_generic` | Inventory fix | `init_repo` | "Trusted baseline" | pass |

### Defects found and fixed

- Design defect in the plan (export through `git archive`) found while writing the attribute test; replaced before implementation. Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- Git LFS files are exported as pointer files (no filters run); submodules make the gate REVIEW.
- A bare repository is not supported (`--repository` must be a work tree).
- In a container where the repository belongs to another user, git's `safe.directory` check may refuse it; the runner-native workflow (step 10) does not hit this.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the two functions, the tests, these notes. **Reviewed by Maryam / integrations owner:** not yet. **Verified by:** tests on real repositories written before the code.

### Supervisor Q&A prep

1. **Why not just `git archive`?** It obeys the repository's `.gitattributes`; `export-ignore` would let the change under review hide a file from ASENT. We read the blobs directly, so ASENT sees exactly what was committed.
2. **Could gating a malicious repository run its code on the host?** Not in this step: no checkout, no hooks (`core.hooksPath=/dev/null`, no global config), and git only reads objects.

## Step 4 — orchestrator takes its authority from a frozen base `.asent/` (2026-11-07)

### Ch 6 Implementation

- `backend/project_config/frozen.py` (new): `freeze(source, home, required)` copies the source's `.asent/` to `<run>/asent/` after `load` found it safe (or writes `<run>/asent.status.json` with the problems); `frozen_config(baseline)` finds it again from `<run>/baseline`; `policy_from_config` maps a valid config onto the policy keys the analyzers read (`dependencies`, `ownership`, `infrastructure`); `NOT_ASSESSED = "not assessed (disabled by base config)"`.
- `backend/orchestrator/context_service.py` `[owner review: orchestrator]`: config from `frozen_config`; policy from config, `policy.json` only when a plain server run has no `.asent/`; `@config` in `inputs()`; `surfaces()`, `applicability()` = surfaces ∩ enabled (nothing for an invalid config), `coverage()`, `config_reasons()`; import aliases and source dirs from config; the hardcoded `invoice-pdf-*` alias map is replaced by a generic rule (a LOCAL `.py` artifact is imported by its own path).
- `backend/orchestrator/final_gate.py`: `decide(..., extra_reasons=())`; extra reasons lower ACCEPT to REVIEW and are listed after the blocking ones under BLOCK.
- `backend/orchestrator/workspace_manager.py`: `create(run, source, candidate_source=None, require_config=False)`; no `DEMO` fallback (source required); head files replace the candidate's for gate runs; the base config is frozen.
- `backend/orchestrator/service.py`: scenario runs start from `scenarios.scenario_project(item)`; new `create_gate_run(base, head, gate)`; `analyze` records `coverage`, passes config reasons and "ASENT configuration changed in this change; requires maintainer review" to `decide`, and never repairs a gate run; report has `config` and `coverage`; evidence folder created with `parents=True`.
- `backend/orchestrator/run_context.py`: `mode` adds `gate`; fields `config_digest`, `config_source`, `config_problems`, `config_changed_in_head`, `coverage`, `gate`; generic default title.
- `backend/orchestrator/scenarios.py`: `scenario_project(item)` (demo layer).
- `backend/integrations/git_adapter.py`: `init_repo` commits with `--allow-empty`.
- `demo_project/InvoiceHub/.asent/` (new): config, CAVR policy (M1 format + legacy `dependencies`), SATRA contract, trusted tests (byte copies), SABLE obligations, README.

### Design decisions

- **Config found from the run directory, not passed in:** existing tests rebuild `ContextService(candidate, baseline, knowledge)` and compare input hashes with the run's; finding the frozen copy beside the baseline gives every context of a run the same config without changing any caller.
- **Frozen copy, verified:** the copy is re-loaded and its digest compared with the checked source; a mismatch (source changed during the copy) is UNSAFE. Alternative (read the source each time) rejected: the authority could change during an analysis.
- **Legacy `policy.json` only for plain server runs without `.asent/`:** keeps the dashboard working for existing local repositories; gate runs always freeze (missing -> `ASENT_CONFIG_MISSING`), so they never read the candidate's policy.
- **Invalid config runs no analyzer:** nothing is decided on an authority that cannot be read; REVIEW with every problem as a reason.
- **Absent section with inputs present -> REVIEW, disabled -> not assessed:** as decided by Maryam (decision 3 revised).
- **Generic LOCAL import rule instead of the alias map:** the lock already says where a LOCAL source lives, so its import name follows from the file; registry packages use `cavr.import_aliases`.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Invalid, missing (gate) or unconfigured-but-applicable config gives REVIEW; a head config change cannot raise the decision | `test_invalid_config_in_a_server_run_is_review_without_analysis`, `test_disabled_modules_are_never_passed_and_absent_module_gives_review`, `test_gate_run_flags_a_head_config_change`, `test_gate_run_without_base_config_never_falls_back_to_policy_json` |
| none listed | Evidence bound to the authority (dev-env plan) | A config edit invalidates evidence of every module | `test_config_edit_changes_every_module_input_hash` |

### Ch 7 Test cases

`tests/test_orchestrator_config.py`: 19 passed. `tests/test_gate_git_export.py`: 19 passed (one added). Full suite: 1606 passed, 30 skipped, 0 failed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_demo_fixture_config_is_valid_and_mirrors_its_legacy_policy` | Demo on `.asent/` | fixture `.asent/` | valid; mapped keys equal `policy.json` | pass |
| `test_demo_fixture_trusted_tests_are_the_bundled_satra_tests` | No drift | 3 copies | byte-equal | pass |
| `test_demo_scenario_run_freezes_the_fixture_config` | Freezing | `create("safe")` | run digest = fixture digest; no `.asent` in candidate; all assessed | pass |
| `test_config_edit_changes_every_module_input_hash` | Binding | edit frozen README | 3 input hashes change | pass |
| `test_project_without_asent_keeps_the_legacy_policy_in_server_runs` | Compatibility | project with only `policy.json` | config None, legacy policy, no `@config` | pass |
| `test_workspace_manager_requires_a_source` | No DEMO fallback | source None | ValueError | pass |
| `test_extra_reasons_turn_accept_into_review`, `test_block_beats_a_config_review`, `test_no_applicable_module_with_extra_reasons_is_review` | Final gate | VERIFIED / REJECTED / nothing + extra reason | REVIEW / BLOCK / REVIEW | pass |
| `test_disabled_and_absent_modules_in_coverage` | Coverage | CAVR on, SABLE off with `.tf`, SATRA absent with `.py` | applicable [CAVR]; SABLE `NOT_ASSESSED` + reason; SATRA reason | pass |
| `test_disabled_modules_are_never_passed_and_absent_module_gives_review` | Decision 3 | same project, analysed | REVIEW; no SABLE/SATRA evidence; report coverage label | pass |
| `test_every_module_disabled_is_review` | Edge | all disabled | REVIEW, applicable [] | pass |
| `test_invalid_config_in_a_server_run_is_review_without_analysis` | Failure | `{broken` | REVIEW, reason `ASENT config: ASENT_CONFIG_JSON…`, no evidence | pass |
| `test_enabled_module_with_invalid_file_is_review` | Failure | SABLE on, empty obligations | REVIEW with `ASENT_CONFIG_OBLIGATIONS` | pass |
| `test_symlinked_asent_in_source_is_not_copied_and_is_review` | Attack | `.asent` symlink | UNSAFE, nothing copied | pass |
| `test_gate_run_uses_base_config_and_head_files` | Gate run | base/head exports | candidate = head, baseline = base, base reason | pass |
| `test_gate_run_flags_a_head_config_change` | Gate run | head edits `.asent/` | REVIEW with the change reason; base still wins | pass |
| `test_gate_run_without_base_config_never_falls_back_to_policy_json` | Gate run | base with `policy.json` only | MISSING, policy {}, REVIEW, no evidence | pass |
| `test_gate_run_is_never_repaired` | Gate run | `auto_repair=True` | no `repair.*` events | pass |
| `test_baseline_of_an_empty_tree_can_be_committed` | Edge | empty baseline | commit created | pass |

### Defects found and fixed

- Pre-existing: a run where no module applied ended as ERROR ("Run could not complete") because `evidence/` did not exist when `assurance.json` was written; now created with `parents=True` (found by `test_invalid_config_in_a_server_run_is_review_without_analysis`).
- `init_repo` failed for a base whose only content is `.asent/` (nothing to commit); now `--allow-empty` (found by `test_gate_run_flags_a_head_config_change`).
- Removing the hardcoded alias map broke `tests/test_cavr_targeted.py::test_safe_adapter_import_attribution_and_unrelated_import` (context without config); fixed with the generic LOCAL-artifact rule, test unchanged.
- Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- SRS.md and plan.md are still read from the candidate; SATRA's contract moves to `.asent/` in step 6.
- The replay baseline (`scenarios/replay/weak-oracle/baseline`) has no `.asent/` yet: it is a recorded replay whose snapshot digest is pinned; it keeps the legacy `policy.json` path.
- `main.py` still reads the demo project for `/api/project` and the showcase mount (demo layer only).
- Analyzers still read the legacy policy shape; SABLE uses only the first obligation until step 7.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** all code, the demo `.asent/`, the tests, these notes. **Reviewed by Maryam / orchestrator owner:** not yet. **Verified by:** tests written first; full suite run twice (first run found the alias regression).

### Supervisor Q&A prep

1. **Can a pull request disable a module to get ACCEPT?** No: the authority is the base `.asent/`, frozen when the run is created; a head change to `.asent/` adds a reason that keeps the decision at REVIEW.
2. **Why is a disabled module not a failure?** The project owner said, in reviewed base config with a reason, that it does not apply; the report says "not assessed (disabled by base config)" so nobody reads it as passed.
3. **Did moving the demos to `.asent/` change any demo outcome?** No: the mapped policy equals the old `policy.json` keys (tested) and all 1606 tests pass, including every scenario expectation.

## Step 5 — CAVR in gate runs: the M1 pipeline (2026-11-07)

### Ch 6 Implementation

- `backend/cavr/gate_adapter.py` (new): `analyze_pipeline(context, store, outdir, emit)` -> (status, details, uncertainty), the return shape of `analyzer.analyze`; `map_status`; `SETTINGS` (transport/OSV injection for tests; None = live PyPI and live OSV); `UNSUPPORTED_MANIFESTS`.
- `backend/cavr/analyzer.py`: `analyze` dispatches to the adapter when `context.gate` (every gate run); demo scenario runs keep the lockfile analyzer.
- Algorithm: (1) take CAVR section + policy from the base config, else UNRESOLVED; (2) configured requirements files missing in head, or another dependency manifest (pyproject dependencies, Poetry, Pipenv, setup.py/cfg, npm) -> problem; no file to verify -> UNRESOLVED; (3) per file, `verify_request(["pip","install","-r",file])` (`verify: all`) or the base->head `requirements_edit` (`changed`), with the candidate directory, the base policy, a run-local `CavrStorage`, quarantine and advisory cache; (4) map: VERIFIED -> VERIFIED, REJECTED/BLOCK -> REJECTED, anything else -> UNRESOLVED; module = worst; a manifest problem keeps it from VERIFIED; (5) details keep the pipeline's own status, stage, rule, reason and every package's 8 cache-key fields.

### Design decisions

- **Dispatch by run mode, not by config:** decided by Maryam: a real repository cannot select the lockfile analyzer, and the demo tests keep it.
- **BLOCK maps to REJECTED:** the requirement gate refusing a package is a block, not a review; the original BLOCK is kept in `details.pipeline`.
- **Unknown status -> UNRESOLVED:** a future pipeline status must never pass by default.
- **Other manifests -> UNRESOLVED:** if a repository also declares dependencies in a format the pipeline does not read, verifying only requirements.txt would accept unseen packages. `pyproject.toml` with only tool settings is accepted.
- **Run-local verdict cache:** under the run store's directory, so gate runs never write the dashboard database; the 8-field key is unchanged, so the cache is reusable when the data directory is kept (`--data-dir`, step 8).
- **Dropped from the plan:** `read_artifact(allow_builtin)` and `counterfactual_input`. The lockfile analyzer and its `ROOT` fallback are now reachable only from demo runs. Plan doc updated.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Unknown status, network off, unsupported manifest, missing file -> UNRESOLVED | `test_status_mapping` (6), `test_network_off_is_unresolved`, `test_only_pyproject_dependencies_is_unsupported` |
| none listed | C3 on real artifacts in gate runs (CAVR M1) | Real wheel hash vs registry digest, advisories, 8-field key in gate evidence | `test_approved_pin_is_verified_with_the_eight_field_key`, `test_tampered_wheel_is_not_verified` |
| none listed | C2 requirement gate in gate runs | Denied and unpinned packages blocked before download | `test_denied_package_is_rejected_without_a_download`, `test_unpinned_requirement_is_blocked_by_the_requirement_gate` |

### Ch 7 Test cases

`tests/test_cavr_gate_adapter.py`: 26 passed. With `tests/test_cavr_pipeline.py`, `tests/test_modules.py`, `tests/test_cavr_targeted.py`: 165 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_approved_pin_is_verified_with_the_eight_field_key` | VERIFIED | real pypdf 6.19.0 wheel, recorded registry + "no advisories" | VERIFIED, sha256 `7e5d6e73…`, 8 key fields | pass |
| `test_denied_package_is_rejected_without_a_download` | BLOCK | `reqeusts==2.31.0` in head | REJECTED (pipeline BLOCK, stage gate), 0 downloads | pass |
| `test_affected_version_is_rejected_by_the_advisory_range` | REJECTED | SYNTH-PYPDF-1 affecting [6.0.0, 6.20.0) | REJECTED at stage advisories | pass |
| `test_unpinned_requirement_is_blocked_by_the_requirement_gate` | Unpinned | `pypdf>=6` | REJECTED (BLOCK gate NOT_PINNED), 0 downloads | pass |
| `test_tampered_wheel_is_not_verified` | Tamper | one bit flipped in the served wheel | REJECTED artifact HASH_MISMATCH | pass |
| `test_network_off_is_unresolved` | Network | every request fails | UNRESOLVED | pass |
| `test_only_pyproject_dependencies_is_unsupported` | Unsupported | pyproject `dependencies`, no requirements.txt | UNRESOLVED "unsupported manifest", 0 requests | pass |
| `test_other_unverified_manifests_next_to_requirements_are_unresolved` (4) | Unsupported | setup.py, poetry.lock, package.json, Pipfile | UNRESOLVED naming the file | pass |
| `test_pyproject_for_tool_settings_only_is_fine` | Edge | `[tool.black]` only | VERIFIED | pass |
| `test_configured_requirements_file_missing_in_head` | Failure | file deleted in head | UNRESOLVED | pass |
| `test_changed_mode_without_an_edit_is_verified_at_the_gate_stage`, `test_changed_mode_with_a_denied_addition_is_rejected` | `verify: changed` | no edit / denied addition | VERIFIED (gate, 0 requests) / REJECTED | pass |
| `test_status_mapping` (6), `test_unknown_pipeline_status_through_the_adapter` | Mapping | 6 statuses / unknown status | as specified / UNRESOLVED | pass |
| `test_pipeline_gets_the_candidate_directory_never_the_sample_project` | No sample fallback | spy on `verify_request` | project dir = candidate | pass |
| `test_disabled_cavr_config_is_unresolved` | Defensive | CAVR disabled | UNRESOLVED | pass |
| `test_gate_context_dispatches_to_the_pipeline_and_demo_context_does_not` | Dispatch | gate context / `safe` demo context | pipeline / lockfile analyzer | pass |
| `test_gate_run_through_the_service_publishes_pipeline_evidence` | Orchestrator | full gate run | CAVR VERIFIED (engine pipeline), ACCEPT, SATRA "disabled" | pass |

### Defects found and fixed

- None in the code. Two tests first allowed either REJECTED or UNRESOLVED; after printing the real outcomes (unpinned: BLOCK gate NOT_PINNED; tampered: REJECTED artifact HASH_MISMATCH) they assert those exact values. Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- REJECTED by advisory uses a hand-written SYNTH- advisory: no recorded advisory affects pypdf 6.19.0, and no affected wheel is in the repository. The OSV range check itself is the real code.
- Only pip requirements files; deep runtime analysis is M2; the step-14 decision (orchestrator demo path) is still open.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the adapter, the dispatch, the tests, these notes, the plan correction. **Reviewed by Maryam:** the mapping and the demo-only lockfile analyzer were her instruction; code not yet reviewed. **Verified by:** tests written first, real outcomes printed.

### Supervisor Q&A prep

1. **What does CAVR check on a real pull request?** Every pin in the configured requirements files: refused or unpinned packages are blocked before download; the wheel's SHA-256 is compared with PyPI's digest; the dependency tree comes from Requires-Dist; OSV ranges; the capability contract from the project's call sites; AST sink scan; all under the 8-field cache key.
2. **Why is a project with a pyproject.toml sometimes UNRESOLVED?** When it declares dependencies there; CAVR M1 only reads requirements files, and passing the others unseen would be a false VERIFIED.

## Step 6 — SATRA in gate runs from the base config (2026-11-07)

### Ch 6 Implementation

- `backend/satra/gate_mode.py` (new) `[owner review: satra]`: `analyze_configured(context, outdir, emit)`, the return shape of `satra.analyzer.analyze`.
- `backend/satra/analyzer.py`: `analyze` dispatches to it when `context.gate`; demo runs keep the InvoiceHub path unchanged.
- `backend/satra/pytest_runner.py`: `run_pytest(..., trusted_tests_dir, external, targets, pytest_ini)`; `external=True` never runs on the host, even for hash-known files; trusted tests copied to `asent_assurance/`; `-c` only when an ini exists. Legacy calls build exactly the old command.
- `backend/satra/counterfactuals.py`: `mutate_return_true(root, "file::function")` (top-level functions and methods; False and file unchanged when missing / unparsable).
- `backend/satra/static_adapters.py`: `scan(root, dirs=None)`; `None` keeps `app/`.
- Algorithm: contract rule must be an enabled threat-repository rule -> trusted tests on base and head (container, no network) -> project `tests/` on head if present -> RETURN_TRUE mutant of the base must be killed by the trusted tests -> optional oracle check of `project_security_tests` with `judge` -> decision table in the module docstring.

### Design decisions

- **Gate runs only (demo path unchanged):** `tests/test_modules.py::test_satra_scc_and_inconclusive` expects the demo contract to vanish when the candidate SRS loses its security wording. In a gate run that behaviour is the weakness: the candidate's SRS must not switch SATRA off (`test_candidate_srs_cannot_switch_satra_off_in_a_gate_run`). Same split as CAVR (decision 1).
- **Required knowledge = the contract's rule:** the four InvoiceHub templates are not the project's tests; requiring the contract `rule_id` to be enabled keeps "disabling knowledge cannot waive a test".
- **Mutant not killed -> INCONCLUSIVE, not ACCEPT:** trusted tests that pass on the RETURN_TRUE mutant prove nothing about the contract.
- **Oracle check optional, but reported:** many projects have no single security test file; when none is configured, the uncertainty list says so.
- **Preflight unchanged:** project security tests may import only `pytest` (fixtures come from `conftest.py`), the rule the demo already uses for tests under review.
- **No Ollama in gate runs:** CI has no local model; adaptive generation is reported as not used.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | No engine, missing target, blind trusted tests, disabled rule -> INCONCLUSIVE | `test_without_a_container_engine_it_is_inconclusive`, `test_missing_counterfactual_target_is_inconclusive`, `test_trusted_tests_that_miss_the_mutant_are_inconclusive`, `test_disabled_contract_rule_is_inconclusive` |
| none listed | SATRA independent oracle on external projects (dev-env plan) | Trusted tests from base; regression and weak oracle rejected | `test_regressed_head_is_rejected`, `test_weak_project_security_test_is_rejected`, `test_trusted_tests_come_from_base_even_when_head_edits_them` |

### Ch 7 Test cases

`tests/test_satra_config.py`: 16 passed. `tests/test_satra_*.py`, `tests/test_modules.py`, `tests/test_integration.py`, `tests/test_hash_verification_line_endings.py`, `tests/test_api_replay.py`: 179 passed, 4 skipped (Docker not available).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_secure_change_is_accepted_and_the_mutant_is_killed` | ACCEPT | secure base and head | ACCEPT, mutant failed ≥1 test, oracle "not checked" listed | pass |
| `test_regressed_head_is_rejected` | REJECT | head `return True` | REJECT APPLICATION_REGRESSION | pass |
| `test_weak_project_security_test_is_rejected`, `test_strong_project_security_test_is_accepted` | Oracle | weak / strong project test | REJECT / ACCEPT | pass |
| `test_failing_ordinary_project_tests_are_rejected` | Project tests | `assert False` in tests/ | REJECT | pass |
| `test_without_a_container_engine_it_is_inconclusive` | No engine | no Docker, `permitted_builtin` forced True | INCONCLUSIVE "Docker/Podman" | pass |
| `test_missing_counterfactual_target_is_inconclusive` | Failure | target `not_there` | INCONCLUSIVE | pass |
| `test_trusted_tests_that_miss_the_mutant_are_inconclusive` | Blind tests | only an "allowed" test | INCONCLUSIVE "do not detect" | pass |
| `test_disabled_contract_rule_is_inconclusive` | Knowledge | AUTHZ.IDOR.001 disabled | INCONCLUSIVE, missing_rules | pass |
| `test_trusted_tests_come_from_base_even_when_head_edits_them` | Attack | head replaces trusted test with `assert True` and breaks code | REJECT | pass |
| `test_candidate_srs_cannot_switch_satra_off_in_a_gate_run` | Attack | SRS without security words | REJECT (not INCONCLUSIVE) | pass |
| `test_external_code_never_runs_on_the_host` | Isolation | `external=True`, no engine | unavailable | pass |
| `test_mutate_top_level_function_and_method`, `test_mutate_fails_closed` (3) | Operator | function + method / missing file, function, syntax error | both return True / False, file unchanged | pass |

Container path: Docker is not installed here; `container_on_host` runs the exact command built for the container on the host with `/work` mapped (asserts `--network none` is in it). A real container run is part of step 10.

### Defects found and fixed

- A test removed the protected function to make the target missing, which also broke the trusted tests' import; rewritten to point the contract at a missing function. Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- One operator (RETURN_TRUE); contract semantics such as `route`/`expected_status` are recorded, not executed: the trusted tests carry them.
- Real container execution is not verified on this machine (step 10 CI run).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** all of the above. **Reviewed by Maryam / SATRA owner:** not yet. **Verified by:** tests written first; existing SATRA suites green.

### Supervisor Q&A prep

1. **What does SATRA need from a project?** A contract (`.asent/satra/contract.json`), trusted tests that encode it, and a function whose `return True` mutant those tests must catch. None of these is inferred.
2. **Why INCONCLUSIVE when the mutant survives?** Then the trusted tests would also pass broken code; their pass on the candidate means nothing.

## Step 7 — SABLE in gate runs: every obligation of the base config (2026-11-07)

### Ch 6 Implementation

- `backend/sable/analyzer.py` `[owner review: sable]`: the single-obligation body moved unchanged into `_evaluate(context, emit, knowledge, cfg, baseline_dir, candidate_dir)`; `analyze` keeps the demo path (`policy.infrastructure`, `infra/`) and dispatches gate runs to new `analyze_configured`.
- `analyze_configured`: required SABLE knowledge; base config section + obligations; any `.tf`/`.tf.json` in base or head outside `terraform_dirs` -> UNKNOWN; each obligation evaluated in its root (`terraform_dir`, default the first root); module = REGRESSED if any, else UNKNOWN if any not PRESERVED, else PRESERVED; `details.obligations` lists id, root, status, reason and the full per-obligation details.
- `backend/project_config/schema.py` / `loader.py`: optional `Obligation.terraform_dir`; the loader refuses one that is not in `terraform_dirs` (ASENT_CONFIG_OBLIGATIONS). Schemas regenerated; `docs/asent-config.md` updated.

### Design decisions

- **Each terraform_dir is a root module:** `hcl_parser.parse` takes one root and expands only local `./` modules, so obligations name their root instead of merging graphs.
- **Unconfigured Terraform -> UNKNOWN:** infrastructure the gate never parsed must not pass.
- **Worst obligation wins:** one regressed boundary is a regression whatever the others say.
- **Gate runs only:** demo scenario outputs (and their tests) stay byte-for-byte the same path.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Unparsed Terraform, unknown asset, obligation not holding on base -> UNKNOWN | `test_terraform_outside_the_configured_dirs_is_unknown`, `test_one_unknown_obligation_makes_the_module_unknown`, `test_obligation_that_does_not_hold_on_the_base_is_unknown` |
| none listed | SABLE on external Terraform (dev-env plan) | Several obligations and roots | `test_two_obligations_one_regressed`, `test_obligation_in_a_second_terraform_root` |

### Ch 7 Test cases

`tests/test_sable_config.py`: 14 passed; with `tests/test_sable_*.py`, `tests/test_project_config.py`, `tests/test_integration.py`: 130 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_single_obligation_matches_the_catalog_scenarios` (5) | Same verdicts as catalog | scenarios/sable/{preserved, regressed, widened, unknown, unresolved_role_binding} | PRESERVED, REGRESSED, REGRESSED, UNKNOWN, UNKNOWN | pass |
| `test_unchanged_infrastructure_is_preserved` | Edge | head = base | PRESERVED | pass |
| `test_two_obligations_one_regressed` | Aggregation | infra/ regressed, platform/ unchanged | REGRESSED; {invoice-data: REGRESSED, platform-data: PRESERVED} | pass |
| `test_obligation_that_does_not_hold_on_the_base_is_unknown` | Baseline authority | read-only obligation, base grants Get+Put | UNKNOWN | pass |
| `test_one_unknown_obligation_makes_the_module_unknown` | Aggregation | second obligation on a missing bucket | UNKNOWN; {PRESERVED, UNKNOWN} | pass |
| `test_terraform_outside_the_configured_dirs_is_unknown` | Coverage | `deploy/extra.tf` | UNKNOWN naming the file | pass |
| `test_obligation_in_a_second_terraform_root` | Roots | `terraform_dir: platform` | PRESERVED, roots recorded | pass |
| `test_obligation_naming_an_unconfigured_root_is_invalid_config` | Config | `terraform_dir: elsewhere` | ASENT_CONFIG_OBLIGATIONS | pass |
| `test_gate_run_decision_for_a_regression` | Orchestrator | regressed head | BLOCK, "SABLE: REGRESSED" | pass |
| `test_demo_context_keeps_the_single_obligation_path` | Compatibility | `sable_preserved` demo | old path, PRESERVED | pass |

### Defects found and fixed

- First draft of `test_two_obligations_one_regressed` accepted either outcome; probing showed a read-only obligation is UNKNOWN on the demo base (the base grants Get+Put), so the test now uses two roots and asserts exact statuses, and the base-authority case is its own test. Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- Same model as before: inline IAM role policies and S3 objects, local modules only, no plan expansion, no deployed state.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** all of the above. **Reviewed by Maryam / SABLE owner:** not yet. **Verified by:** tests written first; existing SABLE suites green.

### Supervisor Q&A prep

1. **What must a project give SABLE?** `obligations.json`: which principal may perform which actions on which asset, in which Terraform root; SABLE checks the base satisfies it and the head still does.
2. **What if the PR adds Terraform in a new folder?** It is outside `terraform_dirs`, so SABLE is UNKNOWN and the gate REVIEW until the base config covers it.

## Step 8 — `asent gate` command (2026-11-07)

### Ch 6 Implementation

- `backend/gate/runner.py` (new): `run_gate(repository, base, head, output_dir, data_dir=None, keep_workdir=False) -> (exit_code, report)`; `EXIT_CODES`.
- `backend/gate/summary.py` (new): `module_rows(run, evidence)` (result per module: pass / block / review / "not assessed (disabled by base config)" / not applicable), `render_summary(report)`, `NEEDS` (project input per module).
- `backend/cli.py`: `gate` subcommand (`--repository --base --head --output-dir --data-dir --keep-workdir`), local, no HTTP.
- `tests/gate_support.py` (new, no tests): real git repos (`GateRepo`), recorded PyPI/OSV injection.
- Algorithm: resolve both refs -> export both commits -> `create_gate_run` -> `analyze` (synchronous, no repair) -> report `asent.gate.v1` (refs + SHAs, decision, exit code, reasons, module rows, config digest/problems/changed_in_head, coverage, tool availability, full `asent.assurance.v1`) and summary; exit 0/1/2; any exception -> REVIEW with the reason; output not writable -> exit 2.

### Design decisions

- **Errors still produce a report:** CI needs to show why a change was refused; only an unwritable output directory gives no report (exit 2, message on stderr).
- **`pass` only from current acceptable evidence of an assessed module:** a disabled module's row says "not assessed (disabled by base config)" with its reason, and an ACCEPT with such modules adds "Accepted for the assessed modules only".
- **Temporary work directory by default:** nothing of the target repository stays on the runner; `--data-dir` keeps `runtime/` so the CAVR verdict cache can be reused across runs.
- **No server:** the same `Service` the dashboard uses, called in-process.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| FR-6 | Fail-Closed Security Policy | Every failure is REVIEW / exit 2 with a report | 12 fail-closed tests in `tests/test_gate_cli.py` |
| none listed | CI gate for external repositories (dev-env plan) | `asent gate` exit codes and outputs | `test_sable_preserved_is_accept`, `test_sable_regression_is_block`, `test_report_identifies_the_exact_commits_and_config` |

### Ch 7 Test cases

`tests/test_gate_cli.py`: 20 passed. With init, export and orchestrator config tests the first run was 66 passed, **1 failed** (`test_demo_fixture_config_is_valid_and_mirrors_its_legacy_policy`, a step-7 regression, see defects); the step 8 commit was made before that result was read. After the fix (separate commit): 67 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_no_asent_at_base` | Missing config | no `.asent/` | 2, ASENT_CONFIG_MISSING, summary "REVIEW" | pass |
| `test_invalid_config`, `test_unreviewed_starter` | Invalid / starter | `{broken` / `asent init` output | 2 | pass |
| `test_head_edits_asent` | Config change | head edits `.asent/README.md` | 2, changed_in_head | pass |
| `test_unknown_ref_still_writes_a_report`, `test_not_a_repository` | Git errors | bad ref / plain dir | 2 with report | pass |
| `test_tf_present_without_sable_section` | Decision 3 | `.tf` and no SABLE section | 2, SABLE row "review" | pass |
| `test_sable_enabled_with_invalid_obligations` | Invalid file | empty obligations | 2 | pass |
| `test_satra_enabled_without_a_container_engine` | No engine | SATRA configured, no Docker | 2, SATRA INCONCLUSIVE | pass |
| `test_symlink_in_head`, `test_internal_error_is_review_with_a_report`, `test_unwritable_output_directory` | Failures | symlink / injected RuntimeError / output is a file | 2 | pass |
| `test_sable_preserved_is_accept`, `test_sable_regression_is_block` | Decisions | unchanged / regressed infra | 0 / 1 | pass |
| `test_denied_package_added_in_head_is_block` | CAVR block | `reqeusts` added | 1 | pass |
| `test_cavr_only_accept_with_disabled_modules_never_shown_as_passed` | Decision 3 | CAVR on, SATRA/SABLE off with `.py`/`.tf` present | 0; rows "not assessed (disabled by base config)" + reason, never "pass" | pass |
| `test_report_identifies_the_exact_commits_and_config` | Report | tags `base`, `head` | SHAs = `git rev-parse`; 3 rows | pass |
| `test_hooks_in_the_target_repository_are_not_run` | Isolation | 4 hooks | no marker | pass |
| `test_work_directory_is_removed_unless_kept`, `test_run_gate_api_returns_the_same_report` | Housekeeping | default / `--data-dir` | temp dir empty / runtime kept | pass |

### Defects found and fixed

- Step-7 regression found here: the new optional `Obligation.terraform_dir` (value None) was copied into the legacy `infrastructure` policy, so the demo policy no longer equalled `policy.json` (`test_demo_fixture_config_is_valid_and_mirrors_its_legacy_policy` failed; step 7 had not run that file). Fixed in `frozen.policy_from_config` (legacy keys only), separate `fix(orchestrator)` commit.
- Process defect: the step 8 commit was chained after `tail` and went in although that run had 1 failure; from now on the commit runs only after the test result has been read.
- Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass (read one generated summary), 0 MINOR open.

### Known limitations / deferred

- No PR comment posting; the workflow (step 10) uses the job summary and an artifact.
- Evidence file paths inside `assurance` point into the deleted work directory unless `--data-dir`/`--keep-workdir` is used.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** runner, summary, CLI command, helpers, tests, notes. **Reviewed by Maryam:** not yet. **Verified by:** tests on real git repositories, written first.

### Supervisor Q&A prep

1. **What does a CI job get from ASENT?** An exit code (0/1/2), `asent-report.json` with the exact commit SHAs, config digest and all evidence, and a Markdown summary with one row per module.
2. **Can ACCEPT hide a module that was not checked?** No: the row says "not assessed (disabled by base config)" with the reason from base config, and the summary says the acceptance covers the assessed modules only.

## Step 9 — each CAVR verdict through `asent gate` (2026-11-07)

### Ch 6 Implementation

- `tests/test_gate_cavr_verdicts.py` (new): one end-to-end test per pipeline verdict through `cli.main(["gate", ...])` on real git repositories; plus `test_live_pypi_and_osv` behind `CAVR_LIVE=1`. No production code changed: steps 5 and 8 already carry the pipeline's status, stage, rule and the 8 cache-key fields into `asent-report.json` (`assurance.evidence[CAVR].details.pipeline`) and the CAVR summary row.

### Design decisions

- **Through the CLI, not the adapter:** the mapping is checked where CI sees it: decision, exit code, report fields and the summary row.
- **REJECTED via a SYNTH- advisory:** no recorded advisory affects pypdf 6.19.0 in the repository data; the range check that rejects it is the real OSV code. The live variant checks the same path against live services.
- **Live test asserts consistency, not a fixed verdict:** live advisories change over time; the exit code must follow whatever CAVR found.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| none listed | CAVR verdict mapping in the gate (Maryam's change 1) | VERIFIED 0, REJECTED 1, BLOCK 1, UNRESOLVED 2 | the four tests below |
| FR-6 | Fail-Closed Security Policy | Network off is REVIEW, never ACCEPT | `test_unresolved_is_review_exit_2` |

### Ch 7 Test cases

`tests/test_gate_cavr_verdicts.py`: 4 passed, 1 skipped (live). With `CAVR_LIVE=1` (run once on 2026-11-07): live test passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_verified_is_accept_exit_0` | VERIFIED | `pypdf==6.19.0`, recorded registry + recorded "no advisories" | exit 0, ACCEPT, row "pass VERIFIED", 8 key fields, sha256 `7e5d6e73…` | pass |
| `test_rejected_is_block_exit_1` | REJECTED | SYNTH-PYPDF-GATE affecting [6.0.0, 6.20.0) | exit 1, BLOCK, stage advisories | pass |
| `test_block_is_block_exit_1_without_a_download` | BLOCK | `reqeusts==2.31.0` (denied) | exit 1, BLOCK, stage gate, 0 downloads | pass |
| `test_unresolved_is_review_exit_2` | UNRESOLVED | every request fails | exit 2, REVIEW, "CAVR: UNRESOLVED" | pass |
| `test_live_pypi_and_osv` | Live | live PyPI + OSV, `pypdf==6.19.0` | exit code consistent with CAVR status | pass: REJECTED advisories KNOWN_VULNERABILITY, "pypdf 6.19.0 is affected by 18 known advisories: GHSA-39mj-jf6j-2qj3, GHSA-42gh-23hr-vphw, GHSA-4vqv-7265-gm2w and 15 more" -> BLOCK, exit 1 |

### Defects found and fixed

- None in code. **Finding:** live OSV now lists 18 advisories for pypdf 6.19.0, the version pinned by the InvoiceHub demo (`demo_project/InvoiceHub/requirements.txt`, lock and `.asent/cavr/policy.json`). The recorded answer used by the tests (`tests/test_cavr_data/osv-pypdf-6.19.0.json`) has none. Not changed here: choosing the demo's dependency version is Maryam's decision. Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- The four offline tests depend on recorded data; their VERIFIED case is a statement about the recorded OSV answer of 2026-09-25, not about pypdf today (see finding).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the tests and these notes; ran the live test once. **Reviewed by Maryam:** the required mapping is hers. **Verified by:** offline run and one live run.

### Supervisor Q&A prep

1. **Show that each CAVR verdict reaches CI correctly.** `tests/test_gate_cavr_verdicts.py`: four real repositories, four verdicts, exit codes 0/1/1/2, the pipeline's own stage and rule in the report.
2. **Is the demo dependency safe?** On the recorded data yes; on live OSV (2026-11-07) pypdf 6.19.0 is affected by 18 advisories, and the gate blocks it.

## Step 10 — CLI in the Docker image and a reusable GitHub Actions workflow (2026-11-07)

### Ch 6 Implementation

- `scripts/asent` (new, 0755): POSIX wrapper; `ASENT_HOME` (default the checkout above the script), `ASENT_PYTHON` (default `python3`); `exec python -m backend.cli "$@"`.
- `Dockerfile`: installs the wrapper as `/usr/local/bin/asent`, `ENV ASENT_HOME=/app ASENT_PYTHON=python`; the server `CMD` is unchanged.
- `.github/workflows/cd.yml`: image smoke test also runs `asent gate --help`.
- `.github/workflows/asent-gate.yml` (new): `on: workflow_call` (inputs `asent-repository`, `asent-ref`, `review-fails`, optional `base`/`head`, `python-version`; outputs `decision`, `exit-code`); read-only permissions; target checkout with `fetch-depth: 0`; ASENT checkout at the pinned ref; `pip install -r requirements.lock.txt`; `docker build` of `asent-sandbox:local`; `asent gate` with the PR base/head SHAs (through env); summary to `$GITHUB_STEP_SUMMARY`; report artifact (`if: always()`); BLOCK fails, REVIEW fails unless `review-fails: false`.
- `docs/gate/asent-pr.yml` (new): the copyable caller (`on: pull_request`).

### Design decisions

- **Runner-native, image ships the CLI too:** decided by Maryam (decision 2). Inside the image without a container engine, SATRA and CAVR deep paths are INCONCLUSIVE/UNRESOLVED -> REVIEW; documented in `docs/asent-gate.md`.
- **Fork-safe workflow:** `pull_request` only, `contents: read`, `persist-credentials: false`, no `${{ }}` inside `run:` (tested), so a crafted branch name cannot inject shell code.
- **Pinned ASENT ref as an input:** the gate code that decides must itself be a fixed, reviewable commit.
- **Docker image run with `--user $(id -u):$(id -g)`:** git refuses repositories owned by another user (`safe.directory`), and the gate deliberately ignores global/system git config; matching the owner avoids a permanent REVIEW.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| none listed | Gate on any repository's pull requests (dev-env plan) | Reusable workflow and caller | `test_reusable_workflow_interface`, `test_gate_step_uses_the_pull_request_shas_and_maps_exit_codes`, `test_caller_example_runs_on_pull_requests` |
| FR-6 | Fail-Closed Security Policy | REVIEW fails the job by default; missing exit code fails | `test_gate_step_uses_the_pull_request_shas_and_maps_exit_codes` |

### Ch 7 Test cases

`tests/test_gate_packaging.py`: 10 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_reusable_workflow_interface` | Interface | asent-gate.yml | required inputs, boolean review-fails default true, outputs | pass |
| `test_workflow_permissions_are_read_only` | Least privilege | both files | `contents: read` only | pass |
| `test_no_pull_request_target_anywhere` | Fork safety | both files (text) | absent | pass |
| `test_no_untrusted_expressions_inside_shell_scripts` | Injection | every `run:` | no `${{` | pass |
| `test_checkouts_have_full_history_and_no_persisted_credentials` | Checkout | both checkouts | fetch-depth 0; pinned ASENT; no credentials | pass |
| `test_gate_step_uses_the_pull_request_shas_and_maps_exit_codes` | Gate step | workflow | PR SHAs via env, sandbox build, artifact always, 1/2 mapping | pass |
| `test_caller_example_runs_on_pull_requests` | Template | asent-pr.yml | pull_request, calls the reusable workflow | pass |
| `test_dockerfile_installs_the_cli_and_keeps_the_server` | Image | Dockerfile | wrapper installed, ASENT_HOME, uvicorn CMD last | pass |
| `test_cd_smoke_test_runs_the_gate_cli` | CD | cd.yml | `asent gate --help` | pass |
| `test_wrapper_is_executable_and_runs_a_real_gate` | Wrapper | `scripts/asent gate` on a real repo | help exit 0; README-only project exit 2 with both files | pass |

Not run here: `docker build` (Docker not installed), `actionlint` (not installed), and a real pull-request run of `asent-gate.yml` (would need a push; Maryam said not to push). These are the open items of the plan's done criterion.

### Defects found and fixed

- The workflow comment named the forbidden trigger and tripped the text check; reworded (the stricter text check was kept). Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- Actions are pinned by major version (`@v4`), as in the existing workflows; pinning by commit SHA is recommended for adopters (`docs/asent-gate.md`).
- No PR comment is posted; results are in the job summary and the `asent-gate-report` artifact.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** wrapper, Dockerfile/CD lines, both workflow files, tests, notes. **Reviewed by Maryam:** not yet. **Verified by:** YAML parsed and checked by tests; wrapper executed for real; image and Actions run not verified (see above).

### Supervisor Q&A prep

1. **Is it safe to run on pull requests from strangers?** The workflow has a read-only token, keeps no credentials, never uses `pull_request_target`, and repository code runs only inside the `--network none` sandbox container.
2. **How does another team adopt it?** `asent init`, review and merge `.asent/`, copy `docs/gate/asent-pr.yml` with a pinned ASENT SHA.

## Step 11 — hardcoded-path guard, gate documentation, end-to-end check (2026-11-07)

### Ch 6 Implementation

- `tests/test_gate_no_hardcoded_paths.py` (new): text guard over the 20 modules a gate run executes (patterns `demo_project`, `sample_project`, `SAMPLE_PROJECT_DIR`, `scenarios/`, `fixtures/invoice.pdf`, `InvoiceHub/`, `DEMO` imports) with a 6-entry allowlist, each with the reason it is unreachable from a gate run; behaviour guards: a gate run with every demo-scenario function replaced by one that raises, and a fresh-interpreter gate run that must not import `backend.main`, `backend.cavr.api`, `backend.satra.settings`, `backend.satra.api`, `backend.sable.api`, `backend.sable.fixtures.scenarios`.
- `tests/test_gate_end_to_end.py` (new): `asent init` -> REVIEW (starter) -> review -> ACCEPT (docs change) -> BLOCK (typosquat added) -> REVIEW (policy edited in the PR), all through the CLI on one fresh repository.
- `docs/asent-gate.md` (new): usage, exit codes, how it works, adoption, local/Actions/Docker use, the per-module table, limitations. `README.md`: short section linking it.

### Design decisions

- **Behaviour guard instead of "never imports scenarios":** `orchestrator/service.py` imports `orchestrator.scenarios` at module level, so an import check is impossible without moving code; replacing its functions with ones that raise proves a gate run never calls them.
- **`scenarios/laboratory_hashes.json` kept in `pytest_runner`, allowlisted:** moving it to a config constant would break `tests/test_hash_verification_line_endings.py`, which relocates it by patching `pytest_runner.ROOT`; it is ASENT's own index of inert sources, read only when `external=False`.
- **Allowlist entries must still match:** `test_every_allowlist_entry_still_matches_a_line` stops the list from silently going stale.

### Requirements covered

| ID | Title | What this covers | Acceptance check |
|---|---|---|---|
| none listed | No hardcoded project paths in the analysis path (dev-env plan) | Text and behaviour guards | `test_gate_path_has_no_hardcoded_demo_paths`, `test_gate_run_never_calls_a_demo_scenario_function` |
| FR-6 | Fail-Closed Security Policy | starter and PR-edited config give REVIEW in the real flow | `test_init_review_gate` |

### Ch 7 Test cases

`tests/test_gate_no_hardcoded_paths.py` + `tests/test_gate_end_to_end.py`: 5 passed.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_gate_path_has_no_hardcoded_demo_paths` | Text guard | 20 modules | no unexplained match | pass (first run found `pytest_runner.py:27`, see defects) |
| `test_every_allowlist_entry_still_matches_a_line` | Guard upkeep | 6 entries | each still present, with a reason | pass |
| `test_gate_run_never_calls_a_demo_scenario_function` | Behaviour | scenario functions raise | gate exit 0 | pass |
| `test_gate_run_does_not_import_dashboard_or_live_satra_modules` | Behaviour | fresh interpreter | none of 7 modules imported | pass |
| `test_init_review_gate` | Done criterion | init -> review -> 3 heads | 2, 0, 1, 2 | pass |

### Defects found and fixed

- The text guard found `backend/satra/pytest_runner.py:27` (`fixtures/invoice.pdf` in `permitted_builtin`) that the plan's inventory listed only by function; allowlisted with its reason (same host fallback, not consulted with `external=True`). Review: 0 passes of cavr-reviewer (not requested), 1 self-review pass, 0 MINOR open.

### Known limitations / deferred

- The guard checks text and two behaviours; it is not a proof that no other code path reads a demo file.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** guards, end-to-end test, documentation, README section, notes. **Reviewed by Maryam:** not yet.

### Supervisor Q&A prep

1. **How do you know the gate does not secretly analyse the demo project?** A text guard over every module the gate runs, plus a run where every demo function raises, plus an import check in a fresh interpreter.

## Step M2-1 — Demo and scenario runs through `verify_request`; demo pin pypdf 6.21.4 (2026-11-22)

PR 1 of `docs/cavr-m2-plan.md` (Phase 1). Decisions applied: Q1 option A, Q2, Q4, Q12; D1–D5 of the Phase 1 plan.

### Ch 6 Implementation

- `backend/cavr/analyzer.py` (rewritten). `analyze()` sends gate runs to `gate_adapter.analyze_pipeline` with the
  gate's `SETTINGS`, and demo/scenario runs to `_analyze_demo`, which calls the same `analyze_pipeline` with
  `DEMO_SETTINGS` (a separate dict of the same shape). Then, over `dependencies.lock.json`:
  LOCAL nodes go to `_lab` (the earlier lab code, moved unchanged and restricted to LOCAL sources, rows labelled
  `engine: "demo-lab"`; a LOCAL artifact that is not a `.py` source is UNRESOLVED `LOCAL_ARTIFACT_NOT_SUPPORTED`);
  a lock entry without a usable name and version is UNRESOLVED `LOCK_ENTRY_INVALID`; a PyPI node that no pipeline verdict judged (not a requested package, not in any verified
  tree) becomes UNRESOLVED `LOCKED_NOT_VERIFIED`; any other ecosystem is UNRESOLVED `UNSUPPORTED_ECOSYSTEM`. The
  module status is the worst over the pipeline result and every node. A pipeline exception is UNRESOLVED
  `INTERNAL_ERROR`. Removed: the PyPI wheel branch, the analyzer's own `OSV().query` advisory rule, `read_artifact`
  for wheels, the direct `fast_gate.disabled_jbig2_sinks` call and the orchestrator-store cache for PyPI nodes.
- `backend/cavr/gate_adapter.py`. `analyze_pipeline(..., settings=None)` (None = `SETTINGS`). Each package row adds
  `engine`, `artifact` (wheel file name), `escalation`, `tree_nodes`, `advisories` (one summary line per OSV answer)
  and `contract` + `required` (allowed entries with status REQUIRED) + `confidence` (the contract's rule): the names
  `Service.report` already reads, so no orchestrator file changed.
- `backend/cavr/api.py`. Seven chips: 1–2 `pypdf 6.21.4` (VERIFIED), new 3 `pypdf 6.19.0 (OSV)` (REJECTED), 4
  `pypdf 5.1.0 (OSV)`, 5 left-pad (BLOCK), 6 tampered wheel and 7 network off on 6.21.4.
- Demo data [owner review]: `demo_project/InvoiceHub/{requirements.txt, dependencies.lock.json,
  .asent/cavr/policy.json}` pin `pypdf==6.21.4` (sha256 `33e4fb41…5255c`); `backend/cavr/sample_project/requirements.txt`
  likewise; `scenarios/cavr_controlled/invoice_pdf_safe.py` binds `reader = PdfReader(...)` inside the guard (same
  behaviour; the reachability proof only follows a reader bound to one name).
- Recorded data (`tests/test_cavr_data/`, recorded once on 2026-11-22 with httpx from pypi.org and api.osv.dev; the
  wheel's SHA-256 was checked against the registry digest before saving): `pypdf-6.21.4-py3-none-any.whl` (410430
  bytes, uploaded 2026-10-28, not yanked), `pypi-pypdf-6.21.4.json`, `osv-pypdf-6.21.4.json` (0 advisories),
  `osv-pypdf-6.19.0-2026-11-22.json` (18). `osv-pypdf-6.19.0.json` (0, 2026-10-10) is labelled
  `historical_snapshot: true`.
- Tests support: `test_cavr_support.py` gains `PIN_*`, `pin_registry_response`, `RECORDED_6_21_4`,
  `RECORDED_6_19_0_NOW`, `HISTORICAL_6_19_0_2026_10_10`, `FakeIndex.add_pin`, `recorded_demo_settings`; `World`
  pins 6.21.4 and also serves 6.19.0 with its 18 advisories. `tests/conftest.py` [owner review]:
  `_offline_demo_runs` (session) puts the recorded answers into `analyzer.DEMO_SETTINGS`; `_record_verified_6_19_0`
  + `_no_verified_6_19_0` fail any test in which a pipeline package verdict is VERIFIED for pypdf 6.19.0.

### Design decisions

- **Reuse `analyze_pipeline` for demo runs** rather than a second loop over lock nodes: one code path for gate and
  demo; the demo project already has a frozen `.asent/` config. Alternative (per-lock-node `pip install x==y`)
  rejected: it would verify children twice and differ from the gate.
- **Separate `DEMO_SETTINGS`** instead of patching `gate_adapter.SETTINGS` in tests: `test_live_pypi_and_osv`
  asserts the gate's live default, and a session-wide patch of the gate settings would leak into gate tests.
- **`LOCKED_NOT_VERIFIED`**: a pinned package nobody verified would otherwise pass unseen (fail closed, FR-6).
- **`infer` kept** (D5): the lab path and `Service._repair` read its contract; deleted in PR 12 with the lab path.
- **Revocation tests use `BEH-PROCESS_EXEC`** (D1): the fast gate reads sink rules (through the contract
  vocabulary and `analyzer_version`), not trigger rules; disabling `TRIG-ENV` changes no verdict (tested).
- **6.19.0 never VERIFIED**: rather than relabel tests one by one, a conftest guard enforces it for the whole suite;
  the shared test worlds moved to 6.21.4.
- **`invoice_pdf_safe.py` rewrite** instead of widening the reachability proof: the proof's limit is documented
  (M1 step 9) and changing proofs is out of PR 1.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-15 | Demo/scenario runs publish pipeline evidence: `test_demo_pypi_node_is_judged_by_the_pipeline` |
| FR-11 | Demo pin's wheel hash = recorded file = registry digest: `test_demo_pin_6_21_4_is_verified_on_the_recorded_answers` |
| FR-6 | No OSV answer -> UNRESOLVED; pipeline fault -> UNRESOLVED; unjudged lock node -> UNRESOLVED |
| FR-10 | Assurance report lists pypdf sha256 and contract: `test_assurance_report_lists_each_cavr_package_sha256_and_contract` |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_demo_pypi_node_is_judged_by_the_pipeline` | demo run uses the pipeline | `safe` scenario | VERIFIED, engine pipeline, 8 key fields | pass |
| `test_demo_run_never_asks_osv_outside_the_pipeline` | no second advisory rule | OSV stub + `OSV.query` trap | stub asked once, trap never | pass |
| `test_demo_run_without_an_osv_answer_is_unresolved` | Q1 A | empty OSV cache | UNRESOLVED `ADVISORIES_UNAVAILABLE` | pass |
| `test_demo_pin_6_21_4_is_verified_on_the_recorded_answers` | shipped pin + recordings agree | shipped files | VERIFIED, sha `33e4fb41…` | pass |
| `test_rejected_demo_pins_are_rejected_by_recorded_advisories[6.19.0/5.1.0]` | REJECTED demo cases | recorded 18 / 97 | REJECTED `KNOWN_VULNERABILITY` | pass |
| `test_orchestrator_demo_run_with_the_6_19_0_pin_is_rejected` | REJECTED case through `analyzer.analyze` | pin 6.19.0, approved | REJECTED, 18 advisories | pass |
| `test_local_wheel_in_the_lock_is_unresolved_never_verified` | review BLOCKER | LOCAL wheel with unpinned Requires-Dist | UNRESOLVED `LOCAL_ARTIFACT_NOT_SUPPORTED` | pass |
| `test_non_pypi_ecosystem_in_the_lock_is_unresolved` | edge | npm entry | UNRESOLVED `UNSUPPORTED_ECOSYSTEM` | pass |
| `test_lock_entry_without_a_usable_name_and_version_is_unresolved` (4 cases) | edge | malformed entries | UNRESOLVED `LOCK_ENTRY_INVALID`, nothing VERIFIED | pass |
| `test_unreadable_lockfile_is_unresolved` (3 cases) | edge | bad JSON, list, dict packages | UNRESOLVED | pass |
| `test_missing_lockfile_is_judged_like_the_gate` | edge | no lockfile | VERIFIED (exact pin, no dependencies), as a gate run | pass |
| `test_demo_run_without_a_frozen_cavr_config_is_unresolved` | edge | no frozen `.asent/` | UNRESOLVED | pass |
| `test_assurance_report_lists_each_cavr_package_sha256_and_contract` | report fields | integration `safe` run | sha, artifact, required/denied/confidence | pass |
| `test_pipeline_fault_in_a_demo_run_is_unresolved` | fail closed | `verify_request` raises | UNRESOLVED `INTERNAL_ERROR` | pass |
| `test_local_lab_node_keeps_the_lab_path_labelled_demo_lab` | lab path kept | `cavr_canary` | lab REJECTED; pypdf UNRESOLVED `SINK_REACHABLE` | pass |
| `test_locked_pypi_node_no_request_verifies_is_unresolved` | edge: unjudged pin | extra lock entry | UNRESOLVED `LOCKED_NOT_VERIFIED` | pass |
| `test_demo_settings_never_change_gate_settings` | settings isolation | spy | demo gets DEMO_SETTINGS, gate None | pass |
| `test_disabled_trigger_rule_does_not_change_the_fast_gate` | D1 | TRIG-ENV off | VERIFIED, same key fields | pass |
| `test_inline_pdfreader_pages_form_is_unresolved_never_verified` | known limitation | inline `PdfReader(...).pages` | UNRESOLVED, escalated | pass |
| `test_repaired_cross_module_state_verifies_pypdf` | repair state | `cross_module` + `replace_lab` | pypdf VERIFIED | pass |
| `test_modules::test_cavr_safe_cache_and_advisory` (changed) | cache + revocation | BEH-PROCESS_EXEC off/on | MISS, HIT; revoked UNRESOLVED, not from cache, lookup not reached; restored HIT same key | pass |
| `test_integration::test_gateway_and_knowledge_revocation` (changed) | same through the service | as above | REVIEW then ACCEPT | pass |
| `test_cavr_advisories` (2 new, 1 renamed) | 6.19.0 recordings | 18-advisory answer; historical label | REJECTED; labelled | pass |
| `test_cavr_live.py` (rewritten, CAVR_LIVE=1 only) | live, with URL proof | real PyPI/OSV | `LiveTransport.reached`, OSV mode LIVE | not run (skipped without CAVR_LIVE) |

Run before the commit: `tests/test_cavr_*.py`, `tests/test_gate_*.py`, `test_cli_gate.py`, `test_shared.py`,
`test_modules.py`, `test_integration.py`, `test_orchestrator_config.py`, `test_api_replay.py`: 1538 passed, 11 skipped
(live, `CAVR_LIVE` unset), 604 s. `reports/scenario-validation.json` unchanged.

### Defects found and fixed

- First guard run: 98 tests showed pypdf 6.19.0 VERIFIED through the shared test worlds (`World`, `Gate`,
  `gate_support.recorded_pypi`); moved to 6.21.4.
- `cross_module` would have ended REVIEW: pypdf UNRESOLVED `SINK_REACHABLE` through the inline reader in
  `invoice_pdf_safe.py`; fixed in the demo data, limitation pinned by a test.
- `test_gate_no_hardcoded_paths` allowlist matches the lab line's exact text; the moved line keeps the original
  spelling `context.path/'fixtures/invoice.pdf'`.
- cavr-reviewer BLOCKER: the moved lab code had lost the earlier Requires-Dist check, and nothing limited it to
  `.py` sources, so a LOCAL wheel with unpinned dependencies would have been VERIFIED (fail-open). Fixed: the lab
  accepts only LOCAL `.py` sources (which have no Requires-Dist); anything else is `LOCAL_ARTIFACT_NOT_SUPPORTED`.
  Also from the review: malformed lock entries give a `LOCK_ENTRY_INVALID` row instead of an exception; the 6.19.0
  guard compares canonical versions; six edge tests added.
- Review: 1 pass of cavr-reviewer, verdict "fix first" (1 BLOCKER, 0 MAJOR, 7 MINOR); BLOCKER and MINORs 1–6
  fixed; 1 MINOR open (replay baseline note, recorded under limitations).

### Known limitations / deferred

- Reachability proof follows only `reader = PdfReader(...)` bound to one name; `PdfReader(...).pages` inline stays
  UNRESOLVED (escalated). Answered by the deep path (Phase 2), not by more proofs.
- After revoking `BEH-PROCESS_EXEC` the cache is not consulted at all (the contract fails before an 8-field key
  exists): "not served from the cache" is shown as `cache_hit False` and `lookup None`, not as a MISS.
- A *weakened* sink rule (enabled, fewer `python_sinks`) changes `analyzer_version` (cache miss) and re-scans with
  fewer sinks; the pipeline has no seed-coverage check like the old analyzer's. Not changed in PR 1 (gate behaviour);
  to be decided.
- ASENT's own `pyproject.toml` / `requirements.lock.txt` still pin `pypdf==6.19.0` for the host (the lab harness
  imports it); packaging is outside CAVR's scope.
- SATRA builds its project image from the demo `requirements.txt`, so its Docker image is rebuilt for 6.21.4.
- `scenarios/replay/weak-oracle/baseline` (a SATRA replay fixture) still pins `pypdf==6.19.0` with the old artifact;
  it is a historical replay input, not a CAVR demo pin, and its tests pass (`test_api_replay.py`). Not changed.
- A missing lockfile is judged as in a gate run: an exact pin with no dependencies is VERIFIED.
- `docs/cavr-demo.md` case transcripts are from 2026-10-11 (old pin) and are kept as recorded, with a dated note.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the code, tests, recordings script (run once; not committed) and these notes.
  **Reviewed by Maryam:** the plan and decisions D1–D5 and the additions (live proof, inline-form test, revocation
  assertions, historical label); the diff itself not yet. **Verified by:** the test runs listed above.

### Supervisor Q&A prep

1. **Why is 6.19.0 no longer the VERIFIED pin?** OSV listed 18 advisories for it on 2026-11-22; CAVR rejects it,
   as it should. 6.21.4 has a wheel, is not yanked and has 0 advisories (recorded the same day).
2. **How do tests stay offline but honest?** The bytes and answers are real recordings, served by a fake transport;
   nothing is hand-written, and a guard fails any test that shows 6.19.0 VERIFIED.
3. **What still is not the pipeline?** LOCAL controlled-reproduction modules (the demo lab) until PR 12.

## Step M2-2 — Deep-analysis stage behind the escalation, fail closed (2026-11-22)

PR 2 of `docs/cavr-m2-plan.md` (Phase 1). Decision Q8 applied to the interface; no sandbox yet.

### Ch 6 Implementation

- New `backend/cavr/deep_stage.py`. `identity(deep)` returns `<version>;image:<image id>;budget:<digest>` or None
  when the version, image ID or a budget with `package_seconds > 0` is missing. `run_deep(deep, package)` always
  returns `{status, stage: "deep", rule, reason, evidence, elapsed_seconds}`: no identity -> `DEEP_IDENTITY_UNKNOWN`
  (not called); raises -> `INTERNAL_ERROR`; None -> `DEEP_NO_RESULT`; not a dict / unknown status / empty rule or
  reason / non-dict evidence -> `DEEP_RESULT_INVALID`; elapsed by the host clock (`CLOCK`, `time.monotonic`) over
  `package_seconds` -> `DEEP_BUDGET_EXCEEDED` unless the answer is REJECTED; otherwise the analyzer's answer.
  `identity` never raises (a failing attribute or an undigestable budget is "no identity").
- `backend/cavr/pipeline.py`. `verify_request(..., deep=None)`. `analyzer_version(knowledge, deep)` appends
  `;deep:<identity or unknown>` only when `deep` is given. Stage 8b (`_deep`): only when stage 8's analysis is
  UNRESOLVED with an escalation and `deep` is not None, the analyzer gets a deep copy of the package's evidence and its answer replaces status, stage, rule and reason; the fast scan and
  reachability evidence stay; `evidence["deep"]` holds the deep result; the package's escalation text becomes
  `escalated: deep analysis ran`. The combined analysis is cached like any analysis (VERIFIED / REJECTED only).
  The request-level `escalation` is now the first escalated package's text (unchanged for `deep=None`).
- `gate_adapter.SETTINGS["deep"]` and `analyzer.DEMO_SETTINGS["deep"]` (None) are passed through.

Key algorithm: stages 1–7 unchanged -> stage 8 fast analysis -> if escalated and a deep analyzer is configured:
`run_deep` (validated, timed by the host) -> replace the escalated verdict -> cache if VERIFIED/REJECTED under the
8-field key whose `analyzer_version` carries the deep identity. Every earlier return (BLOCK, hash mismatch, OSV
affected or unknown, contract unknown, tree problems) happens before stage 8, so the deep stage cannot see them.

### Design decisions

- **Deep identity inside `analyzer_version`** rather than a 9th key field: the key stays the 8 fields (M1 rule);
  a new image, version or budget is a miss by construction.
- **Host clock, not the analyzer's own timing**, for the budget (Q8): a package-controlled run cannot report itself
  as within budget. The clock is a module seam (`CLOCK`) so tests are deterministic.
- **REJECTED over budget stays REJECTED**: an observed violation is a violation (Q8); only VERIFIED / UNRESOLVED
  answers become `DEEP_BUDGET_EXCEEDED`.
- **No identity -> not called**: without a key the result could not be cached or audited; fail closed.
- **Placement after `_analyse`, before the cache store**: a cached deep verdict is reused only for the same deep
  identity, and advisories (stage 7) are still checked on every call.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-6 | Every deep failure mode is UNRESOLVED: `test_no_or_malformed_deep_result_is_unresolved`, `..._raises_...`, `..._without_a_full_identity_...`, `test_going_over_the_time_budget_...` |
| FR-4 (interface) | Escalated packages reach a deep stage: `test_deep_verified_lifts_only_the_escalation` |
| NFR-4 | Deep identity and budget in the key: `test_changing_the_image_id_is_a_cache_miss`, `test_changing_the_deep_version_or_budget_changes_the_key` |

### Ch 7 Test cases

`tests/test_cavr_deep_stage.py` (fake deep analyzer `FakeDeep`; real pipeline on the recorded pypdf 6.21.4 data).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_deep_none_keeps_the_analyzer_version_and_the_escalated_verdict` | deep=None unchanged | escalated project | UNRESOLVED `SINK_REACHABLE`, no `;deep:` | pass |
| `test_deep_verified_lifts_only_the_escalation` | lift | deep VERIFIED | package VERIFIED `deep/DEEP_CLEAN`, fast evidence kept | pass |
| `test_deep_rejected_rejects_with_the_deep_evidence` | violation | deep REJECTED | REJECTED with deep evidence | pass |
| `test_deep_unresolved_stays_unresolved` | incomplete | deep UNRESOLVED | UNRESOLVED | pass |
| `test_deep_analyzer_that_raises_is_unresolved_internal_error` | fault | raises | UNRESOLVED `INTERNAL_ERROR` | pass |
| `test_no_or_malformed_deep_result_is_unresolved` (6) | bad answers | None, str, bad status, no rule, empty rule, bad evidence | `DEEP_NO_RESULT` (None) / `DEEP_RESULT_INVALID` | pass |
| `test_deep_analyzer_without_a_full_identity_is_unresolved_and_never_called` (5) | identity | missing version / image / budget | `DEEP_IDENTITY_UNKNOWN`, 0 calls | pass |
| `test_going_over_the_time_budget_is_unresolved_even_when_the_answer_is_verified` | Q8 budget | 120.5 s | UNRESOLVED `DEEP_BUDGET_EXCEEDED` | pass |
| `test_a_violation_found_over_the_budget_is_still_rejected` | Q8 | REJECTED, 120.5 s | REJECTED | pass |
| `test_exactly_on_the_budget_is_within_it` | boundary | 120 s | VERIFIED | pass |
| `test_not_called_for_a_fast_verified_package` | not escalated | clean project | VERIFIED, 0 calls | pass |
| `test_not_called_for_a_rejected_package` | not escalated | affected advisory | REJECTED, 0 calls | pass |
| `test_not_called_for_a_blocked_request` | not escalated | left-pad | BLOCK, 0 calls | pass |
| `test_deep_verified_never_lifts_missing_advisories` | owner request | no OSV answer | UNRESOLVED `ADVISORIES_UNAVAILABLE`, 0 calls | pass |
| `test_deep_verified_never_lifts_a_request_hash_mismatch` | owner request (UNRESOLVED by hash) | wrong `--hash` in requirements | UNRESOLVED `REQUEST_HASH_MISMATCH`, 0 calls | pass |
| `test_deep_verified_never_lifts_a_registry_hash_mismatch` | REJECTED by hash | one bit flipped | REJECTED `HASH_MISMATCH`, 0 calls | pass |
| `test_an_identity_that_cannot_be_read_is_unresolved_never_an_exception` (2) | fail closed | raising property, unsortable budget | `DEEP_IDENTITY_UNKNOWN`, `;deep:unknown` | pass |
| `test_a_cached_deep_verified_is_never_served_without_that_deep_analyzer` | cache | stored deep VERIFIED, then deep=None / no identity | escalated UNRESOLVED / `DEEP_IDENTITY_UNKNOWN`, no hit | pass |
| `test_not_called_for_an_unknown_contract` | not escalated | invalid scopes | UNRESOLVED `CAPABILITY_POLICY_INVALID`, 0 calls | pass |
| `test_a_cached_deep_verified_still_rechecks_osv` | cache + OSV | hit, then advisory | hit with 1 call; then REJECTED | pass |
| `test_changing_the_image_id_is_a_cache_miss` | key | new image ID | MISS, called again | pass |
| `test_changing_the_deep_version_or_budget_changes_the_key` (2) | key | new version / budget | not a hit, called again | pass |
| `test_unresolved_deep_answers_are_not_cached` | cache | deep UNRESOLVED twice | 2 calls, no cache row | pass |

`tests/test_cavr_deep_stage.py`: 34 passed. Run before the commit (same set as Step M2-1): 1572 passed, 11 skipped
(live, `CAVR_LIVE` unset), 818 s; `test_cavr_pipeline.py` unchanged and passing (deep=None is unchanged).

### Defects found and fixed

- First run: 2 of 30 failed because the tests read the request-level stage/rule; a VERIFIED request always reads
  `verdict / ALL_CHECKS_PASSED`. The tests now check the package's stage and rule (test fix, no code change).
- cavr-reviewer MAJOR: the owner asked for a deep VERIFIED never lifting an UNRESOLVED caused by a hash; the test
  covered the REJECTED registry mismatch only. Added the `REQUEST_HASH_MISMATCH` test, kept the REJECTED one renamed.
  MINORs fixed: `identity` cannot raise; stage 8b also requires status UNRESOLVED; the analyzer gets a deep copy;
  exact rules in the malformed-answer test; stored-row and `analyzer_version` asserts in the cache-miss tests; a
  test that a cached deep VERIFIED is not served with `deep=None` or without an identity; docstring wrapped.
- Review: 1 pass of cavr-reviewer, verdict "OK to commit" (0 BLOCKER, 1 MAJOR, 9 MINOR); MAJOR and 7 MINORs
  fixed; 1 MINOR open (budget limits, recorded below); the notes MINOR is this entry.

### Known limitations / deferred

- No real deep analyzer exists: `SETTINGS["deep"]` is None, so every escalated package is still UNRESOLVED
  (`deep analysis required (M2)`). The sandbox analyzer comes in Phase 2 (PR 3–9).
- The budget is checked after `analyse` returns: a hanging analyzer blocks the call. Stopping a run at the
  deadline is the runner's job (PR 4). `package_seconds` has no upper bound, and `runs` / `run_seconds` are carried
  in the identity but not enforced here; both are checked when the real analyzer and the base-policy budget arrive
  (PR 9, PR 12).
- Until PR 3 the image ID is whatever the analyzer object reports; PR 3's `image_identity()` reads the real one.
- `elapsed_seconds` is in the deep evidence; `deep_analysis_ms` in the verdict log is PR 9 (NFR-4).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `deep_stage.py`, the pipeline change, the tests and these notes. **Reviewed by
  Maryam:** the plan and the required test list; the diff itself not yet. **Verified by:** the runs listed above.

### Supervisor Q&A prep

1. **Can a deep VERIFIED hide a known vulnerability?** No. Advisories are checked at stage 7 on every call, before
   the deep stage and also on a cache hit (`test_a_cached_deep_verified_still_rechecks_osv`).
2. **Why trust the time budget?** It is measured by the host around the call, not reported by the analyzer.
3. **What happens if the sandbox image changes?** Its ID is in `analyzer_version`, so the key changes and the
   package is analysed again.

## Step M2-1a — Re-pin the rewritten safe lab adapter for the Docker-less host fallback (2026-11-22)

Fix for a CI failure introduced by Step M2-1: `tests/test_cavr_targeted.py::test_pinned_repair_candidate_functionality_and_security`
failed with "Untrusted package requires Docker/Podman; host fallback only accepts hash-pinned inert sources". It
passed locally only because Docker was available.

### Ch 6 Implementation

- `scenarios/laboratory_hashes.json`: the digest of `scenarios/cavr_controlled/invoice_pdf_safe.py` replaced in
  `cavr_sources` and `python_sources`: `b4e7ebcbe324484da22c64d925a2d03fd8aa06f55da73f62e4104b7163a340bf` (before
  Step M2-1) -> `c8387145dc6fc5957affb64cb5630a770f5180b369dd2e7a344e7b29efc332ea` (Step M2-1 rewrite). These are the
  values the hashing rule of `scripts/build_scenarios.py` gives for that file; the generator itself was not run.
- New `tests/test_cavr_lab_pins.py`: pins match the shipped lab sources; the real host fallback runs with Docker,
  Podman and strace hidden; an unpinned source is still refused.

Cause: the host fallback (`backend/cavr/sandbox.py::run_counterfactual`) pins the lab `.py` source by its
LF-normalised SHA-256, not the pypdf wheel; the lab imports the host's pypdf. Step M2-1 bound `reader =
PdfReader(...)` to one name (for the guard proof), which changed the source digest; the pin still held the old one.
SATRA's host fallback (`backend/satra/pytest_runner.py::permitted_builtin`) reads `python_sources` from the same file
for the vendored copy, so `test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies` also failed
without Docker (`cross_module` ended BLOCK, SATRA INCONCLUSIVE after the repair).

### Design decisions

- **Pin the new source digest, not the 6.21.4 wheel sha256**: the allowlist is compared with `.py` source digests;
  a wheel hash would match nothing and would put a non-source entry into an inert-source list.
- **Edit two entries by hand instead of running the generator**: the generator also rewrites the scenario catalog
  and Terraform candidates, and would add two unrelated SATRA digests (below).
- **Fallback rule unchanged**: `test_an_unpinned_source_is_still_refused_without_docker`.
- **Audit before pinning** (owner request). Old vs new diff: the inline `PdfReader(BytesIO(content)).pages` became
  `reader = PdfReader(BytesIO(content))` + `reader.pages`, and a comment line. Static: same imports (`io.BytesIO`,
  `pypdf.PdfReader`, `pypdf.apply_configuration`), same 5 calls, CAVR `ast_scan.scan_wheel` `SCAN_COMPLETE` with 0
  sinks, 0 dynamic code, 0 gated branches for both. Runtime (host fallback, Python audit hook, both modes, host pypdf
  6.19.0): the same event types and counts for old and new (115 reads, 1 write: the bytecode cache), 0 process,
  network or secret events, no canary. Measured with a scratch script, not committed; the test repeats the checks.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-6 | Fail-Closed Security Policy: an unpinned source is refused without an engine: `test_an_unpinned_source_is_still_refused_without_docker` |
| NFR-1 | Non-Root Isolation: only pinned inert sources run on the host: `test_every_cavr_lab_source_is_pinned_for_the_host_fallback`, `test_pinned_lab_sources_run_on_the_host_without_docker` |

### Ch 7 Test cases

`tests/test_cavr_lab_pins.py` (engines hidden by monkeypatching `sandbox.availability`).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_every_cavr_lab_source_is_pinned_for_the_host_fallback` | pins in step | `invoice_pdf_*.py` | `cavr_sources` == their LF digests; all in `python_sources` | fail before, pass after |
| `test_pinned_lab_sources_run_on_the_host_without_docker` | real fallback | safe adapter, no Docker/Podman/strace | `PINNED_INERT_LAB_PYTHON_AUDIT`, same text both modes, no canary, no process/network/secret/write events except one bytecode-cache write per run | fail before, pass after |
| `test_an_unpinned_source_is_still_refused_without_docker` | rule unchanged | adapter + one comment line | refusal, no runs | pass |

Runs on 2026-11-22. Docker hidden (`DOCKER_HOST=unix:///nonexistent`), `test_cavr_*`, `test_gate_*`, `test_cli_gate`,
`test_shared`, `test_modules`, `test_integration`, `test_orchestrator_config`, `test_api_replay`,
`test_hash_verification_line_endings`: before 2 failed (`test_cavr_targeted.py::test_pinned_repair_candidate_functionality_and_security`,
`test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies`), 1572 passed, 11 skipped; after 1577 passed,
11 skipped, 0 failed. Full suite with Docker: 2346 passed, 11 skipped, 1 xfailed, 2 failed in
`test_satra_project_image_docker.py` (the image build's PyPI download; on rerun one passed, the other failed again on a
truncated `pydantic-core` download reported by pip as a hash mismatch; that path runs in Docker and does not read
`laboratory_hashes.json`). After the review fixes: `test_cavr_lab_pins.py` + `test_cavr_targeted.py` 9 passed with and
without Docker.

### Defects found and fixed

- CI: Step M2-1 changed a pinned lab source without re-pinning it; Step M2-1's verification ran with Docker, so the
  pin was never consulted. Fixed by the re-pin; the new tests fail on any machine if it happens again.
- The first draft of the runtime test forbade every `FILE_WRITE`; the old, approved adapter also writes one file:
  the interpreter's bytecode cache for the imported adapter (`__pycache__/package.cpython-*.pyc.*`) inside the
  disposable workspace. The test allows exactly that write and no other.
- Review: 1 pass of cavr-reviewer, verdict "OK to commit" (0 BLOCKER, 0 MAJOR, 7 MINOR); 6 MINORs fixed, 1 answered by the Docker-hidden run; 0 open.

### Known limitations / deferred

- **For Sheharyar (SATRA), not changed here:** two `backend/satra/trusted_*.py` digests are not in `python_sources`
  (drift since 2026-11-08); the generator would add them: `backend/satra/trusted_data.py`
  `91c373c6b2192385a674dd1a6911c509b2663615cd98f7901e6107125fe3ca80` (since 71413b9) and
  `backend/satra/trusted_run_plugin.py` `cc900a7fee5a3e31a7d0d815258e30f5672f7d0cd859fb7bd78801eac6e2e643`
  (since 3ce766b).
- The host `.venv` still has pypdf 6.19.0 from `pyproject.toml` (the lab imports it); to fix later, not in this
  commit.
- The lab harness runs with `python -I`, which ignores the `PYTHONDONTWRITEBYTECODE=1` set by `sandbox.py`, so the
  interpreter writes a bytecode cache in the workspace (harmless there; not changed here).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the re-pin, the tests, the audit and these notes. **Reviewed by Maryam:** the plan,
  the tag and the audit request; the diff itself not yet. **Verified by:** the runs listed above.

### Supervisor Q&A prep

1. **Why not pin the pypdf 6.21.4 wheel?** The fallback never runs a wheel; it runs one reviewed `.py` file and pins
   that file's digest.
2. **Does re-pinning weaken the fallback?** No. The rule is unchanged, and any other change to the file is refused
   (`test_an_unpinned_source_is_still_refused_without_docker`).
3. **How do you know the new file is still inert?** Same imports and calls, 0 sinks in the CAVR scan, and an
   the same audit-event types and counts as the approved file on the same host fallback.

## Step M2-3 — Repair proposal from real releases, re-verified with `verify_request` (2026-11-23)

PR 15 and the fast-gate part of PR 16 of `docs/cavr-m2-plan.md` (fast-first item 2). Decisions Q9, Q10, Q12 applied;
no sandbox. Owner additions of 2026-11-23: symlinks in the copy, lockfile dependents, the major-version limitation,
the 24-hour limit on the package-wide OSV answer.

### Ch 6 Implementation

- New `backend/cavr/repair_proposal.py`. `propose_repair(verdict, package, project_dir=, policy=, requirements_file=,
  …)` returns one block (`schema: cavr.repair.v1`): `result` PROPOSED / NO_REPAIR_FOUND / NOT_ATTEMPTED, `pin`,
  `removal`, `removal_reason`, `candidates_tried`, `excluded`, `not_tried`, `budget`, `registry`, `advisory_screen`,
  `project_copy`, `limitations`, and always `applied: false`, `gate_decision_changed: false`. Any exception gives
  NO_REPAIR_FOUND / `INTERNAL_ERROR`. `copy_project` copies without following links; `_ProjectFiles` makes the
  requirements / lockfile patches in the copy and restores them after each re-check; `_policy_for_pin` makes the
  patched policy.
- `backend/cavr/pypi_client.py`: `project_url`, `fetch_releases` (every release from `pypi.org/pypi/<name>/json`:
  yanked, has a wheel; SHA-256 of the bytes received) and `release_wheel` (the wheel `fetch_artifact` would take and
  its registry SHA-256, without downloading). Both reuse `_read_capped`, `_parse_release`, `select_wheel`.
- `backend/cavr/advisories.py`: `package_query`, `package_cache_path`, `package_advisories` (OSV's package-wide
  answer, dated and digest-checked cache in the adapter's format, stale after 24 hours, `now` injectable).
- `backend/cavr/gate_adapter.py`: every package row has `repair` (None unless REJECTED); `SETTINGS["repair"]`
  (default True); `_repair` wraps the call once more, so a failure is NO_REPAIR_FOUND. Status, reasons and events
  are computed as before. The block reaches `asent-report.json` through the CAVR evidence.

Key algorithm: REJECTED by an advisory or `HASH_MISMATCH` -> copy the project (links not followed; the copy must
read like the project: same result, rule and sources digest) -> releases newer than the rejected one, minus
pre-releases, yanked and wheel-less -> minus releases affected by any advisory of the package-wide OSV answer ->
same major first, smallest upgrade first -> for at most 5 candidates within 60 s: patch requirements line, lockfile
entry (registry SHA-256) and `approved_requirements` in the copy, `verify_request` with the patched policy, a fresh
quarantine and no store -> the first VERIFIED, not escalated re-check whose wheel has the registry digest is the
pin. Removal separately: only when the project never imports it and nothing depends on it.

### Design decisions

- **Package-wide OSV screen before the budget** (alternative: only the rejected version's advisories, or one OSV
  query per release). 5.1.0's own 97 advisories leave 6.19.0–6.21.3 looking clean, which uses up 5 candidates and
  gives no repair; one query per release is ~60 queries. The screen only filters; each candidate's own
  `verify_request` is the judgement. It is implemented in CAVR because `backend/integrations/osv_adapter.py` only
  asks per version (not edited).
- **Re-check through `verify_request` on a copy** (alternative: re-run selected checks): the proposed policy and
  lockfile go through the requirement gate like any request, and the re-check is the same code as a real verdict.
  The request is the requirements edit (original file -> patched file), so the patch text itself is checked.
- **`store=None` for re-checks**: they are not in the verdict log (metrics stay about real requests) and cannot
  read or write the verdict cache.
- **Copy must read like the project** (owner: skip links that point outside). Skipping an outside `.py` link would
  make the copy read better than the project (`context_extractor` reports such a link as not read), so the
  re-check would be about another project: `COPY_DIFFERS`, no repair. Links inside the project are recreated as
  relative links, never followed.
- **Policy patch is minimal**: no change when an entry already approves the candidate (e.g. `pypdf>=5,<7`);
  otherwise the exact `name==old` pin is replaced by `name==new`, or `name==new` is added.
- **Removal needs proof of no dependents** (owner): another package of the verdict with it in its tree, or a
  lockfile edge pointing to it, blocks removal; a lockfile that locks other packages but has no `edges`, or no
  lockfile, cannot rule a dependent out, so no removal. Never for a hash mismatch (import names untrusted).
- **Upgrades only** (alternative: also downgrades): an older release is a step back in fixes; listed as a limitation.
- **Budget between candidates**: a running `verify_request` is not interrupted (its downloads have their own
  deadlines); stated in every block.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-7 | Nearest safe release proposed from real data: `test_6_19_0_proposes_6_21_4`, `test_5_1_0_proposes_6_21_4_with_the_major_version_limitation` |
| FR-8 (fast part) | Each candidate re-verified by `verify_request` under the proposed policy: `recheck` VERIFIED, `test_tampered_candidate_is_skipped`, `test_candidate_without_an_osv_answer_is_skipped`, `test_escalated_candidate_is_skipped` |
| FR-6 | Fail closed: `test_exception_inside_repair_gives_no_repair_found`, `test_exception_in_the_gate_wiring_keeps_the_verdict`, `test_copy_that_reads_differently_from_the_project_gives_no_repair_found`, `test_package_wide_osv_answer_is_stale_after_24_hours` |
| Q9 | Proposal only: `test_repair_never_writes_the_project`, `test_gate_decision_is_unchanged_with_or_without_a_proposal` |

### Ch 7 Test cases

`tests/test_cavr_repair.py` (recorded pypdf data of 2026-11-23 for the real cases; synthetic `demo` wheels and
SYNTH- advisories otherwise).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_6_19_0_proposes_6_21_4` | real case | pypdf 6.19.0, recorded releases + OSV | pin 6.21.4, re-check VERIFIED, 6.20.0–6.21.3 excluded, 7.x not tried | pass |
| `test_5_1_0_proposes_6_21_4_with_the_major_version_limitation` | real case, major change | pypdf 5.1.0 (real wheel) | pin 6.21.4, policy pin moved, limitation "major version change (5 -> 6)…" | pass |
| `test_tampered_candidate_is_skipped` | tampered | demo 1.1 bytes flipped | 1.1 SKIPPED `HASH_MISMATCH`, 1.2 proposed | pass |
| `test_yanked_version_is_skipped` | yanked | demo 1.1 yanked | excluded `YANKED`, 1.2 proposed | pass |
| `test_release_without_a_wheel_is_excluded` | sdist only | demo 1.1 sdist | excluded `NO_WHEEL` | pass |
| `test_candidate_without_an_osv_answer_is_skipped` | no OSV | no answer for 1.1 | 1.1 SKIPPED `ADVISORIES_UNAVAILABLE` | pass |
| `test_escalated_candidate_is_skipped` | escalated | 1.1 re-check escalated | 1.1 SKIPPED, 1.2 proposed | pass |
| `test_no_safe_version_gives_no_repair_found` | none safe | advisory without fix | NO_REPAIR_FOUND `NO_SAFE_CANDIDATE`, package still REJECTED | pass |
| `test_unused_package_gets_a_removal` | removal | project never imports demo | removal diff, lockfile entry removed, re-check `NOTHING_TO_VERIFY` | pass |
| `test_used_package_never_gets_a_removal` | no removal | demo imported | removal None, reason names `app/uses_demo.py` | pass |
| `test_removal_is_not_proposed_when_a_locked_package_depends_on_it` | owner addition | edge other-tool -> Demo | removal None | pass |
| `test_removal_is_not_proposed_when_the_lockfile_records_no_dependencies` | cannot tell | lockfile without edges | removal None | pass |
| `test_hash_mismatch_is_repaired_but_never_removed` | hash case | demo 1.0 tampered | attempted, removal None | pass |
| `test_repair_never_writes_the_project` | Q9 | every file, link and mtime | unchanged; policy and verdict unchanged | pass |
| `test_recheck_is_neither_logged_nor_cached` | isolation | verdict log, cache rows | unchanged | pass |
| `test_exception_inside_repair_gives_no_repair_found` | fail closed | `fetch_releases` raises | NO_REPAIR_FOUND `INTERNAL_ERROR` | pass |
| `test_budget_limits_the_number_of_candidates` | budget | 7 candidates, all UNRESOLVED | 5 tried, `stopped_by: candidates` | pass |
| `test_budget_limits_the_time` | budget | fake clock +40 s per read, 60 s | `stopped_by: time`, < 3 tried | pass |
| `test_package_wide_osv_answer_is_stale_after_24_hours` | owner addition | fake clock +25 h / +23 h | `ADVISORIES_STALE` / PROPOSED | pass |
| `test_policy_range_that_already_covers_the_candidate_needs_no_policy_change` | policy | `demo>=1,<3` | `changed: false` | pass |
| `test_package_that_is_not_rejected_is_not_repaired` | eligibility | VERIFIED pypdf 6.21.4 | NOT_ATTEMPTED, registry not asked | pass |
| `test_symlink_to_a_file_outside_the_project_is_not_copied` | owner addition | `notes.txt` -> outside file; in-project link | outside link skipped, inside kept, outside file and project unchanged | pass |
| `test_copy_that_reads_differently_from_the_project_gives_no_repair_found` | fail closed | `.py` link out of the project | NO_REPAIR_FOUND `COPY_DIFFERS` | pass |
| `test_gate_decision_is_unchanged_with_or_without_a_proposal` | gate | REJECTED 6.19.0, repair on / off | same status, reasons, row status, events; proposal 6.21.4 only when on | pass |
| `test_gate_row_of_a_verified_package_has_no_repair` | gate | VERIFIED | `repair: null` | pass |
| `test_exception_in_the_gate_wiring_keeps_the_verdict` | gate fail closed | `propose_repair` raises | REJECTED, NO_REPAIR_FOUND | pass |
| `test_cavr_live.py::test_live_repair_for_pypdf_6_19_0` | live (`CAVR_LIVE=1`) | real PyPI + OSV | newer pin, re-check VERIFIED, digest = registry, project unchanged | pass (10 s) |

`tests/test_cavr_repair.py`: 26 passed. Before the commit (CAVR, orchestrator, integration, `test_modules.py`; no
pytest-xdist, run serially): 1483 passed, 11 skipped (live). Baseline of the same set before the step: 1457 passed,
10 skipped; no earlier result changed.

### Defects found and fixed

- First run of the new tests: 1 failure, the removal reason said "(imports)"; reworded to "imported at file:line".
- While writing the symlink test: a directory link inside the project makes `context_extractor` report the
  project as not fully read, so the in-project link in the test is a non-`.py` file link.
- Review: the one cavr-reviewer pass runs after step M2-5 (owner's order); its outcome is recorded there.

### Known limitations / deferred

- Project tests are not run on the proposal (Q10, waiting for Sheharyar / SATRA's image builder API): in every block.
- No sandbox or deep analysis on the re-check: an escalated candidate is skipped (Phase 2).
- No resolver: a candidate whose new dependencies are not in the lockfile is UNRESOLVED and skipped.
- No downgrades, no pre-releases, no replacement package (level 4 is future work, Q3); no transitive (level 2) repair.
- `_repair` (orchestrator) and `repair.rank_repairs` stay until PR 12 (owner decision 2026-11-23): the
  `cross_module` LOCAL-lab demo still uses them.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `repair_proposal.py`, the `pypi_client` / `advisories` additions, the gate wiring,
  the tests, the recorded data (fetched from pypi.org and api.osv.dev on 2026-11-23, stored unchanged) and these
  notes. **Reviewed by Maryam:** the plan, the test list and the four additions; the diff not yet. **Verified by:**
  the runs above and the live test.

### Supervisor Q&A prep

1. **Can repair turn a REJECTED into a pass?** No. The block is extra data on the row; status, reasons and the gate
   decision are computed before and without it (`test_gate_decision_is_unchanged_with_or_without_a_proposal`).
2. **Why trust the proposed version?** It went through the same `verify_request` as any request, under the proposed
   policy and lockfile: real wheel hashed against the registry, tree, OSV for that version, contract, AST scan.
3. **Why is 7.x not proposed for 6.19.0?** Same major first: 6.21.4 is a smaller change; 7.x is listed under `not_tried`.

## Step M2-4 — The repair proposal in the report, the dashboard and the VS Code panel (2026-11-23)

Display of the step M2-3 block. Shared files (Q4, `[owner review: …]`): `backend/commands/report.py`,
`frontend/src/components/CavrModule.tsx`, `vscode-asent/src/report.ts` and its unit test.

### Ch 6 Implementation

- `asent-report.json`: no change needed; the `repair` block is in the CAVR evidence rows since step M2-3
  (`assurance.evidence[].details.pipeline[].packages[].repair`).
- `backend/commands/report.py`: `cavr_repairs(report)` and `_patch_lines` add a section "CAVR repair proposals (not
  applied; for a person to approve)" after the module rows: per REJECTED package its result, the pin with its
  re-check and digests, the requirements +/- lines (or the pip command), the lockfile entry, the policy change, the
  removal or why not, skipped candidates, limitations. Read from the evidence record the CAVR module row names.
- `backend/cavr/api.py`: `dashboard_repair(verdict, condition)` runs after the verdict in the worker thread for a
  REJECTED first package (no requirements file on this path: the pin is a `pip install` command), under the same
  demo condition (`_conditions`). The block goes to the verdict event's `repair` and to the proof's `repair`; the
  pipeline verdict object is not changed.
- `frontend/src/components/cavr/RepairTab.tsx`: rewritten to print the block (result, pin / removal card with the
  re-check, digests, diff, lockfile and policy lines, skipped and excluded candidates, limitations). The approve /
  reject buttons stay and only record the decision (`/api/cavr/approve-alternative`, writes nothing to the project).
  `types.ts`: `RepairBlock`, `RepairPart`, `RepairCandidate`. `CavrModule.tsx`: the recorded alternative is the
  pin requirement (or "remove <name>"). `RequirementsTab.tsx`: FR-7 / FR-8 rows name `repair_proposal.py` and
  print the block's result and re-check.
- `vscode-asent/src/report.ts`: `repairLine` adds one key-evidence line after each package with a block, e.g.
  `repair: proposes pin pypdf==6.21.4 (re-check VERIFIED); not applied`.
- `tests/test_cavr_data/render_cavr.mjs`: a `repair` view.

### Design decisions

- **Read from the evidence, not a new report field**: `asent-report.json` keeps schema `asent.gate.v1`; every
  surface reads the same block, so they cannot disagree.
- **Dashboard repair outside `verify_dashboard_request`**: the proof's `cavr_verdict` stays exactly the pipeline's
  answer (an existing test checks equality); the block sits next to it.
- **Same demo condition for candidates**: a demo condition only makes things worse, also for repair.
- **Buttons kept, relabelled "Record approval / rejection"**: Q9 — a person approves; the dashboard only records it.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-7 / FR-10 | The proposal and its evidence are in the report and text output: `test_asent_gate_report_carries_the_repair_block_and_the_same_decision`, `test_asent_report_text_lists_the_proposal` |
| Q9 | Same exit code (1), decision and reasons with and without repair; tab says "Applied: false" |
| FR-7 (dashboard) | `test_dashboard_rejected_run_has_the_proposal_and_keeps_its_verdict`, `test_the_repair_tab_prints_the_proposal_of_the_run` |

### Ch 7 Test cases

`tests/test_cavr_repair_surfaces.py` (recorded data as in step M2-3) and `vscode-asent/test/unit/report.test.ts`.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_asent_gate_report_carries_the_repair_block_and_the_same_decision` | report JSON | `asent gate`, head pins pypdf 6.19.0, repair on / off | exit 1 BLOCK both; same reasons and CAVR result; block PROPOSED pypdf==6.21.4 only when on | pass |
| `test_asent_report_text_lists_the_proposal` | text output | that report | section, pin line with digests, -/+ lines, lockfile, policy, removal reason, limitation; before "Reasons:" | pass |
| `test_asent_report_text_without_a_block_has_no_repair_section` | text output | repair off; empty report | no section | pass |
| `test_dashboard_rejected_run_has_the_proposal_and_keeps_its_verdict` | dashboard | chip known_vulnerable | verdict BLOCK/REJECTED; repair pin via pip command; proof `cavr_verdict` unchanged | pass |
| `test_dashboard_verified_run_has_no_repair` | dashboard | chip verified | repair None | pass |
| `test_dashboard_network_off_is_unresolved_and_gets_no_repair` | dashboard | network_off | UNRESOLVED, repair None | pass |
| `test_dashboard_tampered_wheel_run_gets_no_proposal` | dashboard | tampered (pypdf 6.21.4) | 7.x candidates SKIPPED `RELEASE_NOT_FOUND`, NO_REPAIR_FOUND | pass |
| `test_the_repair_tab_prints_the_proposal_of_the_run` | page render | known_vulnerable run | pin, re-check, digests, command, "Applied: false" | pass |
| `test_the_repair_tab_without_a_block` | page render | verified run | "Not run: …" | pass |
| `test_no_old_repair_fixture_field_is_left_in_the_page` | source | page and parts | no `chosen_candidate`, `ranked_candidates`, `cost_breakdown`, `dependency_diff`, `repair_engine.py`, `reverifier.py` | pass |
| VS Code: 3 tests in "CAVR repair proposal … in the key evidence" | panel | derived block on the ACCEPT fixture | pin line after its package; removal; no repair found; none without a block | pass |

`tests/test_cavr_repair_surfaces.py`: 10 passed. Before the commit (same set as step M2-3): 1493 passed, 11 skipped;
no earlier result changed. Also run because `backend/commands/report.py` changed: `test_cli_report.py`,
`test_gate_cli.py`, `test_vscode_make_fixtures.py`: 55 passed. `npx tsc --noEmit` (frontend): no errors.
`npm test` (vscode-asent): 93 passing, 5 pending.

### Defects found and fixed

- First version of the tampered-wheel dashboard test assumed tampered candidates; the chip is pypdf 6.21.4, whose
  upgrades (7.x) are not served offline, so they are `RELEASE_NOT_FOUND`. Test corrected to what happens.
- `RequirementsTab.tsx` read `repair.chosen_candidate`, which no longer type-checks; its FR-7 / FR-8 rows changed in
  this step instead of step M2-5.
- Review: recorded after step M2-5.

### Known limitations / deferred

- `asent-summary.md` (`backend/gate/summary.py`) does not list the proposal (not asked; the JSON and `asent report` do).
- The VS Code panel shows one line per block, not the diff; the diff is in `asent report`.
- The dashboard's sample project has no lockfile and the request is a pip command, so its proposal has no diff and
  no lockfile entry, and removal is never proposed there.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the code and tests listed above and these notes. **Reviewed by Maryam:** the plan
  (which surfaces); the diff not yet. **Verified by:** the runs above, `npx tsc --noEmit` (frontend), `npm test`
  (VS Code).

### Supervisor Q&A prep

1. **Could the dashboard show a proposal for a package that passed?** No: `dashboard_repair` returns None unless the
   first package is REJECTED (`test_dashboard_verified_run_has_no_repair`).
2. **Does the "Record approval" button install anything?** No. It writes an audit row through the existing endpoint;
   the proposal is applied by a person in a pull request.

## Step M2-5 — Delete `repair_engine.py` and `reverifier.py` (Q12) (2026-11-23)

### Ch 6 Implementation

- Deleted `backend/cavr/repair_engine.py` (210 lines: `calculate_repair_candidates`, per-name hard-coded candidates)
  and `backend/cavr/reverifier.py` (58 lines: `reverify_candidate`, five constant `passed: True` obligations, a
  fixture-faked stub). Nothing imported either: checked with a repository-wide search over `.py`, `.ts`, `.tsx`,
  `.mjs`, `.json`, shell and packaging files before deleting; neither had tests of its own.
- Kept: the two "must not be loaded" lists in `tests/test_cavr_api.py` still name both modules (they now guard
  against the modules coming back). `docs/cavr-m1-plan.md` and earlier report notes mention them as history.
- `docs/cavr-m2-plan.md`: checklist rows 20 and 21 and the Phase 4 progress (PR 15 done; PR 16 fast-gate part done).

### Design decisions

- **Delete now (Q12)**: their replacement (`repair_proposal.py`, steps M2-3 / M2-4) has landed and is tested, and
  the last reader (`RequirementsTab.tsx` FR-7 / FR-8 labels) changed in step M2-4.
- **Not deleted (owner decision 2026-11-23)**: `backend/cavr/repair.py::rank_repairs` and the orchestrator
  `Service._repair`. The `cross_module` LOCAL-lab demo still uses them (`tests/conftest.py::integration_runs`
  with `auto_repair=True`, `test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies`, `main.py` /
  `cli.py --repair`; tests `test_modules.py::test_repair_constraints`,
  `test_cavr_targeted.py::test_repair_rank_ignores_caller_security_functionality_booleans`). That demo swaps a LOCAL
  adapter that is not on PyPI, which the new repair cannot do. They go with the LOCAL lab path in PR 12. The SATRA
  half of `_repair` belongs to SATRA.

### Requirements covered

| ID | Acceptance check |
|---|---|
| Q12 / "no fixture-faked results" | The constant-pass re-verification stub is gone; `test_api_imports_none_of_the_fixture_or_simulation_modules` and `test_the_running_app_loads_none_of_the_fixture_or_simulation_modules` still pass |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_cavr_api.py::test_api_imports_none_of_the_fixture_or_simulation_modules` | guard | `api.py` imports | neither module imported | pass |
| `test_cavr_api.py::test_the_running_app_loads_none_of_the_fixture_or_simulation_modules` | guard | `import backend.main` in a subprocess | neither module loaded | pass |
| `test_cavr_repair_surfaces.py::test_no_old_repair_fixture_field_is_left_in_the_page` | page | page sources | no `repair_engine.py` / `reverifier.py` label | pass |

Before the commit (same set as step M2-3): 1493 passed, 11 skipped; no earlier result changed.

### Defects found and fixed

- None in this step. Review: recorded under "Review of steps M2-3 to M2-5" below.

### Known limitations / deferred

- `repair.rank_repairs` and `Service._repair` remain until PR 12 (above).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the deletion, the plan update and these notes. **Reviewed by Maryam:** the deletion
  list and the decision to keep `_repair` / `rank_repairs` (2026-11-23). **Verified by:** the search and the runs above.

### Supervisor Q&A prep

1. **Why keep `rank_repairs` if repair was replaced?** Q12: a module is deleted only when nothing uses it; the
   `cross_module` demo still does, until PR 12 removes the LOCAL lab path.

## Review of steps M2-3 to M2-5 — fixes (2026-11-23)

Review: 1 pass of cavr-reviewer over 3d241ed..5773e09, verdict "Fix first" (1 BLOCKER, 12 MINOR of which 3 marked
major); BLOCKER and 9 MINOR fixed in this commit, 3 MINOR open (below).

### Ch 6 Implementation

- `repair_proposal._copy_problem` also compares the bytes (`_file_digest`) of the lockfile and of the requirements
  file in the project and in the copy; a link out of the project is not copied, so the difference is
  `COPY_DIFFERS` (BLOCKER). `copy_project` skips the directories `context_extractor` does not read (dot-directories,
  virtual environments, `__pycache__`, `node_modules`); a copy failure is `COPY_FAILED`.
- Removal: another package of the verdict without a complete tree blocks removal; `REMOVAL_LIMITATION` (Python
  imports only) is added to a block with a removal; the lockfile patch also drops the removed package's edges.
- Patches: requirements and lockfile read and written as bytes (a CRLF file keeps CRLF); an approved exact pin is
  matched by version (`_is_exact_pin`: `demo==1` matches 1.0, a wildcard is not a pin).
- The budget clock starts before the release list is read. A `--hash` line limitation is stated.
- `advisories._post_capped`: the live package-wide OSV page is read in chunks, at most 20 MB.

### Design decisions

- **Bytes of the two files, not only the link list**: whatever the cause (a link, an unreadable file), a re-check
  with other inputs than the project's is not evidence about the project.
- **Explicit `edges: []` is trusted** as the lockfile's own statement (review MINOR 4, second half: not changed);
  a missing `edges` key with other packages locked is still "cannot rule out".

### Ch 7 Test cases

`tests/test_cavr_repair_edges.py` (new) and changes in `tests/test_cavr_repair.py`.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_lockfile_that_links_out_of_the_project_gives_no_repair_found` | BLOCKER | lockfile is a link out | `COPY_DIFFERS` | pass |
| `test_requirements_file_that_links_out_of_the_project_gives_no_repair_found` | same, requirements | link made after judging | `COPY_DIFFERS` | pass |
| `test_virtualenv_dot_directories_and_node_modules_are_not_copied` | copy | `.venv`, `env/pyvenv.cfg`, `.secrets/.env`, `node_modules` | skipped, proposal made, project unchanged | pass |
| `test_project_over_the_copy_budget_gives_no_repair_found` | copy budget | `MAX_COPY_FILES = 1` | `COPY_FAILED` | pass |
| `test_fetch_releases_reads_yanked_and_wheel_flags` | reader | yanked, sdist-only, no files, bad version | flags per release; bad version last | pass |
| `test_fetch_releases_failures_are_unresolved` (6) | reader | 404, transport error, bad JSON, other package, bad shapes | `PROJECT_NOT_FOUND` / `REGISTRY_UNAVAILABLE` / `REGISTRY_INVALID` | pass |
| `test_fetch_releases_over_the_size_cap_is_unresolved` | reader | cap 10 bytes; bad name | `REGISTRY_INVALID`; `INVALID_REQUEST` | pass |
| `test_release_wheel_names_the_wheel_and_its_registry_digest_without_downloading` | reader | one wheel | digest, no download | pass |
| `test_release_wheel_failures_are_unresolved` (5) | reader | yanked release / file, no digest, no wheel, other version | `YANKED`, `REGISTRY_DIGEST_MISSING`, `NO_WHEEL`, `REGISTRY_INVALID`; 404 `RELEASE_NOT_FOUND` | pass |
| `test_package_advisories_reads_a_fresh_cache` | OSV | fresh cache | OK, DATED CACHE | pass |
| `test_package_advisories_without_a_cache_or_with_a_damaged_one_is_unavailable` | OSV | none; digest broken | `ADVISORIES_UNAVAILABLE` | pass |
| `test_package_advisories_invalid_list_future_date_and_bad_name` | OSV | bad list, +2 h, unparsable date, bad name | `ADVISORIES_INVALID`, `ADVISORIES_STALE`, `INVALID_REQUEST` | pass |
| `test_package_advisories_stub_without_a_package_query_never_reaches_the_network` | OSV | per-version stub, live | unavailable, nothing cached | pass |
| `test_pin_rewrites_a_continued_line_with_extras_marker_and_hash_and_keeps_crlf` | rewrite | CRLF, `\` continuation, extras, marker, `--hash` | one line, new hash, CRLF kept | pass |
| `test_remove_deletes_every_physical_line_of_the_requirement` | rewrite | continued line | both lines gone | pass |
| `test_requirement_line_must_be_exactly_one_line` | rewrite | two marker lines; other version | None | pass |
| `test_lockfile_patches` | lockfile | pin, removal, edges, bad edges, no lockfile | entry replaced; edges of removed package dropped; reasons | pass |
| `test_policy_exact_pin_is_matched_by_version_not_by_text` | policy | `demo==1`, `demo==1.*` | `demo==1` replaced; wildcard kept | pass |
| `test_pre_release_is_excluded` | rule | 1.1rc1 | `PRE_RELEASE`, 1.2 proposed | pass |
| `test_advisory_range_that_cannot_be_evaluated_excludes_the_release` | rule | GIT range advisory | `ADVISORY_RANGE_UNKNOWN`, no repair | pass |
| `test_requirement_from_an_included_file_gives_no_pin` | rule | `-r base.txt` | `REQUIREMENT_LINE_NOT_FOUND`, nothing tried | pass |
| `test_recheck_wheel_that_differs_from_the_registry_listing_is_skipped` | rule | listing digest replaced | `RECHECK_DIGEST_DIFFERS` | pass |
| `test_removal_is_not_proposed_when_another_package_of_the_request_depends_on_it` | removal | top requires demo | reason names top==1.0 | pass |
| `test_removal_is_not_proposed_when_another_package_has_no_complete_tree` | removal | top unreadable | "not complete" | pass |
| `test_hash_mismatch_is_repaired_but_never_removed` (tightened) | — | demo 1.0 tampered, used | pin 1.1, no removal | pass |
| `test_budget_limits_the_time` (tightened) | — | fake clock | exactly 1.1 tried, `not_tried` [1.2, 1.3], `BUDGET_EXHAUSTED` | pass |

`tests/test_cavr_repair_edges.py`: 33 passed. Before the commit (same set as step M2-3): 1526 passed, 11 skipped;
no earlier result changed.

### Defects found and fixed

- BLOCKER (reviewer): a lockfile linked out of the project was dropped from the copy and the re-check ran without
  it while the copy check passed. Fixed as above; two tests.
- Found by the new tests: a CRLF requirements file lost its CRs in the patch (`read_text` / `write_text` translate
  newlines). Fixed by reading and writing bytes. The test helper `project_response` failed on an unparsable
  version (test fix).
- Reviewer's platform-wheel point (MINOR 5, first half) does not apply: `dep_tree` and `release_wheel` both use the
  host's default tags. The `--hash` half is now a stated limitation.

### Known limitations / deferred (review MINORs left open)

- No overall repair cap per gate run: each REJECTED package gets its own 60 s budget (MINOR 8). The dashboard
  publishes the verdict events after the repair has run (same MINOR).
- A rewritten requirements line drops an inline comment; a pinned lockfile entry keeps only name, version,
  ecosystem, sha256 (MINOR 6).
- Commit `cabee91`'s `[owner review: …]` tag does not name `vscode-asent/test/unit/report.test.ts` (MINOR 11); history
  is not rewritten, recorded here. `docs/cavr-m2-plan.md` is CAVR's own plan (the plan's rule allows it).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the fixes, the tests and these notes; review by the cavr-reviewer agent.
  **Reviewed by Maryam:** not yet. **Verified by:** the runs above.

### Supervisor Q&A prep

1. **If the lockfile is a link out of the project, what did the re-check check?** Nothing is proposed: the copy has
   no lockfile, its bytes differ from the project's, so the result is `COPY_DIFFERS`.
2. **What does a removal's `NOTHING_TO_VERIFY` prove?** Only that the patched requirements file asks for nothing new.
   The evidence for the removal is the import scan and the dependents check; the block states that only Python
   imports are seen.

## Step M2-6 — Repair budget per gate run (2026-11-23)

Owner request after the review (open MINOR 8: no overall repair cap per gate run).

### Ch 6 Implementation

- `backend/cavr/gate_adapter.py`: `REPAIR_RUN_SECONDS = 120.0`, `RUN_BUDGET_USED_UP`, `CLOCK` (`time.monotonic`).
  `analyze_pipeline` keeps `repair_spent`, the seconds spent inside repair in this run; `_repair` measures each call
  with `CLOCK` and adds it. Before a REJECTED package: nothing left -> NOT_ATTEMPTED / `RUN_BUDGET_USED_UP`,
  "repair budget for this run used up", and the registry is not asked; otherwise `propose_repair` gets
  `budget_seconds = min(60, what is left of the run)` and the same clock.
- `backend/cavr/repair_proposal.py`: `not_attempted(name, version, package, rule, reason)`, a NOT_ATTEMPTED block
  with every key.

### Design decisions

- **Only repair time counts** (alternative: wall time since the start of the run): the verdicts themselves must not
  use up the repair budget; `test_run_budget_counts_repair_time_only`.
- **Per-package budget cut to what is left**: the run total then also holds between the candidates of the last
  package, not only between packages.
- **Checked before a package starts**, like the per-package budget: a repair already running is not stopped, so a
  run can go past 120 s by at most one candidate check.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-7 / NFR (bounded cost) | Repair time of one gate run is bounded: `test_run_budget_is_shared_by_all_rejected_packages` |
| Q9 | Verdicts unchanged when repair is cut: all three packages stay REJECTED, module REJECTED |

### Ch 7 Test cases

`tests/test_cavr_repair.py` (fake clock `gate_adapter.CLOCK`; three REJECTED packages: the real pypdf 6.19.0 with
its recorded advisories, synthetic `demo` and `top` with SYNTH- advisories).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_run_budget_is_shared_by_all_rejected_packages` | run budget | each repair takes 70 s | budgets passed 60 s, 50 s; 3rd NOT_ATTEMPTED `RUN_BUDGET_USED_UP`; all REJECTED | pass |
| `test_run_budget_counts_repair_time_only` | only repair time | pipeline takes 500 s per file | all three repaired (fake), none NOT_ATTEMPTED | pass |
| `test_run_budget_used_up_never_asks_the_registry` | nothing left | `REPAIR_RUN_SECONDS = 0` | all NOT_ATTEMPTED, no release list fetched | pass |

Run before the commit, as asked (repair and gate tests only: `tests/test_cavr_repair*.py`,
`tests/test_cavr_gate_adapter.py`, `tests/test_gate_*.py`): 166 passed, 1 skipped (live).

### Defects found and fixed

- First version started the run clock before the pipeline ran, so verification time counted against the repair
  budget; changed to summing the time spent in repair (test above).
- Review: no cavr-reviewer pass for this commit (owner asked for the tests above only).

### Known limitations / deferred

- The dashboard still publishes the verdict after the repair (rest of review MINOR 8). The dashboard path repairs
  one package per run, so the per-package 60 s bounds it.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the change, the tests and these notes. **Reviewed by Maryam:** the requirement
  (120 s, NOT_ATTEMPTED wording, fake clock with 3 packages). **Verified by:** the run above.

### Supervisor Q&A prep

1. **Can a gate run with many vulnerable packages take forever in repair?** No: at most 120 s of repair per run
   (plus one candidate check in progress); later packages say NOT_ATTEMPTED with the reason.

## Step M2-7 — PR 3: CAVR's own sandbox image and its identity check (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 3, decisions Q5 to Q7. Not wired into `verify_request` or the gate yet (Phase 2b).

### Ch 6 Implementation

- `docker/cavr-sandbox/Dockerfile` (new): `FROM python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`
  (Debian 13), installs `strace` (6.13) and `libfaketime`, adds user `cavr` UID/GID 10001. No ENTRYPOINT.
- `docker/cavr-sandbox/build.sh` (new): runs `python -m backend.cavr.sandbox_image build`.
- `docker/cavr-sandbox/cavr-seccomp.json` (new): CAVR-only copy of the shared profile plus 47 measured syscalls,
  in commented groups (see design decisions).
- `backend/cavr/sandbox_image.py` (new): `IMAGE = "asent-cavr-sandbox:local"`; `build()` runs `docker build --label
  org.asent.cavr.recipe-sha256=<SHA-256 of the Dockerfile>`, reads the ID with `docker image inspect`, writes
  `{image, image_id, recipe_sha256, base, built_at}` to `DATA/cavr/sandbox-image.json`; `image_identity()` is ok only
  when the image exists, its ID equals the recorded one and its label equals the current Dockerfile's SHA-256.
  Rules: ENGINE_UNAVAILABLE, IMAGE_MISSING, IMAGE_NOT_RECORDED, IMAGE_ID_MISMATCH, IMAGE_STALE, SECCOMP_MISSING,
  ENGINE_ERROR. Never raises.
- `backend/cavr/sandbox_exec.py` (new): `lockdown_flags()` and `docker_command(name, image_id, command, mounts, env)`,
  the only builder of a CAVR `docker run`: the image is passed by its checked ID, every mount is a `readonly` bind,
  only listed variables are passed, a bad name / tag / mount / variable raises ValueError.
- `backend/cavr/sandbox_runner.py`: the hardcoded `image_digest` constant is removed; the legacy result field is
  `image_id: None` (that runner never checked its image; it goes with PR 12).
- `tests/test_cavr_support.py`: `docker_skip_reason`, `requires_docker`, `sandbox_identity()` (builds once per
  session if missing), `cavr_containers()`.
- `.github/workflows/ci.yml`: new job `cavr-docker` (builds the image, runs `tests/test_cavr_sandbox_*.py` with
  `CAVR_DOCKER=1`, fails if a `cavr-*` container is left).

### Design decisions

- **Expected image ID recorded at build time, not a constant** (alternative: commit the ID): `docker build` is not
  reproducible (apt packages change), so a committed ID would be wrong on every other machine. The recipe label ties
  the image to the Dockerfile in this checkout, so an image built from an older Dockerfile is IMAGE_STALE.
- **Run by image ID, not tag** (alternative: `asent-cavr-sandbox:local`): the tag could be moved between the check and
  the run.
- **CAVR-only seccomp profile.** The shared `docker/asent-seccomp.json` (57 syscalls, default ERRNO) cannot start a
  container on this engine: runc fails at init with `fstatfs fsmount:fscontext:proc: operation not permitted`
  (exit 125, Docker 29.9.3, 2026-11-23). It also lacks `execve`, `clone`, `wait4`, `ptrace`, `socket`, `connect`.
  The shared file is not changed; the CAVR copy keeps its first entry byte-identical and adds 47 names. Method: the
  full flow (strace -u, pip install of a wheel, import, connect/sendto/IPv6/Unix attempts, os.system, threads, fork,
  setuid(0), prctl, kill) was measured with `strace -c` under Docker's default profile (72 syscalls), and the runc and
  strace needs were found by removing each candidate in turn and comparing the output with the default-profile run.
  Groups, each with its reason in the JSON `comment`: runc init (`close_range`, `execve`, `fstatfs`, `statx`);
  strace (`kill`, `ptrace`, `setgroups`, `setregid`, `setreuid`, `wait4`); strace start-up (`process_vm_writev`,
  `rt_sigsuspend`: removing them gave one failed run in 40); process starts (`clone`, `clone3`, `prctl`,
  `set_tid_address`, `setuid`, `vfork`); sockets (`bind`, `connect`, `getpeername`, `getsockname`, `sendto`,
  `setsockopt`, `socket`), allowed so that attempts reach the kernel and are recorded, while `--network none` makes
  them fail; Python, pip and import (22 file and process syscalls). Never added: mount, namespaces, modules, BPF,
  keyrings, clock setting, reboot (test). With the profile, 20 of 20 runs of the flow gave the same output as
  Docker's default profile.
- **The profile works only with CAVR's flags.** Without `--cap-drop ALL`, runc also needs `capget`; CAVR always drops
  all capabilities, so it is not added.
- **Container user is root** (`Config.User` empty): strace is the container's process (Q5); package code runs as
  10001 through `strace -u cavr` (PR 5 proves it per process).

### Requirements covered

| ID | Acceptance check |
|---|---|
| NFR-1 (rule 5, pinned image) | `test_dockerfile_base_is_pinned_by_digest`; missing / mismatched / stale / unrecorded image -> not ok (6 tests) |
| NFR-1 (rules 1-4) | `test_running_container_has_every_lockdown_flag` reads `docker inspect` of a running container |
| NFR-1 (rule 1) | `test_container_has_only_loopback`: `/sys/class/net` is `lo` only |
| FR-6 fail closed | no engine, inspect error, unreadable record, missing seccomp profile -> not ok, never raises |
| Q6, Q7 | image `asent-cavr-sandbox:local` != SATRA's; strace and libfaketime present (Docker test) |

### Ch 7 Test cases

`tests/test_cavr_sandbox_image.py`: 41 tests, 35 unit (fake `sandbox_image.RUN`) and 6 Docker.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_recorded_image_built_from_the_current_dockerfile_is_ok` | happy path | inspect ID = record, label = Dockerfile SHA | ok, IMAGE_OK | pass |
| `test_missing_image_is_unresolved` | no image | inspect "No such image" | IMAGE_MISSING | pass |
| `test_image_id_mismatch_is_unresolved` | rebuilt / re-tagged | inspect ID != record | IMAGE_ID_MISMATCH | pass |
| `test_no_build_record_is_unresolved`, `test_unreadable_build_record_is_unresolved` (4) | built another way | no / bad record | IMAGE_NOT_RECORDED | pass |
| `test_stale_recipe_label_is_unresolved`, `test_image_without_labels_is_stale` | old Dockerfile | wrong / no label | IMAGE_STALE | pass |
| `test_no_engine_is_unresolved` (4) | no engine | no binary, timeout, permission, daemon down | ENGINE_UNAVAILABLE | pass |
| `test_inspect_error_is_unresolved` (4) | odd engine | exit 2, garbage, non-sha256 ID, exception | ENGINE_ERROR | pass |
| `test_missing_seccomp_profile_is_unresolved` | profile gone | absent file | SECCOMP_MISSING, engine not asked | pass |
| `test_build_records_the_built_image_id`, `test_failed_build_writes_no_record`, `test_build_without_engine_is_not_ok` | build | fake build | record written only on success | pass |
| `test_dockerfile_base_is_pinned_by_digest`, `test_image_is_cavr_own_not_satra` | recipe | Dockerfile | digest pin, strace, libfaketime, UID 10001 | pass |
| `test_sandbox_runner_has_no_hardcoded_digest` | Q12 | `sandbox_runner.py` | no constant | pass |
| `test_shared_profile_lacks_what_strace_and_runc_need` | finding | shared profile | 9 needed names missing | pass |
| `test_cavr_profile_is_the_shared_profile_plus_listed_additions` | smallest addition | CAVR profile | shared entry identical, 47 commented additions, no dangerous names | pass |
| `test_lockdown_flags_are_the_planned_set`, `test_docker_command_runs_the_image_by_id_with_read_only_mounts` | flags | — | exact list; ID last; readonly; no --user/-v/-i/--privileged | pass |
| `test_docker_command_refuses_what_it_cannot_pass_safely` (6) | bad input | bad name, tag, comma mount, relative path, bad variable | ValueError | pass |
| `test_real_image_identity_is_its_inspected_id` (Docker) | real check | built image | ok, ID = `docker image inspect` | pass |
| `test_image_has_strace_and_libfaketime` (Docker) | Q7 | image | strace, `libfaketime.so.1`, `id -u cavr` = 10001 | pass |
| `test_python_and_strace_start_under_the_cavr_profile` (Docker) | profile | `strace -f -u cavr python -c` | `10001 10001`, `+++ exited with 0 +++` | pass |
| `test_the_shared_profile_is_not_used_and_would_not_start_python` (Docker) | finding | shared profile | non-zero exit; not in CAVR flags | pass |
| `test_running_container_has_every_lockdown_flag` (Docker) | rules 1-4, 9 | running container | every HostConfig field as planned | pass |
| `test_container_has_only_loopback` (Docker) | rule 1 | `/sys/class/net` | `lo` | pass |

Runs before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_image.py`: 41 passed;
`CAVR_DOCKER=1 pytest tests/test_cavr_*.py`: 1478 passed, 11 skipped (live, `CAVR_LIVE` unset) in 424 s; CI, packaging and resource tests
(`test_satra_runner_image`, `test_gate_packaging`, `test_cli_workflow`, `test_cli_packaging`, `test_cli_resources`,
`test_cli_doctor`): 61 passed. No existing result changed.

### Defects found and fixed

- First profile candidate failed at runc init (`statx … could not get mount id`) and then in strace
  (`setregid: Operation not permitted`); both added with their reasons.
- Tests: none failed after the code was written.

### Known limitations / deferred

- The CI job is not verified: nothing is pushed (GitHub's Ubuntu runner may need other syscalls for its runc).
- `process_vm_writev` and `rt_sigsuspend` are kept on one failed run in 40 without them; the cause was not found.
- The profile is denied-by-default: a package whose import needs a syscall outside it fails, which is UNRESOLVED
  (fail closed), never VERIFIED.
- The legacy `SandboxRunner`, `docker/asent-sandbox/Dockerfile` and `counterfactual.py` stay until PR 12 (Q12).

### Note for Sheharyar (owner of the shared `docker/asent-seccomp.json`)

The shared profile cannot start a container on current runc (Docker 29.9.3): runc's init needs `fstatfs` and `statx`
after the filter is loaded, and fails with `error closing exec fds: get handle to /proc/thread-self/fd: fstatfs
fsmount:fscontext:proc: operation not permitted`. CAVR does not use it and did not change it.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the image, profile, build script, both modules, the CI job, the tests and these notes.
  **Reviewed by Maryam:** the plan and decisions (2026-11-23). **Verified by:** the runs above on Docker 29.9.3.

### Supervisor Q&A prep

1. **Why not use the repository's seccomp profile?** It cannot start a container on current runc; CAVR uses a copy
   with 47 measured additions, each group explained, and the shared one is unchanged.
2. **How do you know the image a run uses is the one you built?** The run names the image by the ID recorded at
   build time, after checking that the local image still has that ID and carries the current Dockerfile's SHA-256.

## Step M2-8 — PR 4: deadline, kill, output caps and removal of the real container (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 4 (Q8: 20 s per run). Closes the three M1 deferred runner items (silent container
not timed out, kill stops the docker CLI and not the container, invalid UTF-8 leaves the process un-waited) for
CAVR's new runner; the legacy `SandboxRunner` keeps them until PR 12.

### Ch 6 Implementation

- `backend/cavr/sandbox_exec.py`: `run_container(cmd, name, deadline=20, grace=5, stdout_cap=1 MiB,
  stderr_cap=16 MiB)`, `completed(result)`, `new_run_id()` (12 hex), `container_name(run_id, n)` = `cavr-<run>-<n>`.
  Algorithm: `Popen` with stdin `/dev/null`; two reader threads drain stdout and stderr as bytes into capped buffers
  (bytes past the cap are counted, not kept, and wake the main thread); the main thread waits on the host's
  monotonic clock. At the deadline or a cap: `docker kill <name>`, then kill and wait for the docker CLI. In a
  `finally`: `docker rm -f <name>` until `docker ps -a --filter name=^/<name>$` is empty, or LEFT_BEHIND.
  Statuses: COMPLETED (own exit; code kept), TIMEOUT, OUTPUT_CAP, KILLED (137 not sent by CAVR: memory limit),
  ENGINE_ERROR (no docker, or `docker run` exit 125/126/127), LEFT_BEHIND. Only COMPLETED with exit 0 is usable.

### Design decisions

- **Deadline independent of output** (alternative, M1: check the clock after each `readline`): a silent container
  never returns from `readline`; the reader threads make the deadline a plain clock check.
- **Kill by container name, then the CLI** (M1 killed only the CLI, which leaves the container running).
- **Any stream over its cap is UNRESOLVED and killed at once** (alternative: keep reading and truncate): an untrusted
  flood of stdout or a trace past 16 MiB cannot be judged; killing early also bounds the run.
- **Removal is checked, not assumed** (`--rm` removes asynchronously): a container still listed after removal is
  LEFT_BEHIND, which is UNRESOLVED.
- **Docker tests use a 2-3 s deadline** to keep the suite fast; the 20 s default is checked by a unit test.

### Requirements covered

| ID | Acceptance check |
|---|---|
| NFR-1 rule 4 (limits, deadline) | infinite loop TIMEOUT after 3.37 s with a 3 s deadline (<= deadline + 5 s); fork bomb stops at the pids limit (EAGAIN, < 64 forks); memory hog KILLED |
| NFR-1 rule 9 (disposable) | `docker ps -a` lists no `cavr-*` container after every Docker test, including failed runs |
| FR-6 fail closed | timeout, cap, foreign kill, engine error, leftover container: never usable |
| Q8 | `DEADLINE_SECONDS == 20.0` |

### Ch 7 Test cases

`tests/test_cavr_sandbox_exec.py`: 30 tests, 22 unit (fake `docker run` with real OS pipes, fake `docker kill/rm/ps`)
and 8 Docker.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_the_default_deadline_is_twenty_seconds_per_run` | Q8 | constants | 20 s, grace 5 s | pass |
| `test_silent_container_is_killed_at_the_deadline` | silent run | no output, 0.3 s deadline | TIMEOUT within deadline + grace; CLI killed and waited | pass |
| `test_kill_and_removal_target_the_container_name`, `test_kill_happens_before_the_cli_process_is_killed` | kill target | timeout | `docker kill <name>` before the CLI kill; `ps -a` by name | pass |
| `test_output_does_not_keep_a_container_alive_past_its_deadline` | chatter | output every 10 ms | TIMEOUT < 1.5 s | pass |
| `test_finished_container_is_completed_with_its_exit_code`, `test_non_zero_exit_is_completed_but_not_usable` | own exit | exit 0 / 3 | COMPLETED, usable only for 0 | pass |
| `test_docker_failure_and_foreign_kill_are_not_completed` (5) | engine / OOM | 125, 126, 127, 137, -9 | ENGINE_ERROR / KILLED | pass |
| `test_invalid_utf8_is_replaced_not_fatal` | M1 item | `\xff\xfe`, `\xc3(` | U+FFFD in text, bytes kept | pass |
| `test_output_over_the_cap_is_killed_and_unresolved` (2), `test_output_over_the_cap_at_exit_is_still_unresolved` | cap | 5000 bytes, cap 1000 | OUTPUT_CAP, 1000 bytes kept | pass |
| `test_docker_that_cannot_start_is_an_engine_error_and_is_still_cleaned_up` (3), `test_no_docker_binary_at_all_returns_without_waiting` | no engine | Popen raises | ENGINE_ERROR, removal still checked, < 1 s | pass |
| `test_container_still_listed_after_removal_is_left_behind` | leak | `ps -a` keeps listing | LEFT_BEHIND, `rm -f` tried | pass |
| `test_names_are_unique_and_well_formed` | names | 1000 names | 1000 distinct `cavr-<12 hex>-<n>` | pass |
| `test_infinite_loop_is_killed_within_deadline_plus_grace` (Docker) | deadline | `while True: pass`, 3 s | TIMEOUT, 3.0 <= elapsed <= 8.0, no container | pass |
| `test_sleeping_container_is_killed_and_removed` (Docker) | deadline | `sleep 600`, 2 s | TIMEOUT, removed | pass |
| `test_failed_run_leaves_no_container` (2, Docker) | failed run | `/nonexistent`; exit 3 | ENGINE_ERROR / COMPLETED not usable; none left | pass |
| `test_fork_bomb_stops_at_the_pids_limit` (Docker) | pids | fork until error | < 64 forks, errno 11 | pass |
| `test_memory_hog_is_killed_and_unresolved` (Docker) | memory | 16 MiB blocks | KILLED | pass |
| `test_flood_of_output_is_capped_and_killed` (Docker) | cap | `yes` | OUTPUT_CAP, 1 MiB kept | pass |
| `test_invalid_utf8_from_a_real_container_is_replaced` (Docker) | UTF-8 | `a\xffb` | `a�b` | pass |

Runs before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_exec.py`: 30 passed;
`CAVR_DOCKER=1 pytest tests/test_cavr_*.py`: 1508 passed, 11 skipped (live) in 403 s. No existing result changed.

### Defects found and fixed

- None found by the tests after the code was written; the order test was rewritten once to be readable.

### Known limitations / deferred

- `docker kill` needs the engine: if the daemon dies mid-run, removal cannot be checked and the run is LEFT_BEHIND
  (UNRESOLVED) after grace + 20 s.
- The legacy `SandboxRunner` (used only by `counterfactual.py` and its tests) still has the M1 runner items; PR 12.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the runner, the tests and these notes. **Reviewed by Maryam:** the plan (20 s,
  unique names, TIMEOUT -> UNRESOLVED, no container left). **Verified by:** the runs above on Docker 29.9.3.

### Supervisor Q&A prep

1. **What stops a package from hanging the gate?** The host's clock: at 20 s the container is killed by name and
   removed, whatever it prints or does not print; the result is TIMEOUT, which is UNRESOLVED.
2. **How do you know no container is left?** After every run the runner lists containers of that name with
   `docker ps -a`; each Docker test also asserts that no `cavr-*` container exists.

## Step M2-9 — PR 5: behaviour evidence from a trace the package cannot write (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 5, decision Q5. Closes the M1 "report forgery" item for the new path: the result is
read only from strace's trace; the package's output is shown as untrusted and never parsed.

### Ch 6 Implementation

- `backend/cavr/sandbox_harness.py` (new, trusted, stdlib only, mounted read-only at `/opt/cavr/harness.py`). Its first
  statement (`if __name__ == "__main__": posix.dup2(open("/dev/null"), 2)`) points fd 2, strace's stderr, at
  /dev/null before any import. `main`: closes stdin, pops `CAVR_RUN_NONCE`, makes itself non-dumpable (`prctl
  PR_SET_DUMPABLE 0`), runs each job step as a child (env from `CHILD_ENV` + the job's own, stdin /dev/null, stdout and
  stderr to the container's stdout), refuses a step whose argv or env would carry the nonce, after each step sends
  `kill(-1, SIGKILL)` until ESRCH (only as UID 10001 from `/opt/cavr/harness.py`), and marks each phase with a failed
  `stat("/.cavr/<nonce>/<phase>")`. Exit 0 / 3 bad job / 4 step failed / 5 internal.
- `backend/cavr/sandbox_trace.py` (new): `check_trace(data, nonce, steps)`. Every line must be a strace line with a
  PID; the first is the harness's execve; every PID is the harness's or returned by clone/clone3/fork/vfork of a known
  PID (resolved over the whole trace, since a child's first line can come before its parent's clone returns); every
  process has one exit line and nothing after it; the last line is the harness's `+++ exited with 0 +++`; the harness's
  markers are exactly `start, step:<s>:begin, step:<s>:end:0 ..., end:ok` with this nonce; no other process uses the
  nonce. Returns each process's parent and step (by PID).
- `backend/cavr/sandbox_observe.py` (new): `run_harness(steps, mounts, tmpfs, deadline, stderr_cap, run_id, n)`.
  Checks the image, makes a 32-hex nonce, writes `job.json` into a temporary directory mounted read-only at `/job`,
  runs `strace -f -q --always-show-pid -s 1024 -e trace=%file,%network,%process,%creds -u cavr -- /usr/local/bin/python
  -I -S /opt/cavr/harness.py /job/job.json` with `--env CAVR_RUN_NONCE=<nonce>`, then `check_trace`. Always UNRESOLVED
  in Phase 2a: a complete run is `DEEP_NOT_JUDGED` (judging is PR 7 / PR 8); the evidence has image ID, seccomp and
  harness SHA-256, container name, exit code, elapsed time, trace SHA-256, lines and the process map.
- `tests/test_cavr_data/traces/harness-two-steps.{txt,json}`: a real trace (706 lines) recorded 2026-11-23 from
  `run_harness` with a fixed nonce, with the docker command, image ID and SHA-256.

### Design decisions

- **The trace is strace's stderr stream, not a file in a root-only tmpfs** (plan text; changed in the plan review,
  approved 2026-11-23): a file in a tmpfs needs a second root process to carry it out after strace ends, which would
  break "only strace runs as root". Only strace holds the stream: the harness drops its copy first, children get
  /dev/null and the stdout pipe, and `/proc/1/fd` (strace, root) is EACCES for UID 10001 (Docker test).
- **`--always-show-pid`** (strace 6.13): without it, lines of a single live process have no PID, so they cannot be
  attributed; with it every line is `<pid> ...`.
- **The harness never runs package code itself and is non-dumpable**: a child of the same UID cannot read its
  environment (the nonce) or write its memory through `/proc/<pid>/mem` (EACCES, Docker test). Only lines with the
  harness's PID count as markers.
- **Nonce only in strace's environment** (owner's request): not in the job file, not in any child's argv or env
  (unit tests on both the host's `job_file` and the harness's `read_job`); new per run.
- **Fill the trace**: there is no file to fill; a flood of syscalls passes the 16 MiB stderr cap and the run is
  OUTPUT_CAP (Docker test with a 512 KiB cap). **Delete the trace**: there is no file; unlinking `/proc/1/fd/2` is EACCES.
- **Leftover processes are killed by the harness after each step** (kill(-1) as UID 10001 reaches no root process):
  otherwise strace waits for them and the run times out.
- **`chdir` is not in the seccomp profile**, so the harness passes no `cwd` (the image's WORKDIR is /tmp) instead of
  widening the profile. Likewise `setsid` is not allowed: `start_new_session=True` fails with EPERM.

### Requirements covered

| ID | Acceptance check |
|---|---|
| NFR-1 (package code never runs as root) | `test_package_code_never_runs_as_root`: `docker top` during the run lists only `strace` as root, every other process UID 10001; `setuid(0) = -1 EPERM`; every getuid/geteuid in the trace is 10001 |
| FR-13 (trusted observation) | a package cannot open, list or unlink strace's fds, read the harness's environ or mem, or write the job or harness (9 attempts refused); the trace stays complete with one harness exit line |
| FR-6 fail closed | truncated, tampered, forged, filled or cut traces and a killed harness are UNRESOLVED (unit + Docker) |
| M1 report-forgery item | `test_report_markers_in_the_package_output_change_nothing`, `test_package_printing_a_fake_report_is_ignored` |

### Ch 7 Test cases

`tests/test_cavr_sandbox_trace.py`: 64 tests, 56 unit and 8 Docker.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_recorded_trace_is_what_its_metadata_says`, `test_recorded_trace_is_complete_and_maps_each_process_to_its_step` | baseline | recorded trace | complete; root 9; steps probe [10], second [12]; 11 child of 10 | pass |
| `test_empty_trace_is_incomplete` | empty | "" | TRACE_EMPTY | pass |
| `test_trace_cut_in_the_middle_of_a_line_is_incomplete`, `..._without_its_last_lines_...`, `..._without_the_harness_exit_line_...`, `test_trace_cut_at_half_is_incomplete` | truncation | cut traces | TRACE_TRUNCATED / incomplete | pass |
| `test_harness_exit_code_other_than_zero_is_incomplete`, `test_line_after_the_harness_exited_is_incomplete`, `test_child_without_an_exit_line_is_incomplete` | tamper | edited exits | TRACE_TRUNCATED | pass |
| `test_line_from_a_pid_nobody_created_is_incomplete` | injection | PID 77 line | TRACE_UNKNOWN_PID | pass |
| `test_a_line_that_is_not_a_strace_line_is_incomplete` (5) | stray text | traceback, bare exit line, strace message, ... | TRACE_MALFORMED | pass |
| `test_first_line_that_is_not_the_harness_execve_is_incomplete` | other program | execve of /tmp/evil.py | TRACE_NOT_HARNESS | pass |
| `test_missing_end_marker_is_incomplete`, `test_a_failed_step_marker_is_incomplete`, `test_wrong_nonce_is_incomplete`, `test_steps_other_than_the_job_are_incomplete` | markers | edited markers | TRACE_MARKERS | pass |
| `test_marker_with_this_runs_nonce_from_a_package_process_is_incomplete` / `test_marker_guess_from_a_package_process_changes_nothing` | forgery | marker from PID 12 | nonce used -> TRACE_MARKERS; a guess -> still complete | pass |
| `test_unreadable_input_is_incomplete_not_an_exception` | robustness | None, bad bytes | incomplete | pass |
| `test_the_harness_sends_fd_2_to_dev_null_before_any_import` | first statement | AST of the harness | statement 0 is the dup2; imports after; `os.close(0)` in main | pass |
| `test_strace_starts_the_harness_with_isolated_python_and_no_site` | `-I -S`, `-u cavr` | STRACE | as planned | pass |
| `test_the_nonce_is_in_no_child_argv_or_environment` | nonce | job + host env with a fake secret | no nonce, no host variable in any child | pass |
| `test_a_step_that_would_carry_the_nonce_is_refused` (3), `test_a_malformed_job_is_refused` (5) | job | nonce in argv / env value / env key; bad jobs | ValueError (harness and host) | pass |
| `test_leftover_processes_are_killed_until_none_is_left`, `test_kill_minus_one_is_never_sent_outside_the_sandbox` | cleanup | fake kill; this host | 3 rounds; never on the host | pass |
| `test_harness_writes_nothing_to_its_stderr_even_when_a_step_does`, `test_harness_exit_codes` (4) | harness run on the host | steps writing stderr; failing / missing / bad nonce / empty | stderr empty; exit 0, 4, 4, 3, 3 | pass |
| `test_complete_run_is_unresolved_not_judged`, `test_report_markers_in_the_package_output_change_nothing`, `test_the_nonce_is_passed_only_to_the_container_environment` | run_harness | fake run with the recorded trace | DEEP_NOT_JUDGED; forged stdout changes nothing; nonce once, in `--env`, new per run | pass |
| `test_a_run_that_did_not_complete_is_unresolved` (5), `test_harness_exit_other_than_zero_is_unresolved`, `test_incomplete_trace_is_unresolved`, `test_image_problem_runs_nothing`, `test_a_fault_is_unresolved_internal_error`, `test_a_bad_step_is_unresolved` | fail closed | each failure | its rule, UNRESOLVED; nothing run on an image problem | pass |
| `test_benign_step_gives_a_complete_trace` (Docker) | happy path | print | DEEP_NOT_JUDGED, trace complete | pass |
| `test_package_code_never_runs_as_root` (Docker) | NFR-1 | 2 forks + sh + setuid(0) | only strace root; all others 10001 | pass |
| `test_package_cannot_open_strace_fds_and_the_trace_stays_complete_and_unforged` (Docker) | owner's test | 9 attempts on /proc/1/fd, harness /proc, mounts; forged lines on stdout and stderr | 9 refused (EACCES 13 x8, EROFS 30 x1); complete; one harness exit line, last | pass |
| `test_package_that_fills_the_trace_is_unresolved` (Docker) | fill | stat loop, cap 512 KiB | SANDBOX_OUTPUT_CAP | pass |
| `test_package_that_kills_the_harness_is_unresolved` (Docker) | cut | kill(ppid, SIGKILL) | SANDBOX_KILLED (exit 137) | pass |
| `test_package_that_exits_with_an_error_is_unresolved` (Docker) | failure | exit 7 | SANDBOX_EXIT_NONZERO, `step:probe:end:7` | pass |
| `test_package_printing_a_fake_report_is_ignored` (Docker) | forgery | old report markers | DEEP_NOT_JUDGED; markers only in output | pass |
| `test_background_process_left_by_a_step_is_killed_and_the_run_ends` (Docker) | leftovers | forked child sleeps 600 s | complete < 15 s; `killed by SIGKILL` in trace | pass |

Runs before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_trace.py`: 64 passed;
`CAVR_DOCKER=1 pytest tests/test_cavr_*.py`: 1 failed, 1571 passed, 11 skipped (the failure is the strace defect below); after the fix, `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_{image,exec,trace}.py`: 135 passed; 80 of 80 benign runs and 80 of 80 runs with fork, threads and subprocess complete. No existing result changed.

### Defects found and fixed

- **strace start-up race (found by the CAVR suite):** `test_benign_step_gives_a_complete_trace` failed once with exit 1;
  40 repeated runs reproduced it once: `strace: test_ptrace_seize: unexpected wait status 0`. strace's self-test forks a
  child that calls `pause()` and expects to kill it; `pause` was not in the CAVR profile, so the child got EPERM and
  sometimes exited first. Fix: `pause` added to the profile (comment says why). The same race explains the one failed
  run in 40 of the PR 3 measurement, so `process_vm_writev` and `rt_sigsuspend`, kept then for that run, are removed
  (80 of 80 runs without them). The profile now has **46** additions, not 47 as written in Step M2-7;
  `test_cavr_profile_is_the_shared_profile_plus_listed_additions` checks 46. The failure was UNRESOLVED, never VERIFIED.
- First smoke run: the step failed with `chdir("/tmp") = -1 EPERM` (not in the profile); `cwd` removed.
- Without `--always-show-pid` the single-process lines had no PID (found before the checker was written).
- `test_background_process_left_by_a_step_is_killed_and_the_run_ends` first used `start_new_session=True`, which
  fails under the profile (setsid EPERM); changed to a plain fork.

### Known limitations / deferred

- A package can end its own import early (`os._exit(0)`); what it did before is in the trace, but the early exit is
  not detected as such.
- `chdir`, `setsid` and other syscalls outside the profile fail with EPERM: such a package's run is incomplete
  (UNRESOLVED), never VERIFIED.
- Events are not normalised (PR 7) or judged (PR 8); the result is never VERIFIED until PR 9.
- strace's `+++ superseded by execve +++` (execve from a non-leader thread) is accepted as an exit line but no test
  produces it.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** harness, trace check, run_harness, recorded trace, tests and these notes.
  **Reviewed by Maryam:** the trace-channel design and the first-statement / nonce rules (2026-11-23).
  **Verified by:** the runs above on Docker 29.9.3.

### Supervisor Q&A prep

1. **Can the package write a fake clean trace?** No process of UID 10001 holds the trace stream or can reach strace's
   fds; a forged line printed to stdout or stderr goes to the untrusted output. A missing, cut or reordered line makes
   the trace incomplete, which is UNRESOLVED.
2. **How do you know package code never ran as root?** strace starts the harness as 10001; `docker top`, the host's
   view, listed only strace as root while the package's processes ran; `setuid(0)` failed with EPERM.
3. **Why not trust the harness's own report?** It shares a UID with the package's processes; the verdict reads only
   what strace (root) wrote, and the harness's lines count only by its PID.

## Step M2-10 — PR 6: install the verified wheels and import their top-level modules in the sandbox (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 6, sandbox rules 2 and 6. Closes the M1 item "`harness.py` reports
`test_passed: True` without importing" by deleting `harness.py`. Not wired into `verify_request` or the gate (2b).

### Ch 6 Implementation

- `backend/cavr/sandbox_observe.py`: `observe(nodes, modules, quarantine_dir, deadline, run_id, n)`,
  `stage_wheels(nodes, quarantine_dir, stage_dir)`, `install_steps(modules)`, `check_modules(modules)`, `NotStaged`.
  Algorithm: (1) each tree node must be a verified wheel: name and version of safe characters, a `.whl` filename equal
  to the file's own name, a 64-hex sha256, a regular file (no symlink) inside CAVR's quarantine, no name twice;
  (2) its bytes are read once, hashed and compared with the tree's sha256, then written to a per-run staging directory
  (0644) with `hashes.txt` (`name==version --hash=sha256:...`); (3) `run_harness` mounts the staging directory read-only
  at `/pkg` and adds the tmpfs `/site:rw,exec,nosuid,nodev,size=128m`; step `install` = `pip install --no-index
  --no-deps --only-binary :all: --require-hashes --no-compile --find-links /pkg --target /site/lib -r
  /pkg/hashes.txt` (pip re-checks every hash); step `imports` = `python -I -S -c` with `site.addsitedir('/site/lib')`
  (which runs `.pth` files) and `importlib.import_module` for each top-level module. Rules: WHEEL_NOT_VERIFIED,
  WHEEL_HASH_MISMATCH, MODULES_UNKNOWN, INTERNAL_ERROR, otherwise `run_harness`'s (never VERIFIED in Phase 2a).
  Evidence adds the staged wheels, modules, hash-file SHA-256, install target and site tmpfs.
- `backend/cavr/harness.py`: **deleted** (Q12: nothing imported it; it never installed a wheel).

### Design decisions

- **Deviation from sandbox rule 2 (owner's decision 5, 2026-11-23):** rule 2 says every writable tmpfs is `noexec`.
  The pip install target `/site` is `exec` (still `nosuid,nodev`, 128 MiB); `/tmp` stays `noexec`. Reason: a wheel's
  native extension is loaded with `mmap(PROT_EXEC)`, which a noexec mount refuses. Shown by two Docker tests on the
  same wheel (a copy of the image's own `_bisect` CPython extension): installed into `/site` it imports and the trace
  is complete; installed into `/tmp` the import fails with `failed to map segment from shared object`. Trade-off: a
  package can write and execute a file under `/site`; every such execve is in the trace, and the run is still
  network-less, read-only elsewhere, UID 10001 and limited.
- **Staging copy instead of mounting the quarantine file directly** (alternative: bind-mount each quarantine file):
  quarantine files are written by `mkstemp` with mode 0600 and the sandbox user is 10001, so they cannot be read in
  place. The copy is made from the same bytes that were hashed, so what is mounted is exactly what was checked.
- **Top-level modules only** (owner: "import its top-level modules"): `demo.sub` is refused; a str is refused too
  (it would split into letters, a defect the tests caught).
- **One run, two steps**: install and import in the same container, so the `.pth` and import behaviour is traced from
  the same installed bytes; harness processes are told apart by PID in the trace (`processes[pid].step`).

### Requirements covered

| ID | Acceptance check |
|---|---|
| NFR-1 rule 6 (exact bytes) | changed quarantine bytes -> WHEEL_HASH_MISMATCH before mounting; pip inside refuses a wrong hash (`step:install:end:1`) |
| NFR-1 rule 2 (read-only) | wheels at `/pkg` read-only; only `/site` executable (unit + Docker contrast) |
| FR-13 | connect to 198.51.100.24:443 recorded as `= -1 ENETUNREACH`; read of `~/.aws/credentials` recorded; `.pth` at start-up recorded |
| FR-6 fail closed | Docker hidden, bad node, bad module names, a fault -> UNRESOLVED |
| M1 harness item | `test_the_old_harness_is_gone`; a real import of each wheel's modules, seen in the trace |

### Ch 7 Test cases

`tests/test_cavr_sandbox_observe.py`: 36 tests, 29 unit (real wheels from `build_wheel`, fake `run_harness`) and 7 Docker.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_hash_file_holds_exactly_the_trees_sha256_values` | hash file | demo 1.0 + helper 2.0 | two lines with the tree's sha256 | pass |
| `test_staged_wheels_are_the_exact_quarantine_bytes_readable_by_the_sandbox_user` | staging | tree | same bytes, 0644, dir 0755, only wheels + hashes.txt, removed after | pass |
| `test_a_wheel_whose_quarantine_bytes_changed_is_refused_before_mounting` | rule 6 | bytes appended | WHEEL_HASH_MISMATCH, nothing run | pass |
| `test_a_node_that_is_not_a_verified_wheel_is_refused` (8) | verified only | sdist name, no / bad sha, no path, absent file, `../` name, bad name, bad version | WHEEL_NOT_VERIFIED, nothing run | pass |
| `test_a_wheel_outside_the_quarantine_is_refused`, `test_a_symlink_in_the_quarantine_is_refused`, `test_a_name_twice_in_the_tree_is_refused`, `test_no_wheel_is_refused` (3) | provenance | outside file, symlink, Helper twice, empty | WHEEL_NOT_VERIFIED | pass |
| `test_modules_that_are_not_top_level_names_are_refused` (7) | modules | [], None, `demo.sub`, twice, code, "", a str | MODULES_UNKNOWN | pass |
| `test_the_steps_install_offline_by_hash_then_import` | steps | — | pip flags as planned; import argv ends with the modules; no env | pass |
| `test_only_the_install_target_is_executable` | rule 2 deviation | — | only `/site` exec; `/tmp` noexec | pass |
| `test_docker_hidden_is_unresolved_and_nothing_runs`, `test_a_fault_is_unresolved_internal_error` | fail closed | no engine; raising stage | ENGINE_UNAVAILABLE / INTERNAL_ERROR | pass |
| `test_the_old_harness_is_gone` | Q12 | — | `backend/cavr/harness.py` absent | pass |
| `test_benign_wheel_installs_imports_and_gives_a_complete_trace` (Docker) | happy path | demo imports helper | DEEP_NOT_JUDGED; both `__init__.py` opened by the import step | pass |
| `test_import_that_connects_out_is_a_recorded_failed_connect` (Docker) | rule 1 | connect at import | `connect(... 198.51.100.24 ... 443) = -1 ENETUNREACH` | pass |
| `test_import_that_reads_aws_credentials_is_recorded` (Docker) | secret read | open `~/.aws/credentials` | `/tmp/home/.aws/credentials` in the import step's lines | pass |
| `test_a_pth_file_runs_at_start_up_and_is_recorded` (Docker) | .pth | `demo-startup.pth` | its stat in the import step's lines | pass |
| `test_pip_inside_refuses_a_wheel_whose_hash_does_not_match` (Docker) | rule 6 inside | wrong hash in hashes.txt | SANDBOX_EXIT_NONZERO, `step:install:end:1` | pass |
| `test_a_wheel_with_a_native_so_imports_and_gives_a_complete_trace` (Docker) | owner's test | `_bisect` extension, tag cp312-cp312-linux_x86_64 | DEEP_NOT_JUDGED; .so opened without error (4.1 s, 5848 lines) | pass |
| `test_the_same_native_wheel_cannot_load_from_the_noexec_tmp` (Docker) | why `/site` is exec | same wheel into `/tmp/lib` | install 0, import fails "failed to map segment" | pass |

Runs before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_observe.py`: 36 passed;
`CAVR_DOCKER=1 pytest tests/test_cavr_*.py`: 1608 passed, 11 skipped (live) in 441 s. No existing result changed.

### Defects found and fixed

- `check_modules("demo")` accepted a str as the letters `d, e, m, o`; now only a list or tuple is accepted (test above).

### Known limitations / deferred

- Events are kept as raw trace lines; normalisation (PR 7), judging against the contract (PR 8) and the deep verdict
  through `verify_request` (PR 9) are next. Phase 2a returns UNRESOLVED `DEEP_NOT_JUDGED` at best.
- The import runs as one process for all modules; a module that ends the process early stops later imports (its own
  behaviour up to then is traced).
- Native wheels whose import needs a syscall outside the profile fail and are UNRESOLVED.
- CI on GitHub's runner is not verified (nothing pushed).

### Q12: legacy parts after PRs 3-6

| Part | Status |
|---|---|
| `sandbox_runner.SandboxRunner.image_digest` | deleted (PR 3) |
| `backend/cavr/harness.py` | deleted (PR 6) |
| rest of `sandbox_runner.py` (run loop, stdout markers, `_extract_report`, `SECCOMP_PROFILE`) | still used by `counterfactual.py` (only its tests use it) and `tests/test_cli_resources.py`; PR 12 |
| `sandbox.py`, `lab_harness.py`, `runtime_monitor.py` | used by the LOCAL lab (`analyzer.py`, orchestrator `service.py`, `test_modules.py`, `test_cavr_targeted.py`, `test_cavr_lab_pins.py`); PR 12 (`runtime_monitor` PR 7) |
| `docker/asent-sandbox/Dockerfile` | listed by `doctor.py`, `check_wheel.py` and the packaging tests; PR 12 with owner review |

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the staging and install/import code, the tests and these notes. **Reviewed by
  Maryam:** decision 5 (exec only for the install target, native .so test). **Verified by:** the runs above.

### Supervisor Q&A prep

1. **Could the sandbox install something other than what was verified?** No: the host refuses any file whose bytes
   differ from the tree's sha256 before mounting, and pip inside installs only with `--require-hashes --no-index
   --no-deps --only-binary :all:` from the read-only copy.
2. **Why is one tmpfs executable when the rules say noexec?** Native extensions are mapped executable; on a noexec
   mount the import fails (shown by a test). Only the install target is exec, still nosuid and nodev, and every
   execve is traced.

## Review of steps M2-7 to M2-10 — fixes (2026-11-23)

Review outcomes (one cavr-reviewer pass over PRs 3-6, 2026-11-23):
- Step M2-7 (PR 3): 1 pass, fix first (BLOCKER 1, seccomp part); fixed below; 0 open MINOR.
- Step M2-8 (PR 4): 1 pass, fix first (BLOCKER 2); fixed below; 0 open MINOR.
- Step M2-9 (PR 5): 1 pass, fix first (BLOCKER 1, trace-check part); fixed below; MAJOR 1 deferred to PR 7; 0 open MINOR.
- Step M2-10 (PR 6): 1 pass, MINORs 5 and 7 fixed below; 0 open MINOR.

### Ch 6 Implementation

- `docker/cavr-sandbox/cavr-seccomp.json`: `clone` allowed only with `SCMP_CMP_MASKED_EQ` on argument 0, mask
  0x7E820000 (Docker's namespace mask 0x7E020000 + `CLONE_UNTRACED` 0x00800000), result 0; `clone3` is
  `SCMP_ACT_ERRNO` with `errnoRet` 38 (ENOSYS; glibc falls back to `clone`). Still 46 names in the additions.
- `backend/cavr/sandbox_trace.py`: new rule TRACE_UNFOLLOWED: every PID a known process's clone / fork / vfork
  returned must have lines in the trace; every created PID (not only those seen) must have an exit line.
- `backend/cavr/sandbox_exec.py`: `run_container` joins both readers before deciding a run that exited by itself; a
  reader still alive -> ENGINE_ERROR, bytes over a cap -> OUTPUT_CAP; `wake.clear()` after each wait; a run that was
  not COMPLETED is listed twice (`RECHECK_SECONDS` = 0.5) before it counts as removed; `docker_command` refuses a tmpfs
  that is not `<path>:rw,[no]exec,nosuid,nodev,size=<n>m,mode=1777` or that targets /tmp, /, /pkg, /job, /opt/cavr, /proc.
- `backend/cavr/sandbox_observe.py`: SECCOMP_CHANGED when the profile's SHA-256 differs from the one the image check
  read; `top_level_names(data, filename)` from the wheel archive; a module no staged wheel provides -> MODULES_UNKNOWN;
  an unreadable wheel -> WHEEL_NOT_VERIFIED.
- `backend/cavr/harness.py`: **restored** (deleted in `c3d384a`). `docker/asent-sandbox/Dockerfile` still does
  `COPY harness.py` with `backend/cavr` as its documented build context (`docs/cavr-m1-plan.md`), so it is used;
  Q12 ("delete only what nothing uses") keeps it until PR 12, with that Dockerfile and `SandboxRunner`.
- `tests/test_cavr_support.py`: `sandbox_identity()` rebuilds only a missing, unrecorded or stale image; an ID mismatch
  fails the test instead of overwriting the build record.

### Design decisions

- **Filter clone's flags, refuse clone3** (alternative: drop clone and keep only vfork/fork): Python threads and
  `fork` need `clone`; seccomp can read clone's flags (a register) but not clone3's (a struct in memory), which is why
  Docker's own default profile does the same.
- **Both layers**: the profile refuses CLONE_UNTRACED, and the trace check would still notice a created PID with no
  lines, so one layer failing is not enough to hide a process.
- **Restore rather than keep the deletion**: the owner's rule is about use, and a Dockerfile that copies the file is a use.

### Requirements covered

| ID | Acceptance check |
|---|---|
| NFR-1 / FR-13 | `clone(CLONE_UNTRACED)`, `CLONE_NEWUSER`, `NEWNET`, `NEWNS`, `NEWPID` -> EPERM, recorded; no child ran (Docker) |
| FR-6 fail closed | a created PID with no lines -> TRACE_UNFOLLOWED; over-cap output at exit never COMPLETED (50 of 50) |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_a_child_strace_never_followed_is_incomplete` | BLOCKER 1 | recorded trace + `clone(...) = 99`, no line of 99 | TRACE_UNFOLLOWED | pass |
| `test_a_failed_clone_creates_nothing` | no false alarm | `clone(...) = -1 EPERM` | complete | pass |
| `test_untraced_and_namespace_clones_are_refused_and_recorded` (Docker) | BLOCKER 1 | ctypes clone with 5 flags; clone3; a thread | 5 x EPERM, clone3 ENOSYS, thread ok, no child line | pass |
| `test_cavr_profile_is_the_shared_profile_plus_listed_additions` (changed) | filter | profile | clone masked 0x7E820000; clone3 ERRNO 38; neither allowed unconditionally | pass |
| `test_output_over_the_cap_at_exit_is_never_completed` | BLOCKER 2 | 50 runs: 5000 bytes then exit, cap 1000 | OUTPUT_CAP every time | pass |
| `test_output_not_read_to_its_end_is_not_completed` | BLOCKER 2 | exited, streams never closed | ENGINE_ERROR | pass |
| `test_a_stopped_run_is_listed_twice_before_it_counts_as_gone`, `test_a_completed_run_is_listed_once` | MINOR 2 | late container | `rm -f` after the second listing; one listing when completed | pass |
| `test_a_tmpfs_without_nosuid_nodev_and_a_size_is_refused` (6), `test_the_install_target_tmpfs_is_accepted` | MINOR 4 | bad / good tmpfs | ValueError / accepted | pass |
| `test_a_seccomp_profile_changed_after_the_image_check_runs_nothing` | MINOR 3 | other SHA-256 | SECCOMP_CHANGED, nothing run | pass |
| `test_a_module_no_staged_wheel_provides_is_refused`, `test_top_level_names_come_from_the_wheel_archive`, `test_an_unreadable_wheel_is_refused` | MINOR 5 | `os`; mixed wheel; not a zip | MODULES_UNKNOWN; `fast, pkg_a, single`; WHEEL_NOT_VERIFIED | pass |
| `test_the_old_harness_is_gone` | removed | — | `harness.py` stays until PR 12 | removed |

Runs before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_{exec,image,trace,observe}.py`: 188 passed;
`CAVR_DOCKER=1 pytest tests/test_cavr_*.py`: 1625 passed, 11 skipped (live) in 456 s.

### Defects found and fixed

- BLOCKER 1 (confirmed on Docker before the fix): a ctypes `clone(CLONE_UNTRACED|SIGCHLD)` child ran, its stat was
  not in the trace, and the trace was TRACE_COMPLETE; `clone(CLONE_NEWUSER)` succeeded. Fixed in the profile and in
  `check_trace` (above). Corrections: Step M2-7's "Never added: namespaces" and Step M2-10's "every such execve is in
  the trace" were not true before this fix.
- BLOCKER 2: `run_container` could return COMPLETED for output over a cap when the CLI exited before the readers
  caught up (reviewer: `test_output_over_the_cap_at_exit_is_still_unresolved` failed 8 of 100 runs under load). Fixed.
- MINOR 7: deleting `harness.py` broke the legacy `docker/asent-sandbox` recipe; restored. The dashboard's
  `proof.image_digest` (`ProofDrawer.tsx`, `CavrModule.tsx`) is unchanged: it shows `api.py`'s NOT_RUN value, which
  never came from `SandboxRunner`.

### Known limitations / deferred

- MAJOR 1 (truncated `-s 1024` strings, dirfd-relative paths) does not affect completeness in Phase 2a; it is now a
  Part of PR 7 in the plan (`-yy`, larger `-s`, truncated or unresolvable path -> UNRESOLVED).
- The profile's SHA-256 is re-checked right before `docker run`; Docker reads the file by path a moment later, so a
  change in that window is not detected. PR 9 puts the SHA-256 into `analyzer_version`.
- The clone filter uses argument 0, which is the flags on x86_64 and aarch64 (the profile's architectures).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the fixes, tests and these notes, from the cavr-reviewer report. **Reviewed by
  Maryam:** not yet. **Verified by:** the BLOCKER 1 probe on Docker before and after the fix, and the runs above.

### Supervisor Q&A prep

1. **Can a package start a process strace does not follow?** The usual way is `clone(CLONE_UNTRACED)`; the profile
   refuses it (EPERM, recorded), and if a created PID ever had no lines the trace check says TRACE_UNFOLLOWED.
2. **Why is clone3 refused?** seccomp cannot look inside clone3's argument struct, so it cannot refuse namespace or
   untraced flags there; with ENOSYS glibc uses clone, whose flags it can check (as Docker's default profile does).

## Step M2-11 — Refused syscalls and ptrace checked in the sandbox (2026-11-23)

Owner's check before the push: io_uring, process_vm_*, userfaultfd, bpf, perf_event_open refused, and no ptrace by a
UID 10001 package process, each attempt visible in the trace.

### Ch 6 Implementation

- `backend/cavr/sandbox_observe.py`: `TRACED_BY_NAME` = ptrace, process_vm_readv, process_vm_writev, io_uring_setup,
  io_uring_enter, io_uring_register, userfaultfd, bpf, perf_event_open, added to strace's `-e trace=` after
  `%file,%network,%process,%creds`. None of them is in those classes, so before this change an attempt was refused but
  not in the trace.
- `tests/test_cavr_sandbox_trace.py`: `test_a_package_process_is_refused_dangerous_syscalls_and_ptrace` (13 cases,
  Docker; x86_64 and aarch64 numbers) and `test_the_refused_syscalls_are_traced_by_name_and_not_in_the_profile` (unit).

### Design decisions

- **Profile unchanged**: the eight syscalls were never in `docker/cavr-sandbox/cavr-seccomp.json`, so its default
  action refuses them (ERRNO, EPERM); nothing was removed.
- **ptrace stays allowed in the profile**: the filter also applies to strace, which needs ptrace to trace at all, and
  seccomp cannot tell strace's calls from a package's. The kernel refuses it to package processes: each one is already
  traced by strace (TRACEME, ATTACH / SEIZE of its own child), the harness is non-dumpable and traced, PID 1 is root.

### Requirements covered

| ID | Acceptance check |
|---|---|
| NFR-1 rule 3 | 13 attempts from a UID 10001 package process, each `-1 EPERM` in the trace from the probe's PID |
| FR-13 | every attempt of the nine syscalls is in the trace (traced by name) |

### Ch 7 Test cases

`test_a_package_process_is_refused_dangerous_syscalls_and_ptrace` (Docker): the probe forks a sleeping child, makes
one call, prints its return and errno. Trace lines recorded 2026-11-23 (x86_64):

| Test ID | Input | Expected | Trace line (from the probe's PID) | Result |
|---|---|---|---|---|
| `[io_uring_setup]` | `io_uring_setup(0, NULL)` | EPERM / ENOSYS | `io_uring_setup(0, NULL) = -1 EPERM` | pass |
| `[io_uring_enter]` | zeros | EPERM / ENOSYS | `io_uring_enter(0, 0, 0, 0, NULL, ...) = -1 EPERM` | pass |
| `[io_uring_register]` | zeros | EPERM / ENOSYS | `io_uring_register(0, IORING_REGISTER_BUFFERS, NULL, 0) = -1 EPERM` | pass |
| `[process_vm_readv]` | the harness's PID | EPERM / ENOSYS | `process_vm_readv(9, NULL, 0, NULL, 0, ...) = -1 EPERM` | pass |
| `[process_vm_writev]` | the harness's PID | EPERM / ENOSYS | `process_vm_writev(9, NULL, 0, NULL, 0, ...) = -1 EPERM` | pass |
| `[userfaultfd]` | `userfaultfd(0)` | EPERM / ENOSYS | `userfaultfd(0) = -1 EPERM` | pass |
| `[bpf]` | `bpf(0, NULL, 0)` | EPERM / ENOSYS | `bpf(BPF_MAP_CREATE, NULL, 0) = -1 EPERM` | pass |
| `[perf_event_open]` | `perf_event_open(NULL, 0, -1, -1, 0)` | EPERM / ENOSYS | `perf_event_open(NULL, 0, -1, -1, 0) = -1 EPERM` | pass |
| `[ptrace_traceme]` | PTRACE_TRACEME | EPERM | `ptrace(PTRACE_TRACEME) = -1 EPERM` | pass |
| `[ptrace_attach_strace]` | PTRACE_ATTACH 1 | EPERM | `ptrace(PTRACE_ATTACH, 1) = -1 EPERM` | pass |
| `[ptrace_attach_harness]` | PTRACE_ATTACH ppid | EPERM | `ptrace(PTRACE_ATTACH, 9) = -1 EPERM` | pass |
| `[ptrace_attach_own_child]` | PTRACE_ATTACH child | EPERM | `ptrace(PTRACE_ATTACH, 11) = -1 EPERM` | pass |
| `[ptrace_seize_own_child]` | PTRACE_SEIZE child | EPERM | `ptrace(PTRACE_SEIZE, 11, NULL, 0) = -1 EPERM` | pass |
| `test_the_refused_syscalls_are_traced_by_name_and_not_in_the_profile` | profile, STRACE | 8 not allowed, ptrace allowed, all 9 traced | — | pass |

Run before the commit (as the owner asked, sandbox tests only): `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_*.py`:
278 passed; no `cavr-*` container left. In every case the trace was complete (`DEEP_NOT_JUDGED`).

### Defects found and fixed

- Refused attempts of these nine syscalls were not in the trace (not in strace's traced classes); now traced by name.
- Review: no cavr-reviewer pass for this step (owner asked for the check and the sandbox tests only).

### Known limitations / deferred

- ptrace is refused by the kernel, not by seccomp; the test shows each way in for this layout (all package processes
  traced from creation by `strace -f`, harness non-dumpable, PID 1 root).
- The probe's numbers cover x86_64 and aarch64 only; on another architecture the Docker test is skipped.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the trace-set change, the tests and these notes. **Reviewed by Maryam:** the list of
  syscalls to check. **Verified by:** the run above on Docker 29.9.3.

### Supervisor Q&A prep

1. **Why is ptrace allowed in the seccomp profile at all?** The profile also applies to strace, which traces with
   ptrace; a package process's ptrace fails because it and every process it starts are already traced, the harness
   is non-dumpable and strace is root (13 Docker cases, each EPERM in the trace).

## Step M2-12 — Trace normalised into typed events (PR 7) (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 7, decisions D1–D7 (Maryam, 2026-11-23) plus two decisions taken during the step
(Q5: `DAC_READ_SEARCH` for strace; pip's User-Agent builder replaced), both from measured Docker runs.

### Ch 6 Implementation

- `backend/cavr/sandbox_events.py` (new): `normalise(trace, processes, step_pids, steps)` turns every strace line
  into one typed event (FILE_READ, FILE_WRITE, CODE_LOAD, PROCESS_EXEC, NETWORK_CONNECT, NETWORK_BIND,
  NETWORK_LISTEN, CREDENTIAL_CHANGE, REFUSED_SYSCALL, UNKNOWN, plus structure types) with path, real path (`-y`),
  access, sensitivity, persistence, address, argv, outcome and errno; `make_baseline`, `check_baseline`,
  `subtract_baseline`. Algorithm: join `<unfinished ...>` / `<... resumed>` lines; split each call into arguments
  with a small tokenizer (quotes, brackets, `-y` fd paths, comments); look the syscall up in fixed tables; resolve
  each path (absolute, `AT_FDCWD</cwd>`, `fd</dir>`, or the process's tracked directory); classify; anything without
  a rule or unreadable is UNKNOWN / incomplete.
- `backend/cavr/sandbox_trace.py`: `check_trace(..., partial=False)`; `partial=True` gives TRACE_PARTIAL with
  `attributable: True` for a run that did not end well (D6); every result has `attributable`. The marker regex
  accepts `AT_FDCWD</cwd>` (strace -y).
- `backend/cavr/sandbox_observe.py`: strace `-y -s 4096` and `fchdir` traced; import step `python -I -S -B`;
  install step `python -I -B -c PIP_CODE install --isolated ...` (PIP_CODE replaces pip's `user_agent`); a run that
  did not end well is read in partial mode; evidence carries `trace_attributable`, `processes`, `step_pids`, `job_steps`.
- `backend/cavr/sandbox_exec.py`: `CAPABILITIES` + `DAC_READ_SEARCH`.
- `backend/cavr/sandbox_harness.py`: `sys.dont_write_bytecode = True` (the harness's lazy `import ctypes` tried to
  write .pyc); comments.
- `docker/cavr-sandbox/cavr-seccomp.json`: + `chdir`, `fchdir`. `docker/cavr-sandbox/Dockerfile`: setuid / setgid bits
  removed (11 files, e.g. `su`, `mount`, `passwd`), build fails unless pip is 25.0.1, label `org.asent.cavr.pip-version`.
  New image `sha256:0e88dd461ca4…`.
- `docs/cavr-m2-plan.md`: Q5 lists the four capabilities with the reason; sandbox rule 3.
- Deleted (Q12): `backend/cavr/normalizer.py` (nothing imported it). Kept: `runtime_monitor.py` (`sandbox.py` LOCAL
  lab and `tests/test_modules.py` use it; PR 12).
- Tests: `tests/test_cavr_sandbox_events.py` (new), traces `tests/test_cavr_data/traces/events-{probe,benign,baseline}`
  recorded by `tests/test_cavr_data/traces/record_events.py`.

### Design decisions

- **`DAC_READ_SEARCH` for strace** (Maryam's choice): `/proc/<pid>/fd` of a UID 10001 process is 0500, so root without
  it printed no fd path (`openat(3, "x")`); the alternatives were non-dumpable steps (packages lose `/proc/self`) or
  rebuilding fd tables from the trace (more code, close/dup/fcntl traced). Measured: the package process has empty
  Inh/Prm/Eff/Amb sets and cannot read `/etc/shadow`; the image now has no setuid/setgid file and no file capability.
- **pip's User-Agent replaced** (Maryam's choice): pip 25.0.1 execs `lsb_release -a`, `uname -rs` and stats every file
  in `/etc` to build a User-Agent it never sends with `--no-index`. `PIP_CODE` sets `user_agent` to a constant; pip
  still checks every hash. A pip that ignored this would exec → INSTALL_OUTSIDE_ENVELOPE (PR 8), never a pass.
  Pinned: the Dockerfile fails unless pip is 25.0.1.
- **No cwd tracking from scratch**: strace `-y` prints the kernel's directory for `AT_FDCWD` (`AT_FDCWD</tmp>`), so
  most relative paths are resolved from the kernel; calls without a dirfd use the last directory seen for the
  process; after any chdir every other process's directory is unknown (threads can share it) -> incomplete.
- **CODE_LOAD locations (D1, refined with the measured baseline)**: `/usr/local/`, `/usr/lib/`, `/lib/`,
  `/usr/share/locale/`, `/usr/share/zoneinfo/`, `/opt/cavr/`, `/job/`, `/pkg/`, `/site/lib/`, and seven exact paths
  in `RUNTIME_FILES` (`/etc/ld.so.cache`, `/etc/ld.so.preload`, `/etc/localtime`, `/dev/null`, `/proc/self/exe`,
  and the directories `/site/lib` and `/site` themselves); a stat of an ancestor (`/`, `/usr`, ...) only. Both the asked
  path and the real path (when strace prints one) must be inside; sensitive paths are checked first. Without the first
  five the empty baseline would never be clean (measured: its only non-code reads are these).
- **Kept as attempts**: every failed syscall (ENETUNREACH, ENOENT, EACCES, EPERM) is an event; a `sendmsg` refused
  by the profile is a network attempt.
- **bind is its own type** (NETWORK_BIND): pip's urllib3 binds `::1` port 0 to probe IPv6 support; PR 8 decides.
- **Baseline key**: (step, type, call, path, real path, access, address, argv, outcome, errno, complete), counted;
  PIDs and line numbers are not in it.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-13 | failed `connect … ENETUNREACH`, DNS to port 53, `sendto`, refused `sendmsg`, IPv6, Unix: NETWORK_CONNECT events (`test_failed_connect_enetunreach_is_a_network_attempt` …) |
| FR-13 | `~/.aws/credentials` (ENOENT), stat of `~/.ssh/id_rsa`, `/etc/passwd`, `.env` resolved to `/tmp/.env`: sensitive reads |
| FR-13 / MAJOR 1 | 4000-character path kept whole; a cut path or an unreadable dirfd is incomplete |
| FR-6 | unknown syscall, unreadable line, call that never returned -> UNKNOWN; baseline not clean -> BASELINE_NOT_CLEAN |
| NFR-1 | no setuid/setgid/file-capability file in the image; package process holds no capability (Docker) |

### Ch 7 Test cases

`tests/test_cavr_sandbox_events.py`: 86 tests (80 unit on the three recordings and hand-made lines, 6 Docker);
`tests/test_cavr_sandbox_image.py`: 3 new Docker tests. Recordings: image `sha256:0e88dd461ca4…`, 2026-11-23.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_failed_connect_enetunreach_is_a_network_attempt` | attempts kept | probe: connect 198.51.100.24:443 | NETWORK_CONNECT, ENETUNREACH, address parsed | pass |
| `test_ipv6_and_unix_addresses_are_parsed` | sockaddr | probe: `2001:db8::1`, `/run/cavr-probe.sock` | both addresses | pass |
| `test_dns_lookup_is_a_network_attempt_to_port_53` | DNS | probe: `getaddrinfo("example.com")` | connect to port 53, `dns` set | pass |
| `test_sendto_…`, `test_refused_sendmsg_is_still_a_network_attempt` | send | probe | NETWORK_CONNECT, ENETUNREACH / EPERM | pass |
| `test_bind_is_its_own_event_with_its_address` | pip's IPv6 probe | benign | one NETWORK_BIND `::1` port 0, install step | pass |
| `test_sendfile_into_a_file_copies_and_into_a_socket_sends` | sendfile | hand-made | NO_EFFECT / NETWORK_CONNECT | pass |
| `test_read_of_aws_credentials_is_a_secret_read` | secrets | probe ENOENT; ok; EACCES | SECRET_READ each time | pass |
| `test_sensitive_path_table` (17) | table | `.ssh`, `.aws`, `.env`, `/proc/*/environ`, `/etc/passwd`, … and 5 negatives | level / None | pass |
| `test_stat_of_a_sensitive_path_is_a_sensitive_read_attempt` | D4 | probe: stat `~/.ssh/id_rsa` | SECRET_READ, metadata | pass |
| `test_a_symlink_to_a_secret_is_caught_by_its_real_path` | -y real path | `/tmp/innocent` -> `.aws/credentials` | SECRET_READ | pass |
| `test_code_reads_are_code_load_not_file_read` | D1 | benign + hand-made | own module, stdlib = CODE_LOAD; `/etc/os-release`, `/usr` listing = FILE_READ | pass |
| `test_writes_creat_rename_unlink_mkdir_are_file_writes`, `test_persistence_paths` (10), `test_append_to_bashrc_…` | writes | probe + table | FILE_WRITE, persistence flag | pass |
| `test_execve_of_a_shell_is_process_exec`, `test_step_launch_is_not_a_package_exec` | exec | probe `/bin/sh -c true`; job argv | PROCESS_EXEC; STEP_START only for the step's first exec with the job's argv | pass |
| `test_credential_change_even_when_it_fails`, `test_refused_dangerous_syscalls_are_events` | creds, refused | probe setuid(0), ptrace, bpf; hand-made io_uring, unshare, mount | EPERM events | pass |
| `test_clone_with_and_without_clone_thread_is_structure` | clone | probe thread + fork | PROCESS; child's open in the step | pass |
| `test_relative_path_resolved_against_cwd`, `test_a_child_inherits_…`, `test_dirfd_relative_path` | paths | probe `.env`, `rel*.txt`, `child.txt`; chdir / getcwd lines | resolved; unknown directory -> incomplete | pass |
| `test_unresolvable_dirfd_is_incomplete`, `test_truncated_path_is_incomplete` | MAJOR 1 | `openat(3, …)`, `"…"...` | incomplete | pass |
| `test_a_4000_character_path_is_kept_whole` | MAJOR 1 | probe | 4001-character path, ENAMETOOLONG | pass |
| `test_unknown_syscall_…`, `test_unreadable_line_…` (4), `test_an_unfinished_call_…` | fail closed | inotify, broken lines, never returned | UNKNOWN, incomplete | pass |
| `test_every_recorded_syscall_has_a_rule` | coverage | probe, benign | no UNKNOWN, all complete | pass |
| `test_recorded_baseline_is_clean`, `test_benign_import_has_no_file_write_and_nothing_judged_after_the_baseline` | baseline | baseline, benign | BASELINE_OK; import step: 0 judged events, 0 FILE_WRITE | pass |
| `test_baseline_subtraction_is_exact_and_counted`, `test_baseline_of_another_identity_is_refused` | D2 | hand-made | one of two reads left; mismatch / invalid | pass |
| `test_a_baseline_with_anything_but_code_and_structure_is_not_clean` (8) | Maryam's rule | secret read, connect, exec, setuid, ptrace, unknown, write, unreadable dirfd | BASELINE_NOT_CLEAN | pass |
| `test_a_markers_nonce_is_not_part_of_its_key` | determinism | two nonces | same key | pass |
| `test_partial_trace_of_a_killed_run_is_attributable`, `…_still_refuses_unknown_pids_and_foreign_markers`, `test_failed_step_trace_…` | D6 | cut / edited benign trace | TRACE_PARTIAL; TRACE_UNKNOWN_PID / TRACE_MARKERS | pass |
| `test_two_empty_harness_runs_give_the_same_events` (Docker) | determinism | 2 live baseline runs | same keys, BASELINE_OK | fail, then pass (see defects) |
| `test_package_that_calls_chdir_is_traced_not_refused` (Docker) | chdir | chdir, fchdir, relative stat | both succeed, paths resolved | pass |
| `test_y_prints_the_path_of_every_fd` (Docker) | -y | `openat(fd, "nope")` | `openat(3</tmp>, "nope")`, complete | pass |
| `test_benign_wheel_import_produces_zero_file_write_events` (Docker) | -B (Maryam) | `def run()` wheel | 0 FILE_WRITE in the import step | pass |
| `test_install_step_has_no_exec_and_reads_only_the_measured_etc_files` (Docker) | pip override | plain wheel | no exec, no sensitive read, the 9 listed `/etc` paths exactly, no `/etc` listing | pass |
| `test_install_step_still_refuses_a_wrong_hash_without_exec_or_other_etc_reads` (Docker) | rule 6 | hash file with zeros | SANDBOX_EXIT_NONZERO, "DO NOT MATCH THE HASHES", attributable, no exec | pass |
| `test_no_file_in_the_image_has_setuid_setgid_or_file_capabilities` (Docker) | Q5 | whole image | none | pass |
| `test_a_package_process_holds_no_capability` (Docker) | Q5 | `strace -u cavr sh` | Inh/Prm/Eff/Amb all 0; `/etc/shadow` denied | pass |
| `test_the_image_pip_is_the_pinned_version` (Docker) | pin | image | pip 25.0.1, label, Dockerfile ARG | pass |
| `test_the_old_normalizer_is_gone` | Q12 | — | file absent | pass |

Existing results that changed (all from approved changes): `test_cavr_profile_is_the_shared_profile_plus_listed_additions`
(46 -> 48 names: chdir, fchdir), `test_lockdown_flags_are_the_planned_set` and the Docker
`test_running_container_has_every_lockdown_flag` (+ DAC_READ_SEARCH), `test_the_steps_install_offline_by_hash_then_import`
(pip through PIP_CODE with `--isolated`; import with `-B`),
`test_package_cannot_open_strace_fds_and_the_trace_stays_complete_and_unforged` (the expected line is now
`openat(AT_FDCWD</tmp>, "/proc/1/fd/2", …) = -1 EACCES`: strace -y prints the directory; still EACCES).

Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py tests/test_gate_*.py
tests/test_cli_gate.py`: 1828 passed, 1 failed (`test_two_empty_harness_runs_give_the_same_events`), 12 skipped (live),
610 s; after the fix `tests/test_cavr_sandbox_events.py` 80 passed + the Docker test passed.

### Defects found and fixed

- With `-y`, the harness markers (`newfstatat(AT_FDCWD</tmp>, "/.cavr/…")`) no longer matched `sandbox_trace.MARKER`
  (first probe run: TRACE_MARKERS); regex fixed.
- strace printed no fd paths (root without `DAC_READ_SEARCH`); fixed as above.
- The first draft of `_State.cwd_of` let a process inherit its parent's *new* directory after the parent's chdir
  (`test_a_child_inherits_the_directory_and_another_process_forgets_it` failed); fixed with `forget_others`.
- Two live empty-harness runs differed only in the harness's marker paths (`/.cavr/<nonce>/…`, a new nonce per run;
  four runs compared): `event_key` now replaces a marker's nonce with `<nonce>`.
- The empty baseline was not clean: the harness's `import ctypes` tried two `.pyc` writes (EROFS) and opened
  `/dev/null` for writing; fixed with `sys.dont_write_bytecode` in the harness and `/dev/null` as NO_EFFECT.

- Review: one cavr-reviewer pass over PRs 7-9 at the end of Phase 2b (recorded in Step M2-14).

### Known limitations / deferred

- Label scopes (`invoice_documents`, `scratch_tmp`) cannot be mapped to paths, so a file event under them is
  UNRESOLVED (D5, PR 8). Mapping labels to paths is future work.
- The install step still reads nine non-sensitive `/etc` files (pip's global `pip.conf` ×2, which `--isolated`
  does not skip; the stdlib `mimetypes` search ×5; OpenSSL's config and CA bundle ×2); the Docker test pins that
  exact set.
- strace's `+++ superseded by execve +++` is still accepted without a producing test.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `sandbox_events.py`, the trace-check partial mode, the flag / profile / Dockerfile
  changes, the tests, the recordings and these notes. **Reviewed by Maryam:** D1–D7, `DAC_READ_SEARCH`, the pip
  User-Agent replacement, the setuid and pip-pin tests. **Verified by:** the runs above on Docker 29.9.3.

### Supervisor Q&A prep

1. **Why does strace now have DAC_READ_SEARCH, and can a package use it?** Without it root cannot read a UID 10001
   process's `/proc/<pid>/fd`, so dirfd paths were blank. The drop to UID 10001 empties every capability set
   (measured), and the image has no setuid file or file capability that could give one back.
2. **Why are failed syscalls events?** Under `--network none` every connect fails; dropping failures (the old
   `runtime_monitor`) made network attempts invisible. An attempt shows intent, so it is judged like a success.
3. **What is in the baseline, and why must it be clean?** Only what the interpreter and harness do with nothing to
   import: 317 code loads and structure lines (recorded). If it contained a secret read or a connect, subtracting it
   would hide the same event in a package run, so such a baseline is refused.

## Step M2-13 — Observed events judged against the capability contract (PR 8) (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 8, decisions D3, D4, D5 (Maryam, 2026-11-23).

### Ch 6 Implementation

- `backend/cavr/contract_check.py` (new): `judge(events, contract)` -> {result OK / VIOLATION / UNRESOLVED, rule,
  reason, violations, unresolved, not_exercised, judged, used, install_events}; `read_contract`, `capability_of`,
  `in_scope`. Algorithm: read the contract (allowed with scopes, denied); for each event of the import step and the
  harness, map its type to a capability (FILE_READ or its sensitive level, FILE_WRITE or PERSISTENCE_WRITE,
  PROCESS_EXEC, NETWORK_CONNECT; none for CODE_LOAD / structure / a loopback port-0 bind; never-allowed for
  CREDENTIAL_CHANGE and REFUSED_SYSCALL); denied -> violation, "*" -> fine, a scope -> `in_scope`; install-step
  events go through pip's envelope instead. Any violation wins; else anything unjudgeable -> UNRESOLVED.
- `policy.verify_runtime` is kept (Q12): `analyzer.py` and `backend/orchestrator/service.py` still call it for the
  LOCAL lab; PR 12.
- Tests: `tests/test_cavr_contract_check.py` (new).

### Design decisions

- **An attempt counts like a success** (plan): the judgement never looks at `ok` / `errno`.
- **Sensitive reads need their own capability** (D4): `FILE_READ:*` does not allow `~/.aws/credentials`; it needs
  SECRET_READ. A stat of a secret is an attempt.
- **Scopes (D5)**: `*` unrestricted; `ip:port` lists for NETWORK_CONNECT (IPv6 as `[addr]:port`); absolute program
  paths for PROCESS_EXEC; absolute directories for file capabilities (lexically normalised, `/database` is not inside
  `/data`, the real path must be inside too). Any other scope is a label -> UNRESOLVED SCOPE_NOT_CHECKABLE. The demo
  policy's `FILE_READ:invoice_documents` and `FILE_WRITE:scratch_tmp` are labels: a file read or write by an escalated
  package of the demo project is UNRESOLVED, not VERIFIED and not REJECTED.
- **Incomplete events**: a network, credential or refused event is still a violation of a denied capability (its
  capability does not depend on the unreadable part); an incomplete file or exec event is UNRESOLVED (the path that
  could not be read might have been a code load or the step's own start). Alternative (every incomplete event
  UNRESOLVED) would let a package hide a connect behind an unreadable address.
- **Loopback port-0 bind needs no capability**: pip's vendored urllib3 does it to test IPv6 support (measured,
  Step M2-12); with `listen` refused by the profile nothing can connect to it. Any other bind, listen or accept
  needs NETWORK_CONNECT.
- **Install envelope (D3)**: code loads, non-sensitive reads, writes under `/tmp/` and `/site/lib/` (a `.pth` pip
  installs there runs, and is judged, in the import step), a loopback port-0 bind. Anything else ->
  INSTALL_OUTSIDE_ENVELOPE. Tested with the exact events an unpatched pip 25.0.1 makes (`uname -rs`,
  `lsb_release -a`, stat of `/etc/shadow`): UNRESOLVED.
- **Harness events are judged like any other** after the baseline subtraction; nothing is excluded by name.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-6 / FR-13 | each capability denied -> violation with the event; allowed `*`; scoped inside / outside; label -> UNRESOLVED |
| FR-6 | unknown event type, unreadable contract (9 cases), a fault -> UNRESOLVED |
| FR-3 | required capability not used in the run -> `not_exercised` |
| NFR-6 | `not_exercised` and the install envelope are in the evidence |

### Ch 7 Test cases

`tests/test_cavr_contract_check.py`: 52 tests, unit (hand-made events, the demo policy's real contract fields, and the
recorded traces of Step M2-12).

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_denied_capability_is_a_violation` (7) | each capability denied | connect, `.aws`, read, write, exec, `.bashrc`, `/etc/passwd` | VIOLATION, the capability, the event's line | pass |
| `test_failed_attempt_counts_like_a_success` | attempts | connect ENETUNREACH vs = 0 | both VIOLATION | pass |
| `test_unrestricted_grant_allows` (5) | `*` | each capability granted `*` | OK | pass |
| `test_scoped_network_grant_matching_and_non_matching_endpoint` | D5 network | IPv4 / IPv6 inside, port 80, Unix socket, sendto without address | OK, OK, VIOLATION, VIOLATION, EVENT_INCOMPLETE | pass |
| `test_scoped_file_grant_by_path_prefix` | D5 files | inside, outside, `/data/../etc`, `/database`, link to `/etc` | OK, then 4 x VIOLATION | pass |
| `test_scoped_exec_grant_by_program` | D5 exec | `/usr/bin/gs` granted; `/bin/sh` | OK / VIOLATION | pass |
| `test_label_scope_is_unresolved` (3) | D5 labels | `invoice_documents`, `scratch_tmp`, `approved endpoints` | SCOPE_NOT_CHECKABLE | pass |
| `test_the_demo_policy_labels_make_file_events_unresolved_and_the_rest_a_violation` | real policy | InvoiceHub `.asent/cavr/policy.json` | read / write UNRESOLVED; connect, secret VIOLATION | pass |
| `test_sensitive_read_needs_secret_read_even_with_file_read_star` | D4 | `.aws` open, `.ssh` stat with `FILE_READ:*` | VIOLATION (SECRET_READ) | pass |
| `test_credential_change_and_refused_syscall_always_violate` | never allowed | setuid, ptrace, unshare; every capability `*` | VIOLATION | pass |
| `test_code_load_and_structure_need_no_capability` | none needed | stdlib load, clone, getuid, kill, `::1` port-0 bind | OK, 0 judged | pass |
| `test_a_bind_that_is_not_a_loopback_probe_needs_network` | bind | 0.0.0.0:8080, listen | VIOLATION | pass |
| `test_unknown_event_type_is_unresolved` | fail closed | inotify, invented type | EVENT_TYPE_UNKNOWN | pass |
| `test_unreadable_contract_is_unresolved` (9) | fail closed | None, str, not OK, bad lists, unknown / repeated / missing capability, empty scope, no vocabulary | CONTRACT_UNREADABLE | pass |
| `test_violation_wins_over_unknown` | Q8 | unknown + connect | VIOLATION, 1 unresolved listed | pass |
| `test_incomplete_file_event_is_unresolved_but_an_incomplete_connect_still_violates` | incomplete | cut path, blank dirfd, connect without address | EVENT_INCOMPLETE / VIOLATION | pass |
| `test_required_not_observed_is_not_exercised` | FR-3 | REQUIRED FILE_READ unused / used | listed / not listed | pass |
| `test_install_step_envelope_inside` | D3 | pip writes in `/tmp`, `/site/lib` (+ `.pth`), pip.conf probe, `::1` bind | OK | pass |
| `test_install_step_outside_the_envelope_is_unresolved_never_a_pass` (9) | D3 + pip pin | write `/var`, connect, `.aws`, `uname -rs`, `lsb_release -a`, setuid, unknown, blank dirfd, stat `/etc/shadow` | INSTALL_OUTSIDE_ENVELOPE (every capability `*`) | pass |
| `test_recorded_install_step_is_inside_the_envelope` | real pip | benign recording | OK | pass |
| `test_recorded_benign_run_is_within_a_deny_all_contract` | real run | benign minus baseline | OK, 0 judged | fail, then pass (see defects) |
| `test_recorded_probe_run_is_a_violation_with_every_kind_listed` | real run | probe minus baseline | VIOLATION covering 8 capabilities | pass |
| `test_harness_events_are_not_excluded_by_name` | by PID, not name | harness reads `/etc/hostname` | VIOLATION | pass |
| `test_a_fault_is_unresolved_never_a_pass` | fail closed | not an event | INTERNAL_ERROR | pass |

No existing result changed. Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py
tests/test_gate_*.py tests/test_cli_gate.py`: 1882 passed, 12 skipped (live), 606 s.

### Defects found and fixed

- The first draft counted install-step events as judged (`test_recorded_benign_run_is_within_a_deny_all_contract`
  expected 0, got 171); install events are counted separately (`install_events`).
- Two bugs found while reading the draft before the tests ran: denied entries were told from allowed ones by dict
  equality (`entry in allowed`), and the envelope message indexed an empty list; both rewritten.

- Review: one cavr-reviewer pass over PRs 7-9 at the end of Phase 2b (recorded in Step M2-14).

### Known limitations / deferred

- Label scopes (`invoice_documents`, `scratch_tmp`) make file events UNRESOLVED (D5); mapping labels to paths is
  future work.
- A scope cannot name a host by DNS name (there is no DNS in the sandbox); only IP literals are checked.
- `policy.verify_runtime` (LOCAL lab) is replaced only on the pipeline path; deleted with the lab in PR 12.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `contract_check.py`, its tests and these notes. **Reviewed by Maryam:** D3, D4, D5.
  **Verified by:** the runs above.

### Supervisor Q&A prep

1. **Why is a failed connect a violation?** The contract is about what the package tries to do; the sandbox making
   it fail (`--network none`) says nothing about the package. `test_failed_attempt_counts_like_a_success`.
2. **Why is the demo project's file read UNRESOLVED and not VERIFIED?** Its policy grants FILE_READ only for the label
   `invoice_documents`; CAVR cannot tell which paths that means, so it cannot say the read is inside (D5).
3. **Why is pip judged differently?** No package code runs in the install step; pip is trusted code on hash-checked
   bytes, so it is held to a fixed envelope instead of the package's contract, and anything outside is UNRESOLVED.

## Step M2-14 — Escalated packages get one observed sandbox run (PR 9) (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 9, Q8 and its frontier rule, decisions D2, D6, D7 (Maryam, 2026-11-23).

### Ch 6 Implementation

- `backend/cavr/sandbox_deep.py` (new): `SandboxDeepAnalyzer` (the Phase 1 `deep_stage` interface), `for_gate_run`,
  `deep_version`, `high_risk_triggers`. `version` = `cavr-sandbox-deep/1` + SHA-256 of the harness, the profile, the
  strace command, the two step commands, and the normaliser's and checker's versions; `image_id` the checked ID;
  `budget` {runs 1, run_seconds 20, package_seconds 120, gate_run_seconds 300}; `deep_stage.identity` puts all into
  `analyzer_version`. Algorithm of `analyse`: run-wide time left? -> baseline (read, or recorded once by an
  empty-harness run and refused unless clean) -> one `observe` run with deadline min(20, 120, left) -> normalise ->
  subtract the baseline -> `contract_check.judge` -> Q8 verdict (violation REJECTED; anything incomplete UNRESOLVED;
  high-risk trigger unexplored UNRESOLVED; else VERIFIED with the bounded claim).
- `backend/cavr/gate_adapter.py`: `SETTINGS["deep"] = "sandbox"` (D7): one analyzer per gate run when the image
  passes its check, else none (today's verdicts); `details["deep_stage"]`; each row's `deep` block (status, rule,
  reason, elapsed, image ID, trace and baseline SHA-256, trace lines and check, run rule, key events, unexplored
  triggers, claim, not exercised); `BOUNDED_DEEP` when the deep stage is on.
- `backend/commands/report.py` (shared file): `cavr_deep(report)`, one line per package with a deep result under
  the module rows of `asent report`; `_cavr_packages` helper.
- Tests: `tests/test_cavr_sandbox_deep.py` (new).

### Design decisions

- **Recorded runs instead of a fake analyzer in the unit tests**: `OBSERVE` / `RUN_HARNESS` return the real traces of
  Step M2-12, so the normaliser, the baseline and the contract check are the real ones; only the container is not
  started. Alternative (a fake `analyse`) would test none of PRs 7-8.
- **Order of the Q8 rule**: the image is checked first (a run whose evidence names another image, or none, is
  UNRESOLVED DEEP_IMAGE_CHANGED even if it shows a violation: its events would be cached under the wrong identity);
  then a violation, also in a run that did not end well (D6) -> REJECTED; then the run's own problems, then events
  that cannot be judged, then unexplored triggers; VERIFIED only if all pass.
- **High-risk trigger** = a gated branch (`ast_scan` trigger) that reaches a sink whose capability the contract does
  not grant with `*`; any such trigger in any wheel of the tree is UNRESOLVED until Phase 3 (frontier rule).
  Conservative: it can only add UNRESOLVED, never a pass.
- **Baseline stored per identity** in `<data>/cavr/deep/baseline-<hash>.json`, written atomically, re-checked when
  read (identity, clean); a baseline that is not clean is never stored. Its run counts against the 300 s cap.
- **`DEEP_IMAGE_CHANGED`**: a run whose evidence names another image than the identity in the cache key is UNRESOLVED.
- **One analyzer per gate run** so the 300 s cap is per run; the per-package 120 s is also checked by `deep_stage`.
- **The deep stage turns itself off** without Docker or the image (`for_gate_run` -> None): the escalated package keeps
  `escalation: "deep analysis required (M2)"`, and `analyzer_version` is unchanged (D7).

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-4 / FR-13 | escalated packages get one install + import run in `asent-cavr-sandbox:local` through `verify_request` and `asent gate` |
| FR-6 (Q8) | violation REJECTED; timeout, incomplete trace, unknown event, baseline problem, image change UNRESOLVED; unexplored trigger UNRESOLVED |
| FR-15 | the deep result and its key event in `asent-report.json` and one line of `asent report` |
| NFR-4 | budget 20 s / 120 s / 300 s; deep time per package in the evidence (`elapsed_seconds`) |
| NFR-6 | VERIFIED states what was observed and what was not (`claim`, `not_exercised`) |

### Ch 7 Test cases

`tests/test_cavr_sandbox_deep.py`: 32 tests, 25 unit (real pipeline and recorded traces) and 7 Docker.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_clean_complete_run_without_triggers_is_verified` | Q8 all clauses | escalated demo, benign recording | VERIFIED DEEP_RUN_CLEAN, bounded claim, baseline recorded once | pass; superseded: renamed and now UNRESOLVED DEEP_SINK_NOT_EXERCISED (decision below) |
| `test_violation_is_rejected_with_the_event_as_evidence` | Q8 violation | probe recording | REJECTED, key events with line and syscall | pass |
| `test_timeout_is_unresolved` | Q8 budget | benign cut at 50 %, SANDBOX_TIMEOUT | UNRESOLVED SANDBOX_TIMEOUT | pass |
| `test_violation_before_a_timeout_is_rejected` | D6 | probe cut at 99.5 %, SANDBOX_TIMEOUT | REJECTED | pass |
| `test_incomplete_trace_is_unresolved` | Q8 trace | not attributable | UNRESOLVED TRACE_INCOMPLETE | pass |
| `test_unknown_event_is_unresolved` | Q8 unknown | inotify line inserted in the import step | UNRESOLVED EVENT_TYPE_UNKNOWN | pass |
| `test_a_run_on_another_image_is_unresolved` | cache key | evidence names another image | UNRESOLVED DEEP_IMAGE_CHANGED | pass |
| `test_escalated_package_with_an_unexplored_trigger_is_unresolved_until_the_frontier_exists` | frontier rule | `if os.getenv(...)` gates a connect | UNRESOLVED DEEP_TRIGGERS_UNEXPLORED, trigger listed | pass |
| `test_a_violation_wins_over_an_unexplored_trigger` | Q8 order | trigger + probe recording | REJECTED | pass |
| `test_trigger_gating_only_unrestricted_sinks_is_not_high_risk` | trigger rule | `*`, scoped, none | [], listed, listed | pass |
| `test_baseline_is_recorded_once_and_reused` | D2 | two analyzers | one baseline run, file with the identity | pass |
| `test_baseline_unavailable_is_unresolved`, `test_a_baseline_that_is_not_clean_is_refused_…`, `test_a_stored_baseline_of_another_identity_or_not_clean_is_refused` | D2 + Maryam's rule | failed run; probe as baseline; edited file | BASELINE_UNAVAILABLE / BASELINE_NOT_CLEAN / BASELINE_IDENTITY_MISMATCH; nothing stored | pass |
| `test_run_wide_cap_leaves_the_remaining_packages_unresolved` | 300 s cap | 4 packages, 100 s each | 4th DEEP_RUN_BUDGET_USED_UP, not run | pass |
| `test_package_deadline_is_cut_to_what_is_left` | budget | 140 s runs | deadlines 20, 20, then 18 | pass |
| `test_package_over_its_budget_is_unresolved_by_the_deep_stage` | 120 s | 121 s run | UNRESOLVED DEEP_BUDGET_EXCEEDED | pass |
| `test_identity_changes_with_image_harness_profile_and_budget` | cache key | each part changed | identity differs | pass |
| `test_a_new_image_is_a_cache_miss` | cache key | same package, new image | hit, then miss | fail, then pass (see defects) |
| `test_non_escalated_packages_never_reach_the_deep_stage` | escalated only | clean demo | no observe, no baseline, verdict as `deep=None` | pass |
| `test_no_docker_or_no_image_keeps_todays_behaviour` | D7 | ENGINE_UNAVAILABLE, IMAGE_MISSING, IMAGE_ID_MISMATCH | no analyzer; escalation string; same `analyzer_version` | pass |
| `test_the_gate_default_is_the_sandbox_and_it_turns_itself_off_without_an_image` | D7 | SETTINGS | `deep == "sandbox"` | pass |
| `test_gate_row_report_json_and_text_carry_the_deep_result` | FR-15 | `asent gate`, probe recording | exit 1, row `deep`, `deep_stage` on, one report line in `render` | pass |
| `test_gate_without_an_image_has_no_deep_row_and_no_report_line` | D7 | `asent gate`, IMAGE_MISSING | UNRESOLVED escalation, `deep: None`, no line | pass |
| `test_report_text_line_for_each_deep_result` | report | VERIFIED, REJECTED, none | two exact lines | pass |
| `test_demo_wheel_on_the_real_sandbox[benign]` (Docker) | demo | escalated, nothing at import | VERIFIED DEEP_RUN_CLEAN, 0 judged events | pass; superseded: now UNRESOLVED DEEP_SINK_NOT_EXERCISED (decision below) |
| `test_demo_wheel_on_the_real_sandbox[aws]` (Docker) | demo | reads `~/.aws/credentials` | REJECTED; SECRET_READ openat `/tmp/home/.aws/credentials` ENOENT | pass |
| `test_demo_wheel_on_the_real_sandbox[connect]` (Docker) | demo | connect 198.51.100.24:443 | REJECTED; NETWORK_CONNECT ENETUNREACH | pass |
| `test_demo_wheel_on_the_real_sandbox[shell]` (Docker) | demo | `subprocess.run(['/bin/sh', …])` | REJECTED; PROCESS_EXEC `/bin/sh` | pass |
| `test_demo_wheel_on_the_real_sandbox[env_trigger]` (Docker) | demo | connect behind `os.getenv` | UNRESOLVED DEEP_TRIGGERS_UNEXPLORED | pass |
| `test_asent_gate_end_to_end_on_the_real_sandbox[aws / benign]` (Docker) | end to end | `asent gate` | BLOCK exit 1 / ACCEPT exit 0, one report line each | pass; superseded: benign is now REVIEW exit 2 (decision below) |

Measured on the real sandbox (one run each, fresh data directory): every demo verdict took 4.0–4.5 s
including the baseline run; the container run itself 2.8–3.2 s.

No existing result changed (gate tests replace `SETTINGS` without a `deep` key; demo runs keep `deep=None`).
Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py tests/test_gate_*.py
tests/test_cli_gate.py tests/test_cli_report.py`: 1923 passed, 12 skipped (live), 577 s.

### Real projects (D7)

`asent gate --head main` on each target with the image `sha256:0e88dd461ca4…` built, a fresh data directory each run;
before = commit `d4dec7e` (no deep stage), after = PR 9.

| Project | Before: decision, CAVR / SATRA / SABLE, time | After: decision, modules, time | Deep stage after |
|---|---|---|---|
| asent-target-flask (main) | ACCEPT exit 0; pass / pass / pass; 133.3 s | ACCEPT exit 0; pass / pass / pass; 147.8 s | on (IMAGE_OK), no package reached it |
| asent-target-invoicehub (main) | ACCEPT exit 0; pass / pass / pass; 36.5 s | ACCEPT exit 0; pass / pass / pass; 37.2 s | on (IMAGE_OK), no package reached it |

No verdict changed. CAVR's own result is the same text in both: Flask "requirements.txt: no requirement was added or
changed" (verify `changed`, base = head = main, so nothing was verified); InvoiceHub "1 requested packages
verified: pypdf==6.21.4" (VERIFIED by the fast gate, not escalated). So neither project exercised the deep stage;
the five demo wheels did. The Flask time difference (+14.5 s) is within the spread of identical runs on this machine
(the same pre-PR 9 code took 168.3 s in an earlier run today; the post-PR 9 code 143.3 s in another).

### Defects found and fixed

- `test_a_new_image_is_a_cache_miss` first failed: the fake baseline run named the first image, and the analyzer
  refused it for the second image (correct behaviour); the test now records the baseline on the second image.
- Review: one cavr-reviewer pass over PRs 7-9 at the end of Phase 2b (outcome under "Review of steps M2-12 to M2-14").

### Known limitations / deferred

- One run, baseline environment only; the project's call sites are not executed; counterfactual runs (env, file,
  time, hostname) are Phase 3, so a package with a high-risk trigger is UNRESOLVED until PR 12.
- The demo project's label scopes make any file read or write by an escalated package UNRESOLVED (D5); mapping labels
  to paths is future work.
- Dashboard display of the deep result is Phase 5 (PR 19).
- p50/p95 of deep time across packages (NFR-4 metrics) are not yet in `pipeline.metrics`; each package's time is in
  its evidence.
- Neither real target project has an escalated package, so the real-project check shows only that nothing else changed.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `sandbox_deep.py`, the gate adapter and report changes, the tests and these notes.
  **Reviewed by Maryam:** Q8, D2, D6, D7, the budget, the demo wheel list, the real-project check.
  **Verified by:** the runs above on Docker 29.9.3.

### Supervisor Q&A prep

1. **When is a deep VERIFIED given?** Only when the one run completed, its trace is complete, every event minus the
   empty-harness baseline is within the contract, no gated branch reaches an ungranted sink, and every escalation
   reason ran in the import (decision below; `test_an_import_time_sink_inside_a_scoped_contract_is_verified`); it says
   it observed install + import only.
2. **What if Docker is missing in CI?** `for_gate_run` returns no analyzer and the gate gives exactly the verdicts it
   gave before (`test_no_docker_or_no_image_keeps_todays_behaviour`, `test_gate_without_an_image_…`).
3. **Why is the env-trigger wheel UNRESOLVED and not VERIFIED, though its run was clean?** Its import never took the
   `os.getenv` branch, so the sink behind it was never observed; until Phase 3 explores it, Q8 says incomplete.

### Decision after the review: an escalation reason the run did not exercise (Maryam, 2026-11-23)

Decision: when the escalation reason is a denied sink reachable from the project's call sites, an import-only run
cannot clear it -> UNRESOLVED `DEEP_SINK_NOT_EXERCISED`, naming the sink and the call sites, until Phase 3 drives
them. A deep VERIFIED is possible only when every escalation reason was exercised by the run; the deep block records
which reasons the run covered (review MINOR 1).

- **Ch 6 Implementation.** `backend/cavr/sandbox_deep.py`: `escalation_reasons(package, events)` takes every
  REACHABLE sink of the fast gate's reachability judgement; `sink_placement(wheel, file, line, sink)` parses the
  wheel's source and says whether the call is module-level code or inside a function / method / lambda. A reason is
  exercised when the call is module-level AND the import step has an event of the sink's capability (and, as for
  every VERIFIED, all events are within the contract). Order: violation -> run problems -> unjudged events ->
  unexplored triggers (DEEP_TRIGGERS_UNEXPLORED stays first, so the env-trigger wheel is unchanged) -> no reachable
  sink at all (DEEP_ESCALATION_UNKNOWN) -> any reason not exercised (DEEP_SINK_NOT_EXERCISED) -> VERIFIED.
  `evidence["escalation_reasons"]`: package, file, line, sink, capability, placement, events_of_capability,
  exercised, why, call_sites; `gate_adapter` copies it into the row's `deep` block; `asent report` names the first
  sink not exercised. `tests/test_cavr_data/traces/events-scoped` (new recording, same image; `record_events.py`
  can now re-record one stem).
- **Design decisions.** Both a static and a dynamic condition: module level alone is not enough (the module might not
  be imported by the top-level import, a plain `if` might not be taken, an exception might stop it before the call);
  an event alone is not enough (the event might come from other code). The only way an import-time sink stays inside
  a contract that denies it by default is a checkable scope, so the VERIFIED demo uses
  `NETWORK_CONNECT:198.51.100.24:443` (task "Billing dashboard") and connects there at import.
- **Requirements covered.** FR-6 / NFR-6: no VERIFIED for a reason the run did not cover; the deep block lists each
  reason and whether it was covered.

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_a_reachable_sink_the_import_never_ran_is_unresolved_not_exercised` (was `…_without_triggers_is_verified`) | decision | sink in `def send()`, benign recording | UNRESOLVED DEEP_SINK_NOT_EXERCISED naming `demo/net.py:5 socket.create_connection` and `app/uses_demo.py:5 demo.run`; not cached | pass |
| `test_an_import_time_sink_inside_a_scoped_contract_is_verified` | decision | module-level connect, scoped grant, `events-scoped` | VERIFIED; reason exercised, 1 NETWORK_CONNECT event | pass |
| `test_a_module_level_sink_that_shows_no_event_is_not_exercised` | dynamic condition | module-level sink, run without a connect | UNRESOLVED DEEP_SINK_NOT_EXERCISED, "did not run" | pass |
| `test_an_escalation_without_a_reachable_sink_is_unresolved` | fail closed | no REACHABLE sink | UNRESOLVED DEEP_ESCALATION_UNKNOWN | pass |
| `test_sink_placement_reads_the_wheel` | placement | module, function, lambda, method, no call, no wheel | as named | pass |
| `test_a_new_image_is_a_cache_miss` (changed) | cache key | now the import-time wheel (an UNRESOLVED is not cached) | hit, then miss | pass |
| `test_report_text_line_for_each_deep_result` (extended) | report | DEEP_SINK_NOT_EXERCISED row | `- not exercised: d/net.py:5 socket.create_connection (function send)` | pass |
| `test_demo_wheel_on_the_real_sandbox[benign]` (Docker, changed) | demo | sink in a function | UNRESOLVED DEEP_SINK_NOT_EXERCISED | pass |
| `test_demo_wheel_on_the_real_sandbox[import_time]` (Docker, new) | demo | module-level connect to the granted endpoint | VERIFIED DEEP_RUN_CLEAN | pass |
| `test_asent_gate_end_to_end_on_the_real_sandbox[aws / benign / import_time]` (Docker) | end to end | `asent gate` | BLOCK exit 1 / REVIEW exit 2 / ACCEPT exit 0 | pass |

Run before the commit (as Maryam asked, deep and gate tests only): `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_deep.py
tests/test_cavr_deep_stage.py tests/test_cavr_sandbox_events.py tests/test_cavr_contract_check.py tests/test_cavr_gate_adapter.py
tests/test_gate_*.py tests/test_cli_gate.py tests/test_cli_report.py tests/test_cavr_repair_surfaces.py`: 367 passed, 1 skipped
(live), 207 s; the 9 Docker deep tests alone: 9 passed in 51.7 s. No other existing result changed; no full-suite run.

## Review of steps M2-12 to M2-14 — fixes (2026-11-23)

Review outcomes (one cavr-reviewer pass over PRs 7-9, `git diff 7308c2c..HEAD`, 2026-11-23; 1753 passed, 70 skipped
without Docker at review time):
- Step M2-12 (PR 7): 1 pass, fix first (BLOCKER 1 and 2, events part); fixed below; 0 open MINOR.
- Step M2-13 (PR 8): 1 pass, fix first (BLOCKER 1, contract part); fixed below; 0 open MINOR.
- Step M2-14 (PR 9): 1 pass, fix first (BLOCKER 3, notes); fixed below; 0 open MINOR (MINOR 1 decided by Maryam: DEEP_SINK_NOT_EXERCISED, Step M2-14).

### Ch 6 Implementation

- `backend/cavr/sandbox_events.py` (EVENTS_VERSION `cavr-events/2`): every path a file call names (both paths of a
  rename / link, the real path, a symlink's target) is checked for sensitivity, also for writes; symlinks the run
  creates are recorded (`_State.links`, `_link_target`) and followed when later paths are resolved
  (`_State.follow`); a path through `/proc/<pid>/{root,cwd,fd,task,map_files}`, `/proc/thread-self` or `/dev/fd` is
  incomplete (`ALIASES`); `/nonexistent` (the cavr user's passwd home) is a home; `/proc/*/task/*/environ` is a secret;
  an unreadable address family is incomplete; any exception on a line makes that line UNKNOWN.
- `backend/cavr/contract_check.py` (CHECK_VERSION `cavr-contract-check/2`): `capability_of` returns every capability an
  event needs (a write naming a secret needs the write capability and SECRET_READ / SENSITIVE_FILE_READ), judged by
  `_one`; a file event whose path cannot be read is UNRESOLVED whatever is granted; pip touching a secret is outside
  its envelope.
- `backend/cavr/sandbox_deep.py`: the identity also covers the docker lockdown flags, the install tmpfs and the source
  of every module that decides a verdict (`VERDICT_CODE`); a run with an attributable trace and no image ID is
  DEEP_IMAGE_CHANGED.
- `docs/report-notes/cavr-report-notes.md`: Step M2-12's CODE_LOAD list (seven RUNTIME_FILES entries, not five);
  Step M2-14's Q8 order (the image is checked before a violation). `docs/cavr-m2-plan.md`: PR 7 says `-y` (as built),
  PR 9 says where deep time is (as built).

### Design decisions

- **Follow the run's own symlinks** instead of the reviewer's suggestion "no CODE_LOAD for a failed stat in
  /site/lib without a real path": Python's import probes in /site/lib are exactly such stats, so that rule would have
  turned every benign import into FILE_READ events (REJECTED under a deny-all contract). A symlink can only reach a
  secret if someone made it; /site/lib starts empty, pip writes regular files, and the package's own `symlink` is
  traced, so recording it and resolving later paths through it closes the hole without that cost.
- **A file event with an unreadable path cannot be granted**: found by the new
  `test_a_secret_read_through_proc_root_is_never_a_pass` (with `FILE_READ:*` it passed before this change).
- **Hash the verdict code into the identity**: a fix to the normaliser now invalidates cached deep verdicts by
  itself; the version strings were bumped as well.

### Requirements covered

| ID | Acceptance check |
|---|---|
| FR-13 / D4 | O_RDWR, rename, link, linkat, truncate, symlink naming a secret -> sensitive; secret via the run's symlink -> SECRET_READ |
| FR-6 | `/proc/self/root/...`, `/dev/fd/...` -> incomplete -> UNRESOLVED even with `FILE_READ:*`; a line that raises -> UNKNOWN |
| FR-10 / cache | identity changes with STRACE, PIP_INSTALL, IMPORT_ARGV, SITE_TMPFS, CAPABILITIES, both versions, the verdict code |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| `test_a_write_that_names_a_sensitive_path_is_also_sensitive` (6) | BLOCKER 1 | O_RDWR `.aws`, rename, link, linkat `/etc/shadow`, truncate `.netrc`, symlink to `.aws` | FILE_WRITE with `sensitive` | pass |
| `test_a_write_naming_a_secret_needs_the_secret_capability_too` (4) | BLOCKER 1 | same calls; `FILE_WRITE/READ:*`, `/tmp` scopes, + `SECRET_READ:*` | VIOLATION, VIOLATION, OK | pass |
| `test_a_path_through_a_proc_or_fd_alias_is_incomplete` (7) | BLOCKER 2 | `/proc/self/root/…`, `/proc/1/cwd`, `/proc/self/fd/3`, task root, thread-self, `/dev/fd/3/x`, map_files | incomplete | pass |
| `test_proc_self_exe_and_environ_are_not_aliases` | no false alarm | `/proc/self/exe`, `/proc/self/environ` | CODE_LOAD / SECRET_READ | pass |
| `test_a_symlink_the_run_made_is_followed_by_later_paths` | BLOCKER 2 | `/tmp/h -> /tmp/home`, relative `home` | later opens resolve to `/tmp/home/...`, SECRET_READ | pass |
| `test_a_symlink_in_the_install_target_is_not_a_code_load` | BLOCKER 2 | link in `/site/lib` to `.aws` | the link and the stat are SECRET_READ | pass |
| `test_a_failed_symlink_creates_no_link` | edge | EEXIST | not followed | pass |
| `test_more_sensitive_paths` (2) | BLOCKER 2 | `/nonexistent/.ssh/id_rsa`, `/proc/1/task/7/environ` | SECRET_READ | pass |
| `test_reading_a_secret_through_a_symlink_the_run_made_is_a_violation` | BLOCKER 2 | symlink + open, `FILE_READ/WRITE:*` | VIOLATION SECRET_READ | pass |
| `test_a_secret_read_through_proc_root_is_never_a_pass` | BLOCKER 2 | `/proc/self/root/...`, `FILE_READ:*` | EVENT_INCOMPLETE | fail, then pass (see design decisions) |
| `test_pip_touching_a_secret_is_outside_its_envelope` | D3 | install step renames `.aws/credentials` | INSTALL_OUTSIDE_ENVELOPE | pass |
| `test_an_unknown_address_family_is_incomplete_not_an_exception` | MINOR 2 | `sa_family=0x2a /* AF_??? */` | NETWORK_CONNECT, incomplete | pass |
| `test_a_line_the_code_cannot_handle_is_unknown_and_the_rest_is_kept` | MINOR 2 | a line that raises ValueError | UNKNOWN, next line still typed | pass |
| `test_a_run_without_an_image_id_is_unresolved` | MINOR 3 | probe recording, image ID None | DEEP_IMAGE_CHANGED | pass |
| `test_identity_changes_with_image_harness_profile_and_budget` (extended) | MINOR 4, 7 | 7 more parts and a source hash | identity differs each time | pass |
| `test_run_wide_cap_leaves_the_remaining_packages_unresolved` (stronger) | MINOR 5 | — | each of the first three ran | pass |
| `test_the_gate_default_is_the_sandbox_and_it_builds_an_analyzer_when_the_image_passes` (replaces the docstring test) | MINOR 6 | image passes | analyzer built, status on | pass |

No existing result changed. Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py
tests/test_gate_*.py tests/test_cli_gate.py tests/test_cli_report.py`: 1952 passed, 12 skipped (live), 649 s.

### Defects found and fixed

- BLOCKER 1 (reviewer): a write-class call never checked sensitivity, so O_RDWR / rename / link of a secret passed
  under a write grant. Fixed above.
- BLOCKER 2 (reviewer): lexical normalisation missed /proc and /dev/fd aliases, the run's own symlinks, the
  `/nonexistent` home and `/proc/*/task/*/environ`. Fixed above; one more case found by the new tests
  (an incomplete file event under `FILE_READ:*`), also fixed.
- BLOCKER 3 (reviewer): two statements in the notes did not match the code. Corrected.
- MINOR 2–8 fixed as listed; MINOR 9: `backend/commands/report.py` was in the approved plan of this phase (shared
  files, `[owner review: backend/commands/report.py]`); the dangling "Review of steps M2-12 to M2-14" pointer is
  this section.

### Known limitations / deferred

- MINOR 1 (decided by Maryam, 2026-11-23: UNRESOLVED DEEP_SINK_NOT_EXERCISED, see Step M2-14, "Decision after the
  review"): the fast gate escalates because a denied sink is reachable from the project's call
  sites; the deep run imports the package but never calls them, so a clean import gives VERIFIED although the
  escalating sink was never exercised. PR 9 of the plan asks for exactly this ("a benign wheel with a reachable sink
  and a clean complete run -> VERIFIED"), and the verdict's claim says the call sites were not executed. Alternative:
  UNRESOLVED until Phase 3 when the escalating sink is not behind a trigger.
- A truncated path whose real path shows a secret, under a denied capability, is EVENT_INCOMPLETE (UNRESOLVED), not a
  violation.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the fixes, tests and this section, from the cavr-reviewer report. **Reviewed by
  Maryam:** not yet. **Verified by:** the runs above.

### Supervisor Q&A prep

1. **Can a package read a credential through `/proc/self/root/...`, a symlink, a rename or an O_RDWR open?** Each
   is now an event the contract has to allow as a secret read (or, for /proc aliases, UNRESOLVED): 21 tests above.
2. **If the normaliser changes tomorrow, are old deep VERIFIEDs reused?** No: the identity in `analyzer_version`
   contains the SHA-256 of each module that decides the verdict, so the cache key changes.

### End-of-phase checks (after the review fixes, in the same commit)

- Docker hidden (`DOCKER_HOST=unix:///nonexistent`), `tests/test_cavr_*.py tests/test_orchestrator_config.py
  tests/test_gate_*.py tests/test_cli_gate.py tests/test_cli_report.py`: 1893 passed, 71 skipped (59 Docker, 12 live),
  0 failed, 385 s; `sandbox_deep.for_gate_run` -> no analyzer, ENGINE_UNAVAILABLE (today's verdicts).
- Full suite `.venv/bin/python -m pytest -q` (no CAVR_DOCKER): 2764 passed, 71 skipped, 1 xfailed, 1 failed, 1716 s
  (before Phase 2b: 2578 passed, 42 skipped, 1 xfailed, plus 7c7fc72's tests). The failure was
  `tests/test_satra_project_image_docker.py::test_pip_refuses_a_wheel_that_does_not_fit_even_past_the_tag_check`
  (SATRA, not changed in `7308c2c..HEAD`); it passed alone (9 s) and its file passed twice in a row (8 passed in
  260 s and in 650 s), so it is recorded as load-dependent, not caused by this phase.
- `reports/scenario-validation.json` was not modified by the run (no diff); nothing to restore.


## For Sheharyar (SATRA owner): a load-dependent Docker test (2026-11-23)

Seen in the full-suite run at the end of CAVR Phase 2b (no SATRA file changed in `7308c2c..HEAD`):
`tests/test_satra_project_image_docker.py::test_pip_refuses_a_wheel_that_does_not_fit_even_past_the_tag_check`
failed once in `.venv/bin/python -m pytest -q` (1716 s run, alongside CAVR's Docker image tests), then passed alone
(9 s) and its file passed twice in a row (8 passed in 260 s, then in 650 s). The traceback of the failure was not kept
(the run's output was cut to its last lines), so the cause is not known; the long, varying file times suggest a
timeout or Docker-load dependency. Suggested check: run the file under load (e.g. with CAVR_DOCKER=1 tests in
parallel) with `-x --tb=long`.


## Step M2-15 — Trigger frontier from the verified wheel (PR 10) (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 10, Q8 frontier rule; Phase 3a plan approved by Maryam, 2026-11-23 (decisions 1–4
and the additions: `frontier_residual` for PR 12, the `other_guards` rule recorded for PR 12, sandbox-evasion checks
UNRESOLVED by design).

### Ch 6 Implementation

- `backend/cavr/trigger_frontier.py` (new). `frontier(nodes, contract, now=, limit=32)` re-hashes each wheel of the
  verified tree (mismatch -> `ARTIFACT_CHANGED`), parses every `.py` entry after `wheel_meta.check_entries` (nothing
  imported or run) and returns the ordered, bounded list of conditions that guard a sink.
  - `FileScan` walks each module's statements with a path of enclosing guards: `if` body / `else`, `while` body,
    early exits (`if X: return` puts `not X` in front of the rest of the block), nested guards; calls to module-level
    functions of the same file are followed (`CALL_DEPTH` 5). Sinks: threat-repo `python_sinks` with import aliases
    resolved, plus reads of a secret path named by a string constant (`SECRET_READ`).
  - `build_scope` / `Scope`: import aliases and names assigned exactly once per scope (module, function, class).
  - `families_of`: the families a condition reads (env, time, file, host, user, argv, platform, obfuscated); a guard
    with none is an `other_guard`, not a trigger.
  - `Evaluator`: an AST walk (never `eval`) with Kleene logic for unknown values; `search` tries candidate
    environments built from the condition's constants (at most 512, in rounds so that a key read only behind
    another is found); `activate` gives the smallest change from the baseline run, or why there is none (another
    platform, UID 0, os.getlogin, a file outside the sandbox HOME, an invalid hostname, computed / obfuscated values).
  - Risk from the worst sink against the contract (`contract_check.read_contract`): high / medium / low; priority
    = sink_risk × reachability_confidence × novelty / run_cost, all factors in the entry.
  - `frontier_residual(frontier, explored)`: the pure check PR 12 calls; missing / incomplete / truncated frontier,
    any unsimulable entry, or an unexplored simulable entry -> UNRESOLVED, `verified_possible: False`.
- Key algorithm: for each sink with a non-empty guard path -> split the path into trigger guards and opaque guards ->
  evaluate the conjunction of the trigger guards (with polarity) in the baseline world and in every candidate world
  (also at t + 60 s for clocks) -> smallest true candidate = activation -> risk and score -> sort (risk, −score,
  package, file, line, id) -> novelty 0.5 for a repeated activation -> sort again -> cut at `limit`.
- `docs/cavr-m2-plan.md`: PR 10 "as built", the PR 12 records, progress.

### Design decisions

- **New module, `trigger_discovery.py` unchanged.** It feeds `ast_scan` (fast gate, cached) and the PR 9
  `high_risk_triggers`; changing its output would change PR 9 verdicts. Alternative (extend it in place) rejected for
  that reason; PR 12 swaps `high_risk_triggers` onto the frontier.
- **Activation by evaluating the condition**, not by pattern rules per family: `and` / `or` / `not`, `.lower()`, day
  counts and `in (…)` fall out of one evaluator, and "simulable" means "a candidate environment was found that makes
  the condition true", checked, not assumed. Trade-off: only modelled calls are known; anything else is unknown ->
  unsimulable (fail closed).
- **Kleene logic** so that `sys.platform == 'win32' or os.getenv('CI') == 'true'` is simulable through its second side
  while `… and …` is not.
- **The baseline world has the PR 11 canary files** (`CANARY_FILES`), so a check for `~/.aws/credentials` is taken by
  the canary run itself (`baseline_takes_it`).
- **Files only under the sandbox HOME**; any other path is unsimulable (whether the image has it is not known
  statically). Consequence: sandbox-evasion checks such as `/.dockerenv` are UNRESOLVED by design.
- **Bound 32 entries, `dropped` counted per risk**: PR 12's `frontier_residual` treats a cut frontier as UNRESOLVED,
  so the bound can never hide a trigger.
- **Deterministic**: sorted nodes and files, stable ids (SHA-256 of package, version, file, guard lines), `now` is an
  argument and recorded.

### Requirements covered

- FR-12 trigger frontier: env / time / file / host / user / argv / platform conditions in front of a sink, each with
  risk, priority factors and an activation or an unsimulable reason. Check: `tests/test_cavr_trigger_frontier.py`.
- Q8 frontier rule (prepared for PR 12): an unsimulable trigger can never give VERIFIED. Check:
  `test_an_unsimulable_entry_is_always_unresolved` (all risks, explored or not).
- FR-6 fail closed: hash mismatch, unparsed source, native code, unreadable contract all fail closed.

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_ci_true_is_a_simulable_env_trigger | env wheel | `os.environ.get('CI') == 'true'` | env {CI: true}, high | pass |
| test_after_a_date_is_a_simulable_time_trigger | time wheel | `date.today() >= date(2027,1,1)` | time ≥ 2027-01-01 | pass |
| test_kube_config_exists_is_a_simulable_file_trigger | file wheel | `exists(expanduser('~/.kube/config'))` | file /tmp/home/.kube/config | pass |
| test_a_hostname_is_a_simulable_host_trigger | host wheel | `gethostname() == 'build-prod-7'` | hostname build-prod-7 | pass |
| test_win32_platform_check_is_unsimulable_and_says_so | platform wheel | `sys.platform == 'win32'` | unsimulable, reason names win32 / Linux | pass |
| test_reading_the_aws_key_and_sending_it_is_a_secret_read_sink | canary wheel | read ~/.aws/credentials + connect | SECRET_READ and NETWORK_CONNECT sinks | pass |
| test_env_predicates_get_the_value_that_makes_them_true (6) | env forms | truthiness, in, [], .lower(), and, in tuple | the right values | pass |
| test_time_predicates_with_constants_are_simulable (5) | time forms | datetime, timestamp, day count, timedelta, fromisoformat | simulable, after now | pass |
| test_a_date_already_passed_is_taken_by_the_baseline | edge | date in the past | baseline_takes_it | pass |
| test_a_time_compared_with_a_computed_value_is_unsimulable | failure | `time.time() - getmtime(__file__)` | unsimulable | pass |
| test_file_predicates_under_home_are_simulable (3) | file forms | os.path.join, joinpath().is_dir(), `/` | file / dir | pass |
| test_a_canary_file_is_there_in_every_run_so_the_baseline_takes_it | edge | exists(~/.aws/credentials) | baseline_takes_it | pass |
| test_a_file_outside_the_sandbox_home_is_unsimulable (3) | evasion | /.dockerenv, not /.dockerenv, /etc/... | unsimulable | pass |
| test_other_hostname_reads_are_simulable (2), test_an_invalid_hostname_constant_is_unsimulable | host | platform.node, uname, `bad_host!` | simulable / unsimulable | pass |
| test_getuser_is_set_through_the_login_variables, test_root_and_login_checks_are_unsimulable (3) | user | getuser, getuid==0, getlogin | LOGNAME/USER / unsimulable | pass |
| test_argv_predicates_are_simulable (3) | argv | in, len, slice | argv lists | pass |
| test_platform_checks (5) | platform | linux, != win32, nt, Darwin, startswith('win') | baseline or unsimulable | pass |
| else / early exit / nested / or / and / call / opaque / alias / once / twice / while (11 tests) | guard shapes | — | polarity, how, confidence, families | pass |
| test_obfuscated_or_computed_reads_are_unsimulable (4) | failure | getattr, __import__, join, chr | unsimulable | pass |
| test_risk_follows_the_contract (3), test_an_unreadable_contract_makes_every_entry_high | risk | denied / scoped / * / unreadable | high / medium / low / high | pass |
| test_the_design_high_and_low_examples_rank_as_in_section_6_3 | §6.3 | exec (denied) vs connect (*) | exec first | pass |
| test_the_same_activation_twice_halves_the_novelty_of_the_second | novelty | two `getenv('CI')` | 1.0, 0.5 | pass |
| test_the_frontier_is_bounded_and_counts_what_it_dropped | bound | 10 triggers, limit 4 | 4 kept, 6 dropped high | pass |
| test_the_frontier_is_deterministic_and_does_not_depend_on_node_order | determinism | shuffled nodes ×4 | identical JSON | pass |
| test_a_wheel_whose_bytes_changed_is_artifact_changed, …_cannot_be_parsed…, test_native_code…, test_no_nodes… | failure | wrong sha, bad .py, .so, [] | not ok, rule | pass |
| test_an_unsimulable_entry_is_always_unresolved (6), …_wins_over_everything_else | Q8 for PR 12 | unsimulable × risk × explored | UNRESOLVED TRIGGER_UNSIMULABLE | pass |
| test_an_unexplored_simulable_entry_is_unresolved_and_a_baseline_one_is_not | PR 12 check | explored [] / [s1] | UNEXPLORED / EXPLORED | pass |
| test_a_missing_incomplete_or_truncated_frontier_is_unresolved (4), test_a_real_frontier_with_a_win32_check_cannot_give_verified | PR 12 check | — | UNRESOLVED | pass |

84 tests, 84 passed. No existing result changed. `CAVR_DOCKER=1 pytest tests/test_cavr_trigger_frontier.py
tests/test_cavr_sandbox_*.py tests/test_cavr_deep_stage.py`: 545 passed, 240 s. Full suite `.venv/bin/python -m pytest -q`: 2852 passed, 73 skipped, 1 xfailed, 1 failed, 1828 s; the failure was
`tests/test_cli_packaging.py::test_wheel_holds_nothing_else` (the built wheel held the new modules, which git did not
track yet); after `git add` that file passed (12 passed, 9 s).

### Defects found and fixed

- Between activations of equal size the first test run picked by JSON text (`dir` before `file`, a longer argv list);
  4 tests failed. Fixed: ties go to the first candidate in candidate order.
- The full suite's packaging check failed while the new modules were untracked (see Ch 7); no code change needed.

### Known limitations / deferred

- Sandbox-evasion checks (`/.dockerenv`, any file outside the sandbox HOME) are unsimulable, so UNRESOLVED by design.
- Not scanned for guards: `try` / `import` guards, `match` cases, conditional expressions (`a if c else b`), `sleep`
  delays, the cloud metadata address; calls are followed only within the same file; a sink reached through a method
  of an object (`s.connect`) is found only if the threat-repo rules name it.
- Values are known only for the modelled calls; everything else (a file's content, a computed name, `os.getlogin`) is
  unknown. Corrected after the review (as first written, this line said "-> unsimulable", which was not true): a
  guard with no family on the entry's path does not make it unsimulable; it makes `baseline_takes_it` False and is
  listed in `opaque_guards`, and only a run that showed the sink counts (`frontier_residual`, Step M2-16).
- A clock condition the baseline takes is checked at the analysis time (and 60 s later), not at the run's start.
- Not modelled: `nonlocal` rebinding, attributes set from another module (`demo.FLAG = …`), environment writes
  other than through `os.environ` / `os.putenv` / `os.unsetenv` in the wheels' own code (e.g. through ctypes).
- The link from a trigger to the project's import closure (`reachability`) and the `other_guards` rule are PR 12.
- Review (one cavr-reviewer pass over Steps M2-15 and M2-16): fix first; 3 BLOCKER and 2 MAJOR in this step's
  evaluator, fixed in the PR 11 commit (Step M2-16, "Defects found and fixed"); 0 open MINOR.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `trigger_frontier.py`, its tests, these notes and the plan edits, from the approved
  plan. **Reviewed by Maryam:** the plan and decisions 1–4; the code not yet. **Verified by:** the runs above.

### Supervisor Q&A prep

1. **How do you know a trigger is simulable, rather than guessing from its shape?** The evaluator computes the
   condition in the candidate environment and the entry is simulable only if it comes out true (also 60 s later for
   clocks); PR 11's Docker tests then show the branch really runs under that spec.
2. **Why is `sys.platform == 'win32'` not just skipped as irrelevant on Linux?** Code CAVR cannot run is code CAVR
   has not observed; Q8 says incomplete -> UNRESOLVED, and `frontier_residual` enforces it.
3. **Can the bound of 32 hide a malicious trigger?** No: anything cut is counted in `dropped`, and a non-zero
   `dropped` makes `frontier_residual` UNRESOLVED.


## Step M2-16 — Run specs with libfaketime and per-run canaries (PR 11) (2026-11-23)

Plan: `docs/cavr-m2-plan.md` PR 11, Q7, Q8, Q12, sandbox rule 7; Phase 3a plan approved by Maryam, 2026-11-23
(decisions 1–4; the fake HOME 0700 and removed after every run).

### Ch 6 Implementation

- `backend/cavr/env_synthesis.py` (new): `canaries` (four canary files and four canary variables, each a new
  `secrets` value), `canary_spec`, `synthesize(entry)` (a frontier entry's activation -> a spec: env, libfaketime
  clock, HOME files with a canary as content, hostname, argv; refused when unsimulable or unsafe), `step_env`
  (`LD_PRELOAD`, `FAKETIME="@…"`, `FAKETIME_DONT_FAKE_MONOTONIC=1`, `FAKETIME_DISABLE_SHM=1`), `canary_forms`
  ((kind, bytes): verbatim, hex, base64 at three alignments).
- `backend/cavr/sandbox_spec.py` (new): `run_spec(nodes, modules, spec, contract=)` stages the verified wheels,
  writes the spec's HOME into a new 0700 host directory (files 0644, directories 0755) mounted read-only at /tmp/home,
  runs `install` (HOME=/tmp/install-home, no canary) and `imports` (`SPEC_IMPORT_CODE` sets `sys.argv`, then imports)
  with `STRACE_SPEC` (PR 9's command, `-s 65536`, plus write, pwrite64, writev, pwritev, pwritev2), `--hostname`, a
  64 MiB trace cap; removes the HOME in `finally` (`home_removed`, else `SPEC_HOME_LEFT_BEHIND`); normalises with the
  canaries and judges. Always UNRESOLVED: not a verdict.
- `backend/cavr/sandbox_events.py`: write-family syscalls (NO_EFFECT, or NETWORK_CONNECT into a socket);
  `normalise(..., canaries=None)`; `canary_check` decodes every quoted string of a write / send / connect line
  (`c_string`), looks for each canary form in each piece and in their concatenation -> `CANARY_EXFIL_ATTEMPT`; a cut
  string, a shortened array or a buffer printed as an address -> `CANARY_UNCHECKED`. `EVENTS_VERSION` cavr-events/3.
- `backend/cavr/contract_check.py`: `CANARY_EXFIL_ATTEMPT` is a violation (`CANARY_EXFIL`) in every step, before the
  install envelope; `CANARY_UNCHECKED` -> UNRESOLVED `CANARY_CHECK_INCOMPLETE`, except pip's writes to files under
  /tmp/ or /site/lib/ in the install step (`_pip_file_write`). `CHECK_VERSION` /3.
- `backend/cavr/sandbox_exec.py`: `HOSTNAME`, `DEFAULT_HOSTNAME`; `lockdown_flags(seccomp, hostname)` and
  `docker_command(..., hostname=)` (checked; default output unchanged). `backend/cavr/sandbox_observe.py`:
  `run_harness(..., strace=None, hostname=None)` (defaults: PR 9's). `trigger_frontier.py` uses `sandbox_exec.HOSTNAME`.
- Deleted (Q12, decision 1): `backend/cavr/triggers.py`, `backend/cavr/counterfactual.py`, and their 43 tests in
  `tests/test_cavr_sandbox_runner.py` (36 `baseline_behaviors`, 7 `CounterfactualEngine`).
- `tests/test_cavr_data/traces/record_events.py`: recordings `spec-canary`, `spec-clean` (real `run_spec` runs).
- Key algorithm: spec -> host HOME (0700) -> two steps, canaries only in the imports step -> strace with whole payloads
  up to 64 KiB -> every write / send / connect: decode its strings, search every canary form -> exfiltration event or
  unchecked event -> contract check (a leak is always a violation) -> HOME removed.

### Design decisions

- **HOME as a read-only bind mount** (decision 2), not written by the harness: the harness and its SHA-256 stay the
  same, and no setup write appears in the trace as if the package made it. Trade-off: the package cannot write into
  HOME (an attempt is still an event). The host directory is 0700, so no other host user can read the canaries; the
  mounted HOME inside it is 0755 / 0644 so that UID 10001 can.
- **Separate strace for spec runs** (`STRACE_SPEC`): PR 9's command and every PR 9 verdict stay as they are.
  `-s 65536` because pip writes at most 65536 bytes per call (measured 2026-11-23; no install write was cut in either
  recording), so only a package's own larger writes can be cut, and those are UNRESOLVED.
- **Cut pip writes exempt** (decision 3): a pip write into a file under /tmp/ or /site/lib/ carries the verified
  wheel's bytes, and the canaries are drawn after that hash was checked. Every other cut payload is UNRESOLVED.
- **Hex and base64 as well as verbatim** (decision 4): base64 at all three alignments, only the whole groups that
  depend on the canary alone, so a canary inside a larger encoded blob is found too.
- **`FAKETIME_DISABLE_SHM=1`**: measured without it, libfaketime 0.9.10 creates and unlinks a POSIX semaphore in
  /dev/shm (three FILE_WRITE events attributed to the package). With it, only code loads are added. No capability and
  no seccomp change.
- **A trigger's value wins over a canary variable of the same name**, and that variable leaves the registry: a value
  the package compares with a constant is known to it, so finding it in a payload would prove nothing.

### Requirements covered

- FR-4 (part): one counterfactual run per spec, real container, real trace. Check: `test_each_trigger_type_fires_under_its_spec_and_not_without_it` (env, date, file, hostname, argv).
- Sandbox rule 7 (canaries only, random per run, registered). Check: `test_canaries_are_unique_in_a_run_and_new_in_every_run`, `test_no_host_environment_value_reaches_a_run`.
- FR-13 (canary data flow): a canary in a write / send / connect is CANARY_EXFIL_ATTEMPT, a violation even under
  `--network none`. Check: `test_reading_the_fake_aws_key_and_sending_it_is_a_canary_exfiltration_attempt`.
- FR-6 / Q8 fail closed: a payload that cannot be checked is UNRESOLVED; a HOME that cannot be removed is UNRESOLVED.
- Q7: time through libfaketime, no capability. Check: `test_the_date_spec_moves_the_packages_clock_and_nothing_else`.

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_each_trigger_type_fires_under_its_spec_and_not_without_it[env/date/file/hostname/argv] (Docker) | each trigger fires | wheel with `CI=true` / date ≥ 2027-01-01 / ~/.kube/config / hostname build-prod-7 / `--deploy` | connect to 198.51.100.24:443 under the spec, none under canary_spec | pass |
| test_the_date_spec_moves_the_packages_clock_and_nothing_else (Docker) | libfaketime | faketime 2031-05-06 07:08:09 | package prints that clock; judged OK | pass |
| test_the_win32_wheel_is_unsimulable_and_gets_no_run (Docker file) | unsimulable | `sys.platform == 'win32'` | no spec; frontier_residual UNRESOLVED | pass |
| test_reading_the_fake_aws_key_and_sending_it_is_a_canary_exfiltration_attempt (Docker) | canary leak | read ~/.aws/credentials, UDP sendto | CANARY_EXFIL_ATTEMPT file:aws-secret-key; VIOLATION | pass |
| test_every_spec_has_the_file_and_variable_canaries, …_unique…, …_the_ones_the_frontier_counts… | canaries | canary_spec() | 9 canaries, each in its file / variable, new every run | pass |
| test_canary_forms_… (3) | forms | value, prefixes, digits | verbatim / hex / base64 found at every offset; one hex form for digits | pass |
| test_env_spec … test_argv_spec (8) | one spec per family | frontier entries | env, faketime + LD_PRELOAD, file with canary, dir, hostname, argv | pass |
| test_a_trigger_that_sets_a_canary_variable_wins_and_that_canary_is_dropped | edge | GITHUB_TOKEN compared | trigger value, canary dropped | pass |
| test_an_unsimulable_entry_gives_no_spec | failure | win32 entry | TRIGGER_UNSIMULABLE | pass |
| test_a_spec_that_cannot_be_built_safely_is_refused (13), test_a_canary_path_or_parent_already_there_is_accepted | failure | HOME, LD_PRELOAD, PYTHONPATH, NUL, /etc, `..`, canary collisions, bad host, 1960, argv NUL | SPEC_REFUSED / accepted | pass |
| test_the_spec_run_mounts_a_read_only_home_built_from_the_spec | HOME | canary_spec | bind readonly at /tmp/home; root 0700; files 0644; removed | pass |
| test_the_fake_home_is_removed_after_a_timeout_or_a_failure (2), …_when_writing_it_fails, test_a_home_that_cannot_be_removed_is_unresolved | nothing left behind | TIMEOUT, engine fault, bad path, rmtree fails | HOME gone / SPEC_HOME_LEFT_BEHIND | pass |
| test_the_steps_give_canaries_only_to_the_imports_step, test_the_spec_run_uses_its_own_strace…, test_the_pr9_strace_and_flags_are_unchanged | steps | — | install HOME=/tmp/install-home; STRACE_SPEC; PR 9 STRACE -s 4096, cavr-sandbox | pass |
| test_no_host_environment_value_reaches_a_run | rule 7 | three host secrets set | absent from docker argv, job file, HOME; only the nonce variable | pass |
| test_docker_refuses_an_invalid_hostname (4), test_a_wheel_whose_quarantine_bytes_changed… | failure | bad names; wrong sha | ValueError; WHEEL_HASH_MISMATCH, nothing started | pass |
| test_a_canary_in_a_write_send_or_connect_is_an_exfiltration_attempt (6) | canary check | sendto, write, writev, sendmsg, AF_UNIX path, abstract name | one CANARY_EXFIL_ATTEMPT | pass |
| base64 / hex, split over iov, env canary, escapes decoded, no canary, without canaries (7) | canary check | — | found / not found as stated | pass |
| cut payload, cut with canary, shortened array, address buffer, file path kept (5) | not checkable | — | CANARY_UNCHECKED | pass |
| exfil always a violation (2), in install step, failed under network none; unchecked UNRESOLVED; pip file write exempt; pip pipe / other path not (2) | judged | — | VIOLATION / UNRESOLVED / OK | pass |
| test_recorded_leaks_are_each_found_with_the_canary_that_leaked, …_cut_write…, …_clean_run…, …_violation_under_any_contract | recorded runs | spec-canary, spec-clean (2026-11-23, image sha256:0e88dd46…) | 4 leaks with their canary and form; 1 unchecked (imports); clean run OK | pass |

44 + 34 + 8 = 86 new tests, all passed. `CAVR_DOCKER=1 pytest tests/test_cavr_trigger_frontier.py
tests/test_cavr_env_synthesis.py tests/test_cavr_canary_events.py tests/test_cavr_sandbox_*.py
tests/test_cavr_deep_stage.py tests/test_cavr_contract_check.py`: 647 passed, 249 s; no fake HOME and no container
left. Existing results changed: only the 43 removed tests (decision 1).

After the review fixes: 113 frontier tests (84 + 29), 48 synthesis / spec-run tests, 36 canary-event tests, 8 Docker
tests. `CAVR_DOCKER=1` run of the same files: 682 passed, 239 s; no fake HOME and no container left.

| Test ID (review of PRs 10-11) | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_the_baseline_environment_is_the_real_runs_so_an_early_exit_on_it_is_never_passed (4) | BLOCKER 1 | `if PYPI_TOKEN / GITHUB_TOKEN / PATH / HOME…: return` before a sink | not baseline-taken, unsimulable | pass |
| test_a_condition_that_needs_a_canary_variable_unset_is_unsimulable, …_may_still_be_set_to_a_constant, test_a_sandbox_variable_cannot_be_changed | BLOCKER 1 | GITHUB_TOKEN is None / == const; HOME == /root | unsimulable / simulable / unsimulable | pass |
| test_a_bool_op_used_as_a_value_with_an_unknown_operand_is_unknown (2), test_a_bool_op_in_a_condition_keeps_kleene_logic | BLOCKER 2a | `(helper() or getenv(...)) == 'prod'`; `helper() or getenv('CI')` | unknown / Kleene | pass |
| test_a_keyword_default_of_environ_get_is_used | BLOCKER 2b | `environ.get('SAFE', default='1')` early exit | not baseline-taken | pass |
| test_an_opaque_guard_alone_never_lets_the_baseline_take_the_entry, test_every_simulable_entry_needs_run_evidence_also_one_the_baseline_takes | BLOCKER 3 | `not getenv('CI')` + `uptime() > 3600` | baseline_takes_it False; UNRESOLVED until explored | pass |
| test_an_elif_chain_of_early_exits_puts_every_condition_in_front_of_the_sink, test_a_nested_exit_…_makes_what_follows_opaque, test_a_loop_whose_body_breaks_does_not_hide_what_follows | MAJOR 1 | if/elif returns; nested return; loop break | both guards; may-exit; none | pass |
| test_a_package_that_writes_its_own_environment_makes_env_reads_unknown (4), …_in_another_module…, test_a_constant_env_write_only_hides_that_variable, test_a_global_rebinding_… | MAJOR 2 | environ[]=, setdefault, putenv, update; other module; other key; global | unsimulable / simulable | pass |
| test_is_between_strings_is_unknown, test_a_hostname_with_a_trailing_newline_is_not_a_hostname, test_a_method_does_not_see_its_class_scope | MINOR 2, 1, 6 | `is 'true'`, `'build\n'`, class attr | unknown, unsimulable, module name | pass |
| test_a_frontier_whose_counts_do_not_add_up_is_unresolved (3), test_every_other_guard_is_listed | MINOR 4 | bad total / count / no id; 40 guards | FRONTIER_MALFORMED; all 40 listed | pass |
| test_a_spec_path_that_is_not_normal_is_refused_…, test_an_iov_printed_as_an_address_is_unchecked (2), test_the_pr9_strace_and_flags_are_unchanged, test_the_frontiers_canary_variables_have_the_shapes_…, refusals of `X\n` / `build\n` | MINOR 5, 7, 9, 1 | — | refused / unchecked / identical / same shapes | pass |

End-of-phase checks (after the review fixes):
- Docker hidden (`DOCKER_HOST=unix:///nonexistent`), `tests/test_cavr_*.py tests/test_orchestrator_config.py
  tests/test_gate_*.py tests/test_cli_gate.py tests/test_cli_report.py`: 2051 passed, 81 skipped (Docker and live),
  0 failed, 393 s; `sandbox_deep.for_gate_run` -> no analyzer, ENGINE_UNAVAILABLE (today's verdicts); `run_spec` ->
  UNRESOLVED ENGINE_UNAVAILABLE, fake HOME removed.
- Full suite `.venv/bin/python -m pytest -q`: 2923 passed, 81 skipped, 1 xfailed, 0 failed, 1081 s.
- `reports/scenario-validation.json` was not modified by the runs (no diff); nothing to restore.

### Defects found and fixed

- `canary_forms` dropped repeated forms and the normaliser named forms by position: for a canary of digits (hex
  without letters, upper == lower) every base64 form was called "hex". Fixed: (kind, bytes) pairs; test added.
- The test of a HOME that cannot be removed left its directory in /tmp (three runs, three directories). Fixed: the
  test removes it and checks.
- The file-trigger Docker test expected the quiet run to be OK; the condition itself stats ~/.kube/config, a
  SECRET_READ attempt that a deny-all contract does not grant. The test now expects exactly that one violation.
- Review (one cavr-reviewer pass over Steps M2-15 and M2-16; fixed here, tests in the table above):
  - BLOCKER 1: the evaluator's baseline had an empty environment, so an early exit on a variable every run has
    (`if "PYPI_TOKEN" in os.environ: return`) looked passed by the baseline. Fixed: `BASELINE_ENV` = the harness's
    CHILD_ENV + the canary variables in their shapes; a sandbox variable keeps its value, a canary variable is never
    unset (a condition that needs it unset is unsimulable).
  - BLOCKER 2: `a or b` with an unknown operand returned True / False as its value; `os.environ.get(k, default=…)`
    ignored the keyword. Fixed: `Evaluator.test` does Kleene logic only where truth is used; `e_BoolOp` returns the
    Python value or unknown; the keyword default is read.
  - BLOCKER 3: guards with no family were left out of `baseline_takes_it`, and `frontier_residual` trusted it. Fixed:
    an entry with an opaque guard is never baseline-taken; `frontier_residual` needs every simulable id in
    `explored` (PR 12 adds an id only when a run showed the entry's sink).
  - MAJOR 1: only the last statement's exit counted. Fixed: `_fall_through` puts each `if` / `elif` early exit in
    front of what follows; any other nested return / raise / exit adds a `may-exit` opaque guard.
  - MAJOR 2: a package writing its own environment was not modelled. Fixed: `env_writes` (os.environ[...] =, del,
    setdefault, pop, update, clear, putenv, unsetenv) over the whole tree makes those reads unknown; a `global`
    rebinding makes the module name computed.
  - MINOR 1-9 fixed: `fullmatch` for host and variable names; `is` only for None / booleans; the baseline-clock
    limitation noted (Step M2-15); `frontier_residual` refuses malformed frontiers and `other_guards` is no longer
    cut; spec paths must be normal; an iov printed as an address is unchecked; methods skip the class scope; the
    canary-check gaps are listed below; the PR 9 strace and flags are compared in full.
  - Review outcome: 1 pass, fix first (3 BLOCKER, 2 MAJOR, 9 MINOR), all fixed; 0 open MINOR.

### Known limitations / deferred

- Sandbox-evasion checks (`/.dockerenv`, files outside the sandbox HOME) are unsimulable and so UNRESOLVED by design.
- Canary matching: verbatim, hex, base64 only; a canary split over two calls, only part of a canary
  (`secret[:16]`), MIME line-wrapped base64, an encrypted or otherwise encoded canary is not found; a canary in exec
  argv or in a file name is not checked.
- What strace's view of a payload misses: another thread rewriting the buffer after strace read it (ptrace
  time-of-check / time-of-use); data paths with no printed payload (sendfile, splice, vmsplice, writes through an
  mmap'd file).
- A canary written to stdout or a /tmp file counts as exfiltration (the user's rule: any write); a package that logs
  its configuration is REJECTED by such a run, by design.
- A package write over 64 KiB in the imports step is UNRESOLVED; a wheel whose install fills the 64 MiB trace cap is
  UNRESOLVED.
- HOME is read-only for the package; files only under HOME.
- Not wired into any verdict; the loop, budget, `other_guards` rule and the swap of `high_risk_triggers` are PR 12.
- `trigger_discovery.py` (fast gate, LOCAL lab) and `sandbox_runner.py` (`tests/test_cli_resources.py`,
  `docker/asent-sandbox/`) stay until PR 12.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `env_synthesis.py`, `sandbox_spec.py`, the edits to `sandbox_events.py`,
  `contract_check.py`, `sandbox_exec.py`, `sandbox_observe.py`, the tests, the recordings, these notes and the plan
  edits, from the approved plan. **Reviewed by Maryam:** the plan and decisions 1–4; the code not yet. **Verified
  by:** the runs above (real Docker runs for every trigger type and the leak).

### Supervisor Q&A prep

1. **The sandbox has no network: how is a leak a leak?** The attempt is the evidence. strace prints the payload of
   `sendto` before the kernel refuses it (ENETUNREACH), and a random value only this run's fake credential holds
   cannot be in that payload by chance; the recorded run shows the secret in the sendto line.
2. **Could libfaketime itself cause events and make a clean package look bad?** Measured: with shared memory off it
   adds only code loads (`test_the_date_spec_moves_the_packages_clock_and_nothing_else` judges that run OK).
3. **Why is a cut payload UNRESOLVED and not ignored?** The canary could be in the part strace did not print; Q8 says
   anything incomplete is UNRESOLVED. pip's file writes are the only exemption, and they never reach the cut limit.


## Step M2-17 — Counterfactual activation loop and driven call sites (PR 12) (2026-11-24)

Plan: `docs/cavr-m2-plan.md` PR 12 and the Phase 3b plan approved by Maryam on 2026-11-24 (order PR 12, clean-up,
PR 13; D1–D4 as recommended; demo option A, done in Step M2-18).

### Ch 6 Implementation

- `backend/cavr/activation_loop.py` (new). `explore(frontier, run, budget, clock, gate_left, synthesize,
  canary_spec, started)` plans and makes the runs of one escalated package; `read_run` turns one `run_spec` result
  into a record (events minus the baseline, judged by `contract_check.judge`, `completed` only for DEEP_NOT_JUDGED on
  the checked image with an attributable trace); `new_events` (multiset difference by `sandbox_events.event_key`,
  install step left out) and `drive_events` (a drive step minus the same run's imports step).
  Algorithm: (1) run 1 is `canary_spec()`; (2) the simulable frontier entries are grouped by activation, in frontier
  order, one `synthesize` spec per group (refused specs and unsimulable entries get no run); (3) runs are made until
  8 runs, 120 s for the package (3 s kept for overhead) or the gate run's 300 s end, or a run has a violation, or the
  canary-only run did not complete; (4) an entry is explored when a completed counterfactual run's new events (or, for
  an entry the baseline takes, the canary-only run's events) contain an event of one of its sink capabilities.
- `backend/cavr/call_drive.py` (new). `plan(package)`: for each `call` site of the contract, the project file is read
  again and must have the context's SHA-256; every `ast.Call` at that line written as the expression is a candidate;
  every argument must pass `ast.literal_eval` (no `*`/`**`, ≤ 4096 bytes), no string may look like a credential and no
  keyword be named like one (D2); at most 4 distinct calls, file / line / column order, steps `drive_1`..`drive_4`.
  `DRIVE_CODE`: import the modules, resolve the symbol, call it with the literals, catch `BaseException`, `os._exit(0)`.
- `backend/cavr/sandbox_deep.py` (v2). `analyse`: baseline (now the spec strace and imports step), frontier, drive
  plan, loop, verdict. `_verdict`: the seven clauses (violation -> REJECTED; no run / incomplete run / unjudged event /
  `frontier_residual` / high-risk `other_guards` / escalation reasons -> UNRESOLVED; else VERIFIED DEEP_RUN_CLEAN).
  `escalation_reasons(package, runs, drives)`: module-level sinks by an imports-step event, function sinks by a drive
  step's `drive_events`, both only when the sink is the only reachable sink of its capability (D3).
  `unexplored_guards`. `BUDGET` runs 8; `VERSION` cavr-sandbox-deep/2; identity adds the frontier, synthesis, loop and
  drive versions, `STRACE_SPEC`, `SPEC_IMPORT_ARGV`, `DRIVE_ARGV`; `VERDICT_CODE` adds the five modules.
  `high_risk_triggers` and DEEP_TRIGGERS_UNEXPLORED removed.
- `backend/cavr/sandbox_spec.py`: `spec_steps` / `run_spec(..., drives=())` add the drive steps (default unchanged).
- `backend/cavr/pipeline.py::_deep`: the package dict gains `project` (project_dir and each file's SHA-256 from the
  context already read).
- `backend/cavr/gate_adapter.py`: `DEEP_EVIDENCE` gains decisive_run, runs, triggers, residual, unexplored_guards,
  drives, loop (unexplored_triggers removed); `BOUNDED_DEEP` states the loop.
- `backend/commands/report.py` `[owner review]`: the VERIFIED deep line gives runs and driven call sites; a residual
  names its first trigger.
- Tests: `tests/test_cavr_activation_loop.py` (new), `tests/test_cavr_call_drive.py` (new),
  `tests/test_cavr_m2_wheels.py` (new, Docker; also the demo script), `tests/test_cavr_sandbox_deep.py` (changed);
  recordings `tests/test_cavr_data/traces/loop-drive-quiet` and `loop-drive-send` (`record_events.py`).

### Design decisions

- Canary-only run first, not the highest-risk trigger: it is the reference of every counterfactual difference
  (PR 13's causal edges) and checks the entries the baseline takes. Alternative: no reference run, use the PR 9
  empty-harness baseline — rejected, that baseline has no package code, so every package event would look "caused".
- Explored = the sink's capability in the difference against the canary-only run, not "an event of the capability":
  an event the package makes without the trigger does not show the branch ran. Cost: a sink that fires in both runs is
  never explored (UNRESOLVED), which is the fail-closed side.
- The 8 runs include the canary-only run (Q8 "8 runs per package"); the empty-harness baseline is not one of them.
  Corrected after the review (as first written, this line said the baseline is "once per gate run and counts against
  the 300 s only", which was not true): it is recorded once per identity and stored on disk, and its time counts
  against the gate run's 300 s and against the 120 s of the package that records it (the package clock starts
  before it, as `deep_stage.run_deep`'s does).
- Same steps in every run (install, imports, drives): a trigger inside a function the project calls is seen under its
  spec; the differences compare like with like. Cost: each run is about 1 s longer per drive step.
- Driving only literal-only call sites: the arguments are the project's own, so a violation found is the package's
  behaviour under the project's call; computed arguments would need values CAVR would have to invent. The project's
  own guards around the call are not evaluated (the call is driven regardless), which over-approximates the project.
- D1 strict residual, D2 credential guard, D3 unique attribution, D4 no predicate feedback: see the plan's decisions.
- The drive's own output is never read: only strace's trace is trusted (sandbox rule, PR 5).

### Requirements covered

- FR-4 (counterfactual activation): the loop with budget, order, early stop and residuals in the verdict —
  `test_m2_demo_wheel_through_asent_gate[env_ci/date/hostname/argv/file_flag]` (REJECTED in run 2, clean in run 1).
- FR-6 / Q8 (fail closed): every clause tested; `[win32]` UNRESOLVED TRIGGER_UNSIMULABLE; `[budget]` UNRESOLVED
  DEEP_RUN_BUDGET_EXHAUSTED.
- FR-12 (frontier used by the verdict): `frontier_residual` decides clause 4.
- NFR-4: `loop.activation_rate`, `loop.new_sensitive_events`, `loop.budget_used` in the evidence.
- NFR-5: no credential-like project literal enters a run (`test_a_credential_is_never_passed_into_a_run`, 7 cases).
- NFR-6: `not_exercised` lists every unexplored trigger and every undriven call site with why.

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_cavr_call_drive.py (33) | drive plan | literal call, no-arg call, imported name; 6 non-literal forms; 7 credential forms; 6 ordinary strings; decorator; changed file; 4 unfindable sites; 2 calls on a line + repeat; 6 calls; 4 KiB args; no project | driven with the literals / not driven with the reason / at most 4 / never raises | pass |
| test_cavr_activation_loop.py (18) | loop | fake runs (events in normaliser shape) | canary-only first, frontier order, shared activation, difference rule, baseline entries, install step never explores, 8-run budget, package / gate time cut, early stop (trigger and canary run), incomplete runs, refused / unsimulable entries, image and trace checks, drive difference, determinism, no frontier | pass |
| test_an_env_gated_sink_is_rejected_by_its_counterfactual_run (replaces …_unexplored_trigger_…_until_the_frontier_exists) | Q8 clause 1 | CI wheel, run 1 events-benign, run 2 events-probe | REJECTED in run 2 (spec-…), CI=true in its spec | pass |
| test_a_trigger_run_that_shows_nothing_leaves_the_trigger_unexplored | clause 4 | both runs events-benign | UNRESOLVED TRIGGER_UNEXPLORED, outcome names run 2 | pass |
| test_a_trigger_on_a_variable_the_sandbox_fixes_is_unsimulable_and_gets_no_run | clause 4 | `os.getenv('CAVR_DEMO_TRIGGER')` | UNRESOLVED TRIGGER_UNSIMULABLE, 1 run | pass |
| test_a_driven_call_that_connects_outside_the_contract_is_rejected | drive | `demo.send('x')`, loop-drive-send, deny | REJECTED, key event step drive_1 | pass |
| test_a_driven_call_inside_its_scope_exercises_the_sink_and_is_verified | drive | same, scoped grant | VERIFIED, exercised_by run 1 drive_1 | pass |
| test_a_driven_call_that_never_reaches_the_sink_leaves_it_not_exercised | drive | `demo.run()`, loop-drive-quiet | UNRESOLVED DEEP_SINK_NOT_EXERCISED | pass |
| test_a_call_with_a_computed_argument_is_not_driven_and_says_why | drive | `demo.send(data)` | not driven; reason and not_exercised name `data` | pass |
| test_two_reachable_sinks_of_one_capability_cannot_be_told_apart_by_an_event | D3 | two connect sinks | UNRESOLVED, both reasons cite D3 | pass |
| test_an_escalation_without_a_reachable_sink_is_unresolved (changed) | clause 6 | now with a real wheel; plus an empty tree | DEEP_ESCALATION_UNKNOWN; empty tree FRONTIER_INCOMPLETE | pass |
| test_a_reachable_sink_the_import_never_ran_is_unresolved_not_exercised (changed) | clause 6 | BENIGN, `demo.run()` driven | same rule; reason names the driven call | pass |
| test_an_import_time_sink_inside_a_scoped_contract_is_verified (changed) | VERIFIED | IMPORT_TIME | VERIFIED; reason "exercised"; 1 canary-only run | pass |
| test_identity_changes_… (extended), test_report_text_line_for_each_deep_result (extended) | identity / report | new versions, STRACE_SPEC, DRIVE_ARGV; VERIFIED and residual rows | each a new identity; new line text | pass |
| test_demo_wheel_on_the_real_sandbox[env_trigger] (Docker, changed) | demo | PR 9 TRIGGERED wheel | UNRESOLVED TRIGGER_UNSIMULABLE (was DEEP_TRIGGERS_UNEXPLORED) | pass |
| test_demo_wheel_on_the_real_sandbox[ci_trigger] (Docker, new) | demo | CI=true wheel | REJECTED DEEP_CONTRACT_VIOLATION | pass |
| test_m2_demo_wheel_through_asent_gate[env_ci, date, hostname, argv] (Docker) | trigger wheels | Phase 3a wheels, deny | REJECTED in run 2, BLOCK exit 1 | pass |
| …[file_kube] / [file_flag] (Docker) | file trigger | ~/.kube/config / ~/.cache/deploy.flag with FILE_READ:/tmp/home/.cache | REJECTED in run 1 (SECRET_READ stat) / in run 2 | pass |
| …[canary_exfil] (Docker) | canary | read ~/.aws/credentials, UDP sendto | REJECTED in run 1 | pass |
| …[driven_reject] / [driven_verify] (Docker) | drive | `demo.send('x')` deny / scoped | REJECTED (drive_1) BLOCK / VERIFIED ACCEPT exit 0 | pass |
| …[benign_triggered] (Docker) | in-contract branch | CI=true -> granted connect | VERIFIED ACCEPT exit 0 | pass |
| …[win32] (Docker) | unsimulable | `sys.platform == 'win32'` | UNRESOLVED TRIGGER_UNSIMULABLE REVIEW exit 2, 1 run | pass |
| …[budget] (Docker) | budget | 8 env triggers, scoped | UNRESOLVED DEEP_RUN_BUDGET_EXHAUSTED, 8 runs, DEPLOY_8 never run | pass |
| …[function_sink] (Docker) | today's wheel | sink in `send()`, project calls `demo.run()` | UNRESOLVED DEEP_SINK_NOT_EXERCISED REVIEW exit 2 | pass |

Removed: `test_trigger_gating_only_unrestricted_sinks_is_not_high_risk` (its function `high_risk_triggers` is gone; the
frontier's risk tests cover it). New: 33 + 18 + 13 + 9 in `test_cavr_sandbox_deep.py` (8 unit, 1 Docker).
Docker alone: `test_cavr_m2_wheels.py` 13 passed in 131.6 s; the 10 demo wheels of `test_cavr_sandbox_deep.py` 49.2 s.
Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py tests/test_gate_*.py
tests/test_cli_gate.py tests/test_cli_report.py tests/test_integration.py tests/test_modules.py`: 2260 passed, 12
skipped (live network), 0 failed, 998 s; no container left; `reports/` unchanged.

### Defects found and fixed

- The PR 9 demo wheel's trigger `os.getenv('CAVR_DEMO_TRIGGER')` is unsimulable: `CAVR_*` variables are fixed by the
  sandbox (`trigger_frontier.RESERVED_ENV`, PR 10). Its result changed from UNRESOLVED DEEP_TRIGGERS_UNEXPLORED to
  UNRESOLVED TRIGGER_UNSIMULABLE (status unchanged); the REJECTED env case uses the Phase 3a `CI=true` wheel.
- The first CI wheel had no `try` around its connect, so its import step failed and the violating run was partial
  (correctly REJECTED under D6); the demo wheel now catches OSError like the Phase 3a wheels, so its run completes.
- An unsimulable residual's reason named the first entry twice; fixed.
- A deep package with no wheel now stops at the frontier (FRONTIER_INCOMPLETE) before the escalation rule; the test
  that checked DEEP_ESCALATION_UNKNOWN now uses a real wheel, and the empty tree is its own assertion.
- Review: deferred to the end of Phase 3b (one cavr-reviewer pass over all three commits, Step M2-19).

### Known limitations / deferred

- strace cannot tie an event to a Python line: a driven call that shows an event of the sink's capability counts as
  exercising the sink only if no other reachable sink shares that capability (D3); within that, the event may still
  come from other code the call reached.
- Not driven: call sites with computed arguments, `*`/`**`, decorators, methods on returned objects, async functions
  and generators (returned, never run), work left to threads or atexit (cut by `os._exit`). The project is not mounted,
  so a literal path of the project does not exist in the run.
- The credential guard is a heuristic (D2): a credential that does not look like one is passed.
- No predicate feedback (D4); `sleep`, cloud metadata, `try`/`import` guards are not in the frontier (Step M2-15).
- A variable named `CAVR_*` (or any other variable the sandbox fixes) cannot be set, so a trigger on it is
  unsimulable (UNRESOLVED by design).
- Nondeterministic events (e.g. a file read only some runs make) could appear in a difference; they matter only when
  they have the entry's sink capability.
- The causal graph is PR 13 (Step M2-19); the legacy clean-up is Step M2-18.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `activation_loop.py`, `call_drive.py`, the `sandbox_deep.py` rewrite, the edits to
  `sandbox_spec.py`, `pipeline.py`, `gate_adapter.py`, `report.py`, the tests, the two recordings, these notes and the
  plan edits, from the plan Maryam approved on 2026-11-24 (with D1–D4). **Reviewed by Maryam:** the plan and the
  decisions; the code not yet. **Verified by:** the runs above (real Docker runs for all 13 demo wheels).

### Supervisor Q&A prep

1. **Why does a trigger run only count when the canary-only run lacks the event?** The trigger is a cause only if
   changing it changed the behaviour; an event both runs have would have happened anyway. Example: `[env_ci]`'s
   connect to 198.51.100.24:443 is in run 2 (CI=true) and not in run 1.
2. **Is calling the project's function with its literals safe?** It runs in the same sandbox (no network, read-only,
   UID 10001, canaries only), and a literal that looks like a credential is never passed (D2).
3. **Why can a package with a high-risk trigger never be VERIFIED?** High risk means the sink's capability is not
   granted; a run that shows it is a violation (REJECTED), and one that does not leaves it unexplored (UNRESOLVED).


## Step M2-18 — Legacy clean-up and the retired LOCAL-lab demos (Q12) (2026-11-24)

Plan: the Phase 3b plan (legacy clean-up), demo option A chosen by Maryam on 2026-11-24, with two additions: every
reference to `cross_module` / `cavr_canary` updated or removed plus a test that no non-historical file names them,
and an "M2 demo: real wheels" section in `docs/cavr-demo.md` (written with PR 13, Step M2-19, because its recorded
output shows each verdict's cause).

### Ch 6 Implementation

Deleted, with what used each one before:

| Deleted | Used by (before) | Now |
|---|---|---|
| `backend/cavr/sandbox.py`, `lab_harness.py` | `analyzer._lab`, orchestrator `_repair` | deep stage (`sandbox_deep`, PRs 9-12) |
| `backend/cavr/runtime_monitor.py` | `sandbox.py`; `test_modules` | `sandbox_events.normalise` (PR 7) |
| `backend/cavr/sandbox_runner.py`, `harness.py`, `docker/asent-sandbox/` | `test_cavr_sandbox_runner`, `test_cli_resources` (its `SECCOMP_PROFILE`), `doctor.RESOURCES`, `scripts/ci/check_wheel.py`, `test_cli_packaging` | `sandbox_exec` / `sandbox_observe` / `sandbox_harness`, image `asent-cavr-sandbox:local`; the shared profile is `sandbox_image.SHARED_SECCOMP_PROFILE` |
| `backend/cavr/trigger_discovery.py` | **fast gate** `ast_scan`; `analyzer._lab`; `test_modules`, `test_cavr_targeted` | moved unchanged into `ast_scan.rule_scan` |
| `backend/cavr/policy.py` (`verify_runtime`) | `analyzer._lab`, orchestrator `_repair` | `contract_check.judge` (PR 8) |
| `backend/cavr/repair.py` (`rank_repairs`) and the CAVR half of `Service._repair` | orchestrator | `repair_proposal` (proposals only, Q9) |
| `capability_contract.infer`, `use_through_local_artifacts` and helpers | `analyzer._lab`; `test_cavr_vendored_use` | `infer_capability_contract` (M1) |
| the LOCAL-lab path of `analyzer.py` (`_lab`) | demo runs with a LOCAL lock node | a LOCAL node is UNRESOLVED `LOCAL_NOT_SUPPORTED` |
| scenarios `cavr_canary`, `cross_module`, `scenarios/cavr_controlled/`, `apply_scenario`'s lab branch, `replace_lab` | catalog, dashboard buttons, `conftest.integration_runs` | `tests/test_cavr_m2_wheels.py` (real wheels) |

Changed: `backend/cavr/ast_scan.py` (`rule_scan` at its end; imports `trigger_rules.matching`), `analyzer.py`
(docstring, LOCAL rule), `capability_contract.py` (docstring), `backend/orchestrator/service.py` (`_repair` SATRA
only; imports), `backend/orchestrator/scenarios.py`, `backend/commands/doctor.py` (RESOURCES), `scenarios/catalog.json`,
`scenarios/laboratory_hashes.json` (the `cavr_sources` key and exactly the four `python_sources` hashes of the lab
files and their one-line adapters; no remaining file has those bytes), `scripts/build_scenarios.py`,
`scripts/ci/check_wheel.py`, `scripts/generate_defense_replays.py` (frame 06 text), `reports/ASENT_FINAL1_DEMO_RUNBOOK.md`
(a dated "retired" note above Scenario 5; the Final-1 text kept). New: `tests/test_cavr_retired_scenarios.py`.

### Design decisions

- Option A (retire) over porting the lab to wheels: the repair half of `cross_module` (swap the lab for a different
  package) is level-3/4 replacement (future work, Q3) and was applied to the candidate (Q9 forbids); porting the
  detection half needs a LOCAL-wheel trust path in `verify_request` and Docker in demo runs. The detection story is now
  shown by real wheels through `asent gate`.
- `trigger_discovery.scan` moved byte-for-byte instead of being rewritten: the fast gate's sink list must not change in
  a clean-up. Proof: the canonical JSON of `scan_wheel` for the real pypdf 6.21.4 / 6.19.0 / 5.1.0 wheels and the 13
  demo wheels (path field left out) has the same SHA-256 before and after (`eabb11dc10ac56a4…`; 16 wheels, 16
  triggers, 24 sinks). `analyzer_version` holds version strings only, so no cache key changes.
- `laboratory_hashes.json` edited by hand, not regenerated: it is also SATRA's host-fallback allowlist; regenerating
  could change SATRA's other entries.
- A LOCAL lock node fails closed (UNRESOLVED) like any ecosystem the pipeline cannot verify.
- Historical files keep their text (the guard test lists them with the reason): report notes, the plan's decision
  log, `docs/satra/harness-isolation.md` (another owner's dated record), `reports/` (committed evidence and reports).

### Requirements covered

- Q12 (legacy removed once replaced and unused): every module in the table has no importer left
  (`git grep` for the module names in `*.py`: only comments recording the move).
- FR-6 (fail closed): `test_a_local_lock_node_is_unresolved_local_not_supported`.
- NFR-2 / scope: the `cross_module` / `cavr_canary` names are gone from every file in use
  (`test_no_file_in_use_names_a_retired_scenario`).

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_no_file_in_use_names_a_retired_scenario (new) | user's addition | every tracked text file outside the historical list | no `cross_module` / `cavr_canary` | pass |
| test_the_scenario_catalog_has_no_retired_entry (new) | catalog | `scenarios/catalog.json` | neither id | pass |
| test_the_historical_list_names_only_paths_that_exist (new) | guard of the guard | the allowlist | every prefix tracked | pass |
| test_a_local_lock_node_is_unresolved_local_not_supported (was test_local_lab_node_keeps_the_lab_path_labelled_demo_lab) | fail closed | safe scenario + a LOCAL `.py` lock entry | UNRESOLVED LOCAL_NOT_SUPPORTED (was REJECTED demo-lab); pypdf VERIFIED | pass |
| test_local_wheel_in_the_lock_is_unresolved_never_verified (changed) | fail closed | LOCAL wheel | still UNRESOLVED; rule LOCAL_NOT_SUPPORTED, engine demo (was LOCAL_ARTIFACT_NOT_SUPPORTED, demo-lab) | pass |
| test_a_vendored_adapter_that_binds_the_reader_verifies_pypdf (was test_repaired_cross_module_state_verifies_pypdf) | guard proof | the reviewed adapter written directly | pypdf VERIFIED ALL_CHECKS_PASSED (the demo-lab assertion dropped) | pass |
| test_seccomp_profiles_are_the_repository_files (was …_and_the_flags_are_unchanged) | assets | shared and CAVR profile paths | same `docker/asent-seccomp.json`; SandboxRunner flags gone with it | pass |
| test_every_packaged_asset_…, test_a_copy_of_the_package_outside_the_checkout_… (re-pointed) | assets | `sandbox_image.SHARED_SECCOMP_PROFILE` | same path asserted | pass |
| test_trigger_and_runtime_normalization (trimmed), test_trigger_predicates_bounded_and_unsupported_visible, test_trigger_scanner_records_supported_if_else_file_and_unknown_helper (re-pointed) | rule scan | `ast_scan.rule_scan` | unchanged results | pass |
| test_scanner_crash_on_one_file_is_unresolved_not_an_exception (re-pointed) | fault | patched `rule_scan` | UNRESOLVED SOURCE_NOT_PARSED | pass |
| test_gate_run_never_calls_a_demo_scenario_function, test_every_allowlist_entry_still_matches_a_line (changed) | gate path | `replace_lab` and 3 allowlist entries gone | pass | pass |

Deleted with the code they tested (86): `test_cavr_lab_pins.py` (3), `test_cavr_runtime_monitor.py` (9),
`test_cavr_sandbox_runner.py` (33), `test_cavr_vendored_use.py` (31), 4 of 6 in `test_cavr_targeted.py`,
`test_hash_verification_line_endings.py::test_cavr_pinned_python_source_accepts_windows_crlf_checkout` (its SATRA test
stays), `test_cavr_sandbox_image.py::test_sandbox_runner_has_no_hardcoded_digest`,
`test_modules.py::test_controlled_dormant_execution`, `::test_causal_graph_requires_fixture_source_and_sink_evidence`,
`::test_repair_constraints`, `test_integration.py::test_cavr_repair_invalidates_satra_then_reverifies`
(`conftest.integration_runs` builds three scenario runs instead of four).
Scan output before / after the move: SHA-256 `eabb11dc10ac56a41df657aaa66a29f6f037d0862f323a7d9a0b6bd4053860e1` both.
Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py tests/test_gate_*.py
tests/test_cli_gate.py tests/test_cli_report.py tests/test_integration.py tests/test_modules.py tests/test_cli_resources.py
tests/test_cli_packaging.py tests/test_hash_verification_line_endings.py tests/test_scenario_validation_guard.py`: 2202
passed, 12 skipped (live network), 0 failed, 885 s; no container left; `reports/scenario-validation.json` unchanged.

### Defects found and fixed

- `test_cavr_ast_scan.py::test_scanner_crash_on_one_file_is_unresolved_not_an_exception` patched the old imported name
  `ast_scan.scan`; it now patches `ast_scan.rule_scan` (same behaviour tested).
- `test_gate_no_hardcoded_paths.py`: `test_every_allowlist_entry_still_matches_a_line` failed because the three
  allowlisted demo paths were deleted with the lab code (the entries were removed); the monkeypatch list no longer
  names `replace_lab`.
- Review: one cavr-reviewer pass over the three Phase 3b commits at the end (Step M2-19).

### Known limitations / deferred

- `SHA256SUMS` (POC release manifest by `scripts/package.py`, last regenerated 2026-09-30, already stale for most files,
  checked by no test) still lists the deleted files; regenerating it is a packaging step, not part of this clean-up.
- `backend/threat_repo/seed/sources.json` record SRC-LAB (and copies in `vscode-asent/test/fixtures/reports/`) names
  the deleted lab file as a source reference: threat-repository data outside CAVR's scope; left for its owner.
- `frontend/src/components/cavr/RequirementsTab.tsx` still labels a row with `sandbox_runner.py`: PR 19 rewrites the
  module column (Phase 5).
- The orchestrator assurance report's CAVR fields that read the lab (`discovered_triggers`, `execution_modes`,
  `observed_security_events`, `causal_evidence`) are now always empty, as they already were for gate runs; the deep
  evidence is in each pipeline row (`deep`); PR 18 (certificate) / Phase 5.
- `threat_repo.source_sink_rules.correlate` lost its only CAVR user; not deleted (outside CAVR's scope).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the deletions, the edits listed above, the guard test, these notes and the plan edits,
  from the plan and option A approved by Maryam on 2026-11-24. **Reviewed by Maryam:** the plan and the demo choice; the
  diff not yet. **Verified by:** the scan-output digest before and after, and the runs above.

### Supervisor Q&A prep

1. **Did deleting `trigger_discovery.py` change the fast gate?** No: the function moved unchanged, and the scan output
   of 16 real wheels has the same SHA-256 before and after (`eabb11dc…`).
2. **Why retire a working demo?** It proved its point with a hand-written lab file in a host fallback, and its repair
   step applied a package swap that the design now leaves to a person (Q9). The same behaviour is now shown on real
   wheels in the real sandbox, through the command a developer runs.
3. **What happens to a project that vendors a `.py` package in its lock?** It is UNRESOLVED `LOCAL_NOT_SUPPORTED`:
   CAVR does not claim to have verified something it cannot verify.


## Step M2-19 — Causal capability graph from the real runs (PR 13) (2026-11-24)

Plan: `docs/cavr-m2-plan.md` PR 13 as set in the Phase 3b plan approved by Maryam on 2026-11-24.

### Ch 6 Implementation

- `backend/cavr/causal_graph.py` (rewritten; the legacy `build` / `build_causal_graph` had no user left after Step
  M2-18). `build(name, frontier, drives, loop, contract, verdict)`: nodes trigger, spec, run, call, event, rule,
  verdict; edges synthesized_as, configured, observed, violates / within / unjudged, decides, caused. Algorithm:
  (1) one trigger node per frontier entry, one call node per driven call site; (2) per run a spec and a run node; (3)
  the run's `new_events` (counterfactual difference) get a `caused` edge from each trigger of that run, and each drive
  step's `drive_events` one from its call; (4) every event with a capability (or not passed by the judge) outside the
  install step becomes a node, judged alone against the contract, with an edge to its rule node (capability + grant);
  install events the judge passed are counted; (5) ids are content hashes, nodes and edges sorted, `digest` = SHA-256
  of the canonical JSON. `cause(graph, run, event)`: "caused by <activation>", "caused by calling <call> at
  <file>:<line>", "in the canary-only run (no trigger needed)", or "in run N, and also without its trigger".
  `activation_text`: env `A=1`, `clock …`, `<path> exists`, `hostname …`, `argv […]`.
- `backend/cavr/sandbox_deep.py`: `with_graph` builds the graph after the verdict, puts `causal_graph` and `causal`
  {version, digest, counts, cause, error} in the evidence, and appends the cause to a REJECTED reason; `VERDICT_CODE`
  adds `causal_graph.py`, the identity `graph:cavr-causal-graph/1`.
- `backend/cavr/activation_loop.py`: each run record keeps its spec's canary ids (never values).
- `backend/cavr/gate_adapter.py`: `causal` and `causal_graph` in the row's deep block (so in `asent-report.json`).
- `backend/commands/report.py` `[owner review]`: the deep line appends the cause.
- `docs/cavr-demo.md`: section "M2 demo: real wheels" (the user's addition to option A) with the one command per
  wheel and the recorded `asent report` line of all 13 wheels.
- Tests: `tests/test_cavr_causal_graph.py` (new), `tests/test_cavr_m2_wheels.py` (causes), `tests/test_cavr_sandbox_deep.py`.

### Design decisions

- The cause is the counterfactual difference, not "the trigger of the run the event is in": an event the canary-only
  run also has would have happened without the trigger (`test_an_event_both_runs_have_has_no_cause_edge`).
- A call node, not in the listed node types: a driven call is the only cause of a sink inside a function, and the
  report must be able to name it.
- Each event is judged alone for its edge (the same `contract_check.judge` the verdict uses), so the edge says what
  the judge says for that event; the verdict itself is unchanged by the graph.
- Install-step events the judge passed are counted, not listed: pip's file writes are hundreds of nodes with nothing
  to say; anything the install envelope refused is listed.
- Deterministic by construction from the recorded evidence; two real runs differ where their traces differ (canary
  values, containers, trace hashes), which the digest then shows.

### Requirements covered

- FR-5 (causal capability graph): `test_a_trigger_caused_the_event_only_its_run_has`, the eight REJECTED demo wheels
  with their cause in the graph and the report line.
- FR-10 (evidence): the graph's digest is in the deep evidence, hence in the verdict, the evidence chain and
  `asent-report.json`; `test_the_graph_is_deterministic_and_its_digest_follows_every_event`.
- NFR-6: the report line names why (`caused by CI=true`, `in the canary-only run`).

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_a_trigger_caused_the_event_only_its_run_has | caused edge | CI entry; connect only under CI=true | one `caused` trigger -> event (run 2); violates denied rule; decides REJECTED; cause "caused by CI=true" | pass |
| test_an_event_both_runs_have_has_no_cause_edge | no false cause | the same in-scope connect in both runs | no `caused` edge; two `within` edges | pass |
| test_a_violation_of_the_canary_only_run_needs_no_trigger | canary-only cause | read of ~/.aws/credentials in run 1 | 1 run, cause "in the canary-only run (no trigger needed)" | pass |
| test_a_canary_leak_points_at_a_rule_nothing_can_allow | rule node | CANARY_EXFIL_ATTEMPT | rule CANARY_EXFIL "never allowed …" | pass |
| test_a_driven_call_caused_what_its_step_did_beyond_the_import | call cause | drive step connect; the same read in both steps | `caused` call -> connect only | pass |
| test_the_real_drive_recording_gives_the_drive_as_the_cause | real trace | `loop-drive-send` | connect 198.51.100.24:443 ENETUNREACH caused by the call; install events counted, not listed | pass |
| test_each_activation_family_is_named_in_the_cause (8 forms) | cause text | env, time, file, dir, hostname, argv, two, none | the texts as listed | pass |
| test_the_graph_is_deterministic_and_its_digest_follows_every_event | determinism | events shuffled, outcomes reversed; one port changed; another verdict | identical graph; digest changes | pass |
| test_a_graph_that_cannot_be_built_says_so_and_never_raises | fail closed | malformed runs | empty graph with `error`, digest; "cause not in the graph" | pass |
| test_an_env_gated_sink_is_rejected_by_its_counterfactual_run (extended) | deep evidence | CI wheel | cause "caused by CI=true", reason ends with it, digest = graph digest | pass |
| test_report_text_line_for_each_deep_result (extended), test_identity_changes_… (extended) | report / identity | a row with a cause; graph version | line ends "caused by CI=true"; new identity | pass |
| test_m2_demo_wheel_through_asent_gate[13 wheels] (Docker, extended) | end to end | as in Step M2-17 | each REJECTED wheel's cause as in `docs/cavr-demo.md`; no cause and no `decides` edge otherwise; digest present | pass |

9 new graph tests. Docker: `tests/test_cavr_m2_wheels.py` 13 passed (146 s); the demo command for all 13 wheels:
150 s, output recorded in `docs/cavr-demo.md`. Run before the commit: `CAVR_DOCKER=1 pytest tests/test_cavr_*.py
tests/test_orchestrator_config.py tests/test_gate_*.py tests/test_cli_gate.py tests/test_cli_report.py
tests/test_integration.py tests/test_modules.py`: 2187 passed, 12 skipped (live network), 0 failed, 921 s; no container
left; `reports/` unchanged.

### Defects found and fixed

- A never-allowed event (canary leak) pointed at a rule labelled "denied (default deny)"; it now points at "never
  allowed (no capability can allow it)" (`test_a_canary_leak_points_at_a_rule_nothing_can_allow`).
- The first expectation for the date wheel's cause was the constant `2027-01-01`; the real cause is the clock the
  frontier synthesized, `2027-01-02T12:00:00`; the test now expects the real value.
- Review: one cavr-reviewer pass over the three Phase 3b commits, after this commit ("End of Phase 3b" below).

### Known limitations / deferred

- Not in the graph yet: the dependency tree (`depends_on`), event -> package attribution by each wheel's RECORD, canary
  `derived_from` flow, the cross-package path query of the design's §6.6 example (Phase 5 / future work).
- A frontier entry id hashes the file, the guard lines and their shape, not the predicate text, so two different wheels
  with a guard at the same place have the same spec id (`env_ci` and `date`); ids are unique within one package, which
  is what the graph needs.
- The dashboard view of the graph is Phase 5 (`CausalGraphTab.tsx` still reads the old API field).
- The cause names the first event the verdict lists; other violating events carry their own `caused` edges in the graph.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** `causal_graph.py`, the edits to `sandbox_deep.py`, `activation_loop.py`,
  `gate_adapter.py`, `report.py`, the tests, the `docs/cavr-demo.md` section (its output recorded from real runs),
  these notes and the plan edits. **Reviewed by Maryam:** the plan; the code not yet. **Verified by:** the runs above.

### Supervisor Q&A prep

1. **What makes an edge "caused"?** The event is in the run with the trigger's environment and not in the canary-only
   run (counted, so a second identical event still counts once more). Example: `env_ci`'s connect is caused by CI=true.
2. **Is the graph part of the verdict?** It is evidence: built after the verdict from the same records, hashed, and
   stored with it; the verdict rules (Step M2-17) do not read it.
3. **Why does `canary_exfil` say "no trigger needed"?** Its import reads the fake AWS key in the canary-only run
   already; there is no counterfactual run to compare with, and none was needed.


## Review of Steps M2-17 to M2-19 — fixes (End of Phase 3b) (2026-11-24)

One cavr-reviewer pass over `18497c2..810c01b` (the three Phase 3b commits). Review outcome: 1 pass, fix first
(2 BLOCKER, 2 MAJOR, 12 MINOR), all fixed in this commit except MINOR 8 (threat-repository data, outside CAVR's scope,
recorded below); 0 open MINOR in CAVR's scope. None of the findings let a package reach VERIFIED.

### Ch 6 Implementation

- `call_drive.holds_credential(call)`: the D2 check now runs over the whole call's source (string and bytes
  constants, keyword names, dict keys); `looks_like_credential` also refuses a URL with a password. A refused call
  is recorded with `call: None` and its place only; its text never reaches `not_driven`, `not_exercised`, a reason or
  `asent-report.json` (BLOCKER 1, MAJOR 2).
- `sandbox_deep.analyse`: the package's clock starts before the baseline, so a baseline the package records counts
  against its 120 s, as `deep_stage.run_deep` measures (BLOCKER 2).
- `activation_loop.explore`: an entry is explored only when every sink capability it gates is shown; otherwise its
  outcome names what was and was not shown (MAJOR 1). `read_run` accepts a missing result (MINOR 6).
- `causal_graph`: event nodes carry their `event_key` digest and `cause` matches on it and the trace line (MINOR 4);
  `cause` returns None for an event it cannot find and only a real cause is appended (MINOR 3); events within the
  contract with no cause are listed up to 500 per graph, the rest counted (MINOR 5). `sandbox_deep._key_event` gives
  each key event the digest of the full event in its run (the judge keeps a trimmed copy).
- Deep identity: `rules_code`, the SHA-256 of `backend/threat_repo/behavior_rules.py` (MINOR 12).
- `call_drive` docstring: what the driver catches (resolution and call, not the module imports) (MINOR 2).
- `scenarios/catalog.json`: the one SABLE title that had a literal "·" in the base is literal again; the file now
  differs from the base only by the two removed entries (MINOR 9).
- Report notes: the Step M2-17 baseline sentence corrected in place (BLOCKER 2); this section (MINOR 7).

### Design decisions

- Redact instead of hashing the refused call: a hash of a short password is guessable; the place and the
  expression's name are enough for a person to find the call.
- All sinks of an entry, not the worst one: a branch is only explored when what it would do was seen; a partly shown
  branch stays UNRESOLVED (fail closed).
- The graph is capped only for events with nothing to say (within the contract, no cause); everything that decides or
  explains the verdict is always listed.

### Requirements covered

- NFR-5: `test_a_refused_credential_is_recorded_nowhere` (3), `test_a_refused_credential_reaches_no_verdict_field`.
- Q8 / NFR-4 budget: `test_a_fresh_baseline_counts_against_the_package_budget`.
- FR-4 / Q8: `test_an_entry_with_two_sinks_needs_both_shown`.
- FR-5 / FR-10: `test_the_graph_is_deterministic_and_its_digest_follows_every_event` (rewritten),
  `test_events_within_the_contract_without_a_cause_are_capped_and_counted`.

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_a_credential_is_never_passed_into_a_run (9 cases, 2 new) | MAJOR 2 | + `'https://admin:hunter2@db.internal/x'`, `{'password': 'hunter2'}` | not driven, `call` None | pass |
| test_a_refused_credential_is_recorded_nowhere (3) | BLOCKER 1 | token literal; `password=` next to a name; token next to an f-string | the secret not in `json.dumps(plan)` | pass |
| test_a_refused_credential_reaches_no_verdict_field | BLOCKER 1 | project calls `demo.send('ghp_…')` | DEEP_SINK_NOT_EXERCISED; token not in the verdict JSON | pass |
| test_a_fresh_baseline_counts_against_the_package_budget | BLOCKER 2 | 20 s baseline, 16 s runs, 8 triggers | DEEP_RUN_BUDGET_EXHAUSTED, elapsed ≤ 120 s; on the old code DEEP_BUDGET_EXCEEDED (checked) | pass |
| test_an_entry_with_two_sinks_needs_both_shown | MAJOR 1 | read shown, connect not / both | not explored ("not NETWORK_CONNECT") / explored | pass |
| test_a_missing_run_result_is_not_a_completed_run | MINOR 6 | `read_run(None)` | DEEP_NO_RESULT, not completed | pass |
| test_the_graph_is_deterministic_… (rewritten) | MINOR 1 | 3 runs with events, two with one key; runs, outcomes, entries shuffled ×3 | identical graph; port / verdict change -> new digest | pass |
| test_events_within_the_contract_without_a_cause_are_capped_and_counted | MINOR 5 | 10 granted reads + 1 violation, cap 3 | 4 event nodes, 7 counted, the violation listed | pass |
| test_a_graph_that_cannot_be_built_… (changed) | MINOR 3 | malformed runs | `cause` None | pass |

### End-of-phase checks (after the review fixes, in the same commit)

- `CAVR_DOCKER=1 pytest tests/test_cavr_*.py tests/test_orchestrator_config.py tests/test_gate_*.py tests/test_cli_gate.py
  tests/test_cli_report.py tests/test_integration.py tests/test_modules.py`: 2197 passed, 12 skipped (live network),
  0 failed, 822 s; no container left. The 13 demo wheels give the same verdicts, causes and lines as recorded in
  `docs/cavr-demo.md`.
- Docker hidden (`DOCKER_HOST=unix:///nonexistent`), `tests/test_cavr_*.py tests/test_orchestrator_config.py
  tests/test_gate_*.py tests/test_cli_gate.py tests/test_cli_report.py`: 2049 passed, 95 skipped (Docker and live),
  0 failed, 453 s; `sandbox_deep.for_gate_run` -> no analyzer, ENGINE_UNAVAILABLE (today's verdicts).
- Full suite `.venv/bin/python -m pytest -q`: 2916 passed, 95 skipped, 1 xfailed, 0 failed, 776 s (before Phase 3b:
  2923 passed, 81 skipped, 1 xfailed; 86 legacy tests deleted in Step M2-18, new tests in M2-17 / M2-19 / this fix).
- `reports/scenario-validation.json` was not modified by any run (no diff); nothing to restore.

Real projects, `asent gate --head main` with a fresh data directory each (image `sha256:0e88dd461ca4…`):

| Project | Before (`18497c2`) | After (`810c01b`, during the review) | After (the review fixes, quiet machine) |
|---|---|---|---|
| asent-target-flask (main) | ACCEPT exit 0; VERIFIED / ACCEPT / PRESERVED; 184.6 s | ACCEPT exit 0; same; 175.4 s | ACCEPT exit 0; same; 145.5 s |
| asent-target-invoicehub (main) | ACCEPT exit 0; VERIFIED / ACCEPT / PRESERVED; 39.2 s | ACCEPT exit 0; same; 67.6 s (56.8 s re-run) | ACCEPT exit 0; same; 38.5 s |

No verdict changed. Neither project reached the deep stage (Flask: no requirement changed; InvoiceHub: pypdf==6.21.4
VERIFIED by the fast gate). The slower InvoiceHub runs during the review were SATRA (37.6 s -> 65.1 s) and SABLE, which
this phase did not change, on a loaded machine (load average 3.4 while the reviewer ran tests); on a quiet machine it
took 38.5 s.

### Defects found and fixed

- BLOCKER 1, BLOCKER 2, MAJOR 1, MAJOR 2, MINOR 1-7, 9, 10-12: as above.
- While fixing MINOR 4: the judge's violation entries hold a trimmed event (no `access`), so the key could not be
  computed from them (every deep test with a violation became UNRESOLVED INTERNAL_ERROR, fail closed); the key event
  now takes the digest of the full event in its run.
- MINOR 9 was right for one line only: the base file escapes "·" everywhere except one SABLE title.

### Known limitations / deferred

- MINOR 8: `backend/threat_repo/seed/sources.json` (SRC-LAB) still names the deleted lab file (Step M2-18 limitation).
- MINOR 10: an orchestrator run in which only CAVR is REJECTED no longer creates a repair worktree or passes through
  REPAIRING (there is nothing CAVR applies, Q9); SATRA's repair path is unchanged.
- MINOR 11: `other_guards` in front of a medium-risk (scoped) sink do not block VERIFIED (the PR 10 rule names
  high-risk sinks only); a guard CAVR cannot evaluate could hide an out-of-scope use of a scoped capability. Left as
  the approved rule, to be decided with Maryam. Decided the same day: the rule now covers medium risk too (Step M2-20).
- The credential guard stays a heuristic (D2).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the review (cavr-reviewer agent) and the fixes, tests and notes. **Reviewed by
  Maryam:** not yet. **Verified by:** the runs above; the budget test was checked to fail on the old code.

### Supervisor Q&A prep

1. **The guard detects a credential; where does it go?** Nowhere: the call is not driven and its text is not recorded,
   only its file, line and the function's name (`test_a_refused_credential_reaches_no_verdict_field`).
2. **From when is the 120 s measured?** From the start of the package's deep analysis, baseline included, by the
   host's clock (`deep_stage.run_deep`); the loop plans its runs against the same start.
3. **An entry gates a read and a connect; only the read ran?** Not explored: the verdict cannot claim what the connect
   would have done, so it is UNRESOLVED.


## Step M2-20 — Unevaluable guards in front of scoped sinks are unexplored (2026-11-24)

Decision (Maryam, 2026-11-24, after the Phase 3b review's MINOR 11): the PR 10 `other_guards` rule covers every sink
that is not granted with `*`, high or medium risk. A guard CAVR cannot evaluate in front of such a sink is unexplored:
UNRESOLVED `DEEP_GUARD_UNEXPLORED`, unless a completed run showed that sink.

### Ch 6 Implementation

- `backend/cavr/sandbox_deep.py`: `GUARDED_RISKS = ("high", "medium")`; `unexplored_guards(found, runs)` lists every
  `other_guards` entry of those risks for which no completed run showed every sink capability it gates (outside the
  install step; the same all-sinks rule as frontier entries since the review's MAJOR 1), with `risk` and `not_shown`.
  Clause 5 of the verdict and its reason say "not granted with \"*\"".
- `backend/commands/report.py` `[owner review]`: the deep line of a DEEP_GUARD_UNEXPLORED verdict names the guard
  ("unevaluable guard <file>:<line> `<predicate>` gates <capabilities> (<risk> risk), no run showed it").
- `backend/cavr/trigger_frontier.py`: docstring only (the rule PR 12 adds).
- Tests: `test_cavr_sandbox_deep.py` (2 unit tests, the report line), `test_cavr_m2_wheels.py` (Docker wheel
  `guard_out_of_scope`). `docs/cavr-demo.md`: the new row; `docs/cavr-m2-plan.md`: the rule text and progress.

### Design decisions

- Medium risk counts because a scope is a promise about where a capability is used; behind a guard CAVR cannot make
  true, no run tested that promise. Alternative (keep high only): a scoped grant would let an unevaluable branch hide
  an out-of-scope use, as the review showed. Cost: packages with such a guard in front of a scoped sink are UNRESOLVED
  (they were not VERIFIED before either when the sink was an escalation reason; see the test below).
- "Showed that sink" uses every sink capability of the guard (consistent with frontier entries).
- Low risk (granted with `*`) stays out: any use is within the contract, so the branch cannot hide a violation.

### Requirements covered

- FR-6 / Q8 (fail closed): `test_an_unevaluable_guard_in_front_of_a_scoped_sink_is_unexplored`,
  `test_m2_demo_wheel_through_asent_gate[guard_out_of_scope]`.
- NFR-6: the guard, its risk and what was not shown are in `unexplored_guards` and the report line.

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_an_unevaluable_guard_in_front_of_a_scoped_sink_is_unexplored | new rule | `if hash('cavr') % 7 == 99: connect(203.0.113.9:443)`, only 198.51.100.24:443 granted, recording events-benign | UNRESOLVED DEEP_GUARD_UNEXPLORED, guard medium, not_shown NETWORK_CONNECT, 1 run; with the old rule (checked): UNRESOLVED DEEP_SINK_NOT_EXERCISED | pass |
| test_an_unevaluable_guard_whose_sink_a_run_showed_is_not_this_rule | "unless shown" | the same guard + a module-level in-scope connect, recording events-scoped | not DEEP_GUARD_UNEXPLORED (DEEP_SINK_NOT_EXERCISED by D3: two connect sinks) | pass |
| test_report_text_line_for_each_deep_result (extended) | report | a DEEP_GUARD_UNEXPLORED row | "- unevaluable guard g/__init__.py:3 `hash('cavr') % 7 == 99` gates NETWORK_CONNECT (medium risk), no run showed it" | pass |
| test_m2_demo_wheel_through_asent_gate[guard_out_of_scope] (Docker, new) | end to end | the wheel above through `asent gate` | UNRESOLVED DEEP_GUARD_UNEXPLORED, REVIEW exit 2, 1 run | pass |
| test_m2_demo_wheel_through_asent_gate[13 other wheels] (Docker) | no other change | as in Step M2-17 | unchanged | pass |

Demo wheels re-run (`CAVR_DOCKER=1 pytest tests/test_cavr_m2_wheels.py`): 14 passed in 187 s. The demo script for all
14 compared line by line with the output recorded in `docs/cavr-demo.md`: the 13 earlier `CAVR deep` lines and
decisions are byte for byte the same; the only new line is `guard_out_of_scope` (UNRESOLVED DEEP_GUARD_UNEXPLORED,
REVIEW exit 2). No result changed.
Run before the commit (deep and gate tests, as Maryam asked): `CAVR_DOCKER=1 pytest tests/test_cavr_sandbox_deep.py
tests/test_cavr_deep_stage.py tests/test_cavr_m2_wheels.py tests/test_cavr_activation_loop.py tests/test_cavr_causal_graph.py
tests/test_cavr_call_drive.py tests/test_cavr_trigger_frontier.py tests/test_cavr_gate_adapter.py tests/test_gate_*.py
tests/test_cli_gate.py tests/test_cli_report.py`: 397 passed, 1 skipped (live network), 0 failed, 426 s; no container
left. No full-suite run for this step.

### Defects found and fixed

- None in this step.

### Known limitations / deferred

- The Phase 3b review limitation MINOR 11 is closed by this step.
- Which guards are "unevaluable" is the frontier's: a guard that reads none of its families (Step M2-15). A guard that
  reads a family but whose value CAVR cannot compute is a frontier entry (unsimulable -> UNRESOLVED), not an
  other_guard.
- A completed run that shows the guarded sink's capability through other code also clears the guard (strace cannot
  name the Python line; the same limit as D3).

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** the rule change, the report line, the tests, the demo wheel, these notes, the plan and
  demo-doc edits, as Maryam asked on 2026-11-24. **Reviewed by Maryam:** the decision; the code not yet. **Verified
  by:** the runs above; the new unit test was checked to fail with the old rule.

### Supervisor Q&A prep

1. **Why is a guard CAVR cannot evaluate a reason for UNRESOLVED when the sink is granted for a scope?** The scope is
   a claim about where the package connects; behind that guard no run ever executed the connect, so the claim was not
   tested. Example: `guard_out_of_scope` would connect to 203.0.113.9, outside the grant.
2. **Does this make clean packages UNRESOLVED?** Only those with such a guard in front of a scoped or denied sink; the
   13 other demo wheels kept their results byte for byte.

## Step M2-21 — Dashboard: deep view, causal graph, recorded M2 runs, matrix (PR 19, Phase 5a) (2026-11-25)

Plan agreed with Maryam on 2026-11-24 (Q1: versioned FR-10 hash; Q2: Playwright in a scratchpad environment; Q3: four
screenshots; addition: the recorded-run name is only looked up in the fixed list). Branch `cavr-m2-dashboard`,
commits `cbe252b` .. `c165af7`. Screenshots (dashboard on port 8000, headless Chromium):
`docs/report-notes/screenshots/cavr-rejected-env_ci.png`, `cavr-rejected-env_ci-causal-graph.png`,
`cavr-verified-benign_triggered.png`, `cavr-unresolved-budget.png`, `cavr-unresolved-win32.png`.

### Ch 6 Implementation

- `backend/cavr/assurance.py` (FR-10): `compute_record_hash(record)` hashes one canonical JSON list of `hash_version`,
  seq, ts, phase, substep, type, data, prev_hash; new records carry `hash_version: 2`. `verify_chain` checks a record
  without `hash_version` with `compute_record_hash_v1` (the old text hash) and counts it in `legacy_records`; refuses
  an unknown version and a legacy record after a version-2 record. `certificate_for_verdict`: with deep evidence,
  `sandbox_execution` names each deep result (rule, run count, image), a deep VERIFIED claim says what the runs did,
  the residual lists `not_exercised`; the printable HTML shows a RECORDED block for a replay.
- `backend/cavr/sandbox_deep.py`: `_listed_guards` puts the frontier's `other_guards` (at most `MAX_GUARDS_LISTED` =
  50) into the deep evidence. `backend/cavr/causal_graph.py`: public `graph_digest`.
- `tests/test_cavr_m2_wheels.py --record PATH`: runs the 14 demo wheels through `asent gate` in the CAVR sandbox
  (repair on), keeps each run's pipeline verdict (by wrapping `gate_adapter.verify_request`), repair block, decision,
  exit code and deep line; refuses a tree with tracked changes. Output `backend/cavr/recorded/m2-demo-runs.json`
  (header: date, commit, image, Docker version, `index` and `advisories` provenance).
- `backend/cavr/api.py`: `GET /api/cavr/recorded-runs`, `POST /api/cavr/recorded-runs/{name}` (`run_recorded` replays
  through `publish_verdict`, the same events, timeline and certificate as a live run; `recorded` in every event, the
  proof and the certificate; no store). The name is a key of the dictionary loaded once from `RECORDED_PATH`; a
  catch-all `POST /api/cavr/recorded-runs/{rest:path}` answers 404. A `deep_completed` event (step 5) when deep
  evidence exists; the proof has `packages` and `causal_graphs`; its sandbox fields come from the deep runs or say
  `NOT_RUN` ("not available: no deep analysis ran for this request").
- `backend/cavr/dashboard_view.py`: `package_views` (per package: fast-gate stage rules and reasons; the deep block:
  runs with activation, judged result and canary ids, frontier entries and outcomes, driven / not-driven call sites,
  other and unexplored guards, budget, residual, key events, leaks, causal summary) and `causal_graphs`. Leaks are the
  graph's `CANARY_EXFIL_ATTEMPT` events with the key event's `why` (which canary id). A graph is used only when
  `graph_digest(graph)` equals the digest its evidence names.
- `backend/cavr/gate_adapter.py`: `assurance_fields(evidence)`; `backend/orchestrator/service.py` `[owner review]`
  calls it for `discovered_triggers`, `triggered_conditions`, `exercised_conditions`, `unresolved_conditions` (CAVR
  part), `execution_modes`, `observed_security_events`, `causal_evidence`.
- Frontend (`frontend/src/components/cavr/`): `SafeText.tsx` (text only, cut at 160 characters with a closed "show
  more"), `DeepAnalysisTab.tsx` (replaces `CounterfactualTab.tsx`), `CausalGraphTab.tsx` (rewritten: SVG columns
  trigger / call -> spec -> run -> event -> rule -> verdict; cause chains; decisive part by default),
  `RecordedChips.tsx`, `RecordedBanner.tsx`, `RequirementsTab.tsx` (21 rows, Tests column, `CAVR_NAME`);
  `CavrModule.tsx` `[owner review]` (recorded chips, banner, tab "Deep analysis", design name).
- Key algorithm (replay): look the name up in the fixed dictionary -> deep-copy the recorded verdict -> the live
  path's `publish_verdict` with `recorded` set -> each event goes into the run's hash chain -> the page builds its state
  from the stream with the same reducer as a live run.

### Design decisions

- FR-10 versioned (Q1 a) rather than strict: SABLE saves its chains, which would fail as tampered after a strict
  change. A legacy record is reported, not hidden; going back to the old hash inside a chain is refused.
- Recorded runs, not a fake: the file is the output of real gate runs; the replay reuses the live path, so the
  recorded data meets the same code. Alternative (re-run in Docker on demand) fails the "any laptop" demo.
- The name is only a dictionary key (Maryam's addition); a catch-all route keeps multi-segment paths from reaching
  the static mount (405 before the fix).
- View code in `dashboard_view.py`: an existing test forbids `api.py` importing the graph code or hashing; the view
  needs the digest comparison and the activation text. The test was not changed; the indirect import is stated in the
  module docstring. Open for Maryam: update that test's intent (it predates the PR 13 rewrite of `causal_graph.py`).
- The graph is hand-written SVG (no new library). Only "caused by" edges carry a label on the drawing; all edges are
  listed as text, so nothing depends on the picture alone.
- Untrusted text only as React text through `SafeText`; no event value in any attribute.

### Requirements covered

- FR-4, FR-5, FR-12, FR-13, NFR-5: shown from the deep evidence — `test_the_deep_view_of_*`,
  `test_the_graph_of_*`, `test_the_canary_leak_is_named_in_the_view`.
- FR-10: `test_changing_any_one_field_of_a_record_is_detected[ts]`, `[substep]`.
- FR-15 / orchestrator: `test_the_report_of_a_gate_run_carries_the_deep_fields`.
- NFR-6: replayed deep certificate states runs and not-exercised conditions —
  `test_the_certificate_of_a_replayed_deep_verified_run_says_what_the_sandbox_did`.
- Dashboard matrix (checklist row 24): `test_the_matrix_has_every_fr_and_nfr_once_with_real_modules_and_tests`.

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_cavr_assurance.py::test_changing_any_one_field_of_a_record_is_detected (6 cases) | FR-10 | one field of record 2 changed (ts, substep, seq, phase, type, data) | chain broken at that record | pass |
| test_cavr_assurance.py::test_a_legacy_record_after_a_version_2_record_is_refused | no downgrade | v2 chain, tail rewritten with the old hash | refused | pass |
| test_cavr_assurance.py::test_a_legacy_chain_still_verifies_and_is_reported_as_legacy | SABLE compatibility | 3 old-format records | intact, legacy_records 3 | pass |
| test_cavr_recorded_runs.py::test_each_recorded_deep_line_is_the_line_docs_cavr_demo_md_shows (14) | recording = doc | recorded file | each line equals the doc table | pass |
| test_cavr_recorded_runs.py::test_the_recorder_refuses_a_dirty_working_tree | provenance | tracked change | SystemExit, nothing written | pass |
| test_cavr_recorded_runs.py::test_no_host_path_is_in_the_file, test_the_canary_leak_is_recorded_by_its_id_only | privacy, NFR-5 | recorded file | no home path, no canary value | pass |
| test_cavr_api.py::test_a_replay_publishes_the_recorded_verdict_labelled_recorded_and_runs_nothing (5) | replay | env_ci, benign_triggered, win32, budget, canary_exfil | no download, not logged or cached, `recorded` on every event, chain intact | pass |
| test_cavr_api.py::test_a_name_that_is_not_in_the_recorded_list_is_404_over_http (12) | lookup only | ../etc/passwd, %2e%2e, absolute, 5000 characters, ... | 404, no run | pass |
| test_cavr_api.py::test_bad_names_are_404_on_the_whole_app_too | whole app | 11 raw ASGI paths on backend.main | all 404 | pass |
| test_cavr_api.py::test_the_lookup_never_touches_the_filesystem_for_a_name (11) | no path built | open / read_text / exists patched to fail | 404 | pass |
| test_cavr_api.py::test_a_recorded_graph_whose_digest_does_not_match_is_not_shown | consistency | one node label edited | graph left out, digest_checked false | pass |
| test_cavr_api.py::test_the_certificate_of_a_replayed_deep_verified_run_says_what_the_sandbox_did | review BLOCKER 1 | benign_triggered | no "No package code was run"; runs and image; RECORDED block in HTML | pass |
| test_cavr_api.py::test_a_malformed_recording_ends_its_stream_with_no_result | fail closed | verdict without stage / packages | final event, no proof, RECORDING_UNUSABLE | pass |
| test_cavr_frontend.py::test_hostile_event_text_is_printed_as_escaped_text_only | XSS | `<script>`, `<img onerror>`, `javascript:`, 20000 characters in path, argv, predicate, address, reason | no tag, handler or javascript: in markup; only the run's proof link; long value only inside a closed "show more" | pass |
| test_cavr_frontend.py::test_hostile_text_in_the_graph_is_escaped_and_cut | XSS in SVG | hostile node labels, digest recomputed | escaped; SVG labels cut | pass |
| test_cavr_frontend.py::test_no_page_part_sets_inner_html_or_builds_a_link_from_data | sources | every CAVR source | no innerHTML; only 3 fixed hrefs; no src/xlink | pass |
| test_cavr_frontend.py::test_the_graph_of_a_rejected_run_shows_trigger_event_rule_verdict_with_the_caused_by_edge | FR-5 | env_ci | two chains "… caused by (os.environ.get('CI') == 'true') … → violates NETWORK_CONNECT … → REJECTED" | pass |
| test_cavr_frontend.py::test_the_deep_view_of_unresolved_runs_names_what_was_not_explored | FR-4 / Q8 | win32, budget | unsimulable reason; 8 of 8 runs, DEPLOY_8 not explored | pass |
| test_cavr_frontend.py::test_a_recorded_view_says_its_fast_gate_inputs_were_not_pypi_or_osv | review BLOCKER 2 | env_ci | banner, table and FR-11 name the local index and seeded OSV | pass |
| test_cavr_frontend.py::test_the_matrix_has_every_fr_and_nfr_once_with_real_modules_and_tests | row 24 | blocked run | 21 rows; every module and test file exists | pass |
| test_cavr_assurance_fields.py::test_the_report_of_a_gate_run_carries_the_deep_fields | orchestrator | asent gate, fake sandbox | the 7 fields hold the deep data | pass |
| test_cavr_assurance_fields.py::test_a_package_the_fast_gate_did_not_escalate_is_not_available_with_the_reason | never empty | fast VERIFIED row | not_available with the reason in every field | pass |

Existing results that changed (all listed in the plan): `test_the_requirements_tab_prints_what_a_stage_returned_and_no_pass_of_its_own`
(the returned cell moved from piece 5 to 6: new Tests column); the proof's `NOT_RUN` text (assertion unchanged); every
evidence-chain hash (none hard-coded); the deep `analyzer_version` (cache miss only); the orchestrator's 7 fields
(always empty before). Flask / InvoiceHub verdicts and the 7 live chips: unchanged. Test files: `test_cavr_assurance.py`
18 collected (new), `test_cavr_recorded_runs.py` 63 (new), `test_cavr_assurance_fields.py` 12 (new),
`test_cavr_api.py` 126 (48 -> 68 functions), `test_cavr_frontend.py` 52 (21 -> 46 functions), `test_cavr_sandbox_deep.py` 52.
Per commit: `tsc -b`, `vite build`, the API, render and dashboard tests (287 to 326 passed). Re-recording: 14 of 14
deep lines equal the doc.
Full suite after the review fixes and the re-recording (`a7a1bce`, `.venv/bin/python -m pytest -q`): 3082 passed, 97
skipped (Docker / live), 1 xfailed (SATRA known limit), 0 failed, 800 s. The badge fix after it (`c165af7`, one
component and one render test) got the per-commit checks only: 297 passed.

### Defects found and fixed

- Recorded fixture provenance, replayed certificate wording and the recorded commit (review BLOCKERs 1–3): fixed in
  `233a4ea`, re-recorded in `a7a1bce`.
- A multi-segment POST under recorded-runs got 405 from the static mount on the real app (found on the live server):
  catch-all 404 route, `693f2ed`.
- Two identical-looking cause chains for env_ci (the connect at import and again in the drive step): event labels now
  carry run, step and trace line.
- Found on the screenshots: tiny section headings, fixed 380 px graph height, edge labels on top of nodes: `bcc1ce5`;
  a replayed deep VERIFIED badged "Verified by the fast gate" although the fast gate had escalated it: `c165af7`.
- Review (cavr-reviewer): 1 pass, fix first: 3 BLOCKER / 4 MAJOR / 10 MINOR; all BLOCKERs and MAJORs addressed
  (MAJOR 2 by docstrings, then the test updated on Maryam's decision), all 10 MINORs fixed (the proof drawer label
  after the step).

### Known limitations / deferred

- Live chips run the fast gate only (the sample project has no escalated package); the deep view is shown with the
  recorded runs. Live deep runs from the dashboard: not in this PR.
- The digest check proves consistency, not that the recording file was not edited; `counts` is not covered by it.
- The certificate's terminal hash is still taken before the final record; certificate fields of PR 18 (baseline
  digest, SARIF) not done.
- Resolved after the step (Maryam, 2026-11-25): the proof drawer says "Sandbox runs (N, including K canary-only run)"
  (K counted from the runs; "Sandbox runs (0)" without any), and
  `test_api_imports_none_of_the_fixture_or_simulation_modules` no longer forbids `backend.cavr.causal_graph` (the real
  PR 13 graph) but names every deleted fake or legacy module (sandbox, lab_harness, runtime_monitor, sandbox_runner,
  harness, trigger_discovery, policy, repair added); `dashboard_view.py` unchanged.

### Tool disclosure (Ch 8.7)

- **Generated by Claude Code:** all code, tests, the recorder, the recording runs, the screenshots and these notes.
  **Reviewed by Maryam:** the plan and its three decisions; the code not yet. **Verified by:** the per-commit checks,
  the cavr-reviewer pass, the full suite, the 14 recorded lines compared with `docs/cavr-demo.md`, and the screenshots
  taken from the running dashboard (`docs/report-notes/screenshots/`).

### Supervisor Q&A prep

1. **Which parts of a replayed result were really observed?** The sandbox part: containers, traces, events, frontier,
   loop, graph and gate decision. The fast-gate inputs came from a local test index and a seeded OSV cache; the
   banner, the fast-gate table, FR-11 and the certificate say so.
2. **Could a replay be mistaken for a live run?** Every event, the proof, the certificate JSON and the printable
   certificate carry `recorded`; the page shows a RECORDED RUN banner and a "RECORDED REPLAY" pill.
3. **Can event text attack the dashboard?** It is only printed as React text, cut with a "show more"; no event value
   goes into an attribute or link. `test_hostile_event_text_is_printed_as_escaped_text_only` uses `<script>`,
   `javascript:` and 20000-character values.
