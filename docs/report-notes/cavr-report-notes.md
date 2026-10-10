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

Plan commit 12, `feat(cavr): pip wrapper runs the pipeline before pip`.
Review: see the "Steps 12-14 — batch review" section.

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
| Tests | `tests/test_cavr_pip_shim.py` (new, 394 lines, 33 functions, 73 cases); additions in `test_cavr_capture.py` (+11 functions, 20 cases), `test_cavr_pipeline.py` (+5 functions, 9 cases), `test_cavr_manifest.py` (+1), `test_cavr_live.py` (+1 live test); `World` and its constants moved from `test_cavr_pipeline.py` to `test_cavr_support.py` unchanged | |

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

Plan commit 13, `refactor(cavr): dashboard API uses the pipeline`.
Review: see the "Steps 12-14 — batch review" section.
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
| `frontend/src/components/cavr/` (11 files) | `types.ts`, `OverviewTab`, `RequirementsTab`, `CapabilityContractTab`, `TriggersTab`, `CounterfactualTab`, `CausalGraphTab`, `RepairTab`, `AssuranceTab`, `MetricsTab`, `StageDetailPanel` | Read the new evidence (`proofData.cavr_verdict`, `resolution`, `actionData`, `certificate`) and show `fast_gate_ms`, `cache_hit`, `escalated`, `escalation`. Every built-in sample value was removed: a tab without data says so. |
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
- `/api/cavr/cache`, `/simple/…` and the three `/api/cavr/dialog/*` texts still describe the old trusted-package list and the sandbox. They are not in the verdict path. The seed hashes in `storage.SEED_PACKAGES` were not checked against PyPI.
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
   From `verdict_log`, one row per `verify_request` call, through `pipeline.metrics`. Nothing is kept in memory and there are no default numbers.
