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
