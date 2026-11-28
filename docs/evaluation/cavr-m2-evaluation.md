# CAVR M2 evaluation (reduced PR 21)

<!-- cavr-eval:begin environment -->
| Run | Value |
|---|---|
| Recorded (UTC) | 2026-11-25T13:38:38+00:00 |
| Finished (UTC) | 2026-11-25T13:46:22+00:00 |
| Commit that ran | `34fd45c89ddc6d04b634de1c1e7bde0fb85f6f4e` |
| Working tree | clean (tracked files) |
| Expectations committed in | `5936f33d45a092b94562bd347dedaddb8bf58c49` (before the run) |
| Corpus SHA-256 | `933df7a97b9ef36f2b7d177430bc304400d2cc3058a7ffd1468c39e5daf87943` |
| Sandbox image ID | `sha256:0e88dd461ca40066496c9d3966fc0bf226c47556a044ff16ce6112b22e31350f` |
| Docker server | 29.9.3 |
| Platform | Linux-6.18.58.1-microsoft-standard-WSL2-x86_64-with-glibc2.43 |
| Python | 3.14.4 |
| Items | 27 |
| Subset | none (whole corpus) |
| CAVR containers left after the run | 0 |
| Command | `CAVR_DOCKER=1 .venv/bin/python scripts/eval/cavr_eval.py run` |
<!-- cavr-eval:end environment -->

## Findings

<!-- cavr-eval:begin attack_vs_osv -->
### Attack set: CAVR against an OSV-only check

| Wheel | Label | CAVR (run 1) | OSV-only | What it does |
|---|---|---|---|---|
| `env_ci` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | connects out only when CI=true |
| `date` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | connects out only from 2027-01-01 |
| `hostname` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | connects out only on host build-prod-7 |
| `argv` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | connects out only when --deploy is on the command line |
| `file_kube` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | probes ~/.kube/config (a credential path) before connecting |
| `file_flag` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | connects out only when a flag file exists |
| `canary_exfil` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | reads ~/.aws/credentials at import and sends the secret out |
| `driven_reject` | attack | REJECTED DEEP_CONTRACT_VIOLATION | PASS | connects out from a function the project calls |
| `win32` | attack | UNRESOLVED TRIGGER_UNSIMULABLE | PASS | connects out only on Windows, which a Linux sandbox cannot simulate |
| `function_sink` | attack | UNRESOLVED DEEP_SINK_NOT_EXERCISED | PASS | an ungranted connect in a function the project's call never reaches |
| `guard_out_of_scope` | attack | UNRESOLVED DEEP_GUARD_UNEXPLORED | PASS | an ungranted connect behind a guard CAVR cannot evaluate |
| `driven_verify` | benign control | VERIFIED DEEP_RUN_CLEAN | PASS | the driven_reject code under a policy that grants exactly that connect |
| `benign_triggered` | benign control | VERIFIED DEEP_RUN_CLEAN | PASS | the env_ci code under a policy that grants exactly that connect |
| `budget` | benign control | UNRESOLVED DEEP_RUN_BUDGET_EXHAUSTED | PASS | eight granted connects behind eight triggers: more than the 8-run budget |

| Attack set | CAVR | OSV-only |
|---|---|---|
| attacks blocked (REJECTED) | 8 / 11 | 0 / 11 |
| attacks held for review (UNRESOLVED) | 3 / 11 | — (no such answer) |
| attacks passed | 0 / 11 | 11 / 11 |
| benign controls passed | 2 / 3 | 3 / 3 |

OSV-only is computed from the OSV answers the run used; for the synthetic wheels that is the seeded empty answer (they are not on PyPI, so no advisory can exist for them).
<!-- cavr-eval:end attack_vs_osv -->

**How to read this.** Expectations were committed in `5936f33` before the run (`scripts/eval/cavr_eval_corpus.json`)
and were not changed afterwards. The results come from commit `34fd45c`, one live run on 2026-11-25. Every table in
this file is generated from `cavr-m2-eval-raw.json` and `recordings/` by `scripts/eval/cavr_eval.py report`, and the
same command regenerates them byte for byte (`tests/test_cavr_eval.py`). The text in this section is written by hand
and quotes those tables.

1. **Attack set (table above).** CAVR blocked 8 of the 11 attack wheels and held the other 3 for review. It passed
   none. An OSV-only check passed all 11: the wheels have no advisory, which is the case a dormant or
   behaviour-gated attack is built for. Two of the three benign controls were VERIFIED. The third (`budget`) needed
   more sandbox runs than the 8-run budget allows and is UNRESOLVED. **This detection is by construction:** we wrote
   these wheels and tested them before this evaluation (`tests/test_cavr_m2_wheels.py`). The table shows that the
   mechanisms (trigger frontier, counterfactual runs, canaries, call driving, causal graph) work end to end on the
   real sandbox. It is not a real-world detection rate.
2. **Vulnerable set.** All 5 known-vulnerable releases were REJECTED `KNOWN_VULNERABILITY` by live OSV answers, the
   same as the OSV-only check. That includes PyYAML 5.3.1, which has no wheel for this interpreter: the tree is
   UNRESOLVED, but the advisory check still runs and decides.
3. **Clean set: the cost of failing closed.** 2 of 8 clean releases were VERIFIED (`idna`, `packaging`), none was
   falsely REJECTED, and 6 were UNRESOLVED (75 %, table "UNRESOLVED by reason"):
   - 2 compiled code: `pydantic-core`, and `requests` through its child `charset-normalizer`;
   - 1 `.pth` file: `setuptools`;
   - 3 after the deep stage: `click` `TRIGGER_UNSIMULABLE`, `attrs` `DEEP_GUARD_UNEXPLORED`, `six`
     `DEEP_SINK_NOT_EXERCISED`.

   An OSV-only check passes all 8. CAVR never passes what it could not check, and on popular real packages that
   means a person reviews most of them.
4. **Mismatches (2 of 27, recorded, not re-labelled).**
   - `six-1.17.0`: expected VERIFIED, got UNRESOLVED `DEEP_SINK_NOT_EXERCISED`. **My expectation was wrong.** The scan
     found a real `exec` call (`six.py:740`, inside `exec_`), reachable from `six.ensure_str`. Dynamic execution is not
     granted, so six escalated. One deep run was clean, but strace cannot show an `exec` of Python source, so the
     sink stays unexercised.
   - `urllib3-2.2.1`: expected repair PROPOSED, got `NO_REPAIR_FOUND` / `NO_SAFE_CANDIDATE`. **This is a CAVR defect**
     (D-1 below).

   For the two unpredicted rules: `click` matched the best guess (`TRIGGER_UNSIMULABLE`). `attrs` did not: the guess
   was `DEEP_SINK_NOT_EXERCISED`, the result `DEEP_GUARD_UNEXPLORED`.
5. **Repair.** `pypdf` 5.1.0 got a proposed pin to 6.21.4, re-verified VERIFIED by the fast gate, and not applied.
   `jinja2` and `requests` 2.31.0 matched their expected `NO_REPAIR_FOUND`, **but not for the reason written in the
   corpus**. No candidate was re-verified: D-1 excluded every newer release that no advisory affects (jinja2 3.1.6;
   requests 2.33.0–2.34.2). For `PyYAML` the 5-candidate budget ran out on releases with no cp314 wheel.
6. **Time** (table "Time per stage: real packages and synthetic wheels"). Medians per gate run:
   - Real packages: 7.6 s (p95 15.5 s), dominated by network work: downloading and hashing the tree (median
     1.5 s, p95 8.2 s) and live OSV (median 0.8 s, p95 4.1 s).
   - Synthetic wheels: 7.6 s (p95 40.9 s), dominated by the deep stage (median 6.2 s; `budget` used all 8 runs,
     39.5 s).
   - Repair, where it was attempted (5 real REJECTED items): median 2.6 s, p95 7.5 s.
   - The deep stage ran for 17 of 27 items (77 % of those that reached the AST scan), using 30 sandbox runs of the
     136 allowed (median 1 run per package).
   - No CAVR container was left after the run.
7. **Cache (run 2).** 12 of 27 items hit the cache. For the 10 deep-analysed wheels with a stored VERIFIED or
   REJECTED verdict, run 2 was 5.0–9.6× faster: the sandbox is skipped. For `idna` and `packaging` it was only 1.1×
   and 1.2× faster: the wheels are downloaded and OSV is asked again on every run (by design: advisories are never
   cached). UNRESOLVED and advisory-REJECTED results are never stored, so the other 15 items cannot hit.
8. **First attempt discarded.** A first live run at `5936f33` (13:04 UTC, same corpus) was discarded because of two
   defects in the evaluation script, not in CAVR:
   - it compared the expected rule with the request-level rule, which is always `ALL_CHECKS_PASSED` when everything is
     VERIFIED, instead of the package's rule. That gave false mismatches for `driven_verify` and `benign_triggered`.
   - it saved the real items' OSV answers from a directory the gate does not use, so none was saved, and the
     OSV-only column said NO_ANSWER for every real item.

   Both were fixed in `34fd45c`, with tests, and the corpus was run again. On 2026-11-25 I compared the two attempts
   item by item (status, the deep rule or else the rule, repair result, exit code) and found no difference. The
   discarded raw file was kept only in a scratch directory that has since been cleared, so that comparison **cannot
   be re-checked**; nothing in this report depends on it.

### Found defect D-1: repair's advisory screen reads a GIT range as "cannot evaluate", for every version

Diagnosed from the recorded package-wide OSV answer for urllib3 (44 advisories, `response_sha256 3c505122…`, retrieved
2026-11-25 13:41 UTC). The tables are in "Repair's advisory screen against the OSV specification" below; reproduce
them with `scripts/eval/cavr_eval.py repair-screen urllib3-2.2.1` (add `--all-releases` for every release). The
"specification" column is an independent reading of the OSV schema (`spec_affected`): ECOSYSTEM ranges evaluated in
version order, plus the `versions` list, with GIT ranges not read for a release version.

- **Releases 2.2.2 to 2.7.0 were excluded correctly.** Each is contained in at least 6 advisories' ECOSYSTEM ranges.
  The last ones to close are GHSA-8988-9cw3-xx77 [1.26.0, 2.8.0), GHSA-vxq7-64xx-v4gw [1.10.3, 2.8.0) and
  GHSA-gh4c-6fx4-qh6g [2.6.2, 2.8.0), with their PYSEC aliases. CAVR's AFFECTED set equals the specification's for
  every excluded release and for all 109 releases in the recorded registry answer.
- **Release 2.8.0 was excluded wrongly** (`ADVISORY_RANGE_UNKNOWN`). No advisory contains it: OSV's own per-version
  answer for urllib3 2.8.0 in the same run (recorded as a child of `requests-2.34.2`) has 0 advisories, and the
  specification reading agrees.
  - It was excluded by 7 PYSEC entries that CAVR reads as UNKNOWN for every release: PYSEC-2020-148, PYSEC-2020-149,
    PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207 and PYSEC-2023-212.
  - Each pairs a GIT range with an ECOSYSTEM range that closes at or before 2.0.7, and an enumerated `versions` list
    (4 to 87 entries) that does not list 2.8.0.

**Cause.** `advisories.match_advisory` → `advisories._entry_affects` passes the whole entry to
`backend/threat_repo/package_records.affected`. That function marks any range whose type is not ECOSYSTEM or SEMVER
as uncertain and returns None ("cannot tell") unless some range contains the version. So for every release *outside*
such an advisory the answer is UNKNOWN. Repair excludes UNKNOWN (`ADVISORY_RANGE_UNKNOWN`). For any package with one
such entry, repair can therefore propose no release, and the reason it prints says every release "is affected by a
known advisory".

The same cause excluded jinja2 3.1.6 (PYSEC-2014-82, PYSEC-2019-220) and requests 2.33.0–2.34.2 (PYSEC-2015-17,
PYSEC-2018-28, PYSEC-2023-74); see their tables below. The defect is fail-closed: it over-excludes and never passes.
The fast gate's per-version check is not affected in practice. OSV only returns advisories it considers to affect the
asked version, and for those the `versions` list or the ECOSYSTEM range returns True before the GIT uncertainty
matters.

**Proposed fix (not applied in this branch).** In `backend/cavr/advisories.py::_entry_affects` (CAVR's own code; no
change to `backend/threat_repo/`), for a PyPI release version:

1. Leave a GIT range out of the evaluation only when the entry also has an ECOSYSTEM range, or when the GIT range has
   a closing event (`fixed` or `limit`) and the entry has a non-empty `versions` list. In the OSV schema GIT ranges
   describe commits, and the release versions they cover are enumerated in `versions`.
2. An open GIT range (no closing event) with no ECOSYSTEM range stays UNKNOWN for a release newer than the highest
   listed version. A release published after OSV last enumerated the versions could be affected.
3. An entry with only GIT ranges and no `versions` stays UNKNOWN (fail closed).
4. Compare `versions` entries with `Version()` equality, not as strings ("2.0" equals "2.0.0").
5. When any exclusion was `ADVISORY_RANGE_UNKNOWN`, the `NO_SAFE_CANDIDATE` reason should say "affected by a known
   advisory or with a range CAVR cannot evaluate".

Tests for the fix:
- the recorded PYSEC-2023-192 entry is NOT_AFFECTED for 2.8.0 and AFFECTED for 2.0.5 and 1.26.16;
- an open GIT range with `versions` is UNKNOWN above the highest listed version;
- a GIT-only entry without `versions` stays UNKNOWN;
- a GIT-only entry whose `versions` lists the release is AFFECTED;
- "2.0" in `versions` matches release 2.0.0;
- urllib3's repair, re-run from the recording, reaches the re-check of 2.8.0.

The expected effect is that urllib3 2.2.1 gets a proposed pin to 2.8.0 if its re-check is VERIFIED. jinja2 and
requests would then reach the re-check and, as the corpus predicted, fail it on their native children. The current
behaviour is recorded by `test_cavr_reads_a_git_plus_ecosystem_entry_as_unknown_for_every_version` in
`tests/test_cavr_eval.py`.

## Limitations

- **Small corpus.** 13 real releases and 14 synthetic wheels on one machine. The rates are counts out of 5, 8, 11 and
  3, not estimates with confidence intervals.
- **Synthetic attacks, detection by construction.** We wrote the attack set and tested it before this run, so its
  detection rate shows that the mechanisms work, not how often CAVR would catch real malware. No known-malicious
  package was downloaded (design §16.2). There is no real-world malicious sample in the corpus.
- **Our own projects and policies.** Each real release was judged in a small project that we wrote: one app file
  with a literal call, a policy and a lockfile. Verdicts depend on those; for example, `requests` was granted
  `NETWORK_CONNECT:*`, and everything else was denied process execution and network.
- **Label scopes are not checked.** A grant such as `FILE_READ:invoice_documents` cannot be mapped to paths, so a file
  event under it is UNRESOLVED (`SCOPE_NOT_CHECKABLE`). No item here depended on one, but real policies often will.
- **Linux, Python 3.14, x86_64 only** (WSL2, Docker 29.9.3). Wheel choice, native-code findings (`cp314` wheels of
  charset-normalizer, markupsafe, pydantic-core) and the sandbox are specific to this platform; `win32` cannot be
  simulated at all.
- **Live data on one day.** OSV and PyPI answers are from 2026-11-25 and are saved under `recordings/`. A later run
  can differ as advisories are published or withdrawn.
- **Timing.** Wall time on one laptop, including the network to PyPI and OSV. Stage times come from wrappers around
  the stage functions, so the wrapper's own overhead is included (microseconds). Repair's own re-verification counts as
  repair time.
- **OSV-only column.** It is computed from CAVR's recorded OSV answers for every node of the tree, not by running
  pip-audit, so it does not include pip-audit's own resolver or its other databases. For the synthetic wheels it is
  the seeded empty answer, so "OSV-only passes 11 of 11 attacks" is also true by construction: no advisory can
  exist for a package that is not on PyPI.
- **Not evaluated.** The baselines other than OSV-only (existence, static only, one normal run) and the ablations of
  design §10 remain future work. So do repair with a sandbox re-check or project tests, clean reconstruction, and the
  certificate (docs/cavr-m2-plan.md, "Future work").

## Tables

<!-- cavr-eval:begin tables -->
### Per item (run 1)

| Item | Set | CAVR verdict | Expected | Matches | Fast gate | Deep | Runs | Frontier / explored | Cause | Repair | OSV-only |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `requests-2.34.2` | clean | UNRESOLVED COMPILED_CODE_NOT_SCANNED | UNRESOLVED COMPILED_CODE_NOT_SCANNED | yes | UNRESOLVED COMPILED_CODE_NOT_SCANNED | — | — | — | — | — | PASS |
| `click-8.5.1` | clean | UNRESOLVED TRIGGER_UNSIMULABLE | UNRESOLVED (rule not predicted) | yes | UNRESOLVED SINK_REACHABLE | UNRESOLVED TRIGGER_UNSIMULABLE | 1 | 2 / 0 | — | — | PASS |
| `attrs-26.1.0` | clean | UNRESOLVED DEEP_GUARD_UNEXPLORED | UNRESOLVED (rule not predicted) | yes | UNRESOLVED SINK_REACHABLE | UNRESOLVED DEEP_GUARD_UNEXPLORED | 1 | 0 / 0 | — | — | PASS |
| `idna-3.20` | clean | VERIFIED ALL_CHECKS_PASSED | VERIFIED ALL_CHECKS_PASSED | yes | VERIFIED ALL_CHECKS_PASSED | — | — | — | — | — | PASS |
| `packaging-26.4` | clean | VERIFIED ALL_CHECKS_PASSED | VERIFIED ALL_CHECKS_PASSED | yes | VERIFIED ALL_CHECKS_PASSED | — | — | — | — | — | PASS |
| `pydantic-core-2.50.5` | clean | UNRESOLVED COMPILED_CODE_NOT_SCANNED | UNRESOLVED COMPILED_CODE_NOT_SCANNED | yes | UNRESOLVED COMPILED_CODE_NOT_SCANNED | — | — | — | — | — | PASS |
| `setuptools-84.2.1` | clean | UNRESOLVED PTH_EXECUTES_CODE | UNRESOLVED PTH_EXECUTES_CODE | yes | UNRESOLVED PTH_EXECUTES_CODE | — | — | — | — | — | PASS |
| `six-1.17.0` | clean | UNRESOLVED DEEP_SINK_NOT_EXERCISED | VERIFIED ALL_CHECKS_PASSED | **no**: status UNRESOLVED != expected VERIFIED; rule DEEP_SINK_NOT_EXERCISED != expected ALL_CHECKS_PASSED; stage deep != expected verdict; deep stage ran: True != expected False; decision REVIEW != expected ACCEPT; exit_code 2 != expected 0 | UNRESOLVED SINK_REACHABLE | UNRESOLVED DEEP_SINK_NOT_EXERCISED | 1 | 0 / 0 | — | — | PASS |
| `pypdf-5.1.0` | vulnerable | REJECTED KNOWN_VULNERABILITY | REJECTED KNOWN_VULNERABILITY | yes | REJECTED KNOWN_VULNERABILITY | — | — | — | — | PROPOSED REPAIR_PROPOSED | VULNERABLE |
| `urllib3-2.2.1` | vulnerable | REJECTED KNOWN_VULNERABILITY | REJECTED KNOWN_VULNERABILITY | **no**: repair NO_REPAIR_FOUND != expected PROPOSED | REJECTED KNOWN_VULNERABILITY | — | — | — | — | NO_REPAIR_FOUND NO_SAFE_CANDIDATE | VULNERABLE |
| `jinja2-3.1.4` | vulnerable | REJECTED KNOWN_VULNERABILITY | REJECTED KNOWN_VULNERABILITY | yes | REJECTED KNOWN_VULNERABILITY | — | — | — | — | NO_REPAIR_FOUND NO_SAFE_CANDIDATE | VULNERABLE |
| `pyyaml-5.3.1` | vulnerable | REJECTED KNOWN_VULNERABILITY | REJECTED KNOWN_VULNERABILITY | yes | REJECTED KNOWN_VULNERABILITY | — | — | — | — | NO_REPAIR_FOUND BUDGET_EXHAUSTED | VULNERABLE |
| `requests-2.31.0` | vulnerable | REJECTED KNOWN_VULNERABILITY | REJECTED KNOWN_VULNERABILITY | yes | REJECTED KNOWN_VULNERABILITY | — | — | — | — | NO_REPAIR_FOUND NO_SAFE_CANDIDATE | VULNERABLE |
| `env_ci` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 2 | 1 / 1 | caused by CI=true | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `date` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 2 | 1 / 1 | caused by clock 2027-01-02T12:00:00 | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `hostname` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 2 | 1 / 1 | caused by hostname build-prod-7 | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `argv` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 2 | 1 / 1 | caused by argv ['-c', '--deploy'] | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `file_kube` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 1 | 1 / 0 | in the canary-only run (no trigger needed) | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `file_flag` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 2 | 1 / 1 | caused by /tmp/home/.cache/deploy.flag exists | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `canary_exfil` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 1 | 0 / 0 | in the canary-only run (no trigger needed) | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `driven_reject` | attack | REJECTED DEEP_CONTRACT_VIOLATION | REJECTED DEEP_CONTRACT_VIOLATION | yes | UNRESOLVED SINK_REACHABLE | REJECTED DEEP_CONTRACT_VIOLATION | 1 | 0 / 0 | caused by calling demo.send('x') at app/uses_demo.py:5 | NOT_ATTEMPTED NOT_REPAIRABLE | PASS |
| `win32` | attack | UNRESOLVED TRIGGER_UNSIMULABLE | UNRESOLVED TRIGGER_UNSIMULABLE | yes | UNRESOLVED SINK_REACHABLE | UNRESOLVED TRIGGER_UNSIMULABLE | 1 | 1 / 0 | — | — | PASS |
| `function_sink` | attack | UNRESOLVED DEEP_SINK_NOT_EXERCISED | UNRESOLVED DEEP_SINK_NOT_EXERCISED | yes | UNRESOLVED SINK_REACHABLE | UNRESOLVED DEEP_SINK_NOT_EXERCISED | 1 | 0 / 0 | — | — | PASS |
| `guard_out_of_scope` | attack | UNRESOLVED DEEP_GUARD_UNEXPLORED | UNRESOLVED DEEP_GUARD_UNEXPLORED | yes | UNRESOLVED SINK_REACHABLE | UNRESOLVED DEEP_GUARD_UNEXPLORED | 1 | 0 / 0 | — | — | PASS |
| `driven_verify` | benign control | VERIFIED DEEP_RUN_CLEAN | VERIFIED DEEP_RUN_CLEAN | yes | UNRESOLVED SINK_REACHABLE | VERIFIED DEEP_RUN_CLEAN | 1 | 0 / 0 | — | — | PASS |
| `benign_triggered` | benign control | VERIFIED DEEP_RUN_CLEAN | VERIFIED DEEP_RUN_CLEAN | yes | UNRESOLVED SINK_REACHABLE | VERIFIED DEEP_RUN_CLEAN | 2 | 1 / 1 | — | — | PASS |
| `budget` | benign control | UNRESOLVED DEEP_RUN_BUDGET_EXHAUSTED | UNRESOLVED DEEP_RUN_BUDGET_EXHAUSTED | yes | UNRESOLVED SINK_REACHABLE | UNRESOLVED DEEP_RUN_BUDGET_EXHAUSTED | 8 | 8 / 7 | — | — | PASS |

"Fast gate" for an item that ran the deep stage is the escalated verdict it had before the deep stage: UNRESOLVED, with the rule of its reachability evidence (`extract` builds it; the pipeline replaces that verdict with the deep one).

### Time per stage per item (run 1, wall time)

| Item | requirement_gate | project_context | tree | contract | cache_lookup | advisories | scan | deep | repair | verify_request | gate_run | gate_run (run 2) |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| `requests-2.34.2` | 0.3 ms | 0.6 ms | 7.43 s | 0.5 ms | 0.9 ms | 3.93 s | 729.5 ms | — | — | 12.10 s | 13.52 s | 12.71 s |
| `click-8.5.1` | 0.2 ms | 0.6 ms | 1.46 s | 0.4 ms | 0.9 ms | 724.6 ms | 406.9 ms | 7.22 s | — | 9.82 s | 11.05 s | 11.17 s |
| `attrs-26.1.0` | 0.2 ms | 0.6 ms | 1.45 s | 0.2 ms | 0.4 ms | 841.4 ms | 252.1 ms | 7.67 s | — | 10.21 s | 12.12 s | 10.74 s |
| `idna-3.20` | 0.2 ms | 0.5 ms | 1.45 s | 0.4 ms | 0.9 ms | 790.9 ms | 214.7 ms | — | — | 2.46 s | 3.75 s | 3.38 s |
| `packaging-26.4` | 0.2 ms | 0.6 ms | 1.42 s | 0.4 ms | 0.9 ms | 677.7 ms | 578.8 ms | — | — | 2.68 s | 4.17 s | 3.58 s |
| `pydantic-core-2.50.5` | 0.3 ms | 0.6 ms | 3.43 s | 0.2 ms | 0.4 ms | 1.49 s | 237.0 ms | — | — | 5.16 s | 6.37 s | 6.95 s |
| `setuptools-84.2.1` | 0.2 ms | 0.5 ms | 1.76 s | 0.2 ms | 0.6 ms | 777.1 ms | 1.85 s | — | — | 4.39 s | 5.73 s | 5.69 s |
| `six-1.17.0` | 0.2 ms | 0.5 ms | 1.13 s | 0.1 ms | 0.4 ms | 812.0 ms | 56.0 ms | 6.10 s | — | 8.10 s | 9.52 s | 8.06 s |
| `pypdf-5.1.0` | 0.4 ms | 6.2 ms | 1.65 s | 0.3 ms | 0.6 ms | 1.94 s | — | — | 7.47 s | 3.60 s | 12.50 s | 11.94 s |
| `urllib3-2.2.1` | 0.2 ms | 0.5 ms | 1.41 s | 0.2 ms | 0.4 ms | 1.32 s | — | — | 2.62 s | 2.73 s | 6.60 s | 5.74 s |
| `jinja2-3.1.4` | 0.4 ms | 0.6 ms | 2.86 s | 0.4 ms | 0.7 ms | 1.54 s | — | — | 1.59 s | 4.40 s | 7.30 s | 7.49 s |
| `pyyaml-5.3.1` | 0.2 ms | 0.5 ms | 643.8 ms | — | — | 780.8 ms | — | — | 4.84 s | 1.43 s | 7.62 s | 8.19 s |
| `requests-2.31.0` | 0.2 ms | 0.5 ms | 8.18 s | 0.2 ms | 0.6 ms | 4.11 s | — | — | 1.82 s | 12.29 s | 15.49 s | 15.62 s |
| `env_ci` | 0.2 ms | 6.2 ms | 2.1 ms | 0.2 ms | 0.5 ms | 0.2 ms | 1.2 ms | 11.10 s | 0.0 ms | 11.11 s | 12.35 s | 1.32 s |
| `date` | 0.2 ms | 5.8 ms | 2.1 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.5 ms | 10.62 s | 0.0 ms | 10.64 s | 11.88 s | 1.37 s |
| `hostname` | 0.2 ms | 5.5 ms | 2.3 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.1 ms | 10.51 s | 0.0 ms | 10.52 s | 11.93 s | 1.25 s |
| `argv` | 0.2 ms | 6.0 ms | 2.4 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.1 ms | 10.57 s | 0.0 ms | 10.58 s | 11.93 s | 1.63 s |
| `file_kube` | 0.2 ms | 5.8 ms | 2.5 ms | 0.2 ms | 0.3 ms | 0.3 ms | 1.3 ms | 6.20 s | 0.0 ms | 6.21 s | 7.61 s | 1.23 s |
| `file_flag` | 0.3 ms | 5.5 ms | 2.3 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.1 ms | 10.53 s | 0.0 ms | 10.55 s | 11.92 s | 1.33 s |
| `canary_exfil` | 0.2 ms | 6.1 ms | 2.2 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.4 ms | 5.83 s | 0.0 ms | 5.84 s | 7.27 s | 1.45 s |
| `driven_reject` | 0.2 ms | 6.6 ms | 2.2 ms | 0.2 ms | 0.4 ms | 0.3 ms | 1.0 ms | 5.88 s | 0.0 ms | 5.90 s | 7.24 s | 1.22 s |
| `win32` | 0.2 ms | 6.3 ms | 2.1 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.1 ms | 5.79 s | — | 5.80 s | 7.11 s | 6.07 s |
| `function_sink` | 0.4 ms | 6.0 ms | 2.3 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.0 ms | 5.93 s | — | 5.94 s | 7.29 s | 6.90 s |
| `guard_out_of_scope` | 0.3 ms | 6.5 ms | 2.4 ms | 0.1 ms | 0.4 ms | 0.2 ms | 1.2 ms | 5.94 s | — | 5.95 s | 7.33 s | 5.95 s |
| `driven_verify` | 0.3 ms | 5.7 ms | 2.2 ms | 0.2 ms | 0.3 ms | 0.2 ms | 1.5 ms | 5.91 s | — | 5.92 s | 7.22 s | 1.29 s |
| `benign_triggered` | 0.2 ms | 5.6 ms | 2.4 ms | 0.2 ms | 0.4 ms | 0.2 ms | 1.8 ms | 10.52 s | — | 10.54 s | 11.87 s | 1.33 s |
| `budget` | 0.3 ms | 5.7 ms | 2.3 ms | 0.2 ms | 0.3 ms | 0.2 ms | 3.0 ms | 39.53 s | — | 39.54 s | 40.91 s | 39.61 s |

### Verdict counts (run 1)

| Set | VERIFIED | REJECTED | UNRESOLVED | BLOCK | Total | Run failed (not in the rates) |
|---|---|---|---|---|---|---|
| Clean | 2 | 0 | 6 | 0 | 8 | 0 |
| Vulnerable | 0 | 5 | 0 | 0 | 5 | 0 |
| Attack | 0 | 8 | 3 | 0 | 11 | 0 |
| Benign control | 2 | 0 | 1 | 0 | 3 | 0 |
| All | 4 | 13 | 10 | 0 | 27 | 0 |

### Detection and the cost of failing closed

| Measure | Value |
|---|---|
| Vulnerable set REJECTED | 5 / 5 |
| Attack set REJECTED | 8 / 11 |
| Attack set UNRESOLVED (held for review) | 3 / 11 |
| Attack set passed (VERIFIED) | 0 / 11 |
| Benign controls VERIFIED | 2 / 3 |
| Clean set VERIFIED | 2 / 8 |
| Clean set false REJECTED | 0 / 8 (0.0 %) |
| Clean set UNRESOLVED | 6 / 8 (75.0 %) |

### UNRESOLVED by reason (run 1)

| Reason | Rules | Clean set | Overall |
|---|---|---|---|
| compiled code | COMPILED_CODE_NOT_SCANNED | 2 | 2 |
| .pth file | PTH_EXECUTES_CODE | 1 | 1 |
| unsimulable trigger | TRIGGER_UNSIMULABLE | 1 | 2 |
| sink not exercised | DEEP_SINK_NOT_EXERCISED | 1 | 2 |
| budget | DEEP_RUN_BUDGET_EXHAUSTED, DEEP_RUN_BUDGET_USED_UP | 0 | 1 |
| other | any other rule | 1 | 2 |

### Time per stage (nearest-rank median and p95, over the items where the stage ran)

| Stage | Run 1 n | Run 1 median | Run 1 p95 | Run 2 n | Run 2 median | Run 2 p95 |
|---|---|---|---|---|---|---|
| requirement_gate | 27 | 0.2 ms | 0.4 ms | 27 | 0.2 ms | 0.5 ms |
| project_context | 27 | 5.5 ms | 6.5 ms | 27 | 5.5 ms | 11.3 ms |
| tree | 27 | 2.5 ms | 7.43 s | 27 | 4.0 ms | 7.04 s |
| contract | 26 | 0.2 ms | 0.4 ms | 26 | 0.2 ms | 0.4 ms |
| cache_lookup | 26 | 0.4 ms | 0.9 ms | 26 | 0.7 ms | 0.9 ms |
| advisories | 27 | 0.3 ms | 3.93 s | 27 | 0.4 ms | 3.68 s |
| scan | 22 | 1.5 ms | 729.5 ms | 10 | 40.0 ms | 1.86 s |
| deep | 17 | 7.22 s | 39.53 s | 7 | 5.34 s | 38.22 s |
| repair | 13 | 0.0 ms | 7.47 s | 13 | 0.0 ms | 7.22 s |
| verify_request | 27 | 5.95 s | 12.29 s | 27 | 2.56 s | 12.42 s |
| gate_run | 27 | 7.62 s | 15.49 s | 27 | 5.74 s | 15.62 s |
| repair (attempted only) | 5 | 2.62 s | 7.47 s | — | — | — |

`repair` counts every REJECTED item, including the deep REJECTED ones repair does not attempt (NOT_ATTEMPTED, microseconds); `repair (attempted only)` leaves those out.

### Time per stage: real packages and synthetic wheels (run 1, median / p95)

| Stage | Real PyPI packages | Synthetic wheels |
|---|---|---|
| gate_run | 7.62 s / 15.49 s (n=13) | 7.61 s / 40.91 s (n=14) |
| verify_request | 4.40 s / 12.29 s (n=13) | 6.21 s / 39.54 s (n=14) |
| tree | 1.46 s / 8.18 s (n=13) | 2.3 ms / 2.5 ms (n=14) |
| advisories | 841.4 ms / 4.11 s (n=13) | 0.2 ms / 0.3 ms (n=14) |
| deep | 7.22 s / 7.67 s (n=3) | 6.20 s / 39.53 s (n=14) |

### Deep stage

| Measure | Value |
|---|---|
| Items that ran the deep stage (run 1) | 17 / 27 (63.0 %) |
| … of the items that reached the AST scan | 17 / 22 (77.3 %) |
| Sandbox runs used / limit (8 per package) | 30 / 136 |
| Runs per package: median / max | 1 / 8 |
| Loop seconds per package: median / max (limit 120) | 7.19 / 39.283 |

### Second run: the verdict cache

| Item | Verdict | Run 1 | Run 2 | Cache hit | Speed-up |
|---|---|---|---|---|---|
| `requests-2.34.2` | UNRESOLVED | 13.52 s | 12.71 s | no | 1.06× |
| `click-8.5.1` | UNRESOLVED | 11.05 s | 11.17 s | no | 0.99× |
| `attrs-26.1.0` | UNRESOLVED | 12.12 s | 10.74 s | no | 1.13× |
| `idna-3.20` | VERIFIED | 3.75 s | 3.38 s | yes | 1.11× |
| `packaging-26.4` | VERIFIED | 4.17 s | 3.58 s | yes | 1.16× |
| `pydantic-core-2.50.5` | UNRESOLVED | 6.37 s | 6.95 s | no | 0.92× |
| `setuptools-84.2.1` | UNRESOLVED | 5.73 s | 5.69 s | no | 1.01× |
| `six-1.17.0` | UNRESOLVED | 9.52 s | 8.06 s | no | 1.18× |
| `pypdf-5.1.0` | REJECTED | 12.50 s | 11.94 s | no | 1.05× |
| `urllib3-2.2.1` | REJECTED | 6.60 s | 5.74 s | no | 1.15× |
| `jinja2-3.1.4` | REJECTED | 7.30 s | 7.49 s | no | 0.97× |
| `pyyaml-5.3.1` | REJECTED | 7.62 s | 8.19 s | no | 0.93× |
| `requests-2.31.0` | REJECTED | 15.49 s | 15.62 s | no | 0.99× |
| `env_ci` | REJECTED | 12.35 s | 1.32 s | yes | 9.33× |
| `date` | REJECTED | 11.88 s | 1.37 s | yes | 8.65× |
| `hostname` | REJECTED | 11.93 s | 1.25 s | yes | 9.57× |
| `argv` | REJECTED | 11.93 s | 1.63 s | yes | 7.32× |
| `file_kube` | REJECTED | 7.61 s | 1.23 s | yes | 6.18× |
| `file_flag` | REJECTED | 11.92 s | 1.33 s | yes | 8.96× |
| `canary_exfil` | REJECTED | 7.27 s | 1.45 s | yes | 5.01× |
| `driven_reject` | REJECTED | 7.24 s | 1.22 s | yes | 5.96× |
| `win32` | UNRESOLVED | 7.11 s | 6.07 s | no | 1.17× |
| `function_sink` | UNRESOLVED | 7.29 s | 6.90 s | no | 1.06× |
| `guard_out_of_scope` | UNRESOLVED | 7.33 s | 5.95 s | no | 1.23× |
| `driven_verify` | VERIFIED | 7.22 s | 1.29 s | yes | 5.58× |
| `benign_triggered` | VERIFIED | 11.87 s | 1.33 s | yes | 8.94× |
| `budget` | UNRESOLVED | 40.91 s | 39.61 s | no | 1.03× |

Cache hits in run 2: 12 / 27. Median speed-up with a hit: 6.18×; without: 1.05×. Only a VERIFIED or REJECTED analysis (stage 8 or deep) is cached; an advisory REJECTED stops before the cache and an UNRESOLVED is never stored, so those items cannot hit.

### CAVR against an OSV-only check, every set

| Set | CAVR REJECTED | CAVR UNRESOLVED | CAVR VERIFIED | OSV-only VULNERABLE | OSV-only PASS | OSV-only no answer |
|---|---|---|---|---|---|---|
| Clean | 0 | 6 | 2 | 0 | 8 | 0 |
| Vulnerable | 5 | 0 | 0 | 5 | 0 | 0 |
| Attack | 8 | 3 | 0 | 0 | 11 | 0 |
| Benign control | 0 | 1 | 2 | 0 | 3 | 0 |

### Repair's advisory screen against the OSV specification

From the recorded package-wide OSV answer and registry answer of run 1 (`cavr_eval.py repair-screen <item>`). "Specification" is `spec_affected`: ECOSYSTEM ranges in version order plus the `versions` list, GIT ranges not read for a release version.

#### `pypdf-5.1.0`: releases repair left out on an advisory

| Release | Repair rule | CAVR AFFECTED | CAVR UNKNOWN | Specification AFFECTED | Exclusion supported |
|---|---|---|---|---|---|
| 5.2.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.3.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.3.1 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.4.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.5.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.6.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.6.1 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.7.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.8.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 5.9.0 | ADVISORY_AFFECTED | 115 | — | 115 | yes |
| 6.0.0 | ADVISORY_AFFECTED | 113 | — | 113 | yes |
| 6.1.0 | ADVISORY_AFFECTED | 113 | — | 113 | yes |
| 6.1.1 | ADVISORY_AFFECTED | 113 | — | 113 | yes |
| 6.1.2 | ADVISORY_AFFECTED | 113 | — | 113 | yes |
| 6.1.3 | ADVISORY_AFFECTED | 109 | — | 109 | yes |
| 6.2.0 | ADVISORY_AFFECTED | 109 | — | 109 | yes |
| 6.3.0 | ADVISORY_AFFECTED | 109 | — | 109 | yes |
| 6.4.0 | ADVISORY_AFFECTED | 107 | — | 107 | yes |
| 6.4.1 | ADVISORY_AFFECTED | 107 | — | 107 | yes |
| 6.4.2 | ADVISORY_AFFECTED | 107 | — | 107 | yes |
| 6.5.0 | ADVISORY_AFFECTED | 107 | — | 107 | yes |
| 6.6.0 | ADVISORY_AFFECTED | 103 | — | 103 | yes |
| 6.6.1 | ADVISORY_AFFECTED | 103 | — | 103 | yes |
| 6.6.2 | ADVISORY_AFFECTED | 101 | — | 101 | yes |
| 6.7.0 | ADVISORY_AFFECTED | 101 | — | 101 | yes |
| 6.7.1 | ADVISORY_AFFECTED | 95 | — | 95 | yes |
| 6.7.2 | ADVISORY_AFFECTED | 93 | — | 93 | yes |
| 6.7.3 | ADVISORY_AFFECTED | 91 | — | 91 | yes |
| 6.7.4 | ADVISORY_AFFECTED | 89 | — | 89 | yes |
| 6.7.5 | ADVISORY_AFFECTED | 87 | — | 87 | yes |
| 6.8.0 | ADVISORY_AFFECTED | 85 | — | 85 | yes |
| 6.9.0 | ADVISORY_AFFECTED | 85 | — | 85 | yes |
| 6.9.1 | ADVISORY_AFFECTED | 83 | — | 83 | yes |
| 6.9.2 | ADVISORY_AFFECTED | 81 | — | 81 | yes |
| 6.10.0 | ADVISORY_AFFECTED | 79 | — | 79 | yes |
| 6.10.1 | ADVISORY_AFFECTED | 77 | — | 77 | yes |
| 6.10.2 | ADVISORY_AFFECTED | 71 | — | 71 | yes |
| 6.11.0 | ADVISORY_AFFECTED | 71 | — | 71 | yes |
| 6.12.0 | ADVISORY_AFFECTED | 67 | — | 67 | yes |
| 6.12.1 | ADVISORY_AFFECTED | 65 | — | 65 | yes |
| 6.12.2 | ADVISORY_AFFECTED | 61 | — | 61 | yes |
| 6.13.0 | ADVISORY_AFFECTED | 57 | — | 57 | yes |
| 6.13.1 | ADVISORY_AFFECTED | 55 | — | 55 | yes |
| 6.13.2 | ADVISORY_AFFECTED | 55 | — | 55 | yes |
| 6.13.3 | ADVISORY_AFFECTED | 54 | — | 54 | yes |
| 6.14.0 | ADVISORY_AFFECTED | 50 | — | 50 | yes |
| 6.14.1 | ADVISORY_AFFECTED | 48 | — | 48 | yes |
| 6.14.2 | ADVISORY_AFFECTED | 46 | — | 46 | yes |
| 6.15.0 | ADVISORY_AFFECTED | 40 | — | 40 | yes |
| 6.16.0 | ADVISORY_AFFECTED | 38 | — | 38 | yes |
| 6.16.1 | ADVISORY_AFFECTED | 34 | — | 34 | yes |
| 6.16.2 | ADVISORY_AFFECTED | 34 | — | 34 | yes |
| 6.17.0 | ADVISORY_AFFECTED | 32 | — | 32 | yes |
| 6.18.0 | ADVISORY_AFFECTED | 30 | — | 30 | yes |
| 6.18.1 | ADVISORY_AFFECTED | 24 | — | 24 | yes |
| 6.19.0 | ADVISORY_AFFECTED | 18 | — | 18 | yes |
| 6.20.0 | ADVISORY_AFFECTED | 16 | — | 16 | yes |
| 6.20.1 | ADVISORY_AFFECTED | 14 | — | 14 | yes |
| 6.21.0 | ADVISORY_AFFECTED | 11 | — | 11 | yes |
| 6.21.1 | ADVISORY_AFFECTED | 10 | — | 10 | yes |
| 6.21.2 | ADVISORY_AFFECTED | 7 | — | 7 | yes |
| 6.21.3 | ADVISORY_AFFECTED | 3 | — | 3 | yes |

CAVR's AFFECTED set equals the specification's for 131 of 131 releases in the recorded registry answer.

| Advisory | CAVR reads it as | Range types | Non-GIT ranges | `versions` listed | Left-out releases it decides |
|---|---|---|---|---|---|
| GHSA-23w6-3w8w-8484 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.16.1 | 114 | 5.2.0 – 6.16.0 (50) |
| GHSA-248m-82v9-q6g6 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.0 | 102 | 5.2.0 – 6.11.0 (38) |
| GHSA-2q4j-m29v-hq73 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.6.2 | 87 | 5.2.0 – 6.6.1 (23) |
| GHSA-2rw7-x74f-jg35 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.2 | 90 | 5.2.0 – 6.7.1 (26) |
| GHSA-39mj-jf6j-2qj3 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.20.0 | 120 | 5.2.0 – 6.19.0 (56) |
| GHSA-3crg-w4f6-42mx | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.0 | 98 | 5.2.0 – 6.9.2 (34) |
| GHSA-42gh-23hr-vphw | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.3 | 125 | 5.2.0 – 6.21.2 (61) |
| GHSA-4f6g-68pf-7vhv | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.6.0 | 85 | 5.2.0 – 6.5.0 (21) |
| GHSA-4pxv-j86v-mhcw | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.2 | 100 | 5.2.0 – 6.10.1 (36) |
| GHSA-4vqv-7265-gm2w | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.3 | 125 | 5.2.0 – 6.21.2 (61) |
| GHSA-4xc4-762w-m6cg | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.6.0 | 85 | 5.2.0 – 6.5.0 (21) |
| GHSA-52x6-gq3r-vpf4 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.0 | 105 | 5.2.0 – 6.12.2 (41) |
| GHSA-55h5-xmcq-c37v | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.0 | 109 | 5.2.0 – 6.13.3 (45) |
| GHSA-5849-834g-hvw5 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.4 | 126 | 5.2.0 – 6.21.3 (62) |
| GHSA-5hgr-hg42-57jg | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.2 | 104 | 5.2.0 – 6.12.1 (40) |
| GHSA-5hx5-vpf9-5wcv | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.1 | 123 | 5.2.0 – 6.21.0 (59) |
| GHSA-5jq2-8x83-x246 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.0 | 117 | 5.2.0 – 6.17.0 (53) |
| GHSA-5qjq-93h5-hrgp | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.0 | 109 | 5.2.0 – 6.13.3 (45) |
| GHSA-5xf7-4p34-54qr | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.1 | 110 | 5.2.0 – 6.14.0 (46) |
| GHSA-62m5-6wh8-28x7 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.3 | 125 | 5.2.0 – 6.21.2 (61) |
| GHSA-6c7f-9265-g8fw | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.2 | 124 | 5.2.0 – 6.21.1 (60) |
| GHSA-6vvc-x485-93v7 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.0 | 122 | 5.2.0 – 6.20.1 (58) |
| GHSA-763m-79hh-57f2 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.16.1 | 114 | 5.2.0 – 6.16.0 (50) |
| GHSA-7gw9-cf7v-778f | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.2 | 100 | 5.2.0 – 6.10.1 (36) |
| GHSA-7hfw-26vp-jp8m | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.0.0 | 74 | 5.2.0 – 5.9.0 (10) |
| GHSA-7mh2-4gg2-979f | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.20.0 | 120 | 5.2.0 – 6.19.0 (56) |
| GHSA-87mj-5ggw-8qc3 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.9.2 | 97 | 5.2.0 – 6.9.1 (33) |
| GHSA-996q-pr4m-cvgq | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.1 | 89 | 5.2.0 – 6.7.0 (25) |
| GHSA-9m86-7pmv-2852 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.5 | 93 | 5.2.0 – 6.7.4 (29) |
| GHSA-9mvc-8737-8j8h | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.1 | 89 | 5.2.0 – 6.7.0 (25) |
| GHSA-9mx8-4j7g-633p | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.20.1 | 121 | 5.2.0 – 6.20.0 (57) |
| GHSA-cgf9-327m-v77c | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.0 | 122 | 5.2.0 – 6.20.1 (58) |
| GHSA-cggf-277g-3q54 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.4 | 126 | 5.2.0 – 6.21.3 (62) |
| GHSA-cj93-chg6-vgv8 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.0 | 102 | 5.2.0 – 6.11.0 (38) |
| GHSA-f2v5-7jq9-h8cg | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.4 | 92 | 5.2.0 – 6.7.3 (28) |
| GHSA-f54x-cmq8-qg57 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.0 | 122 | 5.2.0 – 6.20.1 (58) |
| GHSA-fc8x-2rww-xw9m | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.15.0 | 112 | 5.2.0 – 6.14.2 (48) |
| GHSA-fp3f-mc75-235c | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.15.0 | 112 | 5.2.0 – 6.14.2 (48) |
| GHSA-fp3h-c4fm-7vvf | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.1 | 118 | 5.2.0 – 6.18.0 (54) |
| GHSA-fwg2-594c-jp42 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.15.0 | 112 | 5.2.0 – 6.14.2 (48) |
| GHSA-g867-7843-wf8q | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.2 | 111 | 5.2.0 – 6.14.1 (47) |
| GHSA-g9cg-prrw-2r8q | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.1 | 118 | 5.2.0 – 6.18.0 (54) |
| GHSA-g9xf-7f8q-9mcj | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.1 | 106 | 5.2.0 – 6.13.0 (42) |
| GHSA-gmh7-3g9r-mjh5 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.2 | 124 | 5.2.0 – 6.21.1 (60) |
| GHSA-hqmh-ppp3-xvm7 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.8.0 | 94 | 5.2.0 – 6.7.5 (30) |
| GHSA-j543-4vmf-qm7v | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.2 | 104 | 5.2.0 – 6.12.1 (40) |
| GHSA-jfx9-29x2-rv3j | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.1.3 | 78 | 5.2.0 – 6.1.2 (14) |
| GHSA-jj6c-8h6c-hppx | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.1 | 99 | 5.2.0 – 6.10.0 (35) |
| GHSA-jm82-fx9c-mx94 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.3 | 108 | 5.2.0 – 6.13.2 (44) |
| GHSA-jp53-mhqp-8xcg | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.16.0 | 113 | 5.2.0 – 6.15.0 (49) |
| GHSA-jr96-gvgh-j3r4 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.2 | 124 | 5.2.0 – 6.21.1 (60) |
| GHSA-jw7q-gvrg-4vj3 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.1 | 118 | 5.2.0 – 6.18.0 (54) |
| GHSA-m2v9-299j-rv96 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.0 | 105 | 5.2.0 – 6.12.2 (41) |
| GHSA-m449-cwjh-6pw7 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.4.0 | 81 | 5.2.0 – 6.3.0 (17) |
| GHSA-mfr5-77xh-9j7h | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.4 | 126 | 5.2.0 – 6.21.3 (62) |
| GHSA-php9-fj8v-98fj | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.19.0 | 119 | 5.2.0 – 6.18.1 (55) |
| GHSA-qfv9-64jg-mh7p | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.20.1 | 121 | 5.2.0 – 6.20.0 (57) |
| GHSA-qpxp-75px-xjcp | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.9.1 | 96 | 5.2.0 – 6.9.0 (32) |
| GHSA-qv6h-rv94-w285 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.17.0 | 116 | 5.2.0 – 6.16.2 (52) |
| GHSA-v247-6f48-mgcj | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.19.0 | 119 | 5.2.0 – 6.18.1 (55) |
| GHSA-vr63-x8vc-m265 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.1.3 | 78 | 5.2.0 – 6.1.2 (14) |
| GHSA-w23x-9jrw-r45c | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.19.0 | 119 | 5.2.0 – 6.18.1 (55) |
| GHSA-wgvp-vg3v-2xq3 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.1 | 89 | 5.2.0 – 6.7.0 (25) |
| GHSA-wjqc-6w8f-h24c | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.1 | 103 | 5.2.0 – 6.12.0 (39) |
| GHSA-x284-j5p8-9c5p | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.2 | 100 | 5.2.0 – 6.10.1 (36) |
| GHSA-x3rh-gjgm-fmqc | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.21.3 | 125 | 5.2.0 – 6.21.2 (61) |
| GHSA-x7hp-r3qg-r3cj | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.3 | 91 | 5.2.0 – 6.7.2 (27) |
| PYSEC-2026-1827 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.6.2 | 87 | 5.2.0 – 6.6.1 (23) |
| PYSEC-2026-1828 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.6.0 | 85 | 5.2.0 – 6.5.0 (21) |
| PYSEC-2026-1829 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.6.0 | 85 | 5.2.0 – 6.5.0 (21) |
| PYSEC-2026-1830 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.0.0 | 74 | 5.2.0 – 5.9.0 (10) |
| PYSEC-2026-1831 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.1.3 | 78 | 5.2.0 – 6.1.2 (14) |
| PYSEC-2026-1832 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.4.0 | 81 | 5.2.0 – 6.3.0 (17) |
| PYSEC-2026-1833 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.1.3 | 78 | 5.2.0 – 6.1.2 (14) |
| PYSEC-2026-3004 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.0 | 102 | 5.2.0 – 6.11.0 (38) |
| PYSEC-2026-3005 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.2 | 90 | 5.2.0 – 6.7.1 (26) |
| PYSEC-2026-3006 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.0 | 98 | 5.2.0 – 6.9.2 (34) |
| PYSEC-2026-3007 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.2 | 100 | 5.2.0 – 6.10.1 (36) |
| PYSEC-2026-3009 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.0 | 105 | 5.2.0 – 6.12.2 (41) |
| PYSEC-2026-3010 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.2 | 104 | 5.2.0 – 6.12.1 (40) |
| PYSEC-2026-3011 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.2 | 100 | 5.2.0 – 6.10.1 (36) |
| PYSEC-2026-3012 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.9.2 | 97 | 5.2.0 – 6.9.1 (33) |
| PYSEC-2026-3013 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.1 | 89 | 5.2.0 – 6.7.0 (25) |
| PYSEC-2026-3014 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.5 | 93 | 5.2.0 – 6.7.4 (29) |
| PYSEC-2026-3015 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.1 | 89 | 5.2.0 – 6.7.0 (25) |
| PYSEC-2026-3016 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.0 | 102 | 5.2.0 – 6.11.0 (38) |
| PYSEC-2026-3017 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.4 | 92 | 5.2.0 – 6.7.3 (28) |
| PYSEC-2026-3018 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.1 | 106 | 5.2.0 – 6.13.0 (42) |
| PYSEC-2026-3019 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.8.0 | 94 | 5.2.0 – 6.7.5 (30) |
| PYSEC-2026-3020 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.2 | 104 | 5.2.0 – 6.12.1 (40) |
| PYSEC-2026-3021 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.1 | 99 | 5.2.0 – 6.10.0 (35) |
| PYSEC-2026-3022 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.13.0 | 105 | 5.2.0 – 6.12.2 (41) |
| PYSEC-2026-3023 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.9.1 | 96 | 5.2.0 – 6.9.0 (32) |
| PYSEC-2026-3024 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.1 | 89 | 5.2.0 – 6.7.0 (25) |
| PYSEC-2026-3025 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.12.1 | 103 | 5.2.0 – 6.12.0 (39) |
| PYSEC-2026-3026 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.10.2 | 100 | 5.2.0 – 6.10.1 (36) |
| PYSEC-2026-3027 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.7.3 | 91 | 5.2.0 – 6.7.2 (27) |
| PYSEC-2026-3610 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.0 | 109 | 5.2.0 – 6.13.3 (45) |
| PYSEC-2026-3611 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.0 | 109 | 5.2.0 – 6.13.3 (45) |
| PYSEC-2026-3612 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.1 | 110 | 5.2.0 – 6.14.0 (46) |
| PYSEC-2026-3613 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.14.2 | 111 | 5.2.0 – 6.14.1 (47) |
| PYSEC-2026-3655 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.15.0 | 112 | 5.2.0 – 6.14.2 (48) |
| PYSEC-2026-3656 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.15.0 | 112 | 5.2.0 – 6.14.2 (48) |
| PYSEC-2026-3910 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.16.1 | 114 | 5.2.0 – 6.16.0 (50) |
| PYSEC-2026-3911 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.16.1 | 114 | 5.2.0 – 6.16.0 (50) |
| PYSEC-2026-3912 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.15.0 | 112 | 5.2.0 – 6.14.2 (48) |
| PYSEC-2026-3913 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.16.0 | 113 | 5.2.0 – 6.15.0 (49) |
| PYSEC-2026-4153 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.0 | 117 | 5.2.0 – 6.17.0 (53) |
| PYSEC-2026-4154 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.1 | 118 | 5.2.0 – 6.18.0 (54) |
| PYSEC-2026-4155 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.1 | 118 | 5.2.0 – 6.18.0 (54) |
| PYSEC-2026-4156 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.18.1 | 118 | 5.2.0 – 6.18.0 (54) |
| PYSEC-2026-4157 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.19.0 | 119 | 5.2.0 – 6.18.1 (55) |
| PYSEC-2026-4158 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.17.0 | 116 | 5.2.0 – 6.16.2 (52) |
| PYSEC-2026-4159 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.19.0 | 119 | 5.2.0 – 6.18.1 (55) |
| PYSEC-2026-4160 | AFFECTED | ECOSYSTEM | introduced 0, fixed 6.19.0 | 119 | 5.2.0 – 6.18.1 (55) |

#### `urllib3-2.2.1`: releases repair left out on an advisory

| Release | Repair rule | CAVR AFFECTED | CAVR UNKNOWN | Specification AFFECTED | Exclusion supported |
|---|---|---|---|---|---|
| 2.2.2 | ADVISORY_AFFECTED | 16 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 16 | yes |
| 2.2.3 | ADVISORY_AFFECTED | 16 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 16 | yes |
| 2.3.0 | ADVISORY_AFFECTED | 16 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 16 | yes |
| 2.4.0 | ADVISORY_AFFECTED | 16 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 16 | yes |
| 2.5.0 | ADVISORY_AFFECTED | 12 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 12 | yes |
| 2.6.0 | ADVISORY_AFFECTED | 10 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 10 | yes |
| 2.6.1 | ADVISORY_AFFECTED | 10 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 10 | yes |
| 2.6.2 | ADVISORY_AFFECTED | 12 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 12 | yes |
| 2.6.3 | ADVISORY_AFFECTED | 10 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 10 | yes |
| 2.7.0 | ADVISORY_AFFECTED | 6 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 6 | yes |
| 2.8.0 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2020-148, PYSEC-2020-149, PYSEC-2021-108, PYSEC-2021-59, PYSEC-2023-192, PYSEC-2023-207, PYSEC-2023-212 | 0 | **no** |

CAVR's AFFECTED set equals the specification's for 109 of 109 releases in the recorded registry answer.

| Advisory | CAVR reads it as | Range types | Non-GIT ranges | `versions` listed | Left-out releases it decides |
|---|---|---|---|---|---|
| GHSA-2xpw-w6gg-jr37 | AFFECTED | ECOSYSTEM | introduced 1.0, fixed 2.6.0 | 98 | 2.2.2 – 2.5.0 (5) |
| GHSA-38jv-5279-wg99 | AFFECTED | ECOSYSTEM | introduced 1.22, fixed 2.6.3 | 62 | 2.2.2 – 2.6.2 (8) |
| GHSA-48p4-8xcf-vxj5 | AFFECTED | ECOSYSTEM | introduced 2.2.0, fixed 2.5.0 | 6 | 2.2.2 – 2.4.0 (4) |
| GHSA-8988-9cw3-xx77 | AFFECTED | ECOSYSTEM | introduced 1.26.0, fixed 2.8.0 | 46 | 2.2.2 – 2.7.0 (10) |
| GHSA-gh4c-6fx4-qh6g | AFFECTED | ECOSYSTEM | introduced 2.6.2, fixed 2.8.0 | 3 | 2.6.2 – 2.7.0 (3) |
| GHSA-gm62-xv2j-4w53 | AFFECTED | ECOSYSTEM | introduced 1.24, fixed 2.6.0 | 57 | 2.2.2 – 2.5.0 (5) |
| GHSA-mf9v-mfxr-j63j | AFFECTED | ECOSYSTEM | introduced 2.6.0, fixed 2.7.0 | 4 | 2.6.0 – 2.6.3 (4) |
| GHSA-pq67-6m6q-mj2v | AFFECTED | ECOSYSTEM | introduced 0, fixed 2.5.0 | 102 | 2.2.2 – 2.4.0 (4) |
| GHSA-qccp-gfcp-xxvc | AFFECTED | ECOSYSTEM | introduced 1.23, fixed 2.7.0 | 62 | 2.2.2 – 2.6.3 (9) |
| GHSA-vxq7-64xx-v4gw | AFFECTED | ECOSYSTEM | introduced 1.10.3, fixed 2.8.0 | 82 | 2.2.2 – 2.7.0 (10) |
| PYSEC-2026-141 | AFFECTED | ECOSYSTEM | introduced 1.23, fixed 2.7.0 | 62 | 2.2.2 – 2.6.3 (9) |
| PYSEC-2026-142 | AFFECTED | ECOSYSTEM | introduced 2.6.0, fixed 2.7.0 | 4 | 2.6.0 – 2.6.3 (4) |
| PYSEC-2026-1994 | AFFECTED | ECOSYSTEM | introduced 1.0, fixed 2.6.0 | 98 | 2.2.2 – 2.5.0 (5) |
| PYSEC-2026-1996 | AFFECTED | ECOSYSTEM | introduced 1.22, fixed 2.6.3 | 62 | 2.2.2 – 2.6.2 (8) |
| PYSEC-2026-1997 | AFFECTED | ECOSYSTEM | introduced 2.2.0, fixed 2.5.0 | 6 | 2.2.2 – 2.4.0 (4) |
| PYSEC-2026-1998 | AFFECTED | ECOSYSTEM | introduced 1.24, fixed 2.6.0 | 57 | 2.2.2 – 2.5.0 (5) |
| PYSEC-2026-1999 | AFFECTED | ECOSYSTEM | introduced 0, fixed 2.5.0 | 102 | 2.2.2 – 2.4.0 (4) |
| PYSEC-2026-4175 | AFFECTED | ECOSYSTEM | introduced 1.26.0, fixed 2.8.0 | 46 | 2.2.2 – 2.7.0 (10) |
| PYSEC-2026-4176 | AFFECTED | ECOSYSTEM | introduced 2.6.2, fixed 2.8.0 | 3 | 2.6.2 – 2.7.0 (3) |
| PYSEC-2026-4177 | AFFECTED | ECOSYSTEM | introduced 1.10.3, fixed 2.8.0 | 82 | 2.2.2 – 2.7.0 (10) |
| PYSEC-2020-148 | UNKNOWN | ECOSYSTEM+GIT | introduced 0, fixed 1.25.9 | 59 | 2.2.2 – 2.8.0 (11) |
| PYSEC-2020-149 | UNKNOWN | ECOSYSTEM+GIT | introduced 1.25.2, fixed 1.25.8 | 6 | 2.2.2 – 2.8.0 (11) |
| PYSEC-2021-108 | UNKNOWN | ECOSYSTEM+GIT | introduced 1.25.4, fixed 1.26.5 | 13 | 2.2.2 – 2.8.0 (11) |
| PYSEC-2021-59 | UNKNOWN | ECOSYSTEM+GIT | introduced 1.26.0, fixed 1.26.4 | 4 | 2.2.2 – 2.8.0 (11) |
| PYSEC-2023-192 | UNKNOWN | ECOSYSTEM+GIT | introduced 2.0.0, fixed 2.0.6, introduced 0, fixed 1.26.17 | 85 | 2.2.2 – 2.8.0 (11) |
| PYSEC-2023-207 | UNKNOWN | ECOSYSTEM+GIT | introduced 0, fixed 1.24.2 | 49 | 2.2.2 – 2.8.0 (11) |
| PYSEC-2023-212 | UNKNOWN | ECOSYSTEM+GIT | introduced 2.0.0, fixed 2.0.7, introduced 0, fixed 1.26.18 | 87 | 2.2.2 – 2.8.0 (11) |

#### `jinja2-3.1.4`: releases repair left out on an advisory

| Release | Repair rule | CAVR AFFECTED | CAVR UNKNOWN | Specification AFFECTED | Exclusion supported |
|---|---|---|---|---|---|
| 3.1.5 | ADVISORY_AFFECTED | 2 | PYSEC-2014-82, PYSEC-2019-220 | 2 | yes |
| 3.1.6 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2014-82, PYSEC-2019-220 | 0 | **no** |

CAVR's AFFECTED set equals the specification's for 52 of 52 releases in the recorded registry answer.

| Advisory | CAVR reads it as | Range types | Non-GIT ranges | `versions` listed | Left-out releases it decides |
|---|---|---|---|---|---|
| GHSA-cpwx-vrp4-4pq7 | AFFECTED | ECOSYSTEM | introduced 0, fixed 3.1.6 | 51 | 3.1.5 |
| PYSEC-2026-1471 | AFFECTED | ECOSYSTEM | introduced 0, fixed 3.1.6 | 51 | 3.1.5 |
| PYSEC-2014-82 | UNKNOWN | ECOSYSTEM+GIT | introduced 0, fixed 2.7.3 | 20 | 3.1.5 – 3.1.6 (2) |
| PYSEC-2019-220 | UNKNOWN | ECOSYSTEM+GIT | introduced 0, fixed 2.8.1 | 22 | 3.1.5 – 3.1.6 (2) |

#### `requests-2.31.0`: releases repair left out on an advisory

| Release | Repair rule | CAVR AFFECTED | CAVR UNKNOWN | Specification AFFECTED | Exclusion supported |
|---|---|---|---|---|---|
| 2.32.2 | ADVISORY_AFFECTED | 4 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 4 | yes |
| 2.32.3 | ADVISORY_AFFECTED | 4 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 4 | yes |
| 2.32.4 | ADVISORY_AFFECTED | 2 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 2 | yes |
| 2.32.5 | ADVISORY_AFFECTED | 2 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 2 | yes |
| 2.33.0 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 0 | **no** |
| 2.33.1 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 0 | **no** |
| 2.34.0 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 0 | **no** |
| 2.34.1 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 0 | **no** |
| 2.34.2 | ADVISORY_RANGE_UNKNOWN | 0 | PYSEC-2015-17, PYSEC-2018-28, PYSEC-2023-74 | 0 | **no** |

CAVR's AFFECTED set equals the specification's for 163 of 163 releases in the recorded registry answer.

| Advisory | CAVR reads it as | Range types | Non-GIT ranges | `versions` listed | Left-out releases it decides |
|---|---|---|---|---|---|
| GHSA-9hjg-9r4m-mvj7 | AFFECTED | ECOSYSTEM | introduced 0, fixed 2.32.4 | 155 | 2.32.2 – 2.32.3 (2) |
| GHSA-gc5v-m9x4-r6x2 | AFFECTED | ECOSYSTEM | introduced 0, fixed 2.33.0 | 157 | 2.32.2 – 2.32.5 (4) |
| PYSEC-2026-1872 | AFFECTED | ECOSYSTEM | introduced 0, fixed 2.32.4 | 155 | 2.32.2 – 2.32.3 (2) |
| PYSEC-2026-2275 | AFFECTED | ECOSYSTEM | introduced 0, fixed 2.33.0 | 157 | 2.32.2 – 2.32.5 (4) |
| PYSEC-2015-17 | UNKNOWN | ECOSYSTEM+GIT | introduced 2.1.0, fixed 2.6.0 | 81 | 2.32.2 – 2.34.2 (9) |
| PYSEC-2018-28 | UNKNOWN | ECOSYSTEM+GIT | introduced 0, fixed 2.20.0 | 134 | 2.32.2 – 2.34.2 (9) |
| PYSEC-2023-74 | UNKNOWN | ECOSYSTEM+GIT | introduced 2.3.0, fixed 2.31.0 | 66 | 2.32.2 – 2.34.2 (9) |

Charts: [verdicts by set](verdicts-by-set.svg), [time per stage](time-per-stage.svg). Raw data: [cavr-m2-eval-raw.json](cavr-m2-eval-raw.json), [cavr-m2-eval.csv](cavr-m2-eval.csv), recordings under [recordings/](recordings/).
<!-- cavr-eval:end tables -->
