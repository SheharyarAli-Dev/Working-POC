# SATRA trusted runs: keeping the head out of the test harness — implementation notes

Branch `satra-isolate-head`. Fixes a review finding: in gate mode the pull request's head could fake a
passing trusted run. `python -m pytest` ran in `/work` (the head copy) with the trusted tests copied into it,
so a head `pytest.py`, `pytest/` or `_pytest/` replaced pytest, the head's root `conftest.py` was loaded
(rootdir was `/work`), and head code could write `/work/results.xml`, the file SATRA then read.

## Plan

1. **Trusted tests outside the head.** Base trusted tests + base `pytest.ini` mounted read-only at `/trusted`;
   `python -P -s -m pytest -c /trusted/pytest.ini --rootdir=/trusted --confcutdir=/trusted -p no:cacheprovider`,
   `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`; the head is appended to the end of `sys.path` only. Attack tests first.
2. **Results file.** `--junitxml` on a fresh tmpfs directory outside `/work`; every `results.xml` in the head copy
   deleted before the run; missing or invalid file → unavailable (fail closed).
3. **Tampering tripwire.** Head adds/changes harness files, pytest settings, or non-test code that imports
   pytest/_pytest or writes `sys.modules` → INCONCLUSIVE, "test-harness tampering suspected".
4. **Stated limit.** In-process code under test can still lie; written in this file, `docs/satra/threat-model.md`
   and `docs/asent-gate.md`.

One commit per step, `[owner review: SATRA]`; inventory regenerated in each commit that adds tests.

## Step 1 — Trusted tests run from /trusted, outside the head (2026-11-08)

**Ch 6 Implementation**
- `backend/satra/pytest_runner.py::_trusted_layout(base, trusted_tests_dir, pytest_ini)`: builds `<tmp>/trusted`
  (base ini byte copy, or `[pytest]\n` when none is configured, plus the base tests as `asent_assurance/`) and
  `<tmp>/asent` (only the plugin file), both siblings of the head copy `<tmp>/project`, never inside it.
- `run_pytest`: when a container engine is used and `trusted_tests_dir` is given (`isolated`), the command is
  `python -P -s -m pytest -q -o addopts= -c /trusted/pytest.ini --rootdir=/trusted --confcutdir=/trusted
  -p no:cacheprovider -p asent_satra_trusted_run … /trusted/asent_assurance`, mounts `/work:rw`, `/trusted:ro`,
  `/asent:ro`, env `PYTEST_DISABLE_PLUGIN_AUTOLOAD=1`, `PYTHONPATH=/asent`, `ASENT_SATRA_TRUSTED`, `ASENT_SATRA_HEAD`.
  The head's ini is no longer copied for these runs. All other runs (head tests, the InvoiceHub demo) are unchanged.
- `backend/satra/trusted_run_plugin.py::pytest_load_initial_conftests` (tryfirst): removes any `sys.path` entry
  inside the head, then appends each base-ini `pythonpath` entry mapped into the head (`src` → `/work/src`) and
  then `/work`, at the END of `sys.path`.
- Algorithm: pytest and the stdlib load from the image before any head path exists on `sys.path` (`-P`: no cwd,
  `-s`: no user site); config and conftest discovery is limited to `/trusted` (`-c`, `--rootdir`,
  `--confcutdir`, only `/trusted` paths as arguments); the head is reachable only as importable code, last.
- `tests/test_satra_config.py::container_on_host`: maps every `-v` mount (single-pass regex), uses only the
  `-e` environment and the `-w` directory, records each mount's files before the run; accepts `python -P -s -m pytest`.

**Design decisions**
- `-s` added to the requested `python -P -m pytest`: a user site directory is another `usercustomize`/`.pth`
  source; disabling it costs nothing because the image installs into the system site-packages.
- Head appended, not prepended: with `pythonpath`-style prepending a head `json.py`, `_pytest/` or an installed
  package name would shadow modules that pytest or the trusted tests import later. Appending keeps head files
  importable only under names nothing else provides. Alternative: `python -I` (would also drop `PYTHONPATH`, so
  the plugin would have to be baked into the runner image — rejected to keep the runner image unchanged).
- A plugin instead of computing paths on the host: it uses pytest's own `getini("pythonpath")` resolution, so
  `pythonpath = src` means exactly what pytest means; the only change is where it points (head, appended).
- `-o addopts=` kept: the old trusted command already ignored the base ini's `addopts`; keeping it keeps results the same.
- The trusted tests keep the directory name `asent_assurance`, so JUnit class names (`asent_assurance.test_contract`)
  and the "project already has an asent_assurance directory" refusal are unchanged.

**Requirements covered:** FR-07 (trusted runs isolated from head-controlled harness inputs); FR-02 (trusted tests
come only from the base) — acceptance: a broken head with any planted harness file still fails `test_other_user_denied`.

**Ch 7 Test cases** (`tests/test_satra_harness_isolation.py`)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_trusted_run_mounts_base_tests_read_only_outside_the_head | command + layout | secure head | `-P -s`, `-c/--rootdir/--confcutdir=/trusted`, no cacheprovider, autoload off, `/trusted:ro`, only base files there | pass |
| test_trusted_pytest_ini_is_the_base_file | base ini only | head edits `.asent/satra/pytest.ini` | `/trusted/pytest.ini` = base bytes | pass |
| test_without_a_base_ini_the_trusted_run_uses_an_empty_one | no ini configured | `pytest_ini=None` | `[pytest]\n`, 2 passed | pass |
| test_head_is_on_sys_path_only_after_the_standard_library_and_site_packages | append-only | trusted probe of `sys.path` | head entries last; pytest not from head | pass |
| test_base_ini_pythonpath_entries_point_into_the_head | src layout | base `pythonpath = src` | `/work/src/app` imported | pass |
| test_broken_head_without_any_attack_fails_the_trusted_test | reference | broken head | exit 1, denied test FAIL | pass |
| test_head_harness_files_do_not_change_the_trusted_result | 11 attacks | pytest.py, pytest/, _pytest/, root conftest forcing passes, pyproject.toml addopts, pytest.ini, tox.ini, setup.cfg, sitecustomize.py, usercustomize.py, .pth (root + user site) | exit 1, denied test FAIL ×11 | pass |
| test_control_the_same_files_force_a_pass_on_an_unguarded_run | attacks are real | 8 vectors on plain `python -m pytest` in the head | exit 0, nothing failing ×8 | pass |

Before the change, `test_head_harness_files_do_not_change_the_trusted_result` failed for pytest.py, pytest/,
_pytest/ and the root conftest (exit 0, "2 passed"), and the first four layout tests failed: the bypass was real.
The settings-file and site-hook vectors were already inert in the old command (`-c` and `-o addopts=`; no site dir).
`tests/test_satra_config.py`: 28 passed, assertions unchanged (gate verdicts the same); this file: 25 passed.
Full suite: `.venv/bin/python -m pytest -q` → 1833 passed, 37 skipped (baseline before the change: 1808 passed, 37 skipped).
`reports/scenario-validation.json` is rewritten by every full run (`tests/conftest.py::integration_runs`). Regenerated
from an unmodified `HEAD` worktree on this machine it gives the same verdicts as with the change (safe ACCEPT;
satra_weak, satra_bypass, cross_module REVIEW). The committed copy (another machine, 2026-11-04) differs in those
three, so that difference is environmental; the committed file was restored, not re-committed.

**Defects found and fixed:** the first fixture version replaced container paths with `str.replace`, so `/asent`
matched inside the host path `/tmp/asent-pytest-…`; replaced by a single-pass anchored regex.

**Known limitations / deferred:** the host harness does not enforce `:ro`; the real container run is covered by the
Docker tests in CI only (no Docker here). Results file: Step 2. Code under test in the same process: Step 4.

**Tool disclosure (Ch 8.7):** Claude Code wrote the plugin, runner change, tests and this section; Maryam to review.
Verified by the tests above on the host harness; not run in a real container on this machine.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Why can't a head `pytest.py` win any more?* `-P` keeps `/work` off `sys.path` at start-up, pytest is imported from
  the image, and the head is appended last, after pytest is already loaded.
- *Why can't a head conftest load?* Pytest only collects `/trusted` paths, rootdir and confcutdir are `/trusted`,
  and `/work` is not an ancestor of `/trusted`.

## Step 2 — Results file outside the head, read fail-closed (2026-11-08)

**Ch 6 Implementation** (`backend/satra/pytest_runner.py`)
- `_results_parent()`: `/dev/shm` (tmpfs) when it is a writable directory on a POSIX host, else the system temp dir.
- `run_pytest`: a second `TemporaryDirectory(prefix='asent-results-')` per run, mounted `-v <dir>:/results:rw`
  in every container run (trusted, head tests, demo); `--junitxml=/results/results.xml`. The host built-in path
  writes `<dir>/results.xml`. The directory is never inside the project copy and is removed after the run.
- `_remove_results_files(work)`: deletes every `results.xml` in the project copy before the run (the source tree
  is not touched); listed in the result as `removed_results_files`.
- `read_results(xml, exit_code)` / `_load_results`: opens with `O_NOFOLLOW|O_NONBLOCK`, requires a regular file
  ≤ `RESULTS_LIMIT` (32 MiB), parses the bytes, root must be `testsuites`/`testsuite`; exit 0 needs ≥ 1 testcase and
  no failure/error, exit 1 needs ≥ 1 failure/error. Any problem → `{'available': False, 'exit_code': None,
  'pytest_exit_code': …, 'reason': …}`; gate mode already treats unavailable as INCONCLUSIVE.
- The stored `junit.xml` and `junit_sha256` are the exact bytes that were parsed (no second read).

**Design decisions**
- Host `/dev/shm` instead of `--tmpfs /results`: a container tmpfs disappears with the container, and `docker cp`
  cannot read it, so the host could never read the file. A bind-mounted host tmpfs directory is fresh, outside
  `/work`, and not written to disk. Fallback (no `/dev/shm`, e.g. Windows): a fresh temp directory, recorded in
  `results_location`.
- Exit-code agreement check: before, `is_pass` looked at the exit code and the passed count but not the failed
  count, so a run forced to exit 0 after a failure (`atexit` + `os._exit(0)`) counted as a pass. Now it is refused.
- Missing file is unavailable, not "0 tests": exit 0 with no results file can only mean something stopped pytest.
- Not following links: anything in `/results` was written by the container; a symlink there would be resolved on the host.

**Requirements covered:** FR-07, NFR-03 (fail closed) — the verdict is read only from a file the head cannot pre-plant;
a missing, malformed or contradictory file can never yield ACCEPT.

**Ch 7 Test cases** (`tests/test_satra_harness_isolation.py`)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_results_file_is_written_to_a_fresh_tmpfs_directory_outside_the_head | location | trusted run; head tests run | `/results`, empty before, not in `/work`, on `/dev/shm`, removed after | pass ×2 |
| test_results_files_in_the_head_are_deleted_before_the_run | planted file | forged `results.xml`, `app/results.xml` | both removed from copy; real FAIL | pass |
| test_head_code_writing_results_xml_in_the_head_does_not_change_the_result | old bypass | head atexit writes passing `./results.xml` | exit 1, denied FAIL | pass |
| test_head_code_that_exits_before_pytest_writes_results_is_unavailable | missing file | `os._exit(0)` on import | unavailable, "results file missing" | pass |
| test_forged_exit_code_with_the_real_results_file_is_unavailable | exit-code forgery | atexit `os._exit(0)` after failure | unavailable, "does not match" | pass |
| test_missing_results_file_makes_a_gate_run_inconclusive | gate | head exits before results | INCONCLUSIVE | pass |
| test_invalid_results_files_are_refused | reader | not XML, HTML, fail+0, empty+0, pass+1 | refused ×5 | pass |
| test_results_file_that_is_not_a_regular_file_is_refused | reader | symlink, directory, missing | refused ×3 | pass |
| test_oversized_results_file_is_refused | reader | limit 10 bytes | "too large" | pass |
| test_consistent_results_files_are_read | reader | pass+0, fail+1, empty+5 | accepted ×3 | pass |
| test_host_builtin_run_writes_results_outside_the_workspace | demo host path | no engine, exit 4 | junit path outside copy; unavailable | pass |
| test_known_limit_in_process_code_under_test_can_still_forge_results | stated limit | head writes consistent forged file at the argv path, exits 0 | strict xfail (forgery succeeds today) | xfail |

Before the change, 18 of these failed, including `…writing_results_xml_in_the_head…` (the denied test showed PASS)
and `…makes_a_gate_run_inconclusive` (REJECT, from the stale exit code). With the change: 71 passed, 1 xfailed in
this file and `tests/test_satra_config.py`. Full suite: 1851 passed, 37 skipped, 1 xfailed. Scenario verdicts in the
regenerated `reports/scenario-validation.json` equal those of the unmodified `HEAD` worktree (file restored).

**Defects found and fixed:** none beyond the bypasses above.

**Known limitations / deferred:** code under test can still write `/results/results.xml` itself (it can read the
path from `sys.argv`) — Step 4 states this limit; the strict xfail keeps it visible.

**Tool disclosure (Ch 8.7):** Claude Code wrote the code, tests and this section; Maryam to review. Host harness only.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Why not use Docker's `--tmpfs` for /results?* The host cannot read a container tmpfs after the container exits; a host tmpfs directory gives the same freshness and is readable.
- *Can a head still forge the file?* Not by shipping one (deleted, wrong path) or by writing `/work/results.xml`; code running inside the test process still can — stated limit.

## Step 3 — Tripwire: suspected harness tampering is INCONCLUSIVE (2026-11-08)

**Ch 6 Implementation**
- `backend/satra/harness_guard.py::suspicious(base_dir, head_dir)` → `[{path, why}]`. Compares `hashing.manifest`
  of base and head (so `.asent/` and generated folders are excluded, as in every gate snapshot) and checks each
  head file that is **added or changed**:
  - `conftest.py` anywhere; a module named `pytest`, `_pytest`, `sitecustomize`, `usercustomize` (any extension);
    any file under a `pytest/` or `_pytest/` folder; any `.pth` file;
  - `pytest.ini`, `.pytest.ini`, `pytest.toml`, `.pytest.toml`; the pytest section of `pyproject.toml`
    (`[tool.pytest]`, incl. `ini_options`), `tox.ini` (`[pytest]`), `setup.cfg` (`[tool:pytest]`), compared
    parsed; an unreadable settings file is flagged;
  - every `.py` file: AST finds imports of `_pytest` (`import`, `from _pytest …`, `__import__`/`import_module` with a
    literal name), `from sys import modules`, and writes to `sys.modules` (via any `import sys as …` alias:
    item/attribute assignment, `del`, `update`, `setdefault`, `pop`, `popitem`, `clear`, `__setitem__`, `__delitem__`);
    non-test `.py` only (not under `tests/`/`test/`, not `test_*.py`/`*_test.py`): imports of `pytest` itself; an
    unparseable file is flagged. (As corrected in Step 7.)
- `backend/satra/gate_mode.py::analyze_configured`: right after the contract rule check and the static scan, a
  non-empty list → `INCONCLUSIVE`, reason `test-harness tampering suspected: <paths>`, `details["harness_tampering"]`,
  an uncertainty line asking for human review. No image is built and no test runs.

**Design decisions**
- Checked before running anything: the result would be untrustworthy either way, and a REJECT from a run the head may
  have steered is not better evidence than "a human must look". Cost: a tampering PR that also breaks the code gets
  REVIEW, not REJECT.
- Added/changed only: a deleted head file is never loaded into the trusted run (Step 1), so deletion cannot help.
- Settings files compared as parsed sections, so a version bump in `pyproject.toml` is not flagged, but any change
  to the pytest table is. Any change to a dedicated pytest settings file is flagged.
- Test files are exempt only from the plain `import pytest` check, because test code normally imports pytest. A
  test-named file is not safe by its name: code under test can import it (for example `app/tests/shim.py`), so it can
  run in the trusted process; `_pytest` imports and `sys.modules` writes are checked in every `.py` file, and
  `conftest.py` is never exempt. (Corrected in Step 7; the first version exempted test files from all code checks.)
- Fail towards review: unreadable settings and unparseable Python are flagged, since they cannot be shown harmless.
- It is a tripwire, not the control: Step 1's isolation already makes these files inert. Static checks are evadable;
  see Step 4.

**Requirements covered:** FR-02 (detect planting of unauthorised test-harness code) — acceptance: each listed change
gives INCONCLUSIVE with "test-harness tampering suspected" and no execution.

**Ch 7 Test cases** (`tests/test_satra_harness_guard.py`)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_harness_changes_in_the_head_are_flagged | every category | 32 cases (conftest ×2, pytest/_pytest modules & folders ×6, site hooks ×2, .pth, 3 settings files, pyproject ×2, tox, setup.cfg, 2 unreadable, 6 pytest imports, 6 sys.modules forms, unparseable) | exactly that path listed | pass ×32 |
| test_a_changed_existing_conftest_is_flagged | changed, not only added | base vs head conftest | flagged | pass |
| test_ordinary_changes_are_not_flagged | false positives | unchanged harness files, test files importing pytest, unrelated pyproject/tox/setup.cfg changes, sys.modules reads, pytest-like names, app change | nothing listed ×8 | pass |
| test_deleting_a_harness_file_is_not_flagged | deletions | base conftest + ini removed | nothing listed | pass |
| test_asent_config_folder_is_not_compared | frozen config | head `.asent/…/conftest.py` | nothing listed | pass |
| test_tampering_makes_the_gate_run_inconclusive_before_any_test_runs | gate | 7 cases × secure/broken head | INCONCLUSIVE, reason, paths, no build, no run | pass ×14 |
| test_project_tests_that_import_pytest_still_get_a_verdict | no false REVIEW | head adds tests/test_app.py importing pytest | ACCEPT | pass |

Before wiring into `gate_mode.py` the 14 gate cases failed (ACCEPT/REJECT); after: 129 passed, 1 xfailed across
the three SATRA gate test files. Full suite: 1909 passed, 37 skipped, 1 xfailed; scenario verdicts equal the `HEAD`
worktree's (report restored).

**Defects found and fixed:** none.

**Known limitations / deferred:** heuristic; indirect forms (`getattr(__import__("s"+"ys"), "modules")`, `gc`,
frames, `exec` of built strings) are not seen. Legitimate new `conftest.py` files or pytest settings now go to review.

**Tool disclosure (Ch 8.7):** Claude Code wrote the module, gate change, tests and this section; Maryam to review.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Why not REJECT tampering?* It is a suspicion from a heuristic; a human decides. INCONCLUSIVE is never ACCEPT.
- *Won't every PR that adds a conftest be stuck?* It goes to review (REVIEW at the shared gate); that is the intended
  cost of a change to the code that runs the tests.

## Step 4 — Stated limit and threat model (2026-11-08)

### Stated limit: code under test runs in the trusted pytest process

The trusted tests import the head's modules, so head code runs inside the same pytest process with the same rights.
Steps 1–3 close the routes that need no code (files pytest loads by itself, a planted or overwritten results file)
and make the obvious code routes visible. They do **not** stop a fully adversarial head from patching pytest at run
time, replacing what the tests call, writing a consistent results file at the `--junitxml` path from `sys.argv`, and
exiting 0. This is not solved. It is kept visible as the strict xfail
`test_known_limit_in_process_code_under_test_can_still_forge_results`: it fails today, and if it ever passes the
test run fails until this documentation is updated.

**Ch 6 Implementation**
- `docs/satra/threat-model.md` (new; SATRA had no threat model document): scope, what an ACCEPT claims, trust boundary,
  threats → controls → code → tests, five stated limits (in-process code; heuristic tripwire; head tests use head
  config; trusted engine / host harness does not enforce `:ro`; results directory fallback).
- `docs/asent-gate.md`: new section "SATRA's trusted test run"; first "Known limitations" bullet states the limit.
- `docs/satra/README.md`: links to the threat model and these notes.
- `tests/test_satra_harness_isolation.py::test_threat_model_states_that_in_process_forgery_is_not_solved`.

**Design decisions**
- Separate threat-model file instead of editing the report: the submitted report stays closed (AGENTS.md); the report
  can cite this file.
- Strict xfail, not a skipped or deleted test: the limit is executable evidence, and a future fix is forced to update
  the docs.
- Deferred fix: run the code under test in a separate process from the harness (tests reach the application over a
  socket, or results from an observer outside the process). Not attempted here.

**Requirements covered:** NFR-03 (security boundary stated honestly) — acceptance: the doc test finds the limit in all
three documents and the xfail is strict.

**Ch 7 Test cases**

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_threat_model_states_that_in_process_forgery_is_not_solved | limit stays documented | threat-model.md, asent-gate.md, these notes, xfail marker | phrases present; `strict=True` | pass |

The documents were written before this test, so it passed on its first run (no red phase).
Full suite: 1910 passed, 37 skipped, 1 xfailed; scenario verdicts equal the `HEAD` worktree's (report restored).

**Defects found and fixed:** none.

**Known limitations / deferred:** see the stated limit above. No real-container test of Steps 1–2 has been added:
`tests/test_satra_project_image_docker.py` is named test-by-test in `.github/workflows/satra-ci.yml`, which this
change does not edit; the existing real gate tests there exercise the new command in CI.

**Tool disclosure (Ch 8.7):** Claude Code wrote the documents and the test; Maryam to review the wording of the limit.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Is the bypass fixed?* The file-based bypasses are (tests in Steps 1–2). A head whose code attacks the pytest process
  can still lie; that is stated, tested as a strict xfail, and listed as a limit of SATRA ACCEPT.
- *What would fix it fully?* Separating the code under test from the test harness process; deferred.

## Step 5 — Real-container test of the trusted-run isolation (2026-11-08)

**Ch 6 Implementation**
- `tests/test_satra_project_image_docker.py::test_real_container_trusted_run_resists_head_harness_attacks`: real
  Docker, real per-project image, no host mapping (subprocess calls are only recorded, then passed to the engine).
  1. Gate on a head whose `app/security.py` (`PROBE_HEAD`) on import tries to create `/trusted/planted.txt`, overwrite
     `/trusted/asent_assurance/test_contract.py`, and append to the plugin file found in `sys.modules`; `can_access`
     returns a report string (truthy, so the check is broken) that appears in the real JUnit failure message.
     Expected: REJECT; report `plugin=/asent/asent_satra_trusted_run.py`, all three writes `EROFS`.
  2. From the recorded command: `/asent:ro`, `/trusted:ro`, `/work:rw`; the host folders of `/asent`, `/trusted`,
     `/results` are not inside the head copy; `PYTHONPATH=/asent`, `-p asent_satra_trusted_run`.
  3. Gate on a head that writes a passing `/work/results.xml` at exit (`WRITE_WORK_RESULTS`): REJECT, denied test FAIL.
  4. Root conftest forcing passes, head `pytest.py`, `sitecustomize.py`, `pyproject.toml` addopts, each on a broken
     head: gate INCONCLUSIVE ("test-harness tampering suspected"), and the same head run directly as a trusted run in
     the real container: exit 1, `test_other_user_denied` FAIL.
- `.github/workflows/satra-ci.yml`: the test added to the "ran without skips" required list.

**Where the plugin lives in the container:** `/asent/asent_satra_trusted_run.py`. `run_pytest` copies
`backend/satra/trusted_run_plugin.py` to `<tmp>/asent/` (a sibling of the head copy `<tmp>/project`, never inside it)
and mounts it `-v <tmp>/asent:/asent:ro`; `PYTHONPATH=/asent` and `-p asent_satra_trusted_run` load it.

**Design decisions**
- One test function, not parametrized: the CI step matches JUnit names exactly, and `[param]` ids would not match.
- Tripwire-caught attacks are also run directly, because the gate never executes them; otherwise the container
  isolation would be untested for those files.
- The read-only check is observed from inside the container by the head's own code (errno names), not inferred
  from the command line.

**Requirements covered:** FR-07 in CI — the isolation of Steps 1–2 is checked in a real container, and the job fails if
the test is skipped or missing.

**Ch 7 Test cases**

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_real_container_trusted_run_resists_head_harness_attacks | real-container isolation | 6 attacks on a broken head | REJECT ×2, INCONCLUSIVE ×4, direct runs FAIL ×4; `/asent`, `/trusted` writes EROFS; plugin at `/asent`, ro, outside `/work` | skipped locally (no Docker); must run in CI |
| test_satra_ci_fails_when_any_docker_backed_test_is_missing_or_skipped | CI list complete | satra-ci.yml | new test listed | failed before the workflow edit; pass after |

The probe and report parsing were dry-run once through the host harness (throwaway test, not committed): REJECT, report
parsed, mounts as above; on the host the writes do not fail (the harness does not enforce `:ro`), as expected.

Full suite: 1910 passed, 38 skipped (the new Docker test is the 38th), 1 xfailed; `reports/scenario-validation.json` restored
(no runtime code changed in this step).

**Defects found and fixed:** none.

**Known limitations / deferred:** the new test has not run on this machine; its first run is CI.

**Tool disclosure (Ch 8.7):** Claude Code wrote the test, the workflow line and this section; Maryam to review.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *How do you know /trusted is really read-only?* Head code inside the container tries to write there and gets EROFS; the CI job fails if that test is skipped.

## Step 6 — Review fix: native modules are tampering (2026-11-08)

Independent review finding: a head could add `app/security.cpython-312-x86_64-linux-gnu.so` beside a broken
`app/security.py`. Python's import system tries extension modules before source files in the same folder, so the
`.so` would be imported instead of the `.py` that the diff shows; the tripwire did not flag it (only `pytest.so`-style
names were caught).

**Ch 6 Implementation**
- `backend/satra/harness_guard.py`: `NATIVE_SUFFIXES` = lower-cased `importlib.machinery.EXTENSION_SUFFIXES` ∪
  `{.so, .pyd, .dylib}`. In `suspicious`, every added or changed head file whose lower-cased path ends with one of them
  is a finding `{"why": "native module <path>", "label": "native module <path>"}`, before any other rule. Every finding
  now has a `label` (the path for all other kinds).
- `backend/satra/gate_mode.py`: the reason lists labels: `test-harness tampering suspected: native module <path>`
  (other findings unchanged: the path).
- `tests/test_satra_project_image_docker.py::test_real_container_trusted_run_resists_head_harness_attacks`: part 4,
  the review's attack in a real container (gate INCONCLUSIVE with that reason; direct run never passes and its error
  names the `.so`, showing the container's CPython 3.12 does load it instead of `security.py`).

**Design decisions**
- `.so`/`.pyd`/`.dylib` added to the interpreter's own list: ASENT's host Python (3.14 here) and the container's (3.12)
  have different suffixes; every CPython suffix ends in one of these three, so the union covers both.
- Case-insensitive: Windows and macOS file systems may import `X.PYD`/`X.SO`.
- Unchanged native modules from the base are not flagged (added/changed rule, as for every other finding).

**Requirements covered:** FR-02 — a head-supplied native module can never reach ACCEPT; acceptance: the review's attack
gives INCONCLUSIVE with "native module <path>".

**Ch 7 Test cases** (`tests/test_satra_harness_guard.py` unless noted)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_native_modules_added_by_the_head_are_flagged | suffixes, folders, case | 7 paths (cpython-312 .so, abi3.so, `.SO`, cp312 .pyd, `.PYD`, darwin .so, .dylib) | one native finding each | pass ×7 |
| test_a_changed_native_module_is_flagged | changed | base v1 → head v2 | flagged | pass |
| test_an_unchanged_native_module_from_the_base_is_not_flagged | no false positive | same bytes in base and head | nothing | pass |
| test_every_extension_suffix_of_the_interpreter_is_covered | EXTENSION_SUFFIXES | each suffix, alternate upper case | all flagged | pass |
| test_native_module_beside_a_broken_module_makes_the_gate_inconclusive | review's attack | broken security.py + security.cpython-312-x86_64-linux-gnu.so | INCONCLUSIVE, exact reason, no run | pass |
| test_unchanged_native_module_from_the_base_keeps_the_normal_verdict | gate, no false REVIEW | base and head share a .so | ACCEPT | pass |
| test_real_container_trusted_run_resists_head_harness_attacks (part 4) | real container | same attack | INCONCLUSIVE; direct run not a pass, error names the .so | skipped locally (no Docker); CI |

Before the fix 10 of these failed (the review's gate attack was not INCONCLUSIVE); after: 142 passed, 1 xfailed in the
three SATRA gate test files.

**Defects found and fixed:** the review finding above.

**Known limitations / deferred:** a native module the base already has can still be loaded by code under test (it is
base-approved code). Native code is in-process code: the stated limit of Step 4 applies.

**Tool disclosure (Ch 8.7):** Claude Code wrote the change, tests and this section; Maryam to review.

**Review:** independent review reported 2 problems (this and Step 7); both fixed, tests first.

**Supervisor Q&A prep**
- *Why would a .so beat security.py?* `FileFinder` tries extension loaders before source loaders for the same module name.

## Step 7 — Review fix: test-named files are checked for _pytest and sys.modules (2026-11-08)

Independent review finding: test-named files were exempt from all code checks, but a file under a `tests/` folder is
not inert: code under test can import it (the review's `app/tests/shim.py`), so it runs in the trusted process. A
shim there could write `sys.modules` or import `_pytest` without a finding. The Step 3 design note said the head's
tests "never run in the trusted process"; that was wrong and is corrected above.

**Ch 6 Implementation** (`backend/satra/harness_guard.py`)
- `_why`: every `.py` file goes to `_code(path, test_file=_is_test(parts))` (before: non-test files only).
- `_imports_harness(module, test_file)`: `_pytest` always counts; `pytest` itself counts only outside test files.
  Used for `import`, `from … import` and literal `__import__`/`import_module` calls.
- `from sys import modules` and every `sys.modules` write are checked regardless of the file's name.
- Reasons now read "code imports …" / "code writes sys.modules" (no longer "non-test code").
- Docs: Step 3 implementation bullet and design note, `docs/satra/threat-model.md`, `docs/asent-gate.md` corrected.

**Design decisions**
- Keep the `import pytest` exemption: nearly every test file has it, and flagging it would send every PR with tests to
  review. `pytest`'s public API cannot rewrite reports by itself; the `_pytest` internals and `sys.modules` can.
- No exemption by folder or name for the other checks: whether a file can be imported depends on the code under
  test, which the head controls.
- Cost: a head test that legitimately imports `_pytest` (e.g. `from _pytest.monkeypatch import MonkeyPatch`) now goes
  to review.

**Requirements covered:** FR-02 — acceptance: the review's `app/tests/shim.py` gives INCONCLUSIVE; test files that
only import `pytest` still get a normal verdict.

**Ch 7 Test cases** (`tests/test_satra_harness_guard.py`)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_test_named_files_are_still_checked_for_pytest_internals_and_sys_modules | no name exemption | app/tests/shim.py (sys.modules write; _pytest import), tests/test_app.py `import _pytest.reports`, test_root.py `from sys import modules`, app/sec_test.py `del s.modules[…]`, test/helpers.py `import_module('_pytest.runner')` | each flagged | pass ×6 |
| test_review_shim_under_a_tests_folder_makes_the_gate_inconclusive | review's case, gate | broken head + app/tests/shim.py writing sys.modules | INCONCLUSIVE, `…: app/tests/shim.py`, no run | pass |
| test_ordinary_changes_are_not_flagged["test files import pytest"] | exemption kept | `import pytest`, `from pytest import fixture`, `import pytest.mark`, `__import__('pytest')` in test files | nothing | pass |
| test_project_tests_that_import_pytest_still_get_a_verdict | gate, unchanged | head test importing pytest | ACCEPT | pass |

Changed existing case: `NOT_FLAGGED["test files import pytest"]` held `app/sec_test.py: import _pytest`, which asserted
the defect; it now holds `import pytest.mark`, and the `_pytest` form is a flagged case above.
Before the fix the 7 new cases failed; after: 149 passed, 1 xfailed in the three SATRA gate test files.
Full suite: 1929 passed, 38 skipped, 1 xfailed; `reports/scenario-validation.json` restored. (Step 6 full suite: 1922 passed, 38 skipped, 1 xfailed.)

**Defects found and fixed:** the review finding above, and the wrong design sentence in Step 3.

**Known limitations / deferred:** indirect forms remain unseen (Step 3 limits); unchanged base test files are not scanned.

**Tool disclosure (Ch 8.7):** Claude Code wrote the change, tests and this section; Maryam to review.

**Review:** independent review reported 2 problems (Step 6 and this); both fixed, tests first.

**Supervisor Q&A prep**
- *Why still allow `import pytest` in tests?* It is the normal test-file import; the dangerous parts (`_pytest`, `sys.modules`) are checked everywhere.

## Step 8 — Second review: test-module shims, shadowing native modules, pythonpath files (2026-11-08)

Second independent review, three findings: (1) non-test code could import a shim under `tests/` that uses pytest's
public API (`from pytest import TestReport`), allowed there; (2) a head change to a `.py` whose folder already has a
native module of the same name is never what runs (Python imports the `.so`); (3) a plain file — e.g. a zip, which is
importable from `sys.path` — at a base-ini `pythonpath` entry, or that directory deleted, changes where the trusted
run imports the head from.

**Ch 6 Implementation** (`backend/satra/harness_guard.py`, `backend/satra/gate_mode.py`)
- `_test_module(dotted)`: a part equal to `tests`/`test`, or starting `test_`, or ending `_test`. In `_code`, for
  non-test files only: `import x`, `from x import y` (module and each imported name, relative imports included, e.g.
  `from .tests import shim`, `from . import tests`), and literal `__import__`/`import_module` → "non-test code imports
  test module …".
- `suspicious`: builds `natives` {(folder, lower-case module name) → native path} from base ∪ head; a changed `.py`
  with the same key → `why "shadowed by native module <so>"`, label `<py> (shadowed by native module <so>)`.
- `suspicious(base, head, pytest_ini=None)` + `_pythonpath(ini)`: `[pytest] pythonpath` split with `shlex` (as pytest
  does), normalised, keeping only entries the trusted-run plugin maps into the head (not `.`, absolute or `..`). For each:
  an added/changed head file at exactly that path → "plain file where the base pytest.ini maps pythonpath entry …";
  base files under `entry/` but none in the head → finding `entry/`, "deletes the directory …".
- `gate_mode.py`: passes the base config's `pytest_ini` to `suspicious`.
- `docs/satra/threat-model.md`: new "In short" section (isolation = control; tripwire = best-effort heuristic; in-process
  forging = known limit; planned fix = app outside the test process, future work); threats table extended.

**Design decisions**
- Imported names are checked as well as the module (`from app import helpers_test`), because `from pkg import mod`
  imports a submodule.
- Shadowing uses base ∪ head: the review's case is a base `.so` the head did not touch, which the native-module rule
  (added/changed only) cannot see.
- The pythonpath rules read the same ini the trusted run uses (frozen base `.asent/`), not the head's.
- Unreadable base ini → no pythonpath findings; the base trusted run then fails on its own (INCONCLUSIVE).

**Requirements covered:** FR-02 — acceptance: the three review cases give INCONCLUSIVE before any test runs.

**Ch 7 Test cases** (`tests/test_satra_harness_guard.py`)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_non_test_code_importing_a_test_module_is_flagged | rule 1 | 11 forms (absolute, relative `.tests`, `. import tests`, `..test`, `test_*`, `*_test`, import_module, `__import__`) | app/util.py flagged | pass ×11 |
| test_test_files_may_import_other_test_modules | no false positive | 3 test-file imports | nothing | pass ×3 |
| test_names_that_only_contain_test_are_not_test_modules | no false positive | testing, latest, contest_rules, attest, testsuite | nothing | pass ×4 |
| test_review_shim_with_test_report_makes_the_gate_inconclusive | review case 1 | app/tests/shim.py `from pytest import TestReport` + broken app/security.py importing it | INCONCLUSIVE `…: app/security.py`, no run | pass |
| test_changed_py_next_to_a_base_native_module_is_flagged | review case 2 | base .py + .so, head changes .py | .py flagged with the .so named | pass |
| test_any_native_suffix_of_the_same_module_name_shadows | suffixes, case, `__init__` | abi3.so, .pyd, `.DYLIB`, `__init__` .so | flagged ×4 | pass |
| test_head_added_native_module_flags_the_changed_py_too | both flagged | head adds .so, breaks .py | 2 findings | pass |
| test_native_modules_do_not_flag_other_modules | no false positive | other module, other folder, non-.py | nothing ×3 | pass |
| test_base_native_module_beside_a_changed_py_makes_the_gate_inconclusive | review case 2, gate | base .so, head breaks .py | INCONCLUSIVE, no run | pass |
| test_zip_file_named_like_a_pythonpath_entry_is_flagged | review case 3 | `pythonpath = src`, head src = real zip | `src` + `src/` | pass |
| test_plain_file_at_a_nested_pythonpath_entry_is_flagged | nested entry | `lib pkgs/src`, file pkgs/src | pkgs/src only | pass |
| test_deleting_a_pythonpath_directory_is_flagged | deletion | src/ removed | `src/` | pass |
| test_pythonpath_rules_ignore_entries_outside_the_head | not mapped | `.`, none, `../outside /abs` | nothing ×3 | pass |
| test_editing_files_inside_a_pythonpath_directory_is_not_flagged | no false positive | change inside src/ | nothing | pass |
| test_zip_named_src_makes_the_gate_inconclusive | review case 3, gate | as above | INCONCLUSIVE `…: src, src/`, no run | pass |

Changed existing assertions: `test_native_module_beside_a_broken_module_makes_the_gate_inconclusive` and part 4 of the
real-container test now accept that the reason continues after `native module <so>` (the shadowed `.py` is listed
second); the first test also checks both paths. Before the change the three review gate cases failed (INCONCLUSIVE
only from incomplete execution, REJECT, and "do not detect the counterfactual"); after: 199 passed, 7 skipped, 1 xfailed
in the five SATRA gate/image test files. Full suite: 1966 passed, 38 skipped, 1 xfailed; `reports/scenario-validation.json`
restored.

**Defects found and fixed:** the three review findings above. Found while testing, **not fixed (out of scope)**:
`backend/orchestrator/workspace_manager.py::create` leaves the base's emptied folders in the candidate worktree, so a
head that turns a directory into a file (`src/` → `src`) makes `create_gate_run` raise `IsADirectoryError`.
`backend/gate/runner.py` turns that into REVIEW (fails closed), but SATRA never sees such a head in a real gate run.
The gate test therefore builds the candidate workspace's shape itself.

**Known limitations / deferred:** `django.test`-style framework modules imported by app code are flagged too (review);
a test-named shim the base already has is not re-checked; the tripwire remains a heuristic (threat model, "In short").

**Tool disclosure (Ch 8.7):** Claude Code wrote the change, tests and docs; Maryam to review.

**Review:** second independent review reported 3 problems; all fixed, tests first.

**Supervisor Q&A prep**
- *Why can a zip named `src` matter?* `sys.path` entries may be zip files; the plugin appends `/work/src`, so a zip there would be imported.
- *Is the tripwire the security control?* No: the isolation is; the tripwire only sends suspicious heads to a human.
