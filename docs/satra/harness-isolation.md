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
  - non-test `.py` (not under `tests/`/`test/`, not `test_*.py`/`*_test.py`): AST finds `import pytest`/`_pytest`,
    `from _pytest …`, `__import__`/`import_module` with a literal pytest name, `from sys import modules`, and writes
    to `sys.modules` (via any `import sys as …` alias: item/attribute assignment, `del`, `update`, `setdefault`,
    `pop`, `popitem`, `clear`, `__setitem__`, `__delitem__`); an unparseable file is flagged.
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
- Test files are exempt from the import/`sys.modules` check: test code normally imports pytest, and the head's tests
  never run in the trusted process. `conftest.py` is never exempt.
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
