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
