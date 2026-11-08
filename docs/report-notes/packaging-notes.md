# ASENT packaging report notes (installable `asent` command)

Branch `asent-installable-cli`, work of 2026-11-08. Not CAVR work, so these notes are kept here and not in
`cavr-report-notes.md`. Commits are local; nothing is pushed. Every commit was checked with
`.venv/bin/python -m pytest -q` on the exact committed tree (a scratch `git worktree` per commit);
`reports/scenario-validation.json`, which the suite rewrites, was restored after each run.

Requirements below are the items of the task request (labelled R1–R9); they are not FR/NFR IDs from the
SRS, which has none for packaging.

- R1 `pip install git+…` / `pipx install …` gives a working `asent` from any folder, no PYTHONPATH, no checkout
- R2 Dockerfiles, sandbox Dockerfiles and default policies are package data
- R3 `asent init`, `gate` (current repo, default base, head HEAD), `doctor`, `dashboard` (127.0.0.1), `report`, `--version`
- R4 `--json` on every command
- R5 CI: build wheel, install outside the repo, run `--version`, `doctor --json`, `gate` on a sample repo, upload the wheel
- R6 existing tests green, gate behaviour unchanged, no security setting changed
- R7 README install and quick start
- R8 gate base default: origin/HEAD, else main, else master, else REVIEW with a reason
- R9 doctor only checks and prints fixes

## Step 1 — Assets and state outside a checkout (2026-11-08)

Commits: `feat(config)` [owner review: shared config], `refactor(satra)` [owner review: SATRA] [owner review: gate tests],
`refactor:` [owner review: orchestrator] [owner review: integrations] [owner review: main.py].
Full suite per commit: 1972 passed, 38 skipped, 1 xfailed / 1972 passed, 38 skipped, 1 xfailed / 1976 passed, 38 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Change | What it does |
|---|---|---|
| `backend/config.py` | `layout(root, package, environ)`; `ASSETS`, `STATE`, `INSTALLED`, `ADVISORIES` | Source tree (root has `requirements.lock.txt` **and** `docker/sandbox.Dockerfile`): assets and state are the repository root, exactly as before. Otherwise (installed): assets are `backend/_data/`, state is `$XDG_DATA_HOME/asent` (default `~/.local/share/asent`, `%LOCALAPPDATA%\asent` on Windows). `DATA` = `ASENT_DATA` or `STATE/runtime`. |
| `backend/cavr/sandbox_runner.py` | `SECCOMP_PROFILE = ASSETS/docker/asent-seccomp.json` | Same file in a checkout; the packaged copy when installed. Flags unchanged. |
| `backend/cavr/sandbox.py` | `laboratory_hashes.json` from `ASSETS` | path only |
| `backend/satra/project_image.py`, `pytest_runner.py`, `settings.py` | `ROOT` → `ASSETS`; `PROJECT_TOP = STATE` | path only; the default `.satra_workspace` moves to the user folder when installed |
| `backend/orchestrator/scenarios.py`, `service.py` | `ROOT` → `ASSETS` | demo scenario files, path only |
| `backend/integrations/osv_adapter.py`, `registry_adapter.py` | cache = `ADVISORIES`; artifact fallback `ASSETS/rel` | an installed ASENT never writes into site-packages |
| `backend/main.py` | `ASSETS/frontend/dist` | path only |

### Design decisions
- Two markers, not one: `pyproject.toml` did not exist yet in step 1, and a lone `docker/` folder can sit next to
  site-packages (the `docker` SDK package), so it must not switch the layout.
- Writable state goes to the XDG data folder rather than next to the code: site-packages may be read-only and
  is replaced on upgrade. Alternative (a `platformdirs` dependency) rejected to add no dependency.
- One path constant per kind (`ASSETS`, `STATE`, `ADVISORIES`) instead of an `asset()` function: each edit stays
  a one-token change that owners can check line by line.

### Requirements covered
- R1/R2: assets are read from the package when installed — `test_a_copy_of_the_package_outside_the_checkout_uses_packaged_assets_and_user_state`.
- R6: checkout paths unchanged and sandbox flags pinned — `test_this_checkout_keeps_every_path_unchanged`, `test_seccomp_profile_is_the_repository_file_and_the_flags_are_unchanged`.

### Ch 7 Test cases (`tests/test_cli_resources.py`)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_layout_of_a_source_tree | checkout detection | lockfile + sandbox Dockerfile | assets = state = root | pass |
| test_layout_of_an_installed_package_uses_xdg_data_home | installed layout | no markers, XDG set | `_data`, `XDG/asent` | pass |
| test_layout_of_an_installed_package_defaults_to_home_local_share | no XDG | HOME only | `~/.local/share/asent` | pass |
| test_a_dockerfile_alone_is_not_a_source_tree | edge: one marker | only Dockerfile | installed layout | pass |
| test_this_checkout_keeps_every_path_unchanged | no behaviour change | this repo | ROOT paths | pass |
| test_seccomp_profile_is_the_repository_file_and_the_flags_are_unchanged | security flags | `get_docker_command` | exact flag list | pass |
| test_no_module_builds_asset_or_state_paths_from_the_repository_root | guard | all backend modules | no `ROOT/'docker…` etc. | pass |
| test_every_packaged_asset_the_code_reads_exists_in_the_checkout | paths exist | 7 files | all present | pass |
| test_a_copy_of_the_package_outside_the_checkout_uses_packaged_assets_and_user_state | installed copy, `python -I` | backend/ copied to tmp | `_data` assets, XDG state, nothing written in package | pass |
| test_asent_data_still_overrides_the_installed_data_folder | override | `ASENT_DATA` | that folder | pass |

### Defects found and fixed
- `tests/test_gate_no_hardcoded_paths.py::test_gate_path_has_no_hardcoded_demo_paths` failed: its allowlist matches
  two `pytest_runner.py` lines by text (`ROOT/'scenarios…'`). Fixed by changing `ROOT` to `ASSETS` in the two allowlist
  strings; the reasons are unchanged.
- The first source-tree marker was `pyproject.toml`, which did not exist yet; replaced by `requirements.lock.txt`.
- The full suite caught `tests/test_hash_verification_line_endings.py::test_satra_pinned_python_source_normalizes_but_other_assets_stay_byte_exact`
  failing: it redirected `pytest_runner.ROOT`, but `permitted_builtin` now reads its reference files from `ASSETS`. The test now
  patches `pytest_runner.ASSETS` (one line, same intent).
- Process slip: when `tests/test_cli_resources.py` was cut down for the first commit, the full version (guard,
  installed-copy, asset-existence and ASENT_DATA tests) was not put back, so the first suite runs of the later commits
  lacked those four tests. Found before committing them; the file was restored and every later commit's suite rerun.

### Known limitations / deferred
- The committed advisory evidence in `advisories/` is not packaged; an installed ASENT starts with an empty cache
  and looks advisories up live (offline → UNAVAILABLE, fail closed).
- The Windows `%LOCALAPPDATA%` branch is not tested.

### Tool disclosure (Ch 8.7)
Claude Code wrote all code and tests. Maryam approved touching SATRA, orchestrator, integrations and `main.py`
for path-only edits; line-by-line owner review is pending (commit tags). Verified by the tests above and the full suite.

### Supervisor Q&A prep
- *Why not just keep `ROOT`?* Installed, `ROOT` is site-packages: `ROOT/docker/...` does not exist and `runtime/`
  would be written into site-packages.
- *Did any security setting change?* No; only where the seccomp file is found. A test pins every `docker run` flag.

## Step 2 — pyproject.toml packaging (2026-11-08)

Commit: `build:`. Full suite: 1985 passed, 38 skipped, 1 xfailed. Review: no reviewer pass was run.

### Ch 6 Implementation
| File | What it does |
|---|---|
| `pyproject.toml` | hatchling; name `asent`; version read from `backend/config.py` `VERSION`; dependencies = `requirements.txt`; `asent = backend.cli:entry`; `only-include` backend, docker, scenarios, demo_project with `sources` mapping the last three under `backend/_data/`; `force-include` for `requirements.lock.txt` and the three pinned demo artifacts |
| `hatch_build.py` | adds `frontend/dist` as `backend/_data/frontend/dist` only when `index.html` exists |
| `backend/cli.py` | `entry()` = the old `__main__` block |

### Design decisions
- hatchling over setuptools: `sources` + `force-include` copy repository folders into the package without moving
  any file, so every existing Dockerfile path, workflow and script keeps working.
- `sources` rewrites folder prefixes only; a single top-level file (the lockfile) needs `force-include`.
- The pinned demo wheel matches the `artifacts/*.whl` ignore rule, so it is named explicitly.
- Dependencies use the `requirements.txt` ranges; `requirements.lock.txt` stays the reproducible set (CI uses it
  as `--constraint`).

### Requirements covered
- R1 — `test_installed_asent_command_runs_a_real_gate_outside_the_checkout`; R2 — `test_every_asset_is_packaged_under_backend_data_byte_identical`, `test_every_tracked_backend_file_is_in_the_wheel`.

### Ch 7 Test cases (`tests/test_cli_packaging.py`; the wheel is built for real with `pip wheel`)
| Test ID | Purpose | Expected | Result |
|---|---|---|---|
| test_wheel_name_and_version_come_from_backend_config | metadata | `asent-1.0.0`, Requires-Python >=3.12 | pass |
| test_wheel_dependencies_are_requirements_txt | deps agree | same set | pass |
| test_wheel_declares_the_asent_command | entry point | `asent = backend.cli:entry` | pass |
| test_every_tracked_backend_file_is_in_the_wheel | policies, seeds | none missing | pass |
| test_every_asset_is_packaged_under_backend_data_byte_identical | assets | present and identical | pass |
| test_wheel_holds_nothing_else | no tests/runtime/pyc | no extras | pass |
| test_record_hashes_match | RECORD complete | names equal | pass |
| test_installed_package_is_imported_from_the_venv_not_the_checkout | fresh venv | backend from venv, INSTALLED | pass |
| test_installed_asent_command_runs_a_real_gate_outside_the_checkout | real gate | REVIEW, exit 2 | pass |

### Defects found and fixed
- `requirements.lock.txt` landed at the wheel root (caught by `test_every_asset_is_packaged_under_backend_data_byte_identical`); moved to `force-include`.

### Known limitations / deferred
- The importable package is `backend`; another distribution with a top-level `backend` in the same environment
  would clash. pipx (own environment) is recommended in the README; renaming is deferred.
- The packaging tests need the hatchling download (they skip with the reason when it is impossible).

### Tool disclosure (Ch 8.7)
Claude Code wrote pyproject, hook and tests; Maryam chose to keep the `backend` name. Verified by real wheel builds.

### Supervisor Q&A prep
- *What is in the wheel?* Every tracked file of `backend/`, plus docker/, scenarios/, demo_project/, the lockfile and
  three demo artifacts under `backend/_data/`; a test compares them byte for byte.

## Step 3 — `--version`, `--json`, `asent gate` defaults (2026-11-08)

Commit: `feat(cli)` [owner review: gate]. Full suite: 2000 passed, 38 skipped, 1 xfailed. Review: no reviewer pass was run.

### Ch 6 Implementation
| File | What it does |
|---|---|
| `backend/gate/defaults.py` | `top_level(path)`; `default_base(repo)`: `refs/remotes/origin/HEAD` if it names an existing `refs/remotes/origin/*` commit, else `refs/heads/main`, else `refs/heads/master`, else `(None, None)`. git runs without hooks or system/global config. |
| `backend/gate/runner.py` | `NO_BASE`; `base is None` raises it inside the existing `try`, so REVIEW with both files written |
| `backend/cli.py` | `--version [--json]`; shared `--json` parent parser; `gate` defaults (repository = top level of the cwd's repo, output dir = that top level, head = HEAD); `init --json` |

### Design decisions
- Full refs (`refs/heads/main`) so a tag named `main` can never be chosen.
- A dangling `origin/HEAD` falls back to main/master instead of failing.
- With an explicit `--repository`, `--output-dir` keeps its old default (current folder), so existing callers see no change.

### Requirements covered
- R3/R8 — `test_origin_head_names_the_default_branch_even_when_it_is_not_main_or_master`, `test_no_default_branch_is_review_with_a_clear_reason`; R4 — `test_gate_json_prints_exactly_the_written_report`.

### Ch 7 Test cases (`tests/test_cli_gate.py`, real git repositories)
| Test ID | Input | Expected | Result |
|---|---|---|---|
| test_origin_head_names_the_default_branch_even_when_it_is_not_main_or_master | clone of a `trunk` repo, run from a subfolder | base `refs/remotes/origin/trunk` | pass |
| test_dangling_origin_head_falls_back_to_main | origin/HEAD → missing branch | `refs/heads/main` | pass |
| test_main_is_used_without_origin | no remote | main | pass |
| test_main_is_preferred_over_master | both | main | pass |
| test_master_is_used_when_there_is_no_main | master only | master | pass |
| test_a_tag_named_main_is_not_a_default_branch | tag `main` only | none | pass |
| test_no_default_branch_is_review_with_a_clear_reason | branch `trunk` only | REVIEW, exit 2, reason names `--base` | pass |
| test_explicit_base_and_head_override_the_defaults | `--base`/`--head` | used as given | pass |
| test_outside_a_git_repository_is_review | plain folder | REVIEW, report written | pass |
| test_run_gate_with_no_base_is_review | `run_gate(base=None)` | REVIEW, NO_BASE first | pass |
| test_gate_json_prints_exactly_the_written_report | `--json` | stdout == file | pass |
| test_gate_text_output_names_the_chosen_base | text | names base and how | pass |
| test_version, test_no_command_is_a_usage_error, test_init_json | CLI | as documented | pass |

Tests-first check: against the tree without the CLI changes, 10 of these 15 failed (the 5 that test
`defaults.py`/`run_gate` directly passed, those files being present).

### Defects found and fixed
- None found by the tests after implementation.

### Known limitations / deferred
- `actions/checkout` does not set `origin/HEAD`; in CI without a local main/master the default base is REVIEW.
  The reusable gate workflow always passes `--base`, so it is unaffected.

### Tool disclosure (Ch 8.7)
Claude Code wrote it; Maryam set the base-default rule (origin/HEAD, main, master, else REVIEW).

### Supervisor Q&A prep
- *Why REVIEW and not an error when there is no base?* Fail closed: a pipeline must get a decision and evidence files, never a silent pass.

## Step 4 — `asent report` and `asent doctor` (2026-11-08)

Commits: `feat(cli): asent report …` (full suite: 2009 passed, 38 skipped, 1 xfailed), `feat(cli): asent doctor …` (full suite: 2021 passed, 38 skipped, 1 xfailed).
Review: no reviewer pass was run.

### Ch 6 Implementation
| File | What it does |
|---|---|
| `backend/commands/report.py` | `default_path()` (repo top level, else cwd), `load()` (refuses non-`asent.gate.v1`), `render()` |
| `backend/commands/doctor.py` | `run_checks(which, run, version_info, assets)`: Python ≥3.12, packaged files and default policies, git, Docker, daemon, the two images, dashboard UI (optional). `build_command(image)` prints the docker build command with packaged paths. `render()`. |
| `backend/cli.py` | `report [--file] [--json]`, `report --run ID [--output]`, old `report ID` → exit 2 naming `--run`; `doctor [--json]` exit 0 ready / 1 not |
| `scripts/qa/acceptance-check.py` | `report --run` |

### Design decisions
- doctor takes `which`/`run` as parameters so every failure is tested alone without changing the machine.
- doctor's only commands are `git --version`, `docker info`, `docker image inspect`; fixes are text.
- Required images are the two the official gate workflow builds; the SATRA-live `asent-sandbox-app` is not checked.

### Requirements covered
- R3/R9 — `test_doctor_only_runs_read_only_probes`, `test_missing_image_prints_the_exact_build_command_with_packaged_paths`; R3 report — `test_report_reads_the_repository_report_from_any_subfolder`, `test_the_old_positional_run_id_is_refused_with_the_new_form`.

### Ch 7 Test cases
| Test ID | Input | Expected | Result |
|---|---|---|---|
| test_everything_present_is_ready | fake full machine | ready, 7 required ok | pass |
| test_old_python_is_missing_with_a_fix | 3.11.9 | missing + 3.12 fix | pass |
| test_no_git | no git | missing | pass |
| test_no_docker_skips_daemon_and_images_and_says_what_it_means | no docker | missing, rest skipped, no docker command run | pass |
| test_daemon_down | daemon error | missing with the error text | pass |
| test_missing_image_prints_the_exact_build_command_with_packaged_paths | one image missing | exact command | pass |
| test_missing_packaged_resources | empty assets | missing, reinstall fix | pass |
| test_dashboard_ui_is_optional_and_said_plainly | no UI | warning, still ready | pass |
| test_doctor_only_runs_read_only_probes | 3 machines + source scan | only the 3 probes | pass |
| test_cli_doctor_text_and_exit_code, test_cli_doctor_json, test_real_probes_on_this_machine_have_the_documented_shape | CLI / real machine | exit 1/0, schema | pass |
| test_report_reads_the_repository_report_from_any_subfolder | real gate report, subfolder | text with decision, shas, modules | pass |
| test_report_json_is_the_file, test_report_file_option | --json, --file | the file | pass |
| test_missing_report_is_a_plain_message | no file | exit 2, message | pass |
| test_a_file_that_is_not_a_gate_report_is_refused (3 cases) | broken / list / other schema | exit 2 | pass |
| test_the_old_positional_run_id_is_refused_with_the_new_form | `report run-123` | names `--run run-123` | pass |
| test_run_option_reads_from_the_server | fake server | GET /api/runs/r1/report, --output | pass |

### Defects found and fixed
- In a checkout the UI warning said "an install from git"; now worded by `INSTALLED`.
- Two test bugs: the CLI tests' patched `run_checks` called itself, and the forbidden-word scan matched prose
  ("pulls"); the scan now looks for quoted command words only. The behavioural guarantee is the command recorder.

### Known limitations / deferred
- Docker is not installed on the development machine, so the Docker-present paths ran only with fakes locally;
  the real ones run in `package.yml` (not yet run on GitHub: nothing pushed).
- Podman is not checked by doctor although SATRA can use it.

### Tool disclosure (Ch 8.7)
Claude Code wrote it; Maryam decided `report --run` and that doctor never builds, uses sudo or changes anything.

### Supervisor Q&A prep
- *How do you know doctor never changes anything?* Every command it runs goes through `run`; the test records them and fails on anything but the three read-only probes.

## Step 5 — `asent dashboard` (2026-11-08)

Commit: `feat(cli): asent dashboard …`. Full suite: 2032 passed, 38 skipped, 1 xfailed. Review: no reviewer pass was run.

### Ch 6 Implementation
`backend/commands/dashboard.py`: `HOST = "127.0.0.1"`, `port_type`, `port_free`, `info`, `serve` (uvicorn
`backend.main:app`). `backend/cli.py`: `dashboard [--port] [--json]`, busy port → exit 2.

### Design decisions
- No `--host` option at all (the dashboard has no authentication).
- `--json` prints one compact line before serving so an editor can read the URL and keep the process.

### Requirements covered
- R3/R4 — `test_the_real_server_answers_on_loopback_only`, `test_json_prints_one_line_before_serving`.

### Ch 7 Test cases (`tests/test_cli_dashboard.py`)
| Test ID | Expected | Result |
|---|---|---|
| test_default_is_port_8000_on_loopback | port 8000 | pass |
| test_serve_passes_the_fixed_host_to_uvicorn | host 127.0.0.1 | pass |
| test_there_is_no_host_option | exit 2 | pass |
| test_invalid_port_is_a_usage_error (0, 65536, -1, http) | exit 2 | pass |
| test_port_in_use_is_a_plain_error | exit 2, message | pass |
| test_json_prints_one_line_before_serving | one JSON line | pass |
| test_without_ui_the_text_says_api_only | API only | pass |
| test_the_real_server_answers_on_loopback_only | 200 on loopback, refused on the other address | pass |

### Defects found and fixed — none.

### Known limitations / deferred
- The CI wheel with the UI is about 10 MB, 9.5 MB of it the existing `frontend/public/defense-replays`.

### Tool disclosure (Ch 8.7)
Claude Code wrote it; verified also by hand with the installed wheel: UI `/` 200, `/api/capabilities` 200, listening on `127.0.0.1` only.

### Supervisor Q&A prep
- *Can someone on the network open it?* No; it binds 127.0.0.1 and there is no option to change that; a test connects to the machine's other address and is refused.

## Step 6 — CI package workflow (2026-11-08)

Commit: `ci:`. Full suite: 2042 passed, 38 skipped, 1 xfailed. Review: no reviewer pass was run.

### Ch 6 Implementation
| File | What it does |
|---|---|
| `.github/workflows/package.yml` | job `wheel`: npm build, `python -m build --wheel`, `check_wheel.py --require-ui`, upload `asent-wheel`; job `installed`: fresh venv in `$RUNNER_TEMP` (lockfile as constraints), `asent --version`, `doctor --json`, `docker build` of both images from the packaged Dockerfiles, `doctor` ready, `gate` on two sample repos (ACCEPT 0, BLOCK 1), upload reports |
| `scripts/ci/make_sample_repo.sh` | SABLE-only sample repo on `main`, head on `change` |
| `scripts/ci/check_wheel.py` | required assets, policies, entry point, nothing outside `backend/`, optional UI |

### Design decisions
- The sample is SABLE-only so its decision is deterministic without PyPI or an LLM; the same inputs as
  `test_sable_preserved_is_accept` / `test_sable_regression_is_block`.
- Images are built in CI from the paths doctor reports, which proves the Dockerfiles are usable package data.

### Requirements covered
- R5 — `tests/test_cli_workflow.py` (4 tests), `tests/test_cli_sample_repo.py` (3 tests), check_wheel tests (3).

### Ch 7 Test cases
| Test ID | Expected | Result |
|---|---|---|
| test_permissions_and_triggers_are_safe | read-only, no `${{` in scripts | pass |
| test_wheel_job_bundles_the_ui_checks_and_uploads | build order, upload | pass |
| test_installed_job_uses_a_fresh_venv_outside_the_checkout | venv in RUNNER_TEMP, no PYTHONPATH | pass |
| test_installed_job_runs_version_doctor_and_gate_with_expected_decisions | commands present | pass |
| test_sample_repository_decisions[accept/block] | ACCEPT 0 / BLOCK 1 | pass |
| test_script_refuses_an_existing_destination_and_an_unknown_mode | exit 2 | pass |
| test_check_wheel_accepts_the_built_wheel / _require_ui_fails_without_the_dashboard_build / _lists_a_missing_asset | ok / fail / listed | pass |

Local run of the same steps (Python 3.12, wheel built with the UI in a scratch worktree, real PyPI install with
the lockfile as constraints, run from outside the repo): `asent --version` → `asent 1.0.0`; `backend` imported from
the venv; doctor: python, resources, git, dashboard-ui ok, Docker missing (not installed here); sample accept →
exit 0 ACCEPT, sample block → exit 1 BLOCK; nothing written inside site-packages.

### Defects found and fixed — none.

### Known limitations / deferred
- `package.yml` has not run on GitHub yet (not pushed); the Docker image build and the doctor-ready step have
  therefore never run.
- The sample does not exercise CAVR or SATRA.

### Tool disclosure (Ch 8.7)
Claude Code wrote the workflow, scripts and tests; verified by the tests and the local run above.

### Supervisor Q&A prep
- *How do you prove it works without the repo?* The job installs the wheel into a new venv in a temp folder, runs from there with no PYTHONPATH, and checks `backend` is imported from that venv.

## Step 7 — README and notes (2026-11-08)

Commit: `docs:`. Full suite: documentation only; code and tests are those of the `ci:` commit (2042 passed, 38 skipped, 1 xfailed), and the suite was run again before this commit. README section 4.0: install (pipx recommended), quick start, `--json`
outputs, data location, `backend` import-name limitation. Review: no reviewer pass was run.

