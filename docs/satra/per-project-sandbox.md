# SATRA per-project sandbox images — implementation notes

Branch `satra-per-project-sandbox`. Gate runs execute trusted tests in an image built from the
**base commit's** CAVR-approved lockfile instead of ASENT's own `asent-sandbox:local`.

## Step 1 — Runner base image (2026-11-08)

**Ch 6 Implementation**
- `docker/satra-runner.Dockerfile`: `FROM python:3.12-slim@sha256:5e2bdb1b…fa5b` (registry digest, 2026-11-08);
  installs only `docker/satra-runner.requirements.txt` with `--require-hashes --no-deps --only-binary :all:`.
- `docker/satra-runner.requirements.txt`: pytest 9.1.1, pluggy 1.6.0, iniconfig 2.3.0, packaging 26.3,
  Pygments 2.21.0, each with the PyPI sha256 of its py3-none-any wheel.
- `backend/satra/project_image.py::runner_pins()`: parses that file; any line that is not
  `name==version --hash=sha256:<64 hex>` raises `ValueError`.
- `scripts/satra_build_sandbox.sh`: also builds `asent-satra-runner:local` and probes it with `--network none`.

**Design decisions**
- Separate runner instead of building on `asent-sandbox:local`: that image holds ASENT's own packages
  (fastapi, pydantic, …) which CAVR never approved for the project; a project import could silently succeed.
- Pygments is included although not in the original four names: pytest 9.1.1's real Requires-Dist has
  `pygments>=2.7.2` (colorama/exceptiongroup/tomli do not apply on Linux/3.12).
- Base image pinned by digest so the runner is reproducible; the runner image ID is also part of every
  project image key (Step 3).

**Requirements covered:** FR-07 (hardened sandbox) — the gate test environment contains pytest and nothing unapproved.

**Ch 7 Test cases**

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_every_runner_requirement_is_one_exact_pin_with_one_hash | runner fully hash-pinned | runner requirements file | each line `==` + one sha256 | pass |
| test_runner_pins_are_pytest_and_its_linux_dependencies_only | nothing else in runner | `runner_pins()` | exactly 5 names | pass |
| test_runner_dockerfile_uses_a_pinned_base_and_installs_wheels_by_hash_only | wheels only, pinned base | Dockerfile | digest FROM, 3 pip flags, one COPY | pass |
| test_runner_pins_reader_refuses_a_line_without_a_hash | fail closed | `pytest==9.1.1` | ValueError | pass |
| test_build_script_builds_the_runner_image | CI builds it | build script | tag present | pass |
| test_runner_image_has_only_pytest_and_its_dependencies | real image content | built runner | 6 dists; fastapi/pydantic/flask import fails | skipped locally (no Docker); must run in CI |

Full suite: `.venv/bin/python -m pytest -q` → 1706 passed, 32 skipped.

**Defects found and fixed:** none.

**Known limitations / deferred:** the Docker test has not run on this machine (no Docker); first real run is CI.

**Tool disclosure (Ch 8.7):** Claude Code wrote the files and fetched the hashes and the base digest from
pypi.org / registry-1.docker.io; Maryam to review. Verified by the tests above.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Why not reuse asent-sandbox:local?* It contains ASENT's dependencies; tests could import packages the project never had approved.
- *Why is Pygments there?* pytest 9.1.1 requires it (real Requires-Dist), so `--no-deps` would otherwise leave pytest broken.

## Step 2 — Install plan from the base commit (2026-11-08)

**Ch 6 Implementation**
- `backend/satra/project_image.py::install_plan(base_dir, config, supported_tags)` → `READY` with
  `requirements_text`, `lockfile_sha256`, `packages`, `provided_by_runner`, `decisions`; or `INCONCLUSIVE` with `reason`.
- Algorithm: (1) base CAVR section + policy required; (2) no manifest CAVR cannot read (`gate_adapter._unsupported`);
  (3) base `dependencies.lock.json` must exist, parse, pass `lockfile_problems`; every entry is PyPI, valid name/version,
  64-hex sha256, a `.whl` whose filename matches name+version; one version per package; (4) every requirement of the
  base requirements files and every lock package must be PERMITTED by `requirement_gate.evaluate_requirement`;
  (5) runner clash rule; (6) each package needs a wheel whose tags fit the runner; (7) lines written from validated
  fields, sorted, all hashes per package.
- Helpers `_entry_problem`, `_wheel_name` (`filename`, else basename of `artifact`).

**Design decisions**
- Lock entries are validated before requirements, so the reason names the real defect (found by tests, see below).
- Clash rule: same version **and** the runner's wheel hash among the lock's hashes → package left to the runner
  (identical bytes, recorded in `provided_by_runner`); other version or other bytes → INCONCLUSIVE. Alternative
  (let the project's version win) rejected: it silently changes pytest's environment.
- `supported_tags` is required; empty → INCONCLUSIVE (Step 3 reads them from the runner interpreter itself).
  pip's own refusal at build time remains the final check.
- Reuses CAVR's C2 gate instead of a second allowlist implementation, so "approved" means the same thing in both modules.

**Requirements covered:** FR-07 — only base-commit, CAVR-PERMITTED, hash-pinned wheels can enter a gate image.

**Ch 7 Test cases** (`tests/test_satra_project_image.py`, 37 cases incl. parametrized)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_plan_installs_every_approved_lock_entry_with_all_its_hashes | happy path | 8 real Flask lock entries | READY, 7 sorted lines, MarkupSafe 2 hashes | pass |
| test_plan_is_deterministic_and_ignores_lock_order | stable output | reversed lock | same text, other lock digest | pass |
| test_missing_lockfile_is_inconclusive | no lockfile | no file | INCONCLUSIVE | pass |
| test_requirements_with_an_empty_lockfile_is_inconclusive | Maryam's added case | Flask==3.1.3, `[]` | INCONCLUSIVE NOT_IN_LOCKFILE | pass |
| test_no_requirements_and_an_empty_lockfile_install_nothing | stdlib-only project | comment-only req, `[]` | READY, empty | pass |
| test_unreadable_lockfile_is_inconclusive | bad JSON / no packages | 2 inputs | INCONCLUSIVE | pass |
| test_transitive_entry_not_on_the_allowlist_is_inconclusive | Option 1 | Jinja2 not approved | NOT_ON_ALLOWLIST | pass |
| test_denied_lock_entry_is_inconclusive | denylist | blinker denied | DENYLIST | pass |
| test_requirements_file_must_be_fully_permitted | C2 on req file | `>=`, unapproved, `--index-url`, `-e .`, path | INCONCLUSIVE ×5 | pass |
| test_requirement_missing_from_the_lockfile_is_inconclusive | req ⊄ lock | six approved, not locked | NOT_IN_LOCKFILE | pass |
| test_cavr_disabled_means_nothing_is_approved | no CAVR | disabled | INCONCLUSIVE | pass |
| test_configured_requirements_file_missing_in_base_is_inconclusive | missing file | no requirements.txt | INCONCLUSIVE | pass |
| test_dependency_manifest_cavr_cannot_read_is_inconclusive | other manifests | pyproject deps, Pipfile | INCONCLUSIVE ×2 | pass |
| test_malformed_lock_entry_is_inconclusive | field validation / injection | LOCAL, bad sha ×3, newline name, version injection, sdist, no wheel, mismatched wheel | INCONCLUSIVE ×9 | pass |
| test_artifact_path_names_the_wheel_when_filename_is_absent | InvoiceHub lock shape | `artifact` only | READY | pass |
| test_two_versions_of_one_package_are_inconclusive | pip cannot hold both | blinker 1.9.0 + 1.8.2 | INCONCLUSIVE | pass |
| test_runner_package_at_the_same_version_and_bytes_comes_from_the_runner | clash rule, safe case | packaging 26.3 wheel | READY, provided_by_runner | pass |
| test_runner_package_clash_is_inconclusive | clash rule | packaging 25.0, pytest 8.4.2, packaging 26.3 sdist sha | INCONCLUSIVE ×3 | pass |
| test_package_without_a_compatible_wheel_is_inconclusive | wheels only | numpy cp314 only | INCONCLUSIVE | pass |
| test_stable_abi_wheel_is_compatible | abi3 | cryptography cp311-abi3 manylinux_2_34 | READY | pass |
| test_without_runner_tags_no_plan_is_ready | fail closed | no tags | INCONCLUSIVE | pass |
| test_plan_reads_only_the_directory_it_is_given | base only | extra package in a head dir | not installed | pass |

Pre-implementation checks (real `install_plan`, git-archive exports in the scratchpad, tags = CPython 3.12 glibc 2.36 x86_64):
- asent-target-invoicehub `main`: READY, 1 wheel (pypdf 6.21.4) → would still end INCONCLUSIVE at test time (fastapi missing).
  With the 15 missing entries and pins added to a scratch copy: READY, 16 wheels.
- asent-target-flask `asent-config` as committed: INCONCLUSIVE (alembic==1.20.1 NOT_ON_ALLOWLIST). With the 34 pins in memory:
  READY, 56 wheels + packaging 26.3 from the runner; all 57 packages have a fitting wheel (cryptography via cp311-abi3).

**Defects found and fixed:** requirement checks ran before lock-entry validation, so a malformed Flask entry was reported
as "Flask not in lockfile" — validation moved first (2 parametrized cases caught it).

**Known limitations / deferred:** requirement markers/extras are not evaluated (the lock is the install set);
`--hash` values written in requirements.txt are ignored in favour of the lockfile's.

**Tool disclosure (Ch 8.7):** Claude Code wrote the code and tests; all test hashes are PyPI digests (fetched from
pypi.org or copied from the Flask lockfile). Maryam to review.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Can a PR add a package?* No: `install_plan` gets only the base export and the frozen base config; tested.
- *Why must transitive packages be in the policy?* Option 1: every installed wheel is individually PERMITTED by CAVR.

## Step 3 — Build or reuse the gate image (2026-11-08)

**Ch 6 Implementation**
- `project_image.runner_identity(engine)`: `image inspect asent-satra-runner:local` (ID, layers) and one
  `--network none --read-only --cap-drop ALL` run of the runner printing `platform.python_version()` and
  `packaging.tags.sys_tags()`.
- `project_image.image_key(lockfile_sha256, runner_id, python, requirements_text)`: sha256 over those plus
  `BUILDER_VERSION`; tag `asent-satra-project:<key>`.
- `project_image.prepare(base_dir, config, engine)`: identity → `install_plan` → reuse if the tagged image's labels
  (key, lockfile sha256, runner ID, python, builder) all match **and** its layers start with the runner's layers;
  else build from a temp context holding only `Dockerfile` + `requirements.txt`
  (`FROM asent-satra-runner:local`, `pip install --require-hashes --no-deps --only-binary :all:`), then re-inspect.
- `_run` is the single engine call site (replaced by `FakeEngine` in tests).

**Design decisions**
- Key includes the generated requirements digest and `BUILDER_VERSION` besides the three asked-for inputs: both
  are derived, but including them means a code change can never reuse an image built from other instructions.
- Name match alone never reuses: labels and the runner layer prefix are checked; mismatch → rebuild (tests both).
- Python version and tags read from the runner's interpreter, not assumed from the base image tag.
- Build uses the engine's default build network (needed for PyPI); no `--network host`. Test runs are unchanged.
- An empty install set builds a labelled image with no `RUN` (pip refuses an empty requirements file).

**Requirements covered:** FR-07 — content-addressed, label-verified images; build failures fail closed.

**Ch 7 Test cases** (`tests/test_satra_project_image.py`, fake engine; `tests/test_satra_project_image_docker.py`, real Docker)

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| test_build_context_holds_only_the_dockerfile_and_the_hashed_requirements | no project code, wheels only | Flask lock | 2 files, 3 pip flags, 1 COPY, no host network | pass |
| test_runner_is_probed_without_network | isolation of probe | — | `--network none --read-only` | pass |
| test_key_is_a_hash_of_lockfile_runner_and_python | content address | 4 key variants | 4 distinct keys | pass |
| test_image_with_the_right_label_is_reused | cache | same base twice | 1 build, reused | pass |
| test_image_with_the_right_name_but_not_the_right_label_is_rebuilt | never reuse by name | no labels / wrong key | rebuilt ×2 | pass |
| test_missing_runner_image_is_inconclusive | fail closed | no runner | INCONCLUSIVE, no build | pass |
| test_unusable_runner_probe_is_inconclusive | fail closed | 3 bad probes | INCONCLUSIVE ×3 | pass |
| test_plan_refusal_builds_nothing | fail closed | no lockfile | no build | pass |
| test_build_failure_is_inconclusive_with_the_end_of_the_log | build failure | exit 1 + pip hash error | INCONCLUSIVE + log tail | pass |
| test_build_timeout_is_inconclusive | timeout | TimeoutExpired | INCONCLUSIVE | pass |
| test_built_image_that_is_not_on_the_runner_is_inconclusive | wrong base | foreign layers | INCONCLUSIVE | pass |
| test_empty_install_set_builds_the_runner_with_labels_only | no deps | empty req + lock | READY, no RUN | pass |
| test_gate_image_is_built_from_a_real_lock_entry_and_then_reused | real build | real six 1.17.0 wheel | imports six, not flask; reused | skipped locally; CI |
| test_a_changed_hash_makes_pip_refuse_the_build | hash enforcement | six sdist sha on wheel | INCONCLUSIVE, HASH in log | skipped locally; CI |
| test_pip_refuses_a_wheel_that_does_not_fit_even_past_the_tag_check | pip final check | numpy cp314 only, tag check bypassed | INCONCLUSIVE | skipped locally; CI |

**Defects found and fixed:** none in this step.

**Known limitations / deferred:** images are never garbage-collected (one per distinct key); a local attacker with
Docker access could forge labels — the Docker daemon is inside the trust boundary, as for `asent-sandbox:local`.

**Tool disclosure (Ch 8.7):** Claude Code wrote code and tests; six/numpy hashes are PyPI digests. Maryam to review.
The three Docker tests have not run on this machine.

**Review:** no independent review pass run for this step.

**Supervisor Q&A prep**
- *Why can't a cached image be wrong?* Reuse needs all five labels and the runner's layers; the key covers the base lockfile bytes, runner ID and Python.
- *Does any project code run at build time?* No: the context is two generated files, and `--only-binary :all:` means no setup.py runs.
