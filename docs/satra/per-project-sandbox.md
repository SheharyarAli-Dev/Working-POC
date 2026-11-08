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
