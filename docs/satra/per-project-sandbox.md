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
