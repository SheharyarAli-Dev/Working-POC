# `asent gate`: ASENT on any git repository

```
asent gate --repository PATH --base REF --head REF [--output-dir DIR] [--data-dir DIR] [--keep-workdir]
```

Decides one change (base → head) of a git repository, without the ASENT server, and writes
`asent-report.json` and `asent-summary.md` to `--output-dir` (default: the current directory).

| Exit | Decision | Meaning |
|---|---|---|
| 0 | ACCEPT | every assessed module has current acceptable evidence for the exact head commit |
| 1 | BLOCK | a module found a violation (CAVR REJECTED/BLOCK, SATRA REJECT, SABLE REGRESSED) |
| 2 | REVIEW | anything else: uncertain evidence, missing/invalid config, unknown ref, internal error, no output written |

## How it works

1. Both refs are resolved to commit SHAs; the exact committed blobs of both commits are exported
   (`git ls-tree` + `git cat-file`: no checkout, no hooks, no `.gitattributes` effects).
2. The authority is `.asent/` **at the base commit** (schema: [asent-config.md](asent-config.md)). It is
   frozen into the run; if the head commit changes `.asent/`, the decision cannot be ACCEPT.
3. Each module whose inputs exist and which the base config enables is run on base and head:
   CAVR (M1 pipeline), SATRA (configured contract), SABLE (configured obligations).
4. The orchestrator's final gate combines the evidence; disabled modules are reported as
   **"not assessed (disabled by base config)"** and never as passed.

## Getting started in a repository

1. `asent init --repository .` writes a starter `.asent/` (marked `_starter`: every gate decision is
   REVIEW until it is reviewed).
2. Review `.asent/cavr/policy.json` (task description, allowed scopes, approved and denied packages);
   write `.asent/satra/` and `.asent/sable/obligations.json` if those modules apply; remove `_starter`.
3. Merge `.asent/` to the default branch.
4. Copy [gate/asent-pr.yml](gate/asent-pr.yml) to `.github/workflows/asent.yml` and pin a full ASENT
   commit SHA. Pinning third-party actions by commit SHA is recommended as well.

## Running it

- **Locally:** `scripts/asent gate --repository ../project --base main --head feature` (Python with
  `requirements.lock.txt` installed; `ASENT_PYTHON` selects the interpreter). Build the images once:
  `bash scripts/satra_build_sandbox.sh` (`asent-sandbox:local` and the SATRA runner `asent-satra-runner:local`).
- **GitHub Actions:** the reusable workflow `.github/workflows/asent-gate.yml` runs on the runner,
  builds the sandbox and SATRA runner images, gates the pull request's base and head SHAs, publishes the summary and the
  `asent-gate-report` artifact, fails on BLOCK, and on REVIEW unless `review-fails: false`.
- **Docker image:** `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" IMAGE asent gate --repository /repo --base B --head H --output-dir /repo/asent-out`.
  Run as the owner of the repository (git refuses repositories owned by another user, and the gate
  ignores global git config). Inside the image there is no container engine, so SATRA test runs are
  INCONCLUSIVE (REVIEW); CAVR's M1 checks do not need one.

## What works on any project, and what needs project input

| Module | Works on any project | Needs project-specific input (in base `.asent/`) | Not supported → fail closed |
|---|---|---|---|
| CAVR | pinned pip requirements: requirement gate (allow/deny, pins), real PyPI wheel download and SHA-256 vs registry digest, dependency tree from Requires-Dist, OSV range check, capability contract from the project's own imports and call sites, AST sink scan, 8-field verdict cache | `cavr/policy.json`: approved and denied packages, allowed capability scopes, task description | dependencies in pyproject/Poetry/Pipenv/setup.py/npm, unpinned requirements, no network → UNRESOLVED; deep runtime analysis is M2 |
| SATRA | trusted tests run on base and head in a `--network none` container, the project's own `tests/`, Bandit on the configured source dirs, a RETURN_TRUE counterfactual the trusted tests must catch, oracle check of the project's security test | **always**: `satra/contract.json` (rule, route, expected status, authority, counterfactual target) and `satra/trusted_tests/`; optionally `project_security_tests` | no Docker/Podman, no contract, mutant not killed, disabled rule, no approved gate image (below) → INCONCLUSIVE |
| SABLE | HCL parse of the configured Terraform roots and their local modules, inline IAM role policies and S3 object access, successor ranking across renames and `moved` blocks | **always**: `sable/obligations.json` (principal, protected asset, actions, Terraform root) | remote modules, managed policies, other clouds, deployed state, Terraform outside `terraform_dirs` → UNKNOWN |
| Orchestrator / final gate | snapshot binding, evidence reuse and invalidation, ACCEPT/BLOCK/REVIEW | which modules are enabled (with a reason when disabled) | — |
| Repair | — | built-in demo only | never run by the gate |

The built-in demo scenarios (`demo_project/InvoiceHub`, with its own `.asent/`) keep their original
analyzers (CAVR lockfile analyzer, InvoiceHub SATRA path, single SABLE obligation); gate runs never
use those paths (`tests/test_gate_no_hardcoded_paths.py`).

## SATRA's per-project test image

SATRA runs the trusted tests of a gate run in an image made for the project, not in ASENT's own
`asent-sandbox:local` (that image is used only by the built-in demo):

1. **Base commit only.** The base commit's `dependencies.lock.json`, its requirements files and the base
   `.asent/cavr/policy.json` decide what is installed. A pull request cannot add a package to the image.
2. **Every entry approved.** Every requirement and every lockfile entry, transitive packages included, must be
   PERMITTED by CAVR's requirement gate (pinned, on `approved_requirements`, not denied, in the lockfile).
   Each entry needs a PyPI wheel filename and its sha256.
3. **Wheels only, by hash.** The image is built `FROM asent-satra-runner:local` (CPython 3.12 + pytest) with
   `pip install --require-hashes --no-deps --only-binary :all:`, so no `setup.py` or build script runs. The
   project itself is never installed; its files are only mounted for the test run.
4. **Network only while building.** The build downloads the wheels from PyPI. The tests then run exactly as
   before: `--network none`, read-only root, `--cap-drop ALL`, no-new-privileges, CPU/process/tmpfs limits.
5. **Content-addressed.** The tag `asent-satra-project:<key>` is a hash of the lockfile digest, the runner
   image ID and the Python version (plus the generated requirements and builder version). Every gate run
   builds it fresh with `--no-cache`; a cached image is reused only on a development machine that sets
   `ASENT_SATRA_REUSE_IMAGES=1`, and then only when its labels carry the same key and its layers start with
   the runner's.
6. **Runner packages.** If the lockfile also pins pytest, pluggy, iniconfig, packaging or Pygments, it must be
   the runner's version with the runner's wheel hash; otherwise INCONCLUSIVE.

No lockfile, a requirement or entry CAVR does not permit, no wheel for CPython 3.12 Linux x86_64, a clash with
the runner, or a failed build → **INCONCLUSIVE** (REVIEW), never a pass. There is no fallback image. A project
without third-party dependencies commits an empty requirements file and `{"packages": []}` as its lockfile.

**Test-run limits.** The pytest timeout (default 40 s) and container memory (default 512m) can be raised only
by the base commit's `.asent/satra/sandbox.json`, for example `{"timeout_seconds": 120, "memory": "1g"}`, up to
180 s and 2g. A value above the cap, below the default, or any other key → INCONCLUSIVE.

**A new dependency needs its own pull request.** The image is built from the base commit, so code in a pull
request can only import packages that are already approved and locked on the base branch. Add the package
(requirements, lockfile, CAVR policy) in its own pull request, get it gated and merged, and only then merge
code that uses it. Otherwise the head's trusted tests fail on the import: INCONCLUSIVE when collection fails,
or REJECT when the import fails inside a test.

## SATRA's trusted test run

The base commit's trusted tests and `pytest.ini` are mounted read-only at `/trusted`, the head at `/work`, and pytest
starts as `python -P -s -m pytest -c /trusted/pytest.ini --rootdir=/trusted --confcutdir=/trusted -p no:cacheprovider`
with plugin autoloading off. No head `conftest.py`, pytest settings file, `pytest.py`, `sitecustomize.py` or `.pth`
file is loaded; the head is appended to the end of `sys.path` as code under test. Results are written to a fresh
directory outside `/work` and must agree with pytest's exit code. A head that adds or changes any of these files, a native module (`.so`, `.pyd`, `.dylib`), a
pytest setting, code that imports `_pytest` or writes `sys.modules` (test files included), or non-test code that imports pytest gets SATRA **INCONCLUSIVE** ("test-harness
tampering suspected", REVIEW). Details: `docs/satra/harness-isolation.md`, `docs/satra/threat-model.md`.

## Known limitations

- **SATRA cannot defend against code under test that attacks the test process.** The trusted tests import the head's
  code, so that code runs inside the same pytest process and can still forge a passing result. A SATRA ACCEPT is not
  evidence against a deliberately adversarial head; see `docs/satra/threat-model.md`.

- Symlinks, submodules and Git LFS content are not analysed (symlinks/submodules → REVIEW).
- A bare repository is not supported; `--repository` must be a work tree's top level.
- Live advisories change: a dependency verified today can be blocked tomorrow (by design).
