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
  `requirements.lock.txt` installed; `ASENT_PYTHON` selects the interpreter). Build the sandbox once:
  `docker build -t asent-sandbox:local -f docker/sandbox.Dockerfile .`
- **GitHub Actions:** the reusable workflow `.github/workflows/asent-gate.yml` runs on the runner,
  builds the sandbox image, gates the pull request's base and head SHAs, publishes the summary and the
  `asent-gate-report` artifact, fails on BLOCK, and on REVIEW unless `review-fails: false`.
- **Docker image:** `docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/repo" IMAGE asent gate --repository /repo --base B --head H --output-dir /repo/asent-out`.
  Run as the owner of the repository (git refuses repositories owned by another user, and the gate
  ignores global git config). Inside the image there is no container engine, so SATRA test runs are
  INCONCLUSIVE (REVIEW); CAVR's M1 checks do not need one.

## What works on any project, and what needs project input

| Module | Works on any project | Needs project-specific input (in base `.asent/`) | Not supported → fail closed |
|---|---|---|---|
| CAVR | pinned pip requirements: requirement gate (allow/deny, pins), real PyPI wheel download and SHA-256 vs registry digest, dependency tree from Requires-Dist, OSV range check, capability contract from the project's own imports and call sites, AST sink scan, 8-field verdict cache | `cavr/policy.json`: approved and denied packages, allowed capability scopes, task description | dependencies in pyproject/Poetry/Pipenv/setup.py/npm, unpinned requirements, no network → UNRESOLVED; deep runtime analysis is M2 |
| SATRA | trusted tests run on base and head in a `--network none` container, the project's own `tests/`, Bandit on the configured source dirs, a RETURN_TRUE counterfactual the trusted tests must catch, oracle check of the project's security test | **always**: `satra/contract.json` (rule, route, expected status, authority, counterfactual target) and `satra/trusted_tests/`; optionally `project_security_tests` | no Docker/Podman, no contract, mutant not killed, disabled rule → INCONCLUSIVE |
| SABLE | HCL parse of the configured Terraform roots and their local modules, inline IAM role policies and S3 object access, successor ranking across renames and `moved` blocks | **always**: `sable/obligations.json` (principal, protected asset, actions, Terraform root) | remote modules, managed policies, other clouds, deployed state, Terraform outside `terraform_dirs` → UNKNOWN |
| Orchestrator / final gate | snapshot binding, evidence reuse and invalidation, ACCEPT/BLOCK/REVIEW | which modules are enabled (with a reason when disabled) | — |
| Repair | — | built-in demo only | never run by the gate |

The built-in demo scenarios (`demo_project/InvoiceHub`, with its own `.asent/`) keep their original
analyzers (CAVR lockfile analyzer, InvoiceHub SATRA path, single SABLE obligation); gate runs never
use those paths (`tests/test_gate_no_hardcoded_paths.py`).

## Known limitations

- Symlinks, submodules and Git LFS content are not analysed (symlinks/submodules → REVIEW).
- A bare repository is not supported; `--repository` must be a work tree's top level.
- Live advisories change: a dependency verified today can be blocked tomorrow (by design).
