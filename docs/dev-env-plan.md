# Plan: ASENT as a generic gate for any git repository

Status: plan only (2026-11-07). No code written for it yet. Rules from CLAUDE.md apply to every step; no `Co-Authored-By` or "Generated with" lines in commits.

## Context

Today ASENT only analyzes its own bundled InvoiceHub demo. `WorkspaceManager.create` falls back to
`config.DEMO`. SATRA's trusted tests, contract and mutant are InvoiceHub-specific. SABLE reads a fixed
`infra/` directory. The authority files (`policy.json`, `SRS.md`) are read from the **candidate**, so the
change under review can rewrite its own policy. The only CLI is an HTTP client that needs the server
running. Goal: `asent gate --repository PATH --base REF --head REF` runs against any git repo with no
server. It takes its authority from a per-project `.asent/` folder read at the **base** ref, fails
closed (REVIEW) whenever config or evidence is missing, and runs in Docker and in GitHub Actions on PRs.

## Decisions taken (from Q&A, 2026-11-07)

1. **CAVR engine in gate mode:** use the M1 `pipeline.verify_request` on head's pinned requirements.
   The demo fixtures keep the legacy lock analyzer through `cavr.mode: "lockfile"`. Step 14 of the
   CAVR plan (delegation, options A–D) stays Maryam's open decision and is not forced by this plan.
2. **CI runtime:** run on the runner itself. The workflow checks out ASENT at a pinned SHA, installs
   `requirements.lock.txt`, builds `asent-sandbox:local` and runs the gate. The Docker image also ships
   the CLI, for local use or a CI that has no container engine (sandboxed parts then return REVIEW).
3. **Disabled module whose files exist:** allowed only with a non-empty `reason`. The decision covers
   the enabled modules, and the report says "<MODULE> not assessed: <reason>".
4. **Scope:** approving the plan counts as permission to touch orchestrator/satra/sable/integrations/main.
   Each change outside CAVR is its own commit, marked `[owner review: <module>]` in its message body.

## Inventory: hardcoded project paths found

| Where | What | Fix (step) |
|---|---|---|
| `backend/config.py:5` | `DEMO=ROOT/'demo_project'/'InvoiceHub'` | kept for the demo layer only; no analysis module imports it (4, 10) |
| `orchestrator/workspace_manager.py:4,13` | `copy_tree(source or DEMO, …)` | `source` is required; the gate passes base and head exports (4) |
| `orchestrator/service.py:43-53` | scenario run with no source = DEMO + `apply_scenario` | the scenario catalog names its fixture dir (`"project"` field) (4) |
| `orchestrator/service.py:155-194` | `_repair`: `invoice-pdf-lab`, `ROOT/'scenarios/cavr_controlled/invoice_pdf_safe.py'`, `fixtures/invoice.pdf` | demo-only; gate forces `auto_repair=False` (8) |
| `orchestrator/scenarios.py:11-43` | `scenarios/catalog.json`, `scenarios/satra`, `scenarios/sable`, `cavr_controlled` | demo layer; stays, and is never imported on the gate path (10) |
| `orchestrator/context_service.py:15-17` | authority from candidate `SRS.md`/`policy.json` | authority from base `.asent/`; the legacy fallback only applies outside gate mode (4) |
| `orchestrator/context_service.py:47-49,55` | alias map `invoice-pdf-*`/`pypdf`, only `app/` is scanned | `cavr.import_aliases`, `cavr.source_dirs` from config (4) |
| `orchestrator/run_context.py:12` | default title "InvoiceHub assurance run" | generic default (4) |
| `integrations/git_adapter.py:13` | commit message "Trusted InvoiceHub baseline" | "Trusted baseline" (3) |
| `integrations/registry_adapter.py:21` | artifact falls back to `ROOT/rel` (ASENT's own tree) | `allow_builtin=False` unless the run is a demo run (5) |
| `cavr/analyzer.py:80` | `context.path/'fixtures/invoice.pdf'` | `cavr.counterfactual_input` from config, missing → UNRESOLVED (5) |
| `cavr/sandbox.py:23`, `satra/pytest_runner.py:23` | `scenarios/laboratory_hashes.json` | ASENT's own trust index, not a project path; moved to the `config.LAB_HASHES` constant (10) |
| `satra/pytest_runner.py:28` | host-fallback compares against `demo_project/InvoiceHub/{pytest.ini,fixtures/invoice.pdf}` | never consulted in gate mode (`external=True` requires a container); allowlisted (6) |
| `satra/pytest_runner.py:47-48` | copies `backend/satra/trusted_{fixtures,security,functional}.py` | `trusted_tests` dir from config (6) |
| `satra/security_contract.py:98-121` | SRS keyword check + fixed `GET /invoices/{invoice_id}` contract | `.asent/satra/contract.json`; legacy build only when no config (6) |
| `satra/counterfactuals.py:208-225` | `mutate_ownership`: `app/security.py::can_access_invoice` | generic `mutate_return_true(root, "file::function")` from contract (6) |
| `satra/static_adapters.py:9` | bandit on `app/` only | `satra.source_dirs` (6) |
| `satra/analyzer.py:22`, `threat_repo/satra_rules.py:4-17` | "InvoiceHub security contract", the four InvoiceHub rules are required | required rules = the contract's `rule_id`s; legacy message kept for the legacy path (6) |
| `satra/settings.py:9-10` | default target `SheharyarAli-Dev/Threat-Repository` | SATRA live pipeline, not on the gate path; unchanged, and the guard test checks the gate never imports it (10) |
| `sable/analyzer.py:15-16` | `baseline/'infra'`, `policy.json['infrastructure']` (one obligation) | `sable.terraform_dirs` + `obligations.json` (a list) (7) |
| `cavr/api.py:63`, `cavr/context_extractor.py:48,61` | `PROJECT_DIR = SAMPLE_PROJECT_DIR`, default `project_dir=None` → sample | dashboard demo only; the gate adapter always passes an explicit dir, guarded by a test (5, 10) |
| `cavr/requirement_gate.py:39` | `POLICY_PATH = …/project_policy.json` | dashboard only; the gate reads `.asent/cavr/policy.json` (5) |
| `main.py:79,83,145-147` | `/api/project` reads DEMO; mounts InvoiceHub app | server demo; reads the fixture via the catalog (4) |
| `satra/seed_rules.py`, `satra/dictionary.py`, `threat_repo/satra_rules.py` | `applicability: ['InvoiceHub']` | rule metadata, not paths; unchanged (documented) |

Key existing fact: `orchestrator/hashing.py:8` already puts `.asent` in `EXCLUDE`. Config is therefore never
part of the candidate snapshot and never copied by `copy_tree`. It is loaded separately and bound into each
module's `input_hash` as `@config`.

## Design

### `.asent/` layout (documented in `docs/asent-config.md`, schema in `docs/asent-config.schema.json`)
```
.asent/
  config.json            schema_version 1, project name, module switches
  cavr/policy.json       requirement_gate format: approved_requirements, denied_packages,
                         allowed_scopes, project_task_description (+ legacy "dependencies" for lockfile mode)
  satra/contract.json    rule_id, route, expected_status, authority_sources, preconditions, scope,
                         counterfactual {operator: "RETURN_TRUE", target: "app/security.py::can_access_invoice"}
  satra/trusted_tests/   conftest.py + test_*.py, copied into the run as assurance/
  satra/pytest.ini       optional
  sable/obligations.json {"obligations":[{id, principal, protected_asset, actions, scope, minimum_score, margin}]}
  README.md              written by `asent init`
```
`config.json` modules: `CAVR {enabled, mode: pipeline|lockfile, policy, requirements_files, verify: all|changed,
import_aliases, source_dirs, counterfactual_input}`, `SATRA {enabled, contract, trusted_tests, pytest_ini, source_dirs,
project_security_tests}`, `SABLE {enabled, terraform_dirs, obligations}`. `enabled:false` requires `reason`.

The schema is a set of pydantic models (`extra='forbid'`; pydantic is already locked, jsonschema is not).
The committed JSON Schema is generated from them by `model_json_schema()`, and a test fails if the two drift.
Limits: no symlinks in `.asent/`, ≤ 200 files, ≤ 1 MiB. Config file paths stay inside `.asent/`, repo paths
(`terraform_dirs`, `source_dirs`) stay inside the repo, and no path is absolute or contains `..`.

### Trust and fail-closed rules
- Config is read from the **base** commit export. Head's `.asent/` is only hashed: if it differs from
  base, the reason "ASENT configuration changed in this PR; requires maintainer review" is added. The
  result is then REVIEW, or BLOCK if a module blocks.
- REVIEW (exit 2) for: no `.asent/` at base; invalid JSON or schema; `"_starter": true` (an unreviewed
  `init` output); an enabled module with a missing or invalid section or file; unknown/missing ref or a
  shallow clone without the commit; not a git repo; symlinks or over-budget snapshot; no container
  engine for external code; network or OSV unavailable; no applicable module; any internal exception;
  report not writable.
- Exit 0 only when the decision is ACCEPT **and** both output files were written. BLOCK = 1.
  argparse usage errors already exit 2, which matches.
- The gate never runs repair, never pushes, never runs `apply_scenario`, never uses host-fallback
  execution, and runs git with hooks disabled (`git_adapter.git` already sets `core.hooksPath=/dev/null`
  and blanks the global config).

### Gate flow (`backend/gate/runner.py::run_gate`)
1. Resolve `base`/`head` to commit SHAs (`git rev-parse --verify REF^{commit}`).
2. `git_adapter.export_commit` for each: `git archive` → `tarfile.extractall(filter='data')` into a temp dir.
3. `project_config.load(base_export/.asent)` → `ConfigResult(valid, problems, config, digest)`. Invalid → REVIEW report, no analysis.
4. `Service(data_dir).create_gate_run(base_export, head_export, config)` (new): baseline = base, candidate = head
   (same `copy_tree`/`init_repo`/worktree mechanics as `WorkspaceManager.create` plus the file swap `_repair` already uses).
5. `Service.analyze(rid, auto_repair=False)` runs synchronously. The existing `final_gate.decide` gets `extra_reasons`
   (config changed, modules not assessed are reported but not counted).
6. Write `asent-report.json` (`schema: asent.gate.v1`: repository path, base/head ref+sha, config {digest,
   source sha, problems, changed_in_head}, decision, exit_code, coverage per module, tool availability,
   `assurance` = existing `Service.report()`), and `asent-summary.md` (decision line, module table
   status/reason/assessed, "needs project input" notes, bounded claim).
7. `--data-dir` (default temp, deleted afterwards unless `--keep-workdir`), `--output-dir` (default cwd).

### Per-module: what works on any project / what needs project input

| Module | Works on any project | Needs project-specific input | Not supported → fail closed |
|---|---|---|---|
| CAVR (pipeline) | real PyPI wheel download, SHA-256 vs registry digest, Requires-Dist tree, OSV range check, AST risk scan, contract from real imports/call sites, 8-field verdict cache | `cavr/policy.json` (approved/denied, allowed_scopes, task description) | pyproject/poetry/uv/npm manifests, unpinned requirements, no network → UNRESOLVED; deep runtime is M2 |
| SATRA | diff localization, trusted tests run on base and head in a container, ordinary tests, bandit on configured dirs, RETURN_TRUE mutant to check the oracle kills it | **contract, trusted tests, counterfactual target** (none can be inferred safely) | no contract/tests → INCONCLUSIVE; no Docker/Podman → INCONCLUSIVE |
| SABLE | HCL parse of configured dirs, inline IAM role + S3 object model, successor ranking, `moved` blocks | `obligations.json` (which principal may do what on which asset) | remote modules, managed policies outside the model, other clouds, deployed state → UNKNOWN |
| Orchestrator / final gate | snapshot binding, evidence reuse, invalidation, ACCEPT/BLOCK/REVIEW | which modules are enabled | — |
| Repair | — | InvoiceHub only | disabled in gate mode |

## Step 0 baseline (2026-11-07, branch `integration/dev-env` at `fed6c65`)

`.venv/bin/python -m pytest -q`: **1484 passed, 30 skipped, 0 failed** (568 s). Skips: 19 in
`tests/test_cavr_frontend.py` (no Node.js / `frontend/node_modules`), 7 in `tests/test_cavr_live.py`
(`CAVR_LIVE` not set), 4 in `tests/test_satra_sandbox.py` (Docker not available on this machine).
Because Docker is absent locally, gate tests for container-dependent paths must inject tool availability;
the real container path is checked in CI and in the recorded PR run (step 9).

## Steps (tests written first in each step; full `.venv/bin/python -m pytest -q` before each commit;
report notes appended per CLAUDE.md; review result in one line)

**0 — Baseline + plan doc.** Run the full suite and record the exact pass/fail counts in the plan doc
(existing failures are recorded, not fixed here). Write `docs/dev-env-plan.md`. Commit `docs(gate): …`.

**1 — Config schema + loader.** New `backend/project_config/{__init__,schema,loader}.py`, `docs/asent-config.md`,
`docs/asent-config.schema.json`. Tests `tests/test_project_config.py`: missing dir; missing config.json;
bad JSON; unknown key; wrong schema_version; `..`/absolute path; symlink inside `.asent/`; > 200 files / > 1 MiB;
disabled without reason; enabled module whose file is missing; `_starter` → invalid; invalid CAVR policy
(reuses `requirement_gate.policy_problems`); valid full config; digest stable across runs and changing on a
one-byte edit; committed schema == generated. *Done:* every invalid case gives `valid=False` with a named problem.

**2 — `asent init`.** `backend/project_config/starter.py`; `init` subcommand in `backend/cli.py` (local, no HTTP).
Detects surfaces (requirements files, `.py` outside tests, `.tf` dirs), writes starter files with `_starter: true`
and pins copied from requirements.txt, refuses to overwrite without `--force`, refuses a symlinked `.asent`.
Tests `tests/test_gate_init.py`: empty repo; Python repo; Terraform repo; existing `.asent`; `--force`;
starter loads as invalid "starter not reviewed"; after removing `_starter` it loads valid.

**3 — Git export** `[owner review: integrations]`. `git_adapter.export_commit(repo, ref, dest)` + `resolve_commit`;
generic commit message. Tests `tests/test_gate_git_export.py` (real temp repos): good refs; unknown ref; not a repo;
a `post-checkout`/`post-merge` hook is not executed; a symlink in the commit makes snapshotting fail; base == head.

**4 — Orchestrator plumbing + demo fixtures on `.asent/`** `[owner review: orchestrator, main]`. `RunContext`
gets `config_digest`, `config_source`, `not_assessed`, and mode `gate`. `ContextService(…, config=None)` takes policy
from config, falls back to policy.json only outside gate mode, adds `@config` to `inputs()`, makes
`applicability()` the intersection with enabled modules, and reads aliases/source_dirs from config.
`WorkspaceManager.create` requires `source`. New `create_gate_run`. `decide(…, extra_reasons=())`.
Catalog entries get `"project"`. Add `demo_project/InvoiceHub/.asent/` and the replay baseline `.asent/`,
mirroring their policy.json (SATRA trusted tests copied, plus a byte-equality test against
`backend/satra/trusted_*.py`). Tests `tests/test_orchestrator_config.py`: a config edit invalidates evidence;
a disabled module is listed as not assessed; a config problem → REVIEW; BLOCK beats a config REVIEW; no module →
REVIEW. *Done:* `tests/test_integration.py` and `tests/test_modules.py` pass unchanged. Any test whose outcome
changes because authority moved from the candidate to `.asent/` is reported to Maryam and not edited quietly.

**5 — CAVR gate adapter** (Maryam's module). `backend/cavr/gate_adapter.py::analyze_pipeline(context, store, outdir, emit)`
has the same return shape as `analyzer.analyze`. `verify: all` → `pip install -r <file>` on head;
`changed` → `{"requirements_edit": {before, after}}` via `manifest_parser.capture_requirements_edit`.
Mapping: pipeline BLOCK→REJECTED, UNRESOLVED→UNRESOLVED. `analyzer.analyze` dispatches on `cavr.mode`.
`read_artifact(…, allow_builtin)`. `counterfactual_input` comes from config. The pipeline always gets an
explicit `project_dir`. Tests `tests/test_cavr_gate_adapter.py`, using the recorded real-wheel transport
helpers from `tests/test_cavr_support.py`: approved pin → VERIFIED; denied package → REJECTED with no download;
unpinned → UNRESOLVED; tampered bytes → REJECTED/UNRESOLVED per the pipeline rule; network off → UNRESOLVED;
only `pyproject.toml` present → UNRESOLVED "unsupported manifest"; `changed` with no edit → VERIFIED at the gate
stage; the adapter never resolves to `SAMPLE_PROJECT_DIR`; a lockfile-mode artifact under ASENT ROOT is refused
when `allow_builtin=False`.

**6 — SATRA from config** `[owner review: satra, threat_repo]`. Contract from `contract.json`;
`run_pytest(…, trusted_tests_dir, external)`, where external with no engine → unavailable; `mutate_return_true`;
`source_dirs` for bandit; required rules = contract rule_ids; oracle check only when
`project_security_tests` is set, otherwise listed in residual uncertainty. Legacy path is unchanged when
`config` is None. Tests `tests/test_satra_config.py`: no contract → INCONCLUSIVE; external + no engine →
INCONCLUSIVE; mutant target missing → INCONCLUSIVE; RETURN_TRUE operator on a temp project; trusted tests are
taken from base even when head edits `.asent/`; existing `tests/test_satra_*` stay green.

**7 — SABLE from config** `[owner review: sable]`. Loop over the obligations (any REGRESSED → REGRESSED, else any
UNKNOWN → UNKNOWN, else PRESERVED), use `terraform_dirs`, and treat `.tf` changes outside configured dirs → UNKNOWN.
Tests `tests/test_sable_config.py`: two obligations, one regressed; empty list → invalid config;
`.tf` outside dirs → UNKNOWN; the current single-obligation scenarios match `tests/test_sable_*`.

**8 — `asent gate`.** `backend/gate/{runner,report,summary}.py`; `gate` subcommand; `main(argv=None)` so tests can
call it in-process; the HTTP client only opens for server commands. Tests `tests/test_gate_cli.py` on real temp
repos: no `.asent` → 2; invalid → 2; starter → 2; head edits `.asent` → 2; unknown ref → 2 with a report still
written; not a repo → 2; denied package added in head → 1; SABLE regression (fixture infra) → 1; CAVR-only ACCEPT
with SATRA/SABLE disabled with reasons → 0 and both listed as not assessed; SATRA enabled with no engine → 2;
symlink in head → 2; hook not executed; injected internal exception → 2 + report; unwritable output dir → 2;
report SHAs equal `git rev-parse`; summary contains the decision and one row per module.

**9 — Docker + GitHub Actions.** `Dockerfile`: install the `scripts/asent` wrapper (`exec python -m backend.cli "$@"`)
into `/usr/local/bin`, keep the server CMD; `cd.yml` smoke adds `docker run IMAGE asent gate --help`.
`.github/workflows/asent-gate.yml`: `on: workflow_call` (inputs `asent-repository`, `asent-ref` (SHA),
`review-fails` default true), `permissions: contents: read`, checks out the target at `fetch-depth: 0`,
installs ASENT, builds the sandbox image, runs the gate with the PR base/head SHAs, appends the summary to
`$GITHUB_STEP_SUMMARY`, uploads both files, and maps exit 2 to fail or neutral. Copyable caller
`docs/gate/asent-pr.yml` (`on: pull_request`, never `pull_request_target`). Tests `tests/test_gate_packaging.py`
(PyYAML): workflow keys, no `pull_request_target`, read-only permissions, `asent gate` invoked with base/head
SHAs, Dockerfile installs the wrapper. Real run: one PR on a scratch repo, with its actual result in report notes.

**10 — Guard + docs.** `tests/test_gate_no_hardcoded_paths.py`: the gate-path modules (gate/*, project_config/*,
orchestrator service/workspace_manager/context_service/final_gate, cavr analyzer/gate_adapter/pipeline,
satra analyzer/pytest_runner/security_contract, sable analyzer) contain none of `demo_project`,
`sample_project`, `SAMPLE_PROJECT_DIR`, `scenarios/`, `fixtures/invoice.pdf`, `import DEMO`, except a
written allowlist with a reason per entry (demo repair, builtin host fallback). It also checks that
`run_gate` never imports `satra.settings` or `orchestrator.scenarios`. Write `docs/asent-gate.md`
(usage, exit codes, coverage table above). Link it from README.

## Overall done criterion
- `.venv/bin/python -m pytest -q`: every test that passed at step 0 still passes, plus all new tests.
- `asent init` + manual review + `asent gate` on a fresh temp repo gives each exit code 0/1/2 in the cases above,
  each time with `asent-report.json` and `asent-summary.md` written.
- The guard test passes. The demo scenarios run through `.asent/` with unchanged catalog outcomes.
- `docker run IMAGE asent gate --help` works. One real PR run of `asent-gate.yml` is recorded with its actual result.

## Verification
Step by step: the new test files above + the full suite. End to end: build a scratch repo from
`demo_project/InvoiceHub` (+ `.asent/`), commit base, make head variants (denied pin, infra regression,
`.asent` edit), run `python -m backend.cli gate --repository … --base … --head …`, and check `$?`, the JSON and
the summary. Then the same through the Docker image and one GitHub PR.
