# `.asent/`: per-project ASENT configuration

A target repository tells ASENT what to check in a folder `.asent/` at its root. The gate reads
this folder **from the base commit** of the change, never from the change itself, so a pull request
cannot loosen its own rules. If the head commit changes `.asent/`, the decision is REVIEW (or BLOCK if a
module blocks), so a maintainer has to merge that config change on purpose.

Machine-readable schemas (generated from `backend/project_config/schema.py`; a test fails if they drift):
`docs/asent-config.schema.json`, `docs/asent-satra-contract.schema.json`,
`docs/asent-sable-obligations.schema.json`. Regenerate with `python -m backend.project_config --write docs`.

## Layout

```
.asent/
  config.json              which modules apply and where their inputs are   (required)
  cavr/policy.json         CAVR dependency policy                           (when CAVR is enabled)
  satra/contract.json      SATRA security contract                          (when SATRA is enabled)
  satra/trusted_tests/     trusted pytest files, at least one test_*.py      (when SATRA is enabled)
  satra/pytest.ini         optional pytest config for the trusted tests
  sable/obligations.json   SABLE infrastructure obligations                 (when SABLE is enabled)
  README.md                anything else is allowed and is part of the config digest
```

The file locations above are the defaults; `config.json` can name others inside `.asent/`.

## `config.json`

```json
{
  "schema_version": 1,
  "project": {"name": "invoice-service"},
  "modules": {
    "CAVR":  {"enabled": true, "policy": "cavr/policy.json", "requirements_files": ["requirements.txt"], "verify": "all"},
    "SATRA": {"enabled": true, "contract": "satra/contract.json", "trusted_tests": "satra/trusted_tests",
              "source_dirs": ["app"], "project_security_tests": "tests/test_security.py"},
    "SABLE": {"enabled": false, "reason": "this service has no Terraform"}
  }
}
```

| Field | Meaning |
|---|---|
| `schema_version` | must be `1` |
| `project.name` | 1–100 characters, shown in the report |
| `modules.<M>.enabled` | `true` or `false` (JSON booleans only) |
| `modules.<M>.reason` | required, non-blank, when `enabled` is `false` |
| `_starter` | written as `true` by `asent init`; the config is refused until it is removed |
| **CAVR** `policy` | default `cavr/policy.json` |
| `requirements_files` | pip requirements files in the project, default `["requirements.txt"]`, at least one |
| `verify` | `all` (every pin in head, default) or `changed` (only the base→head edit) |
| `import_aliases` | `{distribution: [import names]}` when a wheel's import name differs from its name |
| `source_dirs` | where call sites are read; empty = whole project |
| **SATRA** `contract` | default `satra/contract.json` |
| `trusted_tests` | default `satra/trusted_tests` |
| `pytest_ini` | optional, inside `.asent/` |
| `source_dirs` | application code; empty = whole project |
| `project_security_tests` | optional; the project's own security test file, checked for a weakened oracle |
| **SABLE** `terraform_dirs` | default `["infra"]`, at least one |
| `obligations` | default `sable/obligations.json` |

CAVR always uses the M1 pipeline in a gate run. There is deliberately no field that selects the
older lockfile analyzer; it is used only by ASENT's built-in demo scenarios.

## `cavr/policy.json`

The format CAVR already uses (`backend/cavr/requirement_gate.py`, `backend/cavr/capability_contract.py`):

```json
{
  "project_task_description": "Invoice PDF text extraction",
  "allowed_scopes": ["FILE_READ:invoice_documents", "PROCESS_EXEC:none", "NETWORK_CONNECT:none"],
  "approved_requirements": ["pypdf>=5,<7"],
  "denied_packages": [{"name": "reqeusts", "reason": "typosquat of requests"}]
}
```

`approved_requirements`: `name` + version specifier, no extras, markers or URLs. `denied_packages`: objects
with a bare `name`. `allowed_scopes`: `CAPABILITY:scope` with a capability the threat repository knows,
each named once; scope `none` is a denial. `project_task_description` must be non-blank, because it
selects which threat-repository capability rules apply.

## `satra/contract.json`

```json
{
  "rule_id": "AUTHZ.IDOR.001",
  "route": "GET /invoices/{invoice_id}",
  "expected_status": 403,
  "authority_sources": ["SRS.md#FR-03"],
  "preconditions": ["authenticated normal user", "invoice owned by another user"],
  "scope": ["app/main.py", "app/security.py"],
  "counterfactual": {"operator": "RETURN_TRUE", "target": "app/security.py::can_access_invoice"}
}
```

`expected_status` is an integer 100–599; `authority_sources` and `scope` are non-empty; the only
counterfactual operator is `RETURN_TRUE` (the target function's body becomes `return True`, and the
trusted tests must fail on that mutant). Optional text fields: `subject`, `action`, `resource`,
`state_effect`, `description`.

## `sable/obligations.json`

```json
{"obligations": [{"id": "invoice-data-least-privilege", "principal": "aws_iam_role.app",
                  "protected_asset": "aws_s3_bucket.invoice_data", "actions": ["s3:GetObject", "s3:PutObject"],
                  "scope": "objects", "minimum_score": 6, "margin": 3}]}
```

At least one obligation; ids unique; `actions` non-empty; `minimum_score` and `margin` ≥ 0 (defaults 6 and 3).
Optional `terraform_dir`: the Terraform root (one of `terraform_dirs`) the obligation is about; default the first.
Each obligation must already hold on the base commit, otherwise it is UNKNOWN. The module result is the worst
obligation (REGRESSED > UNKNOWN > PRESERVED); Terraform outside `terraform_dirs` makes it UNKNOWN.

## Rules that apply to every file

- Unknown keys are refused; values are strict (`"403"` is not `403`, `"yes"` is not `true`); a JSON
  object that repeats a key is refused.
- Paths are relative, use `/`, contain no `..`, and never name `.git`; project paths never point into `.asent`.
- No symlinks anywhere in `.asent/` (nor `.asent` itself), only regular files, at most 200 files and 1 MiB.
- Files of a disabled module are not read.

## Fail-closed outcomes

`backend.project_config.load(path)` returns `valid=False` with every problem named:

| Code | Cause |
|---|---|
| `ASENT_CONFIG_MISSING` | no `.asent/` directory, or no `config.json` |
| `ASENT_CONFIG_UNSAFE` | a symlink or non-regular file |
| `ASENT_CONFIG_BUDGET` | more than 200 files or 1 MiB |
| `ASENT_CONFIG_JSON` | `config.json` not UTF-8 JSON, or a repeated key |
| `ASENT_CONFIG_SCHEMA` | `config.json` does not match the schema (including a disabled module without a reason) |
| `ASENT_CONFIG_STARTER` | unreviewed `asent init` output (`"_starter": true`) |
| `ASENT_CONFIG_FILE_MISSING` | an enabled module's file or test directory is missing |
| `ASENT_CONFIG_POLICY` / `_CONTRACT` / `_OBLIGATIONS` | that module's document is unreadable or invalid |

Any of these makes the gate decision **REVIEW**, never ACCEPT. In addition, at gate time:

- a module whose inputs exist in the project but which has **no section** gives REVIEW;
- a module that is **disabled** appears in the report and summary as
  "not assessed (disabled by base config)" with its reason, and is never shown as passed.
