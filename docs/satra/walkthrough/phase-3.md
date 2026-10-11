# Phase 3 walkthrough: AST Localizer & Security Change Contracts

Files: `backend/satra/astscan.py`, `backend/satra/diff_localizer.py`, `backend/satra/security_contract.py`, `backend/satra/cli.py`, `tests/test_satra_localize.py`.

## astscan.py

Analogy: an X-ray scanner for Python code. Instead of searching for keywords like "password" in text, it inspects the abstract syntax tree (AST) to recognize actual function boundaries, routes, parameter bindings, authorization checks, and dangerous sinks (raw SQL execution, file reads, system commands).

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `parse_source` | Safely parses code text into an AST | `ast.parse("def f(): pass")` | syntax errors crash analysis |
| `collect_functions` | Recursively finds all functions and methods with qualified paths | finds `create_app.read_invoice` | nested route handlers are missed |
| `route_of` | Detects HTTP route decorators and HTTP verbs | `@app.get("/invoices/{id}")` -> `GET /invoices/{id}` | cannot correlate code to HTTP endpoints |
| `scan_function` | Scans inside function bodies for auth guards, ownership comparisons, SQL sinks, file calls | finds `row['owner_id'] == user['id']` -> `ownership_compare` | cannot detect security-critical primitives |
| `derive_notes` | Compares baseline vs candidate scans to detect regressions | detects removal of guard -> "ownership check removed" | dropped guards are treated as normal edits |

## diff_localizer.py

Analogy: a border patrol tracking exact movement across files. Compares baseline and candidate worktrees, maps changed line spans to AST functions, handles deletions and renames, and isolates test changes from application code changes.

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `is_test_file` | Distinguishes application code from test files | `tests/test_security.py` -> `True` | test modifications are mistaken for app vulnerabilities |
| `localize_change_set` | Compares AST nodes between baseline and candidate | `scenario/idor-bypass` -> `read_invoice` with regression note | no region mapping for contracts |

## security_contract.py

Analogy: the legal binding contract. Connects localized regions and vulnerability families to trusted policy obligations from `policy.json` and requirements in `SRS.md`.

| Function | What it does | Worked example | Breaks if deleted |
|---|---|---|---|
| `derive_contracts_for_regions` | Produces formal Security Change Contracts (`SCC-...`) | produces `SCC-AUTHZ.IDOR.001-...` with `POL-INV-READ` & `SRS-01` | contracts cannot be verified against trusted policy |
| `build` | Backward-compatible builder for orchestrator | creates default IDOR contract | orchestrator integration breaks |

## Real CLI Worked Output
Running `python -m backend.satra.cli localize --sha <sha>`:
- `scenario/idor-bypass`: `APPLICABLE`, regions: `read_invoice`, note: `ownership check removed`, contract: `AUTHZ.IDOR.001`
- `scenario/sqli-fstring`: `APPLICABLE`, regions: `search_invoices`, note: `sql statement became string-built`, contract: `INJ.SQL.001`
- `scenario/path-traversal`: `APPLICABLE`, regions: `read_file`, note: `path containment check removed`, contract: `PATH.TRAV.001`
- `scenario/docs-only`: `NOT_APPLICABLE`, regions: 0, contracts: 0
