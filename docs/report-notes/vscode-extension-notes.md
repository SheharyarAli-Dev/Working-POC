# ASENT VS Code extension report notes (`vscode-asent/`)

Branch `asent-vscode-extension`, work of 2026-11-21. Not CAVR work, so these notes are kept here and not in
`cavr-report-notes.md`. Commits are local; nothing is pushed. Before each commit the extension's unit tests
were run on exactly the staged tree (a scratch checkout of the index with `node_modules` linked), and
`.venv/bin/python -m pytest -q` was run on the working tree (the Python suite does not read `vscode-asent/`).

Requirements below are the items of the task request (labelled V1–V15); they are not FR/NFR IDs from the
SRS, which has none for the editor extension.

- V1 commands: Init project, Run gate on this branch, Show report, Doctor, Open web dashboard
- V2 dashboard panel: webview with strict CSP, no remote scripts or fonts; ACCEPT/REVIEW/BLOCK banner; CAVR, SATRA-RV, SABLE cards (status, reason, key evidence); base/head commits and config digest from `asent-report.json`; follows light/dark themes
- V3 status bar item with the last gate result; click opens the panel
- V4 findings in the Problems tab at the file and line the report gives
- V5 asent or Docker missing: a clear message with `asent doctor`'s fix lines
- V6 settings: asent path (default `asent`), base branch (default: the repository's default branch)
- V7 tests: unit tests on real reports (ACCEPT, CAVR BLOCK, SATRA BLOCK, REVIEW) and an `@vscode/test-electron` extension test
- V8 CI workflow: tests and a `.vsix` artifact; README section on installing from the VSIX
- V9 only the installed asent CLI's `--json` outputs; no re-implemented checks, no stored tokens, no data sent anywhere, argument array never a shell string
- V10 `"extensionKind": ["workspace"]`
- V11 Workspace Trust: untrusted folder -> Run gate, Init, Dashboard disabled with a clear message; Show report allowed
- V12 activation only for a folder with `.asent/` or `asent-report.json`, or when a command runs
- V13 one gate run and one dashboard process at a time; a second click says it is already running
- V14 manual-only fixtures workflow (workflow_dispatch, read-only) that produces the SATRA BLOCK fixture with Docker
- V15 workflows pin actions like the existing ones (`@v4`/`@v5` tags) and use `permissions: contents: read`

## Step 1 — Scaffold and manifest (2026-11-21)

Commit `chore(vscode): scaffold vscode-asent with its manifest`.
Unit tests on the staged tree: 7 passing. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | What it is |
|---|---|
| `vscode-asent/package.json` | Manifest: five commands, two settings, `extensionKind: ["workspace"]`, `activationEvents` (`workspaceContains:.asent/**`, `workspaceContains:asent-report.json`), `capabilities.untrustedWorkspaces` (`limited`, `asent.path` and `asent.baseBranch` restricted), npm scripts, exact-pinned dev dependencies, no runtime dependencies. |
| `vscode-asent/package-lock.json` | Lockfile from `npm install` (304 packages, all dev). |
| `vscode-asent/tsconfig.json` | Strict TypeScript, CommonJS, `src/` and `test/` compiled to `out/`. |
| `vscode-asent/.mocharc.json` | Unit tests: `out/test/unit/**/*.test.js`. |
| `vscode-asent/.gitignore`, `.vscodeignore` | Keep `node_modules/`, `out/`, `.vscode-test/`, `*.vsix` out of git; only `out/src/**`, `package.json`, `README.md` go into the `.vsix` (no tests, no stub, no fixtures, no source maps). |
| `vscode-asent/test/unit/manifest.test.ts` | 7 tests on `package.json` (below). |

Commands get `onCommand` activation implicitly (VS Code >= 1.74, engine `^1.95.0`), so `activationEvents` lists
only the two folder conditions.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| `asent.path` is a restricted configuration in untrusted folders | Trust the workspace value | A cloned repository's `.vscode/settings.json` could otherwise point `asent.path` at a script inside the repository. VS Code then uses only the user/machine value. |
| `asent.baseBranch` default `""` = let asent choose | Detect the default branch in the extension | `asent gate` already picks origin/HEAD, else `main`, else `master` (`backend/gate/defaults.py`); doing it again in TypeScript would be a second implementation that can disagree. |
| Commands always run, trust is checked in code | `"enablement": "isWorkspaceTrusted"` on commands | Enablement only greys the command out; V11 asks for a clear message. |
| Exact versions, no runtime dependencies | Ranges; bundling with esbuild | Reproducible lockfile; the `.vsix` contains only this extension's compiled code. Versions are 2024 releases (TypeScript 5.6.3, mocha 10.8.2, @vscode/test-electron 2.4.1, @vscode/vsce 3.2.1, @types/vscode 1.95.0). |
| `vsce package --skip-license` | Add a LICENSE file | The repository has no LICENSE file (README §7 names MIT but the file does not exist); writing one would name a copyright holder, which is the team's decision. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V1 | `manifest.test.ts`: exactly the five command IDs with the requested titles. |
| V6 | `asent.path` default `asent`, `asent.baseBranch` default `""`. |
| V10 | `extensionKind` is `["workspace"]`. |
| V11 | `untrustedWorkspaces.supported` is `limited` with both settings restricted. |
| V12 | `activationEvents` is exactly the two `workspaceContains` entries. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-M1 | Command contract | `contributes.commands` | 5 IDs/titles exactly | pass |
| VS-M2 | Settings | `contributes.configuration` | 2 keys, defaults `asent` / `""` | pass |
| VS-M3 | Runs where asent is | `extensionKind` | `["workspace"]` | pass |
| VS-M4 | Activation | `activationEvents` | only the two `workspaceContains` | pass |
| VS-M5 | Trust | `capabilities.untrustedWorkspaces` | `limited`, both settings restricted | pass |
| VS-M6 | Pinning | all dependencies | exact `x.y.z` | pass |
| VS-M7 | Nothing extra shipped | `dependencies` | empty | pass |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- `main` points at `out/src/extension.js`, which exists from step 8 on.

### Tool disclosure (Ch 8.7)

Claude Code wrote the files in this step. Maryam set the requirements and the trust, activation and
extensionKind decisions. Verified by `npm test` (7 passing) and the full Python suite.

### Supervisor Q&A prep

- *Why is `asent.path` restricted?* A repository's own settings file must not choose which program the extension runs before you trust that repository.
- *Why no `onCommand` events?* VS Code adds them for contributed commands since 1.74; listing them again changes nothing.

## Step 2 — Real asent fixtures and their generator (2026-11-21)

Commit `test(vscode): real asent output fixtures and their generator`.
Unit tests on the staged tree: 7 passing (the fixtures are used from step 3 on). Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | What it does |
|---|---|
| `vscode-asent/scripts/make_fixtures.py` | Builds throwaway git repositories with real base/head commits (`tests/gate_support.py`: `GateRepo`, `cavr_files`, `recorded_pypi`, `run_cli`) and runs the real CLI (`backend.cli.main`). Scenarios: `accept`, `cavr-block`, `review`, `sable-block`, `satra-block` (Docker), `doctor`, `init`, `dashboard`. `_expect` refuses to write a report whose decision or module result is not the one its name says. |
| `vscode-asent/test/fixtures/reports/{accept,cavr-block,review,sable-block}.json` | Real `asent gate --json` reports. |
| `vscode-asent/test/fixtures/{doctor,init,dashboard}/*.json` | Real `doctor --json` (Docker missing on this machine), `init --json`, and the line `dashboard --json` prints (`dashboard.info(8000)`, server not started). |
| `vscode-asent/test/fixtures/README.md` | What each file is and how it was made. |

Key algorithm: for each scenario, `pytest.MonkeyPatch.context()` injects the recorded real PyPI/OSV answers
exactly as the gate tests do, the scenario commits base and head, runs `run_cli`, checks the decision with
`_expect`, and only then writes the JSON. `satra-block` raises `ScenarioError` without Docker and writes nothing.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Fixtures from real CLI runs, checked by `_expect` | Hand-written JSON | CLAUDE.md rule: no fixture-faked results. A first exploratory REVIEW attempt (head replacing `.asent/cavr/policy.json` with `{}`) actually gave BLOCK, which is why the generator checks the decision before writing. |
| REVIEW scenario = head edits `.asent/` | Unreviewed starter | Shows a REVIEW banner while CAVR's own card is `pass`, the case most likely to confuse a user. |
| Extra `sable-block` scenario | Only the four requested | Without it the SABLE card's evidence would be tested against no real data. Needs no Docker. |
| SATRA BLOCK generated by a manual workflow | Hand-made report; Docker in the extension CI | Maryam's choice: no fake fixture, no Docker/Python in the normal extension CI. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V7 | Real ACCEPT, CAVR BLOCK and REVIEW reports exist; SATRA BLOCK has a generator scenario that refuses to run without Docker (`satra-block: NOT WRITTEN: Docker is not installed ...`, exit 1). |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-F1 | Generator writes real reports | `make_fixtures.py` | 7 files, decisions ACCEPT/BLOCK/REVIEW/BLOCK | pass |
| VS-F2 | SATRA without Docker | `--only satra-block` | nothing written, exit 1, reason printed | pass |

### Defects found and fixed

- The first REVIEW scenario gave BLOCK (see design decisions); the generator now verifies every decision.

### Known limitations / deferred

- `satra-block.json` is not committed yet: it is produced by the manual workflow of step 10.
- Paths inside the fixtures (`/tmp/asent-fixture-…`, `/home/dell/Working-POC`) are those of this machine.

### Tool disclosure (Ch 8.7)

Claude Code wrote the generator and ran it; Maryam chose the SATRA approach. Verified by running the generator
(all scenarios checked by `_expect`) and inspecting each report's decision and module rows.

### Supervisor Q&A prep

- *Are the fixtures real?* Yes: each is the output of the real `asent` CLI on a real git repository; only PyPI/OSV answers are the recorded real responses the project's own gate tests use.
- *Why is SATRA BLOCK missing?* SATRA runs tests in Docker, which this machine does not have; the manual workflow produces it on a GitHub runner.

## Step 3 — Read gate reports (2026-11-21)

Commit `feat(vscode): read asent gate reports`.
Unit tests on the staged tree: 22 passing, 1 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/report.ts` | `parseReport(text)`, `fromJson(value)` | Refuses anything that is not schema `asent.gate.v1` with one of ACCEPT/REVIEW/BLOCK, both `base`/`head` objects and all three module rows (`ReportError`). Returns decision, exit code, commits, config digest/source/changed-in-head/problems, reasons, three `ModuleCard`s and CAVR `Finding`s. Wrong-typed fields become `null`/empty, never a guess. |
| | `EVIDENCE.CAVR/SATRA/SABLE` | Key evidence lines from the module's own evidence record (`assurance.evidence[evidence_id]`): CAVR pipeline entries and packages with SHA-256; SATRA findings, counterfactual, test-run counts (`backend/satra/gate_mode.py` fields); SABLE obligation status, successor, `projected_authorization.holds`, unexpected resources. At most 12 lines per card. |
| | `cavrFindings` | Problems entries: every CAVR pipeline entry not VERIFIED at its `file` (no line), and for every package not VERIFIED each `contract.call_sites` entry (file + 1-based line). REJECTED → error, anything else → warning. |
| `test/unit/fixtures.ts` | | Loads `test/fixtures`. |
| `test/unit/report.test.ts` | | 16 tests (one skipped until `satra-block.json` exists). |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Copy decision/results/reasons, never compute | Recompute pass/block from statuses | V9: no re-implemented checks; `backend/gate/summary.py` already decides each row. |
| Unknown decision → error | Map unknown text to REVIEW | Showing REVIEW for something asent did not say would still be a claim; the user gets "not an ASENT gate report". |
| Problems only for CAVR | Also SATRA/SABLE via `affected_files` | The real SATRA/SABLE gate evidence names tests and Terraform resources, not finding locations; `affected_files` lists changed files, not where a problem is. |
| Call-site test uses a derived input | A real rejected-and-called package | No recorded real run rejects a package the project calls; the test takes the real ACCEPT report and changes only the status fields, and says so in a comment. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V2 | Cards, commits, digest extracted from real reports (`report.test.ts`). |
| V4 | CAVR BLOCK → one finding at `requirements.txt`, no line. |
| V7 | ACCEPT, CAVR BLOCK, REVIEW parsed from real reports; SATRA BLOCK test present and skipped with its reason. |
| V9 | Values copied from the report; refusal tests for every malformed shape. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-R1 | ACCEPT | `accept.json` | ACCEPT, exit 0, digest 64 hex, CAVR pass, SATRA/SABLE not assessed, no findings | pass |
| VS-R2 | CAVR evidence | `accept.json` | `pypdf==6.19.0: VERIFIED, sha256 7e5d6e730e7d` | pass |
| VS-R3 | CAVR BLOCK | `cavr-block.json` | BLOCK, exit 1, DENYLIST evidence, one finding at `requirements.txt` line null | pass |
| VS-R4 | REVIEW | `review.json` | REVIEW, exit 2, config changed in head, CAVR pass | pass |
| VS-R5 | SABLE BLOCK | `sable-block.json` | REGRESSED, successor, unexpected resource, no findings | pass |
| VS-R6 | SATRA BLOCK | `satra-block.json` | REJECT, failing test, candidate counts | skipped (fixture needs Docker) |
| VS-R7–R13 | Refusals | bad JSON, non-object, doctor schema, unknown decision, missing module, missing base, odd types | `ReportError` / nulls | pass |
| VS-R14 | Call sites | derived from `accept.json` | requirements.txt + lines 7 and 8 | pass |
| VS-R15 | UNRESOLVED | derived from `cavr-block.json` | warning | pass |
| VS-R16 | Bad locations | file not a string, line 0 / 2.5 / empty file | dropped or file-level | pass |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- SATRA's evidence lines are written against `gate_mode.py`'s field names; VS-R6 checks them once the real fixture is committed.

### Tool disclosure (Ch 8.7)

Claude Code wrote the parser and tests. Maryam reviewed the field choices. Verified by `npm test`.

### Supervisor Q&A prep

- *Could the extension show ACCEPT for a report that is not ACCEPT?* No. The decision is copied, and any value other than the three is refused.
- *Why do SATRA/SABLE not appear in Problems?* Their gate reports contain no project file and line; inventing a location would be a fabricated result.

## Step 4 — Start asent with an argument array (2026-11-21)

Commit `feat(vscode): run asent with an argument array and read its JSON`.
Unit tests on the staged tree: 38 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Real CLI check: `ASENT_REAL=../scripts/asent ASENT_PYTHON=../.venv/bin/python npx mocha --grep "real asent"`: 5 passing.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/args.ts` | `gateArgs`, `reportArgs`, `initArgs`, `doctorArgs`, `dashboardArgs`, `reportFile` | The argument lists, each value as one `--name=value` element. Empty base → no `--base`. |
| `src/cli.ts` | `runAsent(path, args, {cwd, env, timeoutMs, signal})` | `spawn(path, args, {shell: false})`; stdout parsed as one JSON document; any exit code is a result. Errors: `AsentNotFound` (ENOENT/EACCES/ENOTDIR), `AsentOutputError` (no JSON; carries exit code and stderr tail), `AsentCancelled` (cancel or timeout: SIGTERM, then SIGKILL after 3 s). Args with NUL refused before spawning; stdout capped at 64 MB. |
| | `startDashboard` | Starts `asent dashboard --json`, resolves on its first line (`{"url", ...}`) and leaves it serving; an `{"error": ...}` document (port in use) or an early exit rejects. |
| `test/stub/asent` | | Test-only stand-in for the CLI: replays the real fixtures, writes/reads `asent-report.json` like the real `gate`/`report`, logs argv. Never shipped (`.vscodeignore`). |
| `test/unit/cli.test.ts` | | Argument lists, stub runs, and 5 tests against the real CLI when `ASENT_REAL` is set. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| `--name=value` form | `--name value` | With `=`, argparse takes the value as-is, so a base branch like `--repository=/etc` cannot become another option; asent then refuses it as a ref (REVIEW). |
| `--output-dir=<folder>` on gate | Let asent write to the repository top level | The panel, `report --file=` and the file watcher all look in the workspace folder. |
| `report --file=<path>` | `asent report` default lookup | The default lookup runs git in the folder; `--file` only reads the file, which matters in untrusted folders. |
| Non-zero exit is a result | Treat exit ≠ 0 as failure | gate exits 1 (BLOCK) / 2 (REVIEW), doctor 1 (not ready), all with valid JSON. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V5 | Missing executable → `AsentNotFound` with the configured path. |
| V9 | Shell metacharacters arrive literally; a would-be `echo hacked > x` creates no file. |
| V13 | Cancellation/timeout kill the process (used by the one-gate-at-a-time logic in step 8). |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-C1–C4 | Argument lists | folders with spaces, `;`, `$(id)`; base `--repository=/etc` | one element each, `--base=--repository=/etc` | pass |
| VS-C5 | No shell | folder `a b; echo hacked > x $(id)` | argv logged unchanged, no `x` created | pass |
| VS-C6 | BLOCK is a result | stub gate `cavr-block.json` | exit 1, JSON equals fixture, cwd = folder | pass |
| VS-C7 | Doctor not ready | stub doctor | exit 1, `ready: false` | pass |
| VS-C8/C9 | Not found / not executable | missing path, name not on PATH, plain file | `AsentNotFound` (ENOENT / EACCES) | pass |
| VS-C10 | No JSON | traceback on stdout; crash on stderr | `AsentOutputError` with exit 2 / stderr text | pass |
| VS-C11/C12 | Cancel / timeout | hanging stub | `AsentCancelled` within 5 s | pass |
| VS-C13 | NUL byte | `--file=a\0b` | refused, stub never started | pass |
| VS-C14–C16 | Dashboard | stub dashboard; busy port; missing | URL line + still running; asent's port message; `AsentNotFound` | pass |
| VS-C17–C21 | Real CLI (`ASENT_REAL`) | `doctor`, `report --file=` (real and missing), `gate --output-dir= --base=main` on a repo without `.asent/`, `init --repository=` | schema `asent.doctor.v1`; report equal; `No ASENT report at`; REVIEW with `ASENT_CONFIG_MISSING` and the file written; starter written | pass (run locally; skipped in CI) |

### Defects found and fixed

- The real `dashboard --json` prints its error as an indented multi-line document, but success as one line; reading only the first line would have shown "printed no JSON" instead of asent's "port … already in use". `startDashboard` now tries the first line, then the whole buffer, and again on exit (VS-C15).

### Known limitations / deferred

- The stub is a test double of the CLI contract; the real CLI is checked by VS-C17–C21 only when `ASENT_REAL` is set.

### Tool disclosure (Ch 8.7)

Claude Code wrote the runner, stub and tests. Verified by `npm test` and by the real-CLI tests against `scripts/asent`.

### Supervisor Q&A prep

- *How do you know there is no command injection?* `shell: false` with an array (static test in step 8), and VS-C5 shows a shell payload in a folder name arriving as plain text.
- *Why a stub instead of the real CLI in CI?* The real gate needs Python, ASENT's dependencies and for SATRA Docker; the stub replays real outputs, and the real CLI is checked separately with `ASENT_REAL`.

## Step 5 — Doctor and "asent not found" messages (2026-11-21)

Commit `feat(vscode): doctor fix lines and the asent-not-found message`.
Unit tests on the staged tree: 43 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/doctor.ts` | `readDoctor` | Accepts only schema `asent.doctor.v1` with boolean `ready` and a `checks` list; keeps the checks that are not `ok`, required first. |
| | `doctorLines` | First line ready / not ready with the count of required problems, then per check `MARK label: detail` and `fix: <asent's fix>` copied unchanged. |
| | `dockerMissing` | True when check `docker` or `docker-daemon` is not ok. |
| | `notFoundLines`, `INSTALL_LINES` | asent not found: the configured path, the install commands of README §4.0, and the `asent.path` setting. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Fix text copied from doctor | Extension's own advice | V5 asks for doctor's fix lines; doctor knows the installed package's Dockerfile paths. |
| Install lines from README §4.0 | A URL only | The same commands the project documents, so the two cannot disagree silently (the test names the pipx line). |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V5 | Real not-ready doctor output → Docker, daemon and both images listed with their exact fix lines. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-D1 | Not ready | `doctor.json` (real, no Docker) | 5 problems, Docker fix `Install Docker: https://docs.docker.com/get-docker/`, `dockerMissing` | pass |
| VS-D2 | Lines | same | header with 4 required, every fix line present, required before optional | pass |
| VS-D3 | Ready | derived: only the ok checks, `ready: true` | no problems, "ready" line | pass |
| VS-D4 | Refusal | null, array, string, gate schema, bad `ready`, bad `checks` | `DoctorError` | pass |
| VS-D5 | Not found | `/opt/bin/asent` | path, both install lines, `asent.path` | pass |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- VS-D3 is a derived input (the real output with its failing checks removed); a real "ready" output comes from the manual fixtures workflow (it also runs `doctor` on a runner with Docker).

### Tool disclosure (Ch 8.7)

Claude Code wrote the module and tests. Verified by `npm test`.

### Supervisor Q&A prep

- *Does the extension install Docker or build images?* No; it shows the commands doctor prints, and doctor itself only looks.

## Step 6 — Report panel HTML (2026-11-21)

Commit `feat(vscode): report panel HTML with a strict CSP and no scripts`.
Unit tests on the staged tree: 51 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/html.ts` | `renderPanel(report, {nonce, message})` | Banner (decision, exit code, time, ASENT version, reasons), three cards (result chip, status, reason, evidence), commit/config block, bounded-claim note. Without a report: only the message. |
| | `csp(nonce)` | `default-src 'none'; style-src 'nonce-…'; img-src 'none'; font-src 'none'; script-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'`. |
| | `escapeHtml` | `& < > " '` escaped for every report value. |
| | `STYLE` | Only `var(--vscode-…)` colours and fonts. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| No script at all | A nonce'd script for interactivity | Nothing in V2 needs interaction; with `script-src 'none'` a report value can never execute even if escaping had a bug. |
| Theme variables only | Own light/dark palettes | Follows every theme, including high contrast, with no theme detection code. |
| Nonce must be base64 | Trust the caller | It is placed inside the CSP; a bad value could widen it. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V2 | Banner per decision, three cards with CAVR/SATRA-RV/SABLE titles, base/head SHA and config digest present; CSP meta exact; no `<script`, no `src=`/`href=`, no `@import`/`url(`; colours only from theme variables. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-H1 | CSP / no scripts / no resources | all four real reports | exact CSP, one nonce'd `<style>`, no script, handlers, links, imports | pass |
| VS-H2 | Theme | `accept.json` | no literal colours outside `var(--vscode-…)` | pass |
| VS-H3 | ACCEPT content | `accept.json` | banner, three titles, both SHAs, digest, evidence line | pass |
| VS-H4 | BLOCK / REVIEW | real reports | banner classes, "Config changed in head: yes" | pass |
| VS-H5 | Injection | derived: `<script>` reason, `<img onerror>` module reason | escaped text only | pass |
| VS-H6 | escapeHtml | `<a href="x">'&'</a>` | all five escaped | pass |
| VS-H7 | No report | message with `<here>` | escaped message, no banner | pass |
| VS-H8 | Bad nonce | `x'; script-src *` | refused | pass |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- The look in light and dark themes is checked by the theme-variable test, not by screenshots.

### Tool disclosure (Ch 8.7)

Claude Code wrote the renderer and tests. Verified by `npm test`.

### Supervisor Q&A prep

- *What if a report contains HTML?* It is escaped (VS-H5), and even unescaped it could not run: the CSP allows no script.

## Step 7 — Problems locations (2026-11-21)

Commit `feat(vscode): place report findings in the Problems tab`.
Unit tests on the staged tree: 56 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/diagnostics.ts` | `diagnosticRoot(folder, repository)` | The report's paths are relative to the gated repository's top level: use `repository` when it is absolute and contains the folder, else the folder (a report from another machine). |
| | `locate(findings, folder, repository)` | Absolute 0-based locations; null line → line 0 with "(file-level: the report gives no line)"; absolute paths, Windows drive paths, NUL, empty names and anything resolving outside the root dropped. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Drop paths outside the root | Show them anyway | A report is input; it must not place markers on arbitrary files such as `/etc/passwd`. |
| File-level entry on line 1 with a note | Skip findings without a line | The report does name the file (e.g. `requirements.txt`); the note keeps it honest that no line was given. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V4 | Real CAVR BLOCK → `requirements.txt` line 0 (shown as 1), message says the report gives no line; a 1-based line 7 → 0-based 6. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-P1 | Real CAVR BLOCK | `cavr-block.json` | one error at `requirements.txt` line 0 with the note | pass |
| VS-P2 | Line conversion | line 7 | 6, message unchanged | pass |
| VS-P3 | Escapes | `../`, `a/../../`, `/etc/passwd`, `C:\x.txt`, NUL, empty | none | pass |
| VS-P4 | Folder inside repository | folder `/w/repo/sub`, repo `/w/repo` | root `/w/repo` | pass |
| VS-P5 | Report from elsewhere | `/tmp/...`, null, relative | root = folder | pass |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- Only CAVR produces Problems entries (see step 3).

### Tool disclosure (Ch 8.7)

Claude Code wrote the module and tests. Verified by `npm test`.

### Supervisor Q&A prep

- *Can a malicious report mark files outside the project?* No; anything resolving outside the root is dropped (VS-P3).

## Step 8 — Commands, status bar, panel and Workspace Trust (2026-11-21)

Commit `feat(vscode): commands, status bar, report panel and workspace trust`.
Unit tests on the staged tree: 62 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/extension.ts` | `activate` | Output channel, diagnostic collection, status bar item (click → Show report), the five commands, a watcher on `<folder>/asent-report.json` (300 ms debounce; not while a gate runs), and an initial silent `report --json` if the file exists. Returns a read-only `state()` for the extension test. |
| | `runGate` | Trusted folder only; one run at a time (`gateRunning`); cancellable progress; 30-min timeout; status `gate running`; then Problems, status, panel and a notification per decision; `warnIfDockerMissing`. |
| | `warnIfDockerMissing` | Only when the report says neither Docker nor Podman was available and SATRA was not disabled/not applicable: runs `doctor --json` and, if Docker is missing, a warning with doctor's fix lines in the ASENT output. |
| | `showReport` / `loadReport` | `report --json --file=`; asent's `{"error"}` text is shown in the panel; allowed in untrusted folders. |
| | `doctor` | `doctor --json` in the home directory; lines in the ASENT output. |
| | `initProject` | Trusted only; `init --json --repository=`; asent's error or the starter message. |
| | `openDashboard` | Trusted only; one process (`dashboard`/`dashboardStarting`); opens the URL only if it matches `^http://127\.0\.0\.1:\d{1,5}/$`; stopped on deactivate. |
| | `reportError` | `AsentNotFound` → error with install lines and "Open settings"; `AsentOutputError` → stderr in output and "Run Doctor"; `AsentCancelled` → warning. |
| `src/panel.ts` | `ReportPanel` | One webview: `enableScripts: false`, `enableCommandUris: false`, `enableForms: false`, `localResourceRoots: []`; a fresh 16-byte nonce per render. |
| `test/unit/security.test.ts` | | Static checks over `src/` (below). |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Trust check in code with a "Manage Workspace Trust" button | Disable via `enablement` | V11 asks for a clear message. |
| Doctor allowed in untrusted folders | Refuse | It checks the machine, not the folder, and runs in the home directory. |
| Docker warning only when SATRA could have run | After every REVIEW | On a machine without Docker every CAVR-only gate would otherwise warn about something irrelevant. |
| Notifications with buttons are not awaited | `await` the choice | Awaiting keeps the command pending until a click. |
| Open only a 127.0.0.1 URL | Open whatever asent prints | V9: the extension itself never sends anything anywhere; the dashboard is local only by design (`backend/commands/dashboard.py`). |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V1, V3, V5, V11, V13 | Implemented here; exercised in a real VS Code by the step 9 extension test. |
| V9 | `security.test.ts`: no shell, `spawn` only in `cli.ts`, no network modules or `fetch`, no `SecretStorage`/`globalState`/`workspaceState`/`.update(`, no `enableScripts: true`/messages, one `openExternal` guarded by the 127.0.0.1 pattern. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-S1 | Module list | `src/` | the 8 modules | pass |
| VS-S2 | Processes | all of `src/` | no `shell: true`, no exec/fork; `child_process` only in `cli.ts` | pass |
| VS-S3 | No network | all of `src/` | no http/https/net/tls/dgram/undici, no fetch/WebSocket | pass |
| VS-S4 | Stores nothing | all of `src/` | no secrets/state/config writes | pass |
| VS-S5 | Webview | `panel.ts` | scripts, command URIs off; no local roots; no messages | pass |
| VS-S6 | One URL | `extension.ts` | one `openExternal`, 127.0.0.1 pattern | pass |

### Defects found and fixed

- First version awaited `showErrorMessage(..., "Show details")` and similar; the command stayed pending until the user clicked, which would also hang the extension test. Changed to `.then(...)`.

### Known limitations / deferred

- The file watcher covers the folder that was current at activation; other folders of a multi-root workspace update when a command runs.
- The dashboard has no "stop" command; it stops when the window closes.

### Tool disclosure (Ch 8.7)

Claude Code wrote `extension.ts`, `panel.ts` and the security test. Verified by `npm test`; the behaviour in VS Code is verified by step 9.

### Supervisor Q&A prep

- *What can an untrusted repository make the extension do?* Read its own `asent-report.json` with the user's asent; Init, Run gate and the dashboard refuse before starting anything, and its settings cannot change `asent.path`.
- *Why is the status bar not stored between sessions?* Nothing is stored; on activation it is read again from `asent-report.json`.

## Step 9 — Extension test in a real VS Code (2026-11-21)

Commit `test(vscode): extension test with @vscode/test-electron`.
Unit tests on the staged tree: 63 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Extension test: **not run on this machine** (the downloaded VS Code needs `libnspr4.so` and other libraries that are not installed; installing them needs sudo). It runs in the CI workflow of step 10.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | What it does |
|---|---|
| `test/extension/runTest.ts` | Runs VS Code 1.95.3 twice: (1) trusted (`--disable-workspace-trust`), `asent.path` = stub in workspace settings; (2) untrusted (trust on, no prompt), workspace `asent.path` = a nonexistent path, user `asent.path` = stub, a real `cavr-block.json` as `asent-report.json`. |
| `test/extension/suite/index.ts` | Mocha in the extension host; `ASENT_SUITE` picks the file. |
| `test/extension/suite/helpers.ts` | Stub argv log, stub control file, `until` polling. |
| `test/extension/suite/trusted.test.ts` | 11 tests (below). |
| `test/extension/suite/untrusted.test.ts` | 3 tests (below). |
| `test/stub/asent` | `ASENT_STUB_CONTROL` file to switch scenarios without restarting VS Code. |
| `test/unit/manifest.test.ts` | New test: the pinned VS Code version matches the minimum in `engines` and `@types/vscode`. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Pin VS Code 1.95.3 | Default `stable` (it downloaded 1.147.0) | Tests the oldest version the manifest allows and does not drift. |
| Untrusted run with a bogus workspace `asent.path` | Same settings as trusted | If VS Code used the workspace value, Show report would fail; it passing shows the restriction works. |

### Requirements covered

| Req | Acceptance check (in VS Code) |
|---|---|
| V1 | All five commands registered. |
| V3 | Status bar `$(shield) ASENT: BLOCK` after a BLOCK gate; `gate running` during a run; updates from a file written outside the extension. |
| V4 | `requirements.txt` has one Error diagnostic on line 0 from source ASENT; cleared after a REVIEW report. |
| V6 | `asent.baseBranch = develop` → `--base=develop`. |
| V11 | Untrusted: no gate/init/dashboard call is made; Show report works with the user's asent. |
| V12 | Activates with no command because the folder has `.asent/`; no asent call before a command. |
| V13 | Second gate during a run and second dashboard click start nothing. |

### Ch 7 Test cases

| Test ID | Purpose | Expected | Result |
|---|---|---|---|
| VS-E1 | Activation by `.asent/` | active, no asent call, status `$(shield) ASENT` | not run locally (CI) |
| VS-E2 | Commands | five registered | not run locally (CI) |
| VS-E3 | Gate BLOCK | argv, cwd, status, diagnostic, panel CSP | not run locally (CI) |
| VS-E4 | One gate | one call for two clicks | not run locally (CI) |
| VS-E5 | Base setting | `--base=develop` | not run locally (CI) |
| VS-E6 | Show report | `report --json --file=` | not run locally (CI) |
| VS-E7 | Watcher | BLOCK after the file changes | not run locally (CI) |
| VS-E8 | Doctor cwd | home directory | not run locally (CI) |
| VS-E9 | Init argv | `--repository=<folder>` | not run locally (CI) |
| VS-E10 | One dashboard | one process for two clicks | not run locally (CI) |
| VS-E11 | asent missing | command returns, no call | not run locally (CI) |
| VS-E12–E14 | Untrusted | not trusted; report shown via user path; gate/init/dashboard refused | not run locally (CI) |

### Defects found and fixed

- `runTests` without a version downloaded the latest stable (1.147.0); pinned to 1.95.3 with a check in `manifest.test.ts`.

### Known limitations / deferred

- The results of VS-E1–E14 are known only after the first CI run of step 10.
- The dashboard test lets the extension call `openExternal` on the stub's `http://127.0.0.1:8000/`; on a headless runner nothing is listening.

### Tool disclosure (Ch 8.7)

Claude Code wrote the extension test. It compiles; it has not been run yet (see above).

### Supervisor Q&A prep

- *How is Workspace Trust tested?* A second VS Code run with trust enabled and the folder untrusted; the stub's argv log proves no gate, init or dashboard was started.

## Step 10 — CI workflow, VSIX artifact and the manual fixtures workflow (2026-11-21)

Commit `ci(vscode): test and package workflow, manual SATRA fixture workflow`.
Unit tests on the staged tree: 63 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Local packaging: `npm run package` → `asent-vscode.vsix` (12 files, 22.05 KB); the CI content check passes on it.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | What it does |
|---|---|
| `.github/workflows/vscode-asent.yml` | On push/PR touching `vscode-asent/**` (and manual): `npm ci`, `npm test`, `xvfb-run -a npm run test:extension`, `npm run package`, a check that the `.vsix` contains only `out/src/*.js`, `package.json`, `readme.md` and the two VSIX metadata files, and upload as artifact `asent-vscode-vsix`. `permissions: contents: read`, `persist-credentials: false`, actions pinned `@v4` like the existing workflows. No Python, no Docker. |
| `.github/workflows/vscode-asent-fixtures.yml` | `workflow_dispatch` only, `contents: read`: Python 3.12 + `requirements.lock.txt`, `scripts/satra_build_sandbox.sh`, checks Docker and both images, `make_fixtures.py --only satra-block doctor`, uploads artifact `vscode-asent-fixtures`. Commits nothing. |
| `vscode-asent/.vscodeignore` | Re-includes only `out/src/*.js`, `package.json`, `README.md`, `LICENSE`. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Fixtures workflow uploads, never commits | Commit from the workflow | Maryam's choice; read-only permissions; she reviews the file before it enters the repository. |
| Tag pins (`@v4`, `@v5`) | Commit SHAs | V15: the same way the existing workflows pin. |
| VSIX content check in CI | Trust `.vscodeignore` | The ignore file already had one wrong rule (below). |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V8 | Workflow runs both test kinds and uploads the `.vsix`. |
| V14 | Manual-only, read-only, uploads `satra-block.json`. |
| V15 | `@v4`/`@v5` pins and `permissions: contents: read` in both. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-K1 | VSIX contents | local `npm run package` | 12 entries, only the allowed ones | pass |
| VS-K2 | CI run | push of this branch | all steps green | not run (nothing is pushed) |

### Defects found and fixed

- `.vscodeignore` had `!out/src/**` and then `out/src/**/*.map`; vsce applies `!` re-includes after all excludes, so the source maps were still packaged (`vsce ls` listed 8 `.map` files). Now only `!out/src/*.js` is re-included, and CI checks the contents.

### Known limitations / deferred

- Neither workflow has run yet; the branch is not pushed.

### Tool disclosure (Ch 8.7)

Claude Code wrote both workflows and fixed `.vscodeignore`. Verified locally by `vsce ls`, `npm run package` and the same content check as CI.

### Supervisor Q&A prep

- *Why a separate workflow for the SATRA fixture?* It needs Docker images and Python; keeping it manual keeps the extension's CI fast and free of them.

## Step 11 — Install from VSIX documentation (2026-11-21)

Commit `docs(vscode): install the extension from the VSIX`.
Unit tests on the staged tree: 63 passing, 6 pending. Full Python suite: 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | What it does |
|---|---|
| `vscode-asent/README.md` | Install from the VSIX (artifact or `npm run package`; Extensions view → Install from VSIX or `code --install-extension`; WSL/Remote note), the commands and the exact `asent` argument lists, what the panel/status bar/Problems show, settings, trust and activation, development commands. Shipped inside the `.vsix`. |
| `README.md` (§4.0) | One paragraph: what the extension does and how to install it from the VSIX, linking to `vscode-asent/README.md`. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Root README gets one paragraph under §4.0 | A new top-level section | Scope rule: only the install section; details live next to the code. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V8 | README explains installing from the VSIX, including WSL/Remote. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-K3 | README shipped | `npm run package` | `extension/readme.md` in the `.vsix` | pass |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- The extension is not published to the Marketplace; installation is from the VSIX only.

### Tool disclosure (Ch 8.7)

Claude Code wrote both texts. Verified by packaging (README included) and by checking that every command and argument list in the table matches `src/args.ts`.

### Supervisor Q&A prep

- *How does someone install it?* Download the `asent-vscode-vsix` artifact and use "Install from VSIX"; in WSL, from the connected window.

## Step 12 — Neutral machine paths in the fixtures (2026-11-21)

Commit `test(vscode): neutral machine paths in the fixtures`.
Unit tests on the staged tree: 66 passing, 6 pending. Python suite: run once after step 14 (Maryam's instruction for the extra steps; result under step 14).
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `vscode-asent/scripts/make_fixtures.py` | `_placeholders(work)` | Regex rules, longest original first, each matching only a whole path segment: scenario repository → `/workspace/project`, scenario temp folder → `/workspace`, ASENT checkout (`ROOT`) → `/opt/asent`, home → `/home/user`, and any `tempfile.mkdtemp` folder (`<tmp>/<prefix>-<8 random>`) → `<tmp>/<prefix>-run`. Both the path and its resolved form are covered. |
| | `neutral(value, work)` | Applies the rules to every JSON string value and key; everything else is returned unchanged. Afterwards, if the scenario folder, `ROOT`, home or `$USER` is still found, raises `ScenarioError` and the file is not written. |
| | `main` | Writes `neutral(scenario(...))`. |
| `vscode-asent/test/fixtures/**/*.json` | | Regenerated (new real runs, so new SHAs, IDs and timings). |
| `vscode-asent/test/fixtures/README.md` | | "Neutral paths (the only edit)" table and the `content_hash` caveat. |
| `vscode-asent/test/unit/fixtures.test.ts` | | 3 tests over every committed fixture. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Edit only string values, on segment boundaries | Text search-and-replace on the JSON file | Cannot break JSON escaping or touch numbers, SHAs or digests; `/home/dell` cannot match inside `/home/dellx`. |
| Refuse to write if a machine path is left | Warn | A fixture must never carry the machine's paths again silently. |
| Keep asent's own run IDs (`exports/c8cb108cfb45`, `workspaces/…`) | Replace them too | They are asent's identifiers, not machine paths; the request was to keep everything else exactly. |
| Placeholder `/tmp/asent-gate-run` keeps the prefix | One generic `/tmp/run` | Shows which asent temp folder it was. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| Extra 1 | No home folder, checkout, scenario temp folder, user name or random temp suffix in any fixture (`fixtures.test.ts`); the placeholders are the documented ones. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-N1 | Fixtures present | `test/fixtures` | at least 7 JSON files | pass |
| VS-N2 | No machine paths | every fixture | no `/home/<x>` other than `/home/user`, no `Working-POC`, `asent-fixture-`, `pytest-of-`, `/Users/`, no mkdtemp suffix | pass |
| VS-N3 | Placeholders | `accept`, `init`, `doctor` | `/workspace/project`, `/workspace/project/.asent`, `/opt/asent`, `/tmp/asent-gate-run/…` | pass |
| VS-N4 | Only strings change (manual check) | one real run each of `accept`, `sable-block`, `doctor`, compared before and after `neutral()` | 693/325/53 values; 8/7/6 changed, all strings, same keys | pass |
| VS-N5 | Leftover check | (code path) machine string after rules | `ScenarioError`, nothing written | not separately tested (no Python test in scope; exercised by every regeneration) |

### Defects found and fixed

None in this step.

### Known limitations / deferred

- Hashes asent computed over records that contain paths (evidence `content_hash`, computed in `backend/db/storage.py` over the record body, which includes `evidence_refs`) were computed over the original paths and do not re-verify against the edited fixture. The extension does not verify them.

### Tool disclosure (Ch 8.7)

Claude Code wrote `neutral()`, regenerated the fixtures and wrote the test. Maryam asked for the change and chose the placeholder style. Verified by VS-N1–N4 and the unit suite.

### Supervisor Q&A prep

- *Are the fixtures still real output?* Yes: they come from real CLI runs; the only edit is the documented path placeholders, and a check showed every other value is unchanged.

## Step 13 — Untrusted extension test really runs untrusted (2026-11-21)

Commit `fix(vscode): run the untrusted extension test with workspace trust on`.
Unit tests on the staged tree: 66 passing, 6 pending. Extension test on the staged tree (first run on this machine, after Maryam
installed the libraries): trusted 11 passing, untrusted 3 passing. Python suite: run once after step 14 (result there).
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `vscode-asent/test/extension/runTest.ts` | `runTrusted` | Unchanged behaviour: `runTests` on VS Code 1.95.3. |
| | `runUntrusted` | `downloadAndUnzipVSCode(1.95.3)`, then starts VS Code itself with `runTests`' other arguments (`--no-sandbox`, `--disable-gpu-sandbox`, `--disable-updates`, `--skip-welcome`, `--skip-release-notes`, `--extensionTestsPath`, `--extensionDevelopmentPath`, own `--extensions-dir`) but **without** `--disable-workspace-trust`; fails on a non-zero exit. |
| | `env` | The per-suite environment for both runs. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Start VS Code directly for the untrusted run | An option of `runTests` | `@vscode/test-electron` 2.4.1 `runTests` always adds `--disable-workspace-trust` (`out/runTest.js` line 53) and has no option to drop it. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V11 | In VS Code with trust on: `isTrusted` is false, Show report works with the user's `asent.path`, and gate/init/dashboard start nothing (VS-E12–E14 pass). |

### Ch 7 Test cases

| Test ID | Purpose | Expected | Result |
|---|---|---|---|
| VS-E1–E11 | Trusted suite (step 9) | as in step 9 | pass (11) |
| VS-E12 | Folder untrusted, extension active | `isTrusted` false | pass |
| VS-E13 | Report via user `asent.path` | status BLOCK, `report --json --file=` | pass |
| VS-E14 | Refused commands | no gate/init/dashboard call | pass |

### Defects found and fixed

- The first run of the extension test failed 3 of 3 untrusted tests: the folder was trusted (`true !== false`), because `runTests` adds `--disable-workspace-trust` itself. In that trusted run VS Code used the workspace's bogus `asent.path`, so the report could not be read; this is the restriction working as designed, not an extension bug. Fixed by `runUntrusted`. (One earlier attempt failed before VS Code started: `ETIMEDOUT` downloading VS Code 1.95.3 from update.code.visualstudio.com; the retry downloaded it.)

### Known limitations / deferred

- `runUntrusted` repeats `runTests`' argument list for 2.4.1; a different `@vscode/test-electron` version may change it.

### Tool disclosure (Ch 8.7)

Claude Code found the cause in `node_modules/@vscode/test-electron/out/runTest.js` and wrote the fix. Verified by the extension test on exactly the staged tree.

### Supervisor Q&A prep

- *How did you notice?* The first real run asserted `isTrusted === false` and got `true`; the test was written to check the precondition, not to assume it.

## Step 14 — ASENT: Stop dashboard (2026-11-21)

Commit `feat(vscode): ASENT: Stop dashboard command`.
Unit tests on the staged tree: 66 passing, 6 pending. Extension test on the staged tree: trusted 13 passing, untrusted 4 passing.
Full Python suite (run once after this step, as Maryam asked for steps 12–14): 2201 passed, 20 skipped, 1 xfailed.
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `vscode-asent/package.json` | | Sixth command `asent.stopDashboard`, "ASENT: Stop dashboard". |
| `vscode-asent/src/extension.ts` | `stopDashboardCommand` | Running → `stopDashboard()` (SIGTERM, SIGKILL after 3 s), a line in the ASENT output and a message; still starting → "still starting"; not running → "not running". Allowed in untrusted folders. |
| | `state()` | Adds `dashboardPid` (read-only, for the extension test). |
| `vscode-asent/test/unit/manifest.test.ts` | | Expects six commands. |
| `vscode-asent/test/extension/suite/trusted.test.ts` | | Six commands; Stop ends the process; Stop again and a new start. |
| `vscode-asent/test/extension/suite/untrusted.test.ts` | | Stop is allowed and starts nothing. |
| `vscode-asent/README.md` | | Command table row; trust paragraph. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Stop allowed in untrusted folders | Require trust | It runs nothing; it only ends a process this window started. |
| Only the process this window started | Find any dashboard on the port | The extension never touches processes it did not start. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| Extra 2 | Start → running with a PID; Stop → not running and the PID is gone; Stop again → nothing; Start again → a second `dashboard --json` call. |

### Ch 7 Test cases

| Test ID | Purpose | Expected | Result |
|---|---|---|---|
| VS-M1' | Manifest | six commands with titles | pass |
| VS-E2' | Commands in VS Code | six registered | pass |
| VS-E15 | Stop | state not running; `process.kill(pid, 0)` fails | pass |
| VS-E16 | Stop when stopped, then start | no error; 2nd dashboard call; stop | pass |
| VS-E18 | Stop in untrusted folder | allowed, no dashboard call | pass |

### Defects found and fixed

- The manifest test, changed first, failed as expected (`1 failing`) until the command was added.

### Known limitations / deferred

- None new. (Step 8's "no stop command" limitation is resolved.)

### Tool disclosure (Ch 8.7)

Claude Code wrote the command and tests; Maryam asked for it. Verified by the unit suite, the extension test on the staged tree, and the full Python suite.

### Supervisor Q&A prep

- *What happens to the dashboard when VS Code closes?* It is stopped on deactivate; Stop dashboard does the same on request.

## Step 15 — Tests never open a browser (2026-11-21)

Commit `test(vscode): stub openExternal so the extension test opens no browser`.
Unit tests on the staged tree: 66 passing, 6 pending. Extension test on the staged tree: trusted 14 passing, untrusted 4 passing.
Python suite: not run for this step (test-only change under `vscode-asent/test/extension/`; Maryam's instruction).
Review: no reviewer pass was run for this step.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `test/extension/suite/helpers.ts` | `stubOpenExternal()` | Replaces `vscode.env.openExternal` with a recorder (returns `true`), asserts the replacement took, and gives `restore()`. |
| | `urlsThatReachedTheOs()` | Reads the shim log (below). |
| `test/extension/suite/trusted.test.ts` | | Stub installed in `before`, restored in `after`. Dashboard test asserts `opened` is exactly `["http://127.0.0.1:8000/"]` (the fixture's URL) and that the second click opens nothing; Stop/start test asserts the second open. New last test: nothing reached the OS opener. |
| `test/extension/runTest.ts` | `openerShims()`, `env()` | For both test runs, `xdg-open`, `wslview`, `sensible-browser`, `x-www-browser`, `www-browser`, `gnome-open`, `kde-open`, `open` are no-op shims placed first on the test VS Code's `PATH` (and `BROWSER`), logging the URL to `ASENT_TEST_OPEN_LOG`. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Patch `vscode.env.openExternal` in the test | A test hook in `src/extension.ts` | Maryam's choice; no test seam in shipped code. VS Code 1.95.3 freezes `vscode.env` only when no extension tests run (`extensionTestsLocationURI \|\| Object.freeze(env)` in `extensionHostProcess.js`), so the patch is possible exactly in tests. |
| PATH shims as a second layer | Only the stub | If the stub ever stopped reaching the extension, a URL would be logged and the last test would fail, instead of a tab opening. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V2/V9 (dashboard) | The URL opened is exactly the one `asent dashboard --json` printed; no test opens a real browser. |

### Ch 7 Test cases

| Test ID | Purpose | Expected | Result |
|---|---|---|---|
| VS-E10' | Dashboard open | `opened` = `["http://127.0.0.1:8000/"]`; second click adds nothing | pass |
| VS-E16' | Start after stop | two recorded opens | pass |
| VS-E19 | Nothing reached the OS | shim log empty | pass |
| VS-K4 | Shim works (manual) | `xdg-open http://127.0.0.1:9/shim-check` with the shim dir first on PATH | URL logged, nothing opened | pass |

### Defects found and fixed

- The dashboard tests opened real browser tabs on Maryam's machine (WSLg display; the stub's `http://127.0.0.1:8000/` has no server). Step 9's notes said nothing would open on a headless runner, which did not hold for a desktop machine. Fixed by the stub and the shims.

### Known limitations / deferred

- The shims cover the usual Linux/WSL openers; on macOS or Windows the test would rely on the stub alone (CI and this machine are Linux).

### Tool disclosure (Ch 8.7)

Claude Code wrote the stub, shims and assertions after Maryam reported the tabs and chose the approach. Verified by the extension test on the staged tree and a manual shim check.

### Supervisor Q&A prep

- *How do you know the test no longer opens a browser?* The stub records the URL and the test asserts it; a second layer logs any URL that reaches the system opener, and a test asserts that log is empty.

## Step 16 — asent is resolved on PATH, never in the workspace (2026-11-21)

Commit `fix(vscode): resolve a bare asent.path on PATH outside the workspace`.
Unit tests: 77 passing, 6 pending (66 before). Extension test: trusted 15 passing, untrusted 5 passing (14 and 4 before).
Python suite: not run for this step (change only under `vscode-asent/`; Maryam's instruction).
Review: found by an independent security review of `master...asent-vscode-extension`; no reviewer pass was run on the fix.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/cli.ts` | `resolveAsent(configured, options)` | Returns the absolute path to start. Absolute `asent.path`: used as it is. Relative path with a separator (or `C:x` on Windows): `AsentNotFound(..., "NOT_ABSOLUTE")`. Bare name: walks PATH (`Path` key on Windows) itself. |
| | `AsentNotFound` | New code `NOT_ABSOLUTE` with its own message. |
| `src/extension.ts` | `asentCommand(folder)` (was `asentPath`) | Reads `asent.path` and calls `resolveAsent` with every workspace folder as `excluded`; used by all six spawn sites. `runGate` resolves before it sets "gate running". |
| | `loadReport` | `asent report` now runs with `cwd: os.homedir()` (the report is passed by absolute path). Doctor already did. |
| `README.md` | Commands, Settings | Show report runs in the home folder; how a bare name is looked up. |

Algorithm (bare name): for each PATH entry (Windows: surrounding quotes removed) skip it if empty, not absolute (covers `.`), or equal to/inside a workspace folder, lexically or after `realpath`; try `name` (POSIX) or `name.com`, `name.exe` (Windows, no extension given); accept the first executable file whose `realpath` is not in a workspace folder; none → `AsentNotFound(name, "ENOENT")`, which shows the existing "asent was not found" message.

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Resolve in the extension, spawn the absolute path | Keep spawn's own lookup and only change `cwd` | libuv on Windows searches the child's `cwd` before PATH; Init, Run gate and Dashboard need `cwd` = the folder, so only an absolute path closes it for every command. |
| Skip every relative PATH entry, not only `""` and `.` | Exactly `""` and `.` | `tools` or `.\bin` also mean "relative to the working directory". |
| `realpath` on the entry and on the found file | Lexical check only | A PATH entry or an `asent` symlink pointing into the workspace would pass a lexical check. |
| Exclude all workspace folders | Only the current one | A multi-root window has several repositories. |
| Refuse a relative `asent.path` with a separator | Resolve it against the folder | The documented values are a name or an absolute path; a relative one would depend on `cwd`, which now differs per command. |
| `platform`, `env`, `isExecutable`, `realpath` injectable | Test on Windows only | The Windows rules (`;`, `Path`, `.com`/`.exe`, case, drive-relative) are tested on Linux CI with a fake file system. |
| Unique stub name `asent-test-stub` in the extension test | Bare `asent` | VS Code puts the login shell's PATH (here `~/.local/bin` with a real pipx `asent`) before the test's own, so `asent` resolved to the real CLI on this machine. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V3 (asent only, argument array) / Workspace Trust | A fake `asent` in the workspace folder, first on PATH, never runs: on activation, Show report and Doctor in the untrusted folder, and with a bare `asent.path` in the trusted one. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-R1 | Skip rules (POSIX) | PATH = workspace, `""`, `.`, `tools`, `./tools`, workspace/tools, bin | `bin/asent` | pass |
| VS-R2 | Fake never runs | resolve + `runAsent` with `cwd` = workspace | stub answered, no HIJACKED | pass |
| VS-R3 | Only bad entries | workspace, `""`, `.` (process cwd = workspace) | `AsentNotFound` ENOENT | pass |
| VS-R4 | Symlinked PATH entry | entry → workspace | ENOENT | pass |
| VS-R5 | Symlinked file | other/asent → workspace/asent | skipped; next entry used | pass |
| VS-R6 | Not executable / directory | 0644 file, directory `asent` | passed over | pass |
| VS-R7 | Absolute / relative | absolute stub; `./asent`, `tools/asent`, `../asent` | as is; NOT_ABSOLUTE | pass |
| VS-R8 | Windows skip rules | workspace, `""`, `.`, `.\tools`, `tools`, other-case workspace\tools, quoted `C:\Program Files\asent`, `Path` key | `C:\Program Files\asent\asent.exe` | pass |
| VS-R9 | Windows only bad entries | workspace, workspace\bin, `.` | ENOENT | pass |
| VS-R10 | Windows extensions | `.com` and `.exe` present; `asent.exe`; extension-less file only | `.com`; exact; ENOENT | pass |
| VS-R11 | Windows absolute / relative | `D:\asent\asent.exe`; `tools\asent.exe`, `.\asent.exe`, `C:asent.exe`, `tools/asent` | as is; NOT_ABSOLUTE | pass |
| VS-E20 | Trusted, bare name | `asent.path` = `asent-test-stub`, fake first on PATH; Show report, Doctor | stub called, report `cwd` = home, no HIJACKED | pass |
| VS-E6' | Show report `cwd` | Show report | `cwd` = home | pass |
| VS-U5 | Untrusted, planted program | user `asent.path` = bare name, fake in folder first on PATH | every report/doctor call by the stub, `cwd` = home, no HIJACKED | pass |
| VS-M1 | Test catches the bug (manual mutation) | `asentCommand` returns the bare name unresolved | VS-E20 fails ("the stub read the report"); file restored | pass |

### Defects found and fixed

- Independent review: on Windows a bare `asent.path` let a repository's own `asent.exe` run (spawn searches `cwd` first), including on activation in an untrusted folder. Fixed by `resolveAsent` and `cwd` = home for report.
- First run of VS-E20 failed: `~/.local/bin/asent` (real pipx install) answered before the stub. The resolver was right; the test now uses a unique stub name.

### Known limitations / deferred

- An `asent` in a virtual environment inside the workspace (e.g. `.venv/bin` on PATH) is no longer found by name; set its absolute path in user settings (README).
- The Windows rules are tested with a fake file system on Linux; the extension has not been run on Windows.
- Init, Run gate and Dashboard still run with `cwd` = the folder (asent needs it); safe now because the program path is absolute.

### Tool disclosure (Ch 8.7)

Claude Code wrote `resolveAsent`, the tests and the extension-test fakes from Maryam's specification (skip rules, home `cwd`, not-found message). Verified by the unit and extension tests and the manual mutation VS-M1.

### Supervisor Q&A prep

- *Why not just run asent in the home folder?* Run gate, Init and the dashboard must run in the repository, and Windows looks in the working folder before PATH; spawning an absolute path is the only fix that covers every command.
- *What if PATH itself points into the repository?* That entry is skipped, lexically and after following symlinks; the found file is checked the same way.

## Step 17 — Problems entries only inside the workspace folder (2026-11-21)

Commit `fix(vscode): place Problems entries only on real files inside the folder`.
Unit tests: 80 passing, 6 pending. Extension test: trusted 16 passing, untrusted 5 passing.
Python suite: not run for this step (change only under `vscode-asent/`; Maryam's instruction).
Review: found by an independent security review of `master...asent-vscode-extension`; no reviewer pass was run on the fix.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/diagnostics.ts` | `locate(findings, folder)` | No `repository` argument any more. Resolves each finding's path against the folder; drops absolute, NUL, outside and folder-itself paths; then `realpath` + `isFile`; keeps the entry only if the real path is inside the folder's real path. The entry's `file` stays the path under the folder as VS Code opened it. |
| | `diagnosticRoot` | Removed (it trusted the report's `repository` when it contained the folder). |
| `src/extension.ts` | `useReport` | Calls `locate(report.findings, folder)`. |
| `README.md` | What you see → Problems | How paths are placed, and the subfolder limitation. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Never use `repository` as a root | Accept it only if it is the git top level | `asent report` passes the file's JSON through unchecked, so in an untrusted folder the field is attacker-controlled; finding the real top level would mean running git there. |
| `realpath` both the folder and the file | Lexical check only | A symlink in the repository pointing outside passed the old lexical check. Comparing real paths also keeps a folder opened through a symlink working. |
| A missing file gets no entry | Place it lexically | Fail closed: `realpath` needs the file; an entry for a file that is not there helps nobody. |
| Directories get no entry | Allow them | Problems entries belong on files. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V6 (Problems) | An entry exists only for an existing file whose real path is inside the workspace folder; a report saying `"repository": "/"` cannot place one on `home/user/.ssh/config`. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-D1' | Real report still placed | `cavr-block.json` | `requirements.txt` line 0, file-level message | pass |
| VS-D6 | Root `/` | fixture with `"repository": "/"`, file `home/user/.ssh/config` | no entry | pass |
| VS-D7 | Root that contains the folder, file exists there | `repository` = parent of the folder, `home/user/.ssh/config` exists under it | no entry | pass |
| VS-D8 | Symlink out | `link/secret.txt`, `secret-link.txt` → outside | no entry | pass |
| VS-D9 | Symlinks that stay inside | file link inside; folder opened via a symlink | entry; path under the opened folder | pass |
| VS-D2' | Line numbers | line 7 | line 6 | pass |
| VS-D3' | Bad paths | `../`, `a/../../`, absolute, `C:\`, NUL, `""`, `.`, directory `app` | none | pass |
| VS-D10 | Missing file | `no-such-file.txt`, `sub/requirements.txt` | none | pass |
| VS-E21 | End to end (trusted) | report with `"repository": "/"` written to the folder; watcher loads it | no ASENT diagnostics on any URI | pass |
| VS-M2 | Old code had the bug (manual) | old `out/src/diagnostics.js`, `locate([home/user/.ssh/config], folder, "/")` | entry on `/home/user/.ssh/config` | confirmed |

### Defects found and fixed

- Independent review: `diagnosticRoot` used the report's `repository` as the root when it was absolute and contained the folder, so `"repository": "/"` put entries on any file; symlinks were only checked lexically. Fixed as above.

### Known limitations / deferred

- When the workspace folder is a subfolder of the gated repository, the report's paths (relative to the repository top level) usually do not exist under the folder and are left out; open the repository's top-level folder to see them.

### Tool disclosure (Ch 8.7)

Claude Code rewrote `locate` and its tests to Maryam's specification (workspace folder only, realpath, the `"repository": "/"` test). Verified by the unit and extension tests and VS-M2.

### Supervisor Q&A prep

- *Why ignore the repository field the report gives?* The extension also reads reports in untrusted folders and `asent report` does not check that field, so it is attacker input; only the folder VS Code opened is trusted as a root.
- *What does realpath add?* A symlink inside the repository can point anywhere; comparing real paths stops it.

## Step 18 — Notification text cannot carry links (2026-11-21)

Commit `fix(vscode): clean report and error text before it goes into a notification`.
Unit tests: 89 passing, 6 pending. Extension test: trusted 16 passing, untrusted 5 passing.
Python suite: not run for this step (change only under `vscode-asent/`; Maryam's instruction).
Review: found by an independent security review of `master...asent-vscode-extension` (rated a hardening item); no reviewer pass was run on the fix.

### Ch 6 Implementation

| File | Function | What it does |
|---|---|---|
| `src/notify.ts` (new, no vscode import) | `notificationText(text, max = 160)` | Control characters → space; then, until nothing changes: remove `[ ] ( )`, remove `scheme://...`, `command:`/`vscode:`/`file:`/`https?:`/`javascript:`/`vbscript:`/`data:`/`mailto:` + non-space, `www.` + non-space; collapse whitespace; cut to `max` with `…`. |
| | `gateNotification(report)` | `ASENT gate: <decision>: <first reason>`, cleaned. |
| | `errorNotification(e)` | One cleaned line per error type; for `AsentNotFound` only the configured path is cleaned (capped at 60) inside the extension's own sentence. |
| `src/extension.ts` | `reportError`, `runGate`, `initProject`, `openDashboard` | Use the functions above. Init errors are now also written in full to the ASENT output. The dashboard "already running" text is built in a `where` variable (no nested template). |
| `test/unit/security.test.ts` | | `notify.ts` added to the module list; new static check of every `show*Message` call in `extension.ts`. |
| `README.md` | What you see | Notifications line. |

### Design decisions

| Decision | Alternatives considered | Why |
|---|---|---|
| Repeat the removals until nothing changes | One pass | Removing brackets can join pieces into a link again (`comm[]and:x`, `ht[t]ps:/(/)x`). |
| Remove known dangerous schemes even inside a word, but only with text after the colon | Word boundary; any `word:` | `xcommand:y` is still caught; ordinary asent text such as `data: 3 files` or `DENYLIST: reqeusts` is unchanged. |
| Clean only the report/asent parts of the extension's own sentences where it helps reading | Clean the whole sentence everywhere | The not-found message keeps its wording; the extension's fixed text has no brackets or links. |
| Static check on `extension.ts` | Expose the last notification through `AsentApi` | No test seam in shipped code (as in Step 15); the check fails if a notification interpolates anything other than `notificationText(...)`, `url`, `where`, `title`, or mentions `.message`, `.reasons`, `json`, `error`, `files`, `stderr` outside it. |
| 160 characters | No limit | "One short line" (Maryam); the full text stays in the panel and the output. |

### Requirements covered

| Req | Acceptance check |
|---|---|
| V7 (messages) | No notification can contain `[`, `]`, `(`, `)`, a link or a `command:` URI from report or asent text; it is one line of at most 160 characters. |

### Ch 7 Test cases

| Test ID | Purpose | Input | Expected | Result |
|---|---|---|---|---|
| VS-N1 | Command link | `Blocked [Fix it](command:...sendSequence?...) now` | `Blocked Fix it now` | pass |
| VS-N2 | Other links | 11 forms (https with parentheses, 127.0.0.1, vscode://, vscode-insiders://, file:///, javascript:, data:, mailto:, www., ftp://, `COMMAND:`) | `see here` | pass |
| VS-N3 | Links that re-form | `comm[]and:`, `[a](ht)(tps://…)`, `x[command:y]`, `c(o)mmand:z`, `ht[t]ps:/(/)evil` | no bracket, no link | pass |
| VS-N4 | One short line | newlines, tab, BEL; 1000 × `x`; `abcdef` with max 4 | one line; 160 with `…`; `abc…` | pass |
| VS-N5 | Ordinary text kept | DENYLIST reason, `reqeusts==2.31.0`, `C:\Users\...`, `data: 3 files`, `ASENT_CONFIG_MISSING` | unchanged | pass |
| VS-N6 | Gate | real CAVR BLOCK report with a malicious first reason | `ASENT gate: BLOCK: CAVR: Fix it second line`; panel has the full text, no `<a`/`href` | pass |
| VS-N7 | Gate, real reason / none | real report; `reasons: []` | cleaned reason; `ASENT gate: BLOCK` | pass |
| VS-N8 | Errors | `AsentOutputError` with link in stderr, `Error`, `AsentNotFound` (link in path; NOT_ABSOLUTE), `AsentCancelled`, a string | all cleaned, start `ASENT: ` | pass |
| VS-S7 | Static check | `extension.ts` before the change | fails on `ASENT: ${e.message}. Install asent…` | confirmed (test-first run) |
| VS-S7' | Static check | `extension.ts` after | passes (≥ 10 calls checked) | pass |

### Defects found and fixed

- Independent review: report reasons and asent error text went into notifications unchanged; VS Code renders `[label](command:...)` there as a clickable link.
- While writing `notify.ts`, the control-character regex was saved with literal U+2028/U+2029 characters, which TypeScript reads as line breaks (compile error); replaced with `\u2028\u2029` escapes.

### Known limitations / deferred

- The static check reads `show*Message(` calls one line at a time; a notification built in a variable is covered only through `gateNotification`/`errorNotification`.
- Status bar tooltips (plain strings, no link rendering) are unchanged.

### Tool disclosure (Ch 8.7)

Claude Code wrote `notify.ts`, its tests and the static check to Maryam's specification (remove brackets, parentheses, links and command: URIs; one short line; panel keeps the full text). Verified by the unit and extension tests; the static check was seen failing on the old code first.

### Supervisor Q&A prep

- *Why not escape the text instead of removing characters?* Notifications have no escaping for their link syntax; removing the characters that make a link is the only reliable option, and the full text is still in the panel.
- *Could removing brackets create a new link?* The removals repeat until nothing changes, and tests cover pieces that join into `command:` and `https://`.
