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
