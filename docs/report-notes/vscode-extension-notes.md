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
