# ASENT for VS Code

Shows the decision of the installed `asent` command (ACCEPT / REVIEW / BLOCK) inside VS Code. The extension
only runs `asent` with `--json` and displays what it printed: it re-implements no check, stores no token or
data, and sends nothing anywhere. `asent` is always started with an argument list, never through a shell.

## Install from the VSIX

1. Install the `asent` command first (repository README §4.0), and check it in a terminal: `asent --version`,
   then `asent doctor`.
2. Get `asent-vscode.vsix`: GitHub → Actions → workflow **VS Code extension** → a successful run → artifact
   **asent-vscode-vsix** (a zip that contains the `.vsix`). Or build it yourself: `cd vscode-asent && npm ci && npm run package`.
3. Install it: Extensions view → `…` → **Install from VSIX…** → choose `asent-vscode.vsix`, or in a terminal
   `code --install-extension asent-vscode.vsix`.
4. **WSL / Remote / Dev Containers:** the extension runs on the workspace side (`extensionKind: workspace`),
   where `asent` is installed. Install the VSIX while connected to that window (Extensions view → `…` →
   Install from VSIX), so it lands in the WSL/remote side, not in the local Windows VS Code.

Needs VS Code 1.95 or newer.

## Commands

| Command | Runs | Notes |
|---|---|---|
| ASENT: Init project | `asent init --json --repository=<folder>` | Writes a starter `.asent/` (every gate decision is REVIEW until it is reviewed). Trusted folders only. |
| ASENT: Run gate on this branch | `asent gate --json --output-dir=<folder> [--base=<asent.baseBranch>]` | Head is `HEAD`. Shows the panel, status bar and Problems. One run at a time; cancellable. Trusted folders only. |
| ASENT: Show report | `asent report --json --file=<folder>/asent-report.json` (in your home folder) | Opens the panel. Works in untrusted folders. |
| ASENT: Doctor | `asent doctor --json` (in your home folder) | Lists what is missing, with asent's own `fix:` lines, in the **ASENT** output. |
| ASENT: Open web dashboard | `asent dashboard --json` | Opens the `http://127.0.0.1:PORT/` it prints (nothing else). One process at a time; it stops with **ASENT: Stop dashboard** or when the window closes. Trusted folders only. |
| ASENT: Stop dashboard | (stops the process above) | Stops only the dashboard this window started. Works in untrusted folders. |

## What you see

- **Panel**: a big ACCEPT / REVIEW / BLOCK banner with the reasons, one card each for CAVR, SATRA-RV and SABLE
  (result, status, reason, key evidence from the module's evidence record), the base and head commits and the
  config digest, all from `asent-report.json`. It runs no script (strict Content-Security-Policy, nothing loaded
  from anywhere) and uses VS Code's theme colours, so it follows light, dark and high-contrast themes.
- **Status bar**: `ASENT: <decision>` of the last report (warning background for REVIEW, error for BLOCK); click
  it to open the panel. It also updates when `asent gate` in a terminal rewrites `asent-report.json`.
- **Problems**: CAVR findings at the file the report names (e.g. `requirements.txt`). Where the report also gives
  a line (call sites of a rejected package) the entry is on that line; otherwise it is on line 1 and says the
  report gives no line. Paths are taken relative to the workspace folder (the report's `repository` field is
  not used), and an entry is made only for an existing file inside the folder, after following symlinks; so when
  the folder is a subfolder of the gated repository, findings in other parts of the repository are left out.
  SATRA and SABLE gate reports name tests and Terraform resources, not file lines, so they appear only in the panel.
- **Notifications**: one short line. Text from the report or from asent (the first reason, error messages) is
  shown without brackets, parentheses or links, so it cannot add a clickable link; the panel and the **ASENT**
  output keep the full text.
- **asent or Docker missing**: "asent was not found" with the install commands and the `asent.path` setting; when
  a gate ran SATRA without Docker, a warning with `asent doctor`'s fix lines in the ASENT output.

## Settings

| Setting | Default | Meaning |
|---|---|---|
| `asent.path` | `asent` | The `asent` executable: a name on PATH or an absolute path (a relative path is refused). The extension looks a name up on PATH itself and skips empty, `.` and relative entries and every entry in a workspace folder, so a repository's own `asent` / `asent.exe` is never run. An `asent` installed in a virtual environment inside the workspace is therefore not found: set its absolute path in your user settings. |
| `asent.baseBranch` | empty | Base for Run gate. Empty: asent picks the repository's default branch (origin/HEAD, else `main`, else `master`). |

## Workspace Trust and activation

In an untrusted folder only **Show report**, Doctor and Stop dashboard work; Init, Run gate and the dashboard say they need a
trusted folder. The folder's own `.vscode/settings.json` cannot set `asent.path` or `asent.baseBranch` there.
The extension activates only in a folder that has `.asent/` or `asent-report.json`, or when you run one of its commands.

## Development

```bash
cd vscode-asent
npm ci
npm test                      # unit tests (real asent outputs in test/fixtures)
npm run test:extension        # in VS Code 1.95.3; on Linux without a display: xvfb-run -a npm run test:extension
npm run package               # asent-vscode.vsix
ASENT_REAL=../scripts/asent ASENT_PYTHON=../.venv/bin/python npx mocha --grep "real asent"   # against the real CLI
```

The fixtures are real `asent` outputs written by `scripts/make_fixtures.py` (see `test/fixtures/README.md`). The
SATRA BLOCK report needs Docker: run the manual workflow **VS Code extension fixtures**, download its artifact
and commit `reports/satra-block.json`; until then that one unit test is skipped and says why.
