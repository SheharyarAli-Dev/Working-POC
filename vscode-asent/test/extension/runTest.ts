// Runs the extension tests inside a real VS Code (downloaded by @vscode/test-electron), twice:
//   1. trusted:   workspace trust disabled (every folder trusted), asent.path set in the WORKSPACE settings
//   2. untrusted: workspace trust on, the folder not trusted; the workspace's asent.path points at a path that
//                 does not exist and the USER settings point at the stub, so the run shows that VS Code
//                 ignores the workspace value (restrictedConfigurations) and the extension still reads reports.
// `asent` is test/stub/asent, which replays the real CLI outputs in test/fixtures and logs every argv.
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawn } from "child_process";
import { runTests, downloadAndUnzipVSCode } from "@vscode/test-electron";

const ROOT = path.resolve(__dirname, "..", "..", "..");
const STUB = path.join(ROOT, "test", "stub", "asent");
export const VSCODE_VERSION = "1.95.3";

function workspace(name: string, workspaceSettings: object): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `asent-ext-${name}-`));
  fs.mkdirSync(path.join(dir, ".asent"));
  fs.writeFileSync(path.join(dir, ".asent", "config.json"), "{}\n"); // only so that workspaceContains:.asent/** activates
  fs.writeFileSync(path.join(dir, "requirements.txt"), "pypdf==6.19.0\nreqeusts==2.31.0\n");
  fs.mkdirSync(path.join(dir, ".vscode"));
  fs.writeFileSync(path.join(dir, ".vscode", "settings.json"), JSON.stringify(workspaceSettings, null, 2));
  return dir;
}

function userData(name: string, settings: object): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `asent-ext-user-${name}-`));
  fs.mkdirSync(path.join(dir, "User"));
  fs.writeFileSync(path.join(dir, "User", "settings.json"), JSON.stringify(settings, null, 2));
  return dir;
}

// Safety net under the tests' openExternal stub: the programs a desktop uses to open a URL are replaced, for
// the test VS Code only, by shims that log the URL instead. A real browser tab can then never open, and the
// last trusted test checks that the log stayed empty (the stub caught every open).
const OPENERS = ["xdg-open", "wslview", "sensible-browser", "x-www-browser", "www-browser", "gnome-open", "kde-open", "open"];

function openerShims(): { bin: string; log: string } {
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), "asent-ext-openers-"));
  const log = path.join(bin, "opened-urls.log");
  for (const name of OPENERS) {
    fs.writeFileSync(path.join(bin, name), `#!/bin/sh\nprintf '%s\\n' "$*" >> '${log}'\n`, { mode: 0o755 });
  }
  return { bin, log };
}

const SHIMS = openerShims();

function env(suite: string, folder: string): Record<string, string> {
  const base = path.join(folder, "..", path.basename(folder));
  return { ASENT_SUITE: suite, ASENT_STUB_LOG: base + "-argv.jsonl", ASENT_STUB_CONTROL: base + "-control.json",
    ASENT_TEST_FOLDER: folder, ASENT_TEST_STUB: STUB, ASENT_TEST_OPEN_LOG: SHIMS.log,
    PATH: `${SHIMS.bin}${path.delimiter}${process.env.PATH ?? ""}`, BROWSER: path.join(SHIMS.bin, "xdg-open") };
}

const TESTS = path.join(__dirname, "suite", "index");

// The trusted run uses runTests, which always adds --disable-workspace-trust.
async function runTrusted(folder: string, user: string): Promise<void> {
  await runTests({
    // The oldest VS Code that package.json's engines (^1.95.0) allows, so the test does not drift with "stable".
    version: VSCODE_VERSION,
    extensionDevelopmentPath: ROOT,
    extensionTestsPath: TESTS,
    launchArgs: [folder, "--disable-extensions", `--user-data-dir=${user}`],
    extensionTestsEnv: env("trusted", folder),
  });
}

// The untrusted run cannot use runTests (it always disables workspace trust), so it starts the same VS Code
// with runTests' other arguments and without --disable-workspace-trust.
async function runUntrusted(folder: string, user: string): Promise<void> {
  const executable = await downloadAndUnzipVSCode(VSCODE_VERSION);
  const args = [folder, "--disable-extensions", `--user-data-dir=${user}`, `--extensions-dir=${path.join(user, "extensions")}`,
    "--no-sandbox", "--disable-gpu-sandbox", "--disable-updates", "--skip-welcome", "--skip-release-notes",
    `--extensionTestsPath=${TESTS}`, `--extensionDevelopmentPath=${ROOT}`];
  const code = await new Promise<number | null>((resolve, reject) => {
    const child = spawn(executable, args, { env: { ...process.env, ...env("untrusted", folder) }, stdio: "inherit" });
    child.on("error", reject);
    child.on("exit", resolve);
  });
  if (code !== 0) throw new Error(`untrusted extension test run failed (exit ${code})`);
}

async function main(): Promise<void> {
  fs.chmodSync(STUB, 0o755);
  const trusted = workspace("trusted", { "asent.path": STUB });
  await runTrusted(trusted, userData("trusted", {}));

  const untrusted = workspace("untrusted", { "asent.path": "/nonexistent/asent-from-the-repository" });
  fs.copyFileSync(path.join(ROOT, "test", "fixtures", "reports", "cavr-block.json"), path.join(untrusted, "asent-report.json"));
  await runUntrusted(untrusted, userData("untrusted", {
    "asent.path": STUB,
    "security.workspace.trust.enabled": true,
    "security.workspace.trust.startupPrompt": "never",
    "security.workspace.trust.emptyWindow": false,
  }));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
