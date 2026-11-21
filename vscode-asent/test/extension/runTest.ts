// Runs the extension tests inside a real VS Code (downloaded by @vscode/test-electron), twice:
//   1. trusted:   workspace trust disabled (every folder trusted), asent.path set in the WORKSPACE settings
//   2. untrusted: workspace trust on, the folder not trusted; the workspace's asent.path points at a path that
//                 does not exist and the USER settings point at the stub, so the run shows that VS Code
//                 ignores the workspace value (restrictedConfigurations) and the extension still reads reports.
// `asent` is test/stub/asent, which replays the real CLI outputs in test/fixtures and logs every argv.
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runTests } from "@vscode/test-electron";

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

async function run(suite: "trusted" | "untrusted", folder: string, user: string, trustArgs: string[]): Promise<void> {
  const log = path.join(folder, "..", path.basename(folder) + "-argv.jsonl");
  const control = path.join(folder, "..", path.basename(folder) + "-control.json");
  await runTests({
    // The oldest VS Code that package.json's engines (^1.95.0) allows, so the test does not drift with "stable".
    version: VSCODE_VERSION,
    extensionDevelopmentPath: ROOT,
    extensionTestsPath: path.join(__dirname, "suite", "index"),
    launchArgs: [folder, "--disable-extensions", `--user-data-dir=${user}`, ...trustArgs],
    extensionTestsEnv: { ASENT_SUITE: suite, ASENT_STUB_LOG: log, ASENT_STUB_CONTROL: control, ASENT_TEST_FOLDER: folder, ASENT_TEST_STUB: STUB },
  });
}

async function main(): Promise<void> {
  fs.chmodSync(STUB, 0o755);
  const trusted = workspace("trusted", { "asent.path": STUB });
  await run("trusted", trusted, userData("trusted", {}), ["--disable-workspace-trust"]);

  const untrusted = workspace("untrusted", { "asent.path": "/nonexistent/asent-from-the-repository" });
  fs.copyFileSync(path.join(ROOT, "test", "fixtures", "reports", "cavr-block.json"), path.join(untrusted, "asent-report.json"));
  await run("untrusted", untrusted, userData("untrusted", {
    "asent.path": STUB,
    "security.workspace.trust.enabled": true,
    "security.workspace.trust.startupPrompt": "never",
    "security.workspace.trust.emptyWindow": false,
  }), []);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
