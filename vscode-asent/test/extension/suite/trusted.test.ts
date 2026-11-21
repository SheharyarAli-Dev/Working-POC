// Extension test in a real VS Code, trusted folder, asent = test/stub/asent (replays real CLI outputs).
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { api, calls, callsOf, stub, until, FOLDER, ID } from "./helpers";

const fixture = (name: string) => path.resolve(__dirname, "..", "..", "..", "..", "test", "fixtures", "reports", name);
const requirements = vscode.Uri.file(path.join(FOLDER, "requirements.txt"));

describe("ASENT extension (trusted folder)", () => {
  before(() => stub({}));

  it("activates on its own because the folder has .asent/ (no command run yet)", async () => {
    await until("activation", () => vscode.extensions.getExtension(ID)?.isActive === true);
    assert.strictEqual(vscode.workspace.isTrusted, true);
    assert.deepStrictEqual(calls(), [], "no asent call before a command, since there is no asent-report.json yet");
    assert.strictEqual((await api()).state().statusText, "$(shield) ASENT");
  });

  it("contributes the six commands", async () => {
    const all = await vscode.commands.getCommands(true);
    for (const id of ["asent.init", "asent.gate", "asent.showReport", "asent.doctor", "asent.dashboard", "asent.stopDashboard"]) {
      assert.ok(all.includes(id), id);
    }
  });

  it("Run gate (CAVR BLOCK): argument array, status bar, Problems entry and panel", async () => {
    stub({ gate: "cavr-block.json" });
    await vscode.commands.executeCommand("asent.gate");
    const gate = callsOf("gate").at(-1)!;
    assert.deepStrictEqual(gate.argv, ["gate", "--json", `--output-dir=${FOLDER}`]);
    assert.strictEqual(fs.realpathSync(gate.cwd), fs.realpathSync(FOLDER));
    const state = (await api()).state();
    assert.strictEqual(state.decision, "BLOCK");
    assert.strictEqual(state.statusText, "$(shield) ASENT: BLOCK");
    const diagnostics = vscode.languages.getDiagnostics(requirements);
    assert.strictEqual(diagnostics.length, 1);
    assert.strictEqual(diagnostics[0].severity, vscode.DiagnosticSeverity.Error);
    assert.strictEqual(diagnostics[0].range.start.line, 0);
    assert.strictEqual(diagnostics[0].source, "ASENT");
    assert.match(diagnostics[0].message, /^CAVR BLOCK DENYLIST: reqeusts is on the project denylist/);
    assert.match(state.panelHtml ?? "", /<h1>BLOCK<\/h1>/);
    assert.match(state.panelHtml ?? "", /Content-Security-Policy" content="default-src 'none';/);
    assert.ok(fs.existsSync(path.join(FOLDER, "asent-report.json")), "the stub wrote the report like asent does");
  });

  it("a second Run gate while one is running does not start another", async () => {
    stub({ gate: "review.json", mode: "slow-gate" });
    const before = callsOf("gate").length;
    const first = vscode.commands.executeCommand("asent.gate");
    await until("gate running", async () => (await api()).state().gateRunning);
    assert.strictEqual((await api()).state().statusText, "$(sync~spin) ASENT: gate running");
    await vscode.commands.executeCommand("asent.gate"); // returns at once: "already in progress"
    await first;
    assert.strictEqual(callsOf("gate").length, before + 1);
    assert.strictEqual((await api()).state().decision, "REVIEW");
    assert.deepStrictEqual(vscode.languages.getDiagnostics(requirements), [], "REVIEW report has no findings: old entries cleared");
  });

  it("the base branch setting becomes --base=<value>", async () => {
    stub({ gate: "accept.json" });
    const config = vscode.workspace.getConfiguration("asent");
    await config.update("baseBranch", "develop", vscode.ConfigurationTarget.Workspace);
    try {
      await vscode.commands.executeCommand("asent.gate");
      assert.deepStrictEqual(callsOf("gate").at(-1)!.argv, ["gate", "--json", `--output-dir=${FOLDER}`, "--base=develop"]);
      assert.strictEqual((await api()).state().statusText, "$(shield) ASENT: ACCEPT");
    } finally {
      await config.update("baseBranch", undefined, vscode.ConfigurationTarget.Workspace);
    }
  });

  it("Show report reads asent-report.json through asent report --json --file=", async () => {
    await vscode.commands.executeCommand("asent.showReport");
    assert.deepStrictEqual(callsOf("report").at(-1)!.argv, ["report", "--json", `--file=${path.join(FOLDER, "asent-report.json")}`]);
    assert.match((await api()).state().panelHtml ?? "", /<h1>ACCEPT<\/h1>/);
  });

  it("a report written by asent in a terminal updates the status bar (file watcher)", async () => {
    fs.copyFileSync(fixture("sable-block.json"), path.join(FOLDER, "asent-report.json"));
    await until("status bar shows BLOCK", async () => (await api()).state().statusText === "$(shield) ASENT: BLOCK");
    assert.match((await api()).state().panelHtml ?? "", /invoice-data: REGRESSED/);
  });

  it("Doctor runs asent doctor --json in the home directory, not in the folder", async () => {
    await vscode.commands.executeCommand("asent.doctor");
    const doctor = callsOf("doctor").at(-1)!;
    assert.deepStrictEqual(doctor.argv, ["doctor", "--json"]);
    assert.strictEqual(fs.realpathSync(doctor.cwd), fs.realpathSync(os.homedir()));
  });

  it("Init passes the folder as --repository= (asent refuses: .asent/ exists)", async () => {
    await vscode.commands.executeCommand("asent.init");
    assert.deepStrictEqual(callsOf("init").at(-1)!.argv, ["init", "--json", `--repository=${FOLDER}`]);
  });

  it("Dashboard: one process; a second click says it is already running", async () => {
    await vscode.commands.executeCommand("asent.dashboard");
    assert.strictEqual((await api()).state().dashboardRunning, true);
    await vscode.commands.executeCommand("asent.dashboard");
    assert.deepStrictEqual(callsOf("dashboard").map((c) => c.argv), [["dashboard", "--json"]]);
  });

  it("Stop dashboard ends the process it started", async () => {
    const pid = (await api()).state().dashboardPid;
    assert.ok(pid, "the dashboard from the previous test is running");
    await vscode.commands.executeCommand("asent.stopDashboard");
    assert.strictEqual((await api()).state().dashboardRunning, false);
    await until("the stub dashboard process exits", () => {
      try {
        process.kill(pid!, 0);
        return false;
      } catch {
        return true;
      }
    });
  });

  it("Stop dashboard when none is running only says so; a new start works", async () => {
    await vscode.commands.executeCommand("asent.stopDashboard");
    assert.strictEqual((await api()).state().dashboardRunning, false);
    await vscode.commands.executeCommand("asent.dashboard");
    assert.strictEqual((await api()).state().dashboardRunning, true);
    assert.strictEqual(callsOf("dashboard").length, 2);
    await vscode.commands.executeCommand("asent.stopDashboard");
    assert.strictEqual((await api()).state().dashboardRunning, false);
  });

  it("asent missing: the command ends with a message, it does not throw or hang", async () => {
    const config = vscode.workspace.getConfiguration("asent");
    await config.update("path", path.join(FOLDER, "no-such-asent"), vscode.ConfigurationTarget.Workspace);
    try {
      const before = calls().length;
      await vscode.commands.executeCommand("asent.doctor");
      assert.strictEqual(calls().length, before);
    } finally {
      await config.update("path", (await import("./helpers")).STUB, vscode.ConfigurationTarget.Workspace);
    }
  });
});
