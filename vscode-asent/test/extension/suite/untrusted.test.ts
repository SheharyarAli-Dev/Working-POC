// Extension test in a real VS Code, folder NOT trusted. The workspace's own asent.path points at a path
// that does not exist; the user settings point at the stub. asent-report.json (real CAVR BLOCK) is present.
import * as assert from "assert";
import * as path from "path";
import * as vscode from "vscode";
import { api, callsOf, stub, until, FOLDER, ID } from "./helpers";

describe("ASENT extension (untrusted folder)", () => {
  before(() => stub({ gate: "accept.json" }));

  it("the folder is not trusted, and the extension still activates (limited support)", async () => {
    assert.strictEqual(vscode.workspace.isTrusted, false);
    await until("activation", () => vscode.extensions.getExtension(ID)?.isActive === true);
  });

  it("the existing report is shown: read with the USER asent.path (the workspace's value is ignored)", async () => {
    await until("status bar shows BLOCK", async () => (await api()).state().statusText === "$(shield) ASENT: BLOCK");
    await vscode.commands.executeCommand("asent.showReport");
    assert.deepStrictEqual(callsOf("report").at(-1)!.argv, ["report", "--json", `--file=${path.join(FOLDER, "asent-report.json")}`]);
    assert.match((await api()).state().panelHtml ?? "", /<h1>BLOCK<\/h1>/);
  });

  it("Run gate, Init and Dashboard are refused before asent is started", async () => {
    for (const command of ["asent.gate", "asent.init", "asent.dashboard"]) await vscode.commands.executeCommand(command);
    assert.deepStrictEqual(callsOf("gate"), []);
    assert.deepStrictEqual(callsOf("init"), []);
    assert.deepStrictEqual(callsOf("dashboard"), []);
    assert.strictEqual((await api()).state().dashboardRunning, false);
    assert.strictEqual((await api()).state().decision, "BLOCK", "the shown report is unchanged");
  });

  it("Stop dashboard is allowed (it runs nothing) and, with none running, starts nothing", async () => {
    await vscode.commands.executeCommand("asent.stopDashboard");
    assert.deepStrictEqual(callsOf("dashboard"), []);
    assert.strictEqual((await api()).state().dashboardRunning, false);
  });
});
