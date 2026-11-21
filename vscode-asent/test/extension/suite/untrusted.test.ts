// Extension test in a real VS Code, folder NOT trusted. The workspace's own asent.path points at a path
// that does not exist; the user setting is the stub's bare name. asent-report.json (real CAVR BLOCK) is
// present, and so is a fake of that name in the folder, which runTest.ts put first on PATH (the planted-program attack).
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import * as vscode from "vscode";
import { api, callsOf, hijacked, stub, until, FOLDER, ID } from "./helpers";

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

  it("the folder's own asent (first on PATH) never ran: not on activation, not for Show report or Doctor", async () => {
    await vscode.commands.executeCommand("asent.doctor");
    assert.ok(callsOf("report").length >= 2, "activation and Show report both read the report through the stub");
    assert.strictEqual(callsOf("doctor").length, 1);
    for (const call of [...callsOf("report"), ...callsOf("doctor")]) {
      assert.strictEqual(fs.realpathSync(call.cwd), fs.realpathSync(os.homedir()), "asent runs in the home folder, not the untrusted one");
    }
    assert.strictEqual(hijacked(), false, "the untrusted folder's asent ran");
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
