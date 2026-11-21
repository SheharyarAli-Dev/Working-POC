// package.json is the contract with VS Code: commands, settings, activation, trust and where it runs.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "..", "package.json"), "utf8"));

describe("package.json manifest", () => {
  it("contributes exactly the five ASENT commands with their titles", () => {
    const titles = Object.fromEntries(manifest.contributes.commands.map((c: { command: string; title: string }) => [c.command, c.title]));
    assert.deepStrictEqual(titles, {
      "asent.init": "ASENT: Init project",
      "asent.gate": "ASENT: Run gate on this branch",
      "asent.showReport": "ASENT: Show report",
      "asent.doctor": "ASENT: Doctor",
      "asent.dashboard": "ASENT: Open web dashboard",
    });
  });

  it("has the two settings with their defaults", () => {
    const props = manifest.contributes.configuration.properties;
    assert.deepStrictEqual(Object.keys(props).sort(), ["asent.baseBranch", "asent.path"]);
    assert.strictEqual(props["asent.path"].default, "asent");
    assert.strictEqual(props["asent.baseBranch"].default, "");
  });

  it("runs on the workspace side (WSL / Remote), where asent is installed", () => {
    assert.deepStrictEqual(manifest.extensionKind, ["workspace"]);
  });

  it("activates only for a folder with .asent/ or asent-report.json (commands activate implicitly)", () => {
    assert.deepStrictEqual(manifest.activationEvents.sort(), ["workspaceContains:.asent/**", "workspaceContains:asent-report.json"]);
  });

  it("supports untrusted folders only in limited mode, and ignores a workspace asent.path there", () => {
    const untrusted = manifest.capabilities.untrustedWorkspaces;
    assert.strictEqual(untrusted.supported, "limited");
    assert.deepStrictEqual(untrusted.restrictedConfigurations, ["asent.path", "asent.baseBranch"]);
  });

  it("pins every dependency to an exact version", () => {
    for (const [name, version] of Object.entries({ ...manifest.dependencies, ...manifest.devDependencies })) {
      assert.match(String(version), /^\d+\.\d+\.\d+$/, `${name}@${version} is not an exact version`);
    }
  });

  it("has no runtime dependencies (nothing in the .vsix but this extension's own code)", () => {
    assert.deepStrictEqual(manifest.dependencies ?? {}, {});
  });
});
