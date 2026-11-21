// src/diagnostics.ts: report findings -> Problems-tab locations inside the workspace folder only.
import * as assert from "assert";
import * as path from "path";
import { locate, diagnosticRoot } from "../../src/diagnostics";
import { parseReport, Finding } from "../../src/report";
import { fixtureText } from "./fixtures";

const finding = (file: string, line: number | null = null): Finding =>
  ({ module: "CAVR", file, line, severity: "error", message: "CAVR BLOCK DENYLIST: x" });

describe("Problems locations", () => {
  it("CAVR BLOCK (real report): requirements.txt line 1, saying the report gives no line", () => {
    const report = parseReport(fixtureText("reports", "cavr-block.json"));
    const folder = path.resolve("/w/project");
    assert.deepStrictEqual(locate(report.findings, folder, report.repository), [{
      file: path.join(folder, "requirements.txt"), line: 0, severity: "error", source: "ASENT",
      message: "CAVR BLOCK DENYLIST: reqeusts is on the project denylist: typosquat of requests (file-level: the report gives no line)",
    }]);
  });

  it("a 1-based report line becomes VS Code's 0-based line", () => {
    assert.strictEqual(locate([finding("app/pdf_adapter.py", 7)], "/w", null)[0].line, 6);
    assert.strictEqual(locate([finding("app/pdf_adapter.py", 7)], "/w", null)[0].message, "CAVR BLOCK DENYLIST: x");
  });

  it("paths outside the folder, absolute paths and NUL bytes are left out", () => {
    const bad = ["../outside.txt", "a/../../outside.txt", "/etc/passwd", "C:\\x.txt", "a\0b", ""].map((f) => finding(f));
    assert.deepStrictEqual(locate(bad, path.resolve("/w/project"), null), []);
  });

  it("report paths are relative to the gated repository top level when the folder is inside it", () => {
    assert.strictEqual(diagnosticRoot(path.resolve("/w/repo/sub"), path.resolve("/w/repo")), path.resolve("/w/repo"));
    assert.strictEqual(diagnosticRoot(path.resolve("/w/repo"), path.resolve("/w/repo")), path.resolve("/w/repo"));
    const located = locate([finding("sub/requirements.txt")], path.resolve("/w/repo/sub"), path.resolve("/w/repo"));
    assert.strictEqual(located[0].file, path.resolve("/w/repo/sub/requirements.txt"));
  });

  it("a report written elsewhere (another machine, a temp folder) is placed relative to the workspace folder", () => {
    assert.strictEqual(diagnosticRoot(path.resolve("/w/repo"), "/tmp/asent-fixture-x/repo"), path.resolve("/w/repo"));
    assert.strictEqual(diagnosticRoot(path.resolve("/w/repo"), null), path.resolve("/w/repo"));
    assert.strictEqual(diagnosticRoot(path.resolve("/w/repo"), "relative/path"), path.resolve("/w/repo"));
  });
});
