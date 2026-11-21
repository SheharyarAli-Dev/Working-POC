// src/diagnostics.ts: report findings -> Problems-tab locations inside the workspace folder only.
// The report's `repository` field is never used as a root; paths are resolved against the folder, symlinks
// are followed (realpath), and only an existing file inside the folder gets an entry. Real temp folders.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { locate } from "../../src/diagnostics";
import { fromJson, parseReport, Finding } from "../../src/report";
import { fixtureJson, fixtureText } from "./fixtures";

const finding = (file: string, line: number | null = null): Finding =>
  ({ module: "CAVR", file, line, severity: "error", message: "CAVR BLOCK DENYLIST: x" });

describe("Problems locations", () => {
  let dir: string;
  let folder: string;
  let outside: string;
  const write = (file: string) => {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "x\n");
  };
  beforeEach(() => {
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "asent-diag-")));
    folder = path.join(dir, "project");
    outside = path.join(dir, "outside");
    write(path.join(folder, "requirements.txt"));
    write(path.join(folder, "app", "pdf_adapter.py"));
    write(path.join(outside, "secret.txt"));
    write(path.join(dir, "home", "user", ".ssh", "config"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("CAVR BLOCK (real report): requirements.txt line 1, saying the report gives no line", () => {
    const report = parseReport(fixtureText("reports", "cavr-block.json"));
    assert.deepStrictEqual(locate(report.findings, folder), [{
      file: path.join(folder, "requirements.txt"), line: 0, severity: "error", source: "ASENT",
      message: "CAVR BLOCK DENYLIST: reqeusts is on the project denylist: typosquat of requests (file-level: the report gives no line)",
    }]);
  });

  it('"repository": "/" with file home/user/.ssh/config: no entry is created', () => {
    const json = fixtureJson("reports", "cavr-block.json");
    json.repository = "/";
    const record = json.assurance.evidence.find((e: any) => e.evidence_id === json.modules.CAVR.evidence_id);
    record.details.pipeline[0].file = "home/user/.ssh/config";
    const report = fromJson(json);
    assert.strictEqual(report.findings.length, 1, "the finding is in the report");
    assert.deepStrictEqual(locate(report.findings, folder), []);
  });

  it("a repository that contains the folder is not a root either, even when the named file exists there", () => {
    const json = fixtureJson("reports", "cavr-block.json");
    json.repository = dir; // dir/home/user/.ssh/config exists; the old code placed an entry on it
    const record = json.assurance.evidence.find((e: any) => e.evidence_id === json.modules.CAVR.evidence_id);
    record.details.pipeline[0].file = "home/user/.ssh/config";
    assert.deepStrictEqual(locate(fromJson(json).findings, folder), []);
    assert.deepStrictEqual(locate([finding("outside/secret.txt")], folder), []);
  });

  it("a symlink inside the folder that points outside it gives no entry (realpath)", () => {
    fs.symlinkSync(outside, path.join(folder, "link"));
    fs.symlinkSync(path.join(outside, "secret.txt"), path.join(folder, "secret-link.txt"));
    assert.deepStrictEqual(locate([finding("link/secret.txt"), finding("secret-link.txt")], folder), []);
  });

  it("a symlink inside the folder to a file inside it, and a folder opened through a symlink, still work", () => {
    fs.symlinkSync(path.join(folder, "requirements.txt"), path.join(folder, "req-link.txt"));
    assert.strictEqual(locate([finding("req-link.txt")], folder).length, 1);
    const opened = path.join(dir, "opened-via-link");
    fs.symlinkSync(folder, opened);
    assert.deepStrictEqual(locate([finding("requirements.txt")], opened).map((l) => l.file), [path.join(opened, "requirements.txt")]);
  });

  it("a 1-based report line becomes VS Code's 0-based line", () => {
    const [located] = locate([finding("app/pdf_adapter.py", 7)], folder);
    assert.strictEqual(located.line, 6);
    assert.strictEqual(located.message, "CAVR BLOCK DENYLIST: x");
  });

  it("paths outside the folder, absolute paths, NUL bytes, the folder itself and directories are left out", () => {
    const bad = ["../outside/secret.txt", "a/../../outside/secret.txt", path.join(folder, "requirements.txt"), "/etc/passwd",
      "C:\\x.txt", "a\0b", "", ".", "app"].map((f) => finding(f));
    assert.deepStrictEqual(locate(bad, folder), []);
  });

  it("a file that does not exist in the folder gives no entry (fail closed)", () => {
    assert.deepStrictEqual(locate([finding("no-such-file.txt"), finding("sub/requirements.txt")], folder), []);
  });
});
