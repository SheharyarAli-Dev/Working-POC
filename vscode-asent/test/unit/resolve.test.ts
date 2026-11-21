// src/cli.ts resolveAsent: a bare asent.path is looked up on PATH by the extension itself, never in the
// workspace folder, so a repository cannot plant its own `asent` / `asent.exe` (Windows searches the child's
// cwd before PATH; a "." or empty PATH entry does the same on Linux and macOS).
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { resolveAsent, runAsent, AsentNotFound } from "../../src/cli";
import { doctorArgs } from "../../src/args";

const STUB = path.join(__dirname, "..", "..", "..", "test", "stub", "asent");
const notFound = (code: string, asentPath = "asent") => (e: unknown) =>
  e instanceof AsentNotFound && e.code === code && e.asentPath === asentPath;

describe("resolveAsent, POSIX rules (real files)", () => {
  let dir: string;
  let workspace: string;
  let bin: string;
  const fake = (folder: string) => {
    fs.mkdirSync(folder, { recursive: true });
    const file = path.join(folder, "asent");
    fs.writeFileSync(file, `#!/bin/sh\necho hijacked > "${path.join(dir, "HIJACKED")}"\nexit 2\n`, { mode: 0o755 });
    return file;
  };
  const posix = (PATH: string, excluded = [workspace]) => resolveAsent("asent", { platform: "linux", env: { PATH }, excluded });
  beforeEach(() => {
    dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "asent-resolve-")));
    workspace = path.join(dir, "workspace");
    bin = path.join(dir, "bin");
    fake(workspace);
    fake(path.join(workspace, "tools"));
    fs.mkdirSync(bin);
    fs.symlinkSync(STUB, path.join(bin, "asent"));
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it("skips the workspace folder, folders inside it, empty, '.' and relative entries; finds the one on PATH", () => {
    const PATH = [workspace, "", ".", "tools", "./tools", path.join(workspace, "tools"), bin].join(":");
    assert.strictEqual(posix(PATH), path.join(bin, "asent"));
  });

  it("the fake asent in the workspace folder is never run: runAsent with the resolved path and cwd = workspace", async () => {
    const log = path.join(dir, "argv.jsonl");
    const resolved = posix([workspace, ".", bin].join(":"));
    const result = await runAsent(resolved, doctorArgs(), { cwd: workspace, env: { ...process.env, ASENT_STUB_LOG: log } });
    assert.strictEqual((result.json as { schema: string }).schema, "asent.doctor.v1", "the stub answered");
    assert.ok(fs.existsSync(log), "the stub logged the call");
    assert.ok(!fs.existsSync(path.join(dir, "HIJACKED")), "the workspace's asent ran");
  });

  it("only workspace, '.' and empty entries: asent not found (even when the current directory has one)", () => {
    const cwd = process.cwd();
    process.chdir(workspace);
    try {
      assert.throws(() => posix([workspace, "", ".", path.join(workspace, "tools")].join(":")), notFound("ENOENT"));
      assert.throws(() => posix("", []), notFound("ENOENT"));
      assert.throws(() => posix(".", []), notFound("ENOENT"));
    } finally {
      process.chdir(cwd);
    }
  });

  it("a PATH entry that is a symlink into the workspace is skipped (realpath)", () => {
    const link = path.join(dir, "link-to-workspace");
    fs.symlinkSync(workspace, link);
    assert.throws(() => posix(link), notFound("ENOENT"));
  });

  it("an asent on PATH that is a symlink to a file in the workspace is skipped (realpath)", () => {
    const other = path.join(dir, "other");
    fs.mkdirSync(other);
    fs.symlinkSync(path.join(workspace, "asent"), path.join(other, "asent"));
    assert.throws(() => posix(other), notFound("ENOENT"));
    assert.strictEqual(posix([other, bin].join(":")), path.join(bin, "asent"));
  });

  it("a non-executable file or a directory named asent is passed over", () => {
    const plain = path.join(dir, "plain");
    fs.mkdirSync(path.join(plain, "asent"), { recursive: true });
    const noexec = path.join(dir, "noexec");
    fs.mkdirSync(noexec);
    fs.writeFileSync(path.join(noexec, "asent"), "not a program", { mode: 0o644 });
    assert.strictEqual(posix([plain, noexec, bin].join(":")), path.join(bin, "asent"));
  });

  it("an absolute asent.path is used as it is; a relative path with a separator is refused", () => {
    assert.strictEqual(resolveAsent(STUB, { platform: "linux", env: { PATH: "" }, excluded: [workspace] }), STUB);
    for (const relative of ["./asent", "tools/asent", "../asent"]) {
      assert.throws(() => resolveAsent(relative, { platform: "linux", env: { PATH: bin }, excluded: [workspace] }),
        notFound("NOT_ABSOLUTE", relative));
    }
  });
});

describe("resolveAsent, Windows rules (fake file system)", () => {
  const W = "C:\\Users\\me\\proj";
  const exists = (files: string[]) => (f: string) => files.includes(f);
  const win = (env: NodeJS.ProcessEnv, files: string[], configured = "asent") =>
    resolveAsent(configured, { platform: "win32", env, excluded: [W], isExecutable: exists(files), realpath: (p) => p });

  it("asent.exe in the workspace folder, below it (any letter case), in '.', or in a relative entry is never chosen", () => {
    const Path = [W, "", ".", ".\\tools", "tools", "c:\\users\\ME\\PROJ\\tools", "\"C:\\Program Files\\asent\"", "C:\\Tools"].join(";");
    const files = [`${W}\\asent.exe`, ".\\asent.exe", ".\\tools\\asent.exe", "tools\\asent.exe", "c:\\users\\ME\\PROJ\\tools\\asent.exe",
      "C:\\Program Files\\asent\\asent.exe", "C:\\Tools\\asent.exe"];
    assert.strictEqual(win({ Path }, files), "C:\\Program Files\\asent\\asent.exe", "quoted entry, read from the 'Path' key");
  });

  it("only workspace entries: asent not found", () => {
    assert.throws(() => win({ PATH: `${W};${W}\\bin;.;` }, [`${W}\\asent.exe`, `${W}\\bin\\asent.exe`, ".\\asent.exe"]), notFound("ENOENT"));
  });

  it("a bare name tries .com then .exe; a name with an extension is tried as it is", () => {
    assert.strictEqual(win({ PATH: "C:\\Tools" }, ["C:\\Tools\\asent.com", "C:\\Tools\\asent.exe"]), "C:\\Tools\\asent.com");
    assert.strictEqual(win({ PATH: "C:\\Tools" }, ["C:\\Tools\\asent.exe"]), "C:\\Tools\\asent.exe");
    assert.strictEqual(win({ PATH: "C:\\Tools" }, ["C:\\Tools\\asent.exe"], "asent.exe"), "C:\\Tools\\asent.exe");
    assert.throws(() => win({ PATH: "C:\\Tools" }, ["C:\\Tools\\asent"]), notFound("ENOENT"), "no extension-less file on Windows");
  });

  it("an absolute path is used as it is; relative and drive-relative paths are refused", () => {
    assert.strictEqual(win({ PATH: "" }, [], "D:\\asent\\asent.exe"), "D:\\asent\\asent.exe");
    for (const relative of ["tools\\asent.exe", ".\\asent.exe", "C:asent.exe", "tools/asent"]) {
      assert.throws(() => win({ PATH: "C:\\Tools" }, ["C:\\Tools\\asent.exe"], relative), notFound("NOT_ABSOLUTE", relative));
    }
  });
});
