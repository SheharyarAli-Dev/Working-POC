// src/cli.ts and src/args.ts: how asent is started and its one JSON document read.
import * as assert from "assert";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { runAsent, startDashboard, AsentNotFound, AsentOutputError, AsentCancelled } from "../../src/cli";
import { gateArgs, reportArgs, initArgs, doctorArgs, dashboardArgs, reportFile } from "../../src/args";
import { fixtureJson } from "./fixtures";

const STUB = path.join(__dirname, "..", "..", "..", "test", "stub", "asent");

describe("argument lists", () => {
  it("gate: --json, the report next to the folder, and the base only when it is set", () => {
    assert.deepStrictEqual(gateArgs("/w/repo", ""), ["gate", "--json", "--output-dir=/w/repo"]);
    assert.deepStrictEqual(gateArgs("/w/repo", "  "), ["gate", "--json", "--output-dir=/w/repo"]);
    assert.deepStrictEqual(gateArgs("/w/repo", "develop"), ["gate", "--json", "--output-dir=/w/repo", "--base=develop"]);
  });

  it("a base that looks like an option stays one argument value (asent refuses it as a ref: REVIEW)", () => {
    assert.deepStrictEqual(gateArgs("/w", "--repository=/etc"), ["gate", "--json", "--output-dir=/w", "--base=--repository=/etc"]);
  });

  it("shell metacharacters and spaces in paths are passed through unchanged, as one argument", () => {
    const folder = "/w/my repo; rm -rf ~ $(id) `x`";
    assert.deepStrictEqual(initArgs(folder), ["init", "--json", `--repository=${folder}`]);
    assert.deepStrictEqual(reportArgs(reportFile(folder)), ["report", "--json", `--file=${path.join(folder, "asent-report.json")}`]);
  });

  it("doctor and dashboard", () => {
    assert.deepStrictEqual(doctorArgs(), ["doctor", "--json"]);
    assert.deepStrictEqual(dashboardArgs(), ["dashboard", "--json"]);
  });
});

describe("runAsent with the stub CLI", () => {
  let dir: string;
  let log: string;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "asent-cli-test-"));
    log = path.join(dir, "argv.jsonl");
  });
  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));
  const env = (extra: Record<string, string> = {}) => ({ ...process.env, ASENT_STUB_LOG: log, ...extra });
  const calls = () => fs.readFileSync(log, "utf8").trim().split("\n").map((l) => JSON.parse(l));

  it("passes the argument array unchanged (no shell: metacharacters arrive literally)", async () => {
    const folder = path.join(dir, "a b; echo hacked > x $(id)");
    fs.mkdirSync(folder);
    const result = await runAsent(STUB, initArgs(folder), { cwd: folder, env: env() });
    assert.strictEqual(result.exitCode, 0);
    assert.deepStrictEqual(calls()[0].argv, ["init", "--json", `--repository=${folder}`]);
    assert.ok(!fs.existsSync(path.join(folder, "x")), "a shell would have created x");
  });

  it("gate: exit 1 is a result, not an error, and the JSON is the BLOCK report", async () => {
    const result = await runAsent(STUB, gateArgs(dir, ""), { cwd: dir, env: env({ ASENT_STUB_GATE: "cavr-block.json" }) });
    assert.strictEqual(result.exitCode, 1);
    assert.deepStrictEqual(result.json, fixtureJson("reports", "cavr-block.json"));
    assert.strictEqual(calls()[0].cwd, fs.realpathSync(dir));
  });

  it("doctor: exit 1 (not ready) still gives its JSON", async () => {
    const result = await runAsent(STUB, doctorArgs(), { cwd: dir, env: env() });
    assert.strictEqual(result.exitCode, 1);
    assert.strictEqual((result.json as any).ready, false);
  });

  it("a missing executable is AsentNotFound naming the configured path", async () => {
    const missing = path.join(dir, "no-such-asent");
    await assert.rejects(runAsent(missing, doctorArgs(), { cwd: dir }),
      (e: unknown) => e instanceof AsentNotFound && e.asentPath === missing);
    await assert.rejects(runAsent("asent-definitely-not-on-path-xyz", doctorArgs(), { cwd: dir }), AsentNotFound);
  });

  it("a file that is not executable is AsentNotFound too, with the reason", async () => {
    const plain = path.join(dir, "asent");
    fs.writeFileSync(plain, "not a program");
    await assert.rejects(runAsent(plain, doctorArgs(), { cwd: dir }), (e: unknown) => e instanceof AsentNotFound && /EACCES/.test(e.message));
  });

  it("output that is not JSON is AsentOutputError with the exit code and the end of stderr", async () => {
    await assert.rejects(runAsent(STUB, doctorArgs(), { cwd: dir, env: env({ ASENT_STUB_MODE: "not-json" }) }),
      (e: unknown) => e instanceof AsentOutputError && e.exitCode === 2);
    await assert.rejects(runAsent(STUB, doctorArgs(), { cwd: dir, env: env({ ASENT_STUB_MODE: "stderr-crash" }) }),
      (e: unknown) => e instanceof AsentOutputError && /No module named 'httpx'/.test(e.message));
  });

  it("cancellation kills the process and rejects with AsentCancelled", async () => {
    const controller = new AbortController();
    const started = Date.now();
    const run = runAsent(STUB, gateArgs(dir, ""), { cwd: dir, env: env({ ASENT_STUB_MODE: "hang" }), signal: controller.signal });
    setTimeout(() => controller.abort(), 200);
    await assert.rejects(run, (e: unknown) => e instanceof AsentCancelled && e.reason === "cancelled");
    assert.ok(Date.now() - started < 5000);
  });

  it("a timeout kills the process and rejects with AsentCancelled(timed out)", async () => {
    await assert.rejects(runAsent(STUB, gateArgs(dir, ""), { cwd: dir, env: env({ ASENT_STUB_MODE: "hang" }), timeoutMs: 300 }),
      (e: unknown) => e instanceof AsentCancelled && e.reason === "timed out");
  });

  it("refuses an argument with a NUL byte before starting anything", async () => {
    await assert.rejects(runAsent(STUB, ["report", "--json", "--file=a\0b"], { cwd: dir, env: env() }), /NUL/);
    assert.ok(!fs.existsSync(log));
  });
});

describe("startDashboard with the stub CLI", () => {
  it("returns the URL line and keeps the process running until stopped", async () => {
    const dashboard = await startDashboard(STUB, dashboardArgs(), { cwd: os.tmpdir() });
    try {
      assert.deepStrictEqual(dashboard.info, fixtureJson("dashboard", "dashboard.json"));
      assert.strictEqual(dashboard.process.exitCode, null, "still serving");
    } finally {
      dashboard.stop();
    }
    await new Promise((resolve) => dashboard.process.once("exit", resolve));
  });

  it("a busy port is an error with asent's own message", async () => {
    await assert.rejects(startDashboard(STUB, dashboardArgs(), { cwd: os.tmpdir(), env: { ...process.env, ASENT_STUB_MODE: "dashboard-busy" } }),
      /port 8000 on 127\.0\.0\.1 is already in use/);
  });

  it("a missing executable is AsentNotFound", async () => {
    await assert.rejects(startDashboard("/nonexistent/asent", dashboardArgs(), { cwd: os.tmpdir() }), AsentNotFound);
  });
});

// The real CLI, only when ASENT_REAL is set (e.g. ASENT_REAL=../scripts/asent ASENT_PYTHON=../.venv/bin/python):
// checks that the real asent accepts the exact argument forms above (--file=, --json) and prints one JSON document.
const real = process.env.ASENT_REAL ? describe : describe.skip;
real("the real asent CLI (ASENT_REAL)", () => {
  it("doctor --json prints its schema", async () => {
    const result = await runAsent(process.env.ASENT_REAL!, doctorArgs(), { cwd: os.tmpdir(), timeoutMs: 60000 });
    assert.strictEqual((result.json as any).schema, "asent.doctor.v1");
  });

  it("report --json --file=<a real report> prints that report", async () => {
    const file = path.join(__dirname, "..", "..", "..", "test", "fixtures", "reports", "cavr-block.json");
    const result = await runAsent(process.env.ASENT_REAL!, reportArgs(file), { cwd: os.tmpdir(), timeoutMs: 60000 });
    assert.strictEqual(result.exitCode, 0);
    assert.deepStrictEqual(result.json, fixtureJson("reports", "cavr-block.json"));
  });

  it("gate --json --output-dir= --base= on a repository without .asent/ is REVIEW, and the report is written", async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "asent-real-gate-"));
    try {
      const { execFileSync } = await import("child_process");
      const git = (...a: string[]) => execFileSync("git", ["-c", "user.email=t@example.invalid", "-c", "user.name=t", ...a], { cwd: repo });
      git("init", "-q", "-b", "main");
      fs.writeFileSync(path.join(repo, "README.md"), "x\n");
      git("add", "-A");
      git("commit", "-q", "-m", "x");
      const result = await runAsent(process.env.ASENT_REAL!, gateArgs(repo, "main"), { cwd: repo, timeoutMs: 120000 });
      assert.strictEqual(result.exitCode, 2);
      assert.strictEqual((result.json as any).decision, "REVIEW");
      assert.strictEqual((result.json as any).base.ref, "main");
      assert.ok(((result.json as any).reasons as string[]).some((r) => r.includes("ASENT_CONFIG_MISSING")));
      assert.deepStrictEqual(JSON.parse(fs.readFileSync(reportFile(repo), "utf8")), result.json);
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  it("init --json --repository= writes a starter", async () => {
    const repo = fs.mkdtempSync(path.join(os.tmpdir(), "asent-real-init-"));
    try {
      const result = await runAsent(process.env.ASENT_REAL!, initArgs(repo), { cwd: repo, timeoutMs: 60000 });
      assert.strictEqual(result.exitCode, 0);
      assert.strictEqual((result.json as any).starter, true);
      assert.ok(fs.existsSync(path.join(repo, ".asent", "config.json")));
    } finally {
      fs.rmSync(repo, { recursive: true, force: true });
    }
  });

  it("report --json on a missing file gives asent's own error JSON", async () => {
    const result = await runAsent(process.env.ASENT_REAL!, reportArgs("/nonexistent/asent-report.json"), { cwd: os.tmpdir(), timeoutMs: 60000 });
    assert.strictEqual(result.exitCode, 2);
    assert.match((result.json as any).error, /No ASENT report at/);
  });
});
