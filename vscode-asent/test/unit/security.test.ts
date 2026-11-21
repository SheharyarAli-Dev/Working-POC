// Static checks of src/: the extension only starts asent (argument array, no shell), sends nothing
// anywhere, stores no tokens or data, and its webview runs no script.
import * as assert from "assert";
import * as fs from "fs";
import * as path from "path";

const SRC = path.join(__dirname, "..", "..", "..", "src");
const files = fs.readdirSync(SRC).filter((f) => f.endsWith(".ts"));
const code = (f: string) => fs.readFileSync(path.join(SRC, f), "utf8").replace(/^\s*\/\/.*$/gm, ""); // without line comments
const all = files.map((f) => [f, code(f)] as const);

describe("security properties of src/", () => {
  it("has the expected modules", () => {
    assert.deepStrictEqual(files.sort(), ["args.ts", "cli.ts", "diagnostics.ts", "doctor.ts", "extension.ts", "html.ts", "panel.ts", "report.ts"]);
  });

  it("processes are started only in cli.ts, only with spawn, and never through a shell", () => {
    for (const [f, text] of all) {
      assert.doesNotMatch(text, /shell:\s*true/, f);
      assert.doesNotMatch(text, /\b(exec|execSync|execFile|execFileSync|spawnSync|fork)\s*\(/, f);
      if (f !== "cli.ts") assert.doesNotMatch(text, /child_process|\bspawn\s*\(/, f);
    }
    assert.match(code("cli.ts"), /shell:\s*false/);
  });

  it("no network: no http/https/net/tls/dgram modules, no fetch, no sockets", () => {
    for (const [f, text] of all) {
      assert.doesNotMatch(text, /from\s+["'](node:)?(http|https|http2|net|tls|dgram|undici)["']|require\(["'](node:)?(http|https|net|tls|dgram)["']\)/, f);
      assert.doesNotMatch(text, /\bfetch\s*\(|XMLHttpRequest|WebSocket/, f);
    }
  });

  it("stores nothing: no SecretStorage, globalState, workspaceState or configuration writes", () => {
    for (const [f, text] of all) {
      assert.doesNotMatch(text, /\.secrets\b|SecretStorage|globalState|workspaceState|\.update\s*\(/, f);
    }
  });

  it("the webview never enables scripts, command URIs or local resources", () => {
    const panel = code("panel.ts");
    assert.match(panel, /enableScripts:\s*false/);
    assert.match(panel, /enableCommandUris:\s*false/);
    assert.match(panel, /localResourceRoots:\s*\[\]/);
    for (const [f, text] of all) assert.doesNotMatch(text, /enableScripts:\s*true|postMessage|onDidReceiveMessage/, f);
  });

  it("only one place opens a URL, and only the dashboard's 127.0.0.1 address", () => {
    const uses = all.filter(([, text]) => /openExternal/.test(text));
    assert.deepStrictEqual(uses.map(([f]) => f), ["extension.ts"]);
    assert.strictEqual((code("extension.ts").match(/openExternal/g) ?? []).length, 1);
    assert.match(code("extension.ts"), /LOCAL_DASHBOARD = \/\^http:\\\/\\\/127\\\.0\\\.0\\\.1:\\d\{1,5\}\\\/\$\//);
  });
});
