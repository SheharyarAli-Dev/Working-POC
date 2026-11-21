// src/html.ts: the dashboard panel's HTML. No scripts, strict CSP, everything from the report escaped.
import * as assert from "assert";
import { renderPanel, escapeHtml, csp } from "../../src/html";
import { parseReport, fromJson } from "../../src/report";
import { fixtureJson, fixtureText } from "./fixtures";

const NONCE = "bm9uY2Utb2YtdGhlLXRlc3Q=";
const render = (name: string) => renderPanel(parseReport(fixtureText("reports", name)), { nonce: NONCE });

describe("panel HTML", () => {
  it("strict CSP: nothing but the one nonce'd inline style; no scripts at all", () => {
    assert.strictEqual(csp(NONCE), `default-src 'none'; style-src 'nonce-${NONCE}'; img-src 'none'; font-src 'none'; script-src 'none'; frame-src 'none'; form-action 'none'; base-uri 'none'`);
    for (const name of ["accept.json", "cavr-block.json", "review.json", "sable-block.json"]) {
      const html = render(name);
      assert.ok(html.includes(`<meta http-equiv="Content-Security-Policy" content="${csp(NONCE)}">`), name);
      assert.doesNotMatch(html, /<script/i);
      assert.doesNotMatch(html, /\son[a-z]+=/i, "no inline event handlers");
      assert.doesNotMatch(html, /\s(src|href|action)=/i, "no resource or link attributes");
      assert.doesNotMatch(html, /@import|url\(/i, "no remote fonts or stylesheets");
      assert.strictEqual((html.match(/<style/g) ?? []).length, 1);
      assert.ok(html.includes(`<style nonce="${NONCE}">`));
    }
  });

  it("colours come only from VS Code theme variables (light, dark and high contrast follow the theme)", () => {
    const style = render("accept.json").match(/<style[^>]*>([\s\S]*?)<\/style>/)![1];
    assert.doesNotMatch(style.replace(/var\(--vscode-[a-zA-Z0-9-]+(, *[^)]+)?\)/g, ""), /#[0-9a-f]{3,8}\b|rgb\(|hsl\(/i);
    assert.match(style, /var\(--vscode-editor-background/);
    assert.match(style, /var\(--vscode-font-family/);
  });

  it("ACCEPT: big banner, three cards, commits and config digest", () => {
    const raw = fixtureJson("reports", "accept.json");
    const html = render("accept.json");
    assert.match(html, /<section class="banner accept"[^>]*>\s*<h1>ACCEPT<\/h1>/);
    for (const title of ["CAVR", "SATRA-RV", "SABLE"]) assert.ok(html.includes(`<h2>${title}</h2>`), title);
    assert.ok(html.includes(raw.base.sha) && html.includes(raw.head.sha) && html.includes(raw.config.digest));
    assert.ok(html.includes("not assessed (disabled by base config)"));
    assert.ok(html.includes("pypdf==6.19.0: VERIFIED, sha256 7e5d6e730e7d"));
  });

  it("BLOCK and REVIEW banners carry their own class", () => {
    assert.match(render("cavr-block.json"), /<section class="banner block"[^>]*>\s*<h1>BLOCK<\/h1>/);
    assert.match(render("review.json"), /<section class="banner review"[^>]*>\s*<h1>REVIEW<\/h1>/);
    assert.match(render("review.json"), /Config changed in head<\/dt><dd>yes/);
  });

  it("text from the report is escaped (a report cannot inject markup)", () => {
    const raw = fixtureJson("reports", "cavr-block.json");
    raw.reasons = [`<script>alert(1)</script>`];
    raw.modules.CAVR.reason = `<img src=x onerror=alert(1)>"'&`;
    const html = renderPanel(fromJson(raw), { nonce: NONCE });
    assert.doesNotMatch(html, /<script|<img/i);
    assert.ok(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
    assert.ok(html.includes("&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&amp;"));
  });

  it("escapeHtml", () => {
    assert.strictEqual(escapeHtml(`<a href="x">'&'</a>`), "&lt;a href=&quot;x&quot;&gt;&#39;&amp;&#39;&lt;/a&gt;");
  });

  it("no report yet: a plain message, still no scripts", () => {
    const html = renderPanel(null, { nonce: NONCE, message: "No asent-report.json <here>" });
    assert.ok(html.includes("No asent-report.json &lt;here&gt;"));
    assert.doesNotMatch(html, /<script|<h1>(ACCEPT|BLOCK|REVIEW)/);
  });

  it("a nonce that is not base64 is refused (it is placed inside the CSP)", () => {
    assert.throws(() => renderPanel(null, { nonce: "x'; script-src *" }), /nonce/);
  });
});
