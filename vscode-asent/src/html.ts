// The dashboard panel's HTML, built here from a parsed report. The webview runs no script at all
// (enableScripts: false and script-src 'none'), loads nothing (default-src 'none'), and its only style
// is one inline <style> allowed by a per-render nonce. Colours are VS Code's theme variables, so the
// panel follows light, dark and high-contrast themes. Every value from the report is escaped.
// No vscode import (unit-tested in plain Node).
import { GateReport, ModuleCard } from "./report";

export function escapeHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

export function csp(nonce: string): string {
  return `default-src 'none'; style-src 'nonce-${nonce}'; img-src 'none'; font-src 'none'; script-src 'none'; ` +
    `frame-src 'none'; form-action 'none'; base-uri 'none'`;
}

const e = (v: string | null | undefined, empty = "—") => escapeHtml(v ?? empty);
const short = (sha: string | null) => (sha ? sha.slice(0, 12) : "unresolved");
const resultClass = (r: string | null) => (r === "pass" ? "pass" : r === "block" ? "block" : r === "review" ? "review" : "muted");

const STYLE = `
:root { color-scheme: light dark; }
body { font-family: var(--vscode-font-family, sans-serif); font-size: var(--vscode-font-size, 13px);
  color: var(--vscode-foreground); background: var(--vscode-editor-background); margin: 0; padding: 16px 20px 32px; }
.banner { border: 1px solid var(--vscode-panel-border, transparent); border-left-width: 8px; border-radius: 4px;
  padding: 14px 18px; margin-bottom: 16px; background: var(--vscode-editorWidget-background); }
.banner h1 { font-size: 2.6em; letter-spacing: 0.06em; margin: 0 0 4px; }
.banner.accept { border-left-color: var(--vscode-testing-iconPassed); } .banner.accept h1 { color: var(--vscode-testing-iconPassed); }
.banner.review { border-left-color: var(--vscode-editorWarning-foreground); } .banner.review h1 { color: var(--vscode-editorWarning-foreground); }
.banner.block { border-left-color: var(--vscode-errorForeground); } .banner.block h1 { color: var(--vscode-errorForeground); }
.sub, .note, dt { color: var(--vscode-descriptionForeground); }
.banner ul { margin: 8px 0 0; padding-left: 20px; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 12px; margin-bottom: 16px; }
.card { border: 1px solid var(--vscode-widget-border, var(--vscode-panel-border, transparent)); border-radius: 4px;
  padding: 12px 14px; background: var(--vscode-sideBar-background, var(--vscode-editor-background)); min-width: 0; }
.card h2 { font-size: 1.15em; margin: 0 0 6px; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 9px; font-weight: 600; border: 1px solid currentColor; }
.chip.pass { color: var(--vscode-testing-iconPassed); } .chip.block { color: var(--vscode-errorForeground); }
.chip.review { color: var(--vscode-editorWarning-foreground); } .chip.muted { color: var(--vscode-descriptionForeground); }
.card p { margin: 8px 0; overflow-wrap: anywhere; }
.card ul { margin: 6px 0 0; padding-left: 18px; } .card li { margin: 2px 0; overflow-wrap: anywhere; }
code, .mono { font-family: var(--vscode-editor-font-family, monospace); font-size: 0.95em; overflow-wrap: anywhere; }
dl { display: grid; grid-template-columns: max-content 1fr; gap: 4px 14px; margin: 0; }
dd { margin: 0; overflow-wrap: anywhere; }
`;

function card(m: ModuleCard): string {
  const evidence = m.evidence.length
    ? `<ul>${m.evidence.map((line) => `<li><span class="mono">${escapeHtml(line)}</span></li>`).join("")}</ul>`
    : `<p class="note">No evidence record${m.assessed ? "" : " (not assessed)"}.</p>`;
  return `<article class="card">
  <h2>${escapeHtml(m.title)}</h2>
  <span class="chip ${resultClass(m.result)}">${e(m.result, "unknown")}</span>
  <span class="sub">status ${e(m.status)}</span>
  <p>${e(m.reason, "No reason in the report.")}</p>
  ${evidence}
</article>`;
}

function page(nonce: string, body: string): string {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(nonce)) throw new Error("nonce must be base64");
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="${csp(nonce)}">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ASENT</title>
<style nonce="${nonce}">${STYLE}</style>
</head>
<body>
${body}
</body>
</html>`;
}

export interface PanelOptions {
  nonce: string;
  message?: string; // shown instead of a report (no report yet, or why it could not be read)
}

export function renderPanel(report: GateReport | null, options: PanelOptions): string {
  if (!report) {
    return page(options.nonce, `<p class="note">${e(options.message, "No ASENT report.")}</p>`);
  }
  const d = report.decision;
  const reasons = report.reasons.length ? `<ul>${report.reasons.map((r) => `<li>${escapeHtml(r)}</li>`).join("")}</ul>` : "";
  const changed = report.configChangedInHead === null ? "unknown" : report.configChangedInHead ? "yes" : "no";
  const problems = report.configProblems.map((p) => `<dt>Config problem</dt><dd>${escapeHtml(p)}</dd>`).join("");
  const body = `
<section class="banner ${d.toLowerCase()}" aria-label="Gate decision">
  <h1>${d}</h1>
  <div class="sub">exit ${report.exitCode ?? "—"} · ${e(report.generatedAt)} · ASENT ${e(report.asentVersion)}</div>
  ${reasons}
</section>
<section class="cards">
${report.modules.map(card).join("\n")}
</section>
<section class="card">
  <dl>
    <dt>Repository</dt><dd class="mono">${e(report.repository)}</dd>
    <dt>Base</dt><dd><code>${e(report.base.ref)}</code> (<code>${escapeHtml(short(report.base.sha))}</code>) <span class="note mono">${e(report.base.sha, "")}</span></dd>
    <dt>Head</dt><dd><code>${e(report.head.ref)}</code> (<code>${escapeHtml(short(report.head.sha))}</code>) <span class="note mono">${e(report.head.sha, "")}</span></dd>
    <dt>Config digest</dt><dd class="mono">${e(report.configDigest, "none")}</dd>
    <dt>Config source</dt><dd>${e(report.configSource, "base .asent/ (not loaded)")}</dd>
    <dt>Config changed in head</dt><dd>${changed}</dd>
    ${problems}
  </dl>
</section>
<p class="note">Shown as asent wrote it in asent-report.json. A decision covers only the assessed modules' supported
obligations for this exact head commit; it is not a statement of general safety.</p>`;
  return page(options.nonce, body);
}
