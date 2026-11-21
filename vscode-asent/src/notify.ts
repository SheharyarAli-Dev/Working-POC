// The text of VS Code notifications. A notification renders [label](uri) as a clickable link, command: URIs
// included, so text that comes from a report or from asent's output (reasons, error JSON, stderr) is cleaned
// here before it is shown: brackets and parentheses removed, anything that looks like a link or a URI removed,
// one line, at most MAX_NOTIFICATION characters. The panel (escaped HTML, no command URIs) shows the full text.
// No vscode import (unit-tested in plain Node).
import { AsentNotFound, AsentCancelled } from "./cli";
import { GateReport } from "./report";

export const MAX_NOTIFICATION = 160;

const BRACKETS = /[[\]()]/g;
const SCHEME_URI = /[a-z][a-z0-9+.-]*:\/\/\S*/gi; // https://..., vscode://..., file:///..., ftp://...
const KNOWN_SCHEME = /(?:command|vscode|vscode-insiders|file|https?|javascript|vbscript|data|mailto):\S+/gi; // command:x, data:...
const WWW = /www\.\S+/gi;
const NOT_PRINTABLE = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/g;

/** One short line without brackets, parentheses or links; repeated until nothing changes (removal can join pieces). */
export function notificationText(text: string, max = MAX_NOTIFICATION): string {
  let s = String(text).replace(NOT_PRINTABLE, " ");
  for (let previous = ""; previous !== s;) {
    previous = s;
    s = s.replace(BRACKETS, "").replace(SCHEME_URI, " ").replace(KNOWN_SCHEME, " ").replace(WWW, " ");
  }
  s = s.replace(/\s+/g, " ").trim();
  return s.length > max ? s.slice(0, max - 1).trimEnd() + "…" : s;
}

/** "ASENT gate: BLOCK: <first reason>" after a gate run. */
export function gateNotification(report: GateReport): string {
  return notificationText(`ASENT gate: ${report.decision}` + (report.reasons.length ? `: ${report.reasons[0]}` : ""));
}

/** The notification for an error a command ended with (the ASENT output keeps the full message). */
export function errorNotification(e: unknown): string {
  if (e instanceof AsentNotFound) {
    const what = e.code === "ENOENT" ? "asent was not found"
      : e.code === "NOT_ABSOLUTE" ? "asent.path must be a command name on PATH or an absolute path"
        : `asent could not be started, ${e.code}`;
    const fix = e.code === "NOT_ABSOLUTE" ? "Set asent.path." : "Install asent, or set asent.path.";
    return notificationText(`ASENT: ${what}: "${notificationText(e.asentPath, 60)}". ${fix}`);
  }
  if (e instanceof AsentCancelled) return notificationText(`ASENT: ${e.message}.`);
  return notificationText(`ASENT: ${e instanceof Error ? e.message : String(e)}`);
}
