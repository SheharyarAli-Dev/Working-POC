// Where the report's findings go in the Problems tab. Only files the report names, and only inside the
// workspace folder. The report's own `repository` field is never used as a root (a report in an untrusted
// folder can say anything, e.g. "/"): each path is resolved against the folder, symlinks are followed
// (realpath), and only an existing file whose real path is inside the folder's real path gets an entry.
// No vscode import (unit-tested in plain Node); extension.ts turns these into vscode.Diagnostic.
import * as fs from "fs";
import * as path from "path";
import { Finding } from "./report";

export interface Located {
  file: string; // absolute, under the folder as VS Code opened it
  line: number; // 0-based (VS Code)
  severity: Finding["severity"];
  message: string;
  source: "ASENT";
}

const inside = (root: string, target: string) => {
  const rel = path.relative(root, target);
  return rel !== "" && rel !== ".." && !rel.startsWith(".." + path.sep) && !path.isAbsolute(rel);
};

const realFile = (file: string): string | null => {
  try {
    const real = fs.realpathSync.native(file);
    return fs.statSync(real).isFile() ? real : null;
  } catch {
    return null; // does not exist (or cannot be read): no entry, fail closed
  }
};

export function locate(findings: Finding[], folder: string): Located[] {
  const root = path.resolve(folder);
  let realRoot: string;
  try {
    realRoot = fs.realpathSync.native(root);
  } catch {
    return [];
  }
  const out: Located[] = [];
  for (const f of findings) {
    if (!f.file || f.file.includes("\0") || path.isAbsolute(f.file) || path.win32.isAbsolute(f.file)) continue;
    const file = path.resolve(root, f.file);
    if (!inside(root, file)) continue;
    const real = realFile(file);
    if (real === null || !inside(realRoot, real)) continue;
    out.push({
      file, line: f.line === null ? 0 : f.line - 1, severity: f.severity, source: "ASENT",
      message: f.line === null ? `${f.message} (file-level: the report gives no line)` : f.message,
    });
  }
  return out;
}
