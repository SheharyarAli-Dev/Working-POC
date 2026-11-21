// Where the report's findings go in the Problems tab. Only files the report names, and only inside
// the workspace (or the gated repository that contains it); a path that leaves it is dropped.
// No vscode import (unit-tested in plain Node); extension.ts turns these into vscode.Diagnostic.
import * as path from "path";
import { Finding } from "./report";

export interface Located {
  file: string; // absolute
  line: number; // 0-based (VS Code)
  severity: Finding["severity"];
  message: string;
  source: "ASENT";
}

const inside = (root: string, target: string) => {
  const rel = path.relative(root, target);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
};

/** The report's paths are relative to the gated repository's top level; use it when it contains the folder. */
export function diagnosticRoot(folder: string, repository: string | null): string {
  const root = path.resolve(folder);
  if (repository && path.isAbsolute(repository) && inside(path.resolve(repository), root)) return path.resolve(repository);
  return root;
}

export function locate(findings: Finding[], folder: string, repository: string | null): Located[] {
  const root = diagnosticRoot(folder, repository);
  const out: Located[] = [];
  for (const f of findings) {
    if (!f.file || f.file.includes("\0") || path.isAbsolute(f.file) || path.win32.isAbsolute(f.file)) continue;
    const file = path.resolve(root, f.file);
    if (!inside(root, file) || file === root) continue;
    out.push({
      file, line: f.line === null ? 0 : f.line - 1, severity: f.severity, source: "ASENT",
      message: f.line === null ? `${f.message} (file-level: the report gives no line)` : f.message,
    });
  }
  return out;
}
