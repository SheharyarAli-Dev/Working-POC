// Reads `asent doctor --json` (schema asent.doctor.v1) and turns it into the lines the user sees.
// The checks and their fix lines are asent's own; this module only selects and prints them.
// No vscode import (unit-tested in plain Node).

export const DOCTOR_SCHEMA = "asent.doctor.v1";
// README §4.0 "Install the `asent` command".
export const INSTALL_LINES = [
  "pipx install git+https://github.com/SheharyarAli-Dev/Working-POC",
  "pip install git+https://github.com/SheharyarAli-Dev/Working-POC   (inside a virtual environment you manage)",
];
const DOCKER_CHECKS = new Set(["docker", "docker-daemon"]);
const MARK: Record<string, string> = { missing: "MISSING", warning: "warning", skipped: "skipped" };

export interface DoctorProblem {
  id: string;
  label: string;
  status: string;
  required: boolean;
  detail: string;
  fix: string | null;
}

export interface Doctor {
  ready: boolean;
  version: string | null;
  problems: DoctorProblem[]; // checks that are not "ok", required ones first
}

export class DoctorError extends Error {}

export function readDoctor(value: unknown): Doctor {
  const v = value as Record<string, unknown>;
  if (typeof value !== "object" || value === null || Array.isArray(value) || v.schema !== DOCTOR_SCHEMA) {
    throw new DoctorError(`not asent doctor output (expected schema ${DOCTOR_SCHEMA})`);
  }
  if (typeof v.ready !== "boolean" || !Array.isArray(v.checks)) throw new DoctorError("asent doctor output has no ready/checks");
  const problems = (v.checks as unknown[])
    .filter((c): c is Record<string, unknown> => typeof c === "object" && c !== null && (c as Record<string, unknown>).status !== "ok")
    .map((c) => ({
      id: String(c.id ?? ""), label: String(c.label ?? c.id ?? "?"), status: String(c.status ?? "?"),
      required: c.required !== false, detail: typeof c.detail === "string" ? c.detail : "",
      fix: typeof c.fix === "string" ? c.fix : null,
    }));
  problems.sort((a, b) => Number(b.required) - Number(a.required));
  return { ready: v.ready, version: typeof v.version === "string" ? v.version : null, problems };
}

export function dockerMissing(doctor: Doctor): boolean {
  return doctor.problems.some((p) => DOCKER_CHECKS.has(p.id));
}

export function doctorLines(doctor: Doctor): string[] {
  const required = doctor.problems.filter((p) => p.required).length;
  const lines = [doctor.ready
    ? "ASENT doctor: ready. Everything `asent gate` needs is here."
    : `ASENT doctor: not ready (${required} required check${required === 1 ? "" : "s"} need attention). Nothing was changed; run the fixes yourself.`];
  for (const p of doctor.problems) {
    lines.push(`  ${(MARK[p.status] ?? p.status).padEnd(8)} ${p.label}: ${p.detail}` + (p.required ? "" : " (optional)"));
    if (p.fix) lines.push(`    fix: ${p.fix}`);
  }
  return lines;
}

export function notFoundLines(asentPath: string): string[] {
  return [
    `asent was not found: "${asentPath}". The ASENT extension only runs the installed asent command.`,
    "Install it (README §4.0):",
    ...INSTALL_LINES.map((l) => "  " + l),
    "Then make sure `asent --version` works in a terminal, or set the full path in the setting asent.path.",
  ];
}
