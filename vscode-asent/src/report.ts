// Reads an `asent gate --json` / `asent report --json` document (schema asent.gate.v1).
//
// Nothing here decides anything: decision, results, statuses and reasons are copied from the report.
// This module only checks the report's shape (fail closed: anything that is not an ASENT gate report
// is refused with ReportError) and picks out what the panel, the status bar and the Problems tab show.
// No vscode import, so it is unit-tested in plain Node.

export const SCHEMA = "asent.gate.v1";
export const DECISIONS = ["ACCEPT", "REVIEW", "BLOCK"] as const;
export type Decision = (typeof DECISIONS)[number];

const MODULES = [
  { key: "CAVR", title: "CAVR" },
  { key: "SATRA", title: "SATRA-RV" },
  { key: "SABLE", title: "SABLE" },
] as const;
const MAX_EVIDENCE = 12;

export interface ModuleCard {
  key: "CAVR" | "SATRA" | "SABLE";
  title: string;
  result: string | null; // pass / block / review / not assessed (...) / not applicable, as the report says
  status: string | null; // the module's own status (VERIFIED, REJECTED, REJECT, REGRESSED, ...)
  assessed: boolean;
  reason: string | null;
  evidence: string[]; // short lines from the module's evidence record
}

export interface Finding {
  module: "CAVR";
  file: string; // relative to the repository, as the report gives it
  line: number | null; // 1-based; null when the report gives no line
  severity: "error" | "warning";
  message: string;
}

export interface GateReport {
  decision: Decision;
  exitCode: number | null;
  repository: string | null;
  generatedAt: string | null;
  asentVersion: string | null;
  base: { ref: string | null; sha: string | null };
  head: { ref: string | null; sha: string | null };
  configDigest: string | null;
  configSource: string | null;
  configChangedInHead: boolean | null;
  configProblems: string[];
  reasons: string[];
  modules: ModuleCard[];
  findings: Finding[];
  tools: Record<string, boolean>;
}

export class ReportError extends Error {}

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === "object" && v !== null && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" ? v : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const bool = (v: unknown): boolean | null => (typeof v === "boolean" ? v : null);
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);
const strings = (v: unknown): string[] => list(v).filter((x): x is string => typeof x === "string");
const objs = (v: unknown): Obj[] => list(v).filter(isObj);
const oneLine = (s: string) => s.replace(/\s+/g, " ").trim();
const positiveLine = (v: unknown): number | null => (Number.isInteger(v) && (v as number) >= 1 ? (v as number) : null);

export function parseReport(text: string): GateReport {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw new ReportError(`not an ASENT gate report: not valid JSON (${(e as Error).message})`);
  }
  return fromJson(value);
}

export function fromJson(value: unknown): GateReport {
  if (!isObj(value)) throw new ReportError("not an ASENT gate report: not a JSON object");
  if (value.schema !== SCHEMA) throw new ReportError(`not an ASENT gate report: expected schema ${SCHEMA}`);
  const decision = value.decision;
  if (typeof decision !== "string" || !(DECISIONS as readonly string[]).includes(decision)) {
    throw new ReportError(`not an ASENT gate report: unknown decision ${JSON.stringify(decision)}`);
  }
  const commit = (side: "base" | "head") => {
    const v = value[side];
    if (!isObj(v)) throw new ReportError(`not an ASENT gate report: ${side} is missing`);
    return { ref: str(v.ref), sha: str(v.sha) };
  };
  const rows = value.modules;
  if (!isObj(rows)) throw new ReportError("not an ASENT gate report: modules is missing");
  const records = objs(isObj(value.assurance) ? value.assurance.evidence : undefined);
  const config = isObj(value.config) ? value.config : {};
  const tools: Record<string, boolean> = {};
  if (isObj(value.tools)) for (const [k, v] of Object.entries(value.tools)) if (typeof v === "boolean") tools[k] = v;

  const modules = MODULES.map(({ key, title }): ModuleCard => {
    const row = rows[key];
    if (!isObj(row)) throw new ReportError(`not an ASENT gate report: module ${key} is missing`);
    const id = str(row.evidence_id);
    const record = id ? records.find((r) => r.evidence_id === id) : undefined;
    const details = record && isObj(record.details) ? record.details : {};
    return {
      key, title, result: str(row.result), status: str(row.status), assessed: row.assessed === true,
      reason: str(row.reason), evidence: EVIDENCE[key](details).map(oneLine).slice(0, MAX_EVIDENCE),
    };
  });
  const cavrId = str((rows.CAVR as Obj).evidence_id);
  const cavrRecord = cavrId ? records.find((r) => r.evidence_id === cavrId) : undefined;

  return {
    decision: decision as Decision,
    exitCode: num(value.exit_code),
    repository: str(value.repository),
    generatedAt: str(value.generated_at),
    asentVersion: str(value.asent_version),
    base: commit("base"),
    head: commit("head"),
    configDigest: str(config.digest),
    configSource: str(config.source),
    configChangedInHead: bool(config.changed_in_head),
    configProblems: strings(config.problems),
    reasons: strings(value.reasons),
    modules,
    findings: cavrRecord && isObj(cavrRecord.details) ? cavrFindings(cavrRecord.details) : [],
    tools,
  };
}

// --- key evidence per module: field names as the modules write them ------------------------------

const EVIDENCE: Record<ModuleCard["key"], (d: Obj) => string[]> = {
  // backend/cavr/gate_adapter.py: details.pipeline[] = one entry per requirements file, with packages[]
  CAVR(d) {
    const out: string[] = [];
    for (const entry of objs(d.pipeline)) {
      out.push(`${str(entry.file) ?? "?"}: ${str(entry.status) ?? "?"} ${str(entry.rule) ?? ""}: ${str(entry.reason) ?? ""}`);
      for (const pkg of objs(entry.packages)) {
        const sha = str(pkg.sha256);
        out.push(`${str(pkg.name) ?? "?"}==${str(pkg.version) ?? "?"}: ${str(pkg.status) ?? "?"}` + (sha ? `, sha256 ${sha.slice(0, 12)}` : ""));
      }
    }
    return out;
  },
  // backend/satra/gate_mode.py: details.findings[], details.oracle, details.executions{name: pytest result}
  SATRA(d) {
    const out: string[] = [];
    for (const f of objs(d.findings)) {
      const tests = strings(f.tests);
      out.push(`${str(f.diagnosis) ?? "?"}: ` + (tests.length ? `failing test ${tests.join(", ")}` : str(f.reason) ?? ""));
    }
    if (isObj(d.oracle)) {
      out.push(`counterfactual ${str(d.oracle.mutant_operator) ?? "?"}: valid ${String(bool(d.oracle.valid_counterfactual))}`);
    }
    if (isObj(d.executions)) {
      for (const [name, run] of Object.entries(d.executions)) {
        if (!isObj(run)) continue;
        out.push(run.available === false
          ? `${name}: not run (${str(run.reason) ?? "unavailable"})`
          : `${name}: ${num(run.passed) ?? "?"} passed, ${num(run.failed) ?? "?"} failed, ${num(run.errors) ?? "?"} errors`);
      }
    }
    return out;
  },
  // backend/sable: details.obligations[] = {id, status, reason, details{successor, projected_authorization}}
  SABLE(d) {
    const out: string[] = [];
    for (const o of objs(d.obligations)) {
      out.push(`${str(o.id) ?? "?"}: ${str(o.status) ?? "?"}: ${str(o.reason) ?? ""}`);
      const inner = isObj(o.details) ? o.details : {};
      const successor = str(inner.successor);
      if (successor) out.push(`successor ${successor} (${str(inner.correspondence_reason) ?? ""})`);
      const projected = isObj(inner.projected_authorization) ? inner.projected_authorization : null;
      if (projected) {
        out.push(`authorization holds: ${String(bool(projected.holds))}`);
        for (const r of strings(projected.unexpected_resources)) out.push(`unexpected resource ${r}`);
      }
    }
    return out;
  },
};

// --- Problems tab: only where the report names a file ------------------------------------------

function cavrFindings(d: Obj): Finding[] {
  const findings: Finding[] = [];
  const severity = (mapped: unknown) => (mapped === "REJECTED" ? "error" : "warning") as Finding["severity"];
  for (const entry of objs(d.pipeline)) {
    if (entry.mapped === "VERIFIED") continue;
    const file = str(entry.file);
    if (file) {
      findings.push({ module: "CAVR", file, line: null, severity: severity(entry.mapped),
        message: oneLine(`CAVR ${str(entry.status) ?? "?"} ${str(entry.rule) ?? ""}: ${str(entry.reason) ?? ""}`) });
    }
    for (const pkg of objs(entry.packages)) {
      if (pkg.mapped === "VERIFIED") continue;
      const contract = isObj(pkg.contract) ? pkg.contract : {};
      for (const site of objs(contract.call_sites)) {
        const siteFile = str(site.file);
        if (!siteFile) continue;
        findings.push({ module: "CAVR", file: siteFile, line: positiveLine(site.line), severity: severity(pkg.mapped),
          message: oneLine(`CAVR ${str(pkg.status) ?? "?"} ${str(pkg.rule) ?? ""}: ${str(pkg.name) ?? "?"}==${str(pkg.version) ?? "?"} ` +
            `is called here (${str(site.symbol) ?? "?"}): ${str(pkg.reason) ?? ""}`) });
      }
    }
  }
  return findings;
}
