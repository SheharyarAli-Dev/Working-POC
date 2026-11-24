export interface CavrRunState {
  runId: string | null;
  stepIndex: number;
  // The request as the backend reports it for this run; null before the first run.
  request: string | null;
  // Package, version and id of the scenario that was run, copied from GET /api/cavr/scenarios.
  package: string;
  version: string;
  scenarioKey: string;
  explainSimply: boolean;
  verdict: 'ALLOW' | 'BLOCK' | 'NEEDS_REVIEW' | null;
  // The pipeline's status. BLOCK is the requirement gate's refusal (nothing was downloaded).
  policyState: 'VERIFIED' | 'RESTRICTED' | 'REJECTED' | 'UNRESOLVED' | 'BLOCK' | null;
  // The backend's sentence about what the verdict does and does not claim; null before a verdict.
  honestyWording: string | null;
  currentStateMessage: string;
  currentPlainMessage: string;
  
  // Phase Payloads
  gateResult: any | null;
  resolution: any | null;
  cacheResult: any | null;
  actionData: any | null;
  causalGraph: any | null;
  violatingPaths: any[] | null;
  repair: RepairBlock | null;
  reverification: any | null;
  certificate: any | null;
  reconstruction: any | null;
  // PR 19: the per-package views of the deep_completed event (backend/cavr/dashboard_view.py), and the `recorded`
  // block of a replayed recorded run (null for a live run).
  deepPackages: any[] | null;
  recorded: any | null;

  // The answer of /api/cavr/proof/{run_id}. `proofData.cavr_verdict` is the whole pipeline verdict:
  // status, stage, rule, reason, fast_gate_ms, cache_hit, escalated, escalation, packages[].evidence.
  // `proofData.stages` is the timeline: one StageSummary per stage of the fast gate.
  proofData: any | null;
}

// One stage of the timeline, as the backend's `stage_summary` returns it. `ran` is false when
// none of the stage's values was computed; a value that was not computed is null.
export interface StageSummary {
  id: string;
  title: string;
  ran: boolean;
  values: { label: string; value: string | number | boolean | null }[];
}

// Printed wherever a value was not computed for this run. The page never puts a value of its own there.
export const NOT_COMPUTED = '—';

// A value from the backend as text, or the dash when there is none.
export const shown = (value: unknown): string =>
  value === null || value === undefined || value === '' ? NOT_COMPUTED : String(value);

// One chip, as GET /api/cavr/scenarios describes it. The page holds no package name of its own.
export interface Scenario {
  id: string;
  display_name: string;
  description: string;
  request: string;
  package: string;
  version: string;
  condition: string | null;
  expected_status: string;
}

// The repair block of backend/cavr/repair_proposal.py (schema cavr.repair.v1). A proposal for a person to
// approve; `applied` and `gate_decision_changed` are always false.
export interface RepairRecheck {
  request?: string | null;
  status?: string | null;
  rule?: string | null;
  reason?: string | null;
  package?: { sha256?: string | null; registry_sha256?: string | null } | null;
}

export interface RepairPart {
  requirement?: string;
  name?: string;
  version?: string;
  requirements_file?: string | null;
  requirements_diff?: string | null;
  pip_command?: string | null;
  lockfile_entry?: { file: string; before: any; after: { name: string; version: string; sha256: string } | null } | null;
  policy?: { changed?: boolean; added?: string[]; removed?: string[] };
  recheck?: RepairRecheck;
}

export interface RepairCandidate {
  version: string;
  outcome: string;
  status?: string | null;
  rule?: string | null;
  reason?: string | null;
}

export interface RepairBlock {
  result: 'PROPOSED' | 'NO_REPAIR_FOUND' | 'NOT_ATTEMPTED';
  rule: string;
  reason: string;
  package: string | null;
  version: string | null;
  rejected?: { status?: string | null; stage?: string | null; rule?: string | null };
  applied: boolean;
  gate_decision_changed: boolean;
  pin: RepairPart | null;
  removal: RepairPart | null;
  removal_reason?: string | null;
  candidates_tried?: RepairCandidate[];
  excluded?: { version: string; rule: string; reason: string }[];
  budget?: { max_candidates?: number | null; seconds?: number | null; tried?: number; stopped_by?: string | null };
  limitations?: string[];
}
