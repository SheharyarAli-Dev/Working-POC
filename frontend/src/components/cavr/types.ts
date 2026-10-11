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
  counterfactualResults: any | null;
  causalGraph: any | null;
  violatingPaths: any[] | null;
  repair: any | null;
  reverification: any | null;
  certificate: any | null;
  reconstruction: any | null;
  
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

// Text shown by a tab whose stage does not exist on the fast-gate path.
export const NOT_RUN_ON_FAST_GATE =
  'Not run. The fast gate checks the artifact without executing package code; this stage belongs to deep analysis (M2).';

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
