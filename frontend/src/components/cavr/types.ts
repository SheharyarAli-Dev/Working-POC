export interface CavrRunState {
  runId: string | null;
  stepIndex: number;
  package: string;
  version: string;
  scenarioKey: string;
  explainSimply: boolean;
  verdict: 'ALLOW' | 'BLOCK' | 'NEEDS_REVIEW' | null;
  // The pipeline's status. BLOCK is the requirement gate's refusal (nothing was downloaded).
  policyState: 'VERIFIED' | 'RESTRICTED' | 'REJECTED' | 'UNRESOLVED' | 'BLOCK' | null;
  honestyWording: string;
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
  
  // Metrics & telemetry
  terminalLogs: string[];
  meters: {
    network_attempts: number;
    writes_outside_scratch: number;
    processes_spawned: number;
    secrets_touched: number;
  };
  honeytokenFlashing: boolean;
  // The answer of /api/cavr/proof/{run_id}. `proofData.cavr_verdict` is the whole pipeline verdict:
  // status, stage, rule, reason, fast_gate_ms, cache_hit, escalated, escalation, packages[].evidence.
  proofData: any | null;
}

// Text shown by a tab whose stage does not exist on the fast-gate path.
export const NOT_RUN_ON_FAST_GATE =
  'Not run. The fast gate checks the artifact without executing package code; this stage belongs to deep analysis (M2).';
