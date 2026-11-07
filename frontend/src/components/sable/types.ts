// SABLE shared types — mirrors the backend event schema

export type SableVerdict = 'PRESERVED' | 'REGRESSED' | 'UNKNOWN' | null;

export interface SableObligation {
  obligation_id: string;
  principal: string;
  actions: string[];
  protected_asset: string;
  resource_scope: string;
  authority_source: string;
}

export interface TerraformFileEntry {
  path: string;
  content: string;
}

export function terraformFileMap(entries: TerraformFileEntry[]): { files?: Record<string, string>; error?: string } {
  if (entries.length === 0) return { error: 'Add at least one Terraform file.' };
  const files: Record<string, string> = {};
  for (const entry of entries) {
    const path = entry.path.trim().replace(/\\/g, '/');
    const parts = path.split('/');
    if (!path || path.startsWith('/') || /^[A-Za-z]:/.test(path) ||
        parts.some(part => !part || part === '.' || part === '..') || !path.endsWith('.tf')) {
      return { error: `Use a relative .tf path without . or .. segments: ${entry.path || '(blank path)'}` };
    }
    if (Object.prototype.hasOwnProperty.call(files, path)) return { error: `Duplicate Terraform path: ${path}` };
    if (!entry.content.trim()) return { error: `Terraform source is empty: ${path}` };
    files[path] = entry.content;
  }
  return { files };
}

export interface SableHypothesis {
  address: string;
  score: number;
  signals: { signal: string; weight: number }[];
  references: string[];
  module: string;
}

export interface SableAuthResult {
  known: boolean;
  holds: boolean;
  reason: string;
  actual_actions: string[];
  expected_resource: string;
  widening: string[];
  weakening: string[];
  misbinding: string[];
  unexpected_resources: string[];
  outside_model: string[];
  grants: Array<{ policy: string; actions: string[]; resources: string[] }>;
}

export interface SableRunState {
  runId: string | null;
  scenarioId: string | null;
  stepIndex: number;
  verdict: SableVerdict;
  asent_mapping: string | null;
  wording: string | null;
  decisionHash: string | null;
  branchFired: string | null;
  failureMode: string | null;
  reviewerNote: string | null;
  successor: string | null;
  correspondenceReason: string | null;
  hypotheses: SableHypothesis[];
  conflicts: string[];
  baselineAuth: Partial<SableAuthResult> | null;
  candidateAuth: Partial<SableAuthResult> | null;
  obligation: Partial<SableObligation> | null;
  baselineSha: string | null;
  candidateSha: string | null;
  diff: string | null;
  diffLines: string[];
  candidateFiles: string[];
  baselineResources: string[];
  candidateResources: string[];
  baselineGraph: { nodes: any[]; edges: any[] } | null;
  candidateGraph: { nodes: any[]; edges: any[] } | null;
  unsupportedConstructs: string[];
  toolResults: Record<string, any>;
  terminalLogs: string[];
  baselines: Record<string, { verdict: string; reduced_strength?: boolean }>;
  evidence: Record<string, any> | null;
  proofData: Record<string, any> | null;
  meters: {
    hypotheses_generated: number;
    hypotheses_surviving: number;
    conflicts_found: number;
    signals_collected: number;
    policy_findings: number;
  };
  uncertainty: number; // 0-1
}

export const INITIAL_STATE: SableRunState = {
  runId: null,
  scenarioId: null,
  stepIndex: -1,
  verdict: null,
  asent_mapping: null,
  wording: null,
  decisionHash: null,
  branchFired: null,
  failureMode: null,
  reviewerNote: null,
  successor: null,
  correspondenceReason: null,
  hypotheses: [],
  conflicts: [],
  baselineAuth: null,
  candidateAuth: null,
  obligation: null,
  baselineSha: null,
  candidateSha: null,
  diff: null,
  diffLines: [],
  candidateFiles: [],
  baselineResources: [],
  candidateResources: [],
  baselineGraph: null,
  candidateGraph: null,
  unsupportedConstructs: [],
  toolResults: {},
  terminalLogs: [],
  baselines: {},
  evidence: null,
  proofData: null,
  meters: {
    hypotheses_generated: 0,
    hypotheses_surviving: 0,
    conflicts_found: 0,
    signals_collected: 0,
    policy_findings: 0,
  },
  uncertainty: 0,
};

export const STEP_NAMES = [
  'Terraform Change Proposal',
  'Capture Baseline & Candidate',
  'Normalize & Model',
  'Find Successors',
  'Project Obligation',
  'Verify',
  'Attribute',
  'Report & Release',
];

export const STEP_PHASES = ['A+B', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];

export const STEP_SUBSTEPS = [
  'ASENT change-surface routing',
  'Capture and diff',
  'Normalization and obligation model',
  'Correspondence',
  'Projection',
  'Authorization evaluation and evidence tools',
  'Decision',
  'Evidence',
];

export const VERDICT_COLORS: Record<string, string> = {
  PRESERVED: '#16a34a',
  REGRESSED: '#dc2626',
  UNKNOWN: '#d97706',
};

export const VERDICT_BG: Record<string, string> = {
  PRESERVED: '#f0fdf4',
  REGRESSED: '#fef2f2',
  UNKNOWN: '#fffbeb',
};
