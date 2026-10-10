import React from 'react';
import { CavrRunState, NOT_COMPUTED, shown } from './types';
import { Shield, Info, ArrowRight, CheckCircle2, AlertTriangle, XCircle, Search } from 'lucide-react';

interface StageDetailPanelProps {
  state: CavrRunState;
}

export const StageDetailPanel: React.FC<StageDetailPanelProps> = ({ state }) => {
  const { stepIndex, explainSimply, verdict, policyState } = state;

  // The pipeline's verdict (from /api/cavr/proof) and the payloads of the stages that ran.
  // The step index of a run is the last stage that ran: 0 request, 1 gate, 2 artifact / tree / OSV,
  // 3 cache lookup, 4 contract / scan / sinks. Later timeline steps do not exist on the fast gate.
  const v = state.proofData?.cavr_verdict;
  const resolution = state.resolution;
  const contract = state.actionData?.capability_contract;
  const sinks: any[] = state.actionData?.reachability?.sinks || [];
  const verdictLine = v ? `Verdict: ${v.status} (${v.stage} / ${v.rule}). ${v.reason}` : null;
  const afterThis = (next: string) => (verdict ? "The run has finished; nothing was installed." : next);

  const stageDescriptions = [
    {
      title: "Step 1: Capture (C1)",
      what: state.request
        ? `Request received: '${state.request}'. It is verified before anything is installed.`
        : "No request yet. Choose one of the requests above.",
      why: "A request is only as trustworthy as what is actually downloaded for it, so it is checked first.",
      evidence: state.runId ? `Run ${state.runId}.` : NOT_COMPUTED,
      next: afterThis("Requirement gate (C2).")
    },
    {
      title: "Step 2: Requirement Gate (C2)",
      what: state.gateResult
        ? `${state.gateResult.rule_checked}: ${state.gateResult.result} (${state.gateResult.matched_rule}).`
        : "Checking the request against the project policy.",
      why: "A request the policy does not permit is stopped before anything is downloaded.",
      evidence: shown(state.gateResult?.reason),
      next: afterThis("Download the wheel and compare its SHA-256 with the registry (C3).")
    },
    {
      title: "Step 3: Artifact, dependency tree and advisories (C3)",
      what: resolution
        ? `Artifact ${shown(resolution.filename)}: ${shown(resolution.hash_rule)}. Tree: ${shown(resolution.tree?.rule)} (${shown(resolution.tree?.nodes?.length)} files).`
        : "Downloading the wheel and reading its dependencies.",
      why: "The SHA-256 is computed from the downloaded bytes and compared with the registry digest; every dependency is checked the same way.",
      evidence: resolution
        ? (resolution.known_risk_signals?.length
          ? `OSV: ${shown(resolution.advisory_summary)}. The whole list is in the Overview tab and in the proof.`
          : `sha256 ${shown(resolution.sha256)}; registry ${shown(resolution.registry_sha256)}. OSV: ${shown((resolution.advisories || []).map((a: any) => a.rule).join(', '))}.`)
        : NOT_COMPUTED,
      next: afterThis("Look up the verdict cache on the 8-field key.")
    },
    {
      title: "Step 4: Verdict cache lookup",
      what: state.cacheResult ? `Cache: ${state.cacheResult.result}.` : "Looking for a stored analysis of exactly these inputs.",
      why: "A stored analysis is reused only when the file, the tree, the contract, the policy and the analyzer are all the same. OSV is asked again either way.",
      evidence: state.cacheResult?.reason || (state.cacheResult?.key ? `key ${state.cacheResult.key}` : NOT_COMPUTED),
      next: afterThis("Contract from the project's call sites, then the AST scan.")
    },
    {
      title: "Step 5: Capability contract, AST scan and sinks (C4)",
      what: contract
        ? `${contract.rule}: ${shown(contract.summary?.required_count)} required, ${shown(contract.summary?.denied_count)} denied capabilities; ${(contract.call_sites || []).length} call sites.`
        : "Reading the project's imports and call sites.",
      why: "A sensitive call inside a wheel only matters when the contract does not allow it and the project's call sites can reach it.",
      evidence: state.actionData
        ? (sinks.length
          ? sinks.map((sink: any) => `${sink.file}:${sink.line} ${sink.sink} ${sink.verdict}`).join('; ')
          : "No sensitive sink call found in the scanned wheels.")
        : NOT_COMPUTED,
      next: afterThis("Verdict.")
    }
  ];
  if (verdictLine) {
    // Once the verdict is known every stage shows it, so the panel never ends on an intermediate message.
    stageDescriptions.forEach(stage => { stage.what = `${stage.what} ${verdictLine}`; });
  }

  const current = stageDescriptions[Math.min(stepIndex, stageDescriptions.length - 1)];

  return (
    <div className="stage-detail-panel">
      <div className="stage-detail-header">
        <div className="stage-title-wrap">
          <span className="stage-badge">ACTIVE STAGE REASONING</span>
          <h4>{current.title}</h4>
        </div>
        <div className="stage-status-indicator">
          {verdict === 'ALLOW' && <span className="status-chip good"><CheckCircle2 size={13} /> Verified by the fast gate</span>}
          {verdict === 'BLOCK' && <span className="status-chip bad"><XCircle size={13} /> {policyState === 'BLOCK' ? 'Blocked by the project policy' : 'Rejected: a check failed'}</span>}
          {verdict === 'NEEDS_REVIEW' && <span className="status-chip warn"><AlertTriangle size={13} /> Unresolved (fail closed){v?.escalation ? `: ${v.escalation}` : ''}</span>}
          {!verdict && <span className="status-chip neutral"><Search size={13} /> {state.runId ? 'Run in progress' : 'No run yet'}</span>}
        </div>
      </div>

      <div className="stage-grid">
        <div className="stage-col">
          <span className="col-label">WHAT IS HAPPENING</span>
          <p>{explainSimply ? state.currentPlainMessage : current.what}</p>
        </div>
        <div className="stage-col">
          <span className="col-label">WHY THIS MATTERS</span>
          <p>{current.why}</p>
        </div>
        <div className="stage-col">
          <span className="col-label">EVIDENCE FOUND</span>
          <p className="evidence-text">{current.evidence}</p>
        </div>
        <div className="stage-col">
          <span className="col-label">WHAT HAPPENS NEXT</span>
          <p>{current.next}</p>
        </div>
      </div>
    </div>
  );
};
