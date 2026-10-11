import React from 'react';
import { CavrRunState, NOT_COMPUTED, shown } from './types';
import { AdvisoryList } from './AdvisoryList';
import { ShieldCheck, AlertOctagon, HelpCircle, CheckCircle, FileText, Clock, Cpu, Lock, AlertTriangle } from 'lucide-react';

interface OverviewTabProps {
  state: CavrRunState;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ state }) => {
  const { verdict, policyState, honestyWording } = state;
  // The proof's package and version when there is a proof; before it arrives, those of the chip that was clicked.
  const pkg = state.proofData?.package || state.package;
  const ver = state.proofData?.version || state.version;
  // Everything below is copied from the pipeline's verdict; nothing is filled in when it is missing.
  const v = state.proofData?.cavr_verdict;
  const resolution = state.resolution;
  const hash: string | null = resolution?.sha256 || null;
  const condition = state.proofData?.demo_condition;
  const limits: any[] = state.certificate?.residual_uncertainty || [];

  const findings: string[] = [];
  if (state.gateResult && state.gateResult.result !== "PERMITTED") {
    findings.push(`Requirement gate: ${state.gateResult.result} (${state.gateResult.matched_rule}). ${state.gateResult.reason}`);
  }
  if (resolution?.hash_rule && resolution.hash_rule !== "HASH_MATCH") {
    findings.push(`Artifact: ${resolution.hash_rule}. ${resolution.hash_reason || ''}`);
  }
  if (resolution?.known_risk_signals?.length) {
    findings.push(`OSV: ${shown(resolution.advisory_summary)}.`);
  }
  if (v?.escalation) {
    findings.push(`Escalation: ${v.escalation}.`);
  }
  if (v) {
    findings.push(`${v.stage} / ${v.rule}: ${v.reason}`);
  }

  return (
    <div className="evidence-tab-pane overview-pane">
      <div className="overview-hero-card">
        <div className="overview-status-group">
          <div className={`verdict-pill ${verdict ? verdict.toLowerCase() : 'pending'}`}>
            {verdict === 'ALLOW' && <CheckCircle size={18} />}
            {verdict === 'BLOCK' && <AlertOctagon size={18} />}
            {verdict === 'NEEDS_REVIEW' && <AlertTriangle size={18} />}
            <span>VERDICT: {shown(verdict)}</span>
          </div>

          <div className="policy-state-badge">
            POLICY STATE: <strong>{shown(policyState)}</strong>
          </div>
        </div>

        <div className="overview-honesty-banner">
          <span className="honesty-tag">HONESTY WORDING</span>
          <p className="honesty-claim">{shown(honestyWording)}</p>
          <span className="honesty-sub">
            {v ? `${v.status}: ${v.stage} / ${v.rule}` : 'The verdict is bounded by the checks that ran; it never says "safe".'}
          </span>
        </div>
      </div>

      {/* Grid of Key Properties */}
      <div className="overview-stats-grid">
        <div className="overview-stat-box">
          <span className="stat-label"><FileText size={13} /> Package &amp; Version</span>
          <strong className="stat-value">{shown(pkg)} <code>{shown(ver)}</code></strong>
          <span className="stat-meta">Scenario: {shown(state.scenarioKey)}</span>
        </div>

        <div className="overview-stat-box">
          <span className="stat-label"><Lock size={13} /> Artifact SHA-256</span>
          <strong className="stat-value mono">{hash ? `${hash.substring(0, 16)}...` : NOT_COMPUTED}</strong>
          <span className="stat-meta">
            Hash check: {shown(resolution?.hash_rule)}
          </span>
        </div>

        <div className="overview-stat-box">
          <span className="stat-label"><Clock size={13} /> Fast gate</span>
          <strong className="stat-value">{v?.fast_gate_ms != null ? `${v.fast_gate_ms} ms` : NOT_COMPUTED}</strong>
          <span className="stat-meta">Cache hit: {v ? (v.cache_hit ? 'yes' : 'no') : NOT_COMPUTED}</span>
        </div>

        <div className="overview-stat-box">
          <span className="stat-label"><Cpu size={13} /> Escalated</span>
          <strong className="stat-value">{v ? (v.escalated ? 'yes' : 'no') : NOT_COMPUTED}</strong>
          <span className="stat-meta">Escalation: {shown(v?.escalation)}</span>
        </div>
      </div>

      {condition && (
        <div className="overview-honesty-banner">
          <span className="honesty-tag">DEMO CONDITION: {condition.id}</span>
          <p className="honesty-claim">{condition.description}</p>
          <span className="honesty-sub">The pipeline ran unchanged under this condition. A condition can only make a verdict worse.</span>
        </div>
      )}

      {/* Top Findings & Residuals Row */}
      <div className="overview-two-col">
        <div className="overview-card">
          <div className="card-header-row">
            <h5>Findings of this run</h5>
            <span className="card-badge">{findings.length} recorded</span>
          </div>
          <ul className="findings-list">
            {findings.map((f, i) => (
              <li key={i} className="finding-item">
                <span className="finding-num">{i + 1}</span>
                <span>{f}</span>
              </li>
            ))}
          </ul>
        </div>

        <div className="overview-card">
          <div className="card-header-row">
            <h5>What this verdict does not establish</h5>
            <span className="card-badge warn">{limits.length} stated</span>
          </div>
          {limits.length === 0 ? (
            <p className="clean-residual-note">{verdict ? 'No limits were reported for this run.' : 'Available when the run has finished.'}</p>
          ) : (
            <div className="residual-list">
              <ul>
                {limits.map((r: any, idx: number) => (
                  <li key={idx}>
                    <code>{r.predicate}</code> ({r.file_line}): {r.reason}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      </div>

      {/* OSV: the count and the first three ids, with the whole list in a closed section */}
      <AdvisoryList resolution={resolution} runId={state.runId} />
    </div>
  );
};
