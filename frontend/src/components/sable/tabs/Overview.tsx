import React from 'react';
import { SableRunState } from '../types';
import { CheckCircle2, XCircle, AlertTriangle, ArrowRight, Shield } from 'lucide-react';

const VERDICT_COLORS = { PRESERVED: '#16a34a', REGRESSED: '#dc2626', UNKNOWN: '#d97706' };
const VERDICT_BG = { PRESERVED: '#f0fdf4', REGRESSED: '#fef2f2', UNKNOWN: '#fffbeb' };
const VERDICT_BORDER = { PRESERVED: '#bbf7d0', REGRESSED: '#fecaca', UNKNOWN: '#fde68a' };

interface Props { runState: SableRunState; explainSimply: boolean; }

export const OverviewTab: React.FC<Props> = ({ runState, explainSimply }) => {
  const { verdict, obligation, successor, correspondenceReason, asent_mapping,
          branchFired, failureMode, candidateAuth, wording, decisionHash } = runState;

  if (!verdict) {
    return (
      <div className="sable-tab-empty">
        <Shield size={32} strokeWidth={1.2} />
        <p>Run a scenario to see the overview.</p>
      </div>
    );
  }

  const vColor = verdict ? VERDICT_COLORS[verdict] ?? '#6b7280' : '#6b7280';
  const vBg = verdict ? VERDICT_BG[verdict] ?? '#f9fafb' : '#f9fafb';
  const vBorder = verdict ? VERDICT_BORDER[verdict] ?? '#e5e7eb' : '#e5e7eb';

  return (
    <div className="sable-tab-content">
      {/* Verdict Card */}
      <div className="sable-verdict-card" style={{ borderColor: vBorder, background: vBg }}>
        <div className="sable-verdict-badge" style={{ background: vColor }}>
          {verdict === 'PRESERVED' ? <CheckCircle2 size={16}/> : verdict === 'REGRESSED' ? <XCircle size={16}/> : <AlertTriangle size={16}/>}
          {verdict}
        </div>
        <div className="sable-verdict-asent" style={{ color: vColor }}>
          ASENT mapping: <strong>{asent_mapping}</strong>
        </div>
        <p className="sable-verdict-wording">{wording}</p>
        {decisionHash && (
          <code className="sable-decision-hash">Decision hash: {decisionHash.slice(0, 20)}…</code>
        )}
      </div>

      {/* Obligation */}
      <div className="sable-overview-grid">
        <div className="sable-overview-card">
          <div className="sable-card-label">OBLIGATION</div>
          <div className="sable-kv-list">
            <div className="sable-kv"><span>Principal</span><code>{obligation?.principal ?? '–'}</code></div>
            <div className="sable-kv"><span>Actions</span><code>{obligation?.actions?.join(', ') ?? '–'}</code></div>
            <div className="sable-kv"><span>Protected Asset</span><code>{obligation?.protected_asset ?? '–'}</code></div>
            <div className="sable-kv"><span>Resource Scope</span><code>{obligation?.resource_scope ?? '–'}</code></div>
          </div>
        </div>

        <div className="sable-overview-card">
          <div className="sable-card-label">CORRESPONDENCE</div>
          <div className="sable-kv-list">
            <div className="sable-kv"><span>Chosen Successor</span><code>{successor ?? 'None'}</code></div>
            <div className="sable-kv"><span>Reason</span><span className="sable-kv-val-text">{correspondenceReason ?? '–'}</span></div>
            <div className="sable-kv"><span>Hypotheses</span><span>{runState.hypotheses.length}</span></div>
            <div className="sable-kv"><span>Conflicts</span><span style={{ color: runState.conflicts.length > 0 ? '#dc2626' : 'inherit' }}>{runState.conflicts.length > 0 ? runState.conflicts.join('; ') : 'None'}</span></div>
          </div>
        </div>

        <div className="sable-overview-card">
          <div className="sable-card-label">AUTHORIZATION</div>
          <div className="sable-kv-list">
            <div className="sable-kv"><span>Known</span><span>{candidateAuth ? candidateAuth.known ? 'Yes' : 'No — insufficient evidence' : 'Not evaluated'}</span></div>
            <div className="sable-kv"><span>Holds</span><span style={{ color: !candidateAuth || !candidateAuth.known ? '#d97706' : candidateAuth.holds ? '#16a34a' : '#dc2626' }}>{!candidateAuth ? 'Not evaluated' : !candidateAuth.known ? 'Unknown' : candidateAuth.holds ? 'Yes' : 'No'}</span></div>
            <div className="sable-kv"><span>Widening</span><span style={{ color: (candidateAuth?.widening?.length ?? 0) > 0 ? '#dc2626' : candidateAuth?.known ? '#16a34a' : '#d97706' }}>{candidateAuth?.widening?.length ? candidateAuth.widening.join(', ') : candidateAuth?.known ? 'None' : 'Not established'}</span></div>
            <div className="sable-kv"><span>Weakening</span><span style={{ color: (candidateAuth?.weakening?.length ?? 0) > 0 ? '#dc2626' : candidateAuth?.known ? '#16a34a' : '#d97706' }}>{candidateAuth?.weakening?.length ? candidateAuth.weakening.join(', ') : candidateAuth?.known ? 'None' : 'Not established'}</span></div>
            {candidateAuth?.reason && <div className="sable-kv"><span>Reason</span><span className="sable-kv-val-text">{candidateAuth.reason}</span></div>}
          </div>
        </div>

        <div className="sable-overview-card">
          <div className="sable-card-label">DECISION TRACE</div>
          <div className="sable-decision-trace">
            {['no_unique_successor', 'evidence_conflicts'].map(b => (
              <div key={b} className={`sable-trace-branch ${branchFired === b ? 'fired' : ''}`}>
                <code>if {b === 'no_unique_successor' ? 'no_unique_successor(valid) or evidence_conflicts(valid)' : ''}</code>
                <ArrowRight size={12}/> <strong>UNKNOWN</strong>
              </div>
            ))}
            <div className={`sable-trace-branch ${branchFired === 'obligation_holds' ? 'fired' : ''}`}>
              <code>elif obligation_holds(security, intended_successor(valid))</code>
              <ArrowRight size={12}/> <strong>PRESERVED</strong>
            </div>
            <div className={`sable-trace-branch ${branchFired === 'obligation_violated' ? 'fired' : ''}`}>
              <code>else</code> <ArrowRight size={12}/> <strong>REGRESSED</strong>
            </div>
          </div>
        </div>
      </div>

      {/* Uncertainties */}
      {(runState.unsupportedConstructs?.length > 0 || (candidateAuth?.outside_model?.length ?? 0) > 0) && (
        <div className="sable-uncertainty-box">
          <div className="sable-card-label">OPEN UNCERTAINTIES</div>
          <ul>
            {[...runState.unsupportedConstructs, ...(candidateAuth?.outside_model ?? [])].map((u, i) => (
              <li key={i}><AlertTriangle size={12}/> {u}</li>
            ))}
          </ul>
        </div>
      )}

      {explainSimply && verdict && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong>{' '}
          {verdict === 'PRESERVED'
            ? `The permission that protected the customer data bucket still protects it on '${successor}', with the same actions and scope.`
            : verdict === 'REGRESSED'
            ? `The security boundary did not follow the data correctly. ${failureMode === 'widening' ? 'The role now has more access than it should.' : failureMode === 'weakening' ? 'Some required permissions were removed.' : 'The role is now protecting the wrong bucket.'}`
            : 'SABLE could not decide. This is not a green light — it means more evidence is needed.'}
        </div>
      )}
    </div>
  );
};
