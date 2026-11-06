import React, { useState } from 'react';
import { SableRunState } from '../types';
import { CheckCircle2, XCircle, AlertTriangle, ArrowRight, ThumbsUp, ThumbsDown } from 'lucide-react';

interface Props {
  runState: SableRunState;
  explainSimply: boolean;
  onAuditDecision: (action: 'APPROVE' | 'REJECT') => void;
}

const VERDICT_COLORS: Record<string, string> = { PRESERVED: '#16a34a', REGRESSED: '#dc2626', UNKNOWN: '#d97706' };
const VERDICT_BG: Record<string, string> = { PRESERVED: '#f0fdf4', REGRESSED: '#fef2f2', UNKNOWN: '#fffbeb' };
const VERDICT_BORDER: Record<string, string> = { PRESERVED: '#bbf7d0', REGRESSED: '#fecaca', UNKNOWN: '#fde68a' };

const BRANCH_LABELS: Record<string, string> = {
  no_unique_successor: 'no_unique_successor(valid) or evidence_conflicts(valid)',
  evidence_conflicts: 'evidence_conflicts(valid)',
  obligation_holds: 'obligation_holds(security, intended_successor(valid))',
  obligation_violated: 'else (obligation violated)',
};

export const DecisionTab: React.FC<Props> = ({ runState, explainSimply, onAuditDecision }) => {
  const [auditSent, setAuditSent] = useState<'APPROVE' | 'REJECT' | null>(null);
  const { verdict, wording, asent_mapping, branchFired, failureMode, reviewerNote,
          successor, candidateAuth, decisionHash, obligation, baselines } = runState;

  if (!verdict) {
    return (
      <div className="sable-tab-empty">
        <AlertTriangle size={32} strokeWidth={1.2}/>
        <p>Run a scenario to see the decision.</p>
      </div>
    );
  }

  const vColor = VERDICT_COLORS[verdict] ?? '#6b7280';
  const vBg = VERDICT_BG[verdict] ?? '#f9fafb';
  const vBorder = VERDICT_BORDER[verdict] ?? '#e5e7eb';

  const handleAudit = (action: 'APPROVE' | 'REJECT') => {
    setAuditSent(action);
    onAuditDecision(action);
  };

  return (
    <div className="sable-tab-content">
      {/* Main verdict card */}
      <div className="sable-verdict-card" style={{ borderColor: vBorder, background: vBg }}>
        <div className="sable-verdict-badge" style={{ background: vColor }}>
          {verdict === 'PRESERVED' ? <CheckCircle2 size={16}/> : verdict === 'REGRESSED' ? <XCircle size={16}/> : <AlertTriangle size={16}/>}
          {verdict} · ASENT: {asent_mapping}
        </div>
        <p className="sable-verdict-wording"><em>{wording}</em></p>
        {decisionHash && <code className="sable-decision-hash">Decision hash: {decisionHash.slice(0, 24)}…</code>}
      </div>

      {/* Decision trace pseudocode */}
      <div className="sable-decision-trace-full">
        <div className="sable-card-label">DECISION TRACE</div>
        <pre className="sable-pseudocode">
{`baseline = extract_obligation(baseline_tf)
candidates = generate_successor_hypotheses(baseline, candidate_tf)
scored = score_correspondence(baseline, candidates, evidence)
valid = filter_by_confidence_and_constraints(scored)
projected = project_obligation(baseline.obligation, valid)
security = evaluate_authorization(projected, candidate_tf)
`}
{[
  { branch: 'no_unique_successor', label: 'if no_unique_successor(valid) or evidence_conflicts(valid):', result: '→ UNKNOWN' },
  { branch: 'obligation_holds', label: 'elif obligation_holds(security, intended_successor(valid)):', result: '→ PRESERVED' },
  { branch: 'obligation_violated', label: 'else:', result: '→ REGRESSED' },
].map(b => (
  <span key={b.branch} className={`sable-trace-line ${branchFired === b.branch || (b.branch === 'obligation_violated' && verdict === 'REGRESSED') ? 'fired' : ''}`}>
    {b.label} {b.result}{'\n'}
  </span>
))}
        </pre>
      </div>

      {/* Guidance for each verdict */}
      {verdict === 'REGRESSED' && reviewerNote && (
        <div className="sable-decision-guidance regressed">
          <strong>What a reviewer should check:</strong>
          <p>{reviewerNote}</p>
          <p className="sable-small-note">Note: SABLE does not generate fixes or patched Terraform. This guidance is for human review only.</p>
        </div>
      )}

      {verdict === 'UNKNOWN' && (
        <div className="sable-decision-guidance unknown">
          <strong>What evidence would resolve this:</strong>
          <ul>
            {(candidateAuth?.outside_model?.length ?? 0) > 0 && candidateAuth?.outside_model?.map((item, index) => (
              <li key={`unsupported-${index}`}>Review unsupported authorization construct: <code>{item}</code></li>
            ))}
            {runState.conflicts.length > 0 && (
              <li>Resolve conflicting evidence: {runState.conflicts.join('; ')}</li>
            )}
            {runState.correspondenceReason && <li>Correspondence analysis: {runState.correspondenceReason}</li>}
            {runState.conflicts.length === 0 && (candidateAuth?.outside_model?.length ?? 0) === 0 && (
              <li>Review the correspondence and authorization evidence above, then provide evidence that resolves the reported uncertainty.</li>
            )}
          </ul>
          <p className="sable-small-note warning">UNKNOWN does not mean the change is safe.</p>
        </div>
      )}

      {/* Baselines comparison */}
      {Object.keys(baselines ?? {}).length > 0 && (
        <div className="sable-decision-baselines">
          <div className="sable-card-label">BASELINE COMPARISON</div>
          <div className="sable-baselines-row">
            {['B0', 'B1', 'B2', 'B3', 'B4', 'SABLE'].map(bl => {
              const bv = bl === 'SABLE' ? verdict : (baselines?.[bl]?.verdict ?? '–');
              const color = VERDICT_COLORS[bv] ?? '#6b7280';
              const isReduced = bl === 'B4' && baselines?.B4?.reduced_strength;
              return (
                <div key={bl} className="sable-baseline-chip">
                  <span className="sable-bl-name">{bl}</span>
                  <span className="sable-bl-verdict" style={{ color }}>{bv}</span>
                  {isReduced && <span className="sable-reduced-badge">reduced-strength</span>}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Review buttons for UNKNOWN */}
      {verdict === 'UNKNOWN' && (
        <div className="sable-review-buttons">
          <div className="sable-card-label">HUMAN REVIEW DECISION</div>
          {auditSent ? (
            <div className="sable-audit-sent">
              {auditSent === 'APPROVE' ? <CheckCircle2 size={16} color="#16a34a"/> : <XCircle size={16} color="#dc2626"/>}
              Review decision <strong>{auditSent}</strong> recorded in audit log.
            </div>
          ) : (
            <div className="sable-review-btn-row">
              <button className="sable-btn sable-btn-approve" onClick={() => handleAudit('APPROVE')}>
                <ThumbsUp size={14}/> Approve
              </button>
              <button className="sable-btn sable-btn-reject" onClick={() => handleAudit('REJECT')}>
                <ThumbsDown size={14}/> Reject
              </button>
            </div>
          )}
        </div>
      )}

      {explainSimply && (
        <div className="sable-explain-box">
          {verdict === 'PRESERVED'
            ? 'The highlighted branch shows SABLE confirmed the obligation holds — the role still has exactly the right access on the correct bucket.'
            : verdict === 'REGRESSED'
            ? 'The highlighted branch shows SABLE detected a security boundary change. A human reviewer should check the item above before this change is applied.'
            : 'The highlighted branch shows SABLE could not decide. More information is needed before this change can proceed.'}
        </div>
      )}
    </div>
  );
};
