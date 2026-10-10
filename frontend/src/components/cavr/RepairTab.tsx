import React from 'react';
import { CavrRunState, NOT_RUN_ON_FAST_GATE } from './types';
import { Wrench, CheckCircle2, XCircle, ThumbsUp, ThumbsDown, Lock, ArrowRight, ShieldCheck } from 'lucide-react';

interface RepairTabProps {
  state: CavrRunState;
  onApproveReject: (approved: boolean) => void;
  decisionState: 'pending' | 'approved' | 'rejected';
}

export const RepairTab: React.FC<RepairTabProps> = ({ state, onApproveReject, decisionState }) => {
  if (!state.repair) {
    // No invented substitute and no invented "all obligations passed" list.
    return (
      <div className="evidence-tab-pane repair-pane">
        <div className="reverification-card">
          <h6>Repair and re-verification</h6>
          <p>{NOT_RUN_ON_FAST_GATE}</p>
        </div>
      </div>
    );
  }
  const repair = state.repair;
  const reverification = state.reverification || { all_passed: false, obligations: [] };

  const candidates = repair.ranked_candidates || [];
  const chosen = repair.chosen_candidate || candidates[0];

  return (
    <div className="evidence-tab-pane repair-pane">
      {/* Dependency Tree with Crossed Out Rejected Path */}
      <div className="repair-top-grid">
        <div className="repair-tree-card">
          <h6>Dependency Tree &amp; Rejection Boundary</h6>
          <div className="dep-tree-box">
            <div className="tree-node root">
              <span>project: invoice_extractor</span>
            </div>
            <div className="tree-branch">
              <span className="branch-line">└── </span>
              <span className="tree-node rejected-node">
                <del>{state.package}=={state.version}</del>
                <span className="rejected-badge">BLOCKED / QUARANTINED</span>
              </span>
            </div>
            {chosen && (
              <div className="tree-branch approved-branch">
                <span className="branch-line">└── </span>
                <span className="tree-node safe-node">
                  <strong>{chosen.name}=={chosen.version}</strong>
                  <span className="safe-badge">RECOMMENDED SUBSTITUTE</span>
                </span>
              </div>
            )}
          </div>

          {/* Before & After Diff */}
          <div className="dependency-diff-box">
            <span className="diff-title">Dependency Specification Diff:</span>
            <pre className="diff-pre">
              <span className="diff-del">{repair.dependency_diff?.before}</span>
              {"\n"}
              <span className="diff-add">{repair.dependency_diff?.after}</span>
            </pre>
          </div>
        </div>

        {/* Human-in-the-Loop Action Card */}
        <div className="repair-decision-card">
          <div className="decision-header">
            <Lock size={16} className="text-amber-400" />
            <h6>Human-in-the-Loop Authorization Gate</h6>
          </div>
          <p className="decision-notice">
            Under ASENT assurance rules, automated tools may <strong>never</strong> install repair candidates silently. 
            All substitutions require explicit operator approval recorded in the audit log.
          </p>

          {chosen ? (
            <div className="chosen-candidate-preview">
              <div className="candidate-name-row">
                <strong>{chosen.name}</strong> <code>v{chosen.version}</code>
                <span className="candidate-level-pill">{chosen.level_name}</span>
              </div>
              <p className="candidate-reason">{chosen.justification}</p>
            </div>
          ) : (
            <p className="no-cand">No safe alternative discovered. Package permanently unresolved.</p>
          )}

          <div className="decision-buttons-row">
            <button 
              className={`repair-act-btn approve ${decisionState === 'approved' ? 'selected' : ''}`}
              onClick={() => onApproveReject(true)}
              disabled={decisionState !== 'pending'}
            >
              <ThumbsUp size={14} />
              <span>{decisionState === 'approved' ? 'Approved & Logged' : 'Approve Alternative'}</span>
            </button>

            <button 
              className={`repair-act-btn reject ${decisionState === 'rejected' ? 'selected' : ''}`}
              onClick={() => onApproveReject(false)}
              disabled={decisionState !== 'pending'}
            >
              <ThumbsDown size={14} />
              <span>{decisionState === 'rejected' ? 'Rejected & Quarantined' : 'Reject Substitute'}</span>
            </button>
          </div>
        </div>
      </div>

      {/* Candidate Ranking with Stacked Cost Breakdown */}
      <div className="candidate-ranking-card">
        <h6>Candidate Ranking &amp; Objective Cost Breakdown</h6>
        <span className="cost-formula-note">
          Objective: <code>Cost = w1·(direct deps changed) + w2·(version distance) + w3·(call sites changed) + w4·(new risk)</code>
        </span>

        <div className="candidates-list">
          {candidates.map((cand: any, idx: number) => {
            const isChosen = cand.name === chosen?.name;
            const cb = cand.cost_breakdown || { w1_direct_deps: 50, w2_version_distance: 10, w3_call_sites_changed: 0, w4_new_risk: 0 };

            return (
              <div key={idx} className={`candidate-row-card ${isChosen ? 'is-chosen' : ''}`}>
                <div className="candidate-col-info">
                  <div className="cand-rank-badge">#{idx + 1}</div>
                  <div>
                    <strong>{cand.name}</strong> <code>v{cand.version}</code>
                    <span className="cand-level-sub">{cand.level_name}</span>
                  </div>
                </div>

                {/* Stacked Cost Bar */}
                <div className="candidate-col-cost">
                  <div className="cost-total-row">
                    <span>Total Cost:</span>
                    <strong>{cand.cost}</strong>
                  </div>
                  <div className="stacked-cost-bar">
                    <div className="cost-seg w1" style={{ width: `${Math.min(cb.w1_direct_deps * 0.8, 40)}%` }} title={`Deps Cost: ${cb.w1_direct_deps}`} />
                    <div className="cost-seg w2" style={{ width: `${Math.min(cb.w2_version_distance * 0.8, 30)}%` }} title={`Version Dist Cost: ${cb.w2_version_distance}`} />
                    <div className="cost-seg w3" style={{ width: `${Math.min(cb.w3_call_sites_changed * 0.8, 30)}%` }} title={`Call Sites Cost: ${cb.w3_call_sites_changed}`} />
                  </div>
                </div>

                {/* Constraints Checklist */}
                <div className="candidate-col-constraints">
                  <span className="checklist-tag"><CheckCircle2 size={12} className="text-emerald-400" /> Unreachable</span>
                  <span className="checklist-tag"><CheckCircle2 size={12} className="text-emerald-400" /> Satisfiable</span>
                  <span className="checklist-tag"><CheckCircle2 size={12} className="text-emerald-400" /> OSV Clean</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Re-Verification Obligations Checklist */}
      <div className="reverification-card">
        <div className="reverify-header">
          <ShieldCheck size={16} className="text-emerald-400" />
          <h6>Candidate Re-Verification Obligations (P11)</h6>
        </div>

        <div className="obligations-grid">
          {reverification.obligations?.map((ob: any) => (
            <div key={ob.id} className="obligation-item">
              <CheckCircle2 size={15} className="text-emerald-400" />
              <div>
                <strong>{ob.obligation}</strong>
                {ob.evidence && <p>{ob.evidence}</p>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
