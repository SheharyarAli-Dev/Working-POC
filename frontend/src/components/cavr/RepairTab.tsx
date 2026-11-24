import React from 'react';
import { CavrRunState, RepairBlock, RepairPart, shown } from './types';
import { ThumbsUp, ThumbsDown, Lock, ShieldCheck } from 'lucide-react';

interface RepairTabProps {
  state: CavrRunState;
  onApproveReject: (approved: boolean) => void;
  decisionState: 'pending' | 'approved' | 'rejected';
}

// The repair block of backend/cavr/repair_proposal.py, printed as the backend wrote it. A proposal only:
// CAVR never applies it and the verdict above stays what the pipeline decided.
export const RepairTab: React.FC<RepairTabProps> = ({ state, onApproveReject, decisionState }) => {
  const repair: RepairBlock | null = state.repair;
  if (!repair) {
    return (
      <div className="evidence-tab-pane repair-pane">
        <div className="reverification-card">
          <h6>Repair proposal</h6>
          <p>Not run: repair is looked for only when a package is REJECTED.</p>
        </div>
      </div>
    );
  }
  const skipped = (repair.candidates_tried || []).filter((candidate) => candidate.outcome !== 'PROPOSED');

  return (
    <div className="evidence-tab-pane repair-pane">
      <div className="reverification-card">
        <h6>Repair proposal</h6>
        <p>
          <strong>{shown(repair.package)}=={shown(repair.version)}</strong> was {shown(repair.rejected?.status)} (
          {shown(repair.rejected?.stage)} / {shown(repair.rejected?.rule)}).
        </p>
        <p>Result: <strong>{shown(repair.result)}</strong> ({shown(repair.rule)}). {shown(repair.reason)}</p>
        <p>Applied: {String(repair.applied)}. Gate decision changed: {String(repair.gate_decision_changed)}.</p>
      </div>

      {repair.pin && <ProposalCard title={`Pin ${repair.pin.requirement}`} part={repair.pin} />}
      {repair.removal && <ProposalCard title={`Remove ${repair.removal.name}`} part={repair.removal} />}
      {!repair.removal && repair.removal_reason && (
        <div className="reverification-card"><p>Removal not proposed: {repair.removal_reason}</p></div>
      )}

      {repair.result === 'NOT_ATTEMPTED' ? (
        <div className="reverification-card">
          <h6>Candidates</h6>
          <p>No candidate was looked for ({shown(repair.rule)}).</p>
        </div>
      ) : (
        <div className="reverification-card">
          <h6>Candidates</h6>
          <p>
            Tried: {shown(repair.budget?.tried)} of at most {shown(repair.budget?.max_candidates)} within{' '}
            {shown(repair.budget?.seconds)} s. Stopped by the budget: {shown(repair.budget?.stopped_by)}.
          </p>
          <ul>
            {skipped.map((candidate) => (
              <li key={`skipped-${candidate.version}`}>
                skipped {candidate.version}: {shown(candidate.status)} {shown(candidate.rule)}: {shown(candidate.reason)}
              </li>
            ))}
          </ul>
          <details>
            <summary>{(repair.excluded || []).length} releases left out before any re-check</summary>
            <ul>
              {(repair.excluded || []).map((entry) => (
                <li key={`excluded-${entry.version}`}>{entry.version}: {entry.rule}: {entry.reason}</li>
              ))}
            </ul>
          </details>
        </div>
      )}

      <div className="reverification-card">
        <h6>Limitations</h6>
        <ul>
          {(repair.limitations || []).map((item) => <li key={item}>{item}</li>)}
        </ul>
      </div>

      {(repair.pin || repair.removal) && (
        <div className="repair-decision-card">
          <div className="decision-header">
            <Lock size={16} className="text-amber-400" />
            <h6>Human approval</h6>
          </div>
          <p className="decision-notice">
            The proposal is applied by a person, in a pull request of its own. These buttons only record the decision in
            the audit log; nothing is installed and no project file is changed.
          </p>
          <div className="decision-buttons-row">
            <button
              className={`repair-act-btn approve ${decisionState === 'approved' ? 'selected' : ''}`}
              onClick={() => onApproveReject(true)}
              disabled={decisionState !== 'pending'}
            >
              <ThumbsUp size={14} />
              <span>{decisionState === 'approved' ? 'Approval recorded' : 'Record approval'}</span>
            </button>
            <button
              className={`repair-act-btn reject ${decisionState === 'rejected' ? 'selected' : ''}`}
              onClick={() => onApproveReject(false)}
              disabled={decisionState !== 'pending'}
            >
              <ThumbsDown size={14} />
              <span>{decisionState === 'rejected' ? 'Rejection recorded' : 'Record rejection'}</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
};

const ProposalCard: React.FC<{ title: string; part: RepairPart }> = ({ title, part }) => {
  const recheck = part.recheck || {};
  const lock = part.lockfile_entry;
  const policy = part.policy || {};
  const changes = [...(policy.added || []).map((item) => `+ ${item}`), ...(policy.removed || []).map((item) => `- ${item}`)];
  return (
    <div className="reverification-card">
      <div className="reverify-header">
        <ShieldCheck size={16} className="text-emerald-400" />
        <h6>{title}</h6>
      </div>
      <p>
        Re-check: <strong>{shown(recheck.status)}</strong> {shown(recheck.rule)} ({shown(recheck.request)}).{' '}
        {shown(recheck.reason)}
      </p>
      {recheck.package && (
        <p>
          Wheel sha256 {shown(recheck.package.sha256)}; registry sha256 {shown(recheck.package.registry_sha256)}.
        </p>
      )}
      {part.requirements_diff ? (
        <pre className="diff-pre">
          {part.requirements_diff.split('\n').filter((line) => line !== '').map((line, index) => (
            <span key={index} className={line.startsWith('+') && !line.startsWith('+++') ? 'diff-add'
              : line.startsWith('-') && !line.startsWith('---') ? 'diff-del' : ''}>{line + '\n'}</span>
          ))}
        </pre>
      ) : (
        <p>Command: {shown(part.pip_command)}</p>
      )}
      <p>
        Lockfile: {lock ? (lock.after ? `${lock.file}: ${lock.after.name} ${lock.after.version} sha256 ${lock.after.sha256}`
          : `${lock.file}: remove ${shown(lock.before?.name)}`) : 'none in the project'}
      </p>
      <p>Policy approved_requirements: {changes.length ? changes.join(', ') : 'no change needed'}</p>
    </div>
  );
};
