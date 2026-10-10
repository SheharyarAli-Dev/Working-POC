import React from 'react';
import { GitCommit, RefreshCw, GitBranch, Calendar, User } from 'lucide-react';

export interface CommitInfo {
  sha: string;
  parents: string[];
  author: string;
  date: string;
  message: string;
  refs?: string[];
}

interface SatraCommitPickerProps {
  commits: CommitInfo[];
  selectedSha: string;
  onSelectCommit: (sha: string) => void;
  loading: boolean;
  onRefresh: () => void;
}

export const SatraCommitPicker: React.FC<SatraCommitPickerProps> = ({
  commits,
  selectedSha,
  onSelectCommit,
  loading,
  onRefresh
}) => {
  return (
    <div className="satra-commit-picker-card">
      <div className="satra-commit-picker-header">
        <div>
          <div className="satra-commit-picker-title">
            <GitCommit size={15} color="#0284c7" />
            <span>Target Commits (Threat-Repository)</span>
          </div>
          <p className="satra-commit-picker-subtitle">
            Ingested directly from <strong>SheharyarAli-Dev/Threat-Repository</strong>
          </p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="satra-commit-refresh-btn"
          id="refresh-commits-btn"
        >
          <RefreshCw size={12} className={loading ? 'spin' : ''} />
          <span>{loading ? 'Fetching...' : 'Refresh List'}</span>
        </button>
      </div>

      <div className="satra-commit-list">
        {commits.length === 0 ? (
          <div style={{ textAlign: 'center', padding: '24px 12px', color: 'var(--ink-muted)', fontSize: '11.5px' }}>
            No commits loaded. Click "Refresh List" to query Threat-Repository.
          </div>
        ) : (
          commits.map((c) => {
            const isSelected = c.sha === selectedSha;
            const branchRef = c.refs && c.refs.length > 0 ? c.refs[0] : null;

            return (
              <div
                key={c.sha}
                onClick={() => onSelectCommit(c.sha)}
                className={`satra-commit-item ${isSelected ? 'selected' : ''}`}
                id={`commit-row-${c.sha.slice(0, 7)}`}
              >
                <div className="satra-commit-item-top">
                  <span className="satra-sha-badge">
                    <GitCommit size={11} />
                    {c.sha.slice(0, 7)}
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    {branchRef && (
                      <span className="satra-branch-badge">
                        <GitBranch size={9} style={{ display: 'inline', marginRight: 3 }} />
                        {branchRef.replace('origin/', '')}
                      </span>
                    )}
                    <span className="satra-commit-date">
                      <Calendar size={10} style={{ display: 'inline', marginRight: 3 }} />
                      {c.date ? new Date(c.date).toLocaleDateString() : ''}
                    </span>
                  </div>
                </div>

                <div className="satra-commit-message" title={c.message}>
                  {c.message}
                </div>

                <div className="satra-commit-meta">
                  <span style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                    <User size={10} color="var(--ink-muted)" />
                    {c.author}
                  </span>
                  {isSelected && (
                    <span style={{ fontSize: '10px', fontWeight: 700, color: 'var(--accent-emerald)', display: 'flex', alignItems: 'center', gap: '3px' }}>
                      ✓ Selected Target
                    </span>
                  )}
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
