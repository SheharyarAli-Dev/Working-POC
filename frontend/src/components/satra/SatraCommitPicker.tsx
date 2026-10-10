import React from 'react';

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
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">Target Commits (Threat-Repository)</h3>
          <p className="text-xs text-slate-400">Ingested from SheharyarAli-Dev/Threat-Repository</p>
        </div>
        <button
          onClick={onRefresh}
          disabled={loading}
          className="text-xs px-2.5 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 transition-colors border border-slate-700 disabled:opacity-50"
        >
          {loading ? 'Refreshing...' : 'Refresh List'}
        </button>
      </div>

      <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
        {commits.length === 0 ? (
          <div className="text-xs text-slate-500 py-3 text-center">No commits loaded. Click refresh to query Threat-Repository.</div>
        ) : (
          commits.map((c) => {
            const isSelected = c.sha === selectedSha;
            return (
              <div
                key={c.sha}
                onClick={() => onSelectCommit(c.sha)}
                className={`p-2.5 rounded-md cursor-pointer text-xs transition-all border ${
                  isSelected
                    ? 'bg-blue-950/40 border-blue-500/60 shadow-sm'
                    : 'bg-slate-950/60 border-slate-800/80 hover:border-slate-700'
                }`}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="font-mono text-[11px] font-bold text-blue-400">{c.sha.slice(0, 7)}</span>
                  <span className="text-[10px] text-slate-500">{c.date ? new Date(c.date).toLocaleDateString() : ''}</span>
                </div>
                <div className="font-medium text-slate-200 line-clamp-1">{c.message}</div>
                <div className="text-[11px] text-slate-400 mt-1 flex items-center justify-between">
                  <span>{c.author}</span>
                  {c.refs && c.refs.length > 0 && (
                    <span className="text-[10px] bg-slate-800 px-1.5 py-0.5 rounded text-slate-300 font-mono">
                      {c.refs[0]}
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
