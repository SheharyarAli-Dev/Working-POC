import React from 'react';

export interface GateItem {
  id: string;
  label: string;
  passed: boolean;
  detail?: string;
}

interface SatraGateMatrixProps {
  gates: GateItem[];
  verdict: string;
  runStatus: string;
}

export const SatraGateMatrix: React.FC<SatraGateMatrixProps> = ({ gates, verdict, runStatus }) => {
  const passedCount = gates.filter((g) => g.passed).length;
  const totalCount = gates.length;

  const verdictColor =
    verdict === 'ACCEPT' || verdict === 'ACCEPTED'
      ? 'text-emerald-400 bg-emerald-950/40 border-emerald-500/40'
      : verdict === 'BLOCK' || verdict === 'REJECTED'
      ? 'text-rose-400 bg-rose-950/40 border-rose-500/40'
      : 'text-amber-400 bg-amber-950/40 border-amber-500/40';

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">7-Gate Assurance Matrix</h3>
          <p className="text-xs text-slate-400">Sequential verification required for automated acceptance</p>
        </div>
        <div className="flex items-center space-x-2">
          <span className="text-xs font-mono text-slate-400">
            {passedCount}/{totalCount} Gates
          </span>
          {verdict && (
            <span className={`text-xs font-bold px-2 py-0.5 rounded border ${verdictColor}`}>
              {verdict}
            </span>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        {gates.map((g, idx) => (
          <div
            key={g.id || idx}
            className={`p-2.5 rounded-md border text-xs flex items-start space-x-2.5 transition-all ${
              g.passed
                ? 'bg-emerald-950/20 border-emerald-500/30 text-slate-200'
                : 'bg-rose-950/20 border-rose-500/30 text-slate-300'
            }`}
          >
            <div className="mt-0.5">
              {g.passed ? (
                <span className="flex h-4 w-4 items-center justify-center rounded-full bg-emerald-500/20 text-emerald-400 font-bold text-[10px]">
                  ✓
                </span>
              ) : (
                <span className="flex h-4 w-4 items-center justify-center rounded-full bg-rose-500/20 text-rose-400 font-bold text-[10px]">
                  ✗
                </span>
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="font-medium text-slate-100">{g.label}</div>
              {g.detail && <div className="text-[11px] text-slate-400 mt-0.5 truncate">{g.detail}</div>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
