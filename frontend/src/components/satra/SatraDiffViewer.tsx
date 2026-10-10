import React from 'react';

interface SecurityRegion {
  file: string;
  lines?: string;
  function?: string;
  kind?: string;
  mapping_reason?: string;
  confidence?: string;
  touches_security?: boolean;
}

interface SatraDiffViewerProps {
  diffText: string;
  regions: SecurityRegion[];
  contract?: any;
}

export const SatraDiffViewer: React.FC<SatraDiffViewerProps> = ({
  diffText,
  regions,
  contract
}) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-slate-200">AST Security Localization & Diff</h3>
          <p className="text-xs text-slate-400">Security boundary mappings detected in candidate commit</p>
        </div>
        {contract && (
          <span className="text-[11px] font-mono bg-blue-950/60 text-blue-400 border border-blue-500/30 px-2 py-0.5 rounded">
            Contract: {contract.rule_id || contract.subject || 'Formulated'}
          </span>
        )}
      </div>

      {regions && regions.length > 0 && (
        <div className="space-y-1.5">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Localized Security Regions ({regions.length})
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
            {regions.map((r, i) => (
              <div
                key={i}
                className="p-2 bg-slate-950/60 border border-slate-800 rounded text-xs space-y-1"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono text-blue-400 font-semibold">{r.file}</span>
                  {r.lines && <span className="text-[10px] text-slate-500">L{r.lines}</span>}
                </div>
                {r.function && (
                  <div className="text-slate-300 font-mono text-[11px]">fn {r.function}()</div>
                )}
                {r.mapping_reason && (
                  <div className="text-[11px] text-slate-400 line-clamp-2">{r.mapping_reason}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="space-y-1.5">
        <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Unified Git Diff</div>
        <pre className="p-3 bg-slate-950 border border-slate-800 rounded font-mono text-[11px] text-slate-300 max-h-56 overflow-y-auto overflow-x-auto whitespace-pre-wrap">
          {diffText || '# No file diff available for this commit'}
        </pre>
      </div>
    </div>
  );
};
