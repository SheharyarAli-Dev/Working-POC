import React from 'react';
import { Code2, ShieldAlert, GitCommit } from 'lucide-react';

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
    <div className="satra-diff-box">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ink-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <Code2 size={16} color="#0284c7" />
            <span>AST Security Localization &amp; Git Diff</span>
          </div>
          <p style={{ fontSize: '11px', color: 'var(--ink-muted)', marginTop: '2px' }}>
            Security boundaries and changed functions localized from candidate commit
          </p>
        </div>
        {contract && (
          <span style={{
            fontSize: '10.5px',
            fontFamily: 'monospace',
            fontWeight: 700,
            background: '#e0f2fe',
            color: '#0369a1',
            padding: '3px 8px',
            borderRadius: '4px',
            border: '1px solid #bae6fd'
          }}>
            Contract: {contract.rule_id || contract.subject || 'Formulated'}
          </span>
        )}
      </div>

      {regions && regions.length > 0 && (
        <div style={{ marginBottom: '14px' }}>
          <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
            <ShieldAlert size={12} color="#f59e0b" />
            <span>Localized Security Regions ({regions.length})</span>
          </div>
          <div className="satra-regions-grid">
            {regions.map((r, i) => (
              <div key={i} className="satra-region-cell">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '4px' }}>
                  <span style={{ fontFamily: 'monospace', color: '#0284c7', fontWeight: 700 }}>
                    {r.file}
                  </span>
                  {r.lines && <span style={{ fontSize: '10px', color: 'var(--ink-faded)' }}>L{r.lines}</span>}
                </div>
                {r.function && (
                  <div style={{ fontSize: '11px', color: 'var(--ink-primary)', fontFamily: 'monospace', fontWeight: 600 }}>
                    fn {r.function}()
                  </div>
                )}
                {r.mapping_reason && (
                  <div style={{ fontSize: '10.5px', color: 'var(--ink-muted)', marginTop: '3px' }}>
                    {r.mapping_reason}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
          <GitCommit size={12} />
          <span>Unified Git Diff</span>
        </div>
        <pre className="satra-diff-pre">
          {diffText || '# No file diff available for this commit'}
        </pre>
      </div>
    </div>
  );
};
