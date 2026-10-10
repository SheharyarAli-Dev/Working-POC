import React from 'react';
import { CheckCircle2, XCircle, ShieldCheck } from 'lucide-react';

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

export const SatraGateMatrix: React.FC<SatraGateMatrixProps> = ({ gates, verdict }) => {
  const passedCount = gates.filter((g) => g.passed).length;
  const totalCount = gates.length;

  const isAccepted = verdict === 'ACCEPT' || verdict === 'ACCEPTED';
  const isRejected = verdict === 'BLOCK' || verdict === 'REJECTED';

  return (
    <div className="satra-gate-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ink-primary)', display: 'flex', alignItems: 'center', gap: '6px' }}>
            <ShieldCheck size={16} color="var(--accent-emerald)" />
            <span>7-Gate Assurance Matrix</span>
          </div>
          <p style={{ fontSize: '11px', color: 'var(--ink-muted)', marginTop: '2px' }}>
            Sequential verification required for autonomous promotion
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{ fontSize: '11px', fontFamily: 'monospace', fontWeight: 700, color: 'var(--ink-secondary)' }}>
            {passedCount}/{totalCount} Gates
          </span>
          {verdict && (
            <span
              style={{
                fontSize: '11px',
                fontWeight: 800,
                padding: '3px 8px',
                borderRadius: '4px',
                border: '1px solid',
                borderColor: isAccepted ? '#86efac' : isRejected ? '#fca5a5' : '#fde047',
                background: isAccepted ? '#f0fdf4' : isRejected ? '#fef2f2' : '#fefce8',
                color: isAccepted ? '#15803d' : isRejected ? '#b91c1c' : '#854d0e'
              }}
            >
              {verdict}
            </span>
          )}
        </div>
      </div>

      <div className="satra-gate-grid">
        {gates.map((g, idx) => (
          <div
            key={g.id || idx}
            className={`satra-gate-cell ${g.passed ? 'passed' : 'failed'}`}
          >
            <div className={`satra-gate-icon ${g.passed ? 'passed' : 'failed'}`}>
              {g.passed ? <CheckCircle2 size={13} /> : <XCircle size={13} />}
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ fontWeight: 600, color: 'var(--ink-primary)', fontSize: '11.5px' }}>
                {g.label}
              </div>
              {g.detail && (
                <div style={{ fontSize: '10.5px', color: 'var(--ink-muted)', marginTop: '2px', wordBreak: 'break-word' }}>
                  {g.detail}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
