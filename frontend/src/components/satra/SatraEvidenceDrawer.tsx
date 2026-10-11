import React from 'react';
import { X, FileCode, Shield, Terminal } from 'lucide-react';

interface SatraEvidenceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  evidenceData: any;
  proofData: any;
}

export const SatraEvidenceDrawer: React.FC<SatraEvidenceDrawerProps> = ({
  isOpen,
  onClose,
  evidenceData,
  proofData
}) => {
  if (!isOpen) return null;

  return (
    <>
      <div className="satra-drawer-backdrop" onClick={onClose} />
      <div className="satra-drawer-panel">
        <div className="satra-drawer-header">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FileCode size={16} color="var(--accent-emerald)" />
            <div>
              <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--ink-primary)' }}>
                Assurance Evidence &amp; Proof Drawer
              </div>
              <div style={{ fontSize: '11px', color: 'var(--ink-muted)' }}>
                Verifiable Docker sandbox execution chain
              </div>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              padding: '6px',
              borderRadius: '4px',
              border: '1px solid var(--border-light)',
              background: '#ffffff',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              color: 'var(--ink-secondary)'
            }}
          >
            <X size={15} />
          </button>
        </div>

        <div className="satra-drawer-body">
          {proofData && (
            <div>
              <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Terminal size={12} color="#0284c7" />
                <span>Hardened Container Execution Command</span>
              </div>
              <pre style={{
                background: '#0f172a',
                color: '#38bdf8',
                padding: '12px',
                borderRadius: 'var(--radius-sm)',
                fontFamily: 'monospace',
                fontSize: '11px',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
                border: '1px solid #1e293b'
              }}>
                {proofData.docker_command || 'docker run --rm --network none --read-only asent-sandbox:local'}
              </pre>
            </div>
          )}

          {proofData?.image_digest && (
            <div>
              <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <Shield size={12} color="var(--accent-emerald)" />
                <span>Container Image Digest</span>
              </div>
              <div style={{
                background: '#f8fafc',
                border: '1px solid var(--border-light)',
                borderRadius: 'var(--radius-sm)',
                padding: '10px 12px',
                fontFamily: 'monospace',
                fontSize: '11px',
                color: 'var(--ink-primary)',
                wordBreak: 'break-all'
              }}>
                {proofData.image_digest}
              </div>
            </div>
          )}

          <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <div style={{ fontSize: '10.5px', fontWeight: 700, color: 'var(--ink-muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: '6px' }}>
              Full Evidence &amp; Gate Trace (JSON)
            </div>
            <pre style={{
              flex: 1,
              background: '#0f172a',
              color: '#cbd5e1',
              padding: '12px',
              borderRadius: 'var(--radius-sm)',
              fontFamily: 'monospace',
              fontSize: '10.5px',
              overflow: 'auto',
              maxHeight: '400px',
              border: '1px solid #1e293b'
            }}>
              {JSON.stringify(evidenceData || proofData?.evidence_json || {}, null, 2)}
            </pre>
          </div>
        </div>

        <div className="satra-drawer-footer">
          <button
            onClick={onClose}
            className="btn-secondary"
            style={{ padding: '8px 16px', fontSize: '12px' }}
          >
            Close Drawer
          </button>
        </div>
      </div>
    </>
  );
};
