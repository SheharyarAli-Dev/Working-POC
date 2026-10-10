import React, { useEffect, useState } from 'react';
import { CavrRunState } from './types';
import { ShieldCheck, Download, CheckCircle2, XCircle, Link2, AlertTriangle, RefreshCw, FileCode, Printer } from 'lucide-react';

interface AssuranceTabProps {
  state: CavrRunState;
}

export const AssuranceTab: React.FC<AssuranceTabProps> = ({ state }) => {
  const [chainVerifyStatus, setChainVerifyStatus] = useState<{ intact: boolean; message: string } | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [blocks, setBlocks] = useState<any[]>([]);

  // The certificate of this run, built by the backend from the pipeline's verdict. No sample certificate.
  const cert = state.certificate;
  const residuals: any[] = cert?.residual_uncertainty || [];
  const checks: [string, any][] = Object.entries(cert?.security_checks || {});

  // The real records of this run's hash chain.
  useEffect(() => {
    setBlocks([]);
    setChainVerifyStatus(null);
    if (!state.runId || !cert) return;
    fetch(`/api/cavr/evidence/${state.runId}/records`)
      .then(res => (res.ok ? res.json() : []))
      .then(setBlocks)
      .catch(() => setBlocks([]));
  }, [state.runId, cert]);

  const verifyChainCall = async () => {
    if (!state.runId) return;
    setIsVerifying(true);
    try {
      const res = await fetch(`/api/cavr/evidence/${state.runId}/verify`);
      if (res.ok) {
        const data = await res.json();
        setChainVerifyStatus({ intact: data.intact === true, message: data.message || data.error || "No message from the ledger." });
      } else {
        setChainVerifyStatus({ intact: false, message: `The ledger could not be verified (HTTP ${res.status}).` });
      }
    } catch {
      // An unreachable ledger is not an intact ledger.
      setChainVerifyStatus({ intact: false, message: "The ledger could not be reached, so the chain was not verified." });
    } finally {
      setIsVerifying(false);
    }
  };

  if (!cert) {
    return (
      <div className="evidence-tab-pane assurance-pane">
        <div className="cert-document-card">
          <div className="cert-doc-header">
            <div>
              <span className="cert-badge">BOUNDED TRUST CERTIFICATE</span>
              <h5>No certificate yet</h5>
            </div>
          </div>
          <div className="cert-body-preview">
            <p>The certificate and the evidence chain of a run appear here when the run has finished.</p>
          </div>
        </div>
      </div>
    );
  }

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(cert, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `assurance-cert-${cert.certificate_id}.json`;
    a.click();
  };

  const openPrintableHtml = () => {
    if (state.runId) {
      window.open(`/api/cavr/evidence/${state.runId}/certificate.html`, '_blank');
    }
  };

  return (
    <div className="evidence-tab-pane assurance-pane">
      {/* Visual Hash Chain with Verify & Tamper Buttons */}
      <div className="hash-chain-card">
        <div className="chain-topbar">
          <div>
            <h6>Evidence chain of this run ({blocks.length} records)</h6>
            <span className="chain-sub">Each event of the run is hashed together with the SHA-256 of the record before it.</span>
          </div>

          <div className="chain-actions">
            <button 
              className={`chain-btn verify ${isVerifying ? 'loading' : ''}`}
              onClick={verifyChainCall}
            >
              <RefreshCw size={12} className={isVerifying ? 'anim-spin' : ''} />
              <span>Verify Chain</span>
            </button>
          </div>
        </div>

        {/* Chain Verification Result Toast */}
        {chainVerifyStatus && (
          <div className={`chain-verify-alert ${chainVerifyStatus.intact ? 'intact' : 'broken'}`}>
            {chainVerifyStatus.intact ? <CheckCircle2 size={16} /> : <XCircle size={16} />}
            <span>{chainVerifyStatus.message}</span>
          </div>
        )}

        {/* Linked Blocks Visual Strip */}
        <div className="chain-blocks-strip">
          {blocks.map((b, idx) => {
            const isBroken = false;

            return (
              <React.Fragment key={b.seq}>
                <div className={`chain-block ${isBroken ? 'broken-block' : 'valid-block'}`}>
                  <div className="block-seq">BLOCK #{b.seq}</div>
                  <div className="block-phase">{b.phase}</div>
                  <strong className="block-name">{b.substep || b.type}</strong>
                  <code className="block-hash">{String(b.sha256).substring(0, 12)}...</code>
                </div>
                {idx < blocks.length - 1 && (
                  <div className={`chain-connector ${isBroken ? 'broken-link' : 'valid-link'}`}>
                    <Link2 size={14} />
                  </div>
                )}
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Assurance Certificate Document Preview */}
      <div className="cert-document-card">
        <div className="cert-doc-header">
          <div>
            <span className="cert-badge">BOUNDED TRUST CERTIFICATE</span>
            <h5>{cert.certificate_id}</h5>
          </div>

          <div className="cert-btn-group">
            <button className="doc-btn" onClick={downloadJson}>
              <Download size={13} />
              <span>Download JSON</span>
            </button>
            <button className="doc-btn" onClick={openPrintableHtml}>
              <Printer size={13} />
              <span>Printable HTML</span>
            </button>
          </div>
        </div>

        <div className="cert-body-preview">
          <div className="cert-verdict-callout">
            <strong>VERDICT: {cert.status} ({cert.stage} / {cert.rule})</strong>
            <p>{cert.reason}</p>
            <p>"{cert.bounded_trust_claim}"</p>
            <p>
              fast_gate_ms: {String(cert.fast_gate_ms)} · cache_hit: {String(cert.cache_hit)} · escalated: {String(cert.escalated)}
              {cert.escalation ? ` · escalation: ${cert.escalation}` : ''}
              {cert.demo_condition ? ` · demo condition: ${cert.demo_condition.id}` : ''}
            </p>
          </div>

          <div className="cert-kv-grid">
            <div><span>Package:</span> <strong>{cert.subject?.package}</strong></div>
            <div><span>Version:</span> <code>{cert.subject?.version}</code></div>
            <div><span>Artifact SHA-256:</span> <code>{cert.subject?.artifact_sha256 || 'not downloaded'}</code></div>
            <div><span>Registry SHA-256:</span> <code>{cert.subject?.registry_sha256 || 'not read'}</code></div>
            <div><span>Subtree Digest:</span> <code>{cert.subject?.subtree_digest || 'not built'}</code></div>
            <div><span>Contract Digest:</span> <code>{cert.subject?.contract_digest || 'not inferred'}</code></div>
            {checks.map(([name, value]) => (
              <div key={name}><span>{name}:</span> <code>{Array.isArray(value) ? value.join(', ') : String(value)}</code></div>
            ))}
          </div>
        </div>
      </div>

      {/* Prominent Residual Uncertainty Box */}
      <div className="prominent-residual-box">
        <div className="residual-header">
          <AlertTriangle size={18} className="text-amber-400" />
          <h5>What this certificate does not establish</h5>
        </div>

        <p className="residual-explainer">
          The verdict is bounded by the checks listed above. These limits are part of the certificate:
        </p>

        <div className="residual-bullets-grid">
          <div className="residual-bullet-col">
            <strong>Limits stated by this run:</strong>
            <ul>
              {residuals.length > 0 ? (
                residuals.map((r: any, i: number) => (
                  <li key={i}><code>{r.predicate}</code> ({r.file_line}): {r.reason}</li>
                ))
              ) : (
                <li>None reported.</li>
              )}
            </ul>
          </div>

          <div className="residual-bullet-col">
            <strong>Method limits of the fast gate:</strong>
            <ul>
              <li>Static checks only: no package code is installed, imported or run.</li>
              <li>Compiled code in a wheel is not analysed; such a wheel is UNRESOLVED.</li>
              <li>Advisories are what OSV listed when it was asked; they are asked again on every run.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
};
