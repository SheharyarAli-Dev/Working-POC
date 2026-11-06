import React from 'react';
import { SableRunState } from '../types';
import { CheckCircle2, XCircle, AlertTriangle, Copy, Download, RefreshCw } from 'lucide-react';

interface Props { runState: SableRunState; explainSimply: boolean; }

export const EvidenceTab: React.FC<Props> = ({ runState, explainSimply }) => {
  const { evidence, proofData, runId } = runState;
  const [chainStatus, setChainStatus] = React.useState<any>(null);
  const [rerunStatus, setRerunStatus] = React.useState<string | null>(null);
  const [copied, setCopied] = React.useState(false);
  const [chainError, setChainError] = React.useState<string | null>(null);
  const [verifyingChain, setVerifyingChain] = React.useState(false);

  const verifyChain = async () => {
    if (!runId) return;
    setVerifyingChain(true);
    setChainError(null);
    try {
      const r = await fetch(`/api/sable/evidence/${runId}/verify`);
      const d = await r.json();
      if (!r.ok) throw new Error(d?.detail ?? `Evidence verification failed (HTTP ${r.status}).`);
      setChainStatus(d);
    } catch (error) {
      setChainStatus(null);
      setChainError(error instanceof Error ? error.message : 'Evidence verification failed.');
    } finally {
      setVerifyingChain(false);
    }
  };

  const downloadJson = () => {
    const blob = new Blob([JSON.stringify(evidence, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sable_evidence_${runId}.json`;
    a.click();
  };

  const downloadSarif = async () => {
    if (!runId) return;
    const r = await fetch(`/api/sable/evidence/${runId}/sarif`);
    const d = await r.json();
    const blob = new Blob([JSON.stringify(d, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `sable_sarif_${runId}.json`;
    a.click();
  };

  const copyHash = () => {
    if (evidence?.decision_hash) {
      navigator.clipboard.writeText(evidence.decision_hash);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  if (!evidence) {
    return (
      <div className="sable-tab-empty">
        <p>Run a scenario to see the evidence record.</p>
      </div>
    );
  }

  return (
    <div className="sable-tab-content">
      {/* Decision hash */}
      <div className="sable-evidence-hash-row">
        <span>Decision hash:</span>
        <code>{evidence.decision_hash}</code>
        <button className="sable-icon-btn" onClick={copyHash} title="Copy hash">
          {copied ? <CheckCircle2 size={13} color="#16a34a"/> : <Copy size={13}/>}
        </button>
      </div>

      {/* Hash chain verification */}
      <div className="sable-evidence-chain">
        <div className="sable-card-label">EVIDENCE HASH CHAIN</div>
        <div className="sable-chain-actions">
          <button className="sable-btn sable-btn-secondary" onClick={verifyChain} disabled={verifyingChain}>
            <RefreshCw size={12}/> {verifyingChain ? 'Verifying…' : 'Verify chain'}
          </button>
          {proofData && (
            <span className="sable-chain-info">
              {proofData.evidence_chain_length} records in chain
            </span>
          )}
        </div>
        {chainStatus && (
          <div className={`sable-chain-status ${chainStatus.intact ? 'intact' : 'broken'}`}>
            {chainStatus.intact
              ? <><CheckCircle2 size={14}/> Chain intact ({chainStatus.total_records} records verified)</>
              : <><XCircle size={14}/> Chain broken at seq {chainStatus.broken_link_seq}: {chainStatus.error}</>}
          </div>
        )}
        {chainError && <div role="alert" className="sable-diff-warn">{chainError}</div>}
        <p className="sable-small-note">The chain checks record ordering and SHA-256 consistency. It does not prove deployed AWS state or prevent an operator with database access from rebuilding the ledger.</p>
      </div>

      {/* Evidence record */}
      <div className="sable-evidence-record">
        <div className="sable-card-label">EVIDENCE RECORD</div>
        <div className="sable-kv-list">
          <div className="sable-kv"><span>Run ID</span><code>{evidence.run_id}</code></div>
          <div className="sable-kv"><span>Scenario</span><code>{evidence.scenario_id}</code></div>
          <div className="sable-kv"><span>Verdict</span><strong style={{ color: evidence.verdict === 'PRESERVED' ? '#16a34a' : evidence.verdict === 'REGRESSED' ? '#dc2626' : '#d97706' }}>{evidence.verdict}</strong></div>
          <div className="sable-kv"><span>ASENT mapping</span><strong>{evidence.asent_mapping}</strong></div>
          <div className="sable-kv"><span>Chosen successor</span><code>{evidence.chosen_successor ?? '–'}</code></div>
          <div className="sable-kv"><span>Baseline SHA-256</span><code className="sable-hash-truncated">{evidence.baseline_sha256?.slice(0, 20)}…</code></div>
          <div className="sable-kv"><span>Candidate SHA-256</span><code className="sable-hash-truncated">{evidence.candidate_sha256?.slice(0, 20)}…</code></div>
        </div>
      </div>

      {/* Residual uncertainty */}
      {(evidence.residual_uncertainty?.length > 0) && (
        <div className="sable-uncertainty-box">
          <div className="sable-card-label">RESIDUAL UNCERTAINTY</div>
          <ul>
            {evidence.residual_uncertainty.map((u: string, i: number) => (
              <li key={i}><AlertTriangle size={12}/> {u}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Downloads */}
      <div className="sable-evidence-downloads">
        <button className="sable-btn sable-btn-secondary" onClick={downloadJson}>
          <Download size={12}/> Download JSON
        </button>
        <button className="sable-btn sable-btn-secondary" onClick={downloadSarif}>
          <Download size={12}/> Download SARIF
        </button>
      </div>

      {/* Proof drawer raw */}
      {proofData && (
        <details className="sable-proof-details">
          <summary>Raw proof record</summary>
          <pre className="sable-proof-raw">{JSON.stringify(proofData, null, 2).slice(0, 3000)}</pre>
        </details>
      )}

      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong> Every decision SABLE makes is recorded in a hash chain —
          each record is linked to the one before it. If anyone tampers with the records, the
          "Verify chain" button will detect it.
        </div>
      )}
    </div>
  );
};
