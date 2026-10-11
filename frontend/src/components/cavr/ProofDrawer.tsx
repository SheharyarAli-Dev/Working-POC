import React from 'react';
import { shown } from './types';

interface ProofDrawerProps {
  // The answer of GET /api/cavr/proof/{run_id}.
  proof: any;
  onClose: () => void;
}

// The proof of one run, printed as the backend returned it. Nothing here is decided by the page:
// the hash result is the pipeline's rule for the artifact, and a field that is null is a dash.
export const ProofDrawer: React.FC<ProofDrawerProps> = ({ proof, onClose }) => (
  <div className="modal-backdrop" onClick={() => onClose()}>
    <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
      <div className="drawer-top">
        <div>
          <span className="modal-eyebrow">AUDIT RECORD</span>
          <h3>Proof of this run</h3>
          <p>Every line is a field of GET /api/cavr/proof/{shown(proof.run_id)}.</p>
        </div>
        <button className="modal-close-btn" onClick={() => onClose()}>✕</button>
      </div>

      <div className="drawer-content-scroll">
        <div className="proof-group">
          <label>Request and verdict:</label>
          <div className="proof-kv">
            <div><span>Request:</span> <code>{shown(proof.request)}</code></div>
            <div><span>Status:</span> <strong>{shown(proof.cavr_verdict?.status)}</strong></div>
            <div><span>Stage / rule:</span> <code>{shown(proof.cavr_verdict?.stage)} / {shown(proof.cavr_verdict?.rule)}</code></div>
            <div><span>Reason:</span> {shown(proof.cavr_verdict?.reason)}</div>
            <div><span>fast_gate_ms:</span> <code>{shown(proof.cavr_verdict?.fast_gate_ms)}</code></div>
            <div><span>cache_hit:</span> <code>{shown(proof.cavr_verdict?.cache_hit)}</code></div>
            <div><span>Demo condition:</span> <code>{shown(proof.demo_condition?.id)}</code> {proof.demo_condition?.description}</div>
          </div>
        </div>

        <div className="proof-group">
          <label>Hash comparison:</label>
          <div className="proof-kv">
            <div><span>Registry SHA-256:</span> <code>{shown(proof.hash_comparison?.declared_or_expected)}</code></div>
            <div><span>SHA-256 of the downloaded file:</span> <code>{shown(proof.hash_comparison?.actual_sha256)}</code></div>
            <div><span>Result:</span> <strong>{shown(proof.hash_comparison?.rule)}</strong></div>
            <div><span>Bytes equal the registry digest:</span> <code>{shown(proof.hash_comparison?.matches)}</code></div>
          </div>
        </div>

        <div className="proof-group">
          <label>Sandbox:</label>
          <div className="proof-kv">
            <div><span>Container command:</span> <code>{shown(proof.docker_command)}</code></div>
            <div><span>Container ID:</span> <code>{shown(proof.container_id)}</code></div>
            <div><span>Image digest:</span> <code>{shown(proof.image_digest)}</code></div>
          </div>
        </div>

        <div className="proof-group">
          <label>Counterfactual runs ({shown(proof.counterfactual_runs?.length)}):</label>
          <div className="cf-proof-list">
            {(proof.counterfactual_runs || []).map((r: any) => (
              <div key={r.run_number} className="cf-proof-item">
                <strong>Run {r.run_number}: {shown(r.condition_applied?.name)}</strong>
                <span>Behaviors: {shown(r.behaviors_found?.map((b: any) => b.action).join(', '))}</span>
              </div>
            ))}
          </div>
        </div>

        <div className="proof-group">
          <label>Evidence chain (hash of the last record before the certificate was issued):</label>
          <code className="proof-code">{shown(proof.evidence_chain_root)}</code>
          <div className="proof-kv">
            <div><span>Records:</span> <code>{shown(proof.evidence_records_count)}</code></div>
            <div><span>Certificate:</span> <code>{shown(proof.certificate_id)}</code></div>
          </div>
        </div>

        <div className="proof-group">
          <label>The whole proof as JSON:</label>
          <a href={`/api/cavr/proof/${proof.run_id}`} target="_blank" rel="noreferrer">/api/cavr/proof/{proof.run_id}</a>
        </div>
      </div>
    </div>
  </div>
);
