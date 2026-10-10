import React, { useState } from 'react';
import { CavrRunState } from './types';
import { ChevronDown, ChevronRight, AlertTriangle, CheckCircle2, XCircle } from 'lucide-react';

interface CapabilityContractTabProps {
  state: CavrRunState;
}

export const CapabilityContractTab: React.FC<CapabilityContractTabProps> = ({ state }) => {
  const [expandedRows, setExpandedRows] = useState<Record<string, boolean>>({});

  const toggleRow = (cap: string) => {
    setExpandedRows(prev => ({ ...prev, [cap]: !prev[cap] }));
  };

  const contractRows = state.actionData?.capability_contract?.contract_rows || [
    { capability: "FILE_READ(invoice_documents)", status: "REQUIRED", evidence: "invoice_extractor/reader.py:14", justification: "Local PDF stream reading via PdfReader", confidence: 0.98 },
    { capability: "FILE_WRITE(scratch_tmp)", status: "OPTIONAL", evidence: "sandbox_scratchpad", justification: "Scratch buffer write permitted", confidence: 0.85 },
    { capability: "NETWORK_CONNECT(unrestricted)", status: "DENIED", evidence: "project_policy.json", justification: "Offline invoice parser disallows external sockets", confidence: 1.0 },
    { capability: "SECRET_READ(credentials)", status: "DENIED", evidence: "project_policy.json", justification: "No credential store access justified", confidence: 1.0 },
    { capability: "PROCESS_EXEC", status: "DENIED", evidence: "project_policy.json", justification: "Subprocess creation strictly prohibited", confidence: 1.0 },
    { capability: "PERSISTENCE_WRITE", status: "DENIED", evidence: "project_policy.json", justification: "Modifying system startup hooks prohibited", confidence: 1.0 },
    { capability: "NATIVE_EXEC", status: "DENIED", evidence: "pure_python_policy", justification: "Unverified ELF/PE binaries forbidden", confidence: 0.95 }
  ];

  // Observed capabilities from counterfactual runs
  const observedActions = new Set<string>();
  if (state.counterfactualResults?.runs) {
    for (const r of state.counterfactualResults.runs) {
      for (const b of (r.behaviors_found || [])) {
        observedActions.add(b.action);
      }
    }
  }

  return (
    <div className="evidence-tab-pane capability-pane">
      <div className="tab-intro-card">
        <div>
          <h5>Capability Contract Matrix</h5>
          <p>Deterministic capability vocabulary derived from actual AST call sites in your sample invoice project vs observed dynamic behavior.</p>
        </div>
        <div className="contract-legend">
          <span className="legend-chip required">REQUIRED (Justified)</span>
          <span className="legend-chip optional">OPTIONAL (Permitted)</span>
          <span className="legend-chip denied">DENIED (Forbidden)</span>
        </div>
      </div>

      <div className="matrix-table-wrap">
        <table className="matrix-table">
          <thead>
            <tr>
              <th style={{ width: '30%' }}>Capability Scope</th>
              <th style={{ width: '15%' }}>Declared Contract</th>
              <th style={{ width: '15%' }}>Allowed Policy</th>
              <th style={{ width: '20%' }}>Observed Dynamic</th>
              <th style={{ width: '20%' }}>Result Matrix</th>
            </tr>
          </thead>
          <tbody>
            {contractRows.map((row: any) => {
              const cap = row.capability;
              const isExpanded = !!expandedRows[cap];

              // Check if observed
              let observed = "NONE";
              let hasMismatch = false;

              if (cap.includes("FILE_READ")) {
                observed = observedActions.has("FILE_READ") ? "OBSERVED (memory)" : "Clean";
              } else if (cap.includes("NETWORK")) {
                if (observedActions.has("NETWORK_CONNECT")) {
                  observed = "SOCKET_CONNECT (127.0.0.1:18765)";
                  hasMismatch = true;
                }
              } else if (cap.includes("SECRET_READ")) {
                if (observedActions.has("SECRET_ACCESS")) {
                  observed = "HONEYTOKEN_READ (~/.aws/credentials)";
                  hasMismatch = true;
                }
              } else if (cap.includes("PROCESS_EXEC")) {
                if (observedActions.has("PROCESS_CREATE")) {
                  observed = "SUBPROCESS_SPAWNED";
                  hasMismatch = true;
                }
              }

              return (
                <React.Fragment key={cap}>
                  <tr 
                    className={`matrix-row ${hasMismatch ? 'mismatch-row' : ''} ${isExpanded ? 'expanded' : ''}`}
                    onClick={() => toggleRow(cap)}
                  >
                    <td>
                      <div className="cap-name-cell">
                        {isExpanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                        <code>{cap}</code>
                      </div>
                    </td>

                    <td>
                      <span className={`status-pill ${row.status.toLowerCase()}`}>
                        {row.status}
                      </span>
                    </td>

                    <td>
                      <span className={`status-pill ${row.status === 'DENIED' ? 'denied' : 'allowed'}`}>
                        {row.status === 'DENIED' ? 'FORBIDDEN' : 'PERMITTED'}
                      </span>
                    </td>

                    <td>
                      <span className={`obs-cell ${hasMismatch ? 'obs-alert' : 'obs-clean'}`}>
                        {observed}
                      </span>
                    </td>

                    <td>
                      {hasMismatch ? (
                        <span className="result-chip mismatch">
                          <XCircle size={12} /> VIOLATION: Not Justified
                        </span>
                      ) : (
                        <span className="result-chip compliant">
                          <CheckCircle2 size={12} /> Compliant
                        </span>
                      )}
                    </td>
                  </tr>

                  {isExpanded && (
                    <tr className="matrix-detail-row">
                      <td colSpan={5}>
                        <div className="matrix-detail-box">
                          <div className="detail-meta">
                            <strong>Evidence:</strong> <code>{row.evidence}</code>
                            {typeof row.confidence === 'number' && (
                              <> · <strong> Confidence Score:</strong> {int(row.confidence * 100)}%</>
                            )}
                          </div>
                          <p className="detail-justification">{row.justification}</p>
                          {hasMismatch && (
                            <div className="mismatch-explanation">
                              <AlertTriangle size={14} />
                              <span>Critical policy discrepancy: This capability was strictly DENIED by project contract, but malicious execution was observed during testing!</span>
                            </div>
                          )}
                        </div>
                      </td>
                    </tr>
                  )}
                </React.Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};

function int(val: number) {
  return Math.round(val);
}
