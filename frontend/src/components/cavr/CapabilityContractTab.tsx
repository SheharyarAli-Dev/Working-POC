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

  // The rows are the contract the pipeline inferred. Without a contract there is nothing to show.
  const contract = state.actionData?.capability_contract;
  const contractRows: any[] = contract?.contract_rows || [];
  // Sink calls the AST scan found in the wheels, each with the pipeline's judgement.
  const sinks: any[] = state.actionData?.reachability?.sinks || [];

  if (!contract) {
    return (
      <div className="evidence-tab-pane capability-pane">
        <div className="tab-intro-card">
          <div>
            <h5>Capability Contract Matrix</h5>
            <p>
              {state.verdict
                ? 'No contract was inferred for this request: the pipeline stopped before that stage.'
                : 'The contract appears here when the pipeline has read the project.'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="evidence-tab-pane capability-pane">
      <div className="tab-intro-card">
        <div>
          <h5>Capability Contract Matrix</h5>
          <p>{contract.rule}: {contract.reason} Sinks are static findings from the AST scan; no package code was run.</p>
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
              <th style={{ width: '20%' }}>Sink calls in the wheels (static)</th>
              <th style={{ width: '20%' }}>Result Matrix</th>
            </tr>
          </thead>
          <tbody>
            {contractRows.map((row: any) => {
              const cap = row.capability;
              const isExpanded = !!expandedRows[cap];

              // Static findings only: sink calls in the wheels whose capability is this row's.
              const found = sinks.filter((sink: any) => cap.startsWith(sink.capability));
              const reachable = found.filter((sink: any) => sink.verdict === 'REACHABLE');
              const observed = found.length === 0
                ? "no sink call found"
                : found.map((sink: any) => `${sink.file}:${sink.line} ${sink.verdict}`).join(', ');
              const hasMismatch = reachable.length > 0;

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
                          <XCircle size={12} /> Reachable sink: unresolved
                        </span>
                      ) : (
                        <span className="result-chip compliant">
                          <CheckCircle2 size={12} /> {found.length === 0 ? 'Nothing found' : 'No reachable sink'}
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
                          </div>
                          <p className="detail-justification">{row.justification}</p>
                          {hasMismatch && (
                            <div className="mismatch-explanation">
                              <AlertTriangle size={14} />
                              <span>The contract does not allow this capability and the project's call sites can reach the sink call. Deep analysis is required (M2).</span>
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
