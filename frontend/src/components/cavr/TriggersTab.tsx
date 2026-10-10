import React from 'react';
import { CavrRunState } from './types';
import { Crosshair } from 'lucide-react';

interface TriggersTabProps {
  state: CavrRunState;
}

// What the light AST scan found in the wheels: sensitive sink calls with the pipeline's
// judgement of each, and branches that gate a sink behind an environment or file check.
export const TriggersTab: React.FC<TriggersTabProps> = ({ state }) => {
  const scans: any[] = state.actionData?.scan || [];
  const reachability = state.actionData?.reachability;
  const sinks: any[] = reachability?.sinks || [];
  const proofs: any[] = reachability?.proofs || [];
  const triggers: any[] = scans.flatMap((scan: any) => (scan.triggers || []).map((t: any) => ({ ...t, package: scan.package })));

  if (!state.actionData) {
    return (
      <div className="evidence-tab-pane triggers-pane">
        <div className="empty-tab-state">
          <Crosshair size={32} className="text-gray-500" />
          <p>
            {state.verdict
              ? 'The AST scan did not run for this request: the pipeline stopped before that stage.'
              : 'Scan results appear here when the pipeline has scanned the wheels.'}
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="evidence-tab-pane triggers-pane">
      <div className="tab-intro-card">
        <div>
          <h5>AST scan: sinks and gated branches</h5>
          <p>
            {scans.map((scan: any) => `${scan.package} ${scan.version}: ${scan.rule} (${scan.python_files} Python files)`).join('; ') || 'No wheel was scanned.'}
            {state.actionData.analysis_from_cache ? ' This analysis came from the verdict cache.' : ''}
          </p>
        </div>
        <div className="formula-pill">
          <code>{reachability ? `${reachability.rule}` : 'sinks not judged'}</code>
        </div>
      </div>

      <div className="matrix-table-wrap">
        <table className="matrix-table">
          <thead>
            <tr>
              <th>Sink call</th>
              <th>Capability</th>
              <th>Judgement</th>
              <th>Why</th>
            </tr>
          </thead>
          <tbody>
            {sinks.length === 0 ? (
              <tr><td colSpan={4}>No sensitive sink call was found in the scanned wheels.</td></tr>
            ) : sinks.map((sink: any, idx: number) => (
              <tr key={idx} className={`matrix-row ${sink.verdict === 'REACHABLE' ? 'mismatch-row' : ''}`}>
                <td><code>{sink.file}:{sink.line}</code> <code>{sink.sink}</code></td>
                <td>{sink.capability}</td>
                <td><span className={`status-pill ${sink.verdict === 'REACHABLE' ? 'denied' : 'allowed'}`}>{sink.verdict}</span></td>
                <td>{sink.why}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {proofs.map((proof: any) => (
        <div key={proof.id} className="tab-intro-card">
          <div>
            <h5>Reachability proof: {proof.id} ({proof.accepted ? 'accepted' : 'not accepted'})</h5>
            <p>{proof.reason}</p>
            <p>Limit: {proof.limit}</p>
          </div>
        </div>
      ))}

      <div className="matrix-table-wrap">
        <table className="matrix-table">
          <thead>
            <tr>
              <th>Gated branch</th>
              <th>Predicate</th>
              <th>Sinks inside</th>
            </tr>
          </thead>
          <tbody>
            {triggers.length === 0 ? (
              <tr><td colSpan={3}>No branch that gates a sink behind an environment or file check was found.</td></tr>
            ) : triggers.map((trigger: any) => (
              <tr key={`${trigger.package}:${trigger.id}`} className="matrix-row">
                <td><code>{trigger.file}:{trigger.line}</code></td>
                <td><code>{trigger.predicate}</code></td>
                <td>{(trigger.reachable_sinks || []).map((sink: any) => `${sink.sink} (line ${sink.line})`).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
