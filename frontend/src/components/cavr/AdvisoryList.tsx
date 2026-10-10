import React from 'react';
import { NOT_COMPUTED, shown } from './types';

interface AdvisoryListProps {
  // `resolution` of the package_resolved event; null when the pipeline stopped before that stage.
  resolution: any | null;
  runId: string | null;
}

// The OSV result of the run. A long list is shown as the backend's one-line summary (the count and
// the first three ids); every advisory is in the section below it, which is closed until it is
// clicked, and in the proof JSON.
export const AdvisoryList: React.FC<AdvisoryListProps> = ({ resolution, runId }) => {
  const asked: any[] = resolution?.advisories || [];
  const affected: any[] = resolution?.known_risk_signals || [];

  return (
    <div className="overview-card">
      <div className="card-header-row">
        <h5>OSV advisories</h5>
        <span className="card-badge">{asked.length > 0 ? `${shown(resolution.vulnerability_count)} affect this version` : NOT_COMPUTED}</span>
      </div>

      {asked.length > 0 && (
        <ul className="findings-list">
          {asked.map((advisory: any, idx: number) => (
            <li key={idx} className="finding-item">
              <span>
                {shown(advisory.name)} {shown(advisory.version)}: {shown(advisory.rule)} ({shown(advisory.mode)}, retrieved {shown(advisory.retrieved_at)})
              </span>
            </li>
          ))}
        </ul>
      )}

      {affected.length > 0 && (
        <>
          <p>{shown(resolution.advisory_summary)}</p>
          <details>
            <summary style={{ cursor: 'pointer' }}>Show all {affected.length} advisories</summary>
            <div className="history-table-wrap">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>OSV id</th>
                    <th>Aliases</th>
                    <th>Fixed in</th>
                    <th>Summary</th>
                  </tr>
                </thead>
                <tbody>
                  {affected.map((advisory: any) => (
                    <tr key={advisory.cve} className="history-row">
                      <td><code>{advisory.cve}</code></td>
                      <td>{shown((advisory.aliases || []).join(', '))}</td>
                      <td>{shown((advisory.fixed_versions || []).join(', '))}</td>
                      <td>{shown(advisory.summary)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </details>
          <p>
            The same list as JSON: <a href={`/api/cavr/proof/${runId}`} target="_blank" rel="noreferrer">/api/cavr/proof/{runId}</a>
            {' '}(cavr_verdict.packages[0].evidence.advisories[].affected)
          </p>
        </>
      )}
    </div>
  );
};
