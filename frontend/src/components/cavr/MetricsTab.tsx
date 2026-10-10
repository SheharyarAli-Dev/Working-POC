import React, { useState, useEffect } from 'react';
import { CavrRunState, NOT_COMPUTED } from './types';
import { BarChart3, PieChart, Clock, History } from 'lucide-react';

interface MetricsTabProps {
  state: CavrRunState;
}

// The numbers of /api/cavr/metrics, which come from the verdict log: one row per verified request.
// Nothing is shown until the backend has answered.
export const MetricsTab: React.FC<MetricsTabProps> = ({ state }) => {
  const [metrics, setMetrics] = useState<any | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    fetch('/api/cavr/metrics')
      .then(res => { if (!res.ok) throw new Error(String(res.status)); return res.json(); })
      .then(data => { setMetrics(data); setFailed(false); })
      .catch(() => setFailed(true));
  }, [state.stepIndex, state.verdict]);

  if (!metrics) {
    return (
      <div className="evidence-tab-pane metrics-pane">
        <div className="history-table-card">
          <p>{failed ? 'The metrics could not be loaded.' : 'Loading metrics...'}</p>
        </div>
      </div>
    );
  }

  const total: number = metrics.verdicts || 0;
  const byStatus: Record<string, number> = metrics.by_status || {};
  const hitRate = metrics.cache_hit_rate == null ? NOT_COMPUTED : `${(metrics.cache_hit_rate * 100).toFixed(1)}%`;
  const ms = (value: any) => (value == null ? NOT_COMPUTED : `${value} ms`);
  const segment: Record<string, string> = { VERIFIED: 'allow', REJECTED: 'block', BLOCK: 'block', UNRESOLVED: 'review' };

  return (
    <div className="evidence-tab-pane metrics-pane">
      <div className="metrics-kpi-grid">
        <div className="kpi-card">
          <span className="kpi-title"><BarChart3 size={13} /> Verdicts logged</span>
          <strong className="kpi-val">{total}</strong>
          <span className="kpi-sub">One row per verified request</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-title"><PieChart size={13} /> Cache hit rate</span>
          <strong className="kpi-val">{hitRate}</strong>
          <span className="kpi-sub">{metrics.cache_hits} of {total} verdicts (a BLOCK counts as no hit)</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-title"><Clock size={13} /> Fast gate p50</span>
          <strong className="kpi-val">{ms(metrics.fast_gate_ms_p50)}</strong>
          <span className="kpi-sub">Nearest-rank median of fast_gate_ms</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-title"><Clock size={13} /> Fast gate p95</span>
          <strong className="kpi-val">{ms(metrics.fast_gate_ms_p95)}</strong>
          <span className="kpi-sub">Nearest-rank 95th percentile</span>
        </div>
      </div>

      <div className="metrics-charts-row">
        <div className="chart-card">
          <h6>Verdicts by status</h6>
          <div className="verdict-dist-bar">
            {Object.entries(byStatus).map(([status, count]) => (
              <div
                key={status}
                className={`dist-seg ${segment[status] || 'review'}`}
                style={{ width: `${total ? (count / total) * 100 : 0}%` }}
                title={`${status}: ${count}`}
              />
            ))}
          </div>
          <div className="dist-legend">
            {Object.entries(byStatus).map(([status, count]) => (
              <span key={status}><span className={`dot ${segment[status] || 'review'}`} /> {status}: {count}</span>
            ))}
            {total === 0 && <span>No verdict has been logged yet.</span>}
          </div>
        </div>
      </div>

      <div className="history-table-card">
        <div className="history-header">
          <History size={16} />
          <h6>Last verdicts (verdict log)</h6>
        </div>

        <div className="history-table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>Recorded</th>
                <th>Request</th>
                <th>Status</th>
                <th>Stage / rule</th>
                <th>fast_gate_ms</th>
                <th>Cache hit</th>
                <th>Escalated</th>
              </tr>
            </thead>
            <tbody>
              {(metrics.recent || []).length > 0 ? (
                metrics.recent.map((row: any) => (
                  <tr key={row.id} className="history-row">
                    <td>{new Date(row.recorded_at).toLocaleTimeString()}</td>
                    <td><code>{row.requested}</code></td>
                    <td><span className={`verdict-tag-sm ${segment[row.status] || 'review'}`}>{row.status}</span></td>
                    <td><code>{row.stage} / {row.rule}</code></td>
                    <td>{row.fast_gate_ms}</td>
                    <td>{row.cache_hit ? 'yes' : 'no'}</td>
                    <td>{row.escalated ? 'yes' : 'no'}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="text-center py-4 text-gray-500">No verdict has been logged yet.</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
