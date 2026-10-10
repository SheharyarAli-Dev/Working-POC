import React, { useState, useEffect } from 'react';
import { CavrRunState, NOT_COMPUTED, shown } from './types';
import { BarChart3, PieChart, Clock, History } from 'lucide-react';

interface MetricsTabProps {
  state: CavrRunState;
}

// One group of fast_gate_ms values in the answer of /api/cavr/metrics.
interface TimeSummary {
  count: number;
  p50: number | null;
  p95: number | null;
}

// Loads /api/cavr/metrics (the verdict log: one row per request) again after each run.
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
  return <MetricsReport metrics={metrics} />;
};

// The numbers of one answer of /api/cavr/metrics. fast_gate_ms is given per verdict and per cache
// lookup, never as one percentile over all verdicts: a BLOCK takes a few milliseconds and downloads
// nothing, so it would hide how long verifying a package takes.
export const MetricsReport: React.FC<{ metrics: any }> = ({ metrics }) => {
  const total: number = metrics.verdicts || 0;
  const byStatus: Record<string, number> = metrics.by_status || {};
  const times = metrics.fast_gate_ms || {};
  const pairs: any[] = times.by_status_and_cache_lookup || [];
  const percent = (rate: any) => (rate == null ? NOT_COMPUTED : `${(rate * 100).toFixed(1)}%`);
  const segment: Record<string, string> = { VERIFIED: 'allow', REJECTED: 'block', BLOCK: 'block', UNRESOLVED: 'review' };

  // One table of groups: a name, how many requests, and their nearest-rank p50 and p95.
  const timeTable = (title: string, firstColumn: string, groups: Record<string, TimeSummary>) => (
    <div className="history-table-card">
      <div className="history-header">
        <Clock size={16} />
        <h6>{title}</h6>
      </div>
      <div className="history-table-wrap">
        <table className="history-table">
          <thead>
            <tr>
              <th>{firstColumn}</th>
              <th>Requests</th>
              <th>p50 (ms)</th>
              <th>p95 (ms)</th>
            </tr>
          </thead>
          <tbody>
            {Object.entries(groups).map(([name, group]) => (
              <tr key={name} className="history-row">
                <td><code>{name}</code></td>
                <td>{shown(group.count)}</td>
                <td>{shown(group.p50)}</td>
                <td>{shown(group.p95)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  return (
    <div className="evidence-tab-pane metrics-pane">
      <div className="metrics-kpi-grid">
        <div className="kpi-card">
          <span className="kpi-title"><BarChart3 size={13} /> Verdicts logged</span>
          <strong className="kpi-val">{total}</strong>
          <span className="kpi-sub">One row per request. Runs under a demo condition are not logged.</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-title"><PieChart size={13} /> Cache hit rate, all verdicts</span>
          <strong className="kpi-val">{percent(metrics.cache_hit_rate)}</strong>
          <span className="kpi-sub">{shown(metrics.cache_hits)} of {total} verdicts</span>
        </div>

        <div className="kpi-card">
          <span className="kpi-title"><PieChart size={13} /> Cache hit rate, lookups only</span>
          <strong className="kpi-val">{percent(metrics.cache_hit_rate_of_lookups)}</strong>
          <span className="kpi-sub">{shown(metrics.cache_hits)} of {shown(metrics.cache_lookups)} verdicts that reached the cache lookup</span>
        </div>
      </div>

      {timeTable('fast_gate_ms by verdict', 'Verdict', times.by_status || {})}
      {timeTable('fast_gate_ms by cache lookup', 'Cache lookup', times.by_cache_lookup || {})}

      <div className="history-table-card">
        <div className="history-header">
          <Clock size={16} />
          <h6>fast_gate_ms by verdict and cache lookup</h6>
        </div>
        <div className="history-table-wrap">
          <table className="history-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Cache lookup</th>
                <th>Requests</th>
                <th>p50 (ms)</th>
                <th>p95 (ms)</th>
              </tr>
            </thead>
            <tbody>
              {pairs.length > 0 ? (
                pairs.map((row: any) => (
                  <tr key={`${row.status}-${row.cache_lookup}`} className="history-row">
                    <td><code>{row.status}</code></td>
                    <td><code>{row.cache_lookup}</code></td>
                    <td>{shown(row.count)}</td>
                    <td>{shown(row.p50)}</td>
                    <td>{shown(row.p95)}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={5} className="text-center py-4 text-gray-500">No verdict has been logged yet.</td>
                </tr>
              )}
            </tbody>
          </table>
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
                <th>Cache lookup</th>
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
                    <td>{shown(row.fast_gate_ms)}</td>
                    <td>{shown(row.cache_lookup)}</td>
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
