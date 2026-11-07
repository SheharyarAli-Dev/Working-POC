import React, { useState, useEffect } from 'react';
import { Play, RefreshCw, AlertTriangle, CheckCircle2, XCircle, BarChart3, Grid } from 'lucide-react';
import { executeSableBenchmark } from '../benchmarkStream';

interface BenchmarkResult {
  total_scenarios: number;
  runtime_s: number;
  metrics: Record<string, any>;
  ablation_metrics: Record<string, any>;
  ablation_deltas: Record<string, any>;
  kill_tests: Record<string, any>;
  scenario_matrix: Record<string, Record<string, string>>;
  confusion_matrices: Record<string, Record<string, Record<string, number>>>;
  b4_reduced_strength: boolean;
  b4_reduced_strength_note?: string;
  green_light_note: string;
  small_sample_note: string;
  ground_truth_hidden_note: string;
  evaluation_limits_note: string;
}

const SYSTEMS = ['SABLE', 'B0', 'B1', 'B2', 'B3', 'B4'];

const SYSTEM_COLORS: Record<string, string> = {
  SABLE: '#2563eb',
  B0: '#64748b',
  B1: '#0891b2',
  B2: '#7c3aed',
  B3: '#ea580c',
  B4: '#059669',
};

const VERDICT_COLORS: Record<string, string> = {
  PRESERVED: '#16a34a',
  REGRESSED: '#dc2626',
  UNKNOWN: '#d97706',
};

export const BenchmarkTab: React.FC = () => {
  const [result, setResult] = useState<BenchmarkResult | null>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<{ scenario: string; pct: number } | null>(null);
  const [activeMetricView, setActiveMetricView] = useState<'table' | 'bars'>('bars');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch('/api/sable/benchmark/result')
      .then(r => r.ok ? r.json() : null)
      .then(d => { if (d) setResult(d); })
      .catch(() => {});
  }, []);

  const runBenchmark = async () => {
    if (running) return;
    setRunning(true);
    setProgress({ scenario: 'Starting benchmark…', pct: 0 });
    setResult(null);
    setError(null);

    try {
      const result = await executeSableBenchmark(setProgress);
      setResult(result);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : 'Benchmark failed.');
    } finally {
      setRunning(false);
    }
  };

  const METRICS = [
    { key: 'verdict_accuracy', label: 'Verdict accuracy', lowerBetter: false, desc: 'Fraction of scenarios matching the labeled PRESERVED/REGRESSED/UNKNOWN outcome' },
    { key: 'false_safe_rate', label: 'False-safe rate (FSR)', lowerBetter: true, desc: 'True regressions incorrectly marked as PRESERVED (critical safety violation)' },
    { key: 'regression_recall', label: 'Regression recall', lowerBetter: false, desc: 'Fraction of actual regressions correctly flagged' },
    { key: 'false_regression_rate', label: 'False-regression rate', lowerBetter: true, desc: 'Legitimate refactors incorrectly flagged as REGRESSED' },
    { key: 'unknown_precision', label: 'UNKNOWN precision', lowerBetter: false, desc: 'Fraction of UNKNOWN predictions that were genuinely ambiguous/lacked ground' },
  ];

  return (
    <div className="sable-tab-content">
      <div className="sable-benchmark-header">
        <div>
          <strong style={{ fontSize: '1rem', color: '#0f172a' }}>Benchmark</strong>
          <span className="sable-diff-subtitle">
            B0 · B1 · B2 · B3 · B4 · SABLE — whole benchmark, not per-run
          </span>
        </div>
        <button className="sable-btn sable-btn-primary" onClick={runBenchmark} disabled={running}>
          {running ? <><RefreshCw size={13} className="spin"/> Running…</> : <><Play size={13}/> Run Benchmark</>}
        </button>
      </div>

      {running && progress && (
        <div className="sable-benchmark-progress">
          <div className="sable-benchmark-progress-bar" style={{ width: `${progress.pct}%` }}/>
          <span>{progress.pct.toFixed(0)}% — {progress.scenario}</span>
        </div>
      )}

      {error && <div role="alert" className="sable-diff-warn">{error}</div>}

      {!result && !running && (
        <div className="sable-tab-empty" style={{ minHeight: 140 }}>
          <p>Click "Run Benchmark" to evaluate the configured scenario set across B0–B4 and SABLE.</p>
          <p className="sable-small-note">Ground truth hidden from SABLE during evaluation.</p>
        </div>
      )}

      {result && (
        <>
          {result.b4_reduced_strength && (
            <div className="sable-reduced-banner">
              <AlertTriangle size={14}/>
              <span>
                <strong>Reduced-strength baseline:</strong>{' '}
                {result.b4_reduced_strength_note ?? 'External scanners (Checkov/Trivy) unavailable; baselines use built-in approximations.'}
              </span>
            </div>
          )}

          <div className="sable-benchmark-note">
            <AlertTriangle size={13} color="#d97706"/>
            <span>{result.small_sample_note}</span>
          </div>
          <div className="sable-benchmark-note">
            <span>💡 <strong>Interpretation:</strong> {result.green_light_note}</span>
          </div>
          <div className="sable-benchmark-note">
            <span>🔒 {result.ground_truth_hidden_note}</span>
          </div>
          <div className="sable-benchmark-note">
            <AlertTriangle size={13} color="#d97706"/>
            <span>{result.evaluation_limits_note}</span>
          </div>

          {/* Toggle between Grouped Bar Chart and Table */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '1.5rem', marginBottom: '0.75rem' }}>
            <div className="sable-card-label" style={{ margin: 0 }}>
              METRIC COMPARISON (n={result.total_scenarios})
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <button
                className={`sable-btn ${activeMetricView === 'bars' ? 'sable-btn-primary' : 'sable-btn-secondary'}`}
                style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                onClick={() => setActiveMetricView('bars')}
              >
                <BarChart3 size={12}/> Grouped Bars
              </button>
              <button
                className={`sable-btn ${activeMetricView === 'table' ? 'sable-btn-primary' : 'sable-btn-secondary'}`}
                style={{ fontSize: '0.75rem', padding: '4px 8px' }}
                onClick={() => setActiveMetricView('table')}
              >
                <Grid size={12}/> Data Table
              </button>
            </div>
          </div>

          {/* Grouped Bar Chart */}
          {activeMetricView === 'bars' ? (
            <div className="sable-grouped-chart" style={{
              background: '#f8fafc',
              border: '1px solid #e2e8f0',
              borderRadius: '8px',
              padding: '16px',
              marginBottom: '1rem'
            }}>
              {METRICS.map(m => (
                <div key={m.key} style={{ marginBottom: '18px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                    <strong style={{ fontSize: '0.85rem', color: '#1e293b' }}>{m.label}</strong>
                    <span style={{ fontSize: '0.75rem', color: '#64748b' }}>{m.desc}</span>
                  </div>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '8px' }}>
                    {SYSTEMS.map(sys => {
                      const val = result.metrics[sys]?.[m.key] ?? 0;
                      const isGood = m.lowerBetter ? val <= 0.10 : val >= 0.80;
                      const barPct = Math.min(Math.max(val * 100, 3), 100);

                      return (
                        <div key={sys} style={{ textAlign: 'center' }}>
                          <div style={{
                            height: '70px',
                            display: 'flex',
                            alignItems: 'flex-end',
                            justifyContent: 'center',
                            background: '#ffffff',
                            borderRadius: '4px',
                            border: '1px solid #e2e8f0',
                            padding: '3px'
                          }}>
                            <div style={{
                              width: '100%',
                              height: `${barPct}%`,
                              background: sys === 'SABLE' ? '#2563eb' : SYSTEM_COLORS[sys] ?? '#94a3b8',
                              borderRadius: '2px',
                              transition: 'height 0.4s ease'
                            }}/>
                          </div>
                          <div style={{ fontSize: '0.75rem', fontWeight: 600, marginTop: '4px', color: isGood ? '#16a34a' : '#dc2626' }}>
                            {(val * 100).toFixed(1)}%
                          </div>
                          <div style={{ fontSize: '0.7rem', color: '#64748b', fontWeight: sys === 'SABLE' ? 700 : 500 }}>
                            {sys}
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ))}
            </div>
          ) : (
            /* Table View */
            <div className="sable-bm-table">
              <table>
                <thead>
                  <tr>
                    <th>Metric</th>
                    {SYSTEMS.map(s => <th key={s}>{s}</th>)}
                  </tr>
                </thead>
                <tbody>
                  {METRICS.map(({ key, label, lowerBetter }) => (
                    <tr key={key}>
                      <td>{label}</td>
                      {SYSTEMS.map(sys => {
                        const m = result.metrics[sys];
                        const val = m?.[key] ?? 0;
                        const n = m?.n ?? 0;
                        const isGood = lowerBetter ? val <= 0.10 : val >= 0.80;
                        return (
                          <td key={sys}>
                            <span style={{ color: isGood ? '#16a34a' : '#dc2626', fontWeight: 600 }}>
                              {(val * 100).toFixed(1)}%
                            </span>
                            <span className="sable-metric-n"> (n={n})</span>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {/* B4 vs SABLE gap highlight */}
          <div className="sable-bm-gap-note" style={{
            background: '#eff6ff',
            border: '1px solid #bfdbfe',
            borderRadius: '6px',
            padding: '12px',
            margin: '1rem 0'
          }}>
            <strong style={{ color: '#1e40af' }}>Observed B4 vs SABLE comparison:</strong>{' '}
            {(() => {
              const sableFsr = result.metrics?.SABLE?.false_safe_rate ?? 0;
              const b4Fsr = result.metrics?.B4?.false_safe_rate ?? 0;
              const delta = (b4Fsr - sableFsr) * 100;
              const recallSable = (result.metrics?.SABLE?.regression_recall ?? 0) * 100;
              const recallB4 = (result.metrics?.B4?.regression_recall ?? 0) * 100;
              return (
                <span>
                  False-safe rate delta: <strong>{delta > 0 ? `+${delta.toFixed(1)}pp` : `${delta.toFixed(1)}pp`}</strong> (B4: {(b4Fsr*100).toFixed(1)}% vs SABLE: {(sableFsr*100).toFixed(1)}%).
                  Recall: SABLE {recallSable.toFixed(1)}% vs B4 {recallB4.toFixed(1)}%.
                  {' '}This B4 implementation reuses SABLE's correspondence and authorization code, so it is not an independent strongest-baseline result.
                </span>
              );
            })()}
          </div>

          {/* Confusion Matrices Per System */}
          <div className="sable-card-label" style={{ marginTop: '1.5rem', marginBottom: '0.5rem' }}>
            CONFUSION MATRICES PER SYSTEM
          </div>
          <p className="sable-small-note" style={{ marginBottom: '0.75rem' }}>
            Rows = Ground Truth (Actual) · Columns = Predicted Verdict
          </p>

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))',
            gap: '12px',
            marginBottom: '1.5rem'
          }}>
            {SYSTEMS.map(sys => {
              const cm = result.confusion_matrices?.[sys] ?? {
                PRESERVED: { PRESERVED: 0, REGRESSED: 0, UNKNOWN: 0 },
                REGRESSED: { PRESERVED: 0, REGRESSED: 0, UNKNOWN: 0 },
                UNKNOWN: { PRESERVED: 0, REGRESSED: 0, UNKNOWN: 0 },
              };

              return (
                <div key={sys} className="sable-overview-card" style={{ padding: '12px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px' }}>
                    <strong style={{ fontSize: '0.85rem', color: sys === 'SABLE' ? '#2563eb' : '#1e293b' }}>
                      {sys} {sys === 'SABLE' ? '(Proposed)' : ''}
                    </strong>
                    <span style={{ fontSize: '0.75rem', color: '#64748b' }}>n={result.total_scenarios}</span>
                  </div>

                  <table style={{ width: '100%', fontSize: '0.75rem', borderCollapse: 'collapse', textAlign: 'center' }}>
                    <thead>
                      <tr style={{ background: '#f8fafc', color: '#64748b' }}>
                        <th style={{ padding: '4px', textAlign: 'left' }}>GT \ Pred</th>
                        <th style={{ padding: '4px', color: '#16a34a' }}>PRES</th>
                        <th style={{ padding: '4px', color: '#dc2626' }}>REGR</th>
                        <th style={{ padding: '4px', color: '#d97706' }}>UNKN</th>
                      </tr>
                    </thead>
                    <tbody>
                      {(['PRESERVED', 'REGRESSED', 'UNKNOWN'] as const).map(actual => (
                        <tr key={actual} style={{ borderTop: '1px solid #f1f5f9' }}>
                          <td style={{ padding: '4px', textAlign: 'left', fontWeight: 600, color: '#475569' }}>
                            {actual.slice(0, 4)}
                          </td>
                          {(['PRESERVED', 'REGRESSED', 'UNKNOWN'] as const).map(pred => {
                            const count = cm[actual]?.[pred] ?? 0;
                            const isCorrect = actual === pred;
                            const isDangerous = actual === 'REGRESSED' && pred === 'PRESERVED';

                            let bg = '#ffffff';
                            let fg = '#334155';
                            if (isDangerous && count > 0) {
                              bg = '#fee2e2'; fg = '#b91c1c';
                            } else if (isCorrect && count > 0) {
                              bg = '#f0fdf4'; fg = '#15803d';
                            }

                            return (
                              <td key={pred} style={{ padding: '4px', background: bg, color: fg, fontWeight: count > 0 ? 600 : 400 }}>
                                {count}
                              </td>
                            );
                          })}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })}
          </div>

          {/* Per-scenario matrix */}
          {Object.keys(result.scenario_matrix ?? {}).length > 0 && (
            <>
              <div className="sable-card-label" style={{ marginTop: '1.5rem' }}>PER-SCENARIO MATRIX</div>
              <p className="sable-small-note" style={{ marginBottom: '0.5rem' }}>
                Full breakdown across all scenarios. Cells color-coded by predicted verdict.
              </p>
              <div className="sable-scenario-matrix">
                <table>
                  <thead>
                    <tr>
                      <th>Scenario</th>
                      {SYSTEMS.map(s => <th key={s}>{s}</th>)}
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(result.scenario_matrix).map(([sid, row]) => (
                      <tr key={sid}>
                        <td><span title={sid} style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{sid}</span></td>
                        {SYSTEMS.map(sys => {
                          const v = row[sys] ?? '–';
                          const color = VERDICT_COLORS[v] ?? '#6b7280';
                          return <td key={sys} style={{ color, fontWeight: 600 }}>{v}</td>;
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </>
      )}
    </div>
  );
};
