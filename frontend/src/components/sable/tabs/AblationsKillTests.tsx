import React, { useState, useEffect } from 'react';
import { Play, RefreshCw, AlertTriangle, CheckCircle2, XCircle, Sliders, ShieldAlert } from 'lucide-react';
import { executeSableBenchmark } from '../benchmarkStream';

interface AblationsKillTestsProps {
  onRunBenchmark?: () => void;
}

const ABLATION_DESCRIPTIONS: Record<string, { title: string; desc: string }> = {
  no_move_evidence: {
    title: 'Remove explicit move evidence',
    desc: 'Eliminates explicit moved {} blocks from correspondence ranker. Tests whether structural similarity alone can track resource moves.'
  },
  no_dependency_context: {
    title: 'Remove dependency & reference context',
    desc: 'Strips incoming/outgoing references, exported application references, and module output context from scoring.'
  },
  no_policy_relationship: {
    title: 'Remove policy-resource relationship evidence',
    desc: 'Removes policy attachment and IAM relationship context, relying solely on naming and resource properties.'
  },
  no_ambiguity_handling: {
    title: 'Force best match (remove ambiguity threshold)',
    desc: 'Sets uniqueness margin to 0 and forces the top-scoring candidate even when competing hypotheses are within margin.'
  },
  no_obligation_projection: {
    title: 'Correspondence without obligation projection',
    desc: 'Matches successors structurally but does not project or evaluate the security obligation against candidate IAM policies.'
  },
  no_correspondence: {
    title: 'Obligation checking without correspondence',
    desc: 'Checks authorization on the original baseline address only (B0 style), without attempting to follow structural refactoring.'
  }
};

export const AblationsKillTestsTab: React.FC<AblationsKillTestsProps> = () => {
  const [result, setResult] = useState<any>(null);
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<{ scenario: string; pct: number } | null>(null);
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
    setProgress({ scenario: 'Initializing benchmark engine…', pct: 0 });
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

  const ablations = result?.ablation_deltas ?? {};
  const killTests = result?.kill_tests ?? {};

  return (
    <div className="sable-tab-content">
      <div className="sable-benchmark-header">
        <div>
          <strong style={{ fontSize: '1rem', color: '#0f172a' }}>Ablations & Kill Tests</strong>
          <span className="sable-diff-subtitle">
            Controlled empirical evaluation — whole benchmark, not per-run
          </span>
        </div>
        <button
          className="sable-btn sable-btn-primary"
          onClick={runBenchmark}
          disabled={running}
        >
          {running ? (
            <><RefreshCw size={13} className="spin"/> Running benchmark…</>
          ) : (
            <><Play size={13}/> Run Benchmark</>
          )}
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
          <Sliders size={28} strokeWidth={1.4} color="#64748b"/>
          <p>Click "Run Benchmark" to evaluate the 6 ablations and 6 kill tests across all benchmark scenarios.</p>
          <p className="sable-small-note">Thresholds defined in sable_config.json before any run.</p>
        </div>
      )}

      {result && (
        <>
          {/* Note Banner */}
          <div className="sable-benchmark-note" style={{ marginBottom: '1.25rem' }}>
            <AlertTriangle size={13} color="#d97706"/>
            <span><strong>Controlled Empirical Claims:</strong> {result.small_sample_note}</span>
          </div>

          {/* Section 1: Ablations */}
          <div className="sable-card-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <Sliders size={14}/> 6 REAL ABLATIONS (DELTA VS FULL SABLE)
          </div>
          <p className="sable-small-note" style={{ marginBottom: '0.75rem' }}>
            Measures the causal contribution of each component by removing it from the real engine and evaluating degradation across all {result.total_scenarios} scenarios.
          </p>

          <div className="sable-ablation-grid" style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '12px',
            marginBottom: '2rem'
          }}>
            {Object.entries(ablations).map(([key, data]: [string, any]) => {
              const meta = ABLATION_DESCRIPTIONS[key] ?? { title: key.replace(/_/g, ' '), desc: '' };
              const fsrDelta = (data.false_safe_rate_delta ?? 0) * 100;
              const recallDelta = (data.recall_delta ?? 0) * 100;
              const fsrDegraded = fsrDelta > 0;
              const recallDegraded = recallDelta < 0;

              return (
                <div key={key} className="sable-overview-card" style={{ padding: '14px' }}>
                  <div style={{ fontWeight: 600, fontSize: '0.85rem', color: '#1e293b', marginBottom: 4 }}>
                    {meta.title}
                  </div>
                  <div style={{ fontSize: '0.75rem', color: '#64748b', marginBottom: 12, lineHeight: 1.4 }}>
                    {meta.desc}
                  </div>

                  <div className="sable-kv-list">
                    <div className="sable-kv">
                      <span>False-Safe Rate Δ</span>
                      <strong style={{ color: fsrDegraded ? '#dc2626' : '#16a34a' }}>
                        {fsrDelta > 0 ? `+${fsrDelta.toFixed(1)}pp` : `${fsrDelta.toFixed(1)}pp`}
                        {fsrDegraded ? ' (worse safety)' : ' (no degradation)'}
                      </strong>
                    </div>
                    <div className="sable-kv">
                      <span>Regression Recall Δ</span>
                      <strong style={{ color: recallDegraded ? '#dc2626' : '#16a34a' }}>
                        {recallDelta > 0 ? `+${recallDelta.toFixed(1)}pp` : `${recallDelta.toFixed(1)}pp`}
                        {recallDegraded ? ' (missed regressions)' : ' (preserved)'}
                      </strong>
                    </div>
                    <div className="sable-kv">
                      <span>Ablated vs Full FSR</span>
                      <code style={{ fontSize: '0.75rem' }}>
                        {(data.ablated_fsr * 100).toFixed(1)}% vs {(data.full_fsr * 100).toFixed(1)}%
                      </code>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Section 2: Kill Tests */}
          <div className="sable-card-label" style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <ShieldAlert size={14}/> 6 PRE-SPECIFIED KILL TESTS (K1 TO K6)
          </div>
          <p className="sable-small-note" style={{ marginBottom: '0.75rem' }}>
            Falsification criteria defined in <code>sable_config.json</code> prior to the run. If any test fails, the claimed scientific contribution is narrowed or withdrawn.
          </p>

          <div className="sable-kt-grid">
            {Object.entries(killTests).map(([kid, kt]: [string, any]) => {
              const isPass = kt.status === 'PASS';
              const isFail = kt.status === 'FAIL';
              const statusLabel = kt.status === 'UNMEASURED' ? 'UNMEASURED' : kt.status === 'PASS' || kt.status === 'FAIL' || kt.status === 'INCONCLUSIVE' ? kt.status : 'NOT RUN';

              return (
                <div key={kid} className={`sable-kt-card ${kt.status.toLowerCase()}`}>
                  <div className="sable-kt-header">
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <strong style={{ fontSize: '0.9rem' }}>{kid}</strong>
                      <span style={{ fontSize: '0.8rem', color: '#64748b' }}>
                        {kid === 'K1' ? 'Strong baseline equivalence' :
                         kid === 'K2' ? 'Address evidence suffices' :
                         kid === 'K3' ? 'Attribution ambiguity exists' :
                         kid === 'K4' ? 'UNKNOWN escape hatch' :
                         kid === 'K5' ? 'Security predicate non-trivial' :
                         'Execution feasibility'}
                      </span>
                    </div>
                    {isPass ? (
                      <span className="sable-badge-pass"><CheckCircle2 size={12}/> PASS</span>
                    ) : isFail ? (
                      <span className="sable-badge-fail"><XCircle size={12}/> FAIL</span>
                    ) : kt.status === 'UNMEASURED' ? (
                      <span className="sable-badge sable-badge-approx"><AlertTriangle size={12}/> UNMEASURED</span>
                    ) : kt.status === 'INCONCLUSIVE' ? (
                      <span className="sable-badge-inc"><AlertTriangle size={12}/> INCONCLUSIVE</span>
                    ) : (
                      <span className="sable-badge sable-badge-approx"><AlertTriangle size={12}/> {statusLabel}</span>
                    )}
                  </div>

                  <div className="sable-kt-body">
                    <div className="sable-kt-threshold">
                      Threshold: <code>{typeof kt.threshold === 'object' ? JSON.stringify(kt.threshold) : kt.threshold}</code>
                    </div>
                    <div className="sable-kt-measured">
                      Measured: <code>{JSON.stringify(kt.measured)}</code>
                    </div>
                    <div className="sable-kt-consequence" style={{
                      color: isPass ? '#16a34a' : '#dc2626',
                      fontWeight: isPass ? 400 : 600,
                      marginTop: 6
                    }}>
                      {isPass ? `✓ Passed criterion: ${kt.consequence}` : `⚠ ${kt.consequence}`}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </>
      )}
    </div>
  );
};
