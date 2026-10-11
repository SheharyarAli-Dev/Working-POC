import React from 'react';
import { CavrRunState, NOT_RUN_ON_FAST_GATE } from './types';
import { Cpu, Zap, Activity, Clock, ShieldAlert, CheckCircle2, AlertOctagon } from 'lucide-react';

interface CounterfactualTabProps {
  state: CavrRunState;
}

export const CounterfactualTab: React.FC<CounterfactualTabProps> = ({ state }) => {
  const cf = state.counterfactualResults;
  if (!cf) {
    // No invented baseline run: on the fast-gate path nothing is executed.
    return (
      <div className="evidence-tab-pane counterfactual-pane">
        <div className="cf-summary-bar">
          <div className="cf-meta-block">
            <span className="cf-label">COUNTERFACTUAL RUNS</span>
            <p className="cf-stop-text">{NOT_RUN_ON_FAST_GATE}</p>
          </div>
        </div>
      </div>
    );
  }

  const runs = cf.runs || [];
  const comparison = cf.comparison || { baseline_behaviors_count: 0, counterfactual_total_behaviors: 0, new_behaviors_revealed_by_counterfactual: 0 };
  const budgetUsed = cf.budget_used_seconds || 0;
  const maxBudget = cf.max_budget_seconds || 1;
  const budgetPct = Math.min((budgetUsed / maxBudget) * 100, 100);

  return (
    <div className="evidence-tab-pane counterfactual-pane">
      {/* Top Banner: Value of Counterfactual Activation */}
      <div className="cf-summary-bar">
        <div className="cf-meta-block">
          <span className="cf-label">STOP REASON</span>
          <p className="cf-stop-text">{cf.stop_reason}</p>
        </div>

        <div className="cf-budget-block">
          <div className="budget-header">
            <span>Exploration Budget:</span>
            <strong>{budgetUsed}s / {maxBudget}s</strong>
          </div>
          <div className="budget-track">
            <div className="budget-fill" style={{ width: `${budgetPct}%` }} />
          </div>
        </div>
      </div>

      {/* Comparison Chart: Baseline vs Counterfactual */}
      <div className="cf-comparison-card">
        <div className="comparison-header">
          <Zap size={16} className="text-amber-400" />
          <h5>Research Value: Single Baseline Run vs. Adaptive Counterfactual Activation</h5>
        </div>

        <div className="comparison-meters-grid">
          <div className="comp-col baseline">
            <span className="comp-label">Standard Single Run (Run 0)</span>
            <div className="comp-big-stat">{comparison.baseline_behaviors_count}</div>
            <p className="comp-desc">
              Conventional sandboxes only observe normal startup behavior. Dormant malicious triggers stay hidden!
            </p>
          </div>

          <div className="comp-arrow">→</div>

          <div className="comp-col counterfactual">
            <span className="comp-label">With Counterfactual Activation (Runs 1..n)</span>
            <div className="comp-big-stat highlight">{comparison.counterfactual_total_behaviors}</div>
            <p className="comp-desc">
              Synthesizing targeted fake files &amp; credentials revealed <strong>+{comparison.new_behaviors_revealed_by_counterfactual} hidden hostile behavior(s)</strong>!
            </p>
          </div>
        </div>
      </div>

      {/* Run-by-Run Strip */}
      <div className="runs-strip-container">
        <h6>Run-by-Run Adaptive Execution Strip</h6>

        <div className="runs-cards-grid">
          {runs.map((r: any) => {
            const hasViolation = r.behaviors_found?.some((b: any) => b.verdict_impact === 'VIOLATION');
            // A run that was not observed (no isolation, no report) says nothing about the package.
            const notObserved = !r.behaviors_found?.length || r.behaviors_found.some((b: any) => b.verdict_impact === 'UNRESOLVED');

            return (
              <div key={r.run_number} className={`run-card ${hasViolation ? 'violation-run' : 'clean-run'}`}>
                <div className="run-card-top">
                  <span className="run-tag">RUN {r.run_number}</span>
                  <span className={`run-status-chip ${hasViolation || notObserved ? 'bad' : 'good'}`}>
                    {hasViolation ? 'VIOLATION TRIGGERED' : (notObserved ? 'NOT OBSERVED' : 'NO VIOLATION OBSERVED')}
                  </span>
                </div>

                <div className="run-condition-box">
                  <span className="cond-label">Condition Applied:</span>
                  <strong className="cond-name">{r.condition_applied?.name}</strong>
                  {r.condition_applied?.details && (
                    <span className="cond-details">{r.condition_applied.details}</span>
                  )}
                </div>

                {/* Behaviors Swimlane */}
                <div className="run-swimlane-box">
                  <span className="swimlane-label">Observed Actions:</span>
                  <div className="swimlane-items">
                    {r.behaviors_found?.map((b: any, bIdx: number) => (
                      <span key={bIdx} className={`swimlane-pill ${b.verdict_impact === 'VIOLATION' ? 'violation' : 'neutral'}`}>
                        {b.action}: {b.resource}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="run-footer-meta">
                  <span>Coverage: <strong>{r.cumulative_coverage}%</strong></span>
                  <span>Frontier Left: <strong>{r.frontier_size}</strong></span>
                  <span>Time: <strong>{r.duration_ms}ms</strong></span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
