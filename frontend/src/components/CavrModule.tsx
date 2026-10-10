import React, { useState, useEffect } from 'react';
import {
  Database, ShieldAlert, Cpu, Terminal, Copy, Check, Eye,
  Lock, Info, HelpCircle, Search, AlertTriangle
} from 'lucide-react';

import { CavrRunState, Scenario, StageSummary, shown } from './cavr/types';
import { EMPTY_RUN, applyEvent } from './cavr/runState';
import { ScenarioChips } from './cavr/ScenarioChips';
import { Timeline } from './cavr/Timeline';
import { ProofDrawer } from './cavr/ProofDrawer';
import { StageDetailPanel } from './cavr/StageDetailPanel';
import { OverviewTab } from './cavr/OverviewTab';
import { RequirementsTab } from './cavr/RequirementsTab';
import { CapabilityContractTab } from './cavr/CapabilityContractTab';
import { TriggersTab } from './cavr/TriggersTab';
import { CounterfactualTab } from './cavr/CounterfactualTab';
import { CausalGraphTab } from './cavr/CausalGraphTab';
import { RepairTab } from './cavr/RepairTab';
import { AssuranceTab } from './cavr/AssuranceTab';
import { MetricsTab } from './cavr/MetricsTab';

// One row of GET /api/cavr/cache: an analysis CAVR stored after a real run.
interface CachedVerdict {
  name: string;
  version: string;
  sha256: string;
  source: string;
  status: string;
  capabilities: string;
  added_at: string;
}

export const CavrModule: React.FC = () => {
  // Dialog visibility states
  const [showCacheDialog, setShowCacheDialog] = useState(false);
  const [showActionDialog, setShowActionDialog] = useState(false);
  const [showEnvDialog, setShowEnvDialog] = useState(false);
  const [showProofDrawer, setShowProofDrawer] = useState(false);

  // The verdict cache as the backend lists it, and the search box of its dialog
  const [packages, setPackages] = useState<CachedVerdict[]>([]);
  const [cacheSearch, setCacheSearch] = useState('');
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Active evidence tab: overview | requirements | contract | triggers | counterfactual | causal | repair | assurance | metrics
  const [activeEvidenceTab, setActiveEvidenceTab] = useState<string>('overview');
  const [newTabAlerts, setNewTabAlerts] = useState<Record<string, boolean>>({});

  // Workflow state
  const [explainSimply, setExplainSimply] = useState(false);
  const [activeWorkflowBox, setActiveWorkflowBox] = useState<'none' | 'cache' | 'action' | 'env'>('none');
  const [isRunning, setIsRunning] = useState(false);
  // The scenario chips, read from the backend. `null` until it has answered.
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [scenariosFailed, setScenariosFailed] = useState(false);
  const [currentScenario, setCurrentScenario] = useState<string | null>(null);

  const [runState, setRunState] = useState<CavrRunState>(EMPTY_RUN);
  const [alternativeDecision, setAlternativeDecision] = useState<'pending' | 'approved' | 'rejected'>('pending');

  const fetchCache = async () => {
    try {
      const res = await fetch('/api/cavr/cache');
      if (res.ok) {
        const data = await res.json();
        setPackages(data);
      }
    } catch (err) {
      console.error('Failed to load cache:', err);
    }
  };

  const fetchScenarios = async () => {
    try {
      const res = await fetch('/api/cavr/scenarios');
      if (!res.ok) throw new Error(String(res.status));
      setScenarios(await res.json());
      setScenariosFailed(false);
    } catch (err) {
      console.error('Failed to load scenarios:', err);
      setScenariosFailed(true);
    }
  };

  useEffect(() => {
    fetchCache();
    fetchScenarios();
  }, []);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Run one chip: the backend builds the request from the scenario id and runs the real pipeline.
  const runScenario = async (scenario: Scenario) => {
    if (isRunning) return;
    setIsRunning(true);
    setCurrentScenario(scenario.id);
    setActiveWorkflowBox('none');
    setAlternativeDecision('pending');
    setActiveEvidenceTab('overview');
    setNewTabAlerts({});

    // Every result of the run before is cleared, so nothing of it can be read as a result of this one.
    setRunState({
      ...EMPTY_RUN,
      request: scenario.request,
      package: scenario.package,
      version: scenario.version,
      scenarioKey: scenario.id,
      explainSimply: explainSimply,
      currentStateMessage: `Sending '${scenario.request}' to the pipeline...`,
      currentPlainMessage: `Asking ASENT to check '${scenario.request}'.`
    });

    try {
      const res = await fetch(`/api/cavr/run?scenario=${encodeURIComponent(scenario.id)}`, { method: 'POST' });

      if (!res.ok) throw new Error(`The run could not be started (HTTP ${res.status})`);
      const data = await res.json();
      const currentRunId = data.run_id;

      // The request shown is the one the backend says it is verifying.
      setRunState(prev => ({ ...prev, runId: currentRunId, request: data.request }));

      // Connect to SSE stream
      const eventSource = new EventSource(data.stream_url);

      eventSource.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          handlePipelineEvent(payload, currentRunId);
        } catch (e) {
          // heartbeat
        }
      };

      // The backend ends the stream after the last event; the browser reports that as an error.
      eventSource.onerror = () => {
        eventSource.close();
        setIsRunning(false);
      };
    } catch (err: any) {
      console.error('Workflow error:', err);
      setRunState(prev => ({
        ...prev,
        currentStateMessage: `No run was started: ${err?.message || err}`,
        currentPlainMessage: 'The check could not be started, so there is no result.'
      }));
      setIsRunning(false);
    }
  };

  const handlePipelineEvent = (ev: any, currentRunId: string) => {
    const { type, payload } = ev;
    if (!payload) return;

    setRunState(prev => applyEvent(prev, ev));

    // Which box and which tabs light up. These follow the events; they are not results.
    if (type === 'requirement_gate_evaluated') {
      setNewTabAlerts(a => ({ ...a, requirements: true }));
    } else if (type === 'cache_result' && payload.result === 'HIT') {
      setActiveWorkflowBox('cache');
    } else if (type === 'action_completed') {
      setActiveWorkflowBox('action');
      setNewTabAlerts(a => ({ ...a, contract: true, triggers: true }));
    } else if (type === 'verdict_computed') {
      // The whole verdict and the timeline of this run.
      fetch(`/api/cavr/proof/${currentRunId}`)
        .then(r => { if (!r.ok) throw new Error(String(r.status)); return r.json(); })
        .then(proof => setRunState(s => (s.runId === currentRunId ? { ...s, proofData: proof } : s)))
        .catch(e => console.error('Failed to load proof:', e));
    } else if (type === 'state_change' && payload.state === 'DECIDED') {
      // The last event of a run. The cache box shows what is stored now.
      if (payload.certificate) setNewTabAlerts(a => ({ ...a, assurance: true }));
      setActiveWorkflowBox('none');
      setIsRunning(false);
      fetchCache();
    }
  };

  const handleAlternativeChoice = async (approved: boolean) => {
    if (!runState.runId || !runState.repair?.chosen_candidate) return;
    const chosenName = runState.repair.chosen_candidate.name;

    try {
      const res = await fetch('/api/cavr/approve-alternative', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          run_id: runState.runId,
          package: runState.package,
          alternative: chosenName,
          approved,
          user: 'Security Operator (You)',
          reason: approved ? 'Operator authorized clean substitute' : 'Operator rejected substitute'
        })
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      // What the backend recorded. Nothing is installed or rebuilt by this decision.
      const data = await res.json();
      const recorded = `Decision recorded by the backend: ${data.action} for '${data.alternative}'. Nothing was installed.`;

      setAlternativeDecision(data.approved ? 'approved' : 'rejected');
      setActiveWorkflowBox('none');
      setRunState(prev => ({ ...prev, currentStateMessage: recorded, currentPlainMessage: recorded }));
    } catch (err) {
      console.error('Alternative approval failed:', err);
    }
  };

  // The timeline of the current run, as the backend summarised it. Null until a run has finished.
  const stages: StageSummary[] | null = runState.proofData?.stages || null;
  const stageById = (id: string): StageSummary | null => (stages || []).find(stage => stage.id === id) || null;
  const proof = runState.proofData;

  // Filtered rows for the cache dialog
  const filteredPackages = packages.filter(p =>
    p.name.toLowerCase().includes(cacheSearch.toLowerCase()) ||
    p.capabilities.toLowerCase().includes(cacheSearch.toLowerCase())
  );

  // The values of one stage as a key/value list, for the dialogs.
  const stageValues = (id: string) => {
    const stage = stageById(id);
    if (!stage) {
      return <p>{shown(null)} (no run has finished yet)</p>;
    }
    return (
      <div className="proof-kv">
        {stage.values.map(item => (
          <div key={item.label}><span>{item.label}:</span> <code>{shown(item.value)}</code></div>
        ))}
      </div>
    );
  };

  return (
    <div className="cavr-module-container" id="cavr-section">
      {/* CAVR Header */}
      <div className="cavr-header-row">
        <div>
          <div className="cavr-eyebrow">
            <span className="module-pulse-dot" /> CAVR MODULE · CONTINUOUS ARTIFACT VERIFICATION &amp; RUNTIME
          </div>
          <h2 className="cavr-title">CAVR</h2>
          <p className="cavr-subtitle">
            Research-grade package assurance gate. Intercepts agent dependencies,
            derives deterministic capability contracts, adaptively triggers dormant paths via
            counterfactual synthesis, and proves trust with cryptographic evidence chains.
          </p>
        </div>

        {/* Explain Simply Toggle */}
        <div className="explain-toggle-card">
          <span className="toggle-label">
            <HelpCircle size={14} /> Explain simply
          </span>
          <button
            className={`toggle-switch ${explainSimply ? 'on' : ''}`}
            onClick={() => {
              setExplainSimply(!explainSimply);
              setRunState(s => ({ ...s, explainSimply: !explainSimply }));
            }}
            title="Toggle between plain language descriptions and technical security details"
          >
            <span className="switch-knob" />
          </button>
        </div>
      </div>

      {/* THE THREE BOXES (Top Row) */}
      <div className="cavr-three-boxes">
        {/* BOX 1: CACHE */}
        <div className={`cavr-card-box ${activeWorkflowBox === 'cache' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap blue">
              <Database size={18} />
            </span>
            <span className="box-step-tag">STEP 1 · VERIFICATION</span>
          </div>
          <h3 className="box-name">Cache</h3>
          <p className="box-info">
            Analyses stored under the 8-field key after a real run
          </p>
          <div className="box-footer-row">
            <button
              className="box-cta-button"
              onClick={() => setShowCacheDialog(true)}
              id="click-to-view-cache-btn"
            >
              <Eye size={14} />
              <span>Click to view</span>
            </button>
            <span className="box-metric-tag">{packages.length} stored</span>
          </div>
        </div>

        {/* BOX 2: ACTION */}
        <div className={`cavr-card-box ${activeWorkflowBox === 'action' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap amber">
              <ShieldAlert size={18} />
            </span>
            <span className="box-step-tag">STEP 2 · STATIC INSPECTION</span>
          </div>
          <h3 className="box-name">Action</h3>
          <p className="box-info">
            Requirement gate, capability contract and AST scan of the wheel
          </p>
          <div className="box-footer-row">
            <button
              className="box-cta-button"
              onClick={() => setShowActionDialog(true)}
              id="click-to-view-action-btn"
            >
              <Info size={14} />
              <span>Click to view</span>
            </button>
            <span className="box-metric-tag" title="Result of the AST scan in this run">
              {shown(runState.actionData?.scan?.[0]?.rule)}
            </span>
          </div>
        </div>

        {/* BOX 3: ENVIRONMENT CHECKING */}
        <div className={`cavr-card-box ${activeWorkflowBox === 'env' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap green">
              <Cpu size={18} />
            </span>
            <span className="box-step-tag">STEP 3 · HOSTILE SANDBOX</span>
          </div>
          <h3 className="box-name">Environment checking</h3>
          <p className="box-info">
            Sandbox execution and counterfactual runs (deep analysis, M2)
          </p>
          <div className="box-footer-row">
            <button
              className="box-cta-button"
              onClick={() => setShowEnvDialog(true)}
              id="click-here-env-btn"
            >
              <Terminal size={14} />
              <span>Click to view</span>
            </button>
            <span className="box-metric-tag" title="The fast gate runs no sandbox, so there is no sandbox result">
              {shown(runState.counterfactualResults?.stop_reason)}
            </span>
          </div>
        </div>
      </div>

      {/* WIDE WORKFLOW BOX */}
      <div className="wide-workflow-box">
        <div className="workflow-box-header">
          <div className="workflow-title-area">
            <span className="live-status-pill">
              <span className={`status-dot ${isRunning ? 'pulsing' : ''}`} />
              {isRunning ? 'RUN IN PROGRESS' : 'FAST GATE'}
            </span>
            <h4>Continuous Artifact Verification &amp; Runtime Pipeline</h4>
            <p>
              {explainSimply
                ? 'Each request below is really checked. The six steps show what the check returned; a step that did not run shows a dash.'
                : 'One verification path (verify_request) shown as six stages. Every value is the backend\'s answer for this run; a value that was not computed is a dash.'}
            </p>
          </div>

          <ScenarioChips
            scenarios={scenarios}
            failed={scenariosFailed}
            current={currentScenario}
            disabled={isRunning}
            onRun={runScenario}
          />
        </div>

        {/* Request / Banner Row */}
        <div className="interception-prompt-card">
          <div className="prompt-meta-col">
            <span className="prompt-label">INTERCEPTED TARGET</span>
            <code className="prompt-code">
              {shown(runState.request)}
            </code>
          </div>

          <div className="prompt-narrative-col">
            <span className="narrative-tag">
              {explainSimply ? 'Simple Explanation' : 'Pipeline State Transition'}
            </span>
            <p className="narrative-text">
              {explainSimply ? runState.currentPlainMessage : runState.currentStateMessage}
            </p>
          </div>

          {proof && (
            <button
              className="proof-drawer-btn"
              onClick={() => setShowProofDrawer(true)}
            >
              <Lock size={13} />
              <span>Proof Details</span>
            </button>
          )}
        </div>

        {/* TIMELINE: the six stages of the fast gate, filled from the proof of the run */}
        <Timeline stages={runState.proofData?.stages || null} runId={runState.runId} />

        {/* STAGE DETAIL PANEL */}
        <StageDetailPanel state={runState} />

        {/* 9 EVIDENCE TABS ROW */}
        <div className="evidence-tabs-bar">
          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'overview' ? 'active' : ''}`}
            onClick={() => setActiveEvidenceTab('overview')}
          >
            Overview
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'requirements' ? 'active' : ''} ${newTabAlerts.requirements ? 'pulse-alert' : ''}`}
            onClick={() => setActiveEvidenceTab('requirements')}
          >
            Requirements
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'contract' ? 'active' : ''} ${newTabAlerts.contract ? 'pulse-alert' : ''}`}
            onClick={() => setActiveEvidenceTab('contract')}
          >
            Capability Contract
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'triggers' ? 'active' : ''} ${newTabAlerts.triggers ? 'pulse-alert' : ''}`}
            onClick={() => setActiveEvidenceTab('triggers')}
          >
            Triggers
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'counterfactual' ? 'active' : ''}`}
            onClick={() => setActiveEvidenceTab('counterfactual')}
          >
            Counterfactual Runs
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'causal' ? 'active' : ''}`}
            onClick={() => setActiveEvidenceTab('causal')}
          >
            Causal Graph
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'repair' ? 'active' : ''}`}
            onClick={() => setActiveEvidenceTab('repair')}
          >
            Repair
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'assurance' ? 'active' : ''} ${newTabAlerts.assurance ? 'pulse-alert' : ''}`}
            onClick={() => setActiveEvidenceTab('assurance')}
          >
            Assurance
          </button>

          <button
            className={`evidence-tab-btn ${activeEvidenceTab === 'metrics' ? 'active' : ''}`}
            onClick={() => setActiveEvidenceTab('metrics')}
          >
            Metrics
          </button>
        </div>

        {/* ACTIVE EVIDENCE TAB CONTENT */}
        <div className="evidence-tab-content-area">
          {activeEvidenceTab === 'overview' && <OverviewTab state={runState} />}
          {activeEvidenceTab === 'requirements' && <RequirementsTab state={runState} />}
          {activeEvidenceTab === 'contract' && <CapabilityContractTab state={runState} />}
          {activeEvidenceTab === 'triggers' && <TriggersTab state={runState} />}
          {activeEvidenceTab === 'counterfactual' && <CounterfactualTab state={runState} />}
          {activeEvidenceTab === 'causal' && <CausalGraphTab state={runState} />}
          {activeEvidenceTab === 'repair' && (
            <RepairTab
              state={runState}
              onApproveReject={handleAlternativeChoice}
              decisionState={alternativeDecision}
            />
          )}
          {activeEvidenceTab === 'assurance' && <AssuranceTab state={runState} />}
          {activeEvidenceTab === 'metrics' && <MetricsTab state={runState} />}
        </div>
      </div>

      {/* DIALOG 1: THE VERDICT CACHE */}
      {showCacheDialog && (
        <div className="modal-backdrop" onClick={() => setShowCacheDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">VERDICT CACHE</span>
                <h3>Stored analyses (8-field key)</h3>
                <p>The rows of GET /api/cavr/cache: analyses CAVR stored after a real run. Empty until a request has been verified.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowCacheDialog(false)}>✕</button>
            </div>

            <div className="dialog-note-banner">
              <Info size={14} className="text-cyan-400" />
              <span>
                <strong>What a cache hit means:</strong> a row is reused only when all eight key fields match again
                (ecosystem, name, version, artifact SHA-256, subtree digest, contract digest, policy version, analyzer version).
                On a hit the wheel is still downloaded and hashed and OSV is still asked; only the AST scan and the sink judgement are skipped.
              </span>
            </div>

            {/* Search input */}
            <div className="dialog-search-row">
              <Search size={14} className="text-gray-400" />
              <input
                type="text"
                placeholder="Search by package name or by what the analysis was for..."
                value={cacheSearch}
                onChange={(e) => setCacheSearch(e.target.value)}
                className="dialog-search-input"
              />
            </div>

            <div className="modal-table-scroll">
              <table className="cache-table">
                <thead>
                  <tr>
                    <th>Package Name</th>
                    <th>Version</th>
                    <th>SHA-256 of the wheel</th>
                    <th>Analysis for</th>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Stored at</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPackages.length === 0 && (
                    <tr><td colSpan={7}>{packages.length === 0 ? 'No analysis is stored yet.' : 'No stored analysis matches the search.'}</td></tr>
                  )}
                  {filteredPackages.map((pkg) => (
                    <tr key={`${pkg.name}-${pkg.version}-${pkg.added_at}`}>
                      <td><strong>{pkg.name}</strong></td>
                      <td><code>{pkg.version}</code></td>
                      <td>
                        <button
                          className="hash-copy-btn"
                          onClick={() => copyToClipboard(pkg.sha256, `${pkg.name}-${pkg.version}`)}
                          title={`Click to copy the full SHA-256: ${pkg.sha256}`}
                        >
                          <code>{pkg.sha256.substring(0, 16)}...</code>
                          {copiedHash === `${pkg.name}-${pkg.version}` ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                        </button>
                      </td>
                      <td><span className="cap-pill">{pkg.capabilities}</span></td>
                      <td>{pkg.source}</td>
                      <td><span className="status-badge trusted">{pkg.status}</span></td>
                      <td>{shown(pkg.added_at)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* DIALOG 2: WHAT THE STATIC STAGES RETURNED */}
      {showActionDialog && (
        <div className="modal-backdrop" onClick={() => setShowActionDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">STATIC INSPECTION</span>
                <h3>Action: what the static stages returned for this run</h3>
                <p>Copied from the proof of the run ({shown(runState.runId)}). No package code is installed, imported or run.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowActionDialog(false)}>✕</button>
            </div>

            <div className="dialog-interactive-card">
              <h6>Requirement gate (C2)</h6>
              {stageValues('gate')}
            </div>

            <div className="dialog-interactive-card">
              <h6>Contract, AST scan and sinks (C4)</h6>
              {stageValues('analysis')}
            </div>

            {/* The four statuses the pipeline can return */}
            <div className="dialog-interactive-card">
              <h6>The four statuses of a verdict</h6>
              <div className="four-states-grid">
                <div className="state-box verified">
                  <strong>VERIFIED</strong>
                  <p>Every fast-gate check passed for this file and this project. Not a claim that the package is safe.</p>
                </div>
                <div className="state-box rejected">
                  <strong>REJECTED</strong>
                  <p>A check failed: the downloaded bytes do not match the registry, or OSV lists the version as affected.</p>
                </div>
                <div className="state-box unresolved">
                  <strong>UNRESOLVED</strong>
                  <p>Something could not be established. Unknown is never treated as a pass.</p>
                </div>
                <div className="state-box rejected">
                  <strong>BLOCK</strong>
                  <p>The project policy does not permit the request. Nothing was downloaded.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DIALOG 3: THE SANDBOX IS NOT PART OF THE FAST GATE */}
      {showEnvDialog && (
        <div className="modal-backdrop" onClick={() => setShowEnvDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">ENVIRONMENT CHECKING</span>
                <h3>Environment: what the backend reports about execution</h3>
                <p>Copied from the proof of the run ({shown(runState.runId)}).</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowEnvDialog(false)}>✕</button>
            </div>

            <div className="dialog-interactive-card">
              <h6>Sandbox fields of the proof</h6>
              <div className="proof-kv">
                <div><span>Container command:</span> <code>{shown(proof?.docker_command)}</code></div>
                <div><span>Container ID:</span> <code>{shown(proof?.container_id)}</code></div>
                <div><span>Image digest:</span> <code>{shown(proof?.image_digest)}</code></div>
                <div><span>Counterfactual runs:</span> <code>{shown(proof?.counterfactual_runs?.length)}</code></div>
              </div>
            </div>

            <div className="dialog-interactive-card limitation-card">
              <h6><AlertTriangle size={14} className="inline mr-1 text-amber-400" /> Limits of what is shown</h6>
              <ul className="limitations-list">
                <li><strong>No execution:</strong> the fast gate never installs, imports or runs package code. Sandbox execution and counterfactual runs belong to deep analysis (M2).</li>
                <li><strong>Escalation:</strong> when a sensitive call is reachable from the project, the verdict is UNRESOLVED and names the deep analysis as the next step. It is not run here.</li>
                <li><strong>No claim of safety:</strong> VERIFIED is bounded by the checks listed in the timeline. It never says the package is safe.</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {showProofDrawer && proof && <ProofDrawer proof={proof} onClose={() => setShowProofDrawer(false)} />}
    </div>
  );
};
