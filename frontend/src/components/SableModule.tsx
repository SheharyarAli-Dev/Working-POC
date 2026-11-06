import React, { useState, useEffect, useRef } from 'react';
import {
  Database, Shield, ShieldAlert, Cpu, CheckCircle2, XCircle, AlertTriangle,
  Terminal, Play, RefreshCw, Eye, EyeOff, Info, Lock,
  ArrowRight, ChevronDown, ChevronRight, Copy, Check, Upload, FileCheck
} from 'lucide-react';

import { SableRunState, INITIAL_STATE, STEP_NAMES, STEP_PHASES, STEP_SUBSTEPS, VERDICT_COLORS, VERDICT_BG, TerraformFileEntry, terraformFileMap } from './sable/types';
import { OverviewTab } from './sable/tabs/Overview';
import { SpecificationTab } from './sable/tabs/Specification';
import { TerraformDiffTab } from './sable/tabs/TerraformDiff';
import { ResourceGraphTab } from './sable/tabs/ResourceGraph';
import { CorrespondenceTab } from './sable/tabs/Correspondence';
import { ProjectionTab } from './sable/tabs/Projection';
import { VerificationTab } from './sable/tabs/Verification';
import { DecisionTab } from './sable/tabs/Decision';
import { BenchmarkTab } from './sable/tabs/Benchmark';
import { AblationsKillTestsTab } from './sable/tabs/AblationsKillTests';
import { EvidenceTab } from './sable/tabs/Evidence';

interface Scenario {
  id: string;
  name: string;
  family: string;
  is_hard_case: boolean;
  notes: string;
}

const EVIDENCE_TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'specification', label: 'Specification' },
  { id: 'diff', label: 'Terraform Diff' },
  { id: 'graph', label: 'Resource Graph' },
  { id: 'correspondence', label: 'Correspondence' },
  { id: 'projection', label: 'Projection' },
  { id: 'verification', label: 'Verification' },
  { id: 'decision', label: 'Decision' },
  { id: 'benchmark', label: 'Benchmark' },
  { id: 'ablations', label: 'Ablations & Kill Tests' },
  { id: 'evidence', label: 'Evidence' },
];

const LIFECYCLE_STAGES = ['Loaded', 'Normalized', 'Modeled', 'Matched', 'Projected', 'Verified', 'Decided'];

// STEP_INDEX to lifecycle stage map
const STEP_TO_LIFECYCLE: Record<number, number> = { 0: 0, 1: 0, 2: 1, 3: 3, 4: 4, 5: 5, 6: 6, 7: 6 };

export const SableModule: React.FC = () => {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('rename_with_moved');
  const [isRunning, setIsRunning] = useState(false);
  const [runState, setRunState] = useState<SableRunState>(INITIAL_STATE);
  const [activeEvidenceTab, setActiveEvidenceTab] = useState('overview');
  const [unlockedTabs, setUnlockedTabs] = useState<Set<string>>(new Set(['overview', 'specification', 'benchmark', 'ablations']));
  const [newTabAlerts, setNewTabAlerts] = useState<Record<string, boolean>>({});
  const [expandedStep, setExpandedStep] = useState<number | null>(null);
  const [explainSimply, setExplainSimply] = useState(false);
  const [showProofDrawer, setShowProofDrawer] = useState(false);
  const [rerunDeterminismResult, setRerunDeterminismResult] = useState<any>(null);
  const [isVerifyingDeterminism, setIsVerifyingDeterminism] = useState(false);

  // Dialog states
  const [showBaselineDialog, setShowBaselineDialog] = useState(false);
  const [showEnvDialog, setShowEnvDialog] = useState(false);
  const [showActionDialog, setShowActionDialog] = useState(false);
  const [showUploadDialog, setShowUploadDialog] = useState(false);
  const [uploadBaselineFiles, setUploadBaselineFiles] = useState<TerraformFileEntry[]>([{ path: 'main.tf', content: '' }]);
  const [uploadCandidateFiles, setUploadCandidateFiles] = useState<TerraformFileEntry[]>([{ path: 'main.tf', content: '' }]);
  const [uploadError, setUploadError] = useState<string | null>(null);
  const [requestError, setRequestError] = useState<string | null>(null);
  const [scenarioLoadError, setScenarioLoadError] = useState<string | null>(null);
  const [baselineCopied, setBaselineCopied] = useState(false);
  const [baselineDialogData, setBaselineDialogData] = useState<any>(null);
  const [envDialogData, setEnvDialogData] = useState<any>(null);
  const [actionDialogData, setActionDialogData] = useState<any>(null);
  const [activeBoxGlow, setActiveBoxGlow] = useState<'none' | 'baseline' | 'env' | 'action'>('none');

  const terminalRef = useRef<HTMLDivElement>(null);
  const eventSourceRef = useRef<EventSource | null>(null);

  // Load scenarios
  useEffect(() => {
    let active = true;
    fetch('/api/sable/scenarios')
      .then(async response => {
        if (!response.ok) throw new Error(`Scenario service returned HTTP ${response.status}`);
        return response.json();
      })
      .then(data => { if (active) setScenarios(data); })
      .catch(error => { if (active) setScenarioLoadError(error instanceof Error ? error.message : 'Could not load SABLE scenarios.'); });
    return () => { active = false; };
  }, []);

  // Load dialog data
  useEffect(() => {
    fetch('/api/sable/dialog/baseline').then(r => r.json()).then(setBaselineDialogData).catch(() => {});
    fetch('/api/sable/dialog/environment').then(r => r.json()).then(setEnvDialogData).catch(() => {});
    fetch('/api/sable/dialog/action').then(r => r.json()).then(setActionDialogData).catch(() => {});
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [runState.terminalLogs]);

  const unlockTab = (tab: string) => {
    setUnlockedTabs(prev => new Set([...prev, tab]));
    setNewTabAlerts(prev => ({ ...prev, [tab]: true }));
    setTimeout(() => setNewTabAlerts(prev => ({ ...prev, [tab]: false })), 3000);
  };

  const runScenario = async () => {
    if (isRunning) return;
    setRequestError(null);
    setIsRunning(true);
    setRunState({ ...INITIAL_STATE, scenarioId: selectedScenario });
    setActiveEvidenceTab('overview');
    setUnlockedTabs(new Set(['overview', 'specification', 'benchmark']));
    setNewTabAlerts({});
    setExpandedStep(null);
    setActiveBoxGlow('none');
    setShowProofDrawer(false);

    // Close any existing SSE
    eventSourceRef.current?.close();

    try {
      const res = await fetch('/api/sable/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario_id: selectedScenario, obligation_id: 'S3-APPROLE-CUSTOMERDATA' })
      });

      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.detail || `SABLE could not start (HTTP ${res.status}).`);
      }

      const { run_id, stream_url } = await res.json();

      // Update run state with run ID
      setRunState(prev => ({ ...prev, runId: run_id }));

      // Connect to SSE
      const es = new EventSource(stream_url);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const ev = JSON.parse(event.data);
          handlePipelineEvent(ev, run_id);
        } catch { /* ignore */ }
      };

      es.onerror = () => {
        es.close();
        setIsRunning(false);
        setRequestError(`The SABLE event stream ended before completion for run ${run_id}. The decision has not been inferred; inspect the run or retry.`);
      };

    } catch (error) {
      setIsRunning(false);
      setRequestError(error instanceof Error ? error.message : 'SABLE could not start the analysis.');
    }
  };

  const handlePipelineEvent = (ev: any, runId: string) => {
    const payload = ev.payload ?? ev.data ?? {};
    const stepIndex = ev.step_index ?? payload.step_index ?? 0;
    const type = ev.type;
    const logs: string[] = payload.logs ?? [];

    setRunState(prev => {
      const next = { ...prev };

      // Terminal logs
      if (logs.length > 0) {
        next.terminalLogs = [...prev.terminalLogs, ...logs.filter((l: string) => !prev.terminalLogs.includes(l))];
      }

      // Step progress
      next.stepIndex = stepIndex;

      // Meter updates
      if (payload.hypotheses) {
        next.hypotheses = payload.hypotheses;
        next.meters = {
          ...prev.meters,
          hypotheses_generated: payload.hypotheses.length,
          hypotheses_surviving: payload.hypotheses.filter((h: any) => h.score >= 6).length,
          signals_collected: payload.hypotheses.reduce((sum: number, h: any) => sum + h.signals.length, 0),
        };
      }
      if (payload.conflicts) {
        next.conflicts = payload.conflicts;
        next.meters = { ...next.meters, conflicts_found: payload.conflicts.length };
      }

      switch (type) {
        case 'state_change':
          if (stepIndex === 0) {
            next.obligation = payload.obligation;
          }
          break;

        case 'capture.complete':
          next.baselineSha = payload.baseline_sha256;
          next.candidateSha = payload.candidate_sha256;
          next.diffLines = payload.diff_lines ?? [];
          next.diff = payload.diff ?? '';
          next.candidateFiles = payload.candidate_files ?? [];
          next.baselineResources = payload.baseline_files ?? [];
          unlockTab('diff');
          break;

        case 'normalize.complete':
          next.baselineResources = payload.baseline_resources ?? [];
          next.candidateResources = payload.candidate_resources ?? [];
          next.baselineGraph = payload.baseline_graph ?? null;
          next.candidateGraph = payload.candidate_graph ?? null;
          next.unsupportedConstructs = payload.unsupported_constructs ?? [];
          unlockTab('graph');
          break;

        case 'obligation.loaded':
          next.obligation = payload.obligation ?? payload;
          next.baselineAuth = payload.baseline_auth ?? null;
          unlockTab('specification');
          break;

        case 'obligation.baseline_failed':
          next.verdict = 'UNKNOWN';
          next.wording = payload.reason;
          setActiveBoxGlow('baseline');
          break;

        case 'correspondence.scored':
          next.hypotheses = payload.hypotheses ?? [];
          next.conflicts = payload.conflicts ?? [];
          unlockTab('correspondence');
          break;

        case 'correspondence.no_winner':
          next.verdict = 'UNKNOWN';
          next.correspondenceReason = payload.reason;
          next.conflicts = payload.hypotheses ? [] : prev.conflicts;
          unlockTab('projection');
          break;

        case 'projection.complete':
          next.successor = payload.successor;
          next.candidateAuth = payload.candidate_auth ?? null;
          next.baselineAuth = payload.baseline_auth ?? prev.baselineAuth;
          next.meters = { ...next.meters, policy_findings: (payload.candidate_auth?.widening?.length ?? 0) + (payload.candidate_auth?.weakening?.length ?? 0) };
          next.uncertainty = payload.candidate_auth?.outside_model?.length > 0 ? 0.5 : 0;
          unlockTab('projection');
          break;

        case 'verification.complete':
          next.toolResults = payload.tool_results ?? {};
          next.unsupportedConstructs = [...(next.unsupportedConstructs ?? []), ...(payload.unsupported_constructs ?? [])];
          unlockTab('verification');
          break;

        case 'decision.attributed':
          next.verdict = payload.verdict;
          next.wording = payload.wording;
          next.asent_mapping = payload.asent_mapping;
          next.branchFired = payload.branch_fired;
          next.failureMode = payload.failure_mode;
          next.reviewerNote = payload.reviewer_note;
          next.correspondenceReason = payload.correspondence_reason ?? prev.correspondenceReason;
          next.candidateAuth = payload.auth_result ?? prev.candidateAuth;
          if (payload.verdict === 'REGRESSED') setActiveBoxGlow('action');
          unlockTab('decision');
          break;

        case 'run.complete':
          next.verdict = payload.verdict;
          next.wording = payload.wording;
          next.asent_mapping = payload.asent_mapping;
          next.decisionHash = payload.decision_hash;
          next.evidence = payload.evidence ?? null;
          next.baselines = payload.baselines ?? {};
          setIsRunning(false);
          eventSourceRef.current?.close();
          unlockTab('decision');
          unlockTab('evidence');
          // Fetch proof
          fetch(`/api/sable/proof/${runId}`).then(r => r.json()).then(d => {
            setRunState(p => ({ ...p, proofData: d }));
          }).catch(() => {});
          break;
      }

      return next;
    });
  };

  const sendAuditDecision = async (action: 'APPROVE' | 'REJECT') => {
    if (!runState.runId) return;
    await fetch(`/api/sable/audit/${runState.runId}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action, user: 'Security Operator (Admin)', reason: 'Human review decision' })
    });
  };

  const handleRerunCustom = async (customCandidateTf: Record<string, string>) => {
    if (isRunning) return;
    setRequestError(null);
    setIsRunning(true);
    setRunState({ ...INITIAL_STATE, scenarioId: selectedScenario });
    setActiveEvidenceTab('diff');
    setUnlockedTabs(new Set(['overview', 'specification', 'diff', 'benchmark', 'ablations']));
    setNewTabAlerts({});
    setExpandedStep(null);
    setActiveBoxGlow('none');
    setShowProofDrawer(false);
    setRerunDeterminismResult(null);

    eventSourceRef.current?.close();

    try {
      const res = await fetch('/api/sable/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: selectedScenario,
          obligation_id: 'S3-APPROLE-CUSTOMERDATA',
          custom_candidate_tf: customCandidateTf
        })
      });

      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.detail || `SABLE could not start the candidate analysis (HTTP ${res.status}).`);
      }

      const { run_id, stream_url } = await res.json();
      setRunState(prev => ({ ...prev, runId: run_id }));

      const es = new EventSource(stream_url);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const ev = JSON.parse(event.data);
          handlePipelineEvent(ev, run_id);
        } catch { /* ignore */ }
      };

      es.onerror = () => {
        es.close();
        setIsRunning(false);
        setRequestError(`The SABLE event stream ended before completion for run ${run_id}. The decision has not been inferred; inspect the run or retry.`);
      };
    } catch (error) {
      setIsRunning(false);
      setRequestError(error instanceof Error ? error.message : 'SABLE could not start the candidate analysis.');
    }
  };

  const handleUploadRun = async () => {
    if (isRunning) return;
    const baseline = terraformFileMap(uploadBaselineFiles);
    const candidate = terraformFileMap(uploadCandidateFiles);
    if (baseline.error || candidate.error || !baseline.files || !candidate.files) {
      setUploadError(baseline.error ?? candidate.error ?? 'Provide complete baseline and candidate Terraform file maps.');
      return;
    }
    setUploadError(null);
    setRequestError(null);
    setIsRunning(true);
    setRunState({ ...INITIAL_STATE, scenarioId: 'custom_upload' });
    setActiveEvidenceTab('overview');
    setUnlockedTabs(new Set(['overview', 'specification', 'benchmark', 'ablations']));
    setNewTabAlerts({});
    setExpandedStep(null);
    setActiveBoxGlow('none');
    setShowProofDrawer(false);
    setRerunDeterminismResult(null);

    eventSourceRef.current?.close();

    try {
      const res = await fetch('/api/sable/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          scenario_id: 'custom_upload',
          obligation_id: 'S3-APPROLE-CUSTOMERDATA',
          baseline_files: baseline.files,
          candidate_files: candidate.files
        })
      });

      if (!res.ok) {
        const body = await res.json().catch(() => null);
        throw new Error(body?.detail || `SABLE rejected the custom bundle (HTTP ${res.status}).`);
      }

      const { run_id, stream_url } = await res.json();
      setShowUploadDialog(false);
      setRunState(prev => ({ ...prev, runId: run_id }));

      const es = new EventSource(stream_url);
      eventSourceRef.current = es;

      es.onmessage = (event) => {
        try {
          const ev = JSON.parse(event.data);
          handlePipelineEvent(ev, run_id);
        } catch { /* ignore */ }
      };

      es.onerror = () => {
        es.close();
        setIsRunning(false);
        setRequestError(`The SABLE event stream ended before completion for run ${run_id}. The decision has not been inferred; inspect the run or retry.`);
      };
    } catch (error) {
      setIsRunning(false);
      setUploadError(error instanceof Error ? error.message : 'SABLE could not start the custom bundle analysis.');
    }
  };

  const handleVerifyDeterminism = async () => {
    if (!runState.runId || isVerifyingDeterminism) return;
    setIsVerifyingDeterminism(true);
    try {
      const res = await fetch(`/api/sable/runs/${runState.runId}/verify-determinism`, {
        method: 'POST'
      });
      if (res.ok) {
        const data = await res.json();
        setRerunDeterminismResult(data);
      }
    } catch {
      /* ignore */
    } finally {
      setIsVerifyingDeterminism(false);
    }
  };

  const renderBundleFiles = (label: string, files: TerraformFileEntry[], setFiles: React.Dispatch<React.SetStateAction<TerraformFileEntry[]>>) => (
    <section style={{ marginBottom: '1rem' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
        <strong style={{ fontSize: '0.85rem' }}>{label}</strong>
        <button type="button" className="sable-btn sable-btn-secondary" onClick={() => setFiles(current => [...current, { path: '', content: '' }])}>Add file</button>
      </div>
      {files.map((file, index) => (
        <div key={`${index}-${file.path}`} style={{ border: '1px solid #e2e8f0', borderRadius: 6, padding: 8, marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <input aria-label={`${label} relative path ${index + 1}`} placeholder="main.tf or modules/storage/main.tf" value={file.path} onChange={e => setFiles(current => current.map((item, i) => i === index ? { ...item, path: e.target.value } : item))} style={{ flex: 1 }} />
            {files.length > 1 && <button type="button" className="sable-btn sable-btn-secondary" onClick={() => setFiles(current => current.filter((_, i) => i !== index))}>Remove</button>}
          </div>
          <textarea aria-label={`${label} source ${index + 1}`} placeholder="Paste the complete contents of this .tf file" value={file.content} onChange={e => setFiles(current => current.map((item, i) => i === index ? { ...item, content: e.target.value } : item))} style={{ width: '100%', height: 120, fontFamily: 'monospace', fontSize: '0.8rem', padding: 8, border: '1px solid #cbd5e1', borderRadius: 4 }} />
        </div>
      ))}
    </section>
  );

  const lifecycleStage = runState.stepIndex >= 0 ? STEP_TO_LIFECYCLE[runState.stepIndex] ?? 0 : -1;

  // Group scenarios by family
  const families = [...new Set(scenarios.map(s => s.family))];

  // Verdict color for current run
  const verdictColor = runState.verdict ? VERDICT_COLORS[runState.verdict] ?? '#6b7280' : '#6b7280';

  return (
    <div className="sable-module-container">
      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="cavr-header-row">
        <div>
          <div className="cavr-eyebrow">
            <span className="module-pulse-dot"/> SABLE MODULE · INFRASTRUCTURE SECURITY BOUNDARY ASSURANCE
          </div>
          <h2 className="cavr-title">SABLE</h2>
          <p className="cavr-subtitle">
            Did the least-privilege boundary follow the data after the refactor?
          </p>
          <p className="sable-one-liner">
            Terraform got restructured. We check whether the role that was allowed to touch the
            customer-data bucket is still allowed on the same data, no more and no less.
          </p>
          <div className="sable-header-badges">
            <span className="sable-badge-info"><Lock size={11}/> LLM in decision path: none</span>
            <span className="sable-badge-info">Network OFF · Cloud OFF · Deterministic</span>
          </div>
        </div>
        <div className="sable-header-actions">
          <div className="explain-toggle-card">
            <span className="toggle-label">
              <Eye size={13} /> Explain simply
            </span>
            <div
              className={`toggle-switch ${explainSimply ? 'on' : ''}`}
              onClick={() => setExplainSimply(e => !e)}
              role="switch"
              aria-checked={explainSimply}
              title="Toggle plain English mode"
            >
              <span className="switch-knob" />
            </div>
          </div>
          {runState.proofData && (
            <button
              className="box-cta-button"
              onClick={() => setShowProofDrawer(p => !p)}
              style={{ background: '#fff', cursor: 'pointer' }}
            >
              <FileCheck size={14} />
              <span>Proof drawer</span>
            </button>
          )}
        </div>
      </div>

      {/* ── Three top boxes ─────────────────────────────────────────── */}
      <div className="cavr-three-boxes">
        {/* Box 1: Baseline */}
        <div className={`cavr-card-box ${activeBoxGlow === 'baseline' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap blue">
              <Database size={18} />
            </span>
            <span className="box-step-tag">STEP 1 · SECURITY OBLIGATION</span>
          </div>
          <h3 className="box-name">Baseline</h3>
          <p className="box-info">
            Trusted Terraform and the security obligation to check against.
          </p>
          <div className="box-footer-row">
            <button
              className="box-cta-button"
              onClick={() => setShowBaselineDialog(true)}
              id="click-to-view-baseline-btn"
            >
              <Eye size={14} />
              <span>Click to view</span>
            </button>
            <span className="box-metric-tag">{runState.obligation?.obligation_id || 'S3-APPROLE'}</span>
          </div>
        </div>

        {/* Box 2: Environment checking */}
        <div className={`cavr-card-box ${activeBoxGlow === 'env' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap green">
              <Cpu size={18} />
            </span>
            <span className="box-step-tag">STEP 2 · EVIDENCE ENGINES</span>
          </div>
          <h3 className="box-name">Environment checking</h3>
          <p className="box-info">
            Local, offline tools that gather evidence without network or cloud access.
          </p>
          <div className="box-footer-row">
            <button
              className="box-cta-button"
              onClick={() => setShowEnvDialog(true)}
              id="click-here-env-btn"
            >
              <Terminal size={14} />
              <span>Click here</span>
            </button>
            <span className="box-metric-tag">Checkov · python-hcl2</span>
          </div>
        </div>

        {/* Box 3: Action */}
        <div className={`cavr-card-box ${activeBoxGlow === 'action' ? 'glow-active' : ''}`}>
          <div className="box-badge-row">
            <span className="box-icon-wrap amber">
              <ShieldAlert size={18} />
            </span>
            <span className="box-step-tag">STEP 3 · DECISION LOGIC</span>
          </div>
          <h3 className="box-name">Action</h3>
          <p className="box-info">
            Pipeline steps, signal weights, and deterministic decision logic.
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
            <span className="box-metric-tag">5 Invariants · 0-10</span>
          </div>
        </div>
      </div>

      {/* ── Wide workflow box ────────────────────────────────────────── */}
      <div className="wide-workflow-box">
        <div className="workflow-box-header">
          <div className="workflow-title-area">
            <span className="live-status-pill">
              <span className={`status-dot ${isRunning ? 'pulsing' : ''}`} />
              {isRunning ? 'PIPELINE ACTIVE · 8 PHASES' : 'INFRASTRUCTURE ASSURANCE ENGINE'}
            </span>
            <h4>Infrastructure Security Boundary Assurance</h4>
            <p>
              {explainSimply
                ? 'Watch how ASENT inspects Terraform refactors, tracks data resources across renames, and verifies security boundaries without any cloud access.'
                : 'Deterministic 8-stage pipeline. AST & HCL parsing, multi-signal correspondence, sound policy projection, and evidence ledger.'}
            </p>
          </div>
        </div>

        {/* Scenario selector */}
        <div className="sable-scenario-bar">
          <div className="sable-scenario-families">
            {families.slice(0, 8).map(family => {
              const familyScenarios = scenarios.filter(s => s.family === family);
              return (
                <div key={family} className="sable-family-group">
                  <div className="sable-family-label">{family.replace(/_/g, ' ')}</div>
                  <div className="sable-family-chips">
                    {familyScenarios.map(s => (
                      <button
                        key={s.id}
                        className={`sable-scenario-chip ${selectedScenario === s.id ? 'active' : ''} ${s.is_hard_case ? 'hard-case' : ''}`}
                        onClick={() => setSelectedScenario(s.id)}
                        title={s.notes}
                      >
                        {s.is_hard_case && '⚡ '}
                        {s.name.replace(/\[Hard\] /, '').slice(0, 28)}
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
            <button
              className="sable-btn sable-btn-secondary"
              style={{ padding: '8px 12px', fontSize: '0.8rem', display: 'flex', alignItems: 'center', gap: '6px' }}
              onClick={() => { setUploadError(null); setShowUploadDialog(true); }}
              title="Upload custom baseline and candidate Terraform bundles"
            >
              <Upload size={14}/> Upload bundle
            </button>
            <button
              className="sable-run-btn"
              onClick={runScenario}
              disabled={isRunning || scenarios.length === 0}
            >
              {isRunning
                ? <><RefreshCw size={14} className="spin"/> Running…</>
                : <><Play size={14}/> Run scenario</>}
            </button>
          </div>
        </div>

        {scenarioLoadError && <div role="alert" className="sable-diff-warn">Could not load SABLE scenarios: {scenarioLoadError}. You can still submit a complete custom baseline and candidate bundle.</div>}
        {requestError && <div role="alert" className="sable-diff-warn">{requestError}</div>}

        {/* Target Scenario / Banner Row */}
        <div className="interception-prompt-card" style={{ marginBottom: '24px' }}>
          <div className="prompt-meta-col">
            <span className="prompt-label">TARGET SCENARIO</span>
            <code className="prompt-code">
              {scenarios.find(s => s.id === selectedScenario)?.name || selectedScenario}
            </code>
          </div>

          <div className="prompt-narrative-col">
            <span className="narrative-tag">
              {explainSimply ? 'Simple Explanation' : 'Pipeline State Transition'}
            </span>
            <p className="narrative-text">
              {runState.wording || (explainSimply
                ? 'Select a scenario and click "Run scenario" to test boundary preservation.'
                : 'Engine standing by. Deterministic correspondence and bounded projection ready.')}
            </p>
          </div>

          {runState.proofData && (
            <button 
              className="proof-drawer-btn"
              onClick={() => setShowProofDrawer(true)}
            >
              <Lock size={13} />
              <span>Proof Details</span>
            </button>
          )}
        </div>

        {/* 8-step horizontal timeline */}
        <div className="timeline-horizontal-wrapper">
          <div className="timeline-track-line" />
          <div className="timeline-nodes-row">
            {STEP_NAMES.map((name, i) => {
              const isPast = runState.stepIndex > i;
              const isCurrent = runState.stepIndex === i;
              return (
                <div
                  key={i}
                  className={`timeline-node-item ${isCurrent ? 'active-step' : ''} ${isPast ? 'completed-step' : ''}`}
                >
                  <div
                    className="node-click-area"
                    onClick={() => setExpandedStep(expandedStep === i ? null : i)}
                  >
                    <div className="node-marker">
                      {isPast ? <Check size={12} /> : <span>{i + 1}</span>}
                    </div>
                    <strong className="node-title">{name}</strong>
                    <span className="node-desc">{STEP_SUBSTEPS[i]}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* Expanded step detail */}
        {expandedStep !== null && (
          <div className="sable-stage-detail" style={{ marginBottom: '20px' }}>
            <div className="sable-stage-detail-header">
              <strong>Step {expandedStep + 1}: {STEP_NAMES[expandedStep]}</strong>
              <span>{STEP_PHASES[expandedStep]} · {STEP_SUBSTEPS[expandedStep]}</span>
            </div>
            <div className="sable-stage-detail-body">
              {expandedStep === 0 && <p>ASENT intercepts the Terraform change proposal before it is applied and routes it to SABLE based on the obligation registry.</p>}
              {expandedStep === 1 && <p>Baseline and candidate bundles are captured. SHA-256 computed for every file and bundle. Unified diff generated.</p>}
              {expandedStep === 2 && (
                <div>
                  <p>HCL parsed with python-hcl2. Local variables, module calls and references resolved. Normalized resource model produced.</p>
                  {runState.unsupportedConstructs.length > 0 && (
                    <div className="sable-stage-warn">Unsupported constructs: {runState.unsupportedConstructs.join('; ')}</div>
                  )}
                </div>
              )}
              {expandedStep === 3 && (
                <div>
                  <p>Successor hypotheses generated from candidate resources of compatible type. Scored with fixed signals and thresholds.</p>
                  {runState.hypotheses.length > 0 && (
                    <p>Top hypothesis: <code>{runState.hypotheses[0]?.address}</code> with score {runState.hypotheses[0]?.score}</p>
                  )}
                </div>
              )}
              {expandedStep === 4 && (
                <div>
                  <p>Baseline obligation projected onto surviving hypotheses using the bounded authorization evaluator.</p>
                  {runState.successor && <p>Chosen successor: <code>{runState.successor}</code></p>}
                </div>
              )}
              {expandedStep === 5 && <p>Available local tools (Terraform validate, Checkov) run against the candidate. Unavailable tools labeled as built-in approximation.</p>}
              {expandedStep === 6 && (
                <div>
                  <p>Decision logic executed. Branch fired: <code>{runState.branchFired ?? 'pending'}</code></p>
                  {runState.verdict && <p>Verdict: <strong style={{ color: verdictColor }}>{runState.verdict}</strong></p>}
                </div>
              )}
              {expandedStep === 7 && (
                <div>
                  <p>Hash-chained evidence record emitted. SARIF export available. ASENT handoff complete.</p>
                  {runState.decisionHash && <p>Decision hash: <code>{runState.decisionHash.slice(0, 16)}…</code></p>}
                </div>
              )}
            </div>
          </div>
        )}

        {/* Analysis Console */}
        <div className="sable-console" style={{ marginBottom: '24px' }}>
          {/* Lifecycle bar */}
          <div className="sable-lifecycle-bar">
            {LIFECYCLE_STAGES.map((stage, i) => (
              <div key={stage} className={`sable-lifecycle-stage ${lifecycleStage === i ? 'active' : lifecycleStage > i ? 'done' : ''}`}>
                {stage}
              </div>
            ))}
          </div>

          {/* Badges */}
          <div className="sable-console-badges">
            <span className="sable-badge-info" title="No network access during analysis">Network OFF</span>
            <span className="sable-badge-info" title="No cloud API calls">Cloud OFF</span>
            <span className="sable-badge-info" title="No AI in decision path">LLM: none</span>
            {Object.entries(runState.toolResults ?? {}).map(([tool, r]: any) => (
              <span key={tool}
                className={`sable-badge-tool ${r.real_tool ? 'real' : 'approx'}`}
                title={r.claim ?? (r.real_tool ? 'Real tool' : 'Built-in approximation, not the real tool')}>
                {tool.replace(/_/g, ' ')}
              </span>
            ))}
          </div>

          {/* Evidence meters */}
          <div className="sable-meters">
            {[
              { label: 'Hypotheses generated', value: runState.meters.hypotheses_generated },
              { label: 'Surviving filter', value: runState.meters.hypotheses_surviving },
              { label: 'Conflicts', value: runState.meters.conflicts_found },
              { label: 'Signals', value: runState.meters.signals_collected },
              { label: 'Policy findings', value: runState.meters.policy_findings },
            ].map(m => (
              <div key={m.label} className="sable-meter-item">
                <span className="sable-meter-label">{m.label}</span>
                <span className="sable-meter-value">{m.value}</span>
              </div>
            ))}
            {runState.uncertainty > 0 && (
              <div className="sable-meter-item">
                <span className="sable-meter-label">Uncertainty</span>
                <span className="sable-meter-value" style={{ color: '#d97706' }}>{Math.round(runState.uncertainty * 100)}%</span>
              </div>
            )}
          </div>

          {/* Terminal */}
          <div className="sable-terminal" ref={terminalRef}>
            {runState.terminalLogs.length === 0 ? (
              <span className="sable-terminal-placeholder">$ Ready. Select a scenario and click Run scenario.</span>
            ) : (
              runState.terminalLogs.map((log, i) => (
                <div key={i} className="sable-terminal-line">{log}</div>
              ))
            )}
          </div>
        </div>

        {/* Evidence tabs */}
        <div className="evidence-tabs-bar">
          {EVIDENCE_TABS.map(tab => {
            const isUnlocked = unlockedTabs.has(tab.id);
            const hasAlert = newTabAlerts[tab.id];
            const isWholeBenchmark = tab.id === 'benchmark' || tab.id === 'ablations';
            return (
              <button
                key={tab.id}
                className={`evidence-tab-btn ${activeEvidenceTab === tab.id ? 'active' : ''} ${hasAlert ? 'pulse-alert' : ''}`}
                onClick={() => isUnlocked && setActiveEvidenceTab(tab.id)}
                title={!isUnlocked ? 'Runs when this stage completes' : isWholeBenchmark ? 'Whole-benchmark view — click Run Benchmark inside' : ''}
                style={!isUnlocked ? { opacity: 0.45, cursor: 'not-allowed' } : {}}
              >
                {tab.label}
                {isWholeBenchmark && <span className="sable-tab-sub"> (whole benchmark)</span>}
              </button>
            );
          })}
        </div>

        <div className="evidence-tab-content-area">
          {activeEvidenceTab === 'overview' && <OverviewTab runState={runState} explainSimply={explainSimply}/>}
          {activeEvidenceTab === 'specification' && <SpecificationTab runState={runState} explainSimply={explainSimply}/>}
          {activeEvidenceTab === 'diff' && <TerraformDiffTab runState={runState} explainSimply={explainSimply} onRerunCustom={handleRerunCustom}/>}
          {activeEvidenceTab === 'graph' && <ResourceGraphTab runState={runState} explainSimply={explainSimply}/>}
          {activeEvidenceTab === 'correspondence' && <CorrespondenceTab runState={runState} explainSimply={explainSimply}/>}
          {activeEvidenceTab === 'projection' && <ProjectionTab runState={runState} explainSimply={explainSimply}/>}
          {activeEvidenceTab === 'verification' && <VerificationTab runState={runState} explainSimply={explainSimply}/>}
          {activeEvidenceTab === 'decision' && <DecisionTab runState={runState} explainSimply={explainSimply} onAuditDecision={sendAuditDecision}/>}
          {activeEvidenceTab === 'benchmark' && <BenchmarkTab/>}
          {activeEvidenceTab === 'ablations' && <AblationsKillTestsTab/>}
          {activeEvidenceTab === 'evidence' && <EvidenceTab runState={runState} explainSimply={explainSimply}/>}
        </div>
      </div>

      {/* ── Dialogs ──────────────────────────────────────────────────── */}
      {showBaselineDialog && baselineDialogData && (
        <div className="cavr-dialog-overlay" onClick={() => setShowBaselineDialog(false)}>
          <div className="cavr-dialog" onClick={e => e.stopPropagation()}>
            <div className="cavr-dialog-header">
              <div>
                <div className="cavr-dialog-title">{baselineDialogData.title}</div>
                <div className="cavr-dialog-subtitle">{baselineDialogData.subtitle}</div>
              </div>
              <button className="cavr-dialog-close" onClick={() => setShowBaselineDialog(false)}>✕</button>
            </div>
            <div className="cavr-dialog-body">
              {/* Obligations table */}
              <div className="sable-dialog-section">
                <strong>Obligation Records</strong>
                {baselineDialogData.obligations?.map((o: any) => (
                  <div key={o.obligation_id} className="sable-obligation-card">
                    <div className="sable-kv"><span>ID</span><code>{o.obligation_id}</code></div>
                    <div className="sable-kv"><span>Principal</span><code>{o.principal}</code></div>
                    <div className="sable-kv"><span>Actions</span><code>{o.actions?.join(', ')}</code></div>
                    <div className="sable-kv"><span>Protected Asset</span><code>{o.protected_asset}</code></div>
                    <div className="sable-kv"><span>Resource Scope</span><code>{o.resource_scope}</code></div>
                    <div className="sable-kv"><span>Authority</span><span>{o.authority_source}</span></div>
                  </div>
                ))}
              </div>
              {/* Bundle SHA */}
              <div className="sable-dialog-section">
                <strong>Bundle SHA-256</strong>
                <div className="sable-hash-row" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <code>{baselineDialogData.bundle_sha256}</code>
                  <button
                    className="sable-btn sable-btn-secondary"
                    onClick={() => {
                      if (baselineDialogData.bundle_sha256) {
                        navigator.clipboard.writeText(baselineDialogData.bundle_sha256);
                        setBaselineCopied(true);
                        setTimeout(() => setBaselineCopied(false), 2000);
                      }
                    }}
                    title="Click to copy SHA-256"
                    style={{ fontSize: '0.75rem', padding: '3px 8px', display: 'inline-flex', alignItems: 'center', gap: '4px' }}
                  >
                    {baselineCopied ? <><Check size={12} color="#16a34a"/> Copied</> : <><Copy size={12}/> Copy</>}
                  </button>
                </div>
              </div>
              {/* Baseline predicate */}
              <div className="sable-dialog-section">
                <strong>Baseline Predicate</strong>
                <div className={`sable-predicate-card ${baselineDialogData.baseline_predicate?.result === 'PASS' ? 'pass' : 'fail'}`}>
                  <CheckCircle2 size={14}/> {baselineDialogData.baseline_predicate?.result} — {baselineDialogData.baseline_predicate?.reason}
                </div>
                <p className="sable-small-note">{baselineDialogData.baseline_predicate?.trust_note}</p>
              </div>
              {/* Baseline TF */}
              <div className="sable-dialog-section">
                <strong>Baseline Terraform</strong>
                {Object.entries(baselineDialogData.baseline_tf_content ?? {}).map(([fname, content]: any) => (
                  <div key={fname}>
                    <code className="sable-filename">{fname}</code>
                    <pre className="sable-tf-viewer">{content.slice(0, 2000)}</pre>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {showEnvDialog && envDialogData && (
        <div className="cavr-dialog-overlay" onClick={() => setShowEnvDialog(false)}>
          <div className="cavr-dialog" onClick={e => e.stopPropagation()}>
            <div className="cavr-dialog-header">
              <div>
                <div className="cavr-dialog-title">{envDialogData.title}</div>
                <div className="cavr-dialog-subtitle">{envDialogData.subtitle}</div>
              </div>
              <button className="cavr-dialog-close" onClick={() => setShowEnvDialog(false)}>✕</button>
            </div>
            <div className="cavr-dialog-body">
              <div className="sable-flags-row">
                {Object.entries(envDialogData.flags ?? {}).map(([k, v]) => (
                  <span key={k} className="sable-flag-badge">{k.replace(/_/g, ' ')}: <strong>{String(v)}</strong></span>
                ))}
              </div>
              <div className="sable-dialog-section">
                <strong>Tool Inventory</strong>
                {Object.values(envDialogData.tool_inventory ?? {}).map((t: any) => (
                  <div key={t.name} className="sable-tool-inv-row">
                    <div className="sable-tool-inv-name">
                      {t.available
                        ? <CheckCircle2 size={13} color="#16a34a"/>
                        : <XCircle size={13} color="#dc2626"/>}
                      <strong>{t.name}</strong>
                      {t.version && <code>{t.version}</code>}
                    </div>
                    <div className="sable-tool-inv-purpose">{t.purpose}</div>
                    {!t.available && t.fallback && (
                      <div className="sable-tool-inv-fallback"><AlertTriangle size={11}/> {t.fallback}</div>
                    )}
                  </div>
                ))}
              </div>
              <div className="sable-dialog-section">
                <strong>Supported IAM/S3 Subset</strong>
                <ul className="sable-small-list">
                  {Object.entries(envDialogData.supported_terraform_subset ?? {}).map(([k, v]: any) => (
                    <li key={k}><code>{k}</code>: {Array.isArray(v) ? v.join(', ') : String(v)}</li>
                  ))}
                </ul>
              </div>
              <div className="sable-dialog-section">
                <strong>Limitations</strong>
                <ul className="sable-small-list">
                  {(envDialogData.limitations ?? []).map((l: string, i: number) => <li key={i}>{l}</li>)}
                </ul>
              </div>
            </div>
          </div>
        </div>
      )}

      {showActionDialog && actionDialogData && (
        <div className="cavr-dialog-overlay" onClick={() => setShowActionDialog(false)}>
          <div className="cavr-dialog" onClick={e => e.stopPropagation()}>
            <div className="cavr-dialog-header">
              <div>
                <div className="cavr-dialog-title">{actionDialogData.title}</div>
                <div className="cavr-dialog-subtitle">{actionDialogData.subtitle}</div>
              </div>
              <button className="cavr-dialog-close" onClick={() => setShowActionDialog(false)}>✕</button>
            </div>
            <div className="cavr-dialog-body">
              <div className="sable-dialog-section">
                <strong>Pipeline Steps</strong>
                {(actionDialogData.pipeline_steps ?? []).map((step: any) => (
                  <div key={step.step} className="sable-pipeline-step">
                    <span className="sable-step-num">{step.step}</span>
                    <div><strong>{step.name}</strong> — {step.desc}</div>
                  </div>
                ))}
              </div>
              <div className="sable-dialog-section">
                <strong>Signals Table</strong>
                <table className="sable-signals-table">
                  <thead><tr><th>Signal</th><th>Weight</th></tr></thead>
                  <tbody>
                    {(actionDialogData.signals_table ?? []).map((s: any) => (
                      <tr key={s.signal}><td>{s.signal}</td><td><code>{s.weight}</code></td></tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="sable-dialog-section">
                <strong>Decision Logic</strong>
                <pre className="sable-pseudocode">{actionDialogData.decision_pseudocode}</pre>
              </div>
              <div className="sable-dialog-section">
                <strong>Outcomes</strong>
                {(actionDialogData.outcomes ?? []).map((o: any) => (
                  <div key={o.verdict} className="sable-outcome-card">
                    <div className="sable-outcome-verdict" style={{ color: VERDICT_COLORS[o.verdict] ?? '#6b7280' }}>{o.verdict} → {o.asent_mapping}</div>
                    <p><em>{o.wording}</em></p>
                  </div>
                ))}
                <p className="sable-small-note">{actionDialogData.honesty_note}</p>
                <p className="sable-small-note"><Lock size={11}/> {actionDialogData.llm_note}</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Proof Drawer */}
      {showProofDrawer && runState.proofData && (
        <div className="cavr-dialog-overlay" onClick={() => setShowProofDrawer(false)}>
          <div className="cavr-dialog" onClick={e => e.stopPropagation()} style={{ maxWidth: 680 }}>
            <div className="cavr-dialog-header">
              <div>
                <div className="cavr-dialog-title">Proof Drawer</div>
                <div className="cavr-dialog-subtitle">Cryptographic Evidence & Determinism Proof · Run {runState.runId}</div>
              </div>
              <button className="cavr-dialog-close" onClick={() => setShowProofDrawer(false)}>✕</button>
            </div>
            <div className="cavr-dialog-body">
              {/* Determinism Re-run Verification */}
              <div style={{
                background: '#f8fafc',
                border: '1px solid #cbd5e1',
                borderRadius: '8px',
                padding: '14px',
                marginBottom: '1rem'
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <div>
                    <strong style={{ fontSize: '0.85rem', color: '#1e293b' }}>Determinism Verification</strong>
                    <span className="sable-small-note" style={{ display: 'block' }}>
                      Re-runs the exact same input to prove decision hash is bit-for-bit identical (zero LLM / stochasticity).
                    </span>
                  </div>
                  <button
                    className="sable-btn sable-btn-primary"
                    onClick={handleVerifyDeterminism}
                    disabled={isVerifyingDeterminism}
                    style={{ fontSize: '0.75rem', padding: '6px 12px' }}
                  >
                    {isVerifyingDeterminism ? <><RefreshCw size={12} className="spin"/> Re-running…</> : <><RefreshCw size={12}/> Re-run to verify determinism</>}
                  </button>
                </div>

                {rerunDeterminismResult && (
                  <div style={{ marginTop: '10px', padding: '10px', background: rerunDeterminismResult.identical ? '#f0fdf4' : '#fef2f2', borderRadius: '6px', border: `1px solid ${rerunDeterminismResult.identical ? '#bbf7d0' : '#fecaca'}` }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '6px', color: rerunDeterminismResult.identical ? '#16a34a' : '#dc2626', fontWeight: 600, fontSize: '0.85rem' }}>
                      {rerunDeterminismResult.identical ? <CheckCircle2 size={16}/> : <XCircle size={16}/>}
                      {rerunDeterminismResult.identical
                        ? 'Identical decision hash confirmed! Execution is 100% deterministic.'
                        : 'Determinism failure: Decision hash differed on re-run.'}
                    </div>
                    <div className="sable-kv" style={{ marginTop: 6 }}><span>Original Hash</span><code>{rerunDeterminismResult.original_hash}</code></div>
                    <div className="sable-kv"><span>Re-run Hash</span><code>{rerunDeterminismResult.rerun_hash}</code></div>
                  </div>
                )}
              </div>

              {/* Exact commands & isolation */}
              <div className="sable-dialog-section">
                <strong>Local Evidence Tools & Execution Isolation</strong>
                <div className="sable-kv-list">
                  <div className="sable-kv"><span>HCL Parser</span><code>python-hcl2 v8.1.4 (pinned)</code></div>
                  <div className="sable-kv"><span>Checkov</span><code>checkov --framework terraform --skip-download (offline)</code></div>
                  <div className="sable-kv"><span>Terraform CLI</span><code>terraform validate (offline, cached providers)</code></div>
                  <div className="sable-kv"><span>Isolation Flags</span><span>{runState.proofData.isolation_flags}</span></div>
                  <div className="sable-kv"><span>LLM in Decision Path</span><strong>{runState.proofData.llm_in_decision_path}</strong></div>
                  <div className="sable-kv"><span>Network / Cloud</span><span>Network OFF · Cloud OFF</span></div>
                </div>
              </div>

              {/* Hashes and Config */}
              <div className="sable-dialog-section">
                <strong>Cryptographic Bundle & Policy Hashes</strong>
                <div className="sable-kv-list">
                  <div className="sable-kv"><span>Decision Hash</span><code>{runState.proofData.decision_hash}</code></div>
                  <div className="sable-kv"><span>Baseline SHA-256</span><code>{runState.proofData.baseline_sha256}</code></div>
                  <div className="sable-kv"><span>Candidate SHA-256</span><code>{runState.proofData.candidate_sha256}</code></div>
                  <div className="sable-kv"><span>Confidence Threshold</span><code>{runState.proofData.config?.confidence_threshold ?? 6} pts</code></div>
                  <div className="sable-kv"><span>Uniqueness Margin</span><code>{runState.proofData.config?.uniqueness_margin ?? 3} pts</code></div>
                  <div className="sable-kv"><span>Evidence Ledger Length</span><code>{runState.proofData.evidence_chain_length} blocks</code></div>
                </div>
              </div>

              {/* Execution log */}
              <div className="sable-dialog-section">
                <strong>Execution Log</strong>
                <pre className="sable-terminal" style={{ maxHeight: 180, fontSize: '0.75rem' }}>
                  {runState.proofData.logs?.join('\n')}
                </pre>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Custom Terraform bundle input */}
      {showUploadDialog && (
        <div className="cavr-dialog-overlay" onClick={() => setShowUploadDialog(false)}>
          <div className="cavr-dialog" onClick={e => e.stopPropagation()} style={{ maxWidth: 900 }}>
            <div className="cavr-dialog-header">
              <div>
                <div className="cavr-dialog-title">Provide Custom Terraform Bundles</div>
                <div className="cavr-dialog-subtitle">Enter every .tf file, preserving relative paths for local modules. The baseline is checked against SABLE's registered S3/IAM obligation.</div>
              </div>
              <button className="cavr-dialog-close" aria-label="Close bundle input" onClick={() => setShowUploadDialog(false)}>×</button>
            </div>
            <div className="cavr-dialog-body">
              {renderBundleFiles('Baseline Terraform (Trusted)', uploadBaselineFiles, setUploadBaselineFiles)}
              {renderBundleFiles('Candidate Terraform (Refactored)', uploadCandidateFiles, setUploadCandidateFiles)}
              {uploadError && <div role="alert" className="sable-diff-warn" style={{ marginBottom: 12 }}>{uploadError}</div>}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button className="sable-btn sable-btn-secondary" onClick={() => setShowUploadDialog(false)}>Cancel</button>
                <button className="sable-btn sable-btn-primary" onClick={handleUploadRun} disabled={isRunning}>
                  {isRunning ? <><RefreshCw size={13} className="spin"/> Analyzing?</> : <><Play size={13}/> Run Analysis on Custom Bundle</>}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
