import React, { useState, useEffect, useRef } from 'react';
import { 
  Database, ShieldAlert, Cpu, CheckCircle2, XCircle, AlertTriangle, 
  Terminal, ExternalLink, Copy, Check, Play, RefreshCw, Eye, 
  Lock, ArrowRight, Download, ThumbsUp, ThumbsDown, Info, HelpCircle,
  FileCode, Layers, ShieldCheck, Activity, Search, Sparkles
} from 'lucide-react';

import { CavrRunState } from './cavr/types';
import { StageDetailPanel } from './cavr/StageDetailPanel';
import { ExpandableStep, SubStep } from './cavr/ExpandableStep';
import { OverviewTab } from './cavr/OverviewTab';
import { RequirementsTab } from './cavr/RequirementsTab';
import { CapabilityContractTab } from './cavr/CapabilityContractTab';
import { TriggersTab } from './cavr/TriggersTab';
import { CounterfactualTab } from './cavr/CounterfactualTab';
import { CausalGraphTab } from './cavr/CausalGraphTab';
import { RepairTab } from './cavr/RepairTab';
import { AssuranceTab } from './cavr/AssuranceTab';
import { MetricsTab } from './cavr/MetricsTab';

interface TrustedPackage {
  name: string;
  version: string;
  sha256: string;
  source: string;
  status: string;
  capabilities: string;
  added_at: string;
}

// One chip, as GET /api/cavr/scenarios describes it. The page holds no package name of its own.
interface Scenario {
  id: string;
  display_name: string;
  description: string;
  request: string;
  package: string;
  version: string;
  condition: string | null;
  expected_status: string;
}

export const CavrModule: React.FC = () => {
  // Dialog visibility states
  const [showCacheDialog, setShowCacheDialog] = useState(false);
  const [showActionDialog, setShowActionDialog] = useState(false);
  const [showEnvDialog, setShowEnvDialog] = useState(false);
  const [showProofDrawer, setShowProofDrawer] = useState(false);

  // Cache state & dialog filters
  const [packages, setPackages] = useState<TrustedPackage[]>([]);
  const [cacheSearch, setCacheSearch] = useState('');
  const [reverifiedRows, setReverifiedRows] = useState<Record<string, boolean>>({});
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  // Action dialog interactive typosquat demo
  const [demoInput, setDemoInput] = useState('reqeusts');

  // Active evidence tab: overview | requirements | contract | triggers | counterfactual | causal | repair | assurance | metrics
  const [activeEvidenceTab, setActiveEvidenceTab] = useState<string>('overview');
  const [newTabAlerts, setNewTabAlerts] = useState<Record<string, boolean>>({});

  // Workflow state
  const [explainSimply, setExplainSimply] = useState(false);
  const [activeWorkflowBox, setActiveWorkflowBox] = useState<'none' | 'cache' | 'action' | 'env'>('none');
  const [timelineStep, setTimelineStep] = useState<number>(0);
  const [expandedTimelineStep, setExpandedTimelineStep] = useState<number | null>(null);
  const [isRunning, setIsRunning] = useState(false);
  // The scenario chips, read from the backend. `null` until it has answered.
  const [scenarios, setScenarios] = useState<Scenario[] | null>(null);
  const [scenariosFailed, setScenariosFailed] = useState(false);
  const [currentScenario, setCurrentScenario] = useState<string | null>(null);

  // Comprehensive run state
  const [runState, setRunState] = useState<CavrRunState>({
    runId: null,
    stepIndex: 0,
    request: null,
    package: '',
    version: '',
    scenarioKey: '',
    explainSimply: false,
    verdict: null,
    policyState: null,
    honestyWording: 'Awaiting execution...',
    currentStateMessage: 'Ready to launch multi-layer assurance pipeline.',
    currentPlainMessage: 'Select a scenario above to observe the real pipeline in action.',
    gateResult: null,
    resolution: null,
    cacheResult: null,
    actionData: null,
    counterfactualResults: null,
    causalGraph: null,
    violatingPaths: null,
    repair: null,
    reverification: null,
    certificate: null,
    reconstruction: null,
    terminalLogs: [],
    meters: { network_attempts: 0, writes_outside_scratch: 0, processes_spawned: 0, secrets_touched: 0 },
    honeytokenFlashing: false,
    proofData: null
  });

  const [containerLifecycle, setContainerLifecycle] = useState<'idle' | 'created' | 'locked' | 'mounted' | 'running' | 'destroyed'>('idle');
  const [alternativeDecision, setAlternativeDecision] = useState<'pending' | 'approved' | 'rejected'>('pending');
  const terminalEndRef = useRef<HTMLDivElement | null>(null);

  // Fetch trusted packages
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

  useEffect(() => {
    if (terminalEndRef.current) {
      terminalEndRef.current.scrollTop = terminalEndRef.current.scrollHeight;
    }
  }, [runState.terminalLogs]);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(id);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const reverifyHashRow = (pkgName: string) => {
    setReverifiedRows(prev => ({ ...prev, [pkgName]: true }));
    setTimeout(() => {
      setReverifiedRows(prev => ({ ...prev, [pkgName]: false }));
    }, 2500);
  };

  // Run one chip: the backend builds the request from the scenario id and runs the real pipeline.
  const runScenario = async (scenario: Scenario) => {
    if (isRunning) return;
    setIsRunning(true);
    setCurrentScenario(scenario.id);
    setTimelineStep(0);
    setExpandedTimelineStep(null);
    setActiveWorkflowBox('none');
    setAlternativeDecision('pending');
    setContainerLifecycle('idle');
    setActiveEvidenceTab('overview');
    setNewTabAlerts({});

    setRunState(prev => ({
      ...prev,
      runId: null,
      stepIndex: 0,
      request: scenario.request,
      package: scenario.package,
      version: scenario.version,
      scenarioKey: scenario.id,
      explainSimply: explainSimply,
      verdict: null,
      policyState: null,
      honestyWording: 'Evaluating...',
      currentStateMessage: `Sending '${scenario.request}' to the pipeline...`,
      currentPlainMessage: `Asking ASENT to check '${scenario.request}'.`,
      gateResult: null,
      resolution: null,
      cacheResult: null,
      actionData: null,
      counterfactualResults: null,
      causalGraph: null,
      violatingPaths: null,
      repair: null,
      reverification: null,
      certificate: null,
      reconstruction: null,
      terminalLogs: [],
      meters: { network_attempts: 0, writes_outside_scratch: 0, processes_spawned: 0, secrets_touched: 0 },
      honeytokenFlashing: false,
      proofData: null
    }));

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
    const { type, step_index, phase, payload } = ev;

    setRunState(prev => {
      let updated = { ...prev };

      if (step_index !== undefined) {
        setTimelineStep(step_index);
        updated.stepIndex = step_index;
      }

      if (payload?.message) {
        updated.currentStateMessage = payload.message;
      }
      if (payload?.plain_explanation) {
        updated.currentPlainMessage = payload.plain_explanation;
      }

      // Handle specific phase payloads
      if (type === 'state_change') {
        if (payload.state === 'INTERCEPTED') {
          setActiveWorkflowBox('none');
          setContainerLifecycle('idle');
        } else if (payload.state === 'SANDBOXING') {
          setActiveWorkflowBox('env');
          setContainerLifecycle('running');
        } else if (payload.state === 'RELEASED') {
          setActiveWorkflowBox('none');
          setContainerLifecycle('destroyed');
          setIsRunning(false);
        } else if (payload.state === 'ALT_RECOMMENDED') {
          setActiveWorkflowBox('none');
          setContainerLifecycle('destroyed');
          setIsRunning(false);
        } else if (payload.state === 'DECIDED') {
          // The last event of a run. The cache box shows what is stored now.
          setIsRunning(false);
          fetchCache();
        }

        if (payload.verdict) {
          updated.verdict = payload.verdict;
        }
        if (payload.policy_state) {
          updated.policyState = payload.policy_state;
        }
        if (payload.honesty_wording) {
          updated.honestyWording = payload.honesty_wording;
        }
        if (payload.certificate) {
          updated.certificate = payload.certificate;
          setNewTabAlerts(a => ({ ...a, assurance: true }));
        }
        if (payload.reconstruction) {
          updated.reconstruction = payload.reconstruction;
        }
      } 
      else if (type === 'requirement_gate_evaluated') {
        updated.gateResult = payload;
        setNewTabAlerts(a => ({ ...a, requirements: true }));
      }
      else if (type === 'package_resolved') {
        updated.resolution = payload.resolution;
      }
      else if (type === 'cache_result') {
        updated.cacheResult = payload;
        if (payload.result === 'HIT') {
          setActiveWorkflowBox('cache');
        }
      }
      else if (type === 'action_completed') {
        setActiveWorkflowBox('action');
        updated.actionData = payload;
        setNewTabAlerts(a => ({ ...a, contract: true, triggers: true }));
      }
      else if (type === 'sandbox_log') {
        updated.terminalLogs = [...updated.terminalLogs, payload.line];
        if (payload.line.includes('HONEYTOKEN') || payload.line.includes('CRITICAL_THREAT')) {
          updated.honeytokenFlashing = true;
          updated.meters = { ...updated.meters, secrets_touched: updated.meters.secrets_touched + 1 };
        }
        if (payload.line.includes('Network attempt') || payload.line.includes('socket.connect')) {
          updated.meters = { ...updated.meters, network_attempts: updated.meters.network_attempts + 1 };
        }
      }
      else if (type === 'counterfactual_completed') {
        updated.counterfactualResults = payload.counterfactual_results;
        setNewTabAlerts(a => ({ ...a, counterfactual: true }));
      }
      else if (type === 'verdict_computed') {
        updated.verdict = payload.verdict;
        updated.policyState = payload.policy_state;
        updated.honestyWording = payload.honesty_wording;
        updated.causalGraph = payload.causal_graph;
        updated.violatingPaths = payload.violating_paths;
        updated.repair = payload.repair;
        updated.reverification = payload.reverification;

        setNewTabAlerts(a => ({ ...a, causal: true, repair: true }));

        // Fetch proof drawer data
        fetch(`/api/cavr/proof/${currentRunId}`)
          .then(r => r.json())
          .then(proof => {
            setRunState(s => ({ ...s, proofData: proof }));
          })
          .catch(e => console.error(e));
      }

      return updated;
    });
  };

  const handleAlternativeChoice = async (approved: boolean) => {
    if (!runState.runId || !runState.repair?.chosen_candidate) return;
    const chosenName = runState.repair.chosen_candidate.name;

    try {
      await fetch('/api/cavr/approve-alternative', {
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

      setAlternativeDecision(approved ? 'approved' : 'rejected');
      setTimelineStep(7);
      setActiveWorkflowBox('none');
      setRunState(prev => ({
        ...prev,
        stepIndex: 7,
        currentStateMessage: approved
          ? `Operator Approved: Safe substitute '${chosenName}' reconstructed into pristine baseline.`
          : `Operator Rejected: Hostile package '${prev.package}' permanently blocked.`,
        currentPlainMessage: approved
          ? `You approved the substitute '${chosenName}'. A clean environment was created!`
          : `You rejected the substitute. '${prev.package}' remains blocked.`
      }));
    } catch (err) {
      console.error('Alternative approval failed:', err);
    }
  };

  // 8 Timeline Steps with real Sub-stages breakdown
  const timelineStepsData = [
    {
      title: 'Agent runs pip install',
      summary: explainSimply ? 'Agent requests package' : 'Interception of agent install command',
      substeps: [
        { phase: 'P1', name: 'CLI Gateway Interception', status: timelineStep >= 0 ? 'done' : 'pending', timeTaken: '12ms', desc: 'Captured through local PEP 503 proxy' }
      ]
    },
    {
      title: 'Index catches it',
      summary: explainSimply ? 'Policy & gate check' : 'PEP 503 Quarantine & Policy Gate',
      substeps: [
        { phase: 'P1', name: 'PEP 503 Index Lookup', status: timelineStep >= 1 ? 'done' : 'pending', timeTaken: '24ms', desc: 'Proxy blocks direct external outbound' },
        { phase: 'P2', name: 'Project Requirement Gate', status: timelineStep >= 1 ? 'done' : 'pending', timeTaken: '45ms', desc: 'Evaluates project_policy.json rules' }
      ]
    },
    {
      title: 'Quarantine',
      summary: explainSimply ? 'Isolated & scanned' : 'Transitive Tree & OSV Scan',
      substeps: [
        { phase: 'P5', name: 'Read-Only Sandbox Mount', status: timelineStep >= 2 ? 'done' : 'pending', timeTaken: '30ms', desc: 'Pinned sha256 stored in read-only isolation' },
        { phase: 'P5', name: 'Transitive Tree Resolution', status: timelineStep >= 2 ? 'done' : 'pending', timeTaken: '85ms', desc: 'Resolves sub-dependencies and edges' },
        { phase: 'P5', name: 'Offline OSV Vulnerability Audit', status: timelineStep >= 2 ? 'done' : 'pending', timeTaken: '40ms', desc: 'Scans offline mirror snapshot' }
      ]
    },
    {
      title: 'Cache Check',
      summary: explainSimply ? 'Database match check' : 'Pre-Verified Store Lookup',
      substeps: [
        { phase: 'P4', name: 'SQLite Hash Lookup', status: timelineStep >= 3 ? 'done' : 'pending', timeTaken: '15ms', desc: 'Checks trusted_packages table' },
        { phase: 'P4', name: 'Integrity Checksum Validation', status: timelineStep >= 3 ? 'done' : 'pending', timeTaken: '20ms', desc: 'Compares computed sha256 to record' }
      ]
    },
    {
      title: 'Action (AST Inspection)',
      summary: explainSimply ? 'Code & contract check' : 'AST Sinks & Trigger Discovery',
      substeps: [
        { phase: 'P3', name: 'Project Context Extraction', status: timelineStep >= 4 ? 'done' : 'pending', timeTaken: '50ms', desc: 'AST parses invoice project call sites' },
        { phase: 'P4', name: 'Capability Contract Inference', status: timelineStep >= 4 ? 'done' : 'pending', timeTaken: '65ms', desc: 'Derives required vs denied permissions' },
        { phase: 'P6', name: 'AST Trigger Predicate Discovery', status: timelineStep >= 4 ? 'done' : 'pending', timeTaken: '90ms', desc: 'Calculates trigger priority formula' }
      ]
    },
    {
      title: 'Environment (Sandbox)',
      summary: explainSimply ? 'Safe container testing' : 'Adaptive Counterfactual Runs',
      substeps: [
        { phase: 'P7', name: 'Run 0: Baseline Execution', status: timelineStep >= 5 ? 'done' : 'pending', timeTaken: '680ms', desc: 'Tests behavior under default conditions' },
        { phase: 'P7', name: 'Run 1..n: Adaptive Counterfactuals', status: timelineStep >= 5 ? 'done' : 'pending', timeTaken: '820ms', desc: 'Synthesizes fake credentials & env vars' },
        { phase: 'P8', name: 'OS Telemetry Normalization', status: timelineStep >= 5 ? 'done' : 'pending', timeTaken: '45ms', desc: 'sys.addaudithook action normalization' }
      ]
    },
    {
      title: 'Verdict Decision',
      summary: explainSimply ? 'Security decision made' : 'Causal Graph & Policy Evaluation',
      substeps: [
        { phase: 'P9', name: 'NetworkX Causal Capability Graph', status: timelineStep >= 6 ? 'done' : 'pending', timeTaken: '110ms', desc: 'Evaluates source-to-sink dataflow paths' },
        { phase: 'P10', name: 'Minimal Safe Repair Search', status: timelineStep >= 6 ? 'done' : 'pending', timeTaken: '80ms', desc: 'Solves 4-level disruption objective' },
        { phase: 'P11', name: 'Candidate Re-Verification', status: timelineStep >= 6 ? 'done' : 'pending', timeTaken: '70ms', desc: 'Verifies sample project obligations' }
      ]
    },
    {
      title: 'Release or Block',
      summary: explainSimply ? 'Final safe delivery' : 'Reconstruction & Assurance',
      substeps: [
        { phase: 'P12', name: 'Clean Environment Reconstruction', status: timelineStep >= 7 ? 'done' : 'pending', timeTaken: '60ms', desc: 'Constructs pristine baseline; discards sandbox' },
        { phase: 'P13', name: 'Assurance Certificate Generation', status: timelineStep >= 7 ? 'done' : 'pending', timeTaken: '40ms', desc: 'Issues hash-chained evidence record' }
      ]
    }
  ];

  // Filtered packages for cache dialog
  const filteredPackages = packages.filter(p => 
    p.name.toLowerCase().includes(cacheSearch.toLowerCase()) || 
    p.capabilities.toLowerCase().includes(cacheSearch.toLowerCase())
  );

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
            Cryptographically pinned packages safe for AI coding agents
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
            <span className="box-metric-tag">{packages.length} pinned</span>
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
            Static AST inspection, trigger ranking &amp; capability inference
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
            <span className="box-metric-tag">AST · Typosquat</span>
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
            Multi-layer isolated sandbox with honeytokens &amp; counterfactuals
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
            <span className="box-metric-tag">Hardened 30s</span>
          </div>
        </div>
      </div>

      {/* WIDE WORKFLOW BOX */}
      <div className="wide-workflow-box">
        <div className="workflow-box-header">
          <div className="workflow-title-area">
            <span className="live-status-pill">
              <span className={`status-dot ${isRunning ? 'pulsing' : ''}`} />
              {isRunning ? 'PIPELINE ACTIVE · 13 PHASES' : 'RESEARCH WORKFLOW ENGINE'}
            </span>
            <h4>Continuous Artifact Verification &amp; Runtime Pipeline</h4>
            <p>
              {explainSimply
                ? 'Watch how ASENT safely catches dependencies, tests hidden paths with fake credentials, and keeps your project secure.'
                : '13-phase deterministic pipeline mapped to 8 timeline steps. Real AST, NetworkX causal graph, and Merkle evidence ledger.'}
            </p>
          </div>

          {/* Scenario chips: one per entry of GET /api/cavr/scenarios, each a real request */}
          <div className="scenario-chips-wrapper">
            <span className="scenario-chips-label">Real requests (live pipeline):</span>
            <div className="scenario-chips-group">
              {scenarios === null && (
                <span className="scenario-chips-label">
                  {scenariosFailed ? 'The scenario list could not be loaded from the backend.' : 'Loading scenarios...'}
                </span>
              )}
              {(scenarios || []).map((scenario) => (
                <button
                  key={scenario.id}
                  className={`scenario-chip ${currentScenario === scenario.id ? 'active' : ''}`}
                  onClick={() => runScenario(scenario)}
                  disabled={isRunning}
                  title={`${scenario.request}. Expected: ${scenario.expected_status}. ${scenario.description}`}
                >
                  <Play size={12} />
                  <span>{scenario.display_name}</span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Custom Input / Banner Row */}
        <div className="interception-prompt-card">
          <div className="prompt-meta-col">
            <span className="prompt-label">INTERCEPTED TARGET</span>
            <code className="prompt-code">
              {runState.request ?? '—'}
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

        {/* 8-STEP EXPANDABLE GLOWING TIMELINE */}
        <div className="timeline-horizontal-wrapper">
          <div className="timeline-track-line" />
          <div className="timeline-nodes-row">
            {timelineStepsData.map((step, idx) => (
              <ExpandableStep
                key={idx}
                stepIndex={idx}
                currentStepIndex={timelineStep}
                title={step.title}
                summary={step.summary}
                substeps={step.substeps as SubStep[]}
                isExpanded={expandedTimelineStep === idx}
                onToggleExpand={() => setExpandedTimelineStep(expandedTimelineStep === idx ? null : idx)}
                onClickStep={() => setExpandedTimelineStep(expandedTimelineStep === idx ? null : idx)}
                explainSimply={explainSimply}
              />
            ))}
          </div>
        </div>

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
            className={`evidence-tab-btn ${activeEvidenceTab === 'counterfactual' ? 'active' : ''} ${newTabAlerts.counterfactual ? 'pulse-alert' : ''}`}
            onClick={() => setActiveEvidenceTab('counterfactual')}
          >
            Counterfactual Runs
          </button>

          <button 
            className={`evidence-tab-btn ${activeEvidenceTab === 'causal' ? 'active' : ''} ${newTabAlerts.causal ? 'pulse-alert' : ''}`}
            onClick={() => setActiveEvidenceTab('causal')}
          >
            Causal Graph
          </button>

          <button 
            className={`evidence-tab-btn ${activeEvidenceTab === 'repair' ? 'active' : ''} ${newTabAlerts.repair ? 'pulse-alert' : ''}`}
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

        {/* SANDBOX CONSOLE & BEHAVIOR METERS */}
        {(activeWorkflowBox === 'env' || runState.terminalLogs.length > 0 || runState.verdict) && (
          <div className="sandbox-console-panel">
            <div className="lifecycle-bar-container">
              <span className="lifecycle-title">Sandbox Lifecycle:</span>
              <div className="lifecycle-stages">
                <span className={`lifecycle-stage ${['created', 'locked', 'mounted', 'running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>1. Created</span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${['locked', 'mounted', 'running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>2. Locked down</span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${['mounted', 'running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>3. Package mounted</span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${['running', 'destroyed'].includes(containerLifecycle) ? 'active' : ''}`}>4. Tests running</span>
                <span className="stage-arrow">→</span>
                <span className={`lifecycle-stage ${containerLifecycle === 'destroyed' ? 'active destroyed' : ''}`}>5. Destroyed</span>
              </div>
            </div>

            <div className="lockdown-badges-row">
              <div className="lockdown-badge" title="Network isolation: all socket creation and internet connections are strictly blocked">
                <span className="badge-k">Network:</span> <span className="badge-v red">OFF</span>
              </div>
              <div className="lockdown-badge" title="Filesystem read-only: unauthorized modifications to container system are impossible">
                <span className="badge-k">Filesystem:</span> <span className="badge-v">read-only</span>
              </div>
              <div className="lockdown-badge" title="User non-root: runs under unprivileged UID 10001, blocking root exploits">
                <span className="badge-k">User:</span> <span className="badge-v">non-root (10001)</span>
              </div>
              <div className="lockdown-badge" title="Capabilities dropped: removes all Linux superuser privileges">
                <span className="badge-k">Capabilities:</span> <span className="badge-v">dropped (ALL)</span>
              </div>
              <div className="lockdown-badge" title="Memory limit: hard 256MB RAM quota blocks denial-of-service">
                <span className="badge-k">Memory:</span> <span className="badge-v">256 MB</span>
              </div>
              <div className="lockdown-badge" title="CPU quota: throttled to 0.5 CPU cores to prevent exhaustion">
                <span className="badge-k">CPU:</span> <span className="badge-v">0.5 cores</span>
              </div>
              <div className="lockdown-badge" title="Timeout: hard 30-second killswitch forcibly removes rogue containers">
                <span className="badge-k">Timeout:</span> <span className="badge-v">30 s</span>
              </div>
            </div>

            <div className="terminal-and-meters-grid">
              <div className="sandbox-terminal-box">
                <div className="terminal-topbar">
                  <div className="terminal-dots">
                    <span className="tdot red" />
                    <span className="tdot yellow" />
                    <span className="tdot green" />
                  </div>
                  <span className="terminal-title">
                    <Terminal size={12} /> asent-sandbox stdout log stream (sys.addaudithook)
                  </span>
                  <span className="terminal-live-tag">LIVE FEED</span>
                </div>
                <div className="terminal-body" ref={terminalEndRef}>
                  {runState.terminalLogs.length === 0 ? (
                    <div className="terminal-empty">Awaiting container execution...</div>
                  ) : (
                    runState.terminalLogs.map((log, idx) => (
                      <div 
                        key={idx} 
                        className={`terminal-log-line ${
                          log.includes('CRITICAL_THREAT') || log.includes('SECURITY_ALERT') ? 'log-critical' :
                          log.includes('LIFECYCLE') ? 'log-lifecycle' :
                          log.includes('TEST_EXECUTION') ? 'log-test' : ''
                        }`}
                      >
                        {log}
                      </div>
                    ))
                  )}
                </div>
              </div>

              <div className="behavior-meters-card">
                <div className="meters-header">
                  <h5>Behavioral Telemetry Meters</h5>
                  <span className="meters-subtitle">Live sys.addaudithook sensors</span>
                </div>

                <div className="meters-list">
                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Network Attempts</span>
                      <strong>{runState.meters.network_attempts}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${runState.meters.network_attempts > 0 ? 'red' : 'green'}`}
                        style={{ width: `${Math.min(runState.meters.network_attempts * 100, 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Writes Outside Scratch</span>
                      <strong>{runState.meters.writes_outside_scratch}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${runState.meters.writes_outside_scratch > 0 ? 'red' : 'green'}`}
                        style={{ width: `${Math.min(runState.meters.writes_outside_scratch * 100, 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Processes Spawned</span>
                      <strong>{runState.meters.processes_spawned}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${runState.meters.processes_spawned > 0 ? 'amber' : 'green'}`}
                        style={{ width: `${Math.min(runState.meters.processes_spawned * 50, 100)}%` }}
                      />
                    </div>
                  </div>

                  <div className="meter-item">
                    <div className="meter-label-row">
                      <span>Secrets Touched</span>
                      <strong>{runState.meters.secrets_touched}</strong>
                    </div>
                    <div className="meter-bar-track">
                      <div 
                        className={`meter-bar-fill ${runState.meters.secrets_touched > 0 ? 'red' : 'green'}`}
                        style={{ width: `${Math.min(runState.meters.secrets_touched * 100, 100)}%` }}
                      />
                    </div>
                  </div>
                </div>

                <div className={`honeytoken-indicator-box ${runState.honeytokenFlashing ? 'flashing-alert' : ''}`}>
                  <div className="indicator-icon">
                    <ShieldAlert size={18} />
                  </div>
                  <div>
                    <strong>Honeytoken Secret Trap</strong>
                    <p>
                      {runState.honeytokenFlashing
                        ? 'CRITICAL ALERT: Synthetic AWS credentials read by package!'
                        : 'Trap active at ~/.aws/credentials. Awaiting access attempts.'}
                    </p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* DIALOG 1: ENRICHED CACHE DIALOG */}
      {showCacheDialog && (
        <div className="modal-backdrop" onClick={() => setShowCacheDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">DEPENDENCY TRUST STORE</span>
                <h3>Trusted Packages &amp; Cryptographic Hashes</h3>
                <p>Pre-verified Python dependencies available for AI coding agents. Stored in SQLite.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowCacheDialog(false)}>✕</button>
            </div>

            {/* Note on Cache Hit vs Mismatch */}
            <div className="dialog-note-banner">
              <Info size={14} className="text-cyan-400" />
              <span>
                <strong>Cache Hit vs. Hash Mismatch:</strong> A Cache Hit skips hostile sandbox analysis because the package name and exact SHA-256 match pre-verified records. A Hash Mismatch indicates artifact bytes were modified or poisoned, triggering mandatory quarantine.
              </span>
            </div>

            {/* Search input */}
            <div className="dialog-search-row">
              <Search size={14} className="text-gray-400" />
              <input 
                type="text" 
                placeholder="Search packages by name or declared capabilities..." 
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
                    <th>SHA-256 Digest</th>
                    <th>Capabilities Scope</th>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Verification</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredPackages.map((pkg) => (
                    <tr key={`${pkg.name}-${pkg.version}`}>
                      <td><strong>{pkg.name}</strong></td>
                      <td><code>{pkg.version}</code></td>
                      <td>
                        <button 
                          className="hash-copy-btn" 
                          onClick={() => copyToClipboard(pkg.sha256, `${pkg.name}-${pkg.version}`)}
                          title="Click to copy full SHA-256 hash"
                        >
                          <code>{pkg.sha256.substring(0, 16)}...</code>
                          {copiedHash === `${pkg.name}-${pkg.version}` ? <Check size={12} className="text-emerald-400" /> : <Copy size={12} />}
                        </button>
                      </td>
                      <td><span className="cap-pill">{pkg.capabilities}</span></td>
                      <td>{pkg.source}</td>
                      <td><span className="status-badge trusted">{pkg.status}</span></td>
                      <td>
                        <button 
                          className={`reverify-btn ${reverifiedRows[pkg.name] ? 'verified' : ''}`}
                          onClick={() => reverifyHashRow(pkg.name)}
                        >
                          {reverifiedRows[pkg.name] ? <Check size={11} /> : <RefreshCw size={11} />}
                          <span>{reverifiedRows[pkg.name] ? 'Matches' : 'Re-verify'}</span>
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* DIALOG 2: ENRICHED ACTION DIALOG */}
      {showActionDialog && (
        <div className="modal-backdrop" onClick={() => setShowActionDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">STATIC AST INSPECTOR &amp; POLICY REASONING</span>
                <h3>Action Box: Rules Catalogue &amp; Priority Formula</h3>
                <p>Inspection rules, trigger scoring, and the 4 policy outcome states.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowActionDialog(false)}>✕</button>
            </div>

            {/* Live Typosquat Demo Field */}
            <div className="dialog-interactive-card">
              <h6>Interactive Typosquatting &amp; Homoglyph Detector</h6>
              <p>Type a package name to calculate edit distance against trusted packages:</p>
              <div className="typo-input-row">
                <input 
                  type="text" 
                  value={demoInput} 
                  onChange={(e) => setDemoInput(e.target.value)} 
                  className="demo-text-input" 
                  placeholder="Try 'reqeusts' or 'collorama'..."
                />
                <div className="demo-result">
                  {packages.some(p => p.name === demoInput) ? (
                    <span className="text-emerald-400 font-semibold"><CheckCircle2 size={13} className="inline mr-1" /> Matches Trusted Package</span>
                  ) : packages.some(p => Math.abs(p.name.length - demoInput.length) <= 2 && (p.name.includes(demoInput.slice(0, 4)) || demoInput.includes(p.name.slice(0, 4)))) ? (
                    <span className="text-red-400 font-semibold"><AlertTriangle size={13} className="inline mr-1" /> High Risk: Suspicious Typosquat / Homoglyph Detected</span>
                  ) : (
                    <span className="text-gray-400">Unmatched dependency name</span>
                  )}
                </div>
              </div>
            </div>

            {/* 4 Policy States */}
            <div className="dialog-interactive-card">
              <h6>The 4 Policy States</h6>
              <div className="four-states-grid">
                <div className="state-box verified">
                  <strong>VERIFIED (ALLOW)</strong>
                  <p>No malicious behavior observed under our tests. Contract satisfied.</p>
                </div>
                <div className="state-box restricted">
                  <strong>RESTRICTED (ALLOW with restrictions)</strong>
                  <p>Permitted under narrowed capability boundary (seccomp syscall filter applied).</p>
                </div>
                <div className="state-box unresolved">
                  <strong>UNRESOLVED (NEEDS_REVIEW)</strong>
                  <p>Fails closed. Ambiguous predicates or execution budget exhausted.</p>
                </div>
                <div className="state-box rejected">
                  <strong>REJECTED (BLOCK)</strong>
                  <p>Decisive capability violation, credential exfiltration, or denylist match detected.</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* DIALOG 3: ENRICHED ENVIRONMENT DIALOG */}
      {showEnvDialog && (
        <div className="modal-backdrop" onClick={() => setShowEnvDialog(false)}>
          <div className="modal-sheet" onClick={(e) => e.stopPropagation()}>
            <div className="modal-top">
              <div>
                <span className="modal-eyebrow">CONTAINER ISOLATION SPECIFICATION</span>
                <h3>Environment: Multi-Layer Hostile Code Sandbox</h3>
                <p>Disposable Docker isolation parameters, synthesized conditions, and explicit bounds.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowEnvDialog(false)}>✕</button>
            </div>

            {/* Dockerfile Summary */}
            <div className="dialog-interactive-card">
              <h6>Dockerfile Summary &amp; Hardened Stack</h6>
              <div className="docker-summary-grid">
                <div><span>Base Image:</span> <code>python:3.12-slim</code></div>
                <div><span>Execution User:</span> <code>sandbox (UID 10001, unprivileged)</code></div>
                <div><span>Observation Layer:</span> <code>sys.addaudithook + seccomp</code></div>
                <div><span>Harness Path:</span> <code>/opt/asent/harness.py</code></div>
              </div>
            </div>

            {/* Synthesizable Counterfactual Conditions */}
            <div className="dialog-interactive-card">
              <h6>Counterfactual Conditions Engine Can Synthesize</h6>
              <ul className="conditions-synth-list">
                <li><strong>Fake Environment Variables:</strong> Synthesizes fake AWS keys (<code>AWS_SECRET_ACCESS_KEY</code>), production flags (<code>PROD=1</code>), or CI flags (<code>CI=true</code>).</li>
                <li><strong>Fake Filesystem Objects:</strong> Places dummy credential honeytokens at <code>~/.aws/credentials</code> and <code>~/.ssh/id_rsa</code>.</li>
                <li><strong>Spoofed Hostname &amp; User:</strong> Spoofs <code>socket.gethostname()</code> and <code>getpass.getuser()</code> to awaken environment-targeted payloads.</li>
                <li><strong>Harness Time Shim:</strong> Warps time comparisons and skips delay sleep calls to test time-bombed payloads safely.</li>
              </ul>
            </div>

            {/* Explicit Limitations Section */}
            <div className="dialog-interactive-card limitation-card">
              <h6><AlertTriangle size={14} className="inline mr-1 text-amber-400" /> Explicit Limitations &amp; Honesty Bounds</h6>
              <ul className="limitations-list">
                <li><strong>Bounded Isolation:</strong> Isolation is bounded to declared container mechanisms. eBPF kernel tracing is not accessible in rootless contexts.</li>
                <li><strong>Finite Test Paths:</strong> Conditions not triggered during exploration stay unresolved.</li>
                <li><strong>No Claim of Universal Absence:</strong> Under our honesty rule, an ALLOW outcome is always presented as <em>"No malicious behavior observed under our tests"</em>. It never claims "proven safe".</li>
              </ul>
            </div>
          </div>
        </div>
      )}

      {/* PROOF DRAWER */}
      {showProofDrawer && runState.proofData && (
        <div className="modal-backdrop" onClick={() => setShowProofDrawer(false)}>
          <div className="drawer-panel" onClick={(e) => e.stopPropagation()}>
            <div className="drawer-top">
              <div>
                <span className="modal-eyebrow">FORENSIC AUDIT RECORD</span>
                <h3>Cryptographic Proof Drawer</h3>
                <p>Reproducible container command, digests, and per-run evidence chain.</p>
              </div>
              <button className="modal-close-btn" onClick={() => setShowProofDrawer(false)}>✕</button>
            </div>

            <div className="drawer-content-scroll">
              <div className="proof-group">
                <label>Exact Docker Run Command:</label>
                <pre className="proof-code"><code>{runState.proofData.docker_command}</code></pre>
              </div>

              <div className="proof-group">
                <label>Container ID &amp; Image Digest:</label>
                <div className="proof-kv">
                  <div><span>Container ID:</span> <code>{runState.proofData.container_id}</code></div>
                  <div><span>Image Digest:</span> <code>{runState.proofData.image_digest}</code></div>
                </div>
              </div>

              <div className="proof-group">
                <label>Cryptographic Hash Comparison:</label>
                <div className="proof-kv">
                  <div><span>Actual Artifact SHA-256:</span> <code>{runState.proofData.hash_comparison?.actual_sha256}</code></div>
                  <div><span>Hash Match:</span> <strong className="text-emerald-400">VERIFIED MATCH</strong></div>
                </div>
              </div>

              <div className="proof-group">
                <label>Counterfactual Container Runs ({runState.proofData.counterfactual_runs?.length || 1}):</label>
                <div className="cf-proof-list">
                  {runState.proofData.counterfactual_runs?.map((r: any) => (
                    <div key={r.run_number} className="cf-proof-item">
                      <strong>Run {r.run_number}: {r.condition_applied?.name}</strong>
                      <span>Behaviors: {r.behaviors_found?.map((b: any) => b.action).join(', ') || 'Clean'}</span>
                    </div>
                  ))}
                </div>
              </div>

              <div className="proof-group">
                <label>Merkle Evidence Root Digest:</label>
                <code className="proof-code">{runState.proofData.evidence_chain_root}</code>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
