import React, { useState, useEffect } from 'react';
import {
  ShieldCheck, RefreshCw, Play, Package, Network, ShieldAlert,
  GitCommit, XCircle, AlertTriangle
} from 'lucide-react';

interface Scenario {
  id: string;
  title: string;
  subtitle: string;
  source: string;
}

export const RunWorkflowModule: React.FC = () => {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedScenario, setSelectedScenario] = useState<string>('safe');
  const [currentRun, setCurrentRun] = useState<any>(null);
  const [moduleEvidence, setModuleEvidence] = useState<any[]>([]);
  const [events, setEvents] = useState<any[]>([]);
  const [loading, setLoading] = useState<boolean>(false);
  const [selectedWorkflowStage, setSelectedWorkflowStage] = useState('snapshot');

  useEffect(() => {
    fetch('/api/scenarios')
      .then((r) => r.json())
      .then((data) => setScenarios(data))
      .catch((e) => console.error(e));

    fetch('/api/runs')
      .then((r) => r.json())
      .then(async (runs) => {
        if (runs && runs.length > 0) {
          const run = runs[0];
          setCurrentRun(run);
          const [evidenceResult, eventsResult] = await Promise.allSettled([
            fetch(`/api/runs/${run.run_id}/evidence`).then((r) => r.ok ? r.json() : []),
            fetch(`/api/runs/${run.run_id}/events`).then((r) => r.ok ? r.json() : null)
          ]);
          if (evidenceResult.status === 'fulfilled') setModuleEvidence(evidenceResult.value);
          else {
            setModuleEvidence([]);
            console.error(evidenceResult.reason);
          }
          if (eventsResult.status === 'fulfilled' && eventsResult.value) setEvents(eventsResult.value);
          else if (eventsResult.status === 'rejected') console.error(eventsResult.reason);
        }
      })
      .catch((e) => console.error(e));
  }, []);

  const triggerRun = async () => {
    setLoading(true);
    setCurrentRun(null);
    setModuleEvidence([]);
    setEvents([]);
    try {
      const res = await fetch('/api/runs', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ scenario: selectedScenario, mode: 'manual' })
      });
      if (res.ok) {
        const run = await res.json();
        setCurrentRun(run);
        setModuleEvidence([]);
        setEvents([]);
        pollRun(run.run_id);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const pollRun = (runId: string) => {
    let count = 0;
    const interval = setInterval(async () => {
      count++;
      try {
        const [rRes, evRes, evidenceRes] = await Promise.all([
          fetch(`/api/runs/${runId}`),
          fetch(`/api/runs/${runId}/events`),
          fetch(`/api/runs/${runId}/evidence`)
        ]);
        if (rRes.ok) {
          const runData = await rRes.json();
          setCurrentRun(runData);
          if (['COMPLETE', 'ERROR', 'INTERRUPTED'].includes(runData.lifecycle) || count > 120) {
            clearInterval(interval);
          }
        }
        if (evRes.ok) setEvents(await evRes.json());
        if (evidenceRes.ok) setModuleEvidence(await evidenceRes.json());
      } catch {
        clearInterval(interval);
      }
    }, 700);
  };

  const currentEvidence = moduleEvidence.filter((e) =>
    !e.stale && e.candidate_snapshot === currentRun?.candidate_snapshot
  );
  const hasEvent = (kind: string) => events.some((event) => event.kind === kind);
  const lastEvent = (kind: string) => [...events].reverse().find((event) => event.kind === kind);
  const finalGateEvent = [...events].reverse().find((event) =>
    event.kind === 'final_gate.changed' && event.data?.statuses
  );
  const workflowFinished = ['COMPLETE', 'ERROR', 'INTERRUPTED'].includes(currentRun?.lifecycle || '');
  const moduleRunState = (module: string) => {
    const started = events.some((event) => event.kind === 'module.started' && event.data?.module === module);
    const result = lastEvent(`${module.toLowerCase()}.decision`);
    if (currentRun?.applicable && !currentRun.applicable.includes(module)) return { state: 'complete', detail: 'Not applicable to this change' };
    if (result) return { state: 'complete', detail: result.data?.status || 'Evidence recorded' };
    if (started) return { state: 'active', detail: 'Analyzing current candidate snapshot' };
    if (workflowFinished) return { state: 'waiting', detail: 'No analysis event recorded for this module' };
    return { state: 'waiting', detail: 'Waiting for the shared router' };
  };
  const sableBaselineEvent = lastEvent('sable.baseline_loaded');
  const sableCandidates = events.filter((event) => event.kind === 'sable.successor_candidate');
  const sableProjectionEvent = lastEvent('sable.obligation_projected');
  const sableDecisionEvent = lastEvent('sable.decision');
  const snapshotEventForFlow = lastEvent('workspace.snapshot');
  const snapshotFileNames = typeof snapshotEventForFlow?.data?.git_diff === 'string'
    ? [...snapshotEventForFlow.data.git_diff.matchAll(/^diff --git a\/(.*?) b\//gm)].map((match) => match[1]).slice(0, 5)
    : [];
  const topSuccessors = [...sableCandidates].sort((a, b) => (b.data?.score || 0) - (a.data?.score || 0)).slice(0, 3);
  const sableLiveSteps = [
    { label: 'Verify trusted baseline', done: Boolean(sableBaselineEvent), skipped: false, detail: sableBaselineEvent ? `Obligation loaded for ${sableBaselineEvent.data?.principal || 'registered principal'}` : 'Waiting for SABLE baseline check' },
    { label: 'Match protected resource', done: sableCandidates.length > 0 || Boolean(sableDecisionEvent), skipped: false, detail: sableCandidates.length ? `${sableCandidates.length} successor candidate(s) scored from Terraform evidence` : sableDecisionEvent ? (sableDecisionEvent.data?.status === 'UNKNOWN' ? 'No safe unique successor was established' : 'No candidate match was needed') : 'Waiting for normalized Terraform resources' },
    { label: 'Project authorization', done: Boolean(sableProjectionEvent) || Boolean(sableDecisionEvent), skipped: Boolean(sableDecisionEvent) && !sableProjectionEvent, detail: sableProjectionEvent ? `${sableProjectionEvent.data?.known ? 'Known' : 'Unknown'} authorization result for ${sableProjectionEvent.data?.successor || 'selected successor'}` : sableDecisionEvent && !sableProjectionEvent ? 'Not reached: earlier evidence did not support projection' : 'Waiting for a selected successor' },
    { label: 'Record SABLE decision', done: Boolean(sableDecisionEvent), skipped: false, detail: sableDecisionEvent ? `${sableDecisionEvent.data?.status} · ${sableDecisionEvent.data?.duration_ms ? `${Math.round(sableDecisionEvent.data.duration_ms)} ms` : 'result recorded'}` : 'Waiting for the analyzer result' },
  ];
  const evidenceFor = (module: string) => [...currentEvidence].reverse().find((e) => e.analyzer === module);
  const moduleStartedEvent = (module: string) => [...events].reverse().find((event) => event.kind === 'module.started' && event.data?.module === module);
  const moduleDecisionEvent = (module: string) => lastEvent(`${module.toLowerCase()}.decision`);
  const recentEvents = events.slice(-8).reverse();
  const eventHeadline = (event: any) => {
    if (event.kind === 'run.created') return 'Candidate accepted for analysis';
    if (event.kind === 'workspace.snapshot') return 'Candidate frozen and fingerprinted';
    if (event.kind === 'module.started') return `${event.data?.module || 'Module'} analysis started`;
    if (event.kind === 'sable.baseline_loaded') return 'Trusted SABLE obligation loaded';
    if (event.kind === 'sable.successor_candidate') return 'Terraform successor scored';
    if (event.kind === 'sable.obligation_projected') return 'Authorization projected onto successor';
    if (event.kind.endsWith('.decision')) return `${event.data?.module || event.kind.split('.')[0]} decision recorded`;
    if (event.kind === 'final_gate.changed') return event.data?.statuses ? 'Shared final gate evaluated' : 'Candidate awaiting evidence';
    return event.kind.replace(/[._]/g, ' ');
  };
  const eventDetail = (event: any) => {
    if (event.kind === 'workspace.snapshot') return `${event.data?.files ?? '—'} files · ${String(event.data?.hash || '').slice(0, 16)}`;
    if (event.kind === 'module.started') return `Input ${String(event.data?.input_hash || '').slice(0, 14)}`;
    if (event.kind === 'sable.successor_candidate') return `${event.data?.address || 'candidate'} · score ${event.data?.score ?? '—'} · ${(event.data?.signals || []).length} signals`;
    if (event.kind === 'sable.obligation_projected') return `${event.data?.known ? 'Known' : 'Unknown'} · ${event.data?.holds ? 'obligation holds' : 'obligation does not hold'}`;
    if (event.kind.endsWith('.decision')) return `${event.data?.status || 'recorded'}${event.data?.duration_ms ? ` · ${Math.round(event.data.duration_ms)} ms` : ''}`;
    if (event.kind === 'final_gate.changed') return event.data?.statuses ? `${event.data?.decision} · ${Object.entries(event.data.statuses).map(([m, status]) => `${m} ${status}`).join(' / ')}` : (event.data?.reasons || []).join('; ');
    return event.data?.reason || event.data?.status || 'Persisted event';
  };
  const cavrEvidence = evidenceFor('CAVR');
  const sableEvidence = evidenceFor('SABLE');
  const sableStatus = sableEvidence?.status ?? 'PENDING';
  const sableStartEvent = [...events].reverse().find((event) =>
    event.kind === 'module.started' && event.data?.module === 'SABLE'
  );
  const sableInputHashMatches = sableEvidence && sableStartEvent?.data?.input_hash
    ? sableEvidence.input_hash === sableStartEvent.data.input_hash
    : null;
  const sableSnapshotIntegrityValid = Boolean(sableEvidence && sableEvidence.integrity_valid &&
    sableEvidence.candidate_snapshot === currentRun?.candidate_snapshot && sableInputHashMatches !== false);
  const sableBadge = !sableEvidence ? 'PENDING' : !sableSnapshotIntegrityValid ? 'STALE / INVALID' :
    sableStatus === 'PRESERVED' ? 'PRESERVED -> ACCEPTABLE' :
      sableStatus === 'REGRESSED' ? 'REGRESSED -> BLOCKING' : `${sableStatus} -> REVIEW`;
  const decision = currentRun?.final_decision || 'REVIEW';
  const isAccept = decision === 'ACCEPT';
  const isBlock = decision === 'BLOCK';
  const sableDetails = sableEvidence?.details || {};
  const projection = sableDetails.projected_authorization;
  const baselineVerification = sableDetails.baseline_verification;
  const baselineGraph = sableDetails.baseline_graph;
  const candidateGraph = sableDetails.candidate_graph;
  const parseErrors = Array.isArray(sableDetails.parse_errors) ? sableDetails.parse_errors : [];
  const hypotheses = Array.isArray(sableDetails.hypotheses) ? sableDetails.hypotheses : [];
  const moduleReason = (evidence: any) => {
    if (!evidence) return '';
    const details = evidence.details || {};
    const unknown = details.projected_authorization?.unknown;
    if (Array.isArray(unknown) && unknown.length) return unknown.join('; ');
    if (typeof details.reason === 'string' && details.reason) return details.reason;
    if (Array.isArray(evidence.residual_uncertainty) && evidence.residual_uncertainty.length) {
      return evidence.residual_uncertainty.join('; ');
    }
    return '';
  };
  const moduleStatus = (module: string) => evidenceFor(module)?.status || 'NO CURRENT EVIDENCE';
  const snapshotEvent = [...events].reverse().find((event) => event.kind === 'workspace.snapshot');
  const terraformDiff = typeof snapshotEvent?.data?.git_diff === 'string'
    ? snapshotEvent.data.git_diff.split('\n').filter((line: string) =>
      line.startsWith('diff --git ') || line.startsWith('--- ') || line.startsWith('+++ ') ||
      line.startsWith('@@') || /\.tf\b|aws_iam_role_policy|role =|policy =|s3:|Resource/.test(line)
    ).join('\n').slice(0, 6000)
    : '';
  const baselineLabel = !baselineVerification
    ? 'No baseline verification recorded'
    : baselineVerification.known && baselineVerification.holds
      ? 'Verified: registered authorization holds on the trusted baseline'
      : !baselineVerification.known
        ? `Unknown: ${baselineVerification.reason || 'result is not known'}`
        : `Does not hold: ${baselineVerification.reason || 'registered authorization check failed'}`;
  const nodeCount = (graph: any) => Array.isArray(graph?.nodes) ? graph.nodes.length : null;
  const liveObligation = sableBaselineEvent?.data || sableEvidence?.details?.obligation || {};
  const liveProjection = sableProjectionEvent?.data || projection;
  const visualSuccessor = liveProjection?.successor || sableDetails.successor || topSuccessors[0]?.data?.address || 'aws_s3_bucket.new_asset';
  const gateStatuses = finalGateEvent?.data?.statuses || {};
  const workflowStages = [
    { id: 'snapshot', title: 'Snapshot', short: 'Freeze candidate', done: hasEvent('workspace.snapshot'), active: loading || Boolean(currentRun && !hasEvent('workspace.snapshot')), result: snapshotEventForFlow ? `${snapshotEventForFlow.data?.files ?? '—'} files · SHA-256 ${String(snapshotEventForFlow.data?.hash || '').slice(0, 18)}…` : loading ? 'Requesting a fresh snapshot' : 'Waiting for a run', evidence: snapshotFileNames.join(' · ') || 'Changed paths appear from the backend snapshot event' },
    { id: 'cavr', title: 'CAVR', short: 'Code boundary', done: Boolean(moduleDecisionEvent('CAVR')), active: moduleRunState('CAVR').state === 'active', result: moduleStatus('CAVR'), evidence: 'Dependency and static code inspection. Sandbox execution is not run on this CAVR path.' },
    { id: 'satra', title: 'SATRA', short: 'Test evidence', done: Boolean(moduleDecisionEvent('SATRA')), active: moduleRunState('SATRA').state === 'active', result: moduleStatus('SATRA'), evidence: events.some((event) => event.kind === 'satra.counterfactual_result') ? 'Counterfactual test result recorded in this run.' : 'Test and counterfactual evidence appears when emitted.' },
    { id: 'sable', title: 'SABLE', short: 'Terraform + IAM', done: Boolean(sableDecisionEvent), active: moduleRunState('SABLE').state === 'active', result: sableEvidence ? sableEvidence.status : 'PENDING', evidence: liveProjection ? `${liveProjection.successor || 'Successor'} · ${liveProjection.known ? liveProjection.holds ? 'obligation holds' : 'obligation fails' : 'authorization unknown'}` : sableCandidates.length ? `${sableCandidates.length} successor hypothesis/hypotheses scored` : 'Baseline and resource matching pending' },
    { id: 'binding', title: 'Bind', short: 'Check evidence', done: sableSnapshotIntegrityValid, active: Boolean(sableEvidence) && !sableSnapshotIntegrityValid, result: sableEvidence ? sableSnapshotIntegrityValid ? 'VERIFIED' : 'INVALID' : 'PENDING', evidence: `Snapshot ${sableEvidence?.candidate_snapshot === currentRun?.candidate_snapshot ? 'matches' : 'not yet matched'} · input hash ${sableInputHashMatches ? 'matches' : sableInputHashMatches === false ? 'mismatch' : 'pending'}` },
    { id: 'gate', title: 'Decision', short: 'Shared gate', done: Boolean(finalGateEvent), active: workflowFinished && !finalGateEvent, result: finalGateEvent?.data?.decision || 'PENDING', evidence: currentRun?.reasons?.join(' · ') || 'The gate evaluates current module statuses and evidence bindings.' },
  ];
  const activeWorkflowStage = workflowStages.find((stage) => stage.id === selectedWorkflowStage) || workflowStages.find((stage) => stage.active) || workflowStages[0];
  const satraTestEvents = events.filter((event) => event.kind === 'satra.test_result');
  const cavrNodes = Array.isArray(evidenceFor('CAVR')?.details?.nodes) ? evidenceFor('CAVR')?.details?.nodes.slice(0, 4) : [];
  const renderResourceGraph = (graph: any, title: string, candidate = false) => {
    const nodes = Array.isArray(graph?.nodes) ? graph.nodes : [];
    const edges = Array.isArray(graph?.edges) ? graph.edges : [];
    const coords: Record<string, { x: number; y: number }> = {};
    const bucketIndex = new Map<string, number>();
    nodes.forEach((node: any, index: number) => {
      const type = String(node.type || '');
      const x = type.includes('role_policy') || type.includes('iam_policy') ? 205 : type.includes('role') ? 77 : type.includes('bucket') ? 333 : 77 + (index % 3) * 128;
      const n = bucketIndex.get(type) || 0;
      bucketIndex.set(type, n + 1);
      coords[node.id] = { x, y: type.includes('bucket') && n > 0 ? 140 : 82 };
    });
    return <div className={`workflow-resource-graph ${candidate ? 'candidate' : 'baseline'}`}>
      <div className="workflow-resource-graph-title"><strong>{title}</strong><span>{nodes.length ? `${nodes.length} Terraform resources` : 'Awaiting graph evidence'}</span></div>
      {nodes.length ? <svg viewBox="0 0 410 190" role="img" aria-label={`${title} SABLE resource graph`}>
        <defs><marker id={candidate ? 'graph-arrow-candidate' : 'graph-arrow-baseline'} viewBox="0 0 10 10" refX="8" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="#93aab4"/></marker></defs>
        {edges.map((edge: any, index: number) => { const a = coords[edge.source], b = coords[edge.target]; return a && b ? <g key={`${edge.source}-${edge.target}-${index}`}><path d={`M ${a.x + (a.x < b.x ? 56 : -56)} ${a.y} L ${b.x + (a.x < b.x ? -56 : 56)} ${b.y}`} markerEnd={`url(#${candidate ? 'graph-arrow-candidate' : 'graph-arrow-baseline'})`} className="resource-edge"/><text x={(a.x+b.x)/2} y={(a.y+b.y)/2-5} textAnchor="middle">{edge.relation || 'references'}</text></g> : null; })}
        {nodes.map((node: any) => { const point = coords[node.id]; const selected = candidate && (node.id === (liveProjection?.successor || sableDetails.successor)); const name = String(node.id).split('.').pop() || node.id; return <g key={node.id} className={selected ? 'selected-successor' : ''}>
          <rect x={point.x-55} y={point.y-25} width="110" height="50" rx="9"/>
          <text x={point.x} y={point.y-3} className="resource-node-name">{name.length > 19 ? `${name.slice(0,17)}…` : name}</text>
          <text x={point.x} y={point.y+12} className="resource-node-type">{String(node.type).replace('aws_','').replaceAll('_',' ')}</text>
        </g>; })}
      </svg> : <div className="resource-graph-empty">Graph details aren’t available for this run.</div>}
    </div>;
  };

  return (
    <div className="workflow-module-container">
      <div className="cavr-header-row">
        <div>
          <div className="cavr-eyebrow">
            <span className="module-pulse-dot" /> AGENT SENTINEL GATEWAY · END-TO-END ASSURANCE AGGREGATOR
          </div>
          <h2 className="cavr-title">RUN WORKFLOW</h2>
          <p className="cavr-subtitle">
            Autonomous AI-change security assurance gate. Aggregates multi-boundary evidence from
            CAVR (package dependencies), SABLE (Terraform boundaries), and SATRA (security-test integrity)
            into one final trust decision: <strong>ACCEPT</strong>, <strong>REVIEW</strong>, or <strong>BLOCK</strong>.
          </p>
        </div>
      </div>

      <div className="workflow-top-controls">
        <div className="scenario-select-wrap">
          <label>Select Candidate AI-Change Scenario:</label>
          <select value={selectedScenario} onChange={(e) => setSelectedScenario(e.target.value)} disabled={loading}>
            {scenarios.map((s) => <option key={s.id} value={s.id}>{s.title} ({s.id})</option>)}
          </select>
        </div>
        <button className="run-scenario-btn" onClick={triggerRun} disabled={loading || Boolean(currentRun && !workflowFinished)}>
          {loading || currentRun && !workflowFinished ? <RefreshCw className="spin" size={16} /> : <Play size={16} />}
          <span>{loading ? 'Starting Workflow…' : currentRun && !workflowFinished ? 'Workflow Running…' : 'Execute Assurance Workflow'}</span>
        </button>
      </div>

      <section className="workflow-live-panel" aria-label="Live workflow execution" aria-live="polite">
        <div className="workflow-live-heading">
          <div><span className={'workflow-live-dot' + (currentRun && !workflowFinished ? ' running' : '')} />
            <strong>{loading ? 'OPENING RUN' : currentRun && !workflowFinished ? 'LIVE EXECUTION' : workflowFinished ? 'EXECUTION TRACE' : 'READY TO RUN'}</strong>
            <span className="workflow-live-caption">{loading ? 'Requesting a fresh candidate snapshot…' : 'Stages update from persisted backend events'}</span>
          </div>
          <span className="workflow-live-meta">{loading ? 'Waiting for backend response' : `${events.length} event${events.length === 1 ? '' : 's'} · ${currentRun?.run_id || 'Run a scenario to begin'}`}</span>
        </div>
        <div className="workflow-stage-track" role="tablist" aria-label="Workflow stages">
          {workflowStages.map((stage, index) => <React.Fragment key={stage.id}>
            <button role="tab" aria-selected={selectedWorkflowStage === stage.id} className={`workflow-stage-tab${stage.done ? ' done' : ''}${stage.active ? ' active' : ''}${selectedWorkflowStage === stage.id ? ' selected' : ''}`} onClick={() => setSelectedWorkflowStage(stage.id)}>
              <span className="workflow-stage-mark">{stage.done ? '✓' : index + 1}</span><strong>{stage.title}</strong><small>{stage.short}</small><em>{stage.result}</em>
            </button>
            {index < workflowStages.length - 1 && <span className={'workflow-stage-link' + (stage.done ? ' complete' : '') + (loading || currentRun && !workflowFinished ? ' flowing' : '')}><i/></span>}
          </React.Fragment>)}
        </div>
        <div className="workflow-stage-detail">
          <div className="stage-detail-label"><span>STAGE {workflowStages.findIndex((stage) => stage.id === activeWorkflowStage.id) + 1} / {workflowStages.length}</span><strong>{activeWorkflowStage.title}</strong><small>{activeWorkflowStage.short}</small></div>
          <div className="stage-detail-live"><span className={activeWorkflowStage.done ? 'stage-light done' : activeWorkflowStage.active ? 'stage-light active' : 'stage-light'}/><strong>{activeWorkflowStage.active ? 'In progress' : activeWorkflowStage.done ? 'Recorded' : 'Waiting'}</strong><p>{activeWorkflowStage.evidence}</p></div>
        </div>
        <div className={'workflow-visual-board' + (loading || currentRun && !workflowFinished ? ' running' : '') + (workflowFinished ? ' finished' : '')}>
          <div className={'visual-source' + (hasEvent('workspace.snapshot') ? ' complete' : '') + (loading ? ' loading' : '')}>
            <div className="visual-file-stack"><i/><i/><i/><b>TF</b></div>
            <strong>{loading ? 'Preparing' : 'Candidate'}</strong><small>{hasEvent('workspace.snapshot') ? `${lastEvent('workspace.snapshot').data?.files ?? '—'} files · fingerprinted` : loading ? 'Request sent to backend' : 'Workspace changes'}</small>
          </div>
          <div className="visual-bus"><i/><span>FROZEN INPUT</span><i/></div>
          <div className="visual-lanes">
            {['CAVR', 'SABLE', 'SATRA'].map((lane) => { const state = moduleRunState(lane); return <div className={`visual-lane ${lane.toLowerCase()} ${state.state}`} key={lane}>
              <span className="visual-lane-icon">{lane === 'CAVR' ? '⌘' : lane === 'SABLE' ? '▤' : '⬡'}</span><span className="visual-lane-copy"><strong>{lane}</strong><small>{lane === 'CAVR' ? 'Code + dependencies' : lane === 'SABLE' ? 'Terraform + IAM' : 'Security tests'}</small><em>{lane === 'CAVR' ? 'Static path · no sandbox run' : lane === 'SABLE' ? 'Resource + access comparison' : 'Test evidence follows run events'}</em></span><span className="visual-lane-state">{state.state === 'complete' ? state.detail : state.state === 'active' ? 'Analyzing…' : 'Queued'}</span>
            </div>; })}
          </div>
          <div className="visual-bus evidence-bus"><i/><span>BOUND EVIDENCE</span><i/></div>
          <div className={`visual-gate ${finalGateEvent ? String(finalGateEvent.data?.decision || 'review').toLowerCase() : ''}`}><span className="visual-gate-shape">{finalGateEvent?.data?.decision === 'ACCEPT' ? '✓' : finalGateEvent?.data?.decision === 'BLOCK' ? '×' : '◇'}</span><strong>{finalGateEvent?.data?.decision || 'GATE'}</strong><small>{finalGateEvent ? 'Shared decision' : 'Awaiting evidence'}</small></div>
          <div className={'visual-snapshot-strip' + (hasEvent('workspace.snapshot') ? ' captured' : '')}>
            <div className="snapshot-strip-title"><strong>{loading && !snapshotEventForFlow ? 'CAPTURING CANDIDATE' : 'SNAPSHOT CONTENTS'}</strong><small>{snapshotEventForFlow ? `${snapshotEventForFlow.data?.files ?? '—'} files · SHA-256 ${String(snapshotEventForFlow.data?.hash || '').slice(0, 18)}…` : loading ? 'Waiting for backend fingerprint' : 'File list appears from the run snapshot'}</small></div>
            <div className="snapshot-file-list">{snapshotFileNames.length ? snapshotFileNames.map((file) => <span className="snapshot-file-chip" key={file}><b>TF</b>{file}</span>) : <><span className="snapshot-file-placeholder"/><span className="snapshot-file-placeholder"/><span className="snapshot-file-placeholder"/></>}</div>
            {loading && !snapshotEventForFlow && <i className="snapshot-scan-beam"/>}
          </div>
          <small className="visual-board-note">Live visualization · station states follow this run’s recorded events</small>
        </div>
        <div className="workflow-proof-modules">
          <div className="workflow-module-scene cavr-scene"><div className="module-scene-head"><strong>CAVR · PACKAGE ASSURANCE</strong><span>{moduleStatus('CAVR')}</span></div><div className="package-chain">{cavrNodes.length ? cavrNodes.map((node: any, i: number) => <React.Fragment key={`${node.name}-${i}`}><div className="package-node"><b>{node.cache_hit ? '↻' : '⬡'}</b><strong>{node.name}</strong><small>{node.version}</small></div>{i < cavrNodes.length - 1 && <i className="package-link"/>}</React.Fragment>) : <div className="package-empty">Package evidence appears after CAVR completes.</div>}</div><small className="module-scene-foot">{lastEvent('cavr.cache_hit') ? `Verified cache hit · ${lastEvent('cavr.cache_hit').data?.package || 'package'}` : cavrEvidence ? 'Current snapshot package evidence recorded' : 'No current CAVR evidence'}</small></div>
          <div className="workflow-module-scene satra-scene"><div className="module-scene-head"><strong>SATRA · TEST COMPARISON</strong><span>{moduleStatus('SATRA')}</span></div><div className="satra-test-grid">{(satraTestEvents.length ? satraTestEvents.slice(0,4) : ['trusted_baseline','trusted_candidate','ordinary_candidate','trusted_counterfactual'].map((label) => ({data:{label,available:null}}))).map((event: any) => {const d=event.data || {}; const state=d.available === false ? 'unavailable' : d.available ? d.exit_code === 0 ? 'passed' : 'failed' : 'pending'; return <div className={`satra-test-cell ${state}`} key={d.label}><span>{state === 'passed' ? '✓' : state === 'failed' ? '×' : state === 'unavailable' ? '–' : '·'}</span><strong>{String(d.label || '').replaceAll('_',' ')}</strong><small>{state === 'unavailable' ? 'Not run' : state === 'pending' ? 'Awaiting run' : state === 'passed' ? 'Passed' : 'Failed'}</small></div>;})}</div><small className="module-scene-foot">{satraTestEvents.find((event) => event.data?.available === false)?.data?.reason || (satraTestEvents.length ? 'Statuses from SATRA test_result events' : 'Test availability and results appear from SATRA events')}</small></div>
        </div>
        <div className="workflow-live-modules">
          {['CAVR', 'SABLE', 'SATRA'].map((module) => {
            const state = moduleRunState(module);
            const description = module === 'CAVR' ? 'Dependency + code-boundary inspection' : module === 'SABLE' ? 'Terraform resource + IAM correspondence' : 'Isolated test comparison';
            const executionNote = module === 'CAVR' ? 'Static path · sandbox not invoked' : module === 'SATRA' ? 'Sandbox evidence shown when emitted' : 'No cloud resources created';
            return <div key={module} className={'workflow-live-module ' + state.state}>
              <span className="workflow-live-module-icon">{state.state === 'complete' ? '✓' : state.state === 'active' ? <span className="workflow-live-spinner" /> : '·'}</span>
              <span><strong>{module}</strong><small>{description}</small><small className="workflow-lane-state">{state.detail} · {executionNote}</small></span>
            </div>;
          })}
        </div>
        <div className="workflow-live-sable">
          <div className="workflow-live-sable-title"><Network size={15}/><strong>SABLE · live reasoning from analyzer events</strong></div>
          <div className="workflow-live-sable-steps">
            {sableLiveSteps.map((step, index) => <div key={step.label} className={'workflow-live-sable-step' + (step.done ? step.skipped ? ' skipped' : ' done' : '') + (index === sableLiveSteps.findIndex((item) => !item.done) && currentRun && !workflowFinished ? ' active' : '')}>
              <span>{step.done ? step.skipped ? '↷' : '✓' : index + 1}</span><strong>{step.label}</strong><small>{step.detail}</small>
            </div>)}
          </div>
        </div>
        <div className="workflow-live-deepdive">
          <div className="workflow-live-deepdive-head">
            <div><span>BOUNDARY REASONING · SABLE ENGINE</span><strong>Did the access boundary follow the asset?</strong></div>
            <span className={'workflow-live-verdict ' + (sableDecisionEvent?.data?.status || sableStatus).toLowerCase()}>{sableDecisionEvent?.data?.status || sableStatus}</span>
          </div>
          <div className="workflow-graph-comparison"><div className="graph-comparison-heading"><strong>RESOURCE CORRESPONDENCE</strong><span>{visualSuccessor}</span></div><div className="workflow-graph-pair">{renderResourceGraph(baselineGraph, 'Trusted baseline')}{renderResourceGraph(candidateGraph, 'Candidate configuration', true)}</div><div className="graph-comparison-note">Nodes and reference edges are drawn from persisted SABLE evidence. Dashed green outline marks the selected successor.</div></div>
          <div className="workflow-obligation-rail">
            <div><small>REGISTERED PRINCIPAL</small><code>{liveObligation.principal || 'Waiting for baseline'}</code></div><b>→</b>
            <div><small>PROTECTED ASSET</small><code>{liveObligation.protected_asset || 'Waiting for baseline'}</code></div><b>→</b>
            <div><small>REQUIRED ACTIONS</small><code>{(liveObligation.actions || []).join(' · ') || 'Waiting for baseline'}</code></div>
          </div>
          <div className="workflow-live-proof-grid">
            <div className="workflow-hypothesis-board">
              <div className="workflow-proof-heading">SUCCESSOR HYPOTHESES <span>{sableCandidates.length} SCORED</span></div>
              {topSuccessors.length ? topSuccessors.map((candidate) => {
                const best = Math.max(...topSuccessors.map((item) => item.data?.score || 0), 1);
                return <div className="workflow-hypothesis" key={candidate.data?.address}>
                  <div><code>{candidate.data?.address}</code><b>{candidate.data?.score}</b></div>
                  <span className="workflow-hypothesis-meter"><i style={{ width: `${Math.max(4, (candidate.data?.score || 0) / best * 100)}%` }}/></span>
                  <small>{(candidate.data?.signals || []).slice(0, 4).map((signal: any) => signal.signal).join(' · ')}</small>
                </div>;
              }) : <div className="workflow-proof-wait">Candidate resources and correspondence signals will appear as SABLE evaluates them.</div>}
            </div>
            <div className="workflow-authorization-board">
              <div className="workflow-proof-heading">AUTHORIZATION PROJECTION <span>{liveProjection ? liveProjection.holds ? 'OBLIGATION HOLDS' : liveProjection.known ? 'OBLIGATION FAILS' : 'UNKNOWN' : 'AWAITING MATCH'}</span></div>
              {liveProjection ? <>
                <div className="workflow-projected-target"><small>SELECTED SUCCESSOR</small><code>{liveProjection.successor || sableDetails.successor || 'Unresolved'}</code></div>
                <div className="workflow-action-compare"><div><small>EXPECTED ACTIONS</small><code>{(liveProjection.expected_actions || []).join(' · ') || '—'}</code></div><div><small>OBSERVED ACTIONS</small><code>{(liveProjection.actual_actions || []).join(' · ') || '—'}</code></div></div>
                <div className="workflow-projected-resource"><small>RESOURCE SCOPE</small><code>{liveProjection.expected_resource || 'Not established'}</code></div>
              </> : <div className="workflow-proof-wait">SABLE projects permissions only after a unique, evidence-supported successor is found.</div>}
            </div>
          </div>
          <div className="workflow-binding-rail">
            <span className={sableEvidence?.integrity_valid ? 'valid' : ''}>EVIDENCE INTEGRITY <b>{sableEvidence ? sableEvidence.integrity_valid ? 'VALID' : 'FAILED' : 'PENDING'}</b></span>
            <span className={sableEvidence?.candidate_snapshot === currentRun?.candidate_snapshot ? 'valid' : ''}>CANDIDATE SNAPSHOT <b>{sableEvidence ? sableEvidence.candidate_snapshot === currentRun?.candidate_snapshot ? 'MATCH' : 'MISMATCH' : 'PENDING'}</b></span>
            <span className={sableInputHashMatches ? 'valid' : ''}>INPUT BINDING <b>{sableInputHashMatches === null ? 'PENDING' : sableInputHashMatches ? 'MATCH' : 'MISMATCH'}</b></span>
            <code>{sableEvidence?.input_hash ? String(sableEvidence.input_hash).slice(0, 18) + '…' : 'Awaiting SABLE evidence envelope'}</code>
          </div>
        </div>
        <details className="workflow-event-ledger">
          <summary className="workflow-event-ledger-head"><strong>Run evidence timeline</strong><span>Open for backend event details</span><b>{events.length} EVENTS</b></summary>
          <div className="workflow-event-ledger-grid">
            {recentEvents.length ? recentEvents.map((event) => <div className="workflow-event-item" key={event.id}>
              <span className="workflow-event-seq">EVT {String(event.id).padStart(3, '0')}</span><i/>
              <div><strong>{eventHeadline(event)}</strong><small>{eventDetail(event)}</small></div>
            </div>) : <div className="workflow-proof-wait">Run a scenario to see persisted event details.</div>}
          </div>
        </details>
      </section>

      <div className={`workflow-decision-banner ${decision.toLowerCase()}`}>
        <div className="gate-icon-col">
          {isAccept ? <ShieldCheck size={48} className="text-good" /> : isBlock ? <XCircle size={48} className="text-bad" /> : <AlertTriangle size={48} className="text-warn" />}
        </div>
        <div className="gate-details-col">
          <span className="gate-tag">FINAL ASENT DECISION</span>
          <h3 className="gate-verdict">{decision}</h3>
          <p className="gate-reason">{currentRun?.reasons?.join(' · ') || 'No final-gate reasons recorded.'}</p>
        </div>
        <div className="gate-meta-col">
          <span>Run ID: <code>{currentRun?.run_id || 'No run selected'}</code></span>
          <span>Snapshot: <code>{currentRun?.candidate_snapshot?.slice(0, 16) || 'Unavailable'}...</code></span>
          {currentRun?.clean_commit && <span className="clean-commit-tag"><GitCommit size={12} /> Git Commit Reconstructed</span>}
        </div>
      </div>

      <details className="workflow-deep-evidence">
        <summary>Technical evidence · module outcomes · Terraform input</summary>
        <div className="workflow-deep-evidence-content">
      <div className="tri-boundary-grid">
        <div className="boundary-card">
          <div className="b-header">
            <span className="b-icon blue"><Package size={16} /></span><strong>CAVR GATE</strong>
            <span className={`badge ${moduleStatus('CAVR') === 'VERIFIED' ? 'good' : moduleStatus('CAVR') === 'REJECTED' || moduleStatus('CAVR') === 'REJECT' ? 'bad' : 'warn'}`}>{moduleStatus('CAVR')}</span>
          </div>
          <p>Locked package dependencies, AST static inspection &amp; hostile sandbox proof.</p>
          {moduleReason(evidenceFor('CAVR')) && <div className="b-meta">Module reason: {moduleReason(evidenceFor('CAVR'))}</div>}
        </div>

        <div className="boundary-card">
          <div className="b-header">
            <span className="b-icon green"><Network size={16} /></span><strong>SABLE GATE</strong>
            <span className={`badge ${!sableEvidence || !sableSnapshotIntegrityValid ? 'warn' : sableStatus === 'REGRESSED' ? 'bad' : sableStatus === 'PRESERVED' ? 'good' : 'warn'}`}>{sableBadge}</span>
          </div>
          <p>Shared evidence for local Terraform modules, S3 buckets, and inline IAM role policies.</p>
          <div className="b-meta">Status: {sableStatus} · {sableSnapshotIntegrityValid ? 'persisted evidence present; snapshot and integrity checks pass' : sableEvidence ? 'snapshot or integrity check failed' : 'awaiting shared evidence'}</div>
          {sableEvidence && <div className="b-meta">Snapshot: <code>{sableEvidence.candidate_snapshot}</code> · Input hash: <code>{sableEvidence.input_hash || 'unavailable'}</code></div>}
          {moduleReason(sableEvidence) && <div className="b-meta">Module reason: {moduleReason(sableEvidence)}</div>}
        </div>

        <div className="boundary-card">
          <div className="b-header">
            <span className="b-icon violet"><ShieldAlert size={16} /></span><strong>SATRA GATE</strong>
            <span className={`badge ${moduleStatus('SATRA') === 'REJECTED' || moduleStatus('SATRA') === 'REJECT' ? 'bad' : moduleStatus('SATRA') === 'VERIFIED' ? 'good' : 'warn'}`}>{moduleStatus('SATRA')}</span>
          </div>
          <p>Security-test integrity, mutation analysis &amp; runtime contract obligations.</p>
          {moduleReason(evidenceFor('SATRA')) && <div className="b-meta">Module reason: {moduleReason(evidenceFor('SATRA'))}</div>}
        </div>
      </div>

      <section className="boundary-card sable-trace" aria-label="Shared SABLE execution trace" style={{ marginTop: 18 }}>
        <div className="b-header">
          <span className="b-icon green"><Network size={16} /></span><strong>SHARED SABLE EXECUTION TRACE</strong>
          <span className={`badge ${!sableEvidence || !sableSnapshotIntegrityValid ? 'warn' : sableStatus === 'PRESERVED' ? 'good' : sableStatus === 'REGRESSED' ? 'bad' : 'warn'}`}>
            {sableEvidence ? `${sableStatus} · ${sableSnapshotIntegrityValid ? 'INTEGRITY VALID' : 'BINDING INVALID'}` : 'NO CURRENT EVIDENCE'}
          </span>
        </div>
        {!sableEvidence ? <p className="b-meta">No persisted SABLE evidence is available for the current run.</p> : <>
          <ol className="sable-trace-list" style={{ display: 'grid', gap: 10, paddingLeft: 24, margin: '18px 0' }}>
            <li style={{ display: 'grid', gridTemplateColumns: '190px minmax(0, 1fr)', gap: 12 }}><strong>Baseline verification</strong><span>{baselineLabel}</span></li>
            <li style={{ display: 'grid', gridTemplateColumns: '190px minmax(0, 1fr)', gap: 12 }}><strong>Terraform parsing</strong><span>{parseErrors.length
              ? `${parseErrors.length} parser issue(s): ${parseErrors.join('; ')}`
              : baselineGraph && candidateGraph
                ? `Evidence contains ${nodeCount(baselineGraph) ?? 'unknown'} baseline and ${nodeCount(candidateGraph) ?? 'unknown'} candidate graph node(s); no parse errors recorded`
                : 'Parse graph details are unavailable in this evidence'}</span></li>
            <li style={{ display: 'grid', gridTemplateColumns: '190px minmax(0, 1fr)', gap: 12 }}><strong>Correspondence / successor</strong><span>{sableDetails.successor
              ? `Selected successor: ${sableDetails.successor}${hypotheses.length ? ` (${hypotheses.length} recorded hypotheses)` : ''}`
              : sableDetails.correspondence_reason || (hypotheses.length ? `No successor selected from ${hypotheses.length} hypotheses` : 'Successor result unavailable in evidence')}</span></li>
            <li style={{ display: 'grid', gridTemplateColumns: '190px minmax(0, 1fr)', gap: 12 }}><strong>Obligation projection</strong><span>{projection
              ? `${projection.known ? 'Known' : 'Unknown'}${projection.holds ? ' · obligation holds' : projection.known ? ' · obligation does not hold' : ''}${projection.reason ? ` · ${projection.reason}` : ''}`
              : 'Projection details unavailable; no successful projection is inferred'}</span></li>
            <li style={{ display: 'grid', gridTemplateColumns: '190px minmax(0, 1fr)', gap: 12 }}><strong>Authorization evaluation</strong><span>{Array.isArray(projection?.unknown) && projection.unknown.length
              ? projection.unknown.join('; ')
              : projection
                ? `${Array.isArray(projection.grants) ? projection.grants.length : 0} policy grant record(s); ${projection.holds ? 'obligation holds' : 'obligation does not hold'}`
                : moduleReason(sableEvidence) || 'Authorization detail unavailable in evidence'}</span></li>
          </ol>
          <div className="b-meta"><strong>Evidence binding:</strong> {sableEvidence.integrity_valid ? 'integrity is valid' : 'integrity check failed'} · {sableEvidence.candidate_snapshot === currentRun?.candidate_snapshot ? 'snapshot matches this run' : 'snapshot does not match this run'} · {sableInputHashMatches === null ? 'input hash comparison unavailable' : sableInputHashMatches ? 'input hash matches the shared SABLE start event' : 'input hash does not match the shared SABLE start event'} · input hash <code style={{ overflowWrap: 'anywhere' }}>{sableEvidence.input_hash || 'unavailable'}</code></div>
          {Array.isArray(projection?.grants) && projection.grants.length > 0 && <div className="sable-grants">
            <strong>Parsed inline policy records</strong>
            {projection.grants.map((grant: any, index: number) => <div className="b-meta" key={`${grant.policy || 'policy'}-${index}`}>
              <code>{grant.policy || 'policy identifier unavailable'}</code>: {grant.effect || 'effect unavailable'} · actions <code>{Array.isArray(grant.actions) ? grant.actions.join(', ') : 'unavailable'}</code> · resources <code>{Array.isArray(grant.resources) ? grant.resources.join(', ') : 'unavailable'}</code>
            </div>)}
          </div>}
          {terraformDiff ? <details className="sable-input-details" style={{ marginTop: 16 }}>
            <summary>Terraform input excerpt from this run’s shared snapshot event</summary>
            <pre style={{ maxHeight: 420, overflow: 'auto', whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontSize: 12, lineHeight: 1.5, padding: 12, background: '#f5f7fa', borderRadius: 6 }}>{terraformDiff}</pre>
          </details> : <div className="b-meta">Terraform diff is unavailable in this run’s shared event stream.</div>}
        </>}
      </section>

      <section className="boundary-card module-outcomes" aria-label="Persisted module outcomes">
        <strong>MODULE OUTCOMES · CURRENT SNAPSHOT</strong>
        <div className="module-outcome-grid">
          {['CAVR', 'SATRA', 'SABLE'].map((module) => {
            const evidence = evidenceFor(module);
            return <div key={module}><strong>{module}: {evidence?.status || 'NO CURRENT EVIDENCE'}</strong>
              {moduleReason(evidence) && <div className="b-meta">{moduleReason(evidence)}</div>}
            </div>;
          })}
        </div>
        <div className="b-meta"><strong>Overall final gate:</strong> {decision} · {currentRun?.reasons?.join(' · ') || 'No final-gate reasons recorded'}</div>
      </section>
        </div>
      </details>
    </div>
  );
};
