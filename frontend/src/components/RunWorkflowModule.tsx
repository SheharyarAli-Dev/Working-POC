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
    }, 1500);
  };

  const currentEvidence = moduleEvidence.filter((e) =>
    !e.stale && e.candidate_snapshot === currentRun?.candidate_snapshot
  );
  const evidenceFor = (module: string) => [...currentEvidence].reverse().find((e) => e.analyzer === module);
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
    sableStatus === 'PRESERVED' || sableStatus === 'NOT_APPLICABLE' ? `${sableStatus} -> ACCEPTABLE` :
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
        <button className="run-scenario-btn" onClick={triggerRun} disabled={loading}>
          {loading ? <RefreshCw className="spin" size={16} /> : <Play size={16} />}
          <span>{loading ? 'Evaluating Boundaries...' : 'Execute Assurance Workflow'}</span>
        </button>
      </div>

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
            <span className={`badge ${!sableEvidence || !sableSnapshotIntegrityValid ? 'warn' : sableStatus === 'REGRESSED' ? 'bad' : sableStatus === 'PRESERVED' || sableStatus === 'NOT_APPLICABLE' ? 'good' : 'warn'}`}>{sableBadge}</span>
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
  );
};
