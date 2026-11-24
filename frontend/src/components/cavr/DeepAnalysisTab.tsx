import React from 'react';
import { CavrRunState, shown } from './types';
import { SafeText, addressText, asText, cut } from './SafeText';
import { RecordedBanner } from './RecordedBanner';

interface DeepAnalysisTabProps {
  state: CavrRunState;
}

// The per-package views of the run (backend/cavr/dashboard_view.py): from the proof when it has arrived, else from
// the deep_completed event. Null before any run.
export const packageViews = (state: CavrRunState): any[] | null =>
  state.proofData?.packages ?? state.deepPackages ?? null;

// Section headings of a package card (the pane's own h6 style is too small next to its tables).
const HEADING: React.CSSProperties = { fontSize: 13, fontWeight: 700, margin: '16px 0 6px' };

const list = (value: unknown): any[] => (Array.isArray(value) ? value : []);
const place = (item: any): string => `${asText(item?.file)}:${asText(item?.line)}`;

// For each package: the fast-gate stages with their rules, then the deep block or why there is none. Every value is
// the backend's; event text is untrusted and only ever printed through SafeText.
export const DeepAnalysisTab: React.FC<DeepAnalysisTabProps> = ({ state }) => {
  const views = packageViews(state);
  return (
    <div className="evidence-tab-pane deep-pane">
      <RecordedBanner recorded={state.recorded} />
      {!views && (
        <div className="tab-intro-card">
          <div>
            <h5>Deep analysis</h5>
            <p>{shown(null)} (no run has finished yet)</p>
          </div>
        </div>
      )}
      {views && views.length === 0 && (
        <div className="tab-intro-card"><div><h5>Deep analysis</h5><p>No package was checked in this run.</p></div></div>
      )}
      {(views || []).map((view, index) => <PackageView key={index} view={view} recorded={state.recorded} />)}
    </div>
  );
};

// The fast-gate stages whose input a recorded run did not get from PyPI or live OSV (see the recording's header).
const RECORDED_INPUT: Record<string, string> = { artifact: 'local test index', tree: 'local test index', advisories: 'seeded, OSV not asked' };

const PackageView: React.FC<{ view: any; recorded: any | null }> = ({ view, recorded }) => (
  <div className="reverification-card deep-package">
    <h5>
      <SafeText value={view.package} /> <SafeText value={view.version} />: <strong>{shown(view.status)}</strong>{' '}
      (<SafeText value={view.stage} /> / <SafeText value={view.rule} />)
    </h5>
    <p className="deep-reason"><SafeText value={view.reason} limit={400} /></p>

    <h6 style={HEADING}>Fast gate</h6>
    {recorded && <p className="recorded-fast-note">Recorded run: the artifact and tree came from a local test index and the advisories from a seeded cache (see the banner); they were not observed on PyPI or OSV.</p>}
    <table className="trace-table deep-fast-table">
      <thead><tr><th>Stage</th><th>Rule</th><th>Reason</th></tr></thead>
      <tbody>
        {list(view.fast).map((stage, index) => (
          <tr key={index}>
            <td>{shown(stage.title)}</td>
            <td><code><SafeText value={stage.rule} /></code>
              {recorded && Object.hasOwn(RECORDED_INPUT, stage.id) ? ` (${RECORDED_INPUT[stage.id]})` : ''}
              {stage.id === 'advisories' && stage.affected !== null && stage.affected !== undefined ? ` (${stage.affected} affect it)` : ''}</td>
            <td><SafeText value={stage.reason} /></td>
          </tr>
        ))}
      </tbody>
    </table>

    {view.deep ? <DeepBlock deep={view.deep} /> : (
      <p className="deep-not-run"><strong>Deep analysis:</strong> <SafeText value={view.deep_not_run} /></p>
    )}
  </div>
);

const DeepBlock: React.FC<{ deep: any }> = ({ deep }) => {
  const runs = list(deep.runs);
  const triggers = list(deep.triggers);
  const unsimulable = triggers.filter((trigger) => trigger.simulable === false);
  const driven = list(deep.drives?.driven);
  const notDriven = list(deep.drives?.not_driven);
  const guards = list(deep.other_guards);
  const unexplored = list(deep.unexplored_guards);
  const keyEvents = list(deep.key_events);
  const leaks = list(deep.leaks);
  const budget = deep.budget || {};
  return (
    <div className="deep-block">
      <h6 style={HEADING}>Deep analysis (CAVR sandbox)</h6>
      <div className="proof-kv">
        <div><span>Final rule:</span> <strong>{shown(deep.status)}</strong> <code><SafeText value={deep.rule} /></code></div>
        <div><span>Reason:</span> <SafeText value={deep.reason} limit={400} /></div>
        <div><span>Image:</span> <code><SafeText value={deep.image_id} /></code></div>
        <div><span>Deep time (s):</span> <code>{shown(deep.elapsed_seconds)}</code></div>
        <div><span>Budget used:</span> {shown(budget.runs)} of {shown(budget.runs_limit)} runs, {shown(budget.seconds)} s of{' '}
          {shown(budget.package_seconds)} s (planned runs: {shown(budget.planned_runs)})</div>
        <div><span>Loop stop:</span> <code>{shown(budget.stop)}</code> <SafeText value={budget.stop_reason} /></div>
      </div>

      <h6 style={HEADING}>Runs ({runs.length})</h6>
      <table className="trace-table deep-runs-table">
        <thead><tr><th>Run</th><th>Kind</th><th>Spec</th><th>Activation</th><th>Status</th><th>Contract check</th><th>Seconds</th><th>New events</th><th>Canaries planted</th></tr></thead>
        <tbody>
          {runs.map((run, index) => (
            <tr key={index}>
              <td>{shown(run.n)}</td>
              <td><SafeText value={run.kind} /></td>
              <td><code><SafeText value={run.spec_id} /></code></td>
              <td><SafeText value={run.activation ?? 'no trigger (canary-only)'} /></td>
              <td><code><SafeText value={run.rule} /></code> {run.completed ? 'completed' : 'not completed'}</td>
              <td><code><SafeText value={run.judged} /></code> <SafeText value={run.judged_rule} /></td>
              <td>{shown(run.elapsed_seconds)}</td>
              <td>{shown(run.new_events)}</td>
              <td>{list(run.canaries).length} <SafeText value={list(run.canaries).join(', ')} limit={60} /></td>
            </tr>
          ))}
        </tbody>
      </table>

      <h6 style={HEADING}>Frontier: <code><SafeText value={deep.frontier?.rule} /></code> ({shown(deep.frontier?.total)} trigger(s))</h6>
      <p><SafeText value={deep.frontier?.reason} /></p>
      {triggers.length === 0 ? <p>No trigger in front of a sink.</p> : (
        <table className="trace-table deep-frontier-table">
          <thead><tr><th>Where</th><th>Condition</th><th>Risk</th><th>Explored</th><th>Run</th><th>Activation</th><th>Outcome</th></tr></thead>
          <tbody>
            {triggers.map((trigger, index) => (
              <tr key={index}>
                <td><code><SafeText value={place(trigger)} /></code></td>
                <td><code><SafeText value={trigger.predicate} /></code></td>
                <td>{shown(trigger.risk)}</td>
                <td>{trigger.outcome === 'explored' ? 'explored' : 'not explored'}</td>
                <td>{shown(trigger.run)}</td>
                <td><SafeText value={trigger.activation} /></td>
                <td><SafeText value={trigger.outcome} limit={240} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      {unsimulable.length > 0 && (
        <div className="deep-unsimulable">
          <strong>Unsimulable ({unsimulable.length}):</strong>
          <ul>{unsimulable.map((trigger, index) => (
            <li key={index}><code><SafeText value={trigger.predicate} /></code>: <SafeText value={trigger.outcome} limit={300} /></li>
          ))}</ul>
        </div>
      )}

      <h6 style={HEADING}>Call sites driven ({driven.length})</h6>
      <ul className="deep-drives">
        {driven.map((drive, index) => (
          <li key={index}><code><SafeText value={drive.call} /></code> at <code><SafeText value={place(drive)} /></code> (step <SafeText value={drive.step} />)</li>
        ))}
        {notDriven.map((drive, index) => (
          <li key={`not-${index}`}>not driven: <code><SafeText value={drive.call ?? drive.expression} /></code> at{' '}
            <code><SafeText value={place(drive)} /></code>: <SafeText value={drive.why} /></li>
        ))}
        {driven.length === 0 && notDriven.length === 0 && <li>No call site of the project reaches the package.</li>}
      </ul>

      <h6 style={HEADING}>Other guards (conditions CAVR cannot evaluate): {shown(deep.frontier?.other_guards_count)}</h6>
      {guards.length > 0 && (
        <ul className="deep-guards">
          {guards.map((guard, index) => (
            <li key={index}><code><SafeText value={place(guard)} /></code> <code><SafeText value={guard.predicate} /></code>{' '}
              ({shown(guard.risk)} risk) gates <SafeText value={list(guard.capabilities).join(', ')} /></li>
          ))}
        </ul>
      )}
      {unexplored.length > 0 && (
        <p className="deep-unexplored"><strong>Unexplored ({unexplored.length}):</strong>{' '}
          {unexplored.map((guard, index) => (
            <span key={index}><code><SafeText value={place(guard)} /></code> not shown: <SafeText value={list(guard.not_shown).join(', ')} />. </span>
          ))}
        </p>
      )}

      {deep.residual && (
        <p className="deep-residual"><strong>Residual:</strong> <code><SafeText value={deep.residual.rule} /></code>{' '}
          <SafeText value={deep.residual.reason} limit={300} /></p>
      )}

      <h6 style={HEADING}>Key events ({keyEvents.length})</h6>
      <ul className="deep-key-events">
        {keyEvents.map((event, index) => (
          <li key={index}>
            run {shown(event.run)} ({shown(event.run_kind)}), step <SafeText value={event.step} />:{' '}
            <code><SafeText value={event.type} /></code> <SafeText value={event.syscall} />{' '}
            <code><SafeText value={event.path ?? addressText(event.address)} /></code>
            {event.argv ? <> argv <code><SafeText value={event.argv} /></code></> : null}{' '}
            = {event.ok ? 'ok' : <SafeText value={event.errno} />} (<SafeText value={event.rule} />: <SafeText value={event.why} />)
          </li>
        ))}
      </ul>

      <h6 style={HEADING}>Canary evidence</h6>
      <p>Canaries planted: every run got fresh random fake secrets; only their ids are kept (see the Runs table).</p>
      {leaks.length === 0 ? (
        <p>{deep.causal?.digest_checked ? 'No canary leak in any run (every violating event is in the graph).'
          : 'No canary leak among the key events of the decisive run; the graph is not available, so the other runs are not covered here.'}</p>
      ) : (
        <ul className="deep-leaks">
          {leaks.map((leak, index) => (
            <li key={index}>
              Leak caught: run {shown(leak.run)}, step <SafeText value={leak.step} />, <SafeText value={leak.syscall} /> to{' '}
              <code><SafeText value={addressText(leak.address)} /></code> (trace line {shown(leak.line)}):{' '}
              <SafeText value={leak.why ?? 'canary id not named in the key events'} />
            </li>
          ))}
        </ul>
      )}

      <h6 style={HEADING}>Causal graph</h6>
      <p>
        Cause: <SafeText value={deep.causal?.cause ?? 'none named'} />. Digest <code>{cut(deep.causal?.digest, 16)}</code>{' '}
        ({deep.causal?.digest_checked ? 'the graph matches its recorded digest: a consistency check, not proof against editing'
          : 'the graph is not available or does not match its digest'}).
      </p>
      <p className="deep-claim">What this claims: <SafeText value={deep.claim} limit={300} /></p>
    </div>
  );
};
