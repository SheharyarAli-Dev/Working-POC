import React from 'react';
import { CavrRunState, NOT_COMPUTED, shown } from './types';
import { ShieldCheck } from 'lucide-react';
import { SafeText, cut } from './SafeText';
import { packageViews } from './DeepAnalysisTab';

interface RequirementsTabProps {
  state: CavrRunState;
}

// The design document's name of CAVR (CAVR_Revised_Research_Design_and_Architecture_FINAL, §1.1).
export const CAVR_NAME = 'Counterfactual Activation, Verified Repair & Recovery';

// One row of the matrix. `modules` are files of backend/cavr/ (or a path from the repository root, ending in "/" for a
// directory); `tests` are files of tests/. A requirement that is not built says so in `missing` and names neither.
export interface Requirement {
  id: string;
  name: string;
  desc: string;
  modules: string[];
  tests: string[];
  missing?: string;
  event: string;
}

export const REQUIREMENTS: Requirement[] = [
  { id: 'FR-1', name: 'Intercept before execution', event: 'P1 Capture',
    desc: 'Capture the pip install request or requirements edit and verify it before anything is installed or run.',
    modules: ['capture.py', 'manifest_parser.py', 'pip_shim.py', 'api.py'],
    tests: ['test_cavr_capture.py', 'test_cavr_manifest.py', 'test_cavr_pip_shim.py'] },
  { id: 'FR-2', name: 'Requirement gate enforcement', event: 'P2 RequirementGate',
    desc: 'Check the request against the project policy: denylist, exact pins, approved requirements, lockfile. Fails closed.',
    modules: ['requirement_gate.py'], tests: ['test_cavr_requirement_gate.py'] },
  { id: 'FR-3', name: 'Capability contract inference', event: 'P3/P4 action_completed',
    desc: "The capabilities the project's real imports and call sites need, against the policy; AST scan and sink reachability.",
    modules: ['context_extractor.py', 'capability_contract.py', 'ast_scan.py', 'reachability.py'],
    tests: ['test_cavr_contract.py', 'test_cavr_ast_scan.py', 'test_cavr_reachability.py'] },
  { id: 'FR-4', name: 'Adaptive counterfactual activation', event: 'P7 deep_completed',
    desc: 'A canary-only run, then one sandbox run per trigger activation (environment, clock, files, host, argv) and the project\'s literal call sites driven, within 8 runs / 20 s / 120 s.',
    modules: ['activation_loop.py', 'env_synthesis.py', 'sandbox_spec.py', 'call_drive.py', 'sandbox_deep.py'],
    tests: ['test_cavr_activation_loop.py', 'test_cavr_env_synthesis.py', 'test_cavr_sandbox_spec.py', 'test_cavr_call_drive.py', 'test_cavr_m2_wheels.py'] },
  { id: 'FR-5', name: 'Causal capability graph', event: 'P9 deep_completed (causal)',
    desc: 'Graph of the real runs: trigger or call site -> run -> event -> contract rule -> verdict, "caused" only for the counterfactual difference.',
    modules: ['causal_graph.py', 'dashboard_view.py'], tests: ['test_cavr_causal_graph.py', 'test_cavr_recorded_runs.py'] },
  { id: 'FR-6', name: 'Fail-closed security policy', event: 'Verdict',
    desc: 'VERIFIED / REJECTED / UNRESOLVED / BLOCK with evidence, fast gate and deep stage. Anything unknown is UNRESOLVED.',
    modules: ['pipeline.py', 'deep_stage.py', 'sandbox_deep.py'],
    tests: ['test_cavr_pipeline.py', 'test_cavr_deep_stage.py', 'test_cavr_sandbox_deep.py'] },
  { id: 'FR-7', name: 'Minimal safe repair', event: 'Verdict (repair)',
    desc: 'For an advisory or hash rejection: the nearest newer release that is not yanked, has a wheel and is not OSV-affected, or a removal. A proposal for a person; never applied.',
    modules: ['repair_proposal.py'], tests: ['test_cavr_repair.py', 'test_cavr_repair_edges.py', 'test_cavr_repair_surfaces.py'] },
  { id: 'FR-8', name: 'Re-verification', event: 'Verdict (repair re-check)',
    desc: 'Each candidate goes through the fast gate again on a copy of the project with the patched requirements, lockfile and policy. Sandbox and project tests: not done (PR 16).',
    modules: ['repair_proposal.py'], tests: ['test_cavr_repair.py'] },
  { id: 'FR-9', name: 'Clean reconstruction', event: 'P12 (not built)',
    desc: 'Rebuild the accepted set in a fresh environment from the trusted baseline and the verified hashes.',
    modules: [], tests: [], missing: 'not implemented (PR 17, future work)' },
  { id: 'FR-10', name: 'Tamper-evident evidence', event: 'P13 AssuranceFinalized',
    desc: 'Every event of a run is hash-chained; each record hash covers every field (ts and substep too, hash version 2); certificate per run.',
    modules: ['assurance.py'], tests: ['test_cavr_assurance.py', 'test_cavr_api.py'] },
  { id: 'FR-11', name: 'Exact artifact, tree and known-risk resolution', event: 'P5 package_resolved',
    desc: 'Real SHA-256 of the downloaded wheel against the registry digest, the transitive tree from Requires-Dist, OSV with real version ranges.',
    modules: ['pypi_client.py', 'wheel_meta.py', 'dep_tree.py', 'advisories.py'],
    tests: ['test_cavr_pypi_client.py', 'test_cavr_wheel_meta.py', 'test_cavr_dep_tree.py', 'test_cavr_advisories.py'] },
  { id: 'FR-12', name: 'Trigger discovery and priority', event: 'P6 deep_completed (frontier)',
    desc: 'The frontier: conditions in front of a sink (environment, clock, file, host, user, argv, platform), how to activate each, risk and order.',
    modules: ['trigger_frontier.py'], tests: ['test_cavr_trigger_frontier.py'] },
  { id: 'FR-13', name: 'OS observation and event normalisation', event: 'P8 deep_completed (events)',
    desc: 'strace of each run, normalised into events (file, network, process, canary) and judged against the contract.',
    modules: ['sandbox_trace.py', 'sandbox_events.py', 'contract_check.py'],
    tests: ['test_cavr_sandbox_trace.py', 'test_cavr_sandbox_events.py', 'test_cavr_contract_check.py', 'test_cavr_canary_events.py'] },
  { id: 'FR-14', name: 'RESTRICTED verdict and its enforcement', event: '(not built)',
    desc: 'A verdict that allows the package under a generated restriction.',
    modules: [], tests: [], missing: 'not implemented (PR 14; enforcement is future work)' },
  { id: 'FR-15', name: 'CAVR verdict in every gate run', event: 'asent gate',
    desc: 'The gate and the orchestrator get their CAVR verdict from the same verification path.',
    modules: ['gate_adapter.py', 'analyzer.py'], tests: ['test_cavr_gate_adapter.py', 'test_gate_cavr_verdicts.py'] },
  { id: 'NFR-1', name: 'Package code never runs as root; isolated sandbox', event: 'P7 deep_completed (runs)',
    desc: 'asent-cavr-sandbox: no network, read-only root, package code as UID 10001 with no capability, a fresh container per run, removed afterwards.',
    modules: ['sandbox_exec.py', 'sandbox_image.py', 'sandbox_observe.py', 'docker/cavr-sandbox/'],
    tests: ['test_cavr_sandbox_exec.py', 'test_cavr_sandbox_image.py', 'test_cavr_sandbox_observe.py'] },
  { id: 'NFR-2', name: 'Deterministic, no paid LLM / API', event: 'Design property',
    desc: 'AST, rules and a hash-chained record; no LLM or paid API in the verification path.',
    modules: ['pipeline.py'], tests: [], missing: 'no test yet (PR 20)' },
  { id: 'NFR-3', name: 'Privacy', event: 'Design property',
    desc: 'Only the package name and version leave the machine (PyPI, OSV); the evidence stays local.',
    modules: ['pypi_client.py', 'advisories.py'], tests: [], missing: 'no test yet (PR 20)' },
  { id: 'NFR-4', name: 'Efficiency', event: 'Verdict',
    desc: 'p50 / p95 of fast_gate_ms per status and cache lookup, cache hit rates, deep time and runs per package.',
    modules: ['pipeline.py', 'sandbox_deep.py'], tests: ['test_cavr_pipeline.py', 'test_cavr_sandbox_deep.py'] },
  { id: 'NFR-5', name: 'Canary-only secrets', event: 'P7 deep_completed (canaries)',
    desc: 'Fresh random fake secrets in every run, kept only by id; no real credential or host environment enters a run.',
    modules: ['env_synthesis.py', 'sandbox_events.py'], tests: ['test_cavr_env_synthesis.py', 'test_cavr_canary_events.py'] },
  { id: 'NFR-6', name: 'Bounded claim', event: 'Certificate / deep evidence',
    desc: 'Every verdict states what was and was not verified: the certificate claim, the deep claim and the conditions not exercised.',
    modules: ['assurance.py', 'gate_adapter.py', 'sandbox_deep.py'], tests: ['test_cavr_api.py', 'test_cavr_sandbox_deep.py'] },
];

// What this run returned for each requirement, or null (printed as the dash). The page gives no PASS or FAIL of its own.
export const returnedValues = (state: CavrRunState): Record<string, unknown> => {
  const { gateResult, actionData, repair, reconstruction, certificate, recorded } = state;
  const v = state.proofData?.cavr_verdict;
  const views = packageViews(state) || [];
  const first = views[0];
  const deep = views.find((view: any) => view?.deep)?.deep;
  const runs: any[] = Array.isArray(deep?.runs) ? deep.runs : [];
  const fast = (id: string) => (first?.fast || []).find((stage: any) => stage.id === id)?.rule;
  const resolved = first && (fast('artifact') || fast('tree') || fast('advisories'))
    ? `${shown(fast('artifact'))} / ${shown(fast('tree'))} / ${shown(fast('advisories'))}` : null;
  return {
    'FR-1': v?.request?.source ? `captured (${v.request.source})` : null,
    'FR-2': gateResult ? `${gateResult.result} (${gateResult.matched_rule})` : null,
    'FR-3': actionData?.capability_contract?.rule,
    'FR-4': deep ? `${runs.length} run(s), stop: ${shown(deep.budget?.stop)}` : null,
    'FR-5': deep ? (deep.causal?.digest_checked
      ? `${shown(deep.causal?.counts?.nodes)} nodes, ${shown(deep.causal?.counts?.edges)} edges; ${deep.causal?.cause ?? 'no cause named'}`
      : 'graph not available') : null,
    'FR-6': v ? `${v.status} (${v.stage} / ${v.rule})` : null,
    'FR-7': repair ? `${repair.result}${repair.pin ? `: ${repair.pin.requirement}` : ''}` : null,
    'FR-8': repair?.pin?.recheck ? `${repair.pin.recheck.status} (${repair.pin.recheck.rule})` : null,
    'FR-9': reconstruction?.status,
    'FR-10': certificate?.certificate_id,
    'FR-11': resolved,
    'FR-12': deep ? `${shown(deep.frontier?.rule)}: ${shown(deep.frontier?.total)} trigger(s)` : null,
    'FR-13': deep && runs.length ? runs.map((run: any) => `run ${shown(run.n)} ${shown(run.judged)}`).join(', ') : null,
    'FR-14': null,
    'FR-15': recorded ? `asent gate ${shown(recorded.decision)} (exit ${shown(recorded.exit_code)}), recorded` : null,
    'NFR-1': deep ? `image ${cut(deep.image_id, 19)}; ${runs.length} run(s), HOME removed after each: ${runs.every((run: any) => run.home_removed === true)}` : null,
    'NFR-2': null,
    'NFR-3': null,
    'NFR-4': v && v.fast_gate_ms !== null && v.fast_gate_ms !== undefined
      ? `fast_gate_ms ${v.fast_gate_ms}${deep ? `; deep ${shown(deep.elapsed_seconds)} s` : ''}` : null,
    'NFR-5': runs.length ? `${runs.map((run: any) => (Array.isArray(run.canaries) ? run.canaries.length : 0)).join(', ')} canary id(s) per run` : null,
    'NFR-6': deep ? `${(deep.not_exercised || []).length} condition(s) not exercised` : certificate?.bounded_trust_claim,
  };
};

export const RequirementsTab: React.FC<RequirementsTabProps> = ({ state }) => {
  const returned = returnedValues(state);
  return (
    <div className="evidence-tab-pane requirements-pane">
      <div className="spec-card">
        <div className="spec-header">
          <ShieldCheck size={18} className="text-cyan-400" />
          <h4>CAVR: {CAVR_NAME}</h4>
        </div>

        <p className="scope-sentence">
          <strong>Scope:</strong> CAVR ({CAVR_NAME}) checks each Python package an AI coding agent asks for before it is
          installed. The fast gate checks the request, the exact artifact, its tree and known advisories, and the project's
          capability contract without running package code; an escalated package goes to the deep analysis, which runs it
          in the CAVR sandbox under counterfactual conditions and builds a causal graph of what it did. A rejected package
          gets a repair proposal for a person to approve.
        </p>

        <div className="scope-two-col">
          <div className="scope-box">
            <h6>Done in M2:</h6>
            <ul>
              <li>Known vulnerabilities from OSV for the exact version, asked on every run</li>
              <li>A downloaded file that differs from the registry digest</li>
              <li>Dormant behaviour behind environment, clock, file, hostname or argv triggers</li>
              <li>Canary secrets read or sent at import or from a project call site</li>
              <li>Unexplored, unsimulable or over-budget triggers reported as UNRESOLVED</li>
            </ul>
          </div>

          <div className="scope-box">
            <h6>Not done (future work):</h6>
            <ul>
              <li>Clean reconstruction (FR-9) and the RESTRICTED verdict (FR-14)</li>
              <li>npm, eBPF observation, Tree-sitter parsing, Sigstore provenance</li>
              <li>Repair by replacing a package with another (level 4); enforcing a restriction</li>
              <li>Sandbox and project tests on a repair candidate (PR 16)</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="traceability-card">
        <h5>Requirements Traceability Matrix</h5>
        <div className="traceability-table-wrap">
          <table className="trace-table">
            <thead>
              <tr>
                <th style={{ width: '8%' }}>Req ID</th>
                <th style={{ width: '24%' }}>Requirement</th>
                <th style={{ width: '18%' }}>Module (backend/cavr/)</th>
                <th style={{ width: '18%' }}>Tests (tests/)</th>
                <th style={{ width: '14%' }}>Proving event</th>
                <th style={{ width: '18%' }}>Returned by this run</th>
              </tr>
            </thead>
            <tbody>
              {REQUIREMENTS.map((r) => (
                <tr key={r.id}>
                  <td><code>{r.id}</code></td>
                  <td>
                    <strong>{r.name}</strong>
                    <div className="req-sub-desc">{r.desc}</div>
                  </td>
                  <td><code>{r.modules.length ? r.modules.join(' / ') : r.missing}</code></td>
                  <td><code>{r.tests.length ? r.tests.join(', ') : r.missing}</code></td>
                  <td><span className="event-tag">{r.event}</span></td>
                  <td>
                    <span className={`req-status ${shown(returned[r.id]) === NOT_COMPUTED ? 'pending' : 'na'}`}><SafeText value={returned[r.id]} /></span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
