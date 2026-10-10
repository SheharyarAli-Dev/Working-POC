import React from 'react';
import { CavrRunState, NOT_COMPUTED, shown } from './types';
import { ShieldCheck } from 'lucide-react';

interface RequirementsTabProps {
  state: CavrRunState;
}

// The last column is what the backend returned for the stage that would prove the requirement,
// or a dash when that stage did not run. The page gives no PASS or FAIL of its own.
export const RequirementsTab: React.FC<RequirementsTabProps> = ({ state }) => {
  const { gateResult, actionData, counterfactualResults, causalGraph, repair, reverification, reconstruction, certificate } = state;
  const v = state.proofData?.cavr_verdict;
  const captureSource = v?.request?.source;

  const requirements: { id: string; name: string; desc: string; module: string; event: string; returned: unknown }[] = [
    {
      id: "FR-1",
      name: "Intercept Before Execution",
      desc: "Capture the pip install request and verify it before anything is installed or executed.",
      module: "capture.py / pip_shim.py / api.py",
      event: "P1 Capture",
      returned: captureSource ? `captured (${captureSource})` : null
    },
    {
      id: "FR-2",
      name: "Requirement Gate Enforcement",
      desc: "Check the request against project_policy.json: denylist, exact pin, approved requirements, lockfile. Fails closed.",
      module: "requirement_gate.py",
      event: "P2 RequirementGate",
      returned: gateResult ? `${gateResult.result} (${gateResult.matched_rule})` : null
    },
    {
      id: "FR-3",
      name: "Capability Contract Inference",
      desc: "Derive allowed and denied capabilities from the project's real imports and call sites and the policy.",
      module: "capability_contract.py",
      event: "P4 ContractInference",
      returned: actionData?.capability_contract?.rule
    },
    {
      id: "FR-4",
      name: "Adaptive Counterfactual Activation",
      desc: "Explore dormant behaviors by synthesizing safe environment conditions (fake env vars, files, time shims) within budget. Deep analysis (M2).",
      module: "counterfactual.py",
      event: "P7 CounterfactualRuns",
      returned: counterfactualResults?.stop_reason
    },
    {
      id: "FR-5",
      name: "Causal Capability Graph",
      desc: "Construct NetworkX directed graph tracking source-to-sink paths from canary secrets to external network sinks. Deep analysis (M2).",
      module: "causal_graph.py",
      event: "P9 CausalGraph",
      returned: causalGraph ? `${(causalGraph.nodes || []).length} nodes` : null
    },
    {
      id: "FR-6",
      name: "Fail-Closed Security Policy",
      desc: "VERIFIED / REJECTED / UNRESOLVED / BLOCK with evidence. Anything unknown is UNRESOLVED.",
      module: "pipeline.py",
      event: "Verdict",
      returned: v ? `${v.status} (${v.stage} / ${v.rule})` : null
    },
    {
      id: "FR-7",
      name: "Minimal Safe Repair",
      desc: "Search candidates across 4 repair levels minimizing disruption objective w1*deps + w2*dist + w3*calls + w4*risk. Deep analysis (M2).",
      module: "repair_engine.py",
      event: "P10 MinimalRepair",
      returned: repair?.chosen_candidate?.name
    },
    {
      id: "FR-8",
      name: "Re-Verification Suite",
      desc: "Re-execute sample project tests and security obligations for chosen repair candidate inside fresh container. Deep analysis (M2).",
      module: "reverifier.py",
      event: "P11 Reverification",
      returned: reverification ? `all_passed: ${reverification.all_passed}` : null
    },
    {
      id: "FR-9",
      name: "Clean Reconstruction",
      desc: "Rebuild accepted dependency set in fresh environment from baseline plus pinned hashes. Discard analysis sandbox. Deep analysis (M2).",
      module: "reconstructor.py",
      event: "P12 CleanReconstruction",
      returned: reconstruction?.status
    },
    {
      id: "FR-10",
      name: "Tamper-Evident Evidence Ledger",
      desc: "Hash-chain every transition record and provide independent cryptographic re-verification endpoint.",
      module: "assurance.py",
      event: "P13 AssuranceEvidence",
      returned: certificate?.certificate_id
    },
    {
      id: "NFR-1",
      name: "Non-Root Isolation",
      desc: "Hardened sandbox: UID 10001, cap-drop ALL, no-new-privileges, read-only rootfs, 30s timeout. Deep analysis (M2).",
      module: "sandbox_runner.py",
      event: "SandboxLockdown",
      returned: counterfactualResults?.stop_reason
    },
    {
      id: "NFR-2",
      name: "Deterministic & No Paid LLM",
      desc: "Purely deterministic AST, NetworkX, and formal repair solver. Zero reliance on paid black-box LLM APIs.",
      module: "inspector.py / triggers.py",
      event: "Design property (not checked by a run)",
      returned: null
    }
  ];

  return (
    <div className="evidence-tab-pane requirements-pane">
      {/* Scope and Specification Box */}
      <div className="spec-card">
        <div className="spec-header">
          <ShieldCheck size={18} className="text-cyan-400" />
          <h4>CAVR Research Specification &amp; Threat Model</h4>
        </div>

        <p className="scope-sentence">
          <strong>Scope:</strong> Continuous Artifact Verification and Runtime (CAVR) intercepts, isolates, dynamically activates, 
          and formally evaluates third-party Python packages for AI coding agents before deployment.
        </p>

        <div className="scope-two-col">
          <div className="scope-box">
            <h6>In-Scope Defenses:</h6>
            <ul>
              <li>Supply chain typosquatting &amp; homoglyphs</li>
              <li>Staged base64 payloads &amp; backdoor scripts</li>
              <li>Dormant Trojan exfiltration gated behind env triggers</li>
              <li>Transitive dependencies pulling unauthorized network sockets</li>
              <li>Known vulnerabilities listed by OSV for the exact version (asked on every run)</li>
            </ul>
          </div>

          <div className="scope-box">
            <h6>Explicit Assumptions &amp; Boundaries:</h6>
            <ul>
              <li>Container isolation belongs to deep analysis (M2); the fast gate runs no package code</li>
              <li>Deterministic capability contract derived from project call sites</li>
              <li>No paid or ungrounded generative LLM in verification loop</li>
              <li>Unreached predicates honestly declared as residual uncertainty</li>
            </ul>
          </div>
        </div>
      </div>

      {/* Traceability Table */}
      <div className="traceability-card">
        <h5>Requirements Traceability Matrix</h5>
        <div className="traceability-table-wrap">
          <table className="trace-table">
            <thead>
              <tr>
                <th style={{ width: '10%' }}>Req ID</th>
                <th style={{ width: '24%' }}>Requirement</th>
                <th style={{ width: '24%' }}>Module Reference</th>
                <th style={{ width: '24%' }}>Proving Event</th>
                <th style={{ width: '18%' }}>Returned by this run</th>
              </tr>
            </thead>
            <tbody>
              {requirements.map((r) => (
                <tr key={r.id}>
                  <td><code>{r.id}</code></td>
                  <td>
                    <strong>{r.name}</strong>
                    <div className="req-sub-desc">{r.desc}</div>
                  </td>
                  <td><code>{r.module}</code></td>
                  <td><span className="event-tag">{r.event}</span></td>
                  <td>
                    <span className={`req-status ${shown(r.returned) === NOT_COMPUTED ? 'pending' : 'na'}`}>{shown(r.returned)}</span>
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
