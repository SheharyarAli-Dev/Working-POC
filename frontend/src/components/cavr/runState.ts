import { CavrRunState } from './types';

// The state of the page with no result in it: before the first run, and at the start of each run.
export const EMPTY_RUN: CavrRunState = {
  runId: null,
  stepIndex: 0,
  request: null,
  package: '',
  version: '',
  scenarioKey: '',
  explainSimply: false,
  verdict: null,
  policyState: null,
  honestyWording: null,
  currentStateMessage: 'No run yet. Choose one of the requests.',
  currentPlainMessage: 'No run yet. Choose one of the requests.',
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
  proofData: null
};

// Copy what one event of the stream says into the run state. Nothing is added to it.
export const applyEvent = (prev: CavrRunState, ev: any): CavrRunState => {
  const { type, step_index, payload } = ev;
  const updated = { ...prev };

  if (step_index !== undefined) {
    updated.stepIndex = step_index;
  }
  if (payload.message) {
    updated.currentStateMessage = payload.message;
  }
  if (payload.plain_explanation) {
    updated.currentPlainMessage = payload.plain_explanation;
  }

  if (type === 'state_change') {
    if (payload.verdict) updated.verdict = payload.verdict;
    if (payload.policy_state) updated.policyState = payload.policy_state;
    if (payload.honesty_wording) updated.honestyWording = payload.honesty_wording;
    if (payload.certificate) updated.certificate = payload.certificate;
    if (payload.reconstruction) updated.reconstruction = payload.reconstruction;
  } else if (type === 'requirement_gate_evaluated') {
    updated.gateResult = payload;
  } else if (type === 'package_resolved') {
    updated.resolution = payload.resolution;
  } else if (type === 'cache_result') {
    updated.cacheResult = payload;
  } else if (type === 'action_completed') {
    updated.actionData = payload;
  } else if (type === 'counterfactual_completed') {
    updated.counterfactualResults = payload.counterfactual_results;
  } else if (type === 'verdict_computed') {
    updated.verdict = payload.verdict;
    updated.policyState = payload.policy_state;
    updated.honestyWording = payload.honesty_wording;
    updated.causalGraph = payload.causal_graph;
    updated.violatingPaths = payload.violating_paths;
    updated.repair = payload.repair;
    updated.reverification = payload.reverification;
  }
  return updated;
};
