import React from 'react';
import { Play } from 'lucide-react';
import { Scenario } from './types';

interface ScenarioChipsProps {
  // The answer of GET /api/cavr/scenarios; null until the backend has answered.
  scenarios: Scenario[] | null;
  failed: boolean;
  current: string | null;
  disabled: boolean;
  onRun: (scenario: Scenario) => void;
}

// One chip per scenario of the backend's list. The label, the request and the description are the
// backend's; the page holds no package name of its own. A click runs the scenario through the real pipeline.
export const ScenarioChips: React.FC<ScenarioChipsProps> = ({ scenarios, failed, current, disabled, onRun }) => (
  <div className="scenario-chips-wrapper">
    <span className="scenario-chips-label">Real requests (live pipeline):</span>
    <div className="scenario-chips-group">
      {scenarios === null && (
        <span className="scenario-chips-label">
          {failed ? 'The scenario list could not be loaded from the backend.' : 'Loading scenarios...'}
        </span>
      )}
      {(scenarios || []).map((scenario) => (
        <button
          key={scenario.id}
          className={`scenario-chip ${current === scenario.id ? 'active' : ''}`}
          onClick={() => onRun(scenario)}
          disabled={disabled}
          title={`${scenario.request}. Expected: ${scenario.expected_status}. ${scenario.description}`}
        >
          <Play size={12} />
          <span>{scenario.display_name}</span>
        </button>
      ))}
    </div>
  </div>
);
