import React from 'react';
import { Check, ChevronDown, ChevronUp } from 'lucide-react';
import { StageSummary, shown } from './types';

interface ExpandableStepProps {
  stepIndex: number;
  // The stage as the backend summarised it, or null when no run has finished yet.
  stage: StageSummary | null;
  title: string;
  isExpanded: boolean;
  onToggleExpand: () => void;
}

// One stage of the timeline. It shows only what the backend returned for the stage: whether it ran,
// and the values it computed. A value that was not computed is printed as a dash. There is no time
// per stage, because the pipeline measures one time for the whole request (fast_gate_ms).
export const ExpandableStep: React.FC<ExpandableStepProps> = ({ stepIndex, stage, title, isExpanded, onToggleExpand }) => {
  const values = stage ? stage.values : [];
  const headline = values.length > 0 ? values[0] : null;

  return (
    <div className={`timeline-node-item ${stage && stage.ran ? 'completed-step' : ''}`}>
      <div className="node-click-area" onClick={onToggleExpand}>
        <div className="node-marker">
          {stage && stage.ran ? <Check size={12} /> : <span>{stepIndex + 1}</span>}
        </div>
        <strong className="node-title">{title}</strong>
        <span className="node-desc">
          {stage === null ? shown(null) : (stage.ran ? `${headline?.label}: ${shown(headline?.value)}` : 'did not run')}
        </span>
      </div>

      <button
        className="substages-toggle-btn"
        onClick={(e) => {
          e.stopPropagation();
          onToggleExpand();
        }}
        title="Show the values this stage returned"
      >
        <span>{values.length} values</span>
        {isExpanded ? <ChevronUp size={11} /> : <ChevronDown size={11} />}
      </button>

      {isExpanded && (
        <div className="substages-dropdown-panel" onClick={(e) => e.stopPropagation()}>
          <div className="dropdown-header">
            <span>{title}</span>
            <button className="dropdown-close" onClick={onToggleExpand}>✕</button>
          </div>
          <div className="substages-list">
            {values.length === 0 && (
              <div className="substage-row pending">
                <div className="substage-text">
                  <p className="substage-desc">No run has finished yet.</p>
                </div>
              </div>
            )}
            {values.map((item) => (
              <div key={item.label} className={`substage-row ${item.value === null ? 'pending' : 'done'}`}>
                <div className="substage-text">
                  <div className="substage-title-line">
                    <span className="substage-phase-tag">{item.label}</span>
                    <strong style={{ wordBreak: 'break-all' }}>{shown(item.value)}</strong>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
