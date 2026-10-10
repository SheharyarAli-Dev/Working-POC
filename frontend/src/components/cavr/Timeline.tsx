import React, { useEffect, useState } from 'react';
import { ExpandableStep } from './ExpandableStep';
import { StageSummary } from './types';

// The timeline before any run has finished: the stage names only, in pipeline order.
// After a run the titles and everything else come from the `stages` of the proof.
export const STAGE_NAMES = [
  'Request (C1)', 'Requirement gate (C2)', 'Artifact, tree and advisories (C3)',
  'Verdict cache lookup', 'Contract, AST scan and sinks (C4)', 'Verdict'
];

interface TimelineProps {
  // `stages` of GET /api/cavr/proof/{run_id}; null until a run has finished.
  stages: StageSummary[] | null;
  runId: string | null;
}

// The six stages of the fast gate in pipeline order. Before a run has finished every stage shows a dash.
export const Timeline: React.FC<TimelineProps> = ({ stages, runId }) => {
  const [expanded, setExpanded] = useState<number | null>(null);

  // A new run closes the open stage, so its values cannot be read as values of the new run.
  useEffect(() => setExpanded(null), [runId]);

  return (
    <div className="timeline-horizontal-wrapper">
      <div className="timeline-track-line" />
      <div className="timeline-nodes-row">
        {STAGE_NAMES.map((name, idx) => {
          const stage = stages ? stages[idx] || null : null;
          return (
            <ExpandableStep
              key={idx}
              stepIndex={idx}
              stage={stage}
              title={stage ? stage.title : name}
              isExpanded={expanded === idx}
              onToggleExpand={() => setExpanded(expanded === idx ? null : idx)}
            />
          );
        })}
      </div>
    </div>
  );
};
