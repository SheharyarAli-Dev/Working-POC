import React from 'react';
import { History } from 'lucide-react';

// One row of GET /api/cavr/recorded-runs: a real gate run of an M2 demo wheel in the CAVR sandbox, recorded once.
export interface RecordedRun {
  id: string;
  display_name: string;
  what: string | null;
  policy: string | null;
  expected_status: string | null;
  decision: string | null;
  exit_code: number | null;
  recorded_at: string | null;
  image_id: string | null;
  label: string | null;
}

interface RecordedChipsProps {
  runs: RecordedRun[] | null;
  failed: boolean;
  current: string | null;
  disabled: boolean;
  onReplay: (run: RecordedRun) => void;
}

// The recorded M2 runs. A click replays the recorded result (no Docker, no network); it is labelled "recorded"
// everywhere it is shown. The list and its names are the backend's.
export const RecordedChips: React.FC<RecordedChipsProps> = ({ runs, failed, current, disabled, onReplay }) => (
  <div className="scenario-chips-wrapper recorded-chips">
    <span className="scenario-chips-label">Recorded M2 runs (replayed from a real sandbox run, no Docker needed):</span>
    <div className="scenario-chips-group">
      {runs === null && (
        <span className="scenario-chips-label">
          {failed ? 'The recorded runs could not be loaded from the backend.' : 'Loading recorded runs...'}
        </span>
      )}
      {runs !== null && runs.length === 0 && <span className="scenario-chips-label">No recorded run is available.</span>}
      {(runs || []).map((run) => (
        <button
          key={run.id}
          className={`scenario-chip recorded ${current === `recorded:${run.id}` ? 'active' : ''}`}
          onClick={() => onReplay(run)}
          disabled={disabled}
          title={`Recorded ${run.recorded_at ?? ''}. ${run.what ?? ''}. Policy: ${run.policy ?? ''}. Gate: ${run.decision ?? ''}.`}
        >
          <History size={12} />
          <span>{run.display_name}</span>
        </button>
      ))}
    </div>
  </div>
);
