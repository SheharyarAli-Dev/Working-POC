import React from 'react';
import { History } from 'lucide-react';
import { SafeText, cut } from './SafeText';
import { shown } from './types';

// Shown on every view of a replayed run: the result is a recorded real run (backend/cavr/recorded/m2-demo-runs.json),
// shown again, not run now. `recorded` is the block the backend writes into every event and the proof.
export const RecordedBanner: React.FC<{ recorded: any | null }> = ({ recorded }) => {
  if (!recorded) return null;
  return (
    <div className="recorded-banner" role="note"
      style={{ border: '1px solid #d97706', background: '#fffbeb', color: '#92400e', borderRadius: 8, padding: '8px 12px', margin: '8px 0' }}>
      <strong><History size={13} style={{ verticalAlign: 'middle' }} /> RECORDED RUN</strong>{' '}
      <span>
        <SafeText value={recorded.id} /> · recorded {shown(recorded.recorded_at)} on image{' '}
        <code>{cut(recorded.image_id, 19)}</code> (commit <code>{cut(recorded.commit, 12)}</code>)
        · gate decision <SafeText value={recorded.decision} /> (exit {shown(recorded.exit_code)}) · replayed: nothing is run now.
      </span>
      {(recorded.index || recorded.advisories) && (
        <div className="recorded-inputs" style={{ fontSize: 12, marginTop: 4 }}>
          Fast-gate inputs of the recorded run (not PyPI, not live OSV): <SafeText value={recorded.index} limit={400} />;{' '}
          <SafeText value={recorded.advisories} limit={400} />. The sandbox runs are real.
        </div>
      )}
    </div>
  );
};
