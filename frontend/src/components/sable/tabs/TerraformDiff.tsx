import React, { useState } from 'react';
import { SableRunState, TerraformFileEntry, terraformFileMap } from '../types';
import { AlertTriangle, GitCompare, Edit3, Play, RefreshCw, Check } from 'lucide-react';

interface Props {
  runState: SableRunState;
  explainSimply: boolean;
  onRerunCustom?: (candidateTf: Record<string, string>) => void;
}

export const TerraformDiffTab: React.FC<Props> = ({ runState, explainSimply, onRerunCustom }) => {
  const [editMode, setEditMode] = useState(false);
  const [customFiles, setCustomFiles] = useState<TerraformFileEntry[]>([]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [editorError, setEditorError] = useState<string | null>(null);

  if (!runState.diff && runState.diffLines.length === 0) {
    return (
      <div className="sable-tab-empty">
        <GitCompare size={32} strokeWidth={1.2}/>
        <p>Run a scenario to see the Terraform diff.</p>
      </div>
    );
  }

  const lines = runState.diffLines.length > 0 ? runState.diffLines : (runState.diff ?? '').split('\n');

  const handleRunAgain = async () => {
    if (!onRerunCustom) return;
    const parsed = terraformFileMap(customFiles);
    if (parsed.error || !parsed.files) {
      setEditorError(parsed.error ?? 'Enter the complete candidate Terraform bundle.');
      return;
    }
    setEditorError(null);
    setIsSubmitting(true);
    try {
      await onRerunCustom(parsed.files);
      setEditMode(false);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <div className="sable-tab-content">
      <div className="sable-diff-header-row">
        <div>
          <strong style={{ fontSize: '1rem', color: '#0f172a' }}>Terraform Diff</strong>
          <span className="sable-diff-subtitle">Baseline vs. Candidate — unified diff</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div className="sable-diff-hashes">
            <span>Baseline SHA: <code>{runState.baselineSha?.slice(0, 12) ?? '–'}…</code></span>
            <span>Candidate SHA: <code>{runState.candidateSha?.slice(0, 12) ?? '–'}…</code></span>
          </div>
          {runState.scenarioId !== 'custom_upload' && <button
            className={`sable-btn ${editMode ? 'sable-btn-primary' : 'sable-btn-secondary'}`}
            style={{ fontSize: '0.75rem', padding: '5px 10px' }}
            onClick={() => {
              setEditorError(null);
              if (!editMode) setCustomFiles(runState.candidateFiles.map(path => ({ path, content: '' })));
              setEditMode(m => !m);
            }}
          >
            <Edit3 size={12}/> {editMode ? 'Hide Editor' : 'Replace Candidate Bundle'}
          </button>}
        </div>
      </div>

      {runState.scenarioId === 'custom_upload' && (
        <div className="sable-small-note" style={{ marginBottom: 12 }}>
          This run used a custom baseline. To change it, use <strong>Upload bundle</strong> and submit both complete file maps; the diff stream does not return source contents for editing.
        </div>
      )}

      {runState.unsupportedConstructs?.length > 0 && (
        <div className="sable-diff-warn">
          <AlertTriangle size={13}/>
          <strong>Unsupported constructs detected:</strong>{' '}
          {runState.unsupportedConstructs.join('; ')}
        </div>
      )}

      {/* The standalone event stream exposes a diff and filenames, not complete source. */}
      {editMode && (
        <div style={{ background: '#ffffff', border: '1px solid #cbd5e1', borderRadius: '8px', padding: '14px', marginBottom: '1rem', boxShadow: '0 2px 4px rgba(0,0,0,0.04)' }}>
          <div style={{ marginBottom: 12 }}>
            <strong style={{ fontSize: '0.85rem', color: '#1e293b' }}>Complete Candidate File Map</strong>
            <span className="sable-small-note" style={{ display: 'block' }}>
              Paste the complete candidate contents below. Submitting replaces the whole candidate file map and keeps this scenario's baseline. The diff above is not editable source.
            </span>
          </div>
          {customFiles.map((file, index) => (
            <div key={`${index}-${file.path}`} style={{ marginBottom: 12 }}>
              <div style={{ display: 'flex', gap: 8, marginBottom: 5 }}>
                <label style={{ flex: 1, fontSize: 12 }}>Relative .tf path
                  <input value={file.path} onChange={e => setCustomFiles(current => current.map((item, i) => i === index ? { ...item, path: e.target.value } : item))} style={{ display: 'block', width: '100%' }} />
                </label>
                {customFiles.length > 1 && <button type="button" className="sable-btn sable-btn-secondary" onClick={() => setCustomFiles(current => current.filter((_, i) => i !== index))}>Remove file</button>}
              </div>
              <textarea value={file.content} onChange={e => setCustomFiles(current => current.map((item, i) => i === index ? { ...item, content: e.target.value } : item))} placeholder={`Paste the complete contents of ${file.path || 'this Terraform file'}`} style={{ width: '100%', height: 180, fontFamily: 'monospace', fontSize: '0.8rem', padding: 10, border: '1px solid #cbd5e1', borderRadius: 4, background: '#f8fafc', color: '#0f172a', resize: 'vertical' }} />
            </div>
          ))}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 10 }}>
            <button type="button" className="sable-btn sable-btn-secondary" onClick={() => setCustomFiles(current => [...current, { path: '', content: '' }])}>Add Terraform file</button>
            <button className="sable-btn sable-btn-primary" onClick={handleRunAgain} disabled={isSubmitting || customFiles.length === 0 || customFiles.some(file => !file.content.trim())}>
              {isSubmitting ? <><RefreshCw size={13} className="spin"/> Running...</> : <><Play size={13}/> Run again</>}
            </button>
          </div>
          {editorError && <div role="alert" className="sable-diff-warn" style={{ marginTop: 10 }}>{editorError}</div>}
        </div>
      )}

      {/* Diff View */}
      <div className="sable-diff-container">
        <div className="sable-diff-pane">
          <div className="sable-diff-pane-header">Baseline</div>
          <pre className="sable-diff-code">
            {lines
              .filter(l => !l.startsWith('+') || l.startsWith('+++'))
              .map((l, i) => (
                <div key={i} className={`sable-diff-line ${l.startsWith('-') ? 'removed' : l.startsWith('@@') ? 'hunk' : ''}`}>
                  {l}
                </div>
              ))}
          </pre>
        </div>
        <div className="sable-diff-pane">
          <div className="sable-diff-pane-header">Candidate</div>
          <pre className="sable-diff-code">
            {lines
              .filter(l => !l.startsWith('-') || l.startsWith('---'))
              .map((l, i) => (
                <div key={i} className={`sable-diff-line ${l.startsWith('+') ? 'added' : l.startsWith('@@') ? 'hunk' : ''}`}>
                  {l}
                </div>
              ))}
          </pre>
        </div>
      </div>

      {/* Moved blocks */}
      {runState.baselineGraph && (runState.candidateGraph as any)?.moves?.length > 0 && (
        <div className="sable-diff-moves">
          <strong>Explicit moved blocks:</strong>
          {((runState.candidateGraph as any)?.moves ?? []).map((m: any, i: number) => (
            <div key={i} className="sable-move-badge">
              <code>{m.from}</code> → <code>{m.to}</code>
            </div>
          ))}
        </div>
      )}

      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong> The highlighted lines show what changed in the Terraform.
          Green lines were added, red lines were removed. SABLE checks whether these changes affect
          who can access the protected bucket.
        </div>
      )}
    </div>
  );
};
