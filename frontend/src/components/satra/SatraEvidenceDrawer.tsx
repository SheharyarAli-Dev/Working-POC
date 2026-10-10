import React from 'react';

interface SatraEvidenceDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  evidenceData: any;
  proofData: any;
}

export const SatraEvidenceDrawer: React.FC<SatraEvidenceDrawerProps> = ({
  isOpen,
  onClose,
  evidenceData,
  proofData
}) => {
  if (!isOpen) return null;

  return (
    <div className="fixed inset-y-0 right-0 w-full max-w-xl bg-slate-950 border-l border-slate-800 shadow-2xl z-50 flex flex-col">
      <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-900">
        <div>
          <h2 className="text-sm font-bold text-slate-100">Assurance Evidence & Proof Drawer</h2>
          <p className="text-xs text-slate-400">Cryptographically verifiable proof bundle</p>
        </div>
        <button
          onClick={onClose}
          className="text-slate-400 hover:text-slate-200 text-lg px-2 py-1 rounded"
        >
          ✕
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
        {proofData && (
          <div className="space-y-2">
            <h3 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">Hardened Container Command</h3>
            <pre className="p-2.5 bg-slate-900 border border-slate-800 rounded font-mono text-[11px] text-blue-400 overflow-x-auto whitespace-pre-wrap">
              {proofData.docker_command || 'docker run --rm --network none --read-only asent-sandbox-app'}
            </pre>
          </div>
        )}

        {proofData?.image_digest && (
          <div className="space-y-1">
            <h3 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">Container Image Digest</h3>
            <div className="p-2 bg-slate-900 border border-slate-800 rounded font-mono text-[11px] text-slate-300 break-all">
              {proofData.image_digest}
            </div>
          </div>
        )}

        <div className="space-y-2">
          <h3 className="font-semibold text-slate-300 uppercase tracking-wider text-[11px]">Full Evidence JSON</h3>
          <pre className="p-3 bg-slate-900 border border-slate-800 rounded font-mono text-[11px] text-slate-300 max-h-96 overflow-y-auto overflow-x-auto">
            {JSON.stringify(evidenceData || proofData?.evidence_json || {}, null, 2)}
          </pre>
        </div>
      </div>

      <div className="p-3 border-t border-slate-800 bg-slate-900 flex justify-end">
        <button
          onClick={onClose}
          className="px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-medium"
        >
          Close Drawer
        </button>
      </div>
    </div>
  );
};
