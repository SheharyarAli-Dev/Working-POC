import React from 'react';
import { SableRunState } from '../types';
import { CheckCircle2, XCircle, AlertTriangle, Shield } from 'lucide-react';

interface Props { runState: SableRunState; explainSimply: boolean; }

export const VerificationTab: React.FC<Props> = ({ runState, explainSimply }) => {
  const { toolResults, unsupportedConstructs, candidateAuth } = runState;

  return (
    <div className="sable-tab-content">
      <div className="sable-card-label">TOOL INVENTORY</div>
      {Object.keys(toolResults).length === 0 ? (
        <div className="sable-tab-empty" style={{ minHeight: 100 }}>
          <Shield size={24} strokeWidth={1.2}/>
          <p>Run a scenario to see tool verification results.</p>
        </div>
      ) : (
        <div className="sable-tools-list">
          {Object.entries(toolResults).map(([tool, result]) => {
            const r = result as any;
            const isReal = r.real_tool === true;
            const avail = r.available;
            return (
              <div key={tool} className="sable-tool-card">
                <div className="sable-tool-header">
                  <strong>{tool.replace(/_/g, ' ')}</strong>
                  {isReal
                    ? <span className="sable-badge sable-badge-real"><CheckCircle2 size={11}/> Real tool</span>
                    : <span className="sable-badge sable-badge-approx"><AlertTriangle size={11}/> Built-in approximation, not the real tool</span>}
                </div>
                <div className="sable-tool-body">
                  {avail ? (
                    <>
                      <div className="sable-kv">
                        <span>Exit code</span>
                        <code style={{ color: r.exit_code === 0 ? '#16a34a' : '#dc2626' }}>{r.exit_code}</code>
                      </div>
                      <div className="sable-kv"><span>Claim</span><span>{r.claim}</span></div>
                      {r.stdout && (
                        <pre className="sable-tool-output">{r.stdout.slice(0, 800)}</pre>
                      )}
                    </>
                  ) : (
                    <div className="sable-kv"><span>Reason</span><span className="sable-text-muted">{r.reason}</span></div>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* Unsupported constructs */}
      {(unsupportedConstructs.length > 0 || (candidateAuth?.outside_model?.length ?? 0) > 0) && (
        <div className="sable-verif-unsupported">
          <div className="sable-card-label">UNSUPPORTED CONSTRUCTS</div>
          <p className="sable-small-note">These constructs were found but are outside the supported IAM/S3 model. They push the decision toward UNKNOWN.</p>
          <ul>
            {[...unsupportedConstructs, ...(candidateAuth?.outside_model ?? [])].map((c, i) => (
              <li key={i}><AlertTriangle size={12} color="#d97706"/> <code>{c}</code></li>
            ))}
          </ul>
        </div>
      )}

      {explainSimply && (
        <div className="sable-explain-box">
          <strong>In plain English:</strong> This tab reports whether optional local tools ran and their results.
          If a tool is unavailable, it did not run. SABLE&apos;s separate bounded IAM/S3 authorization analysis
          still determines the verdict; that analysis is not a substitute Terraform or Checkov scan.
        </div>
      )}
    </div>
  );
};
