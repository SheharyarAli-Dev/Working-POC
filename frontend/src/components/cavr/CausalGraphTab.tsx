import React, { useState } from 'react';
import { CavrRunState, NOT_RUN_ON_FAST_GATE } from './types';
import { GitBranch, Shield, Filter, Info, AlertTriangle, CheckCircle } from 'lucide-react';

interface CausalGraphTabProps {
  state: CavrRunState;
}

export const CausalGraphTab: React.FC<CausalGraphTabProps> = ({ state }) => {
  const [filterViolationsOnly, setFilterViolationsOnly] = useState(false);
  const [showConditions, setShowConditions] = useState(true);
  const [showDependencies, setShowDependencies] = useState(true);
  const [selectedElement, setSelectedElement] = useState<any | null>(null);

  if (!state.causalGraph) {
    // No invented graph: the causal graph is built from observed runs, and none happen on the fast gate.
    return (
      <div className="evidence-tab-pane causal-pane">
        <div className="tab-intro-card">
          <div>
            <h5>Causal Capability Graph</h5>
            <p>{NOT_RUN_ON_FAST_GATE}</p>
          </div>
        </div>
      </div>
    );
  }
  const causal = state.causalGraph;

  const violatingPaths = state.violatingPaths || [];
  const hasViolations = violatingPaths.length > 0;

  // Filter nodes & edges
  let nodes = causal.nodes || [];
  let edges = causal.edges || [];

  if (filterViolationsOnly) {
    nodes = nodes.filter((n: any) => n.is_violating);
    const validIds = new Set(nodes.map((n: any) => n.id));
    edges = edges.filter((e: any) => validIds.has(e.source) && validIds.has(e.target));
  } else {
    if (!showConditions) {
      nodes = nodes.filter((n: any) => n.kind !== 'environment predicate');
    }
    if (!showDependencies) {
      // A dependency is a package node other than the package that was asked for.
      nodes = nodes.filter((n: any) => n.kind !== 'package' || String(n.id).includes(state.package));
    }
    const validIds = new Set(nodes.map((n: any) => n.id));
    edges = edges.filter((e: any) => validIds.has(e.source) && validIds.has(e.target));
  }

  // Assign deterministic 2D coordinates for rendering
  const layoutNodes = nodes.map((node: any, idx: number) => {
    let x = 120 + (idx % 3) * 260;
    let y = 100 + Math.floor(idx / 3) * 160;

    if (node.kind === 'environment predicate') {
      x = 100;
      y = 80 + (idx * 90);
    } else if (node.kind === 'package') {
      x = 360;
      y = 120 + (idx * 110);
    } else if (node.kind === 'secret/canary') {
      x = 480;
      y = 280;
    } else if (node.kind === 'endpoint') {
      x = 680;
      y = 240;
    } else if (node.kind === 'module/function') {
      x = 360;
      y = 220;
    }

    return { ...node, x, y };
  });

  const nodeMap = new Map<string, any>(layoutNodes.map((n: any) => [n.id, n]));

  return (
    <div className="evidence-tab-pane causal-pane">
      {/* Top Controls & Filters */}
      <div className="causal-topbar">
        <div>
          <h5>Causal Capability Graph (NetworkX Evidence Model)</h5>
          <p>
            {hasViolations 
              ? "Critical: Prohibited source-to-sink causal path identified (Canary Secret -> Network Endpoint)."
              : "No prohibited path found in explored conditions."}
          </p>
        </div>

        {/* Filter Controls */}
        <div className="graph-filters">
          <button 
            className={`filter-btn ${filterViolationsOnly ? 'active' : ''}`}
            onClick={() => setFilterViolationsOnly(!filterViolationsOnly)}
          >
            <Filter size={12} /> Violations Only
          </button>

          <button 
            className={`filter-btn ${showConditions ? 'active' : ''}`}
            onClick={() => setShowConditions(!showConditions)}
          >
            Conditions
          </button>

          <button 
            className={`filter-btn ${showDependencies ? 'active' : ''}`}
            onClick={() => setShowDependencies(!showDependencies)}
          >
            Dependencies
          </button>
        </div>
      </div>

      {/* SVG Canvas Area */}
      <div className="svg-canvas-container">
        <svg className="causal-svg" viewBox="0 0 840 460">
          <defs>
            <marker id="arrow" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
            </marker>
            <marker id="arrow-violating" viewBox="0 0 10 10" refX="22" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#ef4444" />
            </marker>
          </defs>

          {/* Edges */}
          {edges.map((edge: any, i: number) => {
            const src = nodeMap.get(edge.source);
            const tgt = nodeMap.get(edge.target);
            if (!src || !tgt) return null;

            const isViolating = edge.is_violating;

            return (
              <g key={i} className="edge-group" onClick={() => setSelectedElement({ type: 'edge', ...edge })}>
                <line
                  x1={src.x}
                  y1={src.y}
                  x2={tgt.x}
                  y2={tgt.y}
                  stroke={isViolating ? '#ef4444' : '#94a3b8'}
                  strokeWidth={isViolating ? 3 : 1.5}
                  strokeDasharray={isViolating ? "6,4" : "none"}
                  markerEnd={isViolating ? "url(#arrow-violating)" : "url(#arrow)"}
                  className={isViolating ? "anim-violating-edge" : ""}
                />
                <text
                  x={(src.x + tgt.x) / 2}
                  y={(src.y + tgt.y) / 2 - 8}
                  fill={isViolating ? '#dc2626' : '#64748b'}
                  fontSize="10"
                  fontWeight="600"
                  textAnchor="middle"
                  className="edge-label"
                >
                  {edge.relation}
                </text>
              </g>
            );
          })}

          {/* Nodes */}
          {layoutNodes.map((n: any) => {
            const isViolating = n.is_violating;
            const isSelected = selectedElement?.id === n.id;

            return (
              <g 
                key={n.id} 
                className={`node-group ${isViolating ? 'violating-node' : ''} ${isSelected ? 'selected' : ''}`}
                transform={`translate(${n.x}, ${n.y})`}
                onClick={() => setSelectedElement({ type: 'node', ...n })}
              >
                {/* Shape based on kind */}
                {n.kind === 'package' && (
                  <rect x="-65" y="-22" width="130" height="44" rx="8" fill={isViolating ? '#fee2e2' : '#e0f2fe'} stroke={isViolating ? '#ef4444' : '#0284c7'} strokeWidth="2" />
                )}
                {n.kind === 'environment predicate' && (
                  <polygon points="0,-22 55,-10 55,10 0,22 -55,10 -55,-10" fill="#fef3c7" stroke="#d97706" strokeWidth="2" />
                )}
                {n.kind === 'secret/canary' && (
                  <rect x="-75" y="-20" width="150" height="40" rx="20" fill="#fce7f3" stroke="#db2777" strokeWidth="2" />
                )}
                {n.kind === 'endpoint' && (
                  <circle cx="0" cy="0" r="26" fill="#fee2e2" stroke="#dc2626" strokeWidth="2" />
                )}
                {n.kind === 'module/function' && (
                  <rect x="-60" y="-18" width="120" height="36" rx="6" fill="#ede9fe" stroke="#7c3aed" strokeWidth="1.5" />
                )}

                <text 
                  x="0" 
                  y="4" 
                  fill={isViolating ? '#991b1b' : (n.kind === 'secret/canary' ? '#9d174d' : (n.kind === 'environment predicate' ? '#92400e' : (n.kind === 'endpoint' ? '#991b1b' : (n.kind === 'module/function' ? '#5b21b6' : '#0369a1'))))} 
                  fontSize="11" 
                  fontWeight="700" 
                  textAnchor="middle"
                >
                  {n.label?.substring(0, 20)}
                </text>
              </g>
            );
          })}
        </svg>

        {/* Legend */}
        <div className="graph-legend">
          <div className="legend-item"><span className="legend-box pkg" /> Package</div>
          <div className="legend-item"><span className="legend-box pred" /> Environment Predicate</div>
          <div className="legend-item"><span className="legend-box secret" /> Secret/Canary</div>
          <div className="legend-item"><span className="legend-box end" /> Endpoint Sink</div>
          <div className="legend-item"><span className="legend-box red-line" /> Violating Path</div>
        </div>
      </div>

      {/* Selected Element Evidence Card */}
      {selectedElement && (
        <div className="element-evidence-card">
          <div className="evidence-card-header">
            <Info size={14} className="text-cyan-400" />
            <h6>Selected Graph Entity Evidence</h6>
          </div>
          <p className="element-desc">
            <strong>ID:</strong> <code>{selectedElement.id || `${selectedElement.source} -> ${selectedElement.target}`}</code> · 
            <strong> Kind:</strong> {selectedElement.kind || selectedElement.relation}
          </p>
          <div className="element-detail-text">
            {selectedElement.is_violating ? (
              <span className="text-red-400">
                <AlertTriangle size={13} className="inline mr-1" />
                Participates in prohibited source-to-sink data exfiltration path!
              </span>
            ) : (
              <span className="text-emerald-400">
                <CheckCircle size={13} className="inline mr-1" />
                No policy violations linked to this entity.
              </span>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
