import React, { useState } from 'react';
import { CavrRunState, shown } from './types';
import { SafeText, asText, cut } from './SafeText';
import { RecordedBanner } from './RecordedBanner';

interface CausalGraphTabProps {
  state: CavrRunState;
}

// The causal capability graph of each deep verdict (backend/cavr/causal_graph.py, PR 13), as the proof carries it
// (`causal_graphs`: only graphs that hash to the digest their evidence names). Nothing is added: the nodes and edges
// are the backend's; the page only places them in columns and follows the edges it was given.
//
//   trigger / call  ->  spec  ->  run  ->  event  ->  contract rule  ->  verdict
//   "caused by": trigger -> event or call -> event (the event is in that trigger's run and not in the canary-only run,
//   or in the call's drive step and not in the same run's imports step).

const COLUMNS: Record<string, number> = { trigger: 0, call: 0, spec: 1, run: 2, event: 3, rule: 4, verdict: 5 };
const COLUMN_TITLES = ['Trigger / call site', 'Run spec', 'Run', 'Event', 'Contract rule', 'Verdict'];
const COLORS: Record<string, { fill: string; stroke: string }> = {
  trigger: { fill: '#fef3c7', stroke: '#d97706' }, call: { fill: '#ede9fe', stroke: '#7c3aed' },
  spec: { fill: '#f1f5f9', stroke: '#64748b' }, run: { fill: '#e0f2fe', stroke: '#0284c7' },
  event: { fill: '#fce7f3', stroke: '#db2777' }, rule: { fill: '#fee2e2', stroke: '#dc2626' },
  verdict: { fill: '#dcfce7', stroke: '#16a34a' }, other: { fill: '#f8fafc', stroke: '#94a3b8' },
};
const EDGE_TEXT: Record<string, string> = {
  caused: 'caused by', synthesized_as: 'synthesized as', configured: 'configured', observed: 'observed',
  violates: 'violates', within: 'within', unjudged: 'not judged', decides: 'decides',
};
const DECISIVE_EDGES = new Set(['caused', 'violates', 'unjudged']);
// Stroke of each edge kind on the drawing; only "caused by" carries a label there (every edge is listed as text below).
const EDGE_STROKES: Record<string, string> = { caused: '#ea580c', violates: '#dc2626', unjudged: '#a16207', within: '#16a34a',
  decides: '#475569' };
const COLUMN_WIDTH = 236;
const ROW_HEIGHT = 56;
const NODE_WIDTH = 170;
const NODE_HEIGHT = 40;

const list = (value: unknown): any[] => (Array.isArray(value) ? value : []);

// The text of one node, from its own fields.
export const nodeLabel = (node: any): string => {
  switch (node?.kind) {
    case 'trigger': return `${asText(node.predicate)} (${asText(node.file)}:${asText(node.line)})`;
    case 'call': return `${asText(node.call)} at ${asText(node.file)}:${asText(node.line)}`;
    case 'spec': return asText(node.spec);
    case 'run': return `run ${asText(node.n)} (${asText(node.run_kind)})`;
    case 'event': return `${asText(node.label ?? node.type)} (run ${asText(node.run)}, ${asText(node.step)}, trace line ${asText(node.line)})`;
    case 'rule': return `${asText(node.capability)}: ${asText(node.grant)}`;
    case 'verdict': return `${asText(node.status)} ${asText(node.rule)}`;
    default: return asText(node?.id);
  }
};

// The nodes shown by default: every trigger, call site and verdict; every event with a cause, a violation or no
// judgement, with the rule it was judged by and the run (and spec) it is in. The rest are shown on request.
export const decisiveIds = (graph: any): Set<string> => {
  const nodes = list(graph?.nodes);
  const edges = list(graph?.edges);
  const kinds = new Map<string, string>(nodes.map((node) => [String(node.id), String(node.kind)]));
  const keep = new Set<string>(nodes.filter((node) => ['trigger', 'call', 'verdict'].includes(node.kind)).map((node) => String(node.id)));
  const events = new Set<string>();
  for (const edge of edges) {
    if (!DECISIVE_EDGES.has(edge.kind)) continue;
    const event = kinds.get(String(edge.to)) === 'event' ? String(edge.to) : String(edge.from);
    if (kinds.get(event) === 'event') events.add(event);
  }
  events.forEach((id) => keep.add(id));
  for (const edge of edges) {
    const from = String(edge.from), to = String(edge.to);
    if (events.has(from) && DECISIVE_EDGES.has(edge.kind)) keep.add(to);          // the rule an event was judged by
    if (edge.kind === 'observed' && events.has(to)) keep.add(from);                // the run the event is in
  }
  for (const edge of edges) {
    if (edge.kind === 'configured' && keep.has(String(edge.to))) keep.add(String(edge.from));   // that run's spec
  }
  return keep;
};

// Each chain from a cause to the verdict: cause -> event -> rule -> verdict, following only the backend's edges.
export const causeChains = (graph: any): string[][] => {
  const nodes = new Map<string, any>(list(graph?.nodes).map((node) => [String(node.id), node]));
  const edges = list(graph?.edges);
  const out = (from: string, kind: string) => edges.filter((e) => String(e.from) === from && e.kind === kind).map((e) => String(e.to));
  const chains: string[][] = [];
  for (const edge of edges.filter((e) => e.kind === 'caused')) {
    const cause = nodes.get(String(edge.from)), event = nodes.get(String(edge.to));
    if (!cause || !event) continue;
    const judged = edges.find((e) => String(e.from) === String(edge.to) && ['violates', 'within', 'unjudged'].includes(e.kind));
    const rule = judged ? nodes.get(String(judged.to)) : null;
    const verdict = rule ? out(String(rule.id), 'decides').map((id) => nodes.get(id)).find(Boolean) : null;
    chains.push([nodeLabel(cause), nodeLabel(event), rule ? `${EDGE_TEXT[judged!.kind]} ${nodeLabel(rule)}` : 'not judged',
                 verdict ? nodeLabel(verdict) : 'does not decide the verdict']);
  }
  return chains;
};

export const CausalGraphTab: React.FC<CausalGraphTabProps> = ({ state }) => {
  const graphs = state.proofData?.causal_graphs;
  const views: any[] = state.proofData?.packages || [];
  const entries: [string, any][] = graphs && typeof graphs === 'object' ? Object.entries(graphs) : [];
  const withDeep = views.filter((view) => view?.deep);
  return (
    <div className="evidence-tab-pane causal-pane">
      <RecordedBanner recorded={state.recorded} />
      {entries.length === 0 && (
        <div className="tab-intro-card">
          <div>
            <h5>Causal capability graph</h5>
            <p>
              {!state.proofData ? `${shown(null)} (no run has finished yet)`
                : withDeep.length === 0 ? 'Not available: no deep analysis ran for this request, so there are no observed runs to draw.'
                  : 'Not available: the graph of this run is missing or does not hash to the digest its evidence names.'}
            </p>
          </div>
        </div>
      )}
      {entries.map(([name, graph]) => <GraphView key={name} name={name} graph={graph} />)}
    </div>
  );
};

const GraphView: React.FC<{ name: string; graph: any }> = ({ name, graph }) => {
  const [showAll, setShowAll] = useState(false);
  const [selected, setSelected] = useState<any | null>(null);
  const allNodes = list(graph.nodes);
  const keep = decisiveIds(graph);
  const nodes = showAll ? allNodes : allNodes.filter((node) => keep.has(String(node.id)));
  const hidden = allNodes.length - nodes.length;
  const ids = new Set(nodes.map((node) => String(node.id)));
  const edges = list(graph.edges).filter((edge) => ids.has(String(edge.from)) && ids.has(String(edge.to)));

  const rows: number[] = [0, 0, 0, 0, 0, 0];
  const placed = new Map<string, { x: number; y: number; node: any }>();
  for (const node of nodes) {
    const column = COLUMNS[node.kind] ?? 5;
    placed.set(String(node.id), { x: 10 + column * COLUMN_WIDTH, y: 40 + rows[column] * ROW_HEIGHT, node });
    rows[column] += 1;
  }
  const width = 10 + 6 * COLUMN_WIDTH;
  const height = 60 + Math.max(1, ...rows) * ROW_HEIGHT;
  const chains = causeChains(graph);

  return (
    <div className="reverification-card causal-graph">
      <h5><SafeText value={name} />: causal capability graph</h5>
      <p>
        {allNodes.length} nodes, {list(graph.edges).length} edges; digest <code>{cut(graph.digest, 16)}</code>.{' '}
        {shown(graph.counts?.install_events_within_envelope)} install-step events inside the contract are counted, not drawn.
      </p>
      <div className="graph-filters">
        <button className={`filter-btn ${showAll ? 'active' : ''}`} onClick={() => setShowAll(!showAll)}>
          {showAll ? 'Show the decisive part only' : `Show all nodes (${hidden} more)`}
        </button>
      </div>

      <h6>Cause chains</h6>
      {chains.length === 0 ? <p>No "caused by" edge: no event needed a trigger or a driven call (or no event was observed outside the import).</p> : (
        <ul className="cause-chains">
          {chains.map((chain, index) => (
            <li key={index}>
              <SafeText value={chain[1]} /> <strong>caused by</strong> <SafeText value={chain[0]} /> → <SafeText value={chain[2]} /> → <SafeText value={chain[3]} />
            </li>
          ))}
        </ul>
      )}

      <div className="svg-canvas-container" style={{ overflowX: 'auto' }}>
        <svg className="causal-svg" viewBox={`0 0 ${width} ${height}`} role="img"
          style={{ width: '100%', maxWidth: width, height: 'auto' }}>
          <defs>
            <marker id="cavr-arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#94a3b8" />
            </marker>
            <marker id="cavr-arrow-caused" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="7" markerHeight="7" orient="auto">
              <path d="M 0 0 L 10 5 L 0 10 z" fill="#ea580c" />
            </marker>
          </defs>
          {COLUMN_TITLES.map((title, column) => (
            <text key={title} x={10 + column * COLUMN_WIDTH + NODE_WIDTH / 2} y={20} textAnchor="middle" fontSize="11" fontWeight="700" fill="#475569">{title}</text>
          ))}
          {edges.map((edge, index) => {
            const from = placed.get(String(edge.from)), to = placed.get(String(edge.to));
            if (!from || !to) return null;
            const caused = edge.kind === 'caused';
            const x1 = from.x + NODE_WIDTH, y1 = from.y + NODE_HEIGHT / 2, x2 = to.x, y2 = to.y + NODE_HEIGHT / 2;
            const bend = caused ? -14 * Math.max(1, Math.round((x2 - x1) / COLUMN_WIDTH)) : 0;
            const stroke = EDGE_STROKES[edge.kind] ?? '#94a3b8';
            const path = `M ${x1} ${y1} Q ${(x1 + x2) / 2} ${(y1 + y2) / 2 + bend} ${x2} ${y2}`;
            return (
              <g key={index} className={`edge-group edge-${caused ? 'caused' : 'plain'}`}>
                <path d={path} fill="none" stroke={stroke} strokeWidth={caused ? 2.5 : 1.4}
                  strokeDasharray={caused ? '6,3' : undefined} markerEnd={caused ? 'url(#cavr-arrow-caused)' : 'url(#cavr-arrow)'} />
                {caused && (
                  <text x={(x1 + x2) / 2} y={(y1 + y2) / 2 + bend / 2 - 4} textAnchor="middle" fontSize="11"
                    fontWeight={700} fill="#c2410c">caused by</text>
                )}
              </g>
            );
          })}
          {nodes.map((node) => {
            const at = placed.get(String(node.id));
            if (!at) return null;
            const color = COLORS[node.kind] ?? COLORS.other;
            const label = nodeLabel(node);
            return (
              <g key={String(node.id)} className="node-group" transform={`translate(${at.x}, ${at.y})`} onClick={() => setSelected(node)}>
                <title>{cut(label)}</title>
                <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="6" fill={color.fill} stroke={color.stroke} strokeWidth="1.5" />
                <text x={NODE_WIDTH / 2} y={NODE_HEIGHT / 2 + 4} textAnchor="middle" fontSize="10" fontWeight="600" fill="#0f172a">{cut(label, 28)}</text>
              </g>
            );
          })}
        </svg>
      </div>

      <p className="graph-legend-text" style={{ fontSize: 12 }}>
        Lines: <span style={{ color: '#ea580c', fontWeight: 700 }}>orange dashed = caused by</span> ·{' '}
        <span style={{ color: '#dc2626' }}>red = violates the contract</span> · <span style={{ color: '#16a34a' }}>green = within the contract</span> ·{' '}
        <span style={{ color: '#a16207' }}>brown = not judged</span> · grey = synthesized as / configured / observed / decides.
      </p>
      <details className="graph-edge-list">
        <summary>Edges as text ({edges.length})</summary>
        <ul>
          {edges.map((edge, index) => {
            const from = placed.get(String(edge.from))?.node, to = placed.get(String(edge.to))?.node;
            return edge.kind === 'caused'
              ? <li key={index}><SafeText value={nodeLabel(to)} /> <strong>caused by</strong> <SafeText value={nodeLabel(from)} /></li>
              : <li key={index}><SafeText value={nodeLabel(from)} /> {EDGE_TEXT[edge.kind] ?? 'edge'} <SafeText value={nodeLabel(to)} /></li>;
          })}
        </ul>
      </details>

      {selected && (
        <div className="element-evidence-card">
          <h6>Selected node</h6>
          <div className="proof-kv">
            {Object.entries(selected).map(([key, value]) => (
              <div key={key}><span>{cut(key, 40)}:</span> <code><SafeText value={value} /></code></div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
