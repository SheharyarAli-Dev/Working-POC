// Renders parts of the CAVR dashboard page to static HTML, for tests/test_cavr_frontend.py.
//
//   node render_cavr.mjs <frontend directory> <work directory>      JSON on stdin, JSON on stdout
//
//   stdin:  {"views": [{"view": "<name>", ...props}, ...]}
//   stdout: {"html": ["<html of the first view>", ...]}
//
// It bundles the real components from frontend/src with esbuild (installed with the frontend, it
// is what the build uses) and renders them with react-dom/server. Effects and fetch do not run in
// a server render, so a view gets its data as props: the test passes real answers of the backend.
//
// Views:
//   page                              the whole module as it is before anything was fetched or run
//   chips        {scenarios}          the scenario chips for an answer of GET /api/cavr/scenarios
//   timeline     {stages}             the six stages, each opened; `stages` of a proof, or null
//   proof        {proof}              the proof drawer for an answer of GET /api/cavr/proof/{run_id}
//   overview | requirements | assurance | stage
//                {events, proof}      one tab, with the run state the page builds from the stream's events
//   metrics      {metrics}            the Metrics tab for an answer of GET /api/cavr/metrics
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { pathToFileURL } from 'node:url';

const [frontend, work] = process.argv.slice(2).map((given) => path.resolve(given));
const esbuild = createRequire(path.join(frontend, 'package.json'))('esbuild');
const components = path.join(frontend, 'src', 'components');
const from = (relative) => JSON.stringify(path.join(components, relative));

const entry = path.join(work, 'entry.tsx');
fs.writeFileSync(entry, `
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { CavrModule } from ${from('CavrModule')};
import { ScenarioChips } from ${from('cavr/ScenarioChips')};
import { ExpandableStep } from ${from('cavr/ExpandableStep')};
import { STAGE_NAMES } from ${from('cavr/Timeline')};
import { ProofDrawer } from ${from('cavr/ProofDrawer')};
import { OverviewTab } from ${from('cavr/OverviewTab')};
import { RequirementsTab } from ${from('cavr/RequirementsTab')};
import { AssuranceTab } from ${from('cavr/AssuranceTab')};
import { StageDetailPanel } from ${from('cavr/StageDetailPanel')};
import { MetricsReport } from ${from('cavr/MetricsTab')};
import { EMPTY_RUN, applyEvent } from ${from('cavr/runState')};

// The run state exactly as the page builds it: the stream's events through the page's own reducer,
// then the proof it fetches after the verdict.
const runState = ({ events, proof }: any) => ({
  ...events.reduce(applyEvent, { ...EMPTY_RUN, runId: proof.run_id, request: proof.request }),
  proofData: proof,
});

const VIEWS: Record<string, (props: any) => React.ReactElement> = {
  page: () => <CavrModule />,
  chips: ({ scenarios }) => (
    <ScenarioChips scenarios={scenarios} failed={false} current={null} disabled={false} onRun={() => undefined} />
  ),
  timeline: ({ stages }) => (
    <div>
      {STAGE_NAMES.map((name: string, index: number) => {
        const stage = stages ? stages[index] || null : null;
        return (
          <ExpandableStep key={index} stepIndex={index} stage={stage} title={stage ? stage.title : name}
            isExpanded={true} onToggleExpand={() => undefined} />
        );
      })}
    </div>
  ),
  proof: ({ proof }) => <ProofDrawer proof={proof} onClose={() => undefined} />,
  overview: (props) => <OverviewTab state={runState(props)} />,
  requirements: (props) => <RequirementsTab state={runState(props)} />,
  assurance: (props) => <AssuranceTab state={runState(props)} />,
  stage: (props) => <StageDetailPanel state={runState(props)} />,
  metrics: ({ metrics }) => <MetricsReport metrics={metrics} />,
};

export const render = (views: any[]) => views.map(({ view, ...props }) => renderToStaticMarkup(VIEWS[view](props)));
`);

const bundle = path.join(work, 'bundle.mjs');
await esbuild.build({
  entryPoints: [entry], outfile: bundle, bundle: true, platform: 'node', format: 'esm', jsx: 'automatic',
  nodePaths: [path.join(frontend, 'node_modules')], logLevel: 'silent',
  // react-dom/server is CommonJS and calls require() for Node's own modules.
  banner: { js: "import { createRequire as cavrRequire } from 'node:module'; const require = cavrRequire(import.meta.url);" },
});
const { render } = await import(pathToFileURL(bundle).href);
const { views } = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify({ html: render(views) }));
