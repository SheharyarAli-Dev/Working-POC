import React, { useState, useRef } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';
import { BackgroundGrid } from './components/BackgroundGrid';
import { Phase01Hero } from './components/Phase01Hero';
import { CavrModule } from './components/CavrModule';
import { SableModule } from './components/SableModule';
import { SatraModule } from './components/SatraModule';
import { RunWorkflowModule } from './components/RunWorkflowModule';
import { Package, Network, ShieldCheck, Workflow } from 'lucide-react';

type TabType = 'CAVR' | 'SABLE' | 'SATRA' | 'RUN_WORKFLOW';

function App() {
  const [activeTab, setActiveTab] = useState<TabType>('CAVR');
  const phase02Ref = useRef<HTMLDivElement | null>(null);

  const scrollToPhase2 = () => {
    if (phase02Ref.current) {
      phase02Ref.current.scrollIntoView({ behavior: 'smooth' });
    }
  };

  return (
    <div className="asent-app-root">
      {/* Background Layer: Eased lerp cursor follower, low transparency dot grid, network circuit lines */}
      <BackgroundGrid />

      {/* Main Content Area */}
      <div className="asent-content-wrapper">
        {/* PHASE 01: Hero Section */}
        <Phase01Hero onScrollToPhase2={scrollToPhase2} />

        {/* PHASE 02: 4 Tabs Section */}
        <section className="phase02-section" ref={phase02Ref} id="phase02-tabs">
          <div className="tabs-navigation-bar">
            <button
              className={`tab-btn ${activeTab === 'CAVR' ? 'active' : ''}`}
              onClick={() => setActiveTab('CAVR')}
              id="tab-cavr"
            >
              <Package size={17} />
              <span>CAVR</span>
              <small className="tab-pill">Default</small>
            </button>

            <button
              className={`tab-btn ${activeTab === 'SABLE' ? 'active' : ''}`}
              onClick={() => setActiveTab('SABLE')}
              id="tab-sable"
            >
              <Network size={17} />
              <span>SABLE</span>
            </button>

            <button
              className={`tab-btn ${activeTab === 'SATRA' ? 'active' : ''}`}
              onClick={() => setActiveTab('SATRA')}
              id="tab-satra"
            >
              <ShieldCheck size={17} />
              <span>SATRA</span>
            </button>

            <button
              className={`tab-btn ${activeTab === 'RUN_WORKFLOW' ? 'active' : ''}`}
              onClick={() => setActiveTab('RUN_WORKFLOW')}
              id="tab-run-workflow"
            >
              <Workflow size={17} />
              <span>RUN WORKFLOW</span>
            </button>
          </div>

          {/* Tab Views */}
          <div className="tab-view-container">
            {activeTab === 'CAVR' && <CavrModule />}
            {activeTab === 'SABLE' && <SableModule />}
            {activeTab === 'SATRA' && <SatraModule />}
            {activeTab === 'RUN_WORKFLOW' && <RunWorkflowModule />}
          </div>
        </section>

        {/* Footer */}
        <footer className="asent-footer">
          <div className="footer-left">
            <strong>AGENT SENTINEL (ASENT)</strong>
            <span>Autonomous AI-Change Security Assurance Gate</span>
          </div>
          <div className="footer-right">
            <span>Deterministic verification · Zero LLM hallucination in gates · Honest limitation disclosure</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

const rootElement = document.getElementById('root');
if (rootElement) {
  createRoot(rootElement).render(<App />);
}
