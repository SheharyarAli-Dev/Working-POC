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

class ErrorBoundary extends React.Component<{ children: React.ReactNode }, { hasError: boolean; error: any }> {
  constructor(props: { children: React.ReactNode }) {
    super(props);
    this.state = { hasError: false, error: null };
  }
  static getDerivedStateFromError(error: any) {
    return { hasError: true, error };
  }
  componentDidCatch(error: any, info: any) {
    console.error('Module Error Boundary caught exception:', error, info);
  }
  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '24px', background: '#fef2f2', border: '1px solid #fca5a5', borderRadius: '8px', color: '#b91c1c', margin: '20px 0' }}>
          <h3 style={{ margin: '0 0 8px 0', fontSize: '16px', fontWeight: 700 }}>Module Rendering Notice</h3>
          <p style={{ margin: '0 0 12px 0', fontSize: '13px' }}>{this.state.error?.message || 'An unexpected error occurred while rendering the module.'}</p>
          <button 
            onClick={() => this.setState({ hasError: false, error: null })}
            style={{ padding: '6px 14px', background: '#b91c1c', color: '#fff', border: 'none', borderRadius: '4px', cursor: 'pointer', fontWeight: 600 }}
          >
            Reload Module
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

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
            <ErrorBoundary>
              {activeTab === 'CAVR' && <CavrModule />}
              {activeTab === 'SABLE' && <SableModule />}
              {activeTab === 'SATRA' && <SatraModule />}
              {activeTab === 'RUN_WORKFLOW' && <RunWorkflowModule />}
            </ErrorBoundary>
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
