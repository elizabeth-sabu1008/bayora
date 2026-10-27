import React, { useState } from 'react';
import { GatewayProvider, useGateway } from './context/GatewayContext';
import { TopBar } from './components/TopBar';
import { DemoCaptionBar } from './components/DemoCaptionBar';
import { LiveApiDrawer } from './components/LiveApiDrawer';
import { RoundWizard } from './components/RoundWizard';
import { CryptographicLedger } from './components/CryptographicLedger';
import { EvidenceVerify } from './components/EvidenceVerify';
import { CacheLabView } from './components/CacheLabView';
import { AbacMatrixView } from './components/AbacMatrixView';
import { SealedRunnerView } from './components/SealedRunnerView';
import { AcceptanceResultsView } from './components/AcceptanceResultsView';
import { ReadmeView } from './components/ReadmeView';
import {
  Compass,
  Layers,
  FileCheck2,
  Cpu,
  ShieldAlert,
  Lock,
  BookOpen,
  Award,
  X,
  AlertTriangle,
  CheckCircle2,
  Info,
  Terminal,
} from 'lucide-react';

const AppContent: React.FC = () => {
  const [activeTab, setActiveTab] = useState<string>('wizard');
  const [bannerDismissed, setBannerDismissed] = useState<boolean>(false);
  const { toasts, removeToast, demoState, stopGuidedDemo, serverHealth } = useGateway();

  const navigationItems = [
    { id: 'wizard', label: 'Round Wizard', icon: Compass, badge: 'Phase 1-8' },
    { id: 'acceptance', label: 'Acceptance Results', icon: Award, badge: '5 Tests' },
    { id: 'ledger', label: 'Cryptographic Ledger', icon: Layers, badge: 'Chain' },
    { id: 'evidence', label: 'Evidence & Verify', icon: FileCheck2, badge: 'Proof' },
    { id: 'cachelab', label: 'Oracle & Cache Lab', icon: Cpu, badge: 'N=200' },
    { id: 'abac', label: 'ABAC & Deny Matrix', icon: ShieldAlert, badge: 'RBAC' },
    { id: 'sandbox', label: 'Sealed Runner', icon: Lock, badge: 'CSP' },
    { id: 'readme', label: 'How This Works', icon: BookOpen, badge: 'Specs' },
  ];

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col font-sans selection:bg-emerald-500/30 selection:text-emerald-200">
      {/* Top Header */}
      <TopBar activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Gemini Not Configured Banner */}
      {!bannerDismissed && serverHealth.geminiConfigured === false && (
        <div className="bg-gradient-to-r from-amber-950/90 via-amber-900/60 to-zinc-950 border-b border-amber-500/40 px-4 py-2.5 flex items-center justify-between text-xs font-mono text-amber-200 shadow-md shrink-0">
          <div className="flex items-center gap-2.5">
            <div className="p-1 rounded bg-amber-500/20 border border-amber-500/40 text-amber-400">
              <AlertTriangle className="h-4 w-4" />
            </div>
            <div>
              <span className="font-bold text-amber-300">Gemini not configured:</span>{' '}
              <span className="text-zinc-300 font-sans">
                The <code className="bg-zinc-900 px-1 py-0.5 rounded text-amber-300 border border-amber-500/30 font-mono">GEMINI_API_KEY</code> environment variable is missing on the server. AI inference queries (/api/llm/*) and red/blue generator agents will return 503 until a key is configured.
              </span>
            </div>
          </div>
          <button
            onClick={() => setBannerDismissed(true)}
            className="text-zinc-400 hover:text-zinc-200 p-1 ml-3 rounded hover:bg-zinc-800/60"
            title="Dismiss notification"
          >
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Guided Demo Caption Bar */}
      <DemoCaptionBar demoState={demoState} onStop={stopGuidedDemo} />

      <div className="flex-1 flex flex-col md:flex-row overflow-hidden">
        {/* Sidebar Navigation */}
        <aside className="w-full md:w-64 bg-zinc-950 border-r border-zinc-800/80 p-3 flex md:flex-col justify-between shrink-0 overflow-x-auto md:overflow-x-visible">
          <div className="space-y-1 w-full flex md:flex-col gap-1 md:gap-1">
            <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider font-mono text-zinc-500 font-bold hidden md:block">
              NAVIGATION
            </div>
            {navigationItems.map(item => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2 rounded-lg text-xs font-mono transition-all whitespace-nowrap ${
                    isActive
                      ? 'bg-emerald-950/40 text-emerald-300 font-bold border border-emerald-500/40 shadow-sm'
                      : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900 border border-transparent'
                  }`}
                >
                  <div className="flex items-center gap-2.5">
                    <Icon className={`h-4 w-4 shrink-0 ${isActive ? 'text-emerald-400' : 'text-zinc-500'}`} />
                    <span>{item.label}</span>
                  </div>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono hidden lg:inline ${
                    isActive ? 'bg-emerald-900/60 text-emerald-200' : 'bg-zinc-900 text-zinc-500'
                  }`}>
                    {item.badge}
                  </span>
                </button>
              );
            })}
          </div>

          {/* Sidebar Footer info */}
          <div className="hidden md:block pt-4 border-t border-zinc-850 px-2 space-y-2">
            <div className="bg-zinc-900/60 p-2.5 rounded-lg border border-zinc-800 text-[11px] font-mono text-zinc-400">
              <span className="text-zinc-500 block text-[10px]">VERIFICATION ENGINE:</span>
              <span className="text-emerald-400 font-bold">Ed25519 + SHA-256</span>
              <span className="text-[10px] text-zinc-500 block mt-0.5">AES-GCM 256 Sealed Vault</span>
            </div>
          </div>
        </aside>

        {/* Main Workspace Area */}
        <main className="flex-1 overflow-y-auto p-4 sm:p-6 lg:p-8 bg-zinc-950">
          {activeTab === 'wizard' && <RoundWizard onNavigateToTab={setActiveTab} />}
          {activeTab === 'acceptance' && <AcceptanceResultsView />}
          {activeTab === 'ledger' && <CryptographicLedger />}
          {activeTab === 'evidence' && <EvidenceVerify />}
          {activeTab === 'cachelab' && <CacheLabView />}
          {activeTab === 'abac' && <AbacMatrixView />}
          {activeTab === 'sandbox' && <SealedRunnerView />}
          {activeTab === 'readme' && <ReadmeView />}
        </main>
      </div>

      {/* Floating Toast Notification Stack */}
      <div className="fixed top-14 right-4 z-50 flex flex-col gap-2 max-w-sm pointer-events-none">
        {toasts.map(toast => (
          <div
            key={toast.id}
            className={`pointer-events-auto p-3.5 rounded-xl border shadow-2xl backdrop-blur-md transition-all font-mono text-xs flex items-start justify-between gap-3 ${
              toast.type === 'success'
                ? 'bg-zinc-950/95 border-emerald-500/60 text-emerald-200'
                : toast.type === 'error'
                ? 'bg-zinc-950/95 border-rose-500/60 text-rose-200'
                : toast.type === 'warning'
                ? 'bg-zinc-950/95 border-amber-500/60 text-amber-200'
                : 'bg-zinc-950/95 border-sky-500/60 text-sky-200'
            }`}
          >
            <div className="space-y-0.5">
              <div className="font-bold flex items-center gap-1.5 text-zinc-100">
                {toast.type === 'success' && <CheckCircle2 className="h-4 w-4 text-emerald-400" />}
                {toast.type === 'error' && <AlertTriangle className="h-4 w-4 text-rose-400" />}
                {toast.type === 'warning' && <AlertTriangle className="h-4 w-4 text-amber-400" />}
                {toast.type === 'info' && <Info className="h-4 w-4 text-sky-400" />}
                <span>{toast.title}</span>
              </div>
              <p className="text-[11px] text-zinc-400 font-sans leading-tight">
                {toast.message}
              </p>
            </div>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-zinc-500 hover:text-zinc-300 p-0.5"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>

      {/* Bottom Live API Traffic Drawer */}
      <LiveApiDrawer />
    </div>
  );
};

export default function App() {
  return (
    <GatewayProvider>
      <AppContent />
    </GatewayProvider>
  );
}
