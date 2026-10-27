import React from 'react';
import { useGateway } from '../context/GatewayContext';
import { Role } from '../core/policy';
import { Shield, Play, Square, Terminal, RotateCcw, Sparkles, AlertTriangle, CheckCircle2 } from 'lucide-react';

interface TopBarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
}

export const TopBar: React.FC<TopBarProps> = ({ activeTab, setActiveTab }) => {
  const {
    currentRole,
    setRole,
    roundId,
    roundState,
    isApiDrawerOpen,
    setIsApiDrawerOpen,
    callLogs,
    resetRound,
    demoState,
    startGuidedDemo,
    stopGuidedDemo,
    serverHealth,
  } = useGateway();

  const roles: { role: Role; label: string; color: string; desc: string }[] = [
    { role: 'Admin', label: 'Admin', color: 'from-amber-500/20 to-amber-600/30 text-amber-300 border-amber-500/40', desc: 'Orchestrator' },
    { role: 'Red', label: 'Red Team', color: 'from-rose-500/20 to-rose-600/30 text-rose-300 border-rose-500/40', desc: 'Attacker' },
    { role: 'Blue', label: 'Blue Team', color: 'from-sky-500/20 to-sky-600/30 text-sky-300 border-sky-500/40', desc: 'Defender' },
    { role: 'Auditor', label: 'Auditor', color: 'from-emerald-500/20 to-emerald-600/30 text-emerald-300 border-emerald-500/40', desc: 'Verifier' },
  ];

  return (
    <header className="sticky top-0 z-40 bg-zinc-950/95 backdrop-blur-md border-b border-zinc-800/80 px-4 lg:px-6 py-2.5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Brand & Round ID */}
        <div className="flex items-center gap-3.5">
          <div className="flex items-center gap-2.5 cursor-pointer" onClick={() => setActiveTab('wizard')}>
            <div className="h-9 w-9 rounded-lg bg-gradient-to-br from-emerald-500 to-teal-700 p-0.5 shadow-lg shadow-emerald-500/20 flex items-center justify-center">
              <div className="h-full w-full bg-zinc-950 rounded-[7px] flex items-center justify-center">
                <Shield className="h-4.5 w-4.5 text-emerald-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-base font-bold tracking-wider text-zinc-100">BAYORA</span>
                <span className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-zinc-800/90 text-zinc-400 border border-zinc-700/50">
                  SEALED EVAL
                </span>
              </div>
              <p className="text-[11px] text-zinc-400 font-sans hidden sm:block">
                Run together. Leak nothing. Prove it.
              </p>
            </div>
          </div>

          <div className="h-5 w-px bg-zinc-800 hidden md:block" />

          {/* Current Round Badge */}
          <div className="hidden sm:flex items-center gap-2 px-2.5 py-1 rounded-md bg-zinc-900 border border-zinc-800/80">
            <span className="text-[11px] uppercase tracking-wider text-zinc-500 font-semibold font-mono">Room:</span>
            <span className="font-mono text-xs font-semibold text-emerald-400">{roundId}</span>
            <span className="inline-flex items-center gap-1 text-[11px] font-mono px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              LIVE
            </span>
            <span className="text-zinc-600 text-xs">|</span>
            <span className="text-[11px] font-mono text-zinc-300 bg-zinc-800/60 px-1.5 py-0.5 rounded">
              {roundState}
            </span>
          </div>

          {/* Gemini API Key Status Indicator */}
          {serverHealth.geminiConfigured === false ? (
            <div
              className="flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-amber-500/10 text-amber-300 border border-amber-500/30 text-xs font-mono font-medium"
              title="Gemini API key is not configured on the server. /api/llm/* endpoints will return 503."
            >
              <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
              <span>Gemini not configured</span>
            </div>
          ) : serverHealth.geminiConfigured === true ? (
            <div
              className="hidden lg:flex items-center gap-1.5 px-2.5 py-1 rounded-md bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 text-xs font-mono font-medium"
              title={`Gemini live model active: ${serverHealth.geminiModel}`}
            >
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
              <span>Gemini Connected ({serverHealth.geminiModel})</span>
            </div>
          ) : null}
        </div>

        {/* Right side controls: Guided Demo Button, Role Switcher & Live API Toggle */}
        <div className="flex items-center gap-2.5">
          {/* Guided Demo Button */}
          {demoState.isRunning ? (
            <button
              onClick={stopGuidedDemo}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-rose-600/30 hover:bg-rose-600/50 text-rose-200 border border-rose-500/50 text-xs font-mono font-bold transition-all shadow-md shadow-rose-950 animate-pulse"
              title="Stop the running automated demonstration"
            >
              <Square className="h-3.5 w-3.5 fill-current" />
              <span>Stop Demo ({demoState.stepNumber}/8)</span>
            </button>
          ) : (
            <button
              onClick={() => startGuidedDemo(setActiveTab)}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white text-xs font-mono font-bold transition-all shadow-lg shadow-emerald-950/60 border border-emerald-400/40 hover:scale-[1.02]"
              title="Run a complete 8-phase sealed evaluation automatically in about 90 seconds"
            >
              <Play className="h-3.5 w-3.5 fill-current" />
              <span>Guided Demo (90s)</span>
            </button>
          )}

          {/* Role Switcher */}
          <div className="flex items-center bg-zinc-900/90 p-1 rounded-lg border border-zinc-800">
            <span className="text-[11px] text-zinc-500 px-2 font-mono font-medium hidden lg:inline">
              ROLE:
            </span>
            {roles.map(r => {
              const isActive = currentRole === r.role;
              return (
                <button
                  key={r.role}
                  onClick={() => setRole(r.role)}
                  title={`${r.label} (${r.desc}) - Switching changes role token sent to gateway`}
                  className={`px-2.5 py-1 text-xs font-medium rounded-md transition-all font-mono flex items-center gap-1.5 ${
                    isActive
                      ? `bg-zinc-800 text-zinc-100 shadow-sm border border-zinc-700 font-semibold`
                      : `text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/40`
                  }`}
                >
                  <span
                    className={`h-2 w-2 rounded-full ${
                      r.role === 'Admin'
                        ? 'bg-amber-400'
                        : r.role === 'Red'
                        ? 'bg-rose-400'
                        : r.role === 'Blue'
                        ? 'bg-sky-400'
                        : 'bg-emerald-400'
                    }`}
                  />
                  <span>{r.label}</span>
                </button>
              );
            })}
          </div>

          {/* Reset Room Button */}
          <button
            onClick={resetRound}
            title="Reset Evaluation Room (generates fresh gateway Ed25519 keys & clean audit chain)"
            className="p-1.5 rounded-md text-zinc-400 hover:text-zinc-200 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-colors"
          >
            <RotateCcw className="h-4 w-4" />
          </button>

          {/* Live Gateway API Drawer Toggle */}
          <button
            onClick={() => setIsApiDrawerOpen(!isApiDrawerOpen)}
            className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-mono font-medium border transition-colors ${
              isApiDrawerOpen
                ? 'bg-emerald-500/20 text-emerald-300 border-emerald-500/40'
                : 'bg-zinc-900 text-zinc-300 hover:text-zinc-100 border-zinc-800 hover:bg-zinc-850'
            }`}
          >
            <Terminal className="h-3.5 w-3.5 text-emerald-400" />
            <span className="hidden sm:inline">Gateway Log</span>
            <span className="text-[10px] px-1 rounded bg-zinc-800 text-zinc-400 font-mono">
              {callLogs.length}
            </span>
          </button>
        </div>
      </div>
    </header>
  );
};
