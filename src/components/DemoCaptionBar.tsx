import React from 'react';
import { GuidedDemoState } from '../core/guidedDemo';
import { Play, Square, Pause, ShieldCheck, Sparkles, AlertCircle } from 'lucide-react';

interface DemoCaptionBarProps {
  demoState: GuidedDemoState;
  onStop: () => void;
}

export const DemoCaptionBar: React.FC<DemoCaptionBarProps> = ({ demoState, onStop }) => {
  if (!demoState.isRunning && !demoState.caption) {
    return null;
  }

  const progressPct = demoState.totalSteps > 0
    ? Math.round((demoState.stepNumber / demoState.totalSteps) * 100)
    : 0;

  return (
    <div className="sticky top-[53px] z-30 bg-gradient-to-r from-zinc-950 via-zinc-900 to-zinc-950 border-b border-emerald-500/40 shadow-2xl transition-all duration-300">
      <div className="max-w-7xl mx-auto px-4 lg:px-6 py-2.5 flex flex-wrap items-center justify-between gap-3 font-mono">
        {/* Left: Step Badge & Caption */}
        <div className="flex items-center gap-3 flex-1 min-w-[280px]">
          <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 text-[11px] font-bold whitespace-nowrap">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-ping" />
            <span>DEMO {demoState.stepNumber}/{demoState.totalSteps}</span>
          </div>

          <div className="flex-1">
            <p className="text-xs sm:text-sm font-semibold text-zinc-100 font-sans tracking-wide leading-snug">
              {demoState.caption}
            </p>
          </div>
        </div>

        {/* Right: Pause state & Stop Button */}
        <div className="flex items-center gap-2.5 shrink-0">
          {demoState.isPaused && (
            <span className="text-[11px] font-mono font-bold px-2.5 py-1 rounded bg-amber-500/20 text-amber-300 border border-amber-500/40 animate-pulse flex items-center gap-1.5">
              <Pause className="h-3.5 w-3.5 fill-current" />
              <span>{demoState.pauseReason || 'PAUSED 4s'}</span>
            </span>
          )}

          {demoState.isRunning && (
            <button
              onClick={onStop}
              className="flex items-center gap-1.5 px-3 py-1 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 hover:text-white border border-zinc-700 text-xs font-bold transition-all shadow-sm"
              title="Stop automated guided demo"
            >
              <Square className="h-3 w-3 fill-current text-rose-400" />
              <span>Stop Demo</span>
            </button>
          )}
        </div>
      </div>

      {/* Progress Bar Line */}
      <div className="w-full bg-zinc-850 h-1 overflow-hidden">
        <div
          className="h-full bg-gradient-to-r from-emerald-500 via-teal-400 to-emerald-300 transition-all duration-500 shadow-sm shadow-emerald-400"
          style={{ width: `${progressPct}%` }}
        />
      </div>
    </div>
  );
};
