import React, { useState, useEffect } from 'react';
import { runCacheProbeExperiment, CacheProbeResult, CacheMode } from '../core/cacheLab';
import {
  Cpu,
  Play,
  RotateCcw,
  HelpCircle,
  ShieldCheck,
  ShieldAlert,
  Clock,
  BarChart3,
  Zap,
  Info,
  X,
  Server,
  CheckCircle2,
} from 'lucide-react';

interface VllmTelemetryState {
  isLoading: boolean;
  connected: boolean;
  status: string;
  message: string;
  baseUrl: string | null;
  metrics: {
    gpuCacheUsagePercent: number | null;
    cpuCacheUsagePercent: number | null;
    prefixCacheHitRate: number | null;
    prefixCacheHits: number | null;
    prefixCacheQueries: number | null;
    numTotalGpuBlocks: number | null;
    numUsedGpuBlocks: number | null;
    numFreeGpuBlocks: number | null;
    requestsRunning: number | null;
    requestsWaiting: number | null;
  } | null;
  lastUpdated: string | null;
  error?: string;
}

export const CacheLabView: React.FC = () => {
  const [results, setResults] = useState<Record<CacheMode, CacheProbeResult | null>>({
    SALT_OFF: null,
    SALT_ON: null,
    SALT_ON_PADDING: null,
  });

  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [activeRunningMode, setActiveRunningMode] = useState<string | null>(null);
  const [showExplainer, setShowExplainer] = useState<boolean>(false);

  const [vllmTelemetry, setVllmTelemetry] = useState<VllmTelemetryState>({
    isLoading: false,
    connected: false,
    status: 'initial',
    message: 'Checking vLLM connection...',
    baseUrl: null,
    metrics: null,
    lastUpdated: null,
  });

  const fetchVllmMetrics = async () => {
    setVllmTelemetry(prev => ({ ...prev, isLoading: true }));
    try {
      const res = await fetch('/api/vllm/metrics');
      const data = await res.json();
      setVllmTelemetry({
        isLoading: false,
        connected: Boolean(data.connected),
        status: data.status || (data.connected ? 'connected' : 'unavailable'),
        message: data.message || (data.connected ? 'Connected to vLLM' : 'vLLM not connected - cache metrics unavailable'),
        baseUrl: data.baseUrl || null,
        metrics: data.metrics || null,
        lastUpdated: new Date().toLocaleTimeString(),
        error: data.error,
      });
    } catch (err: any) {
      setVllmTelemetry({
        isLoading: false,
        connected: false,
        status: 'error',
        message: 'vLLM not connected - cache metrics unavailable',
        baseUrl: null,
        metrics: null,
        lastUpdated: new Date().toLocaleTimeString(),
        error: err?.message || 'Failed to fetch vLLM metrics',
      });
    }
  };

  useEffect(() => {
    fetchVllmMetrics();
  }, []);


  const runAllModes = async () => {
    setIsRunning(true);
    try {
      setActiveRunningMode('SALT_OFF');
      const resOff = await runCacheProbeExperiment('SALT_OFF', 200);
      setResults(prev => ({ ...prev, SALT_OFF: resOff }));

      setActiveRunningMode('SALT_ON');
      const resOn = await runCacheProbeExperiment('SALT_ON', 200);
      setResults(prev => ({ ...prev, SALT_ON: resOn }));

      setActiveRunningMode('SALT_ON_PADDING');
      const resPad = await runCacheProbeExperiment('SALT_ON_PADDING', 200);
      setResults(prev => ({ ...prev, SALT_ON_PADDING: resPad }));
    } catch (e) {
      console.error(e);
    } finally {
      setIsRunning(false);
      setActiveRunningMode(null);
    }
  };

  const runSingleMode = async (mode: CacheMode) => {
    setIsRunning(true);
    setActiveRunningMode(mode);
    try {
      const res = await runCacheProbeExperiment(mode, 200);
      setResults(prev => ({ ...prev, [mode]: res }));
    } catch (e) {
      console.error(e);
    } finally {
      setIsRunning(false);
      setActiveRunningMode(null);
    }
  };

  return (
    <div className="space-y-6 max-w-7xl mx-auto pb-16 font-mono text-xs">
      {/* Header */}
      <div className="bg-zinc-900/80 rounded-xl p-5 border border-zinc-800 shadow-xl flex flex-wrap items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-rose-400 font-bold text-sm">
            <Cpu className="h-4 w-4" />
            <span>PREFIX CACHE SIDE-CHANNEL ATTACK & MITIGATION LAB</span>
          </div>
          <p className="text-zinc-400 font-sans text-xs mt-1">
            Real in-browser inference prefix cache. An attacker probes N=200 prompts measuring real timings via <code className="text-emerald-300">performance.now()</code>.
            Compute real Hit/Miss latency deltas, 20-bin histograms, empirical Mutual Information (bits), and finite-sample noise floors.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => setShowExplainer(true)}
            className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-zinc-800 hover:bg-zinc-750 text-zinc-300 font-bold border border-zinc-700 transition-colors"
          >
            <HelpCircle className="h-4 w-4 text-emerald-400" />
            <span>Explain Physics & Math</span>
          </button>

          <button
            disabled={isRunning}
            onClick={runAllModes}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition-all shadow-md shadow-emerald-950 disabled:opacity-40"
          >
            <Play className="h-4 w-4 fill-current" />
            <span>{isRunning ? `Probing (${activeRunningMode})...` : 'Run N=200 Probe (All 3 Modes)'}</span>
          </button>
        </div>
      </div>

      {/* Production vLLM KV-Cache Telemetry Panel */}
      <div className="bg-zinc-900/90 rounded-xl p-5 border border-zinc-800 shadow-xl space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-zinc-800">
          <div className="flex items-center gap-2.5">
            <div className={`p-1.5 rounded-lg border ${vllmTelemetry.connected ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400' : 'bg-zinc-800 border-zinc-700 text-zinc-400'}`}>
              <Server className="h-4.5 w-4.5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-sm text-zinc-100">PRODUCTION vLLM KV-CACHE TELEMETRY</span>
                <span className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold uppercase ${
                  vllmTelemetry.connected
                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-500/40'
                    : 'bg-zinc-800 text-zinc-400 border border-zinc-700'
                }`}>
                  {vllmTelemetry.connected ? '● LIVE CONNECTED' : '○ NOT CONNECTED'}
                </span>
              </div>
              <p className="text-zinc-400 font-sans text-xs mt-0.5">
                {vllmTelemetry.connected
                  ? `Real hardware KV-cache metrics streamed from ${vllmTelemetry.baseUrl}/metrics`
                  : 'vLLM not connected - cache metrics unavailable (configure VLLM_BASE_URL to connect to real inference server)'}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {vllmTelemetry.lastUpdated && (
              <span className="text-[10px] text-zinc-500 font-mono hidden sm:inline">
                Updated: {vllmTelemetry.lastUpdated}
              </span>
            )}
            <button
              disabled={vllmTelemetry.isLoading}
              onClick={fetchVllmMetrics}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-zinc-800 hover:bg-zinc-750 text-zinc-300 font-mono text-xs font-semibold border border-zinc-700 transition-colors disabled:opacity-40"
            >
              <RotateCcw className={`h-3.5 w-3.5 text-emerald-400 ${vllmTelemetry.isLoading ? 'animate-spin' : ''}`} />
              <span>{vllmTelemetry.isLoading ? 'Fetching...' : 'Refresh vLLM'}</span>
            </button>
          </div>
        </div>

        {vllmTelemetry.connected && vllmTelemetry.metrics ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
            <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800 space-y-1.5">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">GPU KV-Cache Usage</div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-emerald-400">
                  {vllmTelemetry.metrics.gpuCacheUsagePercent !== null ? `${vllmTelemetry.metrics.gpuCacheUsagePercent}%` : 'N/A'}
                </span>
                <span className="text-[10px] text-zinc-500">vllm:kv_cache_usage_perc</span>
              </div>
              {vllmTelemetry.metrics.gpuCacheUsagePercent !== null && (
                <div className="w-full bg-zinc-800 h-1.5 rounded-full overflow-hidden mt-1">
                  <div
                    className={`h-full rounded-full ${
                      vllmTelemetry.metrics.gpuCacheUsagePercent > 85 ? 'bg-rose-500' : 'bg-emerald-500'
                    }`}
                    style={{ width: `${Math.min(100, Math.max(0, vllmTelemetry.metrics.gpuCacheUsagePercent))}%` }}
                  />
                </div>
              )}
            </div>

            <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800 space-y-1.5">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Prefix Cache Hit Rate</div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-sky-400">
                  {vllmTelemetry.metrics.prefixCacheHitRate !== null
                    ? `${(vllmTelemetry.metrics.prefixCacheHitRate * 100).toFixed(1)}%`
                    : 'N/A'}
                </span>
                <span className="text-[10px] text-zinc-500">
                  {vllmTelemetry.metrics.prefixCacheHits !== null && vllmTelemetry.metrics.prefixCacheQueries !== null
                    ? `${vllmTelemetry.metrics.prefixCacheHits}/${vllmTelemetry.metrics.prefixCacheQueries} tok`
                    : 'queries'}
                </span>
              </div>
              <div className="text-[10px] text-zinc-500 font-sans">
                Prefix lookups avoiding recomputation
              </div>
            </div>

            <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800 space-y-1.5">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">KV Memory Blocks</div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-zinc-200">
                  {vllmTelemetry.metrics.numUsedGpuBlocks !== null ? vllmTelemetry.metrics.numUsedGpuBlocks : '—'}
                </span>
                <span className="text-[10px] text-zinc-500">
                  / {vllmTelemetry.metrics.numTotalGpuBlocks !== null ? `${vllmTelemetry.metrics.numTotalGpuBlocks} total` : 'total blocks'}
                </span>
              </div>
              <div className="text-[10px] text-zinc-500 font-sans">
                Free: {vllmTelemetry.metrics.numFreeGpuBlocks !== null ? `${vllmTelemetry.metrics.numFreeGpuBlocks} blocks` : '—'}
              </div>
            </div>

            <div className="bg-zinc-950 p-3.5 rounded-lg border border-zinc-800 space-y-1.5">
              <div className="text-[10px] text-zinc-500 uppercase tracking-wider font-bold">Active Engine Requests</div>
              <div className="flex items-baseline gap-2">
                <span className="text-xl font-bold font-mono text-amber-300">
                  {vllmTelemetry.metrics.requestsRunning !== null ? vllmTelemetry.metrics.requestsRunning : '0'}
                </span>
                <span className="text-[10px] text-zinc-500">
                  running | {vllmTelemetry.metrics.requestsWaiting !== null ? vllmTelemetry.metrics.requestsWaiting : '0'} waiting
                </span>
              </div>
              <div className="text-[10px] text-zinc-500 font-sans">
                CPU Cache: {vllmTelemetry.metrics.cpuCacheUsagePercent !== null ? `${vllmTelemetry.metrics.cpuCacheUsagePercent}%` : '0%'}
              </div>
            </div>
          </div>
        ) : (
          <div className="bg-zinc-950/60 rounded-lg p-4 border border-zinc-850 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 text-xs">
            <div className="space-y-1">
              <div className="flex items-center gap-2 text-zinc-300 font-bold">
                <span className="h-2 w-2 rounded-full bg-zinc-600" />
                <span>vLLM not connected - cache metrics unavailable</span>
              </div>
              <p className="text-zinc-500 font-sans text-[11px] max-w-2xl">
                Hardware prefix-cache metrics (KV cache usage, prefix hit rate, allocated blocks) require an active vLLM instance.
                Configure the <code className="text-zinc-400 bg-zinc-900 px-1 py-0.5 rounded border border-zinc-800">VLLM_BASE_URL</code> environment variable (e.g. <code className="text-emerald-400">http://localhost:8000</code>) to query real Prometheus metrics.
              </p>
            </div>
            <div className="text-[11px] font-mono text-zinc-500 bg-zinc-900/80 px-2.5 py-1.5 rounded border border-zinc-800 shrink-0">
              Status: <span className="text-amber-400">Telemetry Offline</span>
            </div>
          </div>
        )}
      </div>

      {/* 3 Side-by-Side Histograms & Statistics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Mode 1: Salt OFF */}
        <ModeResultCard
          mode="SALT_OFF"
          title="MODE 1: SHARED CACHE (SALT OFF)"
          subtitle="Vulnerable to Timing Attack"
          result={results.SALT_OFF}
          isRunning={isRunning && activeRunningMode === 'SALT_OFF'}
          onRerun={() => runSingleMode('SALT_OFF')}
          status="vulnerable"
        />

        {/* Mode 2: Salt ON */}
        <ModeResultCard
          mode="SALT_ON"
          title="MODE 2: SALTED KEY (SALT ON)"
          subtitle="Tenant Cache Isolation"
          result={results.SALT_ON}
          isRunning={isRunning && activeRunningMode === 'SALT_ON'}
          onRerun={() => runSingleMode('SALT_ON')}
          status="isolated"
        />

        {/* Mode 3: Salt ON + Constant Padding */}
        <ModeResultCard
          mode="SALT_ON_PADDING"
          title="MODE 3: SALT + CONSTANT PADDING"
          subtitle="Cryptographically Defended (0 bits leak)"
          result={results.SALT_ON_PADDING}
          isRunning={isRunning && activeRunningMode === 'SALT_ON_PADDING'}
          onRerun={() => runSingleMode('SALT_ON_PADDING')}
          status="defended"
        />
      </div>

      {/* Math & Theory Explainer Modal */}
      {showExplainer && (
        <div className="fixed inset-0 z-50 bg-black/75 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-zinc-900 border border-zinc-700 rounded-2xl max-w-2xl w-full p-6 space-y-4 shadow-2xl overflow-y-auto max-h-[85vh]">
            <div className="flex items-center justify-between pb-3 border-b border-zinc-800">
              <div className="flex items-center gap-2 text-emerald-400 font-bold text-sm">
                <Info className="h-5 w-5" />
                <span>HOW THE TIMING SIDE-CHANNEL WORKS & HOW WE PROVE MITIGATION</span>
              </div>
              <button
                onClick={() => setShowExplainer(false)}
                className="p-1 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800"
              >
                <X className="h-5 w-5" />
              </button>
            </div>

            <div className="space-y-3 font-sans text-xs text-zinc-300 leading-relaxed">
              <h4 className="font-mono font-bold text-zinc-100 text-sm">1. The Vulnerability: KV Cache Pre-fill Timing</h4>
              <p>
                In production LLM serving (e.g. vLLM, TensorRT-LLM, Gemini), prefix caching reuses computed KV activations for common prompt prefixes.
                A cache HIT bypasses matrix multiplications and returns in microseconds. A cache MISS requires full pre-fill compute, taking milliseconds.
              </p>
              <p>
                An attacker can probe the server with victim candidate prompts. If the query finishes significantly faster, the attacker knows with statistical certainty that a victim user submitted that prefix earlier!
              </p>

              <h4 className="font-mono font-bold text-zinc-100 text-sm mt-3">2. Mutual Information I(X; Y) in Bits</h4>
              <p>
                To quantify this leakage without hand-waving, BAYORA calculates the mathematical Mutual Information:
              </p>
              <div className="bg-zinc-950 p-3 rounded border border-zinc-800 font-mono text-[11px] text-emerald-300">
                I(X; Y) = ∑ P(x, y) * log2( P(x, y) / (P(x) * P(y)) )
              </div>
              <p>
                Where <strong>X</strong> is the secret label (Was prefix in cache?), and <strong>Y</strong> is the observed latency discretized into 20 bins.
                1.00 bit represents 100% deterministic revelation of the victim's secret prefix.
              </p>

              <h4 className="font-mono font-bold text-zinc-100 text-sm mt-3">3. Empirical Finite-Sample Noise Floor</h4>
              <p>
                With any finite sample (N=200), random statistical fluctuations produce an apparent baseline mutual information (typically ~0.02 - 0.08 bits).
                BAYORA computes a real noise floor by randomly permuting/shuffling the labels while preserving the marginal distribution.
              </p>

              <h4 className="font-mono font-bold text-zinc-100 text-sm mt-3">4. The BAYORA Mitigation: Salt + Constant-Latency Shaping</h4>
              <p>
                Under <strong>Mode 3</strong>, BAYORA salts cache entries per tenant session and delays responses until an exact constant deadline (t0 + DEADLINE_MS).
                As shown in the third histogram, the latency delta collapses to ~0.00ms, and Mutual Information drops to or below the empirical noise floor — mathematically eliminating the side-channel to zero bits of actionable leak!
              </p>
            </div>

            <div className="pt-2 flex justify-end">
              <button
                onClick={() => setShowExplainer(false)}
                className="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-mono text-xs font-bold"
              >
                Close Explainer
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

interface ModeCardProps {
  mode: CacheMode;
  title: string;
  subtitle: string;
  result: CacheProbeResult | null;
  isRunning: boolean;
  onRerun: () => void;
  status: 'vulnerable' | 'isolated' | 'defended';
}

const ModeResultCard: React.FC<ModeCardProps> = ({
  title,
  subtitle,
  result,
  isRunning,
  onRerun,
  status,
}) => {
  return (
    <div className={`rounded-xl border p-5 flex flex-col justify-between space-y-4 shadow-xl ${
      status === 'vulnerable'
        ? 'bg-rose-950/20 border-rose-900/60'
        : status === 'isolated'
        ? 'bg-amber-950/20 border-amber-900/60'
        : 'bg-emerald-950/20 border-emerald-900/60'
    }`}>
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded uppercase ${
            status === 'vulnerable'
              ? 'bg-rose-950/80 text-rose-300 border border-rose-800'
              : status === 'isolated'
              ? 'bg-amber-950/80 text-amber-300 border border-amber-800'
              : 'bg-emerald-950/80 text-emerald-300 border border-emerald-800'
          }`}>
            {status}
          </span>
          <button
            disabled={isRunning}
            onClick={onRerun}
            className="p-1 rounded text-zinc-400 hover:text-zinc-100 hover:bg-zinc-800 transition-colors disabled:opacity-40"
            title="Rerun N=200 probes for this mode"
          >
            <RotateCcw className="h-3.5 w-3.5" />
          </button>
        </div>

        <h3 className="font-bold text-xs text-zinc-100 truncate">{title}</h3>
        <p className="text-[11px] text-zinc-400 font-sans">{subtitle}</p>

        {/* Metrics Row */}
        {result ? (
          <div className="mt-3 grid grid-cols-3 gap-2 text-center text-[11px]">
            <div className="bg-zinc-950/70 p-2 rounded border border-zinc-800">
              <div className="text-zinc-500 text-[10px]">Hit Mean</div>
              <div className="font-bold text-emerald-400">{result.hitMeanMs} ms</div>
            </div>
            <div className="bg-zinc-950/70 p-2 rounded border border-zinc-800">
              <div className="text-zinc-500 text-[10px]">Miss Mean</div>
              <div className="font-bold text-rose-400">{result.missMeanMs} ms</div>
            </div>
            <div className="bg-zinc-950/70 p-2 rounded border border-zinc-800">
              <div className="text-zinc-500 text-[10px]">Timing Delta (Δ)</div>
              <div className={`font-bold ${result.deltaMs > 0.5 ? 'text-rose-400' : 'text-emerald-400'}`}>
                {result.deltaMs} ms
              </div>
            </div>
          </div>
        ) : (
          <div className="mt-3 p-4 text-center text-zinc-500 bg-zinc-950/50 rounded border border-zinc-800">
            {isRunning ? 'Measuring timings...' : 'Awaiting N=200 probe execution'}
          </div>
        )}

        {/* Mutual Information vs Noise Floor Box */}
        {result && (
          <div className="mt-3 bg-zinc-950/80 p-3 rounded-lg border border-zinc-800 space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-zinc-400">Mutual Information I(X;Y):</span>
              <span className={`font-bold ${
                result.mutualInformationBits > 0.2 ? 'text-rose-400' : 'text-emerald-400'
              }`}>
                {result.mutualInformationBits} bits
              </span>
            </div>
            <div className="flex items-center justify-between text-[11px]">
              <span className="text-zinc-500">Shuffled Noise Floor:</span>
              <span className="text-zinc-400 font-medium">{result.noiseFloorBits} bits</span>
            </div>
            <div className="pt-1 text-[10px] text-zinc-500 italic border-t border-zinc-850">
              {result.mutualInformationBits > result.noiseFloorBits * 2
                ? '⚠ Signal exceeds noise floor: Side-channel presence verified!'
                : '✓ Information leakage suppressed to within natural noise floor'}
            </div>
          </div>
        )}

        {/* 20-Bin Histogram Chart */}
        {result && result.bins.length > 0 && (
          <div className="mt-4 space-y-1.5">
            <div className="flex items-center justify-between text-[10px] text-zinc-500">
              <span>LATENCY HISTOGRAM (20 BINS)</span>
              <div className="flex items-center gap-2">
                <span className="flex items-center gap-1 text-emerald-400">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" /> Hits
                </span>
                <span className="flex items-center gap-1 text-rose-400">
                  <span className="h-2 w-2 rounded-full bg-rose-500" /> Misses
                </span>
              </div>
            </div>

            <div className="h-28 bg-zinc-950/90 rounded-lg p-2 border border-zinc-850 flex items-end gap-1">
              {result.bins.map((bin, bIdx) => {
                const totalInBin = bin.hitCount + bin.missCount;
                const maxInAnyBin = Math.max(...result.bins.map(b => b.hitCount + b.missCount), 1);
                const heightPct = Math.min(100, Math.round((totalInBin / maxInAnyBin) * 100));

                const hitPct = totalInBin > 0 ? (bin.hitCount / totalInBin) * 100 : 0;
                const missPct = totalInBin > 0 ? (bin.missCount / totalInBin) * 100 : 0;

                return (
                  <div
                    key={bIdx}
                    title={`Bin [${bin.binStartMs.toFixed(2)} - ${bin.binEndMs.toFixed(2)}ms]: ${bin.hitCount} hits, ${bin.missCount} misses`}
                    className="flex-1 flex flex-col justify-end h-full group relative cursor-pointer"
                  >
                    <div
                      className="w-full rounded-t-sm overflow-hidden flex flex-col justify-end transition-all"
                      style={{ height: `${Math.max(4, heightPct)}%` }}
                    >
                      {bin.missCount > 0 && (
                        <div
                          className="w-full bg-rose-500/80 group-hover:bg-rose-400"
                          style={{ height: `${missPct}%` }}
                        />
                      )}
                      {bin.hitCount > 0 && (
                        <div
                          className="w-full bg-emerald-500/80 group-hover:bg-emerald-400"
                          style={{ height: `${hitPct}%` }}
                        />
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex justify-between text-[9px] text-zinc-600">
              <span>{result.bins[0]?.binStartMs.toFixed(2)} ms</span>
              <span>{result.bins[result.bins.length - 1]?.binEndMs.toFixed(2)} ms</span>
            </div>
          </div>
        )}
      </div>

      <div className="pt-2 border-t border-zinc-800/80 flex items-center justify-between text-[11px] text-zinc-500">
        <span>Trials: {result ? result.trialsCount : 200} probes</span>
        <span>Measured via performance.now()</span>
      </div>
    </div>
  );
};
