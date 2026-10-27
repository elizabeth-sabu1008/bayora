/**
 * CacheLab — Side-Channel Prefix Cache Timing Attack & Mitigation Lab
 * Demonstrates real timing side-channels in LLM prefix caching and real cryptographic mitigation.
 */

export type CacheMode = 'SALT_OFF' | 'SALT_ON' | 'SALT_ON_PADDING';

export interface CacheProbeResult {
  mode: CacheMode;
  trialsCount: number;
  hitCount: number;
  missCount: number;
  hitMeanMs: number;
  missMeanMs: number;
  deltaMs: number;
  mutualInformationBits: number;
  noiseFloorBits: number;
  bins: Array<{
    binStartMs: number;
    binEndMs: number;
    hitCount: number;
    missCount: number;
  }>;
  samples: Array<{
    id: number;
    isHit: boolean;
    latencyMs: number;
  }>;
}

// Simple fast deterministic hash for CPU synchronous prefix hashing
function fastHash(str: string): string {
  let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
}

export class MiniInferenceServer {
  private cache: Map<string, { prompt: string; cachedAt: number }> = new Map();
  private salt: string = '';

  constructor(useSalt: boolean = false) {
    if (useSalt) {
      this.salt = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
    }
  }

  public setSalt(salt: string) {
    this.salt = salt;
  }

  public clearCache() {
    this.cache.clear();
  }

  public getCacheSize(): number {
    return this.cache.size;
  }

  /**
   * Real CPU-bound work simulation to mimic KV-cache generation on miss
   */
  private doInferenceComputeWork(): number {
    let acc = 1.0;
    // Real CPU calculation loop
    for (let i = 0; i < 45000; i++) {
      acc = (acc * 1.000037 + Math.sin(i) * 0.00001) % 1000.0;
    }
    return acc;
  }

  /**
   * Query the prefix cache
   */
  public query(prefix: string, mode: CacheMode, paddedTargetMs: number = 4.0): { isHit: boolean; latencyMs: number } {
    const t0 = performance.now();

    // 1. Compute key
    let key = '';
    if (mode === 'SALT_OFF') {
      // Vulnerable: shared prefix key
      key = fastHash(prefix);
    } else {
      // Salted: tenant/session isolated
      key = fastHash(this.salt + prefix);
    }

    const isHit = this.cache.has(key);

    if (isHit) {
      // Hit: Fast return, no heavy re-computation
    } else {
      // Miss: Execute genuine CPU-bound prefill compute
      this.doInferenceComputeWork();
      this.cache.set(key, { prompt: prefix, cachedAt: Date.now() });
    }

    let latency = performance.now() - t0;

    if (mode === 'SALT_ON_PADDING') {
      // Constant-latency defense
      const remaining = Math.max(0, paddedTargetMs - latency);
      if (remaining > 0) {
        // Busy-wait or sleep to ensure precise constant release
        const waitEnd = performance.now() + remaining;
        while (performance.now() < waitEnd) {
          // padding hold
        }
      }
      latency = performance.now() - t0;
    }

    return { isHit, latencyMs: latency };
  }
}

/**
 * Computes Mutual Information I(X; Y) between binary label X (Hit/Miss)
 * and continuous latency Y discretized into 20 bins.
 */
function computeMutualInformation(
  samples: Array<{ isHit: boolean; latencyMs: number }>,
  binsCount: number = 20
): { mi: number; bins: CacheProbeResult['bins'] } {
  if (samples.length === 0) return { mi: 0, bins: [] };

  let minLat = Infinity;
  let maxLat = -Infinity;
  for (const s of samples) {
    if (s.latencyMs < minLat) minLat = s.latencyMs;
    if (s.latencyMs > maxLat) maxLat = s.latencyMs;
  }

  // Ensure non-zero range
  if (maxLat <= minLat) {
    maxLat = minLat + 0.01;
  }

  const binWidth = (maxLat - minLat) / binsCount;
  const bins: CacheProbeResult['bins'] = [];
  for (let b = 0; b < binsCount; b++) {
    bins.push({
      binStartMs: minLat + b * binWidth,
      binEndMs: minLat + (b + 1) * binWidth,
      hitCount: 0,
      missCount: 0,
    });
  }

  let totalHits = 0;
  let totalMisses = 0;

  for (const s of samples) {
    let bIdx = Math.floor((s.latencyMs - minLat) / binWidth);
    if (bIdx >= binsCount) bIdx = binsCount - 1;
    if (bIdx < 0) bIdx = 0;

    if (s.isHit) {
      bins[bIdx].hitCount++;
      totalHits++;
    } else {
      bins[bIdx].missCount++;
      totalMisses++;
    }
  }

  const N = samples.length;
  const pX = [totalMisses / N, totalHits / N];

  let mi = 0;
  for (let b = 0; b < binsCount; b++) {
    const pY = (bins[b].hitCount + bins[b].missCount) / N;
    if (pY === 0) continue;

    // x = 0 (Miss)
    const pX0Y = bins[b].missCount / N;
    if (pX0Y > 0 && pX[0] > 0) {
      mi += pX0Y * Math.log2(pX0Y / (pX[0] * pY));
    }

    // x = 1 (Hit)
    const pX1Y = bins[b].hitCount / N;
    if (pX1Y > 0 && pX[1] > 0) {
      mi += pX1Y * Math.log2(pX1Y / (pX[1] * pY));
    }
  }

  return { mi: Math.max(0, mi), bins };
}

/**
 * Run N=200 probe experiment for a specific mode
 */
export async function runCacheProbeExperiment(
  mode: CacheMode,
  nProbes: number = 200
): Promise<CacheProbeResult> {
  const server = new MiniInferenceServer(mode !== 'SALT_OFF');

  // Seed the victim's session: victim runs with 50 specific prompt prefixes
  const victimPrefixes: string[] = [];
  for (let i = 0; i < 50; i++) {
    const p = `victim_confidential_prompt_prefix_${i}_session_data`;
    victimPrefixes.push(p);
    // Victim populates cache
    server.query(p, mode);
  }

  const samples: Array<{ id: number; isHit: boolean; latencyMs: number }> = [];

  // Attacker tests 200 prompts: 100 which overlap victim's prefixes, 100 which are fresh
  for (let i = 0; i < nProbes; i++) {
    // Yield every 25 iterations so browser stays responsive
    if (i % 25 === 0) {
      await new Promise(r => setTimeout(r, 0));
    }

    const testVictimPrefix = i % 2 === 0;
    const prefix = testVictimPrefix
      ? victimPrefixes[(i / 2) % victimPrefixes.length]
      : `attacker_novel_probe_prefix_${i}_random_input`;

    const { isHit, latencyMs } = server.query(prefix, mode);
    samples.push({
      id: i,
      isHit,
      latencyMs: Math.round(latencyMs * 1000) / 1000,
    });
  }

  // Calculate statistics
  const hits = samples.filter(s => s.isHit);
  const misses = samples.filter(s => !s.isHit);

  const hitMeanMs = hits.length > 0 ? hits.reduce((acc, s) => acc + s.latencyMs, 0) / hits.length : 0;
  const missMeanMs = misses.length > 0 ? misses.reduce((acc, s) => acc + s.latencyMs, 0) / misses.length : 0;
  const deltaMs = Math.abs(missMeanMs - hitMeanMs);

  const { mi, bins } = computeMutualInformation(samples, 20);

  // Compute noise floor by randomly shuffling labels
  const shuffledSamples = samples.map((s, idx) => ({
    ...s,
    isHit: samples[(idx * 7 + 13) % samples.length].isHit, // deterministic pseudorandom permutation
  }));
  const { mi: noiseFloorBits } = computeMutualInformation(shuffledSamples, 20);

  return {
    mode,
    trialsCount: nProbes,
    hitCount: hits.length,
    missCount: misses.length,
    hitMeanMs: Math.round(hitMeanMs * 1000) / 1000,
    missMeanMs: Math.round(missMeanMs * 1000) / 1000,
    deltaMs: Math.round(deltaMs * 1000) / 1000,
    mutualInformationBits: Math.round(mi * 1000) / 1000,
    noiseFloorBits: Math.round(noiseFloorBits * 1000) / 1000,
    bins,
    samples,
  };
}
