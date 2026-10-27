/**
 * Bayora Sealed AirLock API Client & Live Connectivity Manager
 * Implements real backend HTTP/SSE calls with automatic fail-safe fallback to client-side simulation.
 */

export interface GatewayConfig {
  RESPONSE_DEADLINE_MS: number;
  DEFAULT_ROUND_BUDGET: number;
  FIXED_MAX_TOKENS: number;
  CONSTANT_LATENCY_DEADLINE_SECONDS: number;
  ALLOWED_CLOCK_SKEW_SECONDS: number;
  AIRLOCK_STATUS: string;
}

const DEFAULT_CONFIG: GatewayConfig = {
  RESPONSE_DEADLINE_MS: 150,
  DEFAULT_ROUND_BUDGET: 50,
  FIXED_MAX_TOKENS: 128,
  CONSTANT_LATENCY_DEADLINE_SECONDS: 0.15,
  ALLOWED_CLOCK_SKEW_SECONDS: 60,
  AIRLOCK_STATUS: 'sealed',
};

export class BayoraApiClient {
  public baseUrl: string;
  private token: string | null = null;
  public isLive = false;
  public config: GatewayConfig = { ...DEFAULT_CONFIG };

  constructor(baseUrl = 'http://localhost:8000') {
    this.baseUrl = baseUrl;
  }

  public setToken(token: string) {
    this.token = token;
  }

  public getHeaders(): HeadersInit {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-Requested-With': 'XMLHttpRequest',
      'X-Client-Timestamp': Date.now().toString(),
    };
    if (this.token) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    return headers;
  }

  public async checkHealth(): Promise<{ live: boolean; config: GatewayConfig }> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 1200);
      const res = await fetch(`${this.baseUrl}/health`, {
        signal: controller.signal,
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
      });
      clearTimeout(timeoutId);

      if (res.ok) {
        this.isLive = true;
        try {
          const cfgRes = await fetch(`${this.baseUrl}/config`);
          if (cfgRes.ok) {
            const data = await cfgRes.json();
            this.config = { ...this.config, ...data };
          }
        } catch {
          // Keep defaults
        }
        return { live: true, config: this.config };
      }
    } catch {
      // Offline fallback
    }
    this.isLive = false;
    return { live: false, config: this.config };
  }

  // --- API CONTRACT METHODS ---

  public async createRound(name: string, budget = 50) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ name, round_budget: budget }),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  public async getRound(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}`, {
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  public async commitRed(roundId: string, hash: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/commit/red`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ commitment_hash: hash, hash }),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  public async commitBlue(roundId: string, hash: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/commit/blue`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ commitment_hash: hash, hash }),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  public async lockRound(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/lock`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  public async queryOracle(roundId: string, prompt: string, maxTokens = 128) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/oracle/query`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ prompt, max_tokens: maxTokens }),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  public async sealRound(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/seal`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  public async reveal(roundId: string, payload: { role?: string; content: any; nonce: string }) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/reveal`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify(payload),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  public async verifyRound(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/verify`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  public getEventsStream(roundId: string, onEvent: (evt: any) => void): () => void {
    if (!this.isLive || typeof EventSource === 'undefined') {
      return () => {};
    }
    try {
      const es = new EventSource(`${this.baseUrl}/rounds/${roundId}/events`);
      es.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          onEvent(data);
        } catch {}
      };
      return () => es.close();
    } catch {
      return () => {};
    }
  }

  public async evaluateAbac(role: string, action: string, resource: string, tokenAgeMinutes = 0, roundState?: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/authz/evaluate`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({
          role,
          action,
          resource,
          token_age_minutes: tokenAgeMinutes,
          round_state: roundState,
        }),
      });
      if (res.ok) return await res.json();
    } catch {
      // Fallback to legacy endpoint if present
      try {
        const res2 = await fetch(`${this.baseUrl}/abac/evaluate`, {
          method: 'POST',
          headers: this.getHeaders(),
          body: JSON.stringify({ role, action, resource, round_state: roundState }),
        });
        if (res2.ok) return await res2.json();
      } catch {}
    }
    return null;
  }

  public async runCacheProbe(salting: boolean, samples = 200) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/lab/cache-probe`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ salting: salting ? 'on' : 'off', n: samples }),
      });
      if (res.ok) return await res.json();
      // Try /cache-lab/probe fallback
      const res2 = await fetch(`${this.baseUrl}/cache-lab/probe`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ salting, samples }),
      });
      if (res2.ok) return await res2.json();
    } catch {}
    return null;
  }

  public async tamperCopy(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/demo/tamper-copy`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ round_id: roundId }),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  public async restoreCopy(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/demo/restore`, {
        method: 'POST',
        headers: this.getHeaders(),
        body: JSON.stringify({ round_id: roundId }),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  public async runPytestSuite() {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/tests/pytest`, {
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Acquire a real JWT token for a given role via /auth/token */
  public async loginAs(role: 'admin' | 'red' | 'blue' | 'auditor'): Promise<string | null> {
    try {
      const res = await fetch(`${this.baseUrl}/auth/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest' },
        body: JSON.stringify({
          sub: `${role}-operator`,
          role: role,
          zone: role === 'admin' ? 'gateway' : `zone-${role}`,
          expires_in_seconds: 600,
        }),
      });
      if (res.ok) {
        const data = await res.json();
        this.token = data.access_token;
        return data.access_token;
      }
    } catch {}
    return null;
  }

  /** Advance round from CREATED -> COMMIT */
  public async startCommitPhase(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/start`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  /** Get active model backend status */
  public async getModelStatus() {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/model/status`, {
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Tamper a chain event (demo tool) */
  public async tamperEvidence(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/evidence/tamper`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Verify hash chain and Ed25519 checkpoint */
  public async verifyEvidence(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/evidence/verify`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Get findings via disclosure gate */
  public async getFindings(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/findings`, {
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  /** Download evidence pack ZIP */
  public async downloadEvidence(roundId: string): Promise<Blob | null> {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/evidence/pack`, {
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.blob();
    } catch {}
    return null;
  }

  /** Run ABAC deny matrix test */
  public async runDenyMatrix() {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/authz/deny-matrix`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Get audit events from backend */
  public async getEvents(roundId?: string, limit = 100) {
    if (!this.isLive) return null;
    try {
      const params = new URLSearchParams();
      if (roundId) params.set('round_id', roundId);
      params.set('limit', limit.toString());
      const res = await fetch(`${this.baseUrl}/events?${params}`, {
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Create Ed25519 checkpoint at SEAL */
  public async createCheckpoint(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/checkpoint`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }

  /** Verify model weights attestation */
  public async verifyWeightsAttestation(roundId: string) {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/rounds/${roundId}/attestation/verify`, {
        method: 'POST',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
      const err = await res.json().catch(() => ({}));
      return { error: true, status: res.status, message: err.message || err.detail };
    } catch {}
    return null;
  }

  /** Check zero-trust isolation boundaries */
  public async checkIsolation() {
    if (!this.isLive) return null;
    try {
      const res = await fetch(`${this.baseUrl}/system/isolation-check`, {
        method: 'GET',
        headers: this.getHeaders(),
      });
      if (res.ok) return await res.json();
    } catch {}
    return null;
  }
}

export const apiClient = new BayoraApiClient();
