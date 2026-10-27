import {
  generateEd25519KeyPair,
  signEd25519,
  verifyEd25519,
  canonicalJSON,
  bytesToHex,
} from './crypto';
import { Role, Action, Resource, ACCESS_POLICY } from './policy';
import { RoundStateMachine, RoundState } from './stateMachine';
import { AuditChain, AuditEvent } from './auditChain';
import { CommitRevealManager } from './commitReveal';
import { GatewayVault } from './vault';
import { ShapedOracle, OracleRedResponse } from './oracle';
import { SealedRunner } from './sealedRunner';

export interface RoleTokenPayload {
  role: Role;
  exp: number;
  issuedAt: number;
  jti: string;
}

export interface GatewayCallRecord {
  id: string;
  timestamp: number;
  role: Role | 'Unknown';
  action: Action;
  resource: Resource;
  status: number;
  latencyMs: number;
  message?: string;
}

export interface GatewayResponse<T = any> {
  status: number;
  success: boolean;
  data?: T;
  error?: string;
  eventHash?: string;
}

export class SecurityGateway {
  private gatewayPrivateKey: Uint8Array;
  private gatewayPublicKey: Uint8Array;
  public readonly gatewayPublicKeyHex: string;

  public readonly stateMachine: RoundStateMachine;
  public readonly auditChain: AuditChain;
  public readonly commitReveal: CommitRevealManager;
  public readonly vault: GatewayVault;
  public readonly sealedRunner: SealedRunner;
  public oracle: ShapedOracle;

  private callLog: GatewayCallRecord[] = [];
  private listeners: Array<(record: GatewayCallRecord) => void> = [];

  constructor(initialState: RoundState = 'CREATED') {
    const keypair = generateEd25519KeyPair();
    this.gatewayPrivateKey = keypair.secretKey;
    this.gatewayPublicKey = keypair.publicKey;
    this.gatewayPublicKeyHex = keypair.publicKeyHex;

    this.stateMachine = new RoundStateMachine(initialState);
    this.auditChain = new AuditChain();
    this.commitReveal = new CommitRevealManager();
    this.vault = new GatewayVault();
    this.sealedRunner = new SealedRunner();
    this.oracle = new ShapedOracle(this.sealedRunner);

    // Initial audit event
    this.auditChain.appendEvent('Gateway', 'gateway', 'ROOM_INITIALIZED', {
      gatewayPublicKey: this.gatewayPublicKeyHex,
      initialState,
    });
  }

  public subscribe(fn: (record: GatewayCallRecord) => void): () => void {
    this.listeners.push(fn);
    return () => {
      this.listeners = this.listeners.filter(l => l !== fn);
    };
  }

  public getCallLogs(): GatewayCallRecord[] {
    return [...this.callLog];
  }

  /**
   * Issues a cryptographically signed Ed25519 role token
   */
  public async issueRoleToken(role: Role, ttlSeconds: number = 3600): Promise<string> {
    const issuedAt = Date.now();
    const payload: RoleTokenPayload = {
      role,
      issuedAt,
      exp: issuedAt + ttlSeconds * 1000,
      jti: 'tok_' + Math.random().toString(36).slice(2) + Date.now().toString(36),
    };

    const payloadJson = canonicalJSON(payload);
    const signatureHex = await signEd25519(payloadJson, this.gatewayPrivateKey);

    // Token format: base64(payloadJson).signatureHex
    const encodedPayload = btoa(payloadJson);
    return `${encodedPayload}.${signatureHex}`;
  }

  /**
   * Verifies an Ed25519 signed role token
   */
  public async verifyRoleToken(tokenStr: string): Promise<{ valid: boolean; role?: Role; error?: string }> {
    try {
      const parts = tokenStr.split('.');
      if (parts.length !== 2) {
        return { valid: false, error: 'Malformed token structure' };
      }

      const [encodedPayload, signatureHex] = parts;
      const payloadJson = atob(encodedPayload);
      const payload: RoleTokenPayload = JSON.parse(payloadJson);

      if (Date.now() > payload.exp) {
        return { valid: false, error: 'Role token has expired' };
      }

      const isValid = await verifyEd25519(signatureHex, payloadJson, this.gatewayPublicKey);
      if (!isValid) {
        return { valid: false, error: 'Invalid gateway Ed25519 signature' };
      }

      return { valid: true, role: payload.role };
    } catch (err: any) {
      return { valid: false, error: err?.message || 'Token verification error' };
    }
  }

  /**
   * Primary entry point: ONLY path between zones.
   * Checks token, policy, state machine, appends to audit ledger, returns response.
   */
  public async invoke<T = any>(
    tokenStr: string,
    action: Action,
    resource: Resource,
    params?: any
  ): Promise<GatewayResponse<T>> {
    const t0 = performance.now();
    const callId = 'call_' + Math.random().toString(36).slice(2, 9);

    // 1. Verify Role Token
    const tokenResult = await this.verifyRoleToken(tokenStr);
    if (!tokenResult.valid || !tokenResult.role) {
      const status = 401;
      const error = tokenResult.error || 'Unauthorized role token';
      await this.recordCall(callId, 'Unknown', action, resource, status, performance.now() - t0, error);
      return { status, success: false, error };
    }

    const role = tokenResult.role;
    const currentState = this.stateMachine.getState();

    // 2. Check ABAC Policy
    const rule = ACCESS_POLICY[action]?.[resource];
    if (!rule || !rule.allowedRoles.includes(role)) {
      // Special case: check if post-reveal read on vault payloads is permitted
      const isPostReveal = ['REVEAL', 'VERIFY', 'COMPLETED'].includes(currentState);
      const isVaultRead = action === 'read_vault_payload' &&
        (resource === 'red_vault_attack_set' || resource === 'blue_vault_defense_code');

      if (!(isVaultRead && isPostReveal)) {
        const status = 403;
        const error = `403 Forbidden: Role [${role}] is not authorized to execute [${action}] on [${resource}]`;
        await this.recordCall(callId, role, action, resource, status, performance.now() - t0, error);
        return { status, success: false, error };
      }
    }

    // 3. Check State-Based Policy
    if (rule.allowedStates && !rule.allowedStates.includes(currentState)) {
      const status = 409;
      const error = `409 Conflict: Action [${action}] requires state in [${rule.allowedStates.join(', ')}], current state is [${currentState}]`;
      await this.recordCall(callId, role, action, resource, status, performance.now() - t0, error);
      return { status, success: false, error };
    }

    // 4. Execute Action
    try {
      let resultData: any = null;

      switch (action) {
        case 'transition_state': {
          const targetState = params?.targetState as RoundState;
          const transition = this.stateMachine.transitionTo(targetState);
          if (!transition.success) {
            await this.recordCall(callId, role, action, resource, transition.status, performance.now() - t0, transition.error);
            return { status: transition.status, success: false, error: transition.error };
          }

          // Handle automatic checkpoints
          if (targetState === 'LOCK') {
            await this.auditChain.createCheckpoint('LOCK', this.gatewayPrivateKey, this.gatewayPublicKeyHex);
          } else if (targetState === 'SEAL') {
            await this.auditChain.createCheckpoint('SEAL', this.gatewayPrivateKey, this.gatewayPublicKeyHex);
          }

          resultData = { newState: targetState };
          break;
        }

        case 'submit_commitment': {
          const party = resource === 'red_commitment' ? 'Red' : 'Blue';
          const commitmentHash = params?.commitmentHash;
          if (!commitmentHash) {
            throw new Error('Missing commitmentHash');
          }
          const record = this.commitReveal.registerCommitment(party, commitmentHash);
          resultData = record;
          break;
        }

        case 'store_vault_payload': {
          const target = resource === 'red_vault_attack_set' ? 'red_attacks' : 'blue_defense';
          const plaintext = params?.plaintext;
          if (typeof plaintext !== 'string') {
            throw new Error('Missing payload string');
          }

          // If storing blue defense, also load into sandbox runner
          if (target === 'blue_defense') {
            await this.sealedRunner.setDefenseCode(plaintext);
          }

          const entry = await this.vault.storePayload(target, plaintext);
          resultData = {
            target,
            stored: true,
            ciphertextSnippet: entry.ciphertext.slice(0, 32) + '...',
            iv: entry.iv,
            keyFingerprint: entry.keyFingerprint,
          };
          break;
        }

        case 'read_vault_payload': {
          const target = resource === 'red_vault_attack_set' ? 'red_attacks' : 'blue_defense';
          const isPostReveal = ['REVEAL', 'VERIFY', 'COMPLETED'].includes(currentState);

          if (!isPostReveal) {
            // Pre-reveal: only owning role can read
            if ((target === 'red_attacks' && role !== 'Red') || (target === 'blue_defense' && role !== 'Blue')) {
              const status = 403;
              const error = `403 Forbidden: Sealed in vault. Target [${target}] cannot be accessed by [${role}] prior to REVEAL phase.`;
              await this.recordCall(callId, role, action, resource, status, performance.now() - t0, error);
              return { status, success: false, error };
            }
          }

          const plaintext = await this.vault.internalDecrypt(target);
          resultData = { target, plaintext };
          break;
        }

        case 'query_oracle': {
          const prompt = params?.prompt;
          if (typeof prompt !== 'string') {
            throw new Error('Missing prompt in oracle query');
          }

          const { redResponse } = await this.oracle.query(prompt);
          resultData = redResponse;
          break;
        }

        case 'reveal_commitment': {
          const party = resource === 'red_commitment' ? 'Red' : 'Blue';
          const content = params?.content;
          const nonceHex = params?.nonceHex;
          if (typeof content !== 'string' || typeof nonceHex !== 'string') {
            throw new Error('Missing content or nonceHex in reveal');
          }

          const revealResult = await this.commitReveal.reveal(party, content, nonceHex);
          if (revealResult.success) {
            // Unlock vault entry for post-reveal transparency
            await this.vault.unlockVault(party === 'Red' ? 'red_attacks' : 'blue_defense');
          }
          resultData = revealResult;
          break;
        }

        case 'verify_audit_chain': {
          const events = this.auditChain.getEvents();
          const checkpoints = this.auditChain.getCheckpoints();
          const verification = await AuditChain.verify(events, checkpoints, this.gatewayPublicKeyHex);
          resultData = verification;
          break;
        }

        case 'read_audit_chain': {
          resultData = {
            events: this.auditChain.getEvents(),
            checkpoints: this.auditChain.getCheckpoints(),
            latestHash: this.auditChain.getLatestHash(),
          };
          break;
        }

        case 'run_sandbox_isolation': {
          const results = await this.sealedRunner.runIsolationChecks();
          resultData = results;
          break;
        }

        default:
          resultData = { ok: true };
      }

      const latencyMs = performance.now() - t0;
      const event = await this.recordCall(callId, role, action, resource, 200, latencyMs, undefined, params);

      return {
        status: 200,
        success: true,
        data: resultData,
        eventHash: event.entry_hash,
      };
    } catch (err: any) {
      const latencyMs = performance.now() - t0;
      const error = err?.message || 'Internal gateway execution error';
      await this.recordCall(callId, role, action, resource, 500, latencyMs, error);
      return { status: 500, success: false, error };
    }
  }

  private async recordCall(
    callId: string,
    role: Role | 'Unknown',
    action: Action,
    resource: Resource,
    status: number,
    latencyMs: number,
    error?: string,
    params?: any
  ): Promise<AuditEvent> {
    const record: GatewayCallRecord = {
      id: callId,
      timestamp: Date.now(),
      role,
      action,
      resource,
      status,
      latencyMs: Math.round(latencyMs * 10) / 10,
      message: error,
    };

    this.callLog.unshift(record);
    if (this.callLog.length > 300) {
      this.callLog.pop();
    }

    // Notify UI listeners
    for (const listener of this.listeners) {
      try {
        listener(record);
      } catch (e) {
        // ignore
      }
    }

    // Append to audit chain
    const sanitizedParams = params ? { ...params } : {};
    // Redact large payloads from event payload snippet for readability while preserving hash integrity
    if (sanitizedParams.plaintext && sanitizedParams.plaintext.length > 60) {
      sanitizedParams.plaintextSnippet = sanitizedParams.plaintext.slice(0, 40) + '...';
      delete sanitizedParams.plaintext;
    }

    return this.auditChain.appendEvent(
      role === 'Unknown' ? 'Gateway' : role,
      `${role.toLowerCase()}-zone`,
      `API_${action.toUpperCase()}`,
      {
        resource,
        status,
        error: error || null,
        params: sanitizedParams,
      },
      status
    );
  }
}
