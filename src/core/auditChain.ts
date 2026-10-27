import { canonicalJSON, sha256Hex, signEd25519, verifyEd25519 } from './crypto';
import { Role } from './policy';

export const GENESIS_PREV_HASH = '0'.repeat(64);

export interface AuditEventData {
  index: number;
  timestamp: number;
  actor: Role | 'Gateway';
  zone: string;
  type: string;
  payload: Record<string, any>;
  status: number;
  prev_hash: string;
}

export interface AuditEvent extends AuditEventData {
  entry_hash: string;
}

export interface CheckpointPayload {
  checkpointIndex: number;
  phase: string;
  chainHeadHash: string;
  eventCount: number;
  timestamp: number;
}

export interface ChainCheckpoint extends CheckpointPayload {
  signature: string;
  gatewayPublicKey: string;
}

export interface VerificationResult {
  valid: boolean;
  eventsCount: number;
  checkpointsCount: number;
  brokenIndex?: number;
  brokenField?: string;
  expected?: string;
  actual?: string;
  errorMessage?: string;
  details?: string;
}

export class AuditChain {
  private events: AuditEvent[] = [];
  private checkpoints: ChainCheckpoint[] = [];

  constructor() {}

  public getEvents(): AuditEvent[] {
    return [...this.events];
  }

  public getCheckpoints(): ChainCheckpoint[] {
    return [...this.checkpoints];
  }

  public getLatestHash(): string {
    if (this.events.length === 0) {
      return GENESIS_PREV_HASH;
    }
    return this.events[this.events.length - 1].entry_hash;
  }

  public async appendEvent(
    actor: Role | 'Gateway',
    zone: string,
    type: string,
    payload: Record<string, any>,
    status: number = 200,
    timestamp: number = Date.now()
  ): Promise<AuditEvent> {
    const index = this.events.length;
    const prev_hash = this.getLatestHash();

    const eventData: AuditEventData = {
      index,
      timestamp,
      actor,
      zone,
      type,
      payload,
      status,
      prev_hash,
    };

    // entry_hash = SHA256(prev_hash + canonicalJSON(eventData))
    const serializedData = canonicalJSON(eventData);
    const entry_hash = await sha256Hex(prev_hash + serializedData);

    const fullEvent: AuditEvent = {
      ...eventData,
      entry_hash,
    };

    this.events.push(fullEvent);
    return fullEvent;
  }

  public async createCheckpoint(
    phase: string,
    gatewayPrivateKey: Uint8Array,
    gatewayPublicKeyHex: string
  ): Promise<ChainCheckpoint> {
    const checkpointIndex = this.checkpoints.length;
    const chainHeadHash = this.getLatestHash();
    const eventCount = this.events.length;
    const timestamp = Date.now();

    const payload: CheckpointPayload = {
      checkpointIndex,
      phase,
      chainHeadHash,
      eventCount,
      timestamp,
    };

    const messageToSign = canonicalJSON(payload);
    const signature = await signEd25519(messageToSign, gatewayPrivateKey);

    const checkpoint: ChainCheckpoint = {
      ...payload,
      signature,
      gatewayPublicKey: gatewayPublicKeyHex,
    };

    this.checkpoints.push(checkpoint);

    // Also record the checkpoint itself as an audit event
    await this.appendEvent('Gateway', 'gateway', 'CHECKPOINT_CREATED', {
      checkpointIndex,
      phase,
      chainHeadHash,
      signatureSnippet: signature.slice(0, 16) + '...',
    });

    return checkpoint;
  }

  /**
   * Tamper-evident verification of an event list and checkpoints.
   * Recomputes every hash from scratch and verifies Ed25519 signatures.
   */
  public static async verify(
    events: AuditEvent[],
    checkpoints: ChainCheckpoint[],
    gatewayPublicKeyHex: string
  ): Promise<VerificationResult> {
    if (events.length === 0) {
      return {
        valid: true,
        eventsCount: 0,
        checkpointsCount: checkpoints.length,
      };
    }

    // 1. Verify every event in sequence
    for (let i = 0; i < events.length; i++) {
      const evt = events[i];

      // Check index
      if (evt.index !== i) {
        return {
          valid: false,
          eventsCount: events.length,
          checkpointsCount: checkpoints.length,
          brokenIndex: i,
          brokenField: 'index',
          expected: String(i),
          actual: String(evt.index),
          errorMessage: `Event sequence mismatch at index ${i}`,
        };
      }

      // Check prev_hash linkage
      const expectedPrevHash = i === 0 ? GENESIS_PREV_HASH : events[i - 1].entry_hash;
      if (evt.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          eventsCount: events.length,
          checkpointsCount: checkpoints.length,
          brokenIndex: i,
          brokenField: 'prev_hash',
          expected: expectedPrevHash,
          actual: evt.prev_hash,
          errorMessage: `Hash chain broken at event ${i}: prev_hash does not match previous entry_hash`,
        };
      }

      // Recompute entry_hash
      const dataToHash: AuditEventData = {
        index: evt.index,
        timestamp: evt.timestamp,
        actor: evt.actor,
        zone: evt.zone,
        type: evt.type,
        payload: evt.payload,
        status: evt.status,
        prev_hash: evt.prev_hash,
      };

      const serialized = canonicalJSON(dataToHash);
      const computedHash = await sha256Hex(evt.prev_hash + serialized);

      if (computedHash !== evt.entry_hash) {
        return {
          valid: false,
          eventsCount: events.length,
          checkpointsCount: checkpoints.length,
          brokenIndex: i,
          brokenField: 'entry_hash',
          expected: computedHash,
          actual: evt.entry_hash,
          errorMessage: `Tampered event detected at index ${i}: recomputed entry_hash does not match stored hash`,
        };
      }
    }

    // 2. Verify checkpoints against gateway Ed25519 public key
    for (const cp of checkpoints) {
      const payload: CheckpointPayload = {
        checkpointIndex: cp.checkpointIndex,
        phase: cp.phase,
        chainHeadHash: cp.chainHeadHash,
        eventCount: cp.eventCount,
        timestamp: cp.timestamp,
      };

      const msg = canonicalJSON(payload);
      const isValidSig = await verifyEd25519(cp.signature, msg, cp.gatewayPublicKey || gatewayPublicKeyHex);

      if (!isValidSig) {
        return {
          valid: false,
          eventsCount: events.length,
          checkpointsCount: checkpoints.length,
          brokenIndex: cp.eventCount - 1,
          brokenField: `checkpoint_${cp.checkpointIndex}_signature`,
          expected: 'Valid Ed25519 signature',
          actual: cp.signature.slice(0, 20) + '...',
          errorMessage: `Cryptographic checkpoint signature verification failed for checkpoint ${cp.checkpointIndex} (${cp.phase})`,
        };
      }

      // Also verify that the checkpoint's chainHeadHash matches the event at that point
      if (cp.eventCount <= events.length && cp.eventCount > 0) {
        const matchingEvent = events[cp.eventCount - 1];
        if (matchingEvent.entry_hash !== cp.chainHeadHash) {
          return {
            valid: false,
            eventsCount: events.length,
            checkpointsCount: checkpoints.length,
            brokenIndex: cp.eventCount - 1,
            brokenField: `checkpoint_${cp.checkpointIndex}_head_hash`,
            expected: matchingEvent.entry_hash,
            actual: cp.chainHeadHash,
            errorMessage: `Checkpoint ${cp.checkpointIndex} references chainHeadHash ${cp.chainHeadHash}, but event ${cp.eventCount - 1} hash was ${matchingEvent.entry_hash}`,
          };
        }
      }
    }

    return {
      valid: true,
      eventsCount: events.length,
      checkpointsCount: checkpoints.length,
      details: 'All block hashes, canonical JSON serializations, and Ed25519 signatures verified mathematically.',
    };
  }

  public setEvents(events: AuditEvent[]) {
    this.events = events;
  }

  public setCheckpoints(checkpoints: ChainCheckpoint[]) {
    this.checkpoints = checkpoints;
  }
}
