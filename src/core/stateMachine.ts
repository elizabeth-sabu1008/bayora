/**
 * BAYORA Round State Machine
 * CREATED → COMMIT → LOCK → EXECUTE → SEAL → REVEAL → VERIFY → COMPLETED
 */

export type RoundState =
  | 'CREATED'
  | 'COMMIT'
  | 'LOCK'
  | 'EXECUTE'
  | 'SEAL'
  | 'REVEAL'
  | 'VERIFY'
  | 'COMPLETED';

export const ROUND_STATES: RoundState[] = [
  'CREATED',
  'COMMIT',
  'LOCK',
  'EXECUTE',
  'SEAL',
  'REVEAL',
  'VERIFY',
  'COMPLETED',
];

export const STATE_TRANSITIONS: Record<RoundState, RoundState[]> = {
  CREATED: ['COMMIT'],
  COMMIT: ['LOCK'],
  LOCK: ['EXECUTE'],
  EXECUTE: ['SEAL'],
  SEAL: ['REVEAL'],
  REVEAL: ['VERIFY'],
  VERIFY: ['COMPLETED'],
  COMPLETED: [],
};

export const STATE_DESCRIPTIONS: Record<RoundState, { title: string; subtitle: string; zoneAction: string }> = {
  CREATED: {
    title: 'Room Created',
    subtitle: 'Evaluation room initialized, gateway keypair established',
    zoneAction: 'Begin commitment phase for Red and Blue teams'
  },
  COMMIT: {
    title: 'Commit Phase',
    subtitle: 'Red submits attack set hash; Blue submits defense code hash (H = SHA256(content + nonce))',
    zoneAction: 'Both parties commit cryptographically'
  },
  LOCK: {
    title: 'Lock Phase',
    subtitle: 'Commitments sealed; gateway creates signed Ed25519 checkpoint; vault holds encrypted payloads',
    zoneAction: 'Gateway signs checkpoint #1, locks inputs'
  },
  EXECUTE: {
    title: 'Execution Phase',
    subtitle: 'Red queries shaped oracle under strict budget & constant latency deadline; Blue defenses execute in isolated iframe sandbox',
    zoneAction: 'Run attack tests through shaped oracle'
  },
  SEAL: {
    title: 'Seal Phase',
    subtitle: 'Audit ledger sealed; gateway signs checkpoint #2; oracle queries locked',
    zoneAction: 'Close execution zone and compute final ledger hash'
  },
  REVEAL: {
    title: 'Reveal Phase',
    subtitle: 'Red & Blue reveal plaintexts + nonces; gateway validates H match before granting decryption access',
    zoneAction: 'Verify pre-images against initial commitments'
  },
  VERIFY: {
    title: 'Verification Phase',
    subtitle: 'Auditor recomputes entire audit chain, re-verifies Ed25519 checkpoints and tamper-evident signatures',
    zoneAction: 'Run full mathematical verification'
  },
  COMPLETED: {
    title: 'Completed',
    subtitle: 'Round completed and certified. Download immutable evidence pack (ZIP)',
    zoneAction: 'Export tamper-evident evidence bundle'
  },
};

export class RoundStateMachine {
  private currentState: RoundState;

  constructor(initialState: RoundState = 'CREATED') {
    this.currentState = initialState;
  }

  public getState(): RoundState {
    return this.currentState;
  }

  public canTransitionTo(targetState: RoundState): boolean {
    const allowed = STATE_TRANSITIONS[this.currentState] || [];
    return allowed.includes(targetState);
  }

  public transitionTo(targetState: RoundState): { success: boolean; status: number; error?: string } {
    if (this.canTransitionTo(targetState)) {
      this.currentState = targetState;
      return { success: true, status: 200 };
    }
    return {
      success: false,
      status: 409,
      error: `Illegal state transition: Cannot move from ${this.currentState} to ${targetState}. Valid transitions: [${(STATE_TRANSITIONS[this.currentState] || []).join(', ')}]`,
    };
  }

  public getNextAllowedState(): RoundState | null {
    const allowed = STATE_TRANSITIONS[this.currentState] || [];
    return allowed.length > 0 ? allowed[0] : null;
  }

  public getProgressPercentage(): number {
    const index = ROUND_STATES.indexOf(this.currentState);
    return Math.round((index / (ROUND_STATES.length - 1)) * 100);
  }
}
