import { sha256Hex, bytesToHex, hexToBytes, generateRandomNonce } from './crypto';

export interface CommitmentRecord {
  party: 'Red' | 'Blue';
  commitmentHash: string; // H = SHA256(content + nonceHex)
  committedAt: number;
  revealed: boolean;
  revealedAt?: number;
  revealedContent?: string;
  revealedNonceHex?: string;
  verificationPassed?: boolean;
  verificationMessage?: string;
}

export class CommitRevealManager {
  private commitments: Map<'Red' | 'Blue', CommitmentRecord> = new Map();

  /**
   * Helper to create a commitment for a party
   */
  public static async createCommitment(content: string, nonceBytes?: Uint8Array): Promise<{
    nonceHex: string;
    commitmentHash: string;
  }> {
    const nonce = nonceBytes || generateRandomNonce(32);
    const nonceHex = bytesToHex(nonce);
    const commitmentHash = await sha256Hex(content + nonceHex);
    return {
      nonceHex,
      commitmentHash,
    };
  }

  /**
   * Record a commitment submitted to the gateway
   */
  public registerCommitment(party: 'Red' | 'Blue', commitmentHash: string): CommitmentRecord {
    const record: CommitmentRecord = {
      party,
      commitmentHash,
      committedAt: Date.now(),
      revealed: false,
    };
    this.commitments.set(party, record);
    return record;
  }

  public getCommitment(party: 'Red' | 'Blue'): CommitmentRecord | undefined {
    return this.commitments.get(party);
  }

  public getAllCommitments(): Record<'Red' | 'Blue', CommitmentRecord | null> {
    return {
      Red: this.commitments.get('Red') || null,
      Blue: this.commitments.get('Blue') || null,
    };
  }

  /**
   * Verify and reveal a commitment
   */
  public async reveal(
    party: 'Red' | 'Blue',
    content: string,
    nonceHex: string
  ): Promise<{ success: boolean; message: string; record: CommitmentRecord }> {
    const record = this.commitments.get(party);
    if (!record) {
      throw new Error(`No commitment registered for party ${party}`);
    }

    // Recompute H = SHA256(content + nonceHex)
    const computedHash = await sha256Hex(content + nonceHex);
    const matches = computedHash.toLowerCase() === record.commitmentHash.toLowerCase();

    record.revealed = true;
    record.revealedAt = Date.now();
    record.revealedContent = content;
    record.revealedNonceHex = nonceHex;
    record.verificationPassed = matches;
    record.verificationMessage = matches
      ? `Commitment match ✓ (${computedHash.slice(0, 16)}...)`
      : `MISMATCH ✗: Computed ${computedHash.slice(0, 16)}... does not match committed ${record.commitmentHash.slice(0, 16)}...`;

    return {
      success: matches,
      message: record.verificationMessage,
      record,
    };
  }
}
