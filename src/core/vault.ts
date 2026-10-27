import { generateAesKey, encryptAesGcm, decryptAesGcm, exportKeyToHex } from './crypto';

export interface VaultEntry {
  target: 'red_attacks' | 'blue_defense';
  ciphertext: string;
  iv: string;
  timestamp: number;
  unlocked: boolean;
  plaintextCache?: string;
  keyFingerprint: string;
}

export class GatewayVault {
  private redKey: CryptoKey | null = null;
  private blueKey: CryptoKey | null = null;
  private redKeyFingerprint: string = '';
  private blueKeyFingerprint: string = '';

  private entries: Map<'red_attacks' | 'blue_defense', VaultEntry> = new Map();

  public async initialize(): Promise<void> {
    this.redKey = await generateAesKey();
    this.blueKey = await generateAesKey();

    const redHex = await exportKeyToHex(this.redKey);
    const blueHex = await exportKeyToHex(this.blueKey);

    this.redKeyFingerprint = redHex.slice(0, 16) + '...';
    this.blueKeyFingerprint = blueHex.slice(0, 16) + '...';
  }

  public async storePayload(
    target: 'red_attacks' | 'blue_defense',
    plaintext: string
  ): Promise<VaultEntry> {
    if (!this.redKey || !this.blueKey) {
      await this.initialize();
    }

    const key = target === 'red_attacks' ? this.redKey! : this.blueKey!;
    const fingerprint = target === 'red_attacks' ? this.redKeyFingerprint : this.blueKeyFingerprint;

    const { ciphertext, iv } = await encryptAesGcm(plaintext, key);

    const entry: VaultEntry = {
      target,
      ciphertext,
      iv,
      timestamp: Date.now(),
      unlocked: false,
      keyFingerprint: fingerprint,
    };

    this.entries.set(target, entry);
    return entry;
  }

  public getEntryMetadata(target: 'red_attacks' | 'blue_defense'): {
    stored: boolean;
    ciphertextSnippet?: string;
    iv?: string;
    keyFingerprint?: string;
    unlocked: boolean;
    timestamp?: number;
  } {
    const entry = this.entries.get(target);
    if (!entry) {
      return { stored: false, unlocked: false };
    }
    return {
      stored: true,
      ciphertextSnippet: entry.ciphertext.slice(0, 24) + '...' + entry.ciphertext.slice(-12),
      iv: entry.iv,
      keyFingerprint: entry.keyFingerprint,
      unlocked: entry.unlocked,
      timestamp: entry.timestamp,
    };
  }

  /**
   * Internal gateway decryption (e.g. for sealed runner execution)
   */
  public async internalDecrypt(target: 'red_attacks' | 'blue_defense'): Promise<string> {
    const entry = this.entries.get(target);
    if (!entry) {
      throw new Error(`Vault target ${target} has not been stored`);
    }

    const key = target === 'red_attacks' ? this.redKey! : this.blueKey!;
    return decryptAesGcm(entry.ciphertext, entry.iv, key);
  }

  /**
   * Unlock vault after REVEAL phase
   */
  public async unlockVault(target: 'red_attacks' | 'blue_defense'): Promise<string> {
    const decrypted = await this.internalDecrypt(target);
    const entry = this.entries.get(target)!;
    entry.unlocked = true;
    entry.plaintextCache = decrypted;
    return decrypted;
  }

  public isUnlocked(target: 'red_attacks' | 'blue_defense'): boolean {
    return this.entries.get(target)?.unlocked ?? false;
  }
}
