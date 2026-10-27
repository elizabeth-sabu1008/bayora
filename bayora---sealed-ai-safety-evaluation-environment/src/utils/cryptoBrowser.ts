/**
 * Browser-side cryptographic utility matching bayora/common/crypto.py
 */

export function canonicalJson(data: any): string {
  if (data === null || typeof data !== 'object') {
    return JSON.stringify(data);
  }
  if (Array.isArray(data)) {
    return '[' + data.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(data).sort();
  const entries = keys.map(k => `"${k}":${canonicalJson(data[k])}`);
  return '{' + entries.join(',') + '}';
}

export function generateNonceHex(): string {
  const bytes = new Uint8Array(32);
  window.crypto.getRandomValues(bytes);
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Hex(message: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function computeCommitmentHash(payload: any, nonce: string): Promise<string> {
  const canon = canonicalJson(payload);
  const preimage = `${canon}:${nonce}`;
  return sha256Hex(preimage);
}
