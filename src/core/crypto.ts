import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';

// Configure synchronous sha512 for @noble/ed25519
if (ed.hashes) {
  ed.hashes.sha512 = sha512;
}

/**
 * Deterministic JSON stringifier (sorts object keys alphabetically, handles arrays and primitives)
 */
export function canonicalJSON(value: any): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return '[' + value.map(item => canonicalJSON(item)).join(',') + ']';
  }

  const sortedKeys = Object.keys(value).sort();
  const pairs = sortedKeys.map(k => {
    return JSON.stringify(k) + ':' + canonicalJSON(value[k]);
  });
  return '{' + pairs.join(',') + '}';
}

/**
 * Convert byte array to hexadecimal string
 */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

/**
 * Convert hexadecimal string to byte array
 */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * SHA-256 hash using the Web Crypto API
 */
export async function sha256Hex(data: string | Uint8Array): Promise<string> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digestBuffer = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
  return bytesToHex(new Uint8Array(digestBuffer));
}

export async function sha256Bytes(data: string | Uint8Array): Promise<Uint8Array> {
  const bytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const digestBuffer = await crypto.subtle.digest('SHA-256', bytes as unknown as BufferSource);
  return new Uint8Array(digestBuffer);
}

/**
 * Generate 32-byte cryptographically secure random nonce
 */
export function generateRandomNonce(length: number = 32): Uint8Array {
  const nonce = new Uint8Array(length);
  crypto.getRandomValues(nonce);
  return nonce;
}

/**
 * Generate cryptographically secure random canary secret string (CANARY- + 16 hex chars)
 */
export function generateCanarySecret(): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  return 'CANARY-' + bytesToHex(bytes).toUpperCase();
}

/**
 * Web Crypto AES-GCM 256-bit encryption for Vault
 */
export async function generateAesKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

export async function encryptAesGcm(plaintext: string, key: CryptoKey): Promise<{ ciphertext: string; iv: string }> {
  const iv = new Uint8Array(12);
  crypto.getRandomValues(iv);
  const encoded = new TextEncoder().encode(plaintext);

  const cipherBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv,
    },
    key,
    encoded
  );

  return {
    ciphertext: bytesToHex(new Uint8Array(cipherBuffer)),
    iv: bytesToHex(iv),
  };
}

export async function decryptAesGcm(ciphertextHex: string, ivHex: string, key: CryptoKey): Promise<string> {
  const ciphertext = hexToBytes(ciphertextHex);
  const iv = hexToBytes(ivHex);

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: iv as unknown as BufferSource,
    },
    key,
    ciphertext as unknown as BufferSource
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/**
 * Export AES key to raw hex string
 */
export async function exportKeyToHex(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return bytesToHex(new Uint8Array(raw));
}

/**
 * Import AES key from raw hex string
 */
export async function importKeyFromHex(hex: string): Promise<CryptoKey> {
  const raw = hexToBytes(hex);
  return crypto.subtle.importKey(
    'raw',
    raw as unknown as BufferSource,
    { name: 'AES-GCM' },
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Ed25519 Signatures using @noble/ed25519
 */
export interface Ed25519KeyPair {
  secretKey: Uint8Array;
  publicKey: Uint8Array;
  publicKeyHex: string;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  const keypair = ed.keygen();
  return {
    secretKey: keypair.secretKey,
    publicKey: keypair.publicKey,
    publicKeyHex: bytesToHex(keypair.publicKey),
  };
}

export async function signEd25519(message: string | Uint8Array, secretKey: Uint8Array): Promise<string> {
  const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
  const sig = await ed.signAsync(msgBytes, secretKey);
  return bytesToHex(sig);
}

export async function verifyEd25519(signatureHex: string, message: string | Uint8Array, publicKey: Uint8Array | string): Promise<boolean> {
  try {
    const sigBytes = hexToBytes(signatureHex);
    const pubBytes = typeof publicKey === 'string' ? hexToBytes(publicKey) : publicKey;
    const msgBytes = typeof message === 'string' ? new TextEncoder().encode(message) : message;
    return await ed.verifyAsync(sigBytes, msgBytes, pubBytes);
  } catch (err) {
    return false;
  }
}
