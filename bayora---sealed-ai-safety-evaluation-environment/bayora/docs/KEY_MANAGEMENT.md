# Bayora Key Management Architecture

This document specifies the cryptographic key lifecycle, segregation of duties, and rotation procedures for the Bayora evaluation platform.

---

## 1. Segregation of Cryptographic Duties

| Key / Secret | Held Exclusively By | Purpose | Permitted Operations |
| :--- | :--- | :--- | :--- |
| **Evidence Authority Private Key (Ed25519)** | `zone-evidence` container ONLY | Signing round checkpoints at `SEAL` | Sign canonical audit chain head |
| **Evidence Authority Public Key (Ed25519)** | `gateway`, Dashboard, Auditors | Verifying chain integrity offline | Checkpoint verification |
| **Blue Defense Signing Key (Ed25519)** | `zone-blue` container ONLY | Signing defense code before `LOCK` | Defense artifact verification |
| **Red Payload Vault Key (AES-256-GCM)** | `zone-red` container ONLY | Encrypting attack sets at rest | Seal/unseal adversarial prompts |
| **Gateway JWT Airlock Secret** | `gateway` container ONLY | Minting short-lived session tokens | Authentication and ABAC enforcement |

> **CRITICAL SECURITY INVARIANT:**
> The Gateway container **NEVER** holds the Ed25519 private keys. It only receives the signed checkpoint from the Evidence Zone RPC call (`POST http://zone-evidence:8004/checkpoint`). Even if the gateway is fully compromised, an attacker cannot forge signed audit checkpoints.

---

## 2. Key Generation & Lifecycle

### Ed25519 Checkpoint Keypair
1. **Genesis Generation**:
   The evidence service generates a cryptographic keypair on initial container bootstrap if no volume key is mounted:
   ```python
   from cryptography.hazmat.primitives.asymmetric import ed25519
   private_key = ed25519.Ed25519PrivateKey.generate()
   public_key = private_key.public_key()
   ```
2. **Storage**:
   - Private key is stored at `/evidence/keys/evidence_ed25519.pem` with file permissions `0400` owned by `nobody:nogroup`.
   - Public key is exported to `/evidence/keys/evidence_ed25519.pub` and shared with the Gateway and public auditors.
3. **# PRODUCTION Target**:
   - In production, keys are managed inside a **Hardware Security Module (HSM)** or cloud KMS (e.g. AWS CloudHSM / Google Cloud KMS / YubiHSM 2).
   - Signatures are generated via PKCS#11 without ever exposing private key bytes to memory.

---

## 3. Key Rotation Procedure

1. **Epoch-Based Key Versioning**:
   Every checkpoint includes the `key_id` in its canonical header:
   ```json
   {
     "key_id": "bayora-audit-2026-q4",
     "algorithm": "Ed25519",
     "timestamp": "2026-10-24T22:00:00Z",
     "chain_head_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
   }
   ```
2. **Grace Period**:
   Previous public keys are retained in the auditor keyring (`/evidence/keyring/`) to allow offline verification of past evidence packs indefinitely.
3. **Emergency Revocation**:
   If an evidence key is suspected to be compromised:
   - A revocation certificate signed by the root security authority is appended to `anchor.log`.
   - The Gateway immediately transitions active rounds to `ABORTED`.
   - A new keypair is generated and verified across independent nodes.
