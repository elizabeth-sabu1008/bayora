"""
Bayora Red Payload Vault
Stores adversarial payloads encrypted at rest using AES-256-GCM.
The encryption key remains strictly isolated inside the Red Zone container.
Gateway never stores or logs the plaintext payloads at rest, only their SHA-256 hashes.
"""
# PRODUCTION: In production, the key is bound to a TPM 2.0 PCR state or AWS Nitro Enclave
# KMS attestation policy that refuses decryption outside the validated enclave measurement.

import os
import hashlib
from typing import Dict, Any, Tuple, Optional
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from common.crypto import (
    generate_aes_key,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    canonical_json,
)


class RedPayloadVault:
    def __init__(self, key_path: Optional[str] = None):
        self.key_path = key_path or "/tmp/red_vault.key"
        self._key_hex = self._load_or_generate_key()
        # In-memory or encrypted disk storage for ciphertexts
        self._encrypted_store: Dict[str, Dict[str, str]] = {}

    def _load_or_generate_key(self) -> str:
        """Ensure AES-256 key exists strictly within Red Zone storage."""
        if os.path.exists(self.key_path):
            with open(self.key_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        key = generate_aes_key()
        try:
            with open(self.key_path, "w", encoding="utf-8") as f:
                f.write(key)
        except OSError:
            pass  # Fall back to volatile RAM key
        return key

    def store_payload(self, payload_id: str, content: Any) -> Dict[str, str]:
        """
        Encrypt payload using AES-256-GCM.
        Returns metadata containing the ciphertext, nonce, and SHA-256 hash.
        """
        canon_str = canonical_json(content) if isinstance(content, (dict, list)) else str(content)
        content_hash = hashlib.sha256(canon_str.encode("utf-8")).hexdigest()

        ciphertext_hex, nonce_hex = encrypt_aes_gcm(canon_str, self._key_hex)
        self._encrypted_store[payload_id] = {
            "ciphertext": ciphertext_hex,
            "nonce": nonce_hex,
            "hash": content_hash,
        }
        return {
            "payload_id": payload_id,
            "ciphertext_length": len(ciphertext_hex),
            "sha256": content_hash,
        }

    def retrieve_plaintext(self, payload_id: str) -> str:
        """
        Decrypt payload in memory.
        Raises KeyError if payload does not exist.
        """
        if payload_id not in self._encrypted_store:
            raise KeyError(f"Payload ID '{payload_id}' not found in vault")

        entry = self._encrypted_store[payload_id]
        plaintext = decrypt_aes_gcm(
            ciphertext_hex=entry["ciphertext"],
            nonce_hex=entry["nonce"],
            key_hex=self._key_hex,
        )
        return plaintext

    def get_hash(self, payload_id: str) -> str:
        if payload_id not in self._encrypted_store:
            raise KeyError(f"Payload ID '{payload_id}' not found in vault")
        return self._encrypted_store[payload_id]["hash"]
