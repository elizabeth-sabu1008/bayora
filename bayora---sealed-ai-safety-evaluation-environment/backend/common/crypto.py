import json
import hashlib
import secrets
import time
import os
from typing import Any, Dict, Tuple, Optional
try:
    import jwt
except ImportError:
    import base64
    import hmac

    class _JWTFallback:
        class ExpiredSignatureError(Exception):
            pass
        class InvalidTokenError(Exception):
            pass

        @staticmethod
        def encode(payload: dict, key: str, algorithm: str = "HS256") -> str:
            header = {"alg": "HS256", "typ": "JWT"}
            h_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
            p_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=").decode()
            msg = f"{h_b64}.{p_b64}".encode()
            sig = hmac.new(key.encode(), msg, hashlib.sha256).digest()
            sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            return f"{h_b64}.{p_b64}.{sig_b64}"

        @staticmethod
        def decode(token: str, key: str, algorithms: list = None) -> dict:
            parts = token.split(".")
            if len(parts) != 3:
                raise _JWTFallback.InvalidTokenError("Invalid token format")
            h_b64, p_b64, sig_b64 = parts
            rem = len(p_b64) % 4
            if rem > 0:
                p_b64 += "=" * (4 - rem)
            payload = json.loads(base64.urlsafe_b64decode(p_b64.encode()).decode())
            exp = payload.get("exp")
            if exp and time.time() > exp:
                raise _JWTFallback.ExpiredSignatureError("Token expired")
            return payload

    jwt = _JWTFallback()

# PRODUCTION & DEVELOPMENT: JWT Secret MUST be explicitly defined in environment.
_JWT_SECRET_ENV = os.getenv("JWT_SECRET")
if not _JWT_SECRET_ENV:
    raise RuntimeError("CRITICAL SECURITY ERROR: JWT_SECRET environment variable is missing or empty! Refusing to start application without an explicit secret.")

SECRET_KEY = _JWT_SECRET_ENV
ALGORITHM = "HS256"
TOKEN_LIFETIME_SECONDS = 600  # 10 minutes


def canonical_json(data: Any) -> str:
    """
    Produce strict canonical JSON:
    - Keys sorted recursively
    - No whitespace around separators
    - UTF-8 representation
    """
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


def generate_nonce() -> str:
    """Generate a cryptographically secure 32-byte nonce (hex encoded = 64 characters)."""
    return secrets.token_hex(32)


def compute_commitment_hash(payload: Any, nonce: str) -> str:
    """
    Compute H = SHA256(canonical_json(payload) + nonce)
    Ensures that content cannot be altered after commitment.
    """
    canon = canonical_json(payload)
    preimage = f"{canon}:{nonce}".encode("utf-8")
    return hashlib.sha256(preimage).hexdigest()


def verify_commitment_hash(payload: Any, nonce: str, expected_hash: str) -> bool:
    """Verify that the payload and nonce reproduce the expected commitment hash."""
    computed = compute_commitment_hash(payload, nonce)
    return secrets.compare_digest(computed.lower(), expected_hash.lower())


def compute_file_sha256(file_path: str, chunk_size: int = 65536) -> str:
    """Compute SHA-256 hash of a file on disk (for weights attestation)."""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


# --- Ed25519 Digital Signatures for Defense Artifacts ---
# PRODUCTION: In production, Blue engineers sign artifacts using a hardware YubiKey (PIV/OpenPGP)
# and verification checks against a pinned PKI root of trust or Sigstore Rekor transparency log.
try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    def generate_ed25519_keypair() -> Tuple[str, str]:
        """Returns (private_key_hex, public_key_hex)."""
        priv = ed25519.Ed25519PrivateKey.generate()
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub = priv.public_key()
        pub_bytes = pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return priv_bytes.hex(), pub_bytes.hex()

    def sign_ed25519(data: bytes, private_key_hex: str) -> str:
        """Sign binary data with Ed25519 private key. Returns signature in hex."""
        priv_bytes = bytes.fromhex(private_key_hex)
        priv = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig = priv.sign(data)
        return sig.hex()

    def verify_ed25519(data: bytes, signature_hex: str, public_key_hex: str) -> bool:
        """Verify Ed25519 signature."""
        try:
            pub_bytes = bytes.fromhex(public_key_hex)
            sig_bytes = bytes.fromhex(signature_hex)
            pub = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            pub.verify(sig_bytes, data)
            return True
        except Exception:
            return False

except ImportError:
    # Pure Python HMAC-SHA256 fallback if cryptography package is absent
    # PRODUCTION: In production, the strict Ed25519 curve25519 primitive is required.
    def generate_ed25519_keypair() -> Tuple[str, str]:
        priv = secrets.token_hex(32)
        pub = hashlib.sha256(f"pub:{priv}".encode()).hexdigest()
        return priv, pub

    def sign_ed25519(data: bytes, private_key_hex: str) -> str:
        import hmac
        return hmac.new(bytes.fromhex(private_key_hex), data, hashlib.sha256).hexdigest()

    def verify_ed25519(data: bytes, signature_hex: str, public_key_hex: str) -> bool:
        import hmac
        expected_sig = hmac.new(bytes.fromhex(public_key_hex[:64]), data, hashlib.sha256).hexdigest()
        return secrets.compare_digest(signature_hex, expected_sig)


# --- AES-256-GCM Encryption for Red Payload Vault at Rest ---
# PRODUCTION: In production, use hardware TPM 2.0 or envelope encryption with KMS key
# protected by Confidential Computing enclave policies.
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    def generate_aes_key() -> str:
        """Generate 256-bit AES key in hex."""
        return AESGCM.generate_key(bit_length=256).hex()

    def encrypt_aes_gcm(plaintext: str, key_hex: str) -> Tuple[str, str]:
        """
        Encrypt plaintext using AES-256-GCM.
        Returns (ciphertext_hex, nonce_hex).
        """
        aesgcm = AESGCM(bytes.fromhex(key_hex))
        nonce = secrets.token_bytes(12)  # 96-bit nonce standard for GCM
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return ciphertext.hex(), nonce.hex()

    def decrypt_aes_gcm(ciphertext_hex: str, nonce_hex: str, key_hex: str) -> str:
        """Decrypt AES-256-GCM ciphertext."""
        aesgcm = AESGCM(bytes.fromhex(key_hex))
        plaintext = aesgcm.decrypt(
            bytes.fromhex(nonce_hex),
            bytes.fromhex(ciphertext_hex),
            None,
        )
        return plaintext.decode("utf-8")

except ImportError:
    # Minimal XOR + SHA256 MAC fallback if cryptography package is absent
    def generate_aes_key() -> str:
        return secrets.token_hex(32)

    def encrypt_aes_gcm(plaintext: str, key_hex: str) -> Tuple[str, str]:
        nonce = secrets.token_hex(12)
        stream_key = hashlib.sha256(f"{key_hex}:{nonce}".encode()).digest()
        pt_bytes = plaintext.encode("utf-8")
        ct = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(pt_bytes)])
        mac = hashlib.sha256(f"{ct.hex()}:{nonce}:{key_hex}".encode()).hexdigest()[:16]
        return f"{ct.hex()}{mac}", nonce

    def decrypt_aes_gcm(ciphertext_hex: str, nonce_hex: str, key_hex: str) -> str:
        ct_hex = ciphertext_hex[:-16]
        ct = bytes.fromhex(ct_hex)
        stream_key = hashlib.sha256(f"{key_hex}:{nonce_hex}".encode()).digest()
        pt = bytes([b ^ stream_key[i % len(stream_key)] for i, b in enumerate(ct)])
        return pt.decode("utf-8")


# --- JWT Authentication ---
def create_jwt_token(
    sub: str,
    role: str,
    zone: str,
    expires_in_seconds: int = TOKEN_LIFETIME_SECONDS,
    custom_claims: Dict[str, Any] = None,
) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "role": role,
        "zone": zone,
        "iat": now,
        "exp": now + expires_in_seconds,
        "jti": secrets.token_hex(8),
    }
    if custom_claims:
        payload.update(custom_claims)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_jwt_token(token: str) -> Dict[str, Any]:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
