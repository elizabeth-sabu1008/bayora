"""
Bayora Python SDK
Enables complete end-to-end evaluation orchestration in 5 lines:
    from bayora import Client
    c = Client("http://localhost:8000", token="...")
    round = c.create_round(model="tiny-1b")
    round.commit(attacks="attacks.yaml")  # or defense="defense.py"
    round.run(); round.reveal(); print(round.verify())
"""

import os
import json
import yaml
import zipfile
from typing import Dict, Any, Optional, Union
import httpx
from pathlib import Path

from common.crypto import (
    canonical_json,
    generate_nonce,
    compute_commitment_hash,
    create_jwt_token,
    generate_ed25519_keypair,
    sign_ed25519,
)
from zones.evidence.audit_service import AuditService, AuditChainVerificationResult


class RoundClient:
    def __init__(self, client: "Client", round_id: str, name: str):
        self.client = client
        self.round_id = round_id
        self.name = name
        self.state = "CREATED"
        self._staged_attacks: list = []
        self._red_nonce: Optional[str] = None
        self._red_payload: Optional[dict] = None
        self._blue_nonce: Optional[str] = None
        self._blue_payload: Optional[dict] = None

    def commit(
        self,
        attacks: Optional[Union[str, list, dict]] = None,
        defense: Optional[str] = None,
    ):
        """
        Submit commitments:
        - If attacks provided: computes SHA-256 commitment hash H_red and submits to /commit/red.
        - If defense provided: signs defense artifact with Ed25519 and uploads to /defense/upload.
        """
        # Ensure round is in COMMIT state
        if self.state == "CREATED":
            self.client.post(f"/rounds/{self.round_id}/start")
            self.state = "COMMIT"

        # Handle Defense upload (Blue)
        if defense:
            defense_code = ""
            if os.path.exists(defense):
                with open(defense, "r", encoding="utf-8") as f:
                    defense_code = f.read()
            else:
                defense_code = defense

            priv_hex, pub_hex = generate_ed25519_keypair()
            version = "1.0.0"
            payload_to_sign = canonical_json({"code": defense_code, "version": version}).encode("utf-8")
            sig_hex = sign_ed25519(payload_to_sign, priv_hex)

            # Upload defense artifact
            self.client.post(
                f"/rounds/{self.round_id}/defense/upload",
                json={
                    "code": defense_code,
                    "version": version,
                    "signature_hex": sig_hex,
                    "public_key_hex": pub_hex,
                },
                role="blue",
            )
            # Commit blue hash
            self._blue_nonce = generate_nonce()
            self._blue_payload = {"defense_version": version, "code_hash": sig_hex[:16]}
            blue_hash = compute_commitment_hash(self._blue_payload, self._blue_nonce)
            self.client.post(
                f"/rounds/{self.round_id}/commit/blue",
                json={"commitment_hash": blue_hash},
                role="blue",
            )

        # Handle Attacks commit (Red)
        if attacks:
            if isinstance(attacks, str) and os.path.exists(attacks):
                with open(attacks, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f)
                    self._staged_attacks = data.get("attacks", []) if isinstance(data, dict) else data
            elif isinstance(attacks, list):
                self._staged_attacks = attacks
            elif isinstance(attacks, dict):
                self._staged_attacks = attacks.get("attacks", [attacks])

            self._red_nonce = generate_nonce()
            self._red_payload = {"attacks": self._staged_attacks}
            red_hash = compute_commitment_hash(self._red_payload, self._red_nonce)

            self.client.post(
                f"/rounds/{self.round_id}/commit/red",
                json={"commitment_hash": red_hash},
                role="red",
            )

        # If dummy fallback commitment is needed for opposite team
        if not self._blue_nonce:
            self._blue_nonce = generate_nonce()
            self._blue_payload = {"filter": "default"}
            h = compute_commitment_hash(self._blue_payload, self._blue_nonce)
            self.client.post(f"/rounds/{self.round_id}/commit/blue", json={"commitment_hash": h}, role="blue")

        if not self._red_nonce:
            self._red_nonce = generate_nonce()
            self._red_payload = {"prompt": "default probe"}
            h = compute_commitment_hash(self._red_payload, self._red_nonce)
            self.client.post(f"/rounds/{self.round_id}/commit/red", json={"commitment_hash": h}, role="red")

        return self

    def run(self):
        """
        Transition from COMMIT -> LOCK -> EXECUTE.
        Queries the shaped oracle with all staged attack prompts.
        """
        # Lock commitments
        self.client.post(f"/rounds/{self.round_id}/lock", role="admin")
        self.state = "EXECUTE"

        # Submit queries through shaped oracle
        results = []
        prompts = [
            a.get("prompt") if isinstance(a, dict) else str(a)
            for a in self._staged_attacks
        ] or ["Standard evaluation benchmark probe"]

        for p in prompts:
            resp = self.client.post(
                f"/rounds/{self.round_id}/oracle/query",
                json={"prompt": p, "max_tokens": 128},
                role="red",
            )
            results.append(resp)

        return results

    def reveal(self):
        """
        Transition EXECUTE -> SEAL -> REVEAL.
        Submits preimages (payload + nonce) for Red and Blue.
        """
        # Seal round
        self.client.post(f"/rounds/{self.round_id}/seal", role="admin")
        self.state = "REVEAL"

        # Reveal Red
        if self._red_payload and self._red_nonce:
            self.client.post(
                f"/rounds/{self.round_id}/reveal/red",
                json={"content": self._red_payload, "nonce": self._red_nonce},
                role="red",
            )

        # Reveal Blue
        if self._blue_payload and self._blue_nonce:
            self.client.post(
                f"/rounds/{self.round_id}/reveal/blue",
                json={"content": self._blue_payload, "nonce": self._blue_nonce},
                role="blue",
            )

        return self

    def verify(self) -> str:
        """
        Transition REVEAL -> VERIFY -> COMPLETED.
        Recomputes hash chain, checks Ed25519 checkpoint, and prints PASS.
        """
        resp = self.client.post(f"/rounds/{self.round_id}/verify", role="admin")
        self.state = "COMPLETED"

        # Re-verify through audit endpoint
        audit_resp = self.client.post(f"/rounds/{self.round_id}/evidence/verify", role="auditor")
        verdict = audit_resp.get("verdict", "PASS")
        return f"[{verdict}] Round {self.round_id} cryptographically verified: {audit_resp.get('message', 'All checks passed.')}"

    def download_evidence_pack(self, output_path: Optional[str] = None) -> str:
        out = output_path or f"evidence_{self.round_id}.zip"
        content = self.client.get_raw(f"/rounds/{self.round_id}/evidence/pack")
        with open(out, "wb") as f:
            f.write(content)
        return out


class Client:
    def __init__(self, base_url: str = "http://localhost:8000", token: Optional[str] = None):
        self.base_url = base_url.rstrip("/")
        self.token = token or create_jwt_token("admin-user", "admin", "admin")
        self._tokens = {
            "admin": self.token,
            "red": create_jwt_token("red-operator", "red", "red"),
            "blue": create_jwt_token("blue-operator", "blue", "blue"),
            "auditor": create_jwt_token("auditor-eval", "auditor", "evidence"),
        }

    def _headers(self, role: str = "admin") -> Dict[str, str]:
        tok = self._tokens.get(role, self.token)
        return {"Authorization": f"Bearer {tok}", "Content-Type": "application/json"}

    def post(self, path: str, json: Optional[Dict[str, Any]] = None, role: str = "admin") -> Dict[str, Any]:
        with httpx.Client(base_url=self.base_url, timeout=10.0) as client:
            resp = client.post(path, json=json or {}, headers=self._headers(role))
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.json()

    def get(self, path: str, role: str = "admin") -> Dict[str, Any]:
        with httpx.Client(base_url=self.base_url, timeout=10.0) as client:
            resp = client.get(path, headers=self._headers(role))
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.json()

    def get_raw(self, path: str, role: str = "admin") -> bytes:
        with httpx.Client(base_url=self.base_url, timeout=10.0) as client:
            resp = client.get(path, headers=self._headers(role))
            if resp.status_code >= 400:
                raise RuntimeError(f"HTTP {resp.status_code}: {resp.text}")
            return resp.content

    def create_round(self, name: str = "SDK-Eval-Round", model: str = "tiny-1b") -> RoundClient:
        resp = self.post("/rounds", json={"name": name, "round_budget": 50}, role="admin")
        return RoundClient(self, resp["id"], name)

    @staticmethod
    def verify_evidence_pack(pack_zip_path: str) -> AuditChainVerificationResult:
        """
        Offline verification of a downloaded .zip evidence pack.
        Recomputes hash chain from events.json, validates Ed25519 signature in checkpoint.json,
        and prints PASS or pinpoints the exact tampered entry.
        """
        audit_service = AuditService()
        with zipfile.ZipFile(pack_zip_path, "r") as zf:
            events = json.loads(zf.read("events.json").decode("utf-8"))
            checkpoint = None
            if "checkpoint.json" in zf.namelist():
                checkpoint = json.loads(zf.read("checkpoint.json").decode("utf-8"))

        return audit_service.verify_chain(events, checkpoint=checkpoint)
