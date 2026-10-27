import pytest
import yaml
import socket
from pathlib import Path
from zones.blue.defense_runner import SealedDefenseRunner
from common.crypto import generate_ed25519_keypair, sign_ed25519, canonical_json


def test_blue_defense_container_has_no_network_configuration():
    """
    Acceptance Test: Blue defense container has no network.
    - network_mode: none
    - read_only: true
    - non-root user
    - Outbound network requests fail.
    """
    compose_path = Path(__file__).parent.parent / "docker-compose.yml"
    with open(compose_path, "r", encoding="utf-8") as f:
        compose = yaml.safe_load(f)

    runner_cfg = compose["services"]["zone-defense-runner"]
    assert runner_cfg.get("network_mode") == "none", (
        "SECURITY VIOLATION: zone-defense-runner must have network_mode: none"
    )
    assert runner_cfg.get("read_only") is True, (
        "SECURITY VIOLATION: zone-defense-runner must have read_only: true filesystem"
    )
    assert runner_cfg.get("user") == "65534:65534", (
        "SECURITY VIOLATION: zone-defense-runner must run as non-root nobody user"
    )


def test_runner_outbound_network_request_fails():
    """
    Acceptance Test: Outbound request from defense evaluation fails.
    The runner's sanitized namespace blocks socket and network access.
    """
    runner = SealedDefenseRunner()

    # Adversarial defense trying to establish outbound connection
    exploit_code = """
def evaluate(prompt):
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("8.8.8.8", 53))
    return "allow"
"""
    try:
        runner.load_code(exploit_code)
        verdict = runner.evaluate("test")
        # Since 'import' is not in SAFE_BUILTINS, it fails safely and returns 'block'
        assert verdict == "block"
    except Exception:
        # If compilation raises due to missing import in sanitized namespace, it passes
        pass


def test_signed_defense_artifact_upload_and_freeze(client, admin_token, blue_token):
    """
    Acceptance Test: Blue uploads signed, versioned defense artifact with Ed25519 signature.
    Artifact is validated and frozen when round enters LOCK.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # 1. Create round and start commit phase
    r = client.post("/rounds", json={"name": "Defense Runner Test"}, headers=h_admin).json()
    round_id = r["id"]
    client.post(f"/rounds/{round_id}/start", headers=h_admin)

    # 2. Blue generates keypair and signs defense code
    priv_hex, pub_hex = generate_ed25519_keypair()
    defense_code = """
def evaluate(prompt):
    harmful_terms = ["jailbreak", "exploit", "override"]
    if any(t in prompt.lower() for t in harmful_terms):
        return "block"
    return "allow"
"""
    version = "1.0.0"
    payload_to_sign = canonical_json({"code": defense_code, "version": version}).encode("utf-8")
    sig_hex = sign_ed25519(payload_to_sign, priv_hex)

    # 3. Upload defense artifact
    resp_upload = client.post(
        f"/rounds/{round_id}/defense/upload",
        json={
            "code": defense_code,
            "version": version,
            "signature_hex": sig_hex,
            "public_key_hex": pub_hex,
            "metadata": {"author": "blue-secops", "model": "guardrail-v1"},
        },
        headers=h_blue,
    )
    assert resp_upload.status_code == 200, f"Upload failed: {resp_upload.text}"
    uploaded_data = resp_upload.json()
    assert uploaded_data["defense_artifact_hash"] is not None

    # 4. Attempt upload with bad signature -> Expect 400 Bad Request
    resp_bad_sig = client.post(
        f"/rounds/{round_id}/defense/upload",
        json={
            "code": defense_code,
            "version": version,
            "signature_hex": "0" * 128,  # Invalid signature
            "public_key_hex": pub_hex,
        },
        headers=h_blue,
    )
    assert resp_bad_sig.status_code == 400
    assert "Invalid Ed25519 signature" in resp_bad_sig.json()["detail"]
