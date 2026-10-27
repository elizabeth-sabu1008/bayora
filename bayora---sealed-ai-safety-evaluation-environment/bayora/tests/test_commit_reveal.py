import pytest
from common.crypto import (
    canonical_json,
    generate_nonce,
    compute_commitment_hash,
    verify_commitment_hash,
)
from common.models import RoundState


def test_canonical_json_invariance():
    """Ensure key ordering does not affect canonical JSON hash."""
    payload_a = {"z": 1, "a": 2, "m": {"nested_b": True, "nested_a": "val"}}
    payload_b = {"a": 2, "m": {"nested_a": "val", "nested_b": True}, "z": 1}

    nonce = generate_nonce()
    hash_a = compute_commitment_hash(payload_a, nonce)
    hash_b = compute_commitment_hash(payload_b, nonce)

    assert hash_a == hash_b, "Canonical JSON must produce identical hashes regardless of dict key ordering"


def test_changed_payload_fails_reveal_verification(client, admin_token, red_token, blue_token):
    """
    Acceptance Test: A changed payload after COMMIT fails reveal verification
    and marks the round INVALID.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # 1. Create round and start commit phase
    r = client.post("/rounds", json={"name": "Tamper Test Round"}, headers=h_admin).json()
    round_id = r["id"]
    client.post(f"/rounds/{round_id}/start", headers=h_admin)

    # 2. Red commits original payload
    original_red_payload = {
        "attack_type": "jailbreak",
        "prompt": "Legitimate benchmark test question A",
    }
    red_nonce = generate_nonce()
    committed_hash = compute_commitment_hash(original_red_payload, red_nonce)

    resp_commit = client.post(
        f"/rounds/{round_id}/commit/red",
        json={"commitment_hash": committed_hash},
        headers=h_red,
    )
    assert resp_commit.status_code == 200

    # Blue commits dummy defense
    blue_payload = {"filter": "safe"}
    blue_nonce = generate_nonce()
    client.post(
        f"/rounds/{round_id}/commit/blue",
        json={"commitment_hash": compute_commitment_hash(blue_payload, blue_nonce)},
        headers=h_blue,
    )

    # 3. Lock round & advance through execution to seal (which moves to REVEAL)
    client.post(f"/rounds/{round_id}/lock", headers=h_admin)
    client.post(
        f"/rounds/{round_id}/execute",
        json={"test_id": "t1", "input_text": "run"},
        headers=h_red,
    )
    client.post(f"/rounds/{round_id}/seal", headers=h_admin)

    # Verify round is now in REVEAL state
    status_resp = client.get(f"/rounds/{round_id}", headers=h_admin).json()
    assert status_resp["state"] == "REVEAL"

    # 4. TAMPER ATTEMPT: Red attempts to reveal an altered payload!
    tampered_red_payload = {
        "attack_type": "jailbreak",
        "prompt": "ALTERED_INJECTED_EXPLOIT_PAYLOAD",  # Modified content!
    }

    resp_tampered_reveal = client.post(
        f"/rounds/{round_id}/reveal/red",
        json={"content": tampered_red_payload, "nonce": red_nonce},
        headers=h_red,
    )

    # Must fail with 400 Bad Request
    assert resp_tampered_reveal.status_code == 400
    assert "Commitment verification failed" in resp_tampered_reveal.json()["detail"]

    # 5. Verify round state is marked INVALID
    status_after = client.get(f"/rounds/{round_id}", headers=h_admin).json()
    assert status_after["state"] == "INVALID"
    assert "Red commitment verification failed" in status_after["error_message"]

    # 6. Verify audit alarm event was written
    events_resp = client.get(f"/events?round_id={round_id}", headers=h_admin).json()
    alarm_events = [e for e in events_resp if e.get("event_type") == "COMMITMENT_MISMATCH_ALARM"]
    assert len(alarm_events) >= 1
    assert alarm_events[0]["actor_role"] == "red"
