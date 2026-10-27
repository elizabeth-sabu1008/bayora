import pytest
from common.crypto import compute_commitment_hash, generate_nonce


def test_findings_endpoint_returns_403_before_reveal(client, admin_token, red_token, blue_token, auditor_token):
    """
    Acceptance Test: Findings endpoint returns 403 Forbidden before REVEAL state.
    Nobody (Red, Blue, Auditor, or Admin) can fetch findings during CREATED, COMMIT, LOCK, or EXECUTE.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}
    h_auditor = {"Authorization": f"Bearer {auditor_token}"}

    # 1. Round in CREATED state
    r = client.post("/rounds", json={"name": "Disclosure Gate Test"}, headers=h_admin).json()
    round_id = r["id"]

    # Red receives 403
    resp_red = client.get(f"/rounds/{round_id}/findings", headers=h_red)
    assert resp_red.status_code == 403, f"Expected 403 in CREATED, got {resp_red.status_code}"
    assert "Disclosure Gate Locked" in resp_red.json()["detail"]

    # Blue receives 403
    resp_blue = client.get(f"/rounds/{round_id}/findings", headers=h_blue)
    assert resp_blue.status_code == 403

    # Auditor receives 403
    resp_auditor = client.get(f"/rounds/{round_id}/findings", headers=h_auditor)
    assert resp_auditor.status_code == 403

    # 2. Advance to COMMIT state -> Still 403
    client.post(f"/rounds/{round_id}/start", headers=h_admin)
    assert client.get(f"/rounds/{round_id}/findings", headers=h_red).status_code == 403

    # 3. Advance to LOCK state -> Still 403
    client.post(f"/rounds/{round_id}/commit/red", json={"commitment_hash": "a" * 64}, headers=h_red)
    client.post(f"/rounds/{round_id}/commit/blue", json={"commitment_hash": "b" * 64}, headers=h_blue)
    client.post(f"/rounds/{round_id}/lock", headers=h_admin)
    assert client.get(f"/rounds/{round_id}/findings", headers=h_red).status_code == 403

    # 4. Advance through EXECUTE and SEAL to REVEAL state
    client.post(f"/rounds/{round_id}/seal", headers=h_admin)

    # Verify round is now in REVEAL state
    round_status = client.get(f"/rounds/{round_id}", headers=h_admin).json()
    assert round_status["state"] == "REVEAL"

    # 5. POST-REVEAL DISCLOSURE: Each role receives only its authorized view
    # Red view: own query prompts and coarse verdicts
    resp_red_reveal = client.get(f"/rounds/{round_id}/findings", headers=h_red)
    assert resp_red_reveal.status_code == 200
    red_data = resp_red_reveal.json()["data"]
    assert red_data["role"] == "red"
    assert "defense_artifact_code" not in red_data

    # Blue view: defense trigger rate and mitigation stats
    resp_blue_reveal = client.get(f"/rounds/{round_id}/findings", headers=h_blue)
    assert resp_blue_reveal.status_code == 200
    blue_data = resp_blue_reveal.json()["data"]
    assert blue_data["role"] == "blue"
    assert "attacks_blocked" in blue_data

    # Auditor view: cryptographic audit bundle
    resp_auditor_reveal = client.get(f"/rounds/{round_id}/findings", headers=h_auditor)
    assert resp_auditor_reveal.status_code == 200
    auditor_data = resp_auditor_reveal.json()["data"]
    assert auditor_data["role"] == "auditor"
    assert auditor_data["audit_proof_ready"] is True
