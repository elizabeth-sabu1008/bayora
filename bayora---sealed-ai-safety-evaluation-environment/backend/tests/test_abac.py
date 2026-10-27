import pytest
from common.crypto import generate_nonce, compute_commitment_hash


def test_red_token_cannot_read_or_commit_blue_resources(client, admin_token, red_token, blue_token):
    """
    Acceptance Test: A red token cannot read or mutate blue resources (403 Forbidden).
    Default deny applies.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # Create a test round
    r = client.post("/rounds", json={"name": "ABAC Authorization Round"}, headers=h_admin).json()
    round_id = r["id"]
    client.post(f"/rounds/{round_id}/start", headers=h_admin)

    # 1. Red attempts to commit on behalf of Blue -> 403 Forbidden
    resp_illegal_commit = client.post(
        f"/rounds/{round_id}/commit/blue",
        json={"commitment_hash": "a" * 64},
        headers=h_red,
    )
    assert resp_illegal_commit.status_code == 403
    assert "Access denied" in resp_illegal_commit.json()["detail"]

    # 2. Red attempts to reveal Blue defense -> 403 Forbidden
    resp_illegal_reveal = client.post(
        f"/rounds/{round_id}/reveal/blue",
        json={"content": {"filter": "exploit"}, "nonce": "b" * 64},
        headers=h_red,
    )
    assert resp_illegal_reveal.status_code == 403

    # 3. Blue attempts to commit Red attack -> 403 Forbidden
    resp_blue_on_red = client.post(
        f"/rounds/{round_id}/commit/red",
        json={"commitment_hash": "c" * 64},
        headers=h_blue,
    )
    assert resp_blue_on_red.status_code == 403


def test_auditor_cannot_mutate_state(client, admin_token, auditor_token):
    """Auditors have read-only permissions and cannot create or mutate rounds."""
    h_auditor = {"Authorization": f"Bearer {auditor_token}"}

    # Auditor cannot create rounds
    resp_create = client.post("/rounds", json={"name": "Auditor Round"}, headers=h_auditor)
    assert resp_create.status_code == 403

    # But auditor CAN read events log
    resp_events = client.get("/events", headers=h_auditor)
    assert resp_events.status_code == 200
