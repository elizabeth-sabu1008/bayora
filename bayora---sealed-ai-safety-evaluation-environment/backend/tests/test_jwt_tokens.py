import pytest
import time
from common.crypto import create_jwt_token, decode_jwt_token


def test_token_older_than_10_minutes_is_rejected(client, expired_token):
    """
    Acceptance Test: A token older than 10 minutes is rejected with 401 Unauthorized.
    """
    headers = {"Authorization": f"Bearer {expired_token}"}
    resp = client.get("/rounds/rnd_any", headers=headers)
    assert resp.status_code == 401
    assert "Token expired" in resp.json()["detail"]


def test_missing_or_malformed_token_rejected(client):
    """Missing or garbage bearer token returns 401."""
    # Missing token
    resp_no_token = client.get("/rounds/rnd_any")
    assert resp_no_token.status_code == 401

    # Malformed token
    resp_bad_token = client.get(
        "/rounds/rnd_any",
        headers={"Authorization": "Bearer not.a.valid.jwt"},
    )
    assert resp_bad_token.status_code == 401


def test_valid_short_lived_token_accepted(client):
    """Fresh token (< 10 minutes) is accepted."""
    fresh_token = create_jwt_token(
        sub="operator-bob",
        role="admin",
        zone="admin",
        expires_in_seconds=600,  # 10 minutes
    )
    headers = {"Authorization": f"Bearer {fresh_token}"}
    resp = client.post("/rounds", json={"name": "Fresh Token Round"}, headers=headers)
    assert resp.status_code == 200
