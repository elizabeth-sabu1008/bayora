import pytest
from common.models import CoarseVerdict
from common.crypto import compute_commitment_hash, generate_nonce


def test_red_never_receives_anything_beyond_coarse_verdict(client, admin_token, red_token, blue_token):
    """
    Acceptance Test: Red never receives anything beyond the coarse verdict {blocked, passed, error, timeout}.
    No scores, no reasons, no model output text.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # Setup round to EXECUTE state
    r = client.post("/rounds", json={"name": "Oracle Coarse Test"}, headers=h_admin).json()
    round_id = r["id"]
    client.post(f"/rounds/{round_id}/start", headers=h_admin)

    # Commits
    client.post(f"/rounds/{round_id}/commit/red", json={"commitment_hash": "a" * 64}, headers=h_red)
    client.post(f"/rounds/{round_id}/commit/blue", json={"commitment_hash": "b" * 64}, headers=h_blue)
    client.post(f"/rounds/{round_id}/lock", headers=h_admin)

    # Red queries shaped oracle
    resp = client.post(
        f"/rounds/{round_id}/oracle/query",
        json={"prompt": "Harmless prompt testing coarse oracle projection", "max_tokens": 128},
        headers=h_red,
    )
    assert resp.status_code == 200
    data = resp.json()

    # STRICT COARSE ASSERTIONS:
    # 1. Allowed keys strictly restricted to verdict, round_id, query_id
    assert set(data.keys()) == {"verdict", "round_id", "query_id"}, (
        f"DATA LEAK DETECTED: Oracle response contained extra keys: {set(data.keys()) - {'verdict', 'round_id', 'query_id'}}"
    )
    # 2. Verdict is coarse enum only
    assert data["verdict"] in [v.value for v in CoarseVerdict]
    # 3. No score or text present
    assert "score" not in data
    assert "reason" not in data
    assert "model_text" not in data
    assert "output" not in data


def test_query_51_in_50_budget_round_returns_429(client, admin_token, red_token, blue_token):
    """
    Acceptance Test: Query 51 in a 50-budget round returns HTTP 429 Too Many Requests.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # Create round with round_budget=50
    r = client.post(
        "/rounds",
        json={"name": "Budget Exhaustion Round", "round_budget": 50},
        headers=h_admin,
    ).json()
    round_id = r["id"]
    client.post(f"/rounds/{round_id}/start", headers=h_admin)
    client.post(f"/rounds/{round_id}/commit/red", json={"commitment_hash": "1" * 64}, headers=h_red)
    client.post(f"/rounds/{round_id}/commit/blue", json={"commitment_hash": "2" * 64}, headers=h_blue)
    client.post(f"/rounds/{round_id}/lock", headers=h_admin)

    # Execute 50 queries (all should succeed within budget)
    # Use zero latency padding in unit test for speed
    from gateway.main import shaped_oracle
    original_deadline = shaped_oracle.deadline_seconds
    shaped_oracle.deadline_seconds = 0.001  # Fast for 50 iterations

    try:
        for i in range(50):
            resp = client.post(
                f"/rounds/{round_id}/oracle/query",
                json={"prompt": f"Budget evaluation probe query index #{i}"},
                headers=h_red,
            )
            assert resp.status_code == 200, f"Query {i+1} failed with status {resp.status_code}"

        # Query 51 MUST return 429 Too Many Requests
        resp_51 = client.post(
            f"/rounds/{round_id}/oracle/query",
            json={"prompt": "Probe query index #51 - should trigger budget block"},
            headers=h_red,
        )
        assert resp_51.status_code == 429, f"Expected 429 for query 51, got {resp_51.status_code}"
        assert "exceeded" in resp_51.json()["message"]
    finally:
        shaped_oracle.deadline_seconds = original_deadline
