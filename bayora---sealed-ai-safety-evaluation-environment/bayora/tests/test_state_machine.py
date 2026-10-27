import pytest
from common.crypto import generate_nonce, compute_commitment_hash
from common.models import RoundState


def test_out_of_order_calls_fail_with_409(client, admin_token, red_token):
    """
    Acceptance Test: Out-of-order state calls fail with 409 and are logged in events.
    """
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    headers_red = {"Authorization": f"Bearer {red_token}"}

    # 1. Create a round (starts in CREATED state)
    resp = client.post(
        "/rounds",
        json={"name": "State Order Validation Round"},
        headers=headers_admin,
    )
    assert resp.status_code == 200
    round_id = resp.json()["id"]
    assert resp.json()["state"] == "CREATED"

    # 2. Attempt illegal transition: Lock directly while in CREATED state -> Expect 409 Conflict
    resp_lock = client.post(f"/rounds/{round_id}/lock", headers=headers_admin)
    assert resp_lock.status_code == 409, f"Expected 409 but got {resp_lock.status_code}"
    error_data = resp_lock.json()
    assert error_data["error"] == "OutOfOrderStateTransition"
    assert error_data["current_state"] == "CREATED"

    # 3. Attempt illegal transition: Execute directly while in CREATED state -> Expect 409 Conflict
    resp_exec = client.post(
        f"/rounds/{round_id}/execute",
        json={"test_id": "out-of-order-1", "input_text": "trigger jailbreak"},
        headers=headers_red,
    )
    assert resp_exec.status_code == 409
    assert resp_exec.json()["error"] == "OutOfOrderStateTransition"

    # 4. Attempt illegal transition: Seal while in CREATED state -> Expect 409 Conflict
    resp_seal = client.post(f"/rounds/{round_id}/seal", headers=headers_admin)
    assert resp_seal.status_code == 409

    # 5. Verify the illegal attempts were recorded as structured events
    resp_events = client.get("/events", headers=headers_admin)
    assert resp_events.status_code == 200
    events = resp_events.json()
    out_of_order_events = [
        e for e in events if e.get("event_type") == "OUT_OF_ORDER_STATE_ATTEMPT"
    ]
    assert len(out_of_order_events) >= 1
    assert out_of_order_events[0]["status_code"] == 409


def test_happy_path_strict_linear_progression(client, admin_token, red_token, blue_token):
    """
    Verify complete progression:
    CREATED -> COMMIT -> LOCK -> EXECUTE -> SEAL -> REVEAL -> VERIFY -> COMPLETED
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # Step 1: CREATED
    r = client.post("/rounds", json={"name": "Linear Flow Round"}, headers=h_admin).json()
    round_id = r["id"]
    assert r["state"] == "CREATED"

    # Step 2: Advance to COMMIT
    r = client.post(f"/rounds/{round_id}/start", headers=h_admin).json()
    assert r["state"] == "COMMIT"

    # Prepare commitments
    red_payload = {"prompt": "Adversarial test prompt"}
    red_nonce = generate_nonce()
    red_hash = compute_commitment_hash(red_payload, red_nonce)

    blue_payload = {"filter": "Block injection rules"}
    blue_nonce = generate_nonce()
    blue_hash = compute_commitment_hash(blue_payload, blue_nonce)

    # Submit commits
    client.post(f"/rounds/{round_id}/commit/red", json={"commitment_hash": red_hash}, headers=h_red)
    client.post(f"/rounds/{round_id}/commit/blue", json={"commitment_hash": blue_hash}, headers=h_blue)

    # Step 3: Advance to LOCK
    r = client.post(f"/rounds/{round_id}/lock", headers=h_admin).json()
    assert r["state"] == "LOCK"

    # Step 4: Advance to EXECUTE
    r = client.post(
        f"/rounds/{round_id}/execute",
        json={"test_id": "test-1", "input_text": "Sample evaluation text"},
        headers=h_red,
    ).json()
    assert r["state"] == "EXECUTE"
    assert r["execution_result"] is not None

    # Step 5: Advance to SEAL (gateway automatically transitions SEAL -> REVEAL)
    r = client.post(f"/rounds/{round_id}/seal", headers=h_admin).json()
    assert r["state"] == "REVEAL"

    # Step 6: REVEAL
    client.post(f"/rounds/{round_id}/reveal/red", json={"content": red_payload, "nonce": red_nonce}, headers=h_red)
    client.post(f"/rounds/{round_id}/reveal/blue", json={"content": blue_payload, "nonce": blue_nonce}, headers=h_blue)

    # Step 7: VERIFY -> COMPLETED
    r = client.post(f"/rounds/{round_id}/verify", headers=h_admin).json()
    assert r["state"] == "COMPLETED"
    assert r["verification_status"] == "COMPLETED"
