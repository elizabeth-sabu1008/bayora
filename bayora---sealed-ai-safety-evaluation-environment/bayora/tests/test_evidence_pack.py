import pytest
import json
import zipfile
import io
from zones.evidence.audit_service import AuditService
from common.crypto import create_jwt_token


def test_evidence_pack_zip_structure_and_verification(client, admin_token, red_token, blue_token):
    """
    Acceptance Test: Downloadable evidence pack .zip contains:
    events.json, commitments.json, weights_attestation.json, and summary.md.
    Verify that audit verification returns PASS.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    h_red = {"Authorization": f"Bearer {red_token}"}
    h_blue = {"Authorization": f"Bearer {blue_token}"}

    # Execute complete round to COMPLETED state
    r = client.post("/rounds", json={"name": "Evidence Pack Test"}, headers=h_admin).json()
    round_id = r["id"]
    client.post(f"/rounds/{round_id}/start", headers=h_admin)

    client.post(f"/rounds/{round_id}/commit/red", json={"commitment_hash": "e" * 64}, headers=h_red)
    client.post(f"/rounds/{round_id}/commit/blue", json={"commitment_hash": "f" * 64}, headers=h_blue)
    client.post(f"/rounds/{round_id}/lock", headers=h_admin)
    client.post(f"/rounds/{round_id}/oracle/query", json={"prompt": "benchmark probe"}, headers=h_red)
    client.post(f"/rounds/{round_id}/seal", headers=h_admin)
    client.post(f"/rounds/{round_id}/reveal/red", json={"content": {"attack": "1"}, "nonce": "g" * 64}, headers=h_red)
    client.post(f"/rounds/{round_id}/reveal/blue", json={"content": {"filter": "1"}, "nonce": "h" * 64}, headers=h_blue)
    client.post(f"/rounds/{round_id}/verify", headers=h_admin)

    # 1. Download evidence pack .zip
    resp_pack = client.get(f"/rounds/{round_id}/evidence/pack", headers=h_admin)
    assert resp_pack.status_code == 200
    assert resp_pack.headers["content-type"] == "application/zip"

    # 2. Inspect ZIP entries
    zip_bytes = resp_pack.content
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as zf:
        namelist = zf.namelist()
        assert "events.json" in namelist
        assert "commitments.json" in namelist
        assert "weights_attestation.json" in namelist
        assert "summary.md" in namelist

        events = json.loads(zf.read("events.json").decode("utf-8"))
        assert len(events) >= 5

    # 3. Verify evidence via /rounds/{id}/evidence/verify
    resp_verify = client.post(f"/rounds/{round_id}/evidence/verify", headers=h_admin)
    assert resp_verify.status_code == 200
    verify_data = resp_verify.json()
    assert verify_data["verdict"] == "PASS"


def test_tampered_event_pinpointed_by_audit_engine(client, admin_token):
    """
    Acceptance Test: Modifying a single event in the audit chain causes verification
    to fail and pinpoint the exact tampered entry ID!
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    r = client.post("/rounds", json={"name": "Pinpoint Tamper Test"}, headers=h_admin).json()
    round_id = r["id"]

    # Trigger tamper demo endpoint
    resp_tamper = client.post(f"/rounds/{round_id}/evidence/tamper", headers=h_admin)
    assert resp_tamper.status_code == 200
    tampered_id = resp_tamper.json()["tampered_entry_id"]

    # Now run verification -> MUST FAIL and pinpoint tampered_id
    resp_verify = client.post(f"/rounds/{round_id}/evidence/verify", headers=h_admin)
    assert resp_verify.status_code == 200
    res = resp_verify.json()

    assert res["verdict"] == "FAIL"
    assert res["tampered_entry_id"] == tampered_id
    assert f"#{tampered_id}" in res["message"]
