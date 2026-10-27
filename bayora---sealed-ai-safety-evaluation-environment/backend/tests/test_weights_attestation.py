import pytest
import os
import tempfile
from zones.model.mock_inference import MockInferenceServer, WeightsAttestationError


def test_altering_weights_file_makes_attestation_fail(client, admin_token):
    """
    Acceptance Test: Altering the model weights file causes attestation to fail
    and marks the round INVALID.
    """
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(b"ORIGINAL_CANONICAL_MODEL_WEIGHTS_BINARY_BLOB_V1")
        tmp_weights = f.name

    try:
        server = MockInferenceServer(weights_path=tmp_weights)

        # 1. Pre-run attestation establishes baseline SHA-256
        pre_hash = server.attest_weights_pre_run()
        assert len(pre_hash) == 64

        # 2. Tampering attack: inject a modified weight tensor
        with open(tmp_weights, "ab") as f:
            f.write(b"_UNAUTHORIZED_BACKDOOR_WEIGHT_MODIFICATION")

        # 3. Post-run attestation MUST detect modification and raise
        with pytest.raises(WeightsAttestationError) as exc_info:
            server.attest_weights_post_run()

        assert "MODEL WEIGHTS ATTESTATION FAILED" in str(exc_info.value)

    finally:
        if os.path.exists(tmp_weights):
            os.remove(tmp_weights)


def test_weights_attestation_api_endpoint_rejects_tampered_model(client, admin_token):
    """
    Verify Gateway /rounds/{id}/attestation/verify endpoint returns 400 on weights mismatch.
    """
    h_admin = {"Authorization": f"Bearer {admin_token}"}
    r = client.post("/rounds", json={"name": "Attestation Test Round"}, headers=h_admin).json()
    round_id = r["id"]

    # Baseline attestation should pass
    from gateway.main import inference_server
    inference_server.attest_weights_pre_run()

    # Tamper with the inference server weights
    with open(inference_server.weights_path, "ab") as f:
        f.write(b"tamper_bytes")

    # API call to verify attestation
    resp = client.post(f"/rounds/{round_id}/attestation/verify", headers=h_admin)
    assert resp.status_code == 400
    assert "Weights attestation failed" in resp.json()["detail"]

    # Clean up weights file back to original state
    inference_server._ensure_weights_file()
    inference_server.attest_weights_pre_run()
