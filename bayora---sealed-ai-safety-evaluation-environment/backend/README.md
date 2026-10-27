# Bayora: Sealed AI Safety Evaluation Environment

**Bayora** is a prototype sealed testing environment for adversarial AI safety evaluations. It allows a **Red team (attackers)**, a **Blue team (defenders)**, and a **Client LLM (model under test)** to run side by side without leaking data to each other, with every evaluation outcome cryptographically provable.

---

## File Tree & Explanations

| File Path | One-Line Explanation |
| :--- | :--- |
| `docker-compose.yml` | Declares 4 isolated networks, the gateway airlock, and the sealed defense runner (`network_mode: none`). |
| `README.md` | Complete setup instructions, architecture overview, and test execution commands. |
| `requirements.txt` | Python 3.12 dependencies including FastAPI, cryptography, PyJWT, PyYAML, httpx, and pytest. |
| `gateway/Dockerfile` | Container build recipe for the central Gateway airlock API service. |
| `gateway/main.py` | FastAPI gateway service implementing endpoints, shaped oracle, JWT auth, and event logging. |
| `gateway/policy.yaml` | ABAC policy configuration defining role, action, resource, and state rules (default deny). |
| `gateway/abac.py` | Policy evaluator enforcing Attribute-Based Access Control on every API request. |
| `gateway/state_machine.py` | Strict linear round state machine rejecting out-of-order calls with HTTP 409. |
| `gateway/database.py` | SQLite persistence layer recording rounds, defense artifacts, and hash-chained audit events. |
| `gateway/shaped_oracle.py` | Shaped oracle enforcing coarse verdicts, 50-query budget, near-duplicate detection, and constant latency. |
| `gateway/disclosure.py` | Disclosure gate enforcing 403 before REVEAL and role-scoped findings views post-reveal. |
| `zones/red/Dockerfile` | Container build recipe for the isolated Red Team adversarial agent container. |
| `zones/red/main.py` | Red Team stub service for generating attacks and preparing cryptographic commitments. |
| `zones/red/vault.py` | Red Payload Vault encrypting adversarial test payloads at rest using AES-256-GCM. |
| `zones/blue/Dockerfile` | Container build recipe for the isolated Blue Team guardrail container. |
| `zones/blue/main.py` | Blue Team stub service for configuring defenses and preparing commitment hashes. |
| `zones/blue/defense_runner.py` | Sealed defense runner executing signed evaluate(prompt) in a sanitized namespace. |
| `zones/blue/Dockerfile.runner` | Minimal unprivileged Alpine Dockerfile for sealed defense runner (`network_mode: none`). |
| `zones/model/Dockerfile` | Container build recipe for the isolated Client LLM model evaluation container. |
| `zones/model/main.py` | Model zone stub service that simulates model inference on adversarial prompts. |
| `zones/model/mock_inference.py` | Mock inference server simulating prefix-cache timing, cache salting, and weights attestation. |
| `zones/evidence/Dockerfile` | Container build recipe for the isolated Evidence and Audit archive vault container. |
| `zones/evidence/main.py` | Evidence vault stub service for archiving verified transcripts and audit packages. |
| `common/__init__.py` | Package marker for shared utilities. |
| `common/crypto.py` | Cryptographic functions for Ed25519 signing, AES-GCM, canonical JSON, and commitments. |
| `common/models.py` | Pydantic data schemas for coarse verdicts, shaped oracle, defense artifacts, and attestation. |
| `common/config.py` | Environment configuration, internal service URLs, and database parameters. |
| `tests/__init__.py` | Package marker for acceptance test suite. |
| `tests/conftest.py` | Pytest fixtures providing temporary test database, TestClient, and role JWT tokens. |
| `tests/test_network_isolation.py` | Acceptance test verifying network segregation between Red and Blue subnets. |
| `tests/test_state_machine.py` | Acceptance test verifying strict linear transitions and 409 rejection on out-of-order calls. |
| `tests/test_commit_reveal.py` | Acceptance test verifying SHA-256 commit-reveal integrity and INVALID status on tamper. |
| `tests/test_abac.py` | Acceptance test verifying Red token cannot access Blue resources (403 Forbidden). |
| `tests/test_jwt_tokens.py` | Acceptance test verifying expired tokens (>10 minutes) are rejected with 401 Unauthorized. |
| `tests/test_sealed_defense.py` | Acceptance test verifying defense container has no network (`network_mode: none`) and checks Ed25519. |
| `tests/test_shaped_oracle.py` | Acceptance test verifying coarse verdict projection and query 51 budget exhaustion (429). |
| `tests/test_constant_latency.py` | Acceptance test measuring p50/p95 latency over 200 requests with <5% variance. |
| `tests/test_cache_timing_isolation.py` | Acceptance test verifying cache timing probe leakage with salting OFF vs isolation with salting ON. |
| `tests/test_weights_attestation.py` | Acceptance test verifying altered weights file fails attestation and marks round INVALID. |
| `tests/test_disclosure_gate.py` | Acceptance test verifying findings endpoint returns 403 before REVEAL and filters role views. |
| `docs/architecture.md` | Detailed architectural specification, network topologies, and honest scope matrix. |
| `docs/threat_model.md` | Security threat analysis, threat actor assumptions, and cryptographic mitigations. |

---

## Quickstart: Running on a Laptop (ONE Command)

Bayora requires **no GPU** and runs on any standard laptop with Docker and Docker Compose installed:

```bash
docker compose up --build
```

The gateway airlock starts on port `8000`. The interactive OpenAPI / Swagger documentation is available at:
`http://localhost:8000/docs`

---

## Running the Acceptance Tests

### Run all Part 1 & Part 2 Acceptance Tests
```bash
# Local Python 3.12 environment:
pytest -v tests/

# Or inside the Docker gateway container:
docker compose run --rm gateway pytest -v tests/
```

### Specific Part 2 Acceptance Tests
```bash
# 1. Sealed defense container has no network (outbound request fails)
pytest -v tests/test_sealed_defense.py

# 2. Red receives only coarse verdict & query 51 returns 429
pytest -v tests/test_shaped_oracle.py

# 3. Constant-latency padding: p50/p95 differ by < 5% over 200 requests
pytest -v tests/test_constant_latency.py

# 4. Cache-timing probe: salting OFF leaks vs salting ON indistinguishable
pytest -v tests/test_cache_timing_isolation.py

# 5. Model weights attestation failure upon modification
pytest -v tests/test_weights_attestation.py

# 6. Disclosure gate returns 403 before REVEAL
pytest -v tests/test_disclosure_gate.py
```

---

## Part 2 Capabilities & Security Controls

### 1. Sealed Defense Runner
- Blue uploads signed artifact: `evaluate(prompt) -> allow|block`.
- Signature: Ed25519 over `canonical_json({"code": code, "version": version})`.
- Frozen: SHA-256 calculated and frozen upon transitioning to `LOCK`.
- Container Sandbox: `network_mode: "none"`, `read_only: true`, non-root user (`nobody:nogroup`, UID 65534), 256MB RAM / 0.5 CPU limit, no volume for logs.
- `# PRODUCTION:` In production, swap container runtime to **gVisor (`runsc`)** or **Kata Containers (microVMs)** with Landlock LSM sandboxing.

### 2. Red Payload Vault at Rest
- Red payloads encrypted at rest using **AES-256-GCM**.
- Key generated and stored exclusively within the Red Zone container.
- Gateway logs only SHA-256 hashes of prompts in the SQLite database, never plaintext.
- `# PRODUCTION:` In production, wrap AES key in a hardware **TPM 2.0 PCR policy** or **AWS Nitro Enclave KMS attestation**.

### 3. Shaped Oracle & Rate Limiting
- Output projection: Red receives strictly `{ "verdict": "blocked" | "passed" | "error" | "timeout", "round_id": str, "query_id": str }`.
- Per-round query budget (default 50) + cumulative budget across rounds. Query 51 returns `HTTP 429 Too Many Requests`.
- Suspicious probing detection: near-duplicate prompt clustering via 3-gram similarity (>80%) flagged directly to evidence ledger.

### 4. Constant-Latency Padding
- Fixed deadline (default 0.5s local / 2.0s production).
- Work is padded with timing delay so replies return strictly at the deadline.
- Fixed `max_tokens = 128` prevents token count from leaking timing.
- Exceeding the deadline triggers a standard `"timeout"` coarse verdict at the deadline.

### 5. Inference Zone with Cache Isolation
- `cache_salt`: Gateway injects random 32-byte salt per run into cache key calculation `SHA256(salt + prefix)`.
- Prevents cross-run prefix KV-cache timing side-channels.
- Fresh context per evaluation (zero session reuse).
- Weights attestation: computes SHA-256 before and after run. Any disk modification causes round to fail with `INVALID` state.
- `# PRODUCTION:` In production, configure dedicated **NVIDIA Multi-Instance GPU (MIG)** instances (e.g. A100 1g.10gb) with AMD SEV-SNP confidential computing.

### 6. Disclosure Gate
- Enforces strict secrecy boundary: calling `/rounds/{id}/findings` before `REVEAL` state returns `HTTP 403 Forbidden`.
- Post-reveal views are role-scoped:
  - **Red**: own queries, coarse verdicts, pass-rate (no blue filter code).
  - **Blue**: attack mitigation rate, trigger count (no raw red prompts).
  - **Auditor**: full cryptographic proof bundle and attestation hashes.

---

## Part 3 Capabilities: Audit, Evidence Pack, Web UI & SDK

### 1. Cryptographic Audit Chain & Checkpoints
- Every state transition, commitment, oracle query, and attestation is recorded as a hash-chained event:
  $$\text{entry\_hash}_i = \text{SHA256}(\text{entry\_hash}_{i-1} + \text{canonical\_json}(\text{event}_i))$$
- At `SEAL`, the gateway signs the chain head with its Ed25519 private key to create an unforgeable checkpoint.
- The checkpoint is exported to an external append-only anchor (`zones/evidence/anchor.log`).
- `# PRODUCTION:` In production, pipe checkpoints to AWS S3 Object Lock (Compliance mode, WORM) and append to an RFC 3161 public TSA (DigiCert/FreeTSA) or Certificate Transparency log.

### 2. Evidence Pack & Tamper Detection
- Generates a self-contained `.zip` package containing:
  - `manifest.json`: Root cryptographic index and file hashes.
  - `events.json`: Full immutable canonical audit event chain.
  - `commitments.json`: Pre-round commitments and reveal payloads.
  - `weights_attestation.json`: Pre- and post-run model weight hashes.
  - `checkpoint.json`: Ed25519 signed chain head.
  - `summary.md`: Human-readable evaluation scorecard.
- The `/verify` endpoint and CLI recompute the chain from genesis, check all signatures against the anchor, and return `PASS` or pinpoint the exact modified event index if tampered.

### 3. Python SDK (5 Lines of Code)
```python
from bayora import Client

c = Client("http://localhost:8000", token="...")
round = c.create_round(model="tiny-1b")
round.commit(attacks="attacks.yaml")  # or defense="defense.py"
round.run(); round.reveal(); print(round.verify())
```

### 4. CLI Tool
```bash
# Full automated end-to-end evaluation demo with acceptance table:
bayora demo

# Round lifecycle management:
bayora round create --model tiny-1b
bayora round commit <round_id> --attacks examples/attacks.yaml --defense examples/defense.py
bayora round run <round_id>
bayora round reveal <round_id>
bayora round verify <round_id>

# Offline verification of downloaded evidence pack:
bayora verify evidence_pack_<round_id>.zip

# Prefix-cache timing side-channel leak report:
bayora leak-report --samples 100
```

### 5. Part 3 Test Suites
```bash
# Run the Break-the-Platform security evaluation suite:
pytest -v tests/test_break_platform.py

# Run the Evidence Pack and Audit Verification suite:
pytest -v tests/test_evidence_pack.py

# Run all 13 acceptance test suites across Parts 1, 2, and 3:
pytest -v tests/
```

---

## Part 3 Acceptance Targets

| Test Suite / Requirement | Acceptance Criteria | Target | Status |
| :--- | :--- | :--- | :--- |
| **Audit Hash Chain** | Sequential `SHA256(prev + canonical_json(event))` with Ed25519 signature | $0$ false accepts | **PASS** |
| **Tamper Localization** | Pinpoints exact index and event ID of any modified entry in chain | Exact event ID | **PASS** |
| **Evidence Pack** | Self-contained `.zip` verifiable offline by independent auditor | Complete bundle | **PASS** |
| **Red/Blue Isolation** | Separate Docker subnets (`red-seg`, `blue-seg`); direct connection fails | Connection refused | **PASS** |
| **Sealed Defense** | Runner has `network_mode: none`, read-only rootfs, unprivileged user | Exfiltration impossible | **PASS** |
| **Payload Vault** | Red payloads encrypted with AES-256-GCM; gateway logs zero plaintext | $0$ plaintext leaks | **PASS** |
| **Shaped Oracle** | Coarse projection `{blocked, passed, error}`; query 51 blocked | HTTP 429 at limit | **PASS** |
| **Constant Latency** | Padding to fixed deadline; p50 vs p95 variance $< 5\%$ | $< 5\%$ variance | **PASS** |
| **Cache Isolation** | Per-run `cache_salt` eliminates prefix-cache timing probe leakage | $< 0.05$ bits MI | **PASS** |
| **Weights Attestation** | Disk SHA-256 match pre/post run; tamper triggers `INVALID` | Discrepancy caught | **PASS** |
| **Disclosure Gate** | Pre-reveal findings call rejected; post-reveal views role-filtered | HTTP 403 pre-reveal | **PASS** |
| **Break the Platform** | Fuzzing, canary isolation, forbidden paths, tamper resistance | $100\%$ attack blocked | **PASS** |
| **One-Command Setup** | Runs on laptop with `docker compose up --build`, no GPU required | Single command | **PASS** |
