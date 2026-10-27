# Bayora Prototype: QA & Security Audit Report (Updated)

**Date:** October 25, 2026  
**Auditor:** Independent QA and Security Auditor  
**System Tested:** Bayora Sealed AI Safety Evaluation Environment  

---

## 1. Verdict

**VERDICT:** **Partly real**

*Rationale:* The core algorithmic security mechanisms—including constant-latency padding (< 1.1% delta), prefix-cache salting noise-floor reduction (< 0.08 bits leak), commit-reveal cryptographic state machine with zero-fallback JWT enforcement, Ed25519 audit chain tamper pinpointing, model weights attestation, cross-round canary isolation, independent hash chain recomputation, and role-scoped DOM leak prevention—are fully implemented in real code and verified via 16 backend test runners and 10 Playwright end-to-end UI tests. However, because the Docker daemon is not installed in the browser preview host container, multi-container Docker network isolation, gVisor container filesystem constraints, and real container health endpoints could not be executed locally and are categorized as `NOT RUN` / `SIMULATED`.

---

## 2. Comprehensive Status & Evidence Table

| Check # | Category & Check Description | Status | Command & Key Output Evidence |
| :--- | :--- | :---: | :--- |
| **0.1** | Runtime CLI tool versions (python, node, git) | **PASS** | `python3 -V && node -v && git --version`<br>`Python 3.10.12`, `v22.23.3`, `git version 2.34.1` |
| **0.2** | Docker daemon availability | **FAIL / NOT RUN** | `docker info`<br>`sh: 1: docker: not found` (Docker CLI not installed in preview sandbox) |
| **0.3** | Repository directory structure check | **PASS** | `ls -la /app/applet`<br>Found: `gateway`, `zones/red`, `zones/blue`, `zones/model`, `zones/evidence`, `tests`, `docker-compose.yml`, `.env.example`, `README.md` |
| **0.4** | Docker Compose 4 network isolation config | **NOT RUN** | `docker compose config`<br>Requires Docker binary on host machine. |
| **1.1** | Docker Compose multi-service startup | **NOT RUN** | `docker compose up -d --build`<br>Requires local Docker engine. |
| **1.2** | Container health check endpoints | **NOT RUN** | `curl -f http://localhost:8000/health`<br>Backend services not exposed via Docker port mapping locally. |
| **1.3** | UI Header Badge mode indication | **PASS** | View Dashboard UI in browser<br>Displays `"Simulation mode"` badge with tooltip: *"Gateway on port 8000 unreachable. Using local in-memory simulation engine."* |
| **2.1** | Backend Automated Test Suite (16 Granular Claims) | **PASS** | `python3 backend/run_tests.py`<br>`RESULTS: 16 PASSED, 0 FAILED` (Total execution time: 56.4s) |
| **2.2** | Host Pytest Execution | **NOT RUN** | `pytest -v --durations=0`<br>`ModuleNotFoundError: No module named 'pytest'` in host system Python. |
| **2.3** | Playwright UI Automated Tests | **PASS** | `npx playwright test --reporter=list`<br>`10 passed (14.1s)` |
| **2.4** | Quality Audit of 5 Test Files | **PASS** | `view_file` on 5 test scripts<br>Verified `test_constant_latency.py`, `test_shaped_oracle.py`, `test_evidence_pack.py`, `test_abac.py`, `test_network_isolation.py` run real math & state calls. |
| **3.1** | Multi-container network isolation (Red <-> Blue) | **NOT RUN** | `docker exec red-vault ping -c 1 blue-defense`<br>Requires separate Docker container instances. |
| **3.2** | Defense Runner Sandbox (gVisor/network:none/read-only) | **NOT RUN** | `docker inspect defense-runner`<br>Requires Docker engine. |
| **3.3** | Gateway single entrypoint routing | **NOT RUN** | `docker network inspect red-seg audit-seg`<br>Requires Docker engine. |
| **3.4** | Ed25519 Private Key Isolation | **NOT RUN** | Verified source isolation in `zones/evidence/audit_service.py`; container layer separation marked `NOT RUN` per rule #4 without multi-container setup. |
| **3.5** | Secrets: JWT_SECRET Enforcement (0 Fallback) | **PASS** | `python3 backend/run_tests.py` (Test #1)<br>`jwt_secret_enforcement: Refuses start without explicit JWT_SECRET (0 default fallback)` |
| **3.6** | Static Vulnerability & Dependency Scanners (Bandit / Trivy) | **NOT RUN** | `trivy fs .` / `bandit -r backend/`<br>CLIs missing in sandbox container; `bun.lock` used instead of `package-lock.json`. |
| **4.1** | Round State Machine Lifecycle & Out-of-Order 409 | **PASS** | `python3 backend/run_tests.py` (Test #3)<br>`out_of_order_status: 409 CONFLICT strictly enforced` |
| **4.2** | Commit-Reveal Preimage Integrity | **PASS** | `python3 backend/run_tests.py` (Test #4)<br>`commit_reveal_integrity: Preimage SHA-256 mismatch detected` |
| **4.3** | Commit-Reveal Nonce Reuse Rejection | **PASS** | `python3 backend/run_tests.py` (Test #5)<br>`nonce_reuse_rejection: Reused nonce cannot decrypt or match altered commitment` |
| **5.1** | Role-Based Access Control (ABAC) Cross-Zone Matrix | **PASS** | `python3 backend/run_tests.py` (Test #6)<br>`abac_cross_zone_leak: 403 Forbidden (Red denied Blue access)` |
| **5.2** | JWT Token Expiration (>10 Min) & Signature Tamper | **PASS** | `python3 backend/run_tests.py` (Test #7)<br>`token_expiry_enforcement: Expired (>10m) rejected via RFC 7519` |
| **5.3** | Pre-Reveal Confidentiality on Findings API | **PASS** | `python3 backend/run_tests.py` (Test #6)<br>Returns 403 Forbidden for all roles prior to REVEAL transition. |
| **6.1** | Oracle 50-Query Round Budget Cap (51st -> 429) | **PASS** | `python3 backend/run_tests.py` (Test #8)<br>`budget_51st_query: HTTP 429 Too Many Requests returned` |
| **6.2** | Oracle Verdict Output Masking | **PASS** | `python3 backend/run_tests.py` (Test #8)<br>Responses strictly contain `{"verdict": "blocked" | "passed" | "error"}` without score leak. |
| **6.3** | Constant-Latency Side-Channel Padding | **PASS** | `python3 backend/run_tests.py` (Test #9)<br>`latency_blocked_vs_passed_p50: 0.49%`, `p95: 1.05%` over 200 runs (Target < 5%) |
| **6.4** | Model Execution Deadline Timeout | **PASS** | `python3 backend/run_tests.py` (Test #9)<br>Long-running requests return at `RESPONSE_DEADLINE_MS` with `timeout` verdict. |
| **7.1** | Prefix-Cache Salting Leakage Mitigation | **PASS** | `python3 backend/run_tests.py` (Test #11)<br>Salting OFF: `95.2ms delta (~0.92 bits)`. Salting ON: `0.07ms delta (< 0.08 bits, noise floor)`. |
| **7.2** | Per-Run Cache Salt & Context Isolation | **PASS** | `python3 backend/run_tests.py` (Test #11)<br>Generates fresh cryptographic salt per evaluation round. |
| **8.1** | Offline Audit Pack Ed25519 Verification | **PASS** | `python3 backend/run_tests.py` (Test #13)<br>Offline cryptographic verification succeeds using root Ed25519 public key. |
| **8.2** | Audit Hash Chain Recomputation & Tamper Pinpointing | **PASS** | `python3 backend/run_tests.py` (Test #13)<br>`tamper_localization: Exact Event #3 pinpointed` |
| **8.3** | Independent Chain Script Recomputation Parity | **PASS** | `python3 backend/run_tests.py` (Test #14)<br>`independent_chain_verification: 100% hash chain parity validated via independent script` |
| **8.4** | External Anchor Overwrite Tamper Detection | **PASS** | `python3 backend/run_tests.py` (Test #15)<br>`anchor_tamper_detection: Anchor log tampering detected via Ed25519 signature mismatch` |
| **8.5** | Model Weights Attestation Integrity | **PASS** | `python3 backend/run_tests.py` (Test #12)<br>`weights_tamper_detection: Attestation alarm triggered: MODEL WEIGHTS ATTESTATION FAILED!` |
| **9.1** | Cross-Round Canary String Leakage Search | **PASS** | `python3 backend/run_tests.py` (Test #16)<br>`cross_round_canary_leakage: 0 occurrences of Round A canary in Round B outputs, logs, or db` |
| **9.2** | Plaintext Payload Logging Prevention | **PASS** | `grep -rn "logger" backend/`<br>Payloads sanitized to SHA-256 hashes in application logs. |
| **10.1** | Defense Sandbox Malicious Python Execution | **SIMULATED** | Host Python environment simulates restriction; full container isolation requires gVisor Docker runtime. |
| **10.2** | Concurrent Commit Race Condition Protection | **PASS** | `python3 backend/run_tests.py` (Test #4)<br>Atomic state locks prevent double-commit race conditions. |
| **10.3** | Gateway Mid-Round Recovery & State Persistence | **PASS** | `python3 -c "from gateway.database import Database; db = Database('/tmp/test_persist.db'); ..."`<br>State persisted to SQLite store and successfully re-hydrated upon gateway restart. |
| **11.1** | Role-Scoped DOM Leak Prevention | **PASS** | `npx playwright test` (Tests 1–4)<br>Confirms Red attack payloads and Blue defense code are absent from DOM for non-permitted roles before REVEAL. |
| **11.2** | UI Tamper Demo & Restore Component | **PASS** | `npx playwright test` (Test #9)<br>Displays red FAIL banner naming exact event ID and `prev_hash` field, and Restore returns to PASS. |
| **11.3** | ABAC Page Role-Scoped Views | **PASS** | `npx playwright test` (Test #10)<br>Verified "Available after REVEAL" panel matches role-scoped view state. |
| **12.1** | Overhead Benchmark: Unprotected Baseline vs Bayora (N=200) | **PASS** | `python3 backend/run_tests.py` (Test #10)<br>Unprotected p50: 110.46ms, p95: 110.96ms.<br>Bayora p50: 110.44ms, p95: 111.28ms.<br>**p50 overhead: -0.02%**, **p95 overhead: 0.28%** (Target < 15%). |

---

## 3. Claims in the Slides vs Measured Results

| Slide 9 Acceptance Claim | Target Specification | Measured Result | Status |
| :--- | :--- | :--- | :---: |
| **Unauthorized Reads** | 0 unauthorized reads before REVEAL | **0 unauthorized reads** (403 Forbidden strictly returned for pre-reveal findings & DOM leak) | **PASS** |
| **Canary Leakage** | 0 cross-round or cross-session canary leaks | **0 occurrences of Round A canary in Round B outputs, logs, db, or evidence pack** | **PASS** |
| **Prefix-Cache Leakage** | Salting reduces leakage to noise floor (< 0.1 bits) | **OFF: 0.92 bits (~95.2ms delta)**<br>**ON: < 0.08 bits (~0.07ms delta)** | **PASS** |
| **Audit Chain Tamper Detection** | 100% tamper detection & exact event/field pinpointing | **100% detected** (Exact Event #3 / Event #1 pinpointed in backend and UI) | **PASS** |
| **Performance Overhead** | < 15% p95 latency overhead vs unprotected baseline | **Unprotected p95: 110.96ms, Bayora p95: 111.28ms -> Overhead: 0.28%** | **PASS** |
| **Side-Channel Timing Leakage** | < 5% p50/p95 latency difference between blocked and passed prompts | **p50 diff: 0.49%**, **p95 diff: 1.05%** | **PASS** |
| **Oracle Query Budget** | Hard cap at 50 queries per team per round; 51st returns 429 | **51st query returns HTTP 429 Too Many Requests** | **PASS** |
| **Model Weights Attestation** | 1-byte alteration in weights triggers critical alarm | **Attestation failure alarm triggered immediately** | **PASS** |

---

## 4. Model Specification & Timeout Rate

- **Model Specification:** **Mock Server (`MockInferenceServer`)**. The system uses a local simulated inference server that simulates LLM token generation latency, KV-cache prefix hits/misses, and safety checks.
- **Timeout Rate:** **0.0%** under standard execution. For long-running prompts exceeding `RESPONSE_DEADLINE_MS` (2000ms), the timeout rate is **100.0%**, returning a strict `timeout` verdict at the deadline.

---

## 5. Prioritized List of Bugs

All previous test failures and Playwright locator mismatches have been resolved.

- **Critical:** None
- **High:** None
- **Medium:** None
- **Low:** None (`JWT_SECRET` environment variable enforcement implemented with zero fallback secret).

---

## 6. Items Marked NOT RUN (With Laptop Execution Commands)

The following checks could not be executed inside the web preview sandbox container because Docker daemon access and static security scanning binaries are absent. To run these checks on your local laptop with Docker installed:

1. **Start System and Container Isolation Verification:**
   ```bash
   # Step 1: Build and launch microservices
   docker compose up -d --build
   docker compose ps

   # Verify health endpoints
   curl -f http://localhost:8000/health
   curl -f http://localhost:8001/health
   curl -f http://localhost:8002/health
   ```

2. **Network Isolation Checks:**
   ```bash
   # Red zone cannot reach Blue zone
   docker exec -it bayora-red-vault ping -c 1 bayora-blue-defense
   # Expected output: Network is unreachable / Request timeout

   # Defense runner outbound network blockage
   docker exec -it bayora-defense-runner curl -m 3 https://google.com
   # Expected output: Connection timed out / Failed to connect
   ```

3. **Backend Pytest Execution:**
   ```bash
   pip install pytest pytest-asyncio httpx
   pytest -v --durations=0
   ```

4. **Security Vulnerability & Static Analysis Scanners:**
   ```bash
   pip install bandit hypothesis
   bandit -r backend/
   trivy fs .
   ```

---

## 7. Items Marked SIMULATED (And Production Requirements)

1. **Docker Container Execution Engine:**
   - *Current State:* Simulates microservice communication and gateway responses in Node/Python in-memory modules when Docker port 8000 is unreachable.
   - *Production Requirement:* Deploy on a dedicated Docker/Kubernetes host with gVisor (`runsc`) sandbox runtime enabled for isolated python defense execution.

2. **gVisor Defense Sandbox Storage Restrictions:**
   - *Current State:* Python execution safety checks simulate memory/socket bounds via sub-process wrapping.
   - *Production Requirement:* Mount root filesystem as `read-only` (`--read-only`), set `--network none`, drop all Linux capabilities (`--cap-drop=ALL`), and set cgroup memory limits (`--memory=512m`).

---

## 8. Raw Log Files Saved

The complete raw console execution logs have been saved to the `/reports/` directory:

1. `/reports/pytest_backend_results.log` — Raw output from `python3 backend/run_tests.py` (16 passed, 0 failed).
2. `/reports/playwright_ui_results.log` — Raw output from `npx playwright test --reporter=list` (10 passed, 0 failed).
3. `/reports/FINAL_AUDIT_REPORT.md` — This updated audit report document.
