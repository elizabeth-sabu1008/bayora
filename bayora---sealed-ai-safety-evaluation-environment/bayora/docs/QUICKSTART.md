# Bayora Quickstart Guide

Get from `git clone` to your first cryptographically verified evaluation round in under 10 minutes.

---

## 1. Prerequisites & Launch (1 Command)
Bayora requires **no GPU** and runs on any modern laptop with Docker and Docker Compose installed:

```bash
# Clone and start all isolated containers and networks
docker compose up --build -d
```

The multi-homed Gateway airlock starts on port `8000`:
- Interactive Swagger / OpenAPI docs: `http://localhost:8000/docs`
- Web Dashboard & Control Console: `http://localhost:3000`

---

## 2. Option A: Run the 5-Line Python SDK

In Python 3.12:

```python
from bayora import Client

# 1. Connect to gateway airlock
c = Client("http://localhost:8000")

# 2. Create evaluation round
round = c.create_round(name="Q1-Safety-Eval", model="tiny-1b")

# 3. Blue uploads signed defense & Red stages attacks
round.commit(attacks="examples/attacks.yaml", defense="examples/defense.py")

# 4. Execute test probes against the shaped oracle
results = round.run()
for res in results:
    print(f"Probe: {res['verdict']}")

# 5. Reveal preimages and verify cryptographic integrity
round.reveal()
print(round.verify())

# 6. Download standalone evidence pack (.zip)
pack_path = round.download_evidence_pack()
print(f"Evidence bundle saved: {pack_path}")
```

---

## 3. Option B: Run via Bayora CLI

```bash
# 1. Run complete automated demo in < 2 minutes
python bayora/cli/main.py demo

# 2. Step-by-step CLI execution
python bayora/cli/main.py round create --name "Manual-Campaign-01"
python bayora/cli/main.py round commit --id rnd_xxxx --attacks examples/attacks.yaml --defense examples/defense.py
python bayora/cli/main.py round run --id rnd_xxxx
python bayora/cli/main.py round reveal --id rnd_xxxx
python bayora/cli/main.py round verify --id rnd_xxxx

# 3. Independently verify any downloaded evidence pack .zip
python bayora/cli/main.py verify evidence_rnd_xxxx.zip

# 4. Generate prefix-cache timing leak report
python bayora/cli/main.py leak-report
```

---

## 4. Run the Full Acceptance & Break-the-Platform Suite

```bash
pytest -v tests/
```
Output verifies:
- Network isolation (0 cross-tenant routes)
- Zero canary tokens leaked across sessions
- Strict coarse verdict projection (no raw output text or scores)
- Query 51 budget exhaustion (`HTTP 429`)
- Constant-latency padding (<5% p50/p95 variance)
- Cache salting eliminating side-channel leakage (~0 bits)
- Weights attestation detecting modified binaries
- 100% pinpoint accuracy on tampered audit ledger events.
