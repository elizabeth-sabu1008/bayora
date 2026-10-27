import os

# Gateway and Zone configurations
GATEWAY_HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
GATEWAY_PORT = int(os.getenv("GATEWAY_PORT", "8000"))

# Service internal URLs across isolated networks
ZONE_RED_URL = os.getenv("ZONE_RED_URL", "http://zone-red:8001")
ZONE_BLUE_URL = os.getenv("ZONE_BLUE_URL", "http://zone-blue:8002")
ZONE_MODEL_URL = os.getenv("ZONE_MODEL_URL", "http://zone-model:8003")
ZONE_EVIDENCE_URL = os.getenv("ZONE_EVIDENCE_URL", "http://zone-evidence:8004")
ZONE_DEFENSE_RUNNER_URL = os.getenv("ZONE_DEFENSE_RUNNER_URL", "http://zone-defense-runner:8005")

# Database path (SQLite file)
SQLITE_DB_PATH = os.getenv("SQLITE_DB_PATH", "/app/data/bayora.db")

# ABAC policy file path
POLICY_FILE_PATH = os.getenv("POLICY_FILE_PATH", "gateway/policy.yaml")

# Part 2 & 3: Oracle budgets & timing deadline
DEFAULT_ROUND_BUDGET = int(os.getenv("DEFAULT_ROUND_BUDGET", "50"))
DEFAULT_CUMULATIVE_BUDGET = int(os.getenv("DEFAULT_CUMULATIVE_BUDGET", "500"))
RESPONSE_DEADLINE_MS = int(os.getenv("RESPONSE_DEADLINE_MS", "150"))
CONSTANT_LATENCY_DEADLINE_SECONDS = RESPONSE_DEADLINE_MS / 1000.0
FIXED_MAX_TOKENS = int(os.getenv("FIXED_MAX_TOKENS", "128"))
PROBING_SIMILARITY_THRESHOLD = float(os.getenv("PROBING_SIMILARITY_THRESHOLD", "0.80"))

# Weights path for model attestation
WEIGHTS_PATH = os.getenv("WEIGHTS_PATH", "/app/data/model_weights.bin")
DEFENSE_RUNNER_SOCKET = os.getenv("DEFENSE_RUNNER_SOCKET", "/app/data/defense.sock")

