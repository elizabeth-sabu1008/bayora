"""
Bayora Seed Data Script
=======================
Seeds the database with a pre-configured completed benchmark evaluation round,
audit events, commitments, and oracle telemetry for instant demonstration.
"""

import sys
import sqlite3
import hashlib
from datetime import datetime, timezone, timedelta
from bayora.common.crypto import compute_commitment_hash, canonical_json
from bayora.common.config import SQLITE_DB_PATH
from bayora.gateway.migrations import apply_migrations


def seed_database(db_path: str = SQLITE_DB_PATH):
    print(f"Applying migrations and seeding database at {db_path}...")
    apply_migrations(db_path)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Check if seed round already exists
    cur.execute("SELECT id FROM rounds WHERE id = 'rnd_seed_benchmark_01'")
    if cur.fetchone():
        print("Seed round 'rnd_seed_benchmark_01' already exists.")
        conn.close()
        return

    # Seed round data
    round_id = "rnd_seed_benchmark_01"
    now = datetime.now(timezone.utc)

    red_payload = {
        "attack_type": "jailbreak_suite",
        "count": 25,
        "signature_id": "red_v1"
    }
    red_nonce = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    red_commit_hash = compute_commitment_hash(red_payload, red_nonce)

    blue_payload = {
        "defense_type": "guardrail_v2",
        "rules": ["injection_detector", "canary_filter"]
    }
    blue_nonce = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"
    blue_commit_hash = compute_commitment_hash(blue_payload, blue_nonce)

    weights_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    cur.execute("""
        INSERT INTO rounds (
            id, name, state, red_commit_hash, blue_commit_hash,
            defense_artifact_hash, defense_frozen, red_revealed, blue_revealed,
            weights_pre_hash, weights_post_hash, weights_verified,
            round_budget, queries_used, blocked_count, passed_count, cache_salt
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        round_id, "Standard Safety Benchmark - Run 1", "COMPLETED",
        red_commit_hash, blue_commit_hash,
        "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3", 1, 1, 1,
        weights_hash, weights_hash, 1,
        50, 48, 38, 10, "seed_salt_32bytes_value_12345678"
    ))

    # Seed chained audit events
    events = [
        ("admin", "admin", "gateway", "ROUND_CREATE", f"/rounds/{round_id}", "create", 201, None, "CREATED"),
        ("blue", "blue", "zone-blue", "DEFENSE_COMMIT", f"/rounds/{round_id}/commit/blue", "commit", 200, "CREATED", "COMMIT"),
        ("red", "red", "zone-red", "ATTACK_COMMIT", f"/rounds/{round_id}/commit/red", "commit", 200, "COMMIT", "COMMIT"),
        ("admin", "admin", "gateway", "ROUND_LOCK", f"/rounds/{round_id}/lock", "lock", 200, "COMMIT", "LOCK"),
        ("red", "red", "zone-red", "ORACLE_QUERY", f"/rounds/{round_id}/oracle/query", "query", 200, "LOCK", "EXECUTE"),
        ("admin", "admin", "gateway", "ROUND_SEAL", f"/rounds/{round_id}/seal", "seal", 200, "EXECUTE", "SEAL"),
        ("blue", "blue", "zone-blue", "DEFENSE_REVEAL", f"/rounds/{round_id}/reveal/blue", "reveal", 200, "SEAL", "REVEAL"),
        ("red", "red", "zone-red", "ATTACK_REVEAL", f"/rounds/{round_id}/reveal/red", "reveal", 200, "REVEAL", "REVEAL"),
        ("auditor", "auditor", "gateway", "ROUND_VERIFY", f"/rounds/{round_id}/verify", "verify", 200, "REVEAL", "COMPLETED"),
    ]

    prev_hash = "0" * 64
    for idx, (actor_sub, actor_role, actor_zone, event_type, resource, action, status_code, state_before, state_after) in enumerate(events, 1):
        ts = (now + timedelta(seconds=idx * 10)).isoformat()
        details = {"round_id": round_id, "step": idx, "description": f"Executed {event_type}"}
        details_json = canonical_json(details)
        raw = f"{prev_hash}|{ts}|{actor_sub}|{actor_role}|{actor_zone}|{event_type}|{resource}|{action}|{status_code}|{round_id}|{details_json}"
        event_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

        cur.execute("""
            INSERT INTO audit_events (
                id, timestamp, actor_sub, actor_role, actor_zone, event_type,
                resource, action, status_code, state_before, state_after,
                round_id, details_json, prev_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            idx, ts, actor_sub, actor_role, actor_zone, event_type,
            resource, action, status_code, state_before, state_after,
            round_id, details_json, prev_hash, event_hash
        ))
        prev_hash = event_hash

    # Seed cumulative team budget
    cur.execute("INSERT OR REPLACE INTO cumulative_budgets (team_id, queries_used, max_budget) VALUES ('red_team_alpha', 48, 500);")

    conn.commit()
    conn.close()
    print("Seed data successfully installed.")


if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else SQLITE_DB_PATH
    seed_database(db)
