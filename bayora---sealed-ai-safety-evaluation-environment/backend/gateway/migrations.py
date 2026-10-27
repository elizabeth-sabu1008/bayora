"""
Bayora SQLite Database Schema & Migrations
=========================================
Configures SQLite in Write-Ahead Logging (WAL) mode for concurrency and applies
schema migrations cleanly.
"""

import sqlite3
import logging

logger = logging.getLogger("bayora.migrations")

MIGRATIONS = [
    # Version 1: Baseline tables
    """
    CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS rounds (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        state TEXT NOT NULL,
        red_commit_hash TEXT,
        blue_commit_hash TEXT,
        defense_artifact_hash TEXT,
        defense_frozen INTEGER DEFAULT 0,
        red_revealed INTEGER DEFAULT 0,
        blue_revealed INTEGER DEFAULT 0,
        weights_pre_hash TEXT,
        weights_post_hash TEXT,
        weights_verified INTEGER DEFAULT 0,
        round_budget INTEGER DEFAULT 50,
        queries_used INTEGER DEFAULT 0,
        blocked_count INTEGER DEFAULT 0,
        passed_count INTEGER DEFAULT 0,
        cache_salt TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        actor_sub TEXT NOT NULL,
        actor_role TEXT NOT NULL,
        actor_zone TEXT NOT NULL,
        event_type TEXT NOT NULL,
        resource TEXT NOT NULL,
        action TEXT NOT NULL,
        status_code INTEGER NOT NULL,
        state_before TEXT,
        state_after TEXT,
        round_id TEXT,
        details_json TEXT NOT NULL,
        prev_event_hash TEXT NOT NULL,
        event_hash TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS oracle_queries (
        id TEXT PRIMARY KEY,
        round_id TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        prompt_hash TEXT NOT NULL,
        verdict TEXT NOT NULL,
        latency_ms REAL NOT NULL,
        is_probing INTEGER DEFAULT 0,
        FOREIGN KEY (round_id) REFERENCES rounds(id)
    );

    CREATE TABLE IF NOT EXISTS cumulative_budgets (
        team_id TEXT PRIMARY KEY,
        queries_used INTEGER DEFAULT 0,
        max_budget INTEGER DEFAULT 500,
        last_query_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE INDEX IF NOT EXISTS idx_audit_round ON audit_events(round_id);
    CREATE INDEX IF NOT EXISTS idx_oracle_round ON oracle_queries(round_id);
    CREATE INDEX IF NOT EXISTS idx_oracle_hash ON oracle_queries(prompt_hash);
    """,
    # Version 2: Indexing and checkpoint anchors
    """
    CREATE TABLE IF NOT EXISTS checkpoints (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        round_id TEXT NOT NULL,
        chain_head_hash TEXT NOT NULL,
        signature TEXT NOT NULL,
        public_key_id TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (round_id) REFERENCES rounds(id)
    );
    """
]


def apply_migrations(db_path: str):
    """Applies all pending migrations to the SQLite database."""
    conn = sqlite3.connect(db_path)
    try:
        # Enable WAL mode and foreign keys
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")

        conn.execute(
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);"
        )
        cur = conn.cursor()
        cur.execute("SELECT MAX(version) FROM schema_version;")
        row = cur.fetchone()
        current_version = row[0] if (row and row[0] is not None) else 0

        for i, migration_sql in enumerate(MIGRATIONS, start=1):
            if i > current_version:
                logger.info(f"Applying migration v{i}...")
                conn.executescript(migration_sql)
                conn.execute("INSERT INTO schema_version (version) VALUES (?);", (i,))
                conn.commit()
                logger.info(f"Migration v{i} applied successfully.")

    finally:
        conn.close()


if __name__ == "__main__":
    import sys
    path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/bayora_test.db"
    apply_migrations(path)
    print(f"Migrations applied to {path}")
