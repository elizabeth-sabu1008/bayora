import sqlite3
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from pathlib import Path


class Database:
    def __init__(self, db_path: str = "bayora.db"):
        self.db_path = db_path
        p = Path(db_path)
        if p.parent and not p.parent.exists():
            p.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Rounds table with Part 2 extensions
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS rounds (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                state TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                red_commit_hash TEXT,
                blue_commit_hash TEXT,
                red_reveal_content TEXT,
                red_reveal_nonce TEXT,
                blue_reveal_content TEXT,
                blue_reveal_nonce TEXT,
                red_revealed INTEGER DEFAULT 0,
                blue_revealed INTEGER DEFAULT 0,
                red_commitment_match INTEGER DEFAULT NULL,
                blue_commitment_match INTEGER DEFAULT NULL,
                execution_result TEXT,
                verification_status TEXT,
                error_message TEXT,
                round_budget INTEGER DEFAULT 50,
                defense_artifact_code TEXT,
                defense_artifact_version TEXT,
                defense_artifact_sig TEXT,
                defense_artifact_pubkey TEXT,
                defense_artifact_hash TEXT,
                defense_artifact_frozen INTEGER DEFAULT 0,
                weights_pre_sha256 TEXT,
                weights_post_sha256 TEXT,
                weights_verified INTEGER DEFAULT 0,
                model_backend TEXT DEFAULT NULL
            )
            """)

            # Add columns to existing SQLite table if not present
            for col_def in [
                ("red_commitment_match", "INTEGER DEFAULT NULL"),
                ("blue_commitment_match", "INTEGER DEFAULT NULL"),
                ("model_backend", "TEXT DEFAULT NULL"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE rounds ADD COLUMN {col_def[0]} {col_def[1]}")
                except Exception:
                    pass

            # Structured event audit ledger with hash chaining
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor_sub TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                actor_zone TEXT NOT NULL,
                event_type TEXT NOT NULL,
                resource TEXT NOT NULL,
                action TEXT NOT NULL,
                state_before TEXT,
                state_after TEXT,
                round_id TEXT,
                status_code INTEGER NOT NULL,
                details TEXT,
                prev_event_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            )
            """)

            # Shaped Oracle query log (stores ONLY SHA-256 hashes of prompts, NEVER plaintext)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS oracle_queries (
                query_id TEXT PRIMARY KEY,
                round_id TEXT NOT NULL,
                actor_sub TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                prompt_hash TEXT NOT NULL,
                verdict TEXT NOT NULL,
                duration_ms REAL NOT NULL,
                is_suspicious INTEGER DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """)
            conn.commit()

    def get_last_event_hash(self) -> str:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1")
            row = cursor.fetchone()
            if row:
                return row["event_hash"]
            return "0" * 64  # Genesis root hash

    def record_event(
        self,
        actor_sub: str,
        actor_role: str,
        actor_zone: str,
        event_type: str,
        resource: str,
        action: str,
        status_code: int,
        state_before: Optional[str] = None,
        state_after: Optional[str] = None,
        round_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Record a tamper-evident audit event with cryptographic hash chaining.
        Guarantees that plaintext prompts are never stored in event details, only their hashes.
        """
        now = datetime.now(timezone.utc).isoformat()
        prev_hash = self.get_last_event_hash()

        # Sanitize details: strip any 'prompt' or 'content' keys if present
        sanitized_details = dict(details or {})
        if "prompt" in sanitized_details:
            sanitized_details["prompt_sha256"] = hashlib.sha256(str(sanitized_details.pop("prompt")).encode()).hexdigest()
        if "content" in sanitized_details:
            sanitized_details["content_sha256"] = hashlib.sha256(str(sanitized_details.pop("content")).encode()).hexdigest()

        details_str = json.dumps(sanitized_details, sort_keys=True)

        payload_to_hash = (
            f"{prev_hash}|{now}|{actor_sub}|{actor_role}|{actor_zone}|"
            f"{event_type}|{resource}|{action}|{status_code}|{round_id}|{details_str}"
        )
        event_hash = hashlib.sha256(payload_to_hash.encode("utf-8")).hexdigest()

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO events (
                timestamp, actor_sub, actor_role, actor_zone, event_type,
                resource, action, state_before, state_after, round_id,
                status_code, details, prev_event_hash, event_hash
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now, actor_sub, actor_role, actor_zone, event_type,
                resource, action, state_before, state_after, round_id,
                status_code, details_str, prev_hash, event_hash
            ))
            event_id = cursor.lastrowid
            conn.commit()

        return {
            "id": event_id,
            "timestamp": now,
            "actor_sub": actor_sub,
            "actor_role": actor_role,
            "actor_zone": actor_zone,
            "event_type": event_type,
            "resource": resource,
            "action": action,
            "state_before": state_before,
            "state_after": state_after,
            "round_id": round_id,
            "status_code": status_code,
            "details": sanitized_details,
            "event_hash": event_hash,
        }

    def get_events(self, round_id: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            if round_id:
                cursor.execute(
                    "SELECT * FROM events WHERE round_id = ? ORDER BY id DESC LIMIT ?",
                    (round_id, limit)
                )
            else:
                cursor.execute(
                    "SELECT * FROM events ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
            rows = cursor.fetchall()
            results = []
            for r in rows:
                item = dict(r)
                if item.get("details"):
                    try:
                        item["details"] = json.loads(item["details"])
                    except Exception:
                        pass
                results.append(item)
            return results

    def create_round(self, round_id: str, name: str, round_budget: int = 50) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO rounds (
                id, name, state, created_at, updated_at, round_budget
            ) VALUES (?, ?, 'CREATED', ?, ?, ?)
            """, (round_id, name, now, now, round_budget))
            conn.commit()
        return self.get_round(round_id)

    def get_round(self, round_id: str) -> Optional[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM rounds WHERE id = ?", (round_id,))
            row = cursor.fetchone()
            if not row:
                return None
            data = dict(row)
            if data.get("execution_result"):
                try:
                    data["execution_result"] = json.loads(data["execution_result"])
                except Exception:
                    pass
            data["red_revealed"] = bool(data.get("red_revealed", 0))
            data["blue_revealed"] = bool(data.get("blue_revealed", 0))
            data["red_commitment_match"] = None if data.get("red_commitment_match") is None else bool(data["red_commitment_match"])
            data["blue_commitment_match"] = None if data.get("blue_commitment_match") is None else bool(data["blue_commitment_match"])
            data["defense_artifact_frozen"] = bool(data.get("defense_artifact_frozen", 0))
            data["weights_verified"] = bool(data.get("weights_verified", 0))
            return data

    def update_round_state(self, round_id: str, new_state: str, error_message: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE rounds
            SET state = ?, updated_at = ?, error_message = COALESCE(?, error_message)
            WHERE id = ?
            """, (new_state, now, error_message, round_id))
            conn.commit()

    def update_commit(self, round_id: str, role: str, commit_hash: str):
        now = datetime.now(timezone.utc).isoformat()
        col = "red_commit_hash" if role == "red" else "blue_commit_hash"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
            UPDATE rounds
            SET {col} = ?, updated_at = ?
            WHERE id = ?
            """, (commit_hash, now, round_id))
            conn.commit()

    def store_defense_artifact(
        self,
        round_id: str,
        code: str,
        version: str,
        metadata: Dict[str, Any],
        signature_hex: str,
        public_key_hex: str,
    ) -> str:
        """Store signed defense artifact and calculate its SHA-256."""
        now = datetime.now(timezone.utc).isoformat()
        code_hash = hashlib.sha256(code.encode("utf-8")).hexdigest()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE rounds
            SET defense_artifact_code = ?,
                defense_artifact_version = ?,
                defense_artifact_sig = ?,
                defense_artifact_pubkey = ?,
                defense_artifact_hash = ?,
                updated_at = ?
            WHERE id = ?
            """, (code, version, signature_hex, public_key_hex, code_hash, now, round_id))
            conn.commit()
        return code_hash

    def freeze_defense_artifact(self, round_id: str):
        """Freeze defense artifact upon transitioning to LOCK state."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE rounds
            SET defense_artifact_frozen = 1, updated_at = ?
            WHERE id = ?
            """, (now, round_id))
            conn.commit()

    def record_oracle_query(
        self,
        query_id: str,
        round_id: str,
        actor_sub: str,
        actor_role: str,
        prompt_hash: str,
        verdict: str,
        duration_ms: float,
        is_suspicious: bool = False,
    ):
        """Record coarse query result. Logs ONLY prompt_hash, NEVER plaintext."""
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO oracle_queries (
                query_id, round_id, actor_sub, actor_role, prompt_hash,
                verdict, duration_ms, is_suspicious, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                query_id, round_id, actor_sub, actor_role, prompt_hash,
                verdict, duration_ms, 1 if is_suspicious else 0, now
            ))
            conn.commit()

    def get_oracle_queries(self, round_id: str) -> List[Dict[str, Any]]:
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM oracle_queries WHERE round_id = ? ORDER BY created_at ASC",
                (round_id,)
            )
            return [dict(r) for r in cursor.fetchall()]

    def record_weights_attestation(
        self,
        round_id: str,
        pre_sha256: str,
        post_sha256: str,
        verified: bool,
    ):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE rounds
            SET weights_pre_sha256 = ?,
                weights_post_sha256 = ?,
                weights_verified = ?,
                updated_at = ?
            WHERE id = ?
            """, (pre_sha256, post_sha256, 1 if verified else 0, now, round_id))
            conn.commit()

    def record_reveal(self, round_id: str, role: str, content: Dict[str, Any], nonce: str, is_match: bool = True):
        now = datetime.now(timezone.utc).isoformat()
        col_prefix = "red" if role == "red" else "blue"
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"""
            UPDATE rounds
            SET {col_prefix}_reveal_content = ?,
                {col_prefix}_reveal_nonce = ?,
                {col_prefix}_revealed = 1,
                {col_prefix}_commitment_match = ?,
                updated_at = ?
            WHERE id = ?
            """, (json.dumps(content, sort_keys=True), nonce, 1 if is_match else 0, now, round_id))
            conn.commit()

    def record_execution(self, round_id: str, result: Dict[str, Any]):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE rounds
            SET execution_result = ?, updated_at = ?
            WHERE id = ?
            """, (json.dumps(result, sort_keys=True), now, round_id))
            conn.commit()

    def finalize_verification(self, round_id: str, status: str, error: Optional[str] = None):
        now = datetime.now(timezone.utc).isoformat()
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            UPDATE rounds
            SET state = ?, verification_status = ?, error_message = ?, updated_at = ?
            WHERE id = ?
            """, (status, status, error, now, round_id))
            conn.commit()
