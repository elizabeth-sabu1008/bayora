"""
Bayora Disclosure Gate
Enforces strict secrecy boundaries:
- Before REVEAL: Nobody (not even Admin) can fetch per-role findings (HTTP 403).
- After REVEAL: Returns role-scoped views tailored strictly to authorized access.
"""
# PRODUCTION: In production, role-scoped cryptographic keys are derived via zero-knowledge
# proofs or threshold decryption (Shamir Secret Sharing) that can only be assembled post-REVEAL.

from typing import Dict, Any
from fastapi import HTTPException, status
from common.models import RoundState, UserRole


class DisclosureGate:
    @staticmethod
    def enforce_reveal_state(round_state_str: str):
        """Ensure the round has reached REVEAL or terminal state."""
        allowed_states = [RoundState.REVEAL.value, RoundState.VERIFY.value, RoundState.COMPLETED.value]
        if round_state_str not in allowed_states:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Disclosure Gate Locked: Findings are sealed until the round reaches REVEAL. "
                       f"Current state is '{round_state_str}'.",
            )

    @staticmethod
    def filter_findings_for_role(
        role: str,
        round_data: Dict[str, Any],
        events_list: list,
        oracle_queries: list,
    ) -> Dict[str, Any]:
        """
        Generate role-scoped view of findings post-reveal.
        """
        round_id = round_data["id"]

        if role == UserRole.RED.value:
            # Red view: own query prompts, coarse verdicts, pass-rate
            # Never sees Blue's internal filter source code
            red_queries = [
                {"query_id": q.get("query_id"), "prompt_sha256": q.get("prompt_hash"), "verdict": q.get("verdict")}
                for q in oracle_queries if q.get("actor_role") == "red"
            ]
            passed = sum(1 for q in red_queries if q["verdict"] == "passed")
            blocked = sum(1 for q in red_queries if q["verdict"] == "blocked")
            return {
                "round_id": round_id,
                "role": "red",
                "view": "red_findings",
                "total_queries_submitted": len(red_queries),
                "passed_count": passed,
                "blocked_count": blocked,
                "queries": red_queries,
            }

        elif role == UserRole.BLUE.value:
            # Blue view: defense trigger rate, blocked count, artifact verification status
            # Never sees raw adversarial red payloads
            total_evals = len(oracle_queries)
            blocked_count = sum(1 for q in oracle_queries if q.get("verdict") == "blocked")
            return {
                "round_id": round_id,
                "role": "blue",
                "view": "blue_findings",
                "defense_artifact_hash": round_data.get("defense_artifact_hash"),
                "total_evaluations": total_evals,
                "attacks_blocked": blocked_count,
                "mitigation_rate": (blocked_count / total_evals) if total_evals > 0 else 1.0,
            }

        elif role == UserRole.AUDITOR.value:
            # Auditor view: full cryptographic proof bundle
            return {
                "round_id": round_id,
                "role": "auditor",
                "view": "auditor_cryptographic_bundle",
                "red_commit_hash": round_data.get("red_commit_hash"),
                "blue_commit_hash": round_data.get("blue_commit_hash"),
                "defense_artifact_hash": round_data.get("defense_artifact_hash"),
                "verification_status": round_data.get("verification_status"),
                "events_count": len(events_list),
                "audit_proof_ready": True,
            }

        # Admin view
        return {
            "round_id": round_id,
            "role": "admin",
            "view": "full_summary",
            "state": round_data["state"],
            "verification_status": round_data.get("verification_status"),
        }
