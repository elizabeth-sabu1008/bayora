"""
Bayora Shaped Oracle
Enforces:
1. Coarse verdict projection: Red receives ONLY {blocked, passed, error, timeout}.
   No raw output, no defense scores, no reasons.
2. Query budgets: per-round budget (default 50) and cumulative budget per team across rounds.
   Over-budget queries return HTTP 429.
3. Suspicious probing detection: near-duplicate prompt clustering flagged to evidence ledger.
4. Constant-latency padding: replies return strictly at the configured deadline
   (default 0.5s local / 2.0s production).
"""
# PRODUCTION: In production, constant-latency padding uses hardware cycle timers
# and token-bucket rate limiting backed by Redis or Envoy proxy rate-limit service.

import time
import math
from typing import Dict, Any, List, Tuple, Optional
from common.models import CoarseVerdict, ShapedOracleResponse
from common.config import (
    DEFAULT_ROUND_BUDGET,
    DEFAULT_CUMULATIVE_BUDGET,
    CONSTANT_LATENCY_DEADLINE_SECONDS,
    PROBING_SIMILARITY_THRESHOLD,
)


class QueryBudgetExceededError(Exception):
    def __init__(self, message: str, budget_type: str, limit: int, current: int):
        self.message = message
        self.budget_type = budget_type
        self.limit = limit
        self.current = current
        super().__init__(self.message)


class ShapedOracle:
    def __init__(
        self,
        deadline_seconds: float = CONSTANT_LATENCY_DEADLINE_SECONDS,
        round_budget: int = DEFAULT_ROUND_BUDGET,
        cumulative_budget: int = DEFAULT_CUMULATIVE_BUDGET,
        probing_threshold: float = PROBING_SIMILARITY_THRESHOLD,
    ):
        self.deadline_seconds = deadline_seconds
        self.round_budget = round_budget
        self.cumulative_budget = cumulative_budget
        self.probing_threshold = probing_threshold

        # In-memory tracking (backed by SQLite events table)
        self._round_usage: Dict[str, int] = {}
        self._team_usage: Dict[str, int] = {}
        self._round_prompts: Dict[str, List[str]] = {}

    def get_round_usage(self, round_id: str) -> int:
        return self._round_usage.get(round_id, 0)

    def get_team_usage(self, team_sub: str) -> int:
        return self._team_usage.get(team_sub, 0)

    def check_and_increment_budget(self, round_id: str, team_sub: str):
        """
        Enforce per-round budget AND cumulative budget across rounds.
        Over-budget attempts raise QueryBudgetExceededError -> HTTP 429.
        """
        round_count = self._round_usage.get(round_id, 0)
        team_count = self._team_usage.get(team_sub, 0)

        if round_count >= self.round_budget:
            raise QueryBudgetExceededError(
                f"Per-round query budget of {self.round_budget} exceeded for round '{round_id}'.",
                budget_type="round",
                limit=self.round_budget,
                current=round_count,
            )

        if team_count >= self.cumulative_budget:
            raise QueryBudgetExceededError(
                f"Cumulative query budget of {self.cumulative_budget} exceeded for team '{team_sub}'.",
                budget_type="cumulative",
                limit=self.cumulative_budget,
                current=team_count,
            )

        self._round_usage[round_id] = round_count + 1
        self._team_usage[team_sub] = team_count + 1

    @staticmethod
    def _compute_ngram_similarity(text_a: str, text_b: str, n: int = 3) -> float:
        """Compute character n-gram Jaccard similarity between two prompts."""
        if text_a == text_b:
            return 1.0
        if len(text_a) < n or len(text_b) < n:
            return 1.0 if text_a.strip().lower() == text_b.strip().lower() else 0.0

        set_a = {text_a[i:i+n].lower() for i in range(len(text_a) - n + 1)}
        set_b = {text_b[i:i+n].lower() for i in range(len(text_b) - n + 1)}

        intersection = len(set_a & set_b)
        union = len(set_a | set_b)
        return intersection / union if union > 0 else 0.0

    def detect_suspicious_probing(self, round_id: str, prompt: str) -> Tuple[bool, float, Optional[str]]:
        """
        Check if the new prompt is suspiciously similar (near-duplicate) to prior prompts.
        Returns (is_suspicious, max_similarity, matched_prior_hash).
        """
        prior_prompts = self._round_prompts.setdefault(round_id, [])
        max_sim = 0.0
        matched_sample = None

        for prior in prior_prompts:
            sim = self._compute_ngram_similarity(prompt, prior)
            if sim > max_sim:
                max_sim = sim
                matched_sample = prior

        prior_prompts.append(prompt)
        is_suspicious = (len(prior_prompts) > 1 and max_sim >= self.probing_threshold)
        return is_suspicious, max_sim, matched_sample

    def execute_with_constant_latency(
        self,
        evaluation_fn,
        deadline_override: Optional[float] = None,
    ) -> Tuple[CoarseVerdict, float]:
        """
        Execute the evaluation function and pad execution time to guarantee
        that the reply returns strictly at the deadline.
        Returns (coarse_verdict, total_duration).
        """
        deadline = deadline_override or self.deadline_seconds
        start_time = time.perf_counter()

        raw_verdict = CoarseVerdict.ERROR
        try:
            result = evaluation_fn()
            # Normalize to CoarseVerdict
            if isinstance(result, CoarseVerdict):
                raw_verdict = result
            elif str(result).strip().lower() in ("allow", "passed", "safe", "true"):
                raw_verdict = CoarseVerdict.PASSED
            else:
                raw_verdict = CoarseVerdict.BLOCKED
        except Exception:
            raw_verdict = CoarseVerdict.ERROR

        elapsed = time.perf_counter() - start_time

        # High-resolution deadline padding
        target_time = start_time + deadline
        now = time.perf_counter()
        if now > target_time:
            raw_verdict = CoarseVerdict.TIMEOUT
        else:
            remaining = target_time - now
            # Sleep bulk of time if remaining is significant, saving CPU
            if remaining > 0.003:
                time.sleep(remaining - 0.002)
            # High-precision spin-wait for exact microsecond release
            while time.perf_counter() < target_time:
                pass

        total_duration = time.perf_counter() - start_time
        return raw_verdict, total_duration
