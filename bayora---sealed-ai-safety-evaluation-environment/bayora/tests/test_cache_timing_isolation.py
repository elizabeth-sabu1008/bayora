import pytest
import time
import secrets
from zones.model.mock_inference import MockInferenceServer


def test_cache_timing_probe_salting_off_vs_on():
    """
    Acceptance Test:
    - With salting OFF, cache timing probe distinguishes cache hit vs cache miss.
    - With salting ON, each run's salt isolates cache keys, making timing across runs indistinguishable.
    """
    server = MockInferenceServer()

    target_prompt = "CANARY_ADVERSARIAL_PROMPT_PREFIX_TARGET"
    fresh_prompt = "COMPLETELY_UNSEEN_RANDOM_QUERY_PREFIX"

    # =========================================================================
    # PART A: Salting is OFF (Vulnerable to timing side-channels)
    # =========================================================================
    # Prime cache with target prompt (salting = None)
    server.evaluate(target_prompt, cache_salt=None, simulate_timing=True)

    hit_times = []
    miss_times = []

    # Measure 5 cache hits (same prompt, no salt)
    for _ in range(5):
        t0 = time.perf_counter()
        res = server.evaluate(target_prompt, cache_salt=None, simulate_timing=True)
        hit_times.append(time.perf_counter() - t0)
        assert res["cache_hit"] is True

    # Measure 5 cache misses (new prompt, no salt)
    for i in range(5):
        t0 = time.perf_counter()
        res = server.evaluate(f"NEW_PREFIX_{i}_{secrets.token_hex(4)}", cache_salt=None, simulate_timing=True)
        miss_times.append(time.perf_counter() - t0)
        assert res["cache_hit"] is False

    mean_hit = sum(hit_times) / len(hit_times)
    mean_miss = sum(miss_times) / len(miss_times)

    # With salting OFF: miss takes significantly longer than hit (> 2x)
    assert mean_miss > 2.0 * mean_hit, (
        f"With salting OFF, probe failed to distinguish hit ({mean_hit*1000:.1f}ms) "
        f"from miss ({mean_miss*1000:.1f}ms)"
    )

    # =========================================================================
    # PART B: Salting is ON (Isolated per run)
    # =========================================================================
    # Each run gets a dedicated random cache_salt
    salted_times_run_a = []
    salted_times_run_b = []

    # Run A executes target prompt with Salt A
    salt_a = secrets.token_hex(16)
    server.evaluate(target_prompt, cache_salt=salt_a, simulate_timing=True)

    # In Run B (with Salt B), attacker attempts to probe whether target prompt was in Run A
    for _ in range(5):
        salt_b = secrets.token_hex(16)
        t0 = time.perf_counter()
        res = server.evaluate(target_prompt, cache_salt=salt_b, simulate_timing=True)
        salted_times_run_a.append(time.perf_counter() - t0)
        # MUST BE A MISS because salt_b != salt_a
        assert res["cache_hit"] is False

    # Measure fresh unprimed prompt in Run B
    for i in range(5):
        salt_c = secrets.token_hex(16)
        t0 = time.perf_counter()
        res = server.evaluate(f"UNSEEN_{i}_{secrets.token_hex(4)}", cache_salt=salt_c, simulate_timing=True)
        salted_times_run_b.append(time.perf_counter() - t0)
        assert res["cache_hit"] is False

    mean_salt_a = sum(salted_times_run_a) / len(salted_times_run_a)
    mean_salt_b = sum(salted_times_run_b) / len(salted_times_run_b)

    # With salting ON: timing distributions across runs are indistinguishable
    diff_ratio = abs(mean_salt_a - mean_salt_b) / mean_salt_a
    assert diff_ratio < 0.15, (
        f"With salting ON, timings leaked: Run A={mean_salt_a*1000:.1f}ms, Run B={mean_salt_b*1000:.1f}ms"
    )
