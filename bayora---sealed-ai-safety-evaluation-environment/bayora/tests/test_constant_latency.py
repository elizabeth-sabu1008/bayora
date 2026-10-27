import pytest
import time
from gateway.shaped_oracle import ShapedOracle
from common.models import CoarseVerdict


def percentile(data, p):
    """Compute p-th percentile from sorted list."""
    sorted_d = sorted(data)
    idx = int(len(sorted_d) * (p / 100.0))
    idx = min(idx, len(sorted_d) - 1)
    return sorted_d[idx]


def test_reply_times_for_blocked_vs_passed_differ_by_less_than_5_percent():
    """
    Acceptance Test: Reply times for blocked vs passed prompts differ by less than 5%
    (measure p50 and p95 over 200 requests).
    Guarantees timing side-channel resistance.
    """
    deadline = 0.020  # 20ms fixed deadline
    oracle = ShapedOracle(deadline_seconds=deadline)

    blocked_durations = []
    passed_durations = []

    # Fast block function: takes ~1ms of work
    def fast_block():
        time.sleep(0.002)
        return CoarseVerdict.BLOCKED

    # Slow pass function: takes ~9ms of work
    def slow_pass():
        time.sleep(0.009)
        return CoarseVerdict.PASSED

    # Run 100 requests for blocked
    for _ in range(100):
        verdict, duration = oracle.execute_with_constant_latency(fast_block, deadline_override=deadline)
        assert verdict == CoarseVerdict.BLOCKED
        blocked_durations.append(duration)

    # Run 100 requests for passed
    for _ in range(100):
        verdict, duration = oracle.execute_with_constant_latency(slow_pass, deadline_override=deadline)
        assert verdict == CoarseVerdict.PASSED
        passed_durations.append(duration)

    # Total 200 requests measured
    assert len(blocked_durations) + len(passed_durations) == 200

    # Calculate p50 (median) and p95
    p50_blocked = percentile(blocked_durations, 50)
    p50_passed = percentile(passed_durations, 50)

    p95_blocked = percentile(blocked_durations, 95)
    p95_passed = percentile(passed_durations, 95)

    # Relative difference calculation
    p50_diff = abs(p50_blocked - p50_passed) / p50_blocked
    p95_diff = abs(p95_blocked - p95_passed) / p95_blocked

    # Assert both p50 and p95 differ by less than 5% (0.05)
    assert p50_diff < 0.05, (
        f"p50 timing difference {p50_diff:.4f} (>{5}%) between blocked ({p50_blocked*1000:.2f}ms) "
        f"and passed ({p50_passed*1000:.2f}ms)"
    )
    assert p95_diff < 0.05, (
        f"p95 timing difference {p95_diff:.4f} (>{5}%) between blocked ({p95_blocked*1000:.2f}ms) "
        f"and passed ({p95_passed*1000:.2f}ms)"
    )
