"""Small summary-statistics helpers (mean, median, p95, max)."""

import math
import statistics
from collections.abc import Sequence


def percentile(values: Sequence[float], q: float) -> float:
    """Linear-interpolated percentile, ``q`` in [0, 100]. 0.0 for an empty sequence."""
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (len(ordered) - 1) * q / 100
    low, high = math.floor(rank), math.ceil(rank)
    return ordered[low] + (ordered[high] - ordered[low]) * (rank - low)


def summarize(values: Sequence[float]) -> dict[str, float]:
    """mean / median / p95 / max, all 0.0 for an empty sequence."""
    if not values:
        return {"mean": 0.0, "median": 0.0, "p95": 0.0, "max": 0.0}
    return {
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "p95": percentile(values, 95),
        "max": max(values),
    }
