"""Summary statistics."""

import pytest

from leakprobe.util.stats import percentile, summarize


def test_percentile_interpolates() -> None:
    values = [float(v) for v in range(1, 21)]  # 1..20
    assert percentile(values, 0) == 1.0
    assert percentile(values, 100) == 20.0
    assert percentile(values, 50) == pytest.approx(10.5)
    assert percentile(values, 95) == pytest.approx(19.05)


def test_percentile_edge_cases() -> None:
    assert percentile([], 95) == 0.0
    assert percentile([7.0], 95) == 7.0


def test_summarize() -> None:
    assert summarize([0.0, 0.0, 10.0, 30.0]) == {
        "mean": 10.0, "median": 5.0, "p95": pytest.approx(27.0), "max": 30.0,
    }
    assert summarize([]) == {"mean": 0.0, "median": 0.0, "p95": 0.0, "max": 0.0}
