"""Kill-switch leak-window math (PLAN.md 6.4) on synthetic packet records."""

import pytest

from leakprobe.analyzers.leak_window import TrialResult, analyze_trial, summarize_trials
from leakprobe.analyzers.packet_classifier import ClassifierContext
from leakprobe.models import PacketRecord, Status
from leakprobe.tests_impl.killswitch import evaluate_killswitch

CTX = ClassifierContext("203.0.113.10", 51820)
T_FAULT = 1000.0


def udp(ts: float, dst: str = "198.51.100.10", dport: int = 9000) -> PacketRecord:
    return PacketRecord(ts=ts, iface="c-phys", l2="ether", l3="ipv4", proto="udp",
                        src="192.168.100.2", dst=dst, sport=40000, dport=dport, size=60)


def test_counts_only_probe_leaks_after_fault() -> None:
    records = [
        udp(999.9),                                 # before the fault: ignored
        udp(1000.0021),                             # first leak, 2.1 ms after
        udp(1000.010, dst="203.0.113.10", dport=51820),  # endpoint traffic: allowed
        udp(1000.020, dport=53),                    # a leak, but not the probe flow
        udp(1001.4305),                             # last leak, 1430.5 ms after
    ]
    r = analyze_trial(records, T_FAULT, CTX, "198.51.100.10", 9000, probe_sent=500)
    assert r.leak_packets == 2 and r.leaked
    assert r.time_to_first_leak_ms == pytest.approx(2.1)
    assert r.leak_window_ms == pytest.approx(1430.5)
    assert r.probe_sent == 500


def test_no_leak() -> None:
    r = analyze_trial([udp(999.0)], T_FAULT, CTX, "198.51.100.10", 9000)
    assert not r.leaked and r.time_to_first_leak_ms is None and r.leak_window_ms is None


def trials() -> list[TrialResult]:
    return [
        TrialResult(100, 1.0, 1000.0, 500),
        TrialResult(300, 3.0, 2900.0, 500),
        TrialResult(0, None, None, 500),
        TrialResult(error="tcpdump exited early"),
    ]


def test_summarize_trials() -> None:
    m = summarize_trials(trials())
    assert (m["trials"], m["failed_trials"], m["leaked_trials"]) == (3, 1, 2)
    assert m["leak_fraction"] == pytest.approx(0.667)
    assert m["leak_packets_mean"] == pytest.approx(133.33)
    assert m["leak_packets_median"] == 100.0 and m["leak_packets_max"] == 300.0
    assert m["leak_window_ms_max"] == 2900.0 and m["time_to_first_leak_ms_mean"] == 2.0
    assert m["probe_sent"] == 1500


def test_evaluate_fail_with_stats_and_evidence() -> None:
    f = evaluate_killswitch(trials(), "link-down", 3.0)
    assert f.status is Status.FAIL and f.severity.value == "critical"
    assert f.summary.startswith("Leaked in 2/3 trials after link-down")
    for key in ("leak_packets_mean", "leak_packets_median", "leak_packets_p95",
                "leak_packets_max", "leak_window_ms_p95", "leak_window_ms_max"):
        assert key in f.metrics
    assert f.metrics["method"] == "link-down"
    assert "trial 4: error: tcpdump exited early" in f.evidence
    assert "trial 1: 100 probe packets leaked, first after 1.0 ms, last after 1000.0 ms" in (
        f.evidence
    )


def test_evaluate_pass() -> None:
    f = evaluate_killswitch([TrialResult(probe_sent=500)] * 20, "link-down", 3.0)
    assert f.status is Status.PASS
    assert f.summary == "No probe packet leaked in 20 trials after link-down"


def test_evaluate_error_without_traffic() -> None:
    assert evaluate_killswitch([TrialResult(error="x")], "link-down", 3.0).status is Status.ERROR
    assert evaluate_killswitch([TrialResult()], "link-down", 3.0).status is Status.ERROR
