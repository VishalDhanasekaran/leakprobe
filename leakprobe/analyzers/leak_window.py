"""Kill-switch metrics: which probe packets leaked after the fault, and for how long."""

from collections.abc import Sequence
from dataclasses import dataclass

from leakprobe.analyzers.packet_classifier import ClassifierContext, PacketClass, classify
from leakprobe.models import PacketRecord
from leakprobe.util.stats import summarize


@dataclass(frozen=True)
class TrialResult:
    """Outcome of one fault-injection trial (times in ms after the fault)."""

    leak_packets: int = 0
    time_to_first_leak_ms: float | None = None
    leak_window_ms: float | None = None
    probe_sent: int = 0
    probe_errors: int = 0
    error: str | None = None

    @property
    def leaked(self) -> bool:
        return self.leak_packets > 0


def is_probe(pkt: PacketRecord, canary: str, port: int) -> bool:
    """True for packets of the steady probe flow (UDP to the canary port)."""
    return pkt.proto == "udp" and pkt.dst == canary and pkt.dport == port


def analyze_trial(
    records: Sequence[PacketRecord],
    t_fault: float,
    classifier: ClassifierContext,
    canary: str,
    port: int,
    probe_sent: int = 0,
    probe_errors: int = 0,
) -> TrialResult:
    """PLAN.md 6.4: leaked probe packets with ``ts >= t_fault`` and their timing."""
    leaks = sorted(
        (
            p for p in records
            if p.ts >= t_fault
            and is_probe(p, canary, port)
            and classify(p, classifier).cls is PacketClass.LEAK
        ),
        key=lambda p: p.ts,
    )
    if not leaks:
        return TrialResult(probe_sent=probe_sent, probe_errors=probe_errors)
    return TrialResult(
        leak_packets=len(leaks),
        time_to_first_leak_ms=(leaks[0].ts - t_fault) * 1000,
        leak_window_ms=(leaks[-1].ts - t_fault) * 1000,
        probe_sent=probe_sent,
        probe_errors=probe_errors,
    )


def summarize_trials(trials: Sequence[TrialResult]) -> dict[str, float | int | str]:
    """Aggregate metrics over completed trials; a clean trial counts as 0 packets / 0 ms."""
    done = [t for t in trials if t.error is None]
    leaked = [t for t in done if t.leaked]
    metrics: dict[str, float | int | str] = {
        "trials": len(done),
        "failed_trials": len(trials) - len(done),
        "leaked_trials": len(leaked),
        "leak_fraction": round(len(leaked) / len(done), 3) if done else 0.0,
        "probe_sent": sum(t.probe_sent for t in done),
    }
    series = {
        "leak_packets": [float(t.leak_packets) for t in done],
        "leak_window_ms": [t.leak_window_ms or 0.0 for t in done],
        "time_to_first_leak_ms": [t.time_to_first_leak_ms or 0.0 for t in leaked],
    }
    for name, values in series.items():
        for stat, value in summarize(values).items():
            metrics[f"{name}_{stat}"] = round(value, 2)
    return metrics
