"""LP-DNS-01: a unique label must reach only the tunnel resolver."""

from collections.abc import Mapping, Sequence
from typing import Any

from leakprobe.collectors.resolvers import parse_resolv_conf
from leakprobe.lab.services import read_dns_log
from leakprobe.models import Finding, Severity, Status
from leakprobe.probes import dns
from leakprobe.probes.runner import run_probe
from leakprobe.tests_impl.context import RunContext
from leakprobe.util import netns, sh

TEST_ID = "LP-DNS-01"
TITLE = "DNS leak"
TRUSTED = "vpn"  # resolver name whose queries are fine


def evaluate_dns(
    label: str,
    seen: Mapping[str, Sequence[str]],
    servers: Sequence[str],
    probe: Mapping[str, Any] | None = None,
) -> Finding:
    """Decide from which resolvers logged ``label`` (resolver name -> client IPs)."""
    leaked = {name: clients for name, clients in seen.items() if name != TRUSTED and clients}
    evidence = [f"label {label}", f"client nameservers: {', '.join(servers) or 'none'}"]
    for name, clients in seen.items():
        who = ", ".join(sorted(set(clients))) if clients else "not seen"
        evidence.append(f"{name} resolver: {who}")
    if probe:
        system = probe.get("system", {})
        evidence.append(f"system resolution: {'ok' if system.get('ok') else 'failed'}")
    metrics: dict[str, float | int | str] = {
        f"{name}_queries": len(clients) for name, clients in seen.items()
    }
    if leaked:
        names = ", ".join(sorted(leaked))
        status, summary = Status.FAIL, f"Untrusted resolver ({names}) saw the probe label"
    elif seen.get(TRUSTED):
        status, summary = Status.PASS, "Only the tunnel resolver saw the probe label"
    else:
        status, summary = Status.WARN, "No resolver logged the probe label (inconclusive)"
    return Finding(
        test_id=TEST_ID, title=TITLE, status=status, severity=Severity.HIGH,
        summary=summary, evidence=evidence, metrics=metrics,
    )


def client_nameservers(ctx: RunContext) -> list[str]:
    """Nameservers from the client's resolv.conf (inside its namespace in lab mode)."""
    argv = ["cat", "/etc/resolv.conf"]
    out = netns.run(ctx.client_ns, argv) if ctx.client_ns else sh.run(argv)
    return parse_resolv_conf(out.stdout)


def run_dns(ctx: RunContext) -> Finding:
    """Resolve a fresh label via the system and each nameserver, then read resolver logs."""
    if not ctx.dns_logs:
        return Finding(
            test_id=TEST_ID, title=TITLE, status=Status.SKIP, severity=Severity.HIGH,
            summary="Needs resolver logs (lab mode or a beacon resolver)",
        )
    label = dns.new_label()
    servers = client_nameservers(ctx)
    args = ["dns", "--label", label]
    for server in servers:
        args += ["--server", server]
    probe = run_probe(ctx.client_ns, *args)
    seen = {
        name: [client for _, client, qname in read_dns_log(log) if qname == label]
        for name, log in ctx.dns_logs.items()
    }
    return evaluate_dns(label, seen, servers, probe)
