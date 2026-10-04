"""Probe entry point: ``python -m leakprobe.probes <kind> ...`` prints one JSON object.

Probes run inside the namespace under test (``ip netns exec lp-client ...``) so that they
use that namespace's routes, firewall and resolv.conf.
"""

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from leakprobe.probes import dns, identity, traffic


def main(argv: Sequence[str] | None = None) -> None:
    """Parse arguments, run one probe, print its JSON result (or write it to ``--out``)."""
    parser = argparse.ArgumentParser(prog="leakprobe.probes")
    sub = parser.add_subparsers(dest="kind", required=True)

    udp = sub.add_parser("udp")
    udp.add_argument("--dst", required=True)
    udp.add_argument("--port", type=int, required=True)
    udp.add_argument("--count", type=int, default=5)
    udp.add_argument("--interval", type=float, default=0.05)

    stream = sub.add_parser("stream")
    stream.add_argument("--dst", required=True)
    stream.add_argument("--port", type=int, required=True)
    stream.add_argument("--rate", type=float, default=100.0)
    stream.add_argument("--duration", type=float, required=True)

    ident = sub.add_parser("ident")
    ident.add_argument("--host", required=True)
    ident.add_argument("--port", type=int, required=True)

    dns_p = sub.add_parser("dns")
    dns_p.add_argument("--label", required=True)
    dns_p.add_argument("--server", action="append", default=[])

    parser.add_argument("--out", type=Path, help="write the JSON result here instead of stdout")
    args = parser.parse_args(argv)

    result: dict[str, object]
    if args.kind == "udp":
        result = dict(traffic.send_udp(args.dst, args.port, args.count, args.interval))
    elif args.kind == "stream":
        result = dict(traffic.stream_udp(args.dst, args.port, args.rate, args.duration))
    elif args.kind == "ident":
        result = dict(identity.query_beacon(args.host, args.port))
    else:
        result = {
            "system": dns.system_resolve(args.label),
            "direct": [dns.direct_query(s, args.label) for s in args.server],
        }
    text = json.dumps(result)
    if args.out:
        args.out.write_text(text)
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":
    main()
