# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Source of truth

`PLAN.md` is the full spec: test catalogue, lab topology, profiles, milestones, CLI. Read it before starting a milestone. Work strictly milestone by milestone (M0 → M10, PLAN.md §10). Do not start the next milestone until the current one meets its acceptance criteria. Commit after each milestone using conventional commit messages with a descriptive body (see `SKILL.md`; no `Co-Authored-By` trailer). If the spec is ambiguous or contradicts what is on the machine, ask; do not guess.

## Commands

The environment is managed with `uv` (`.venv/` + committed `uv.lock`; project targets Python >=3.11). Use uv, not pip. Prefix tools with `uv run`.

```bash
uv sync --extra dev                                  # setup / update deps
uv run pytest -q                                     # unit tests (no root)
uv run pytest tests/unit/test_cli.py::test_version -q   # single test
uv run ruff check .                                  # lint
uv run mypy leakprobe                                # types
sudo -E LEAKPROBE_LAB=1 .venv/bin/pytest -m root     # integration tests (needs root + lab tools)
scripts/sandbox.sh uv run pytest -q                  # whole suite incl. root tests, no sudo
scripts/sandbox.sh bash                              # shell with a disposable "root" for lab work
```

`scripts/sandbox.sh` runs a command in an unprivileged user+mount+net namespace (tmpfs `/run`, overlay `/etc`), so the lab can be built and tested without sudo and without touching the host. sudo needs a password on this machine, so use the sandbox to verify lab code.

All three of pytest, ruff and mypy must be clean at the end of every milestone.

Lab/capture needs `iproute2`, `wireguard-tools`, `nftables`, `tcpdump` (Arch: `sudo pacman -S wireguard-tools tcpdump`; `wg` and `tcpdump` were missing at project start).

## Architecture

The core idea: on the physical interface, only VPN-endpoint traffic and housekeeping (ARP, NDP 133–137, DHCPv4/v6, optionally LAN) are allowed. Everything else is a leak. Almost every test runs the same pipeline:

```
scenario (probes/, faults/, lab/) -> capture/pcap.py (tcpdump on phys iface) -> PacketRecord list
  -> analyzers/packet_classifier.py (ENDPOINT | HOUSEKEEPING | LAN | LEAK[dns|ipv6|other])
  -> tests_impl/<test_id>.py -> Finding -> report/ (terminal | json | markdown, + remediation)
```

Key boundaries:
- **Capture vs analysis.** Anything needing root (namespaces, tcpdump, fault injection) lives in `lab/`, `capture/`, `faults/`, `probes/`. `analyzers/` and `report/` are pure functions over models and must be unit-testable without root. `analyze`, `audit-routes --from-file` and `report` must run without root.
- **Subprocess.** `leakprobe/util/sh.py` is the only place that spawns processes. Always pass argument lists; never use `shell=True`. Namespace execution (`util/netns.py`) goes through it.
- **CLI.** `cli.py` is a thin typer layer with no logic.
- **Models.** `models.py` (pydantic v2): `PacketRecord`, `Finding`, `Report`, `Status`, `Severity`. Exit codes: 0 all pass (WARN ok unless `--strict`), 1 any FAIL, 2 tool/setup error.
- **Route prediction.** `analyzers/route_predictor.py` walks `ip rule` by priority (from/to/fwmark/lookup/`suppress_prefixlength`), then does longest-prefix match with a lowest-metric tie-break, for v4 and v6. It must flag `0.0.0.0/1 + 128.0.0.0/1` via a non-tunnel device with the TunnelVision / CVE-2024-3661 message.
- **Route audit scope.** LP-ROUTE-01 audits IPv6 only when a tunnel route covers an IPv6 test destination; for a v4-only tunnel, IPv6 egress is LP-V6-01's job (keeps `wg-default-leaky`'s expected ROUTE=pass). Bypass = a non-tunnel route with prefix > /0 that actually wins `predict_egress` for an address inside it; the endpoint host route, link-scope prefixes and the directly connected private subnet are exempt, and routed private prefixes are exempt only with `--allow-lan`. Rule selectors the predictor can't evaluate (uidrange, oif, ports…) never match.
- **Classifier.** MLD (ICMPv6 130–132, 143) counts as HOUSEKEEPING along with NDP 133–137, because the kernel emits it on any IPv6-enabled link. LAN = both ends in local prefixes (or a multicast/broadcast destination), only with `--allow-lan`.
- **Probes and test modules.** Probes run in the namespace under test as `python -m leakprobe.probes <udp|stream|ident|dns>` (JSON on stdout or `--out`), launched through `probes/runner.py`. Each `tests_impl/<test>.py` has a pure `evaluate_*()` (unit-tested) and a `run_*(ctx: RunContext)` that probes/captures; `RunContext` (`tests_impl/context.py`, built by `RunContext.from_lab(state)`) carries namespace, interfaces, endpoint, canary, expected exits and resolver logs. LP-IDENT-01 checks IPv4 only (IPv6 egress is LP-V6-01's). LP-V6-01 is FAIL on any leaked IPv6 packet, WARN if IPv6 is routed outside the tunnel but nothing leaked.
- **Kill-switch timing.** Leak-window math compares pcap kernel timestamps with `time.time()` taken after the fault command, on the same host. Fault injectors expose `inject()`/`restore()`; always call `restore()` in `finally`.

## Lab

There are four namespaces, all prefixed `lp-`: `lp-client — lp-isp — lp-vpn — lp-inet`, plus a direct `isp → inet` path. Capture happens in `lp-client` on `c-phys`.
- The canary/beacon is `198.51.100.10` / `2001:db8:198::10`.
- The exit IP seen by the beacon is `192.0.2.2` via the VPN and `198.51.100.1` via a leak.
- The fake resolvers are the ISP's at `192.168.100.1:53` and the VPN's at `10.66.0.1:53`. Both log qnames, and a DNS leak means the ISP resolver saw the `lp-<uuid8>.leakprobe.test` label.
- `lab up` is idempotent. `lab down` removes every `lp-*` object even after a crash (state in `/run/leakprobe/lab.json`; a context manager plus `atexit` guarantees cleanup).
- Only private and documentation address ranges may be used. Never route lab traffic to real public addresses.
- WireGuard keys are generated per run and must never be committed.

Lab code: `lab/topology.py` holds the whole address plan (import from it, don't repeat addresses); `lab/builder.py` does up/down/status plus `running_lab()` (a context manager with `atexit`); `lab/services.py` runs beacon/canary/DNS as `python -m leakprobe.lab.services` inside namespaces, detached with stderr in `/run/leakprobe/*.stderr`; resolver query logs are in `/run/leakprobe/{isp,vpn}-dns.log`. Beyond PLAN.md's table, IPv6 has `2001:db8:51::/64` (isp–inet) and `2001:db8:192::/64` (vpn–inet), plus `fd66::/64` in the tunnel, and the ISP masquerades everything except toward the client. `lab up` primes ARP/NDP between ISP and client (`_prime_neighbors`); without it the first IPv6 probes sit in the neighbor queue and never hit the wire. The client's wg0 uses wg-quick-style routing (fwmark `0xca6c`, table 51820). `control-broken` has no tunnel at all (`wireguard: null`); `killswitch-v4` is an `ip`-family-only kill switch (used by `wg-ipv6-leak`).

Profiles in `leakprobe/lab/profiles/*.yaml` carry an `expected:` map (ground truth per test ID). `scripts/run_matrix.py` / `leakprobe matrix` compares measured results against it. The target is 100% agreement.

## Tests

- Route fixtures in `tests/fixtures/routes/*.json` are real `ip -j` output; regenerate them with `tests/fixtures/routes/generate.sh` (uses `unshare -rn`, no root). Note `ip -j route show table all` without `-4`/`-6` returns both families on iproute2 7.x.
- `tests/unit/`: no root. Generate pcaps with scapy inside the tests; do not commit binary pcaps. Text fixtures (route JSON, `ss` output) go in `tests/fixtures/`.
- `tests/integration/`: `@pytest.mark.root`, skipped unless `EUID == 0` and `LEAKPROBE_LAB=1`.

## Constraints

- No dependencies beyond typer, rich, pydantic v2, scapy, pyyaml (+ pytest, pytest-cov, ruff, mypy for dev) without asking.
- Every module needs type hints and a short docstring.
- `real` mode must print a probe-traffic notice and require `--yes`.

