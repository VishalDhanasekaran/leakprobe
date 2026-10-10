# LeakProbe demo: leaky VPN vs hardened VPN

This walkthrough reproduces the before/after demo from a fresh clone. It takes about 10
minutes, most of it the kill-switch trials. Everything runs in network namespaces on your
machine; no real VPN, account or internet traffic is involved.

## 0. Setup

```bash
git clone <this repo> leakprobe && cd leakprobe
uv sync
uv run leakprobe doctor
```

`doctor` must show `ok` for root (when run with sudo), `ip`, `wg`, `nft`, `tcpdump`, the
`wireguard` kernel module and network namespaces. Install whatever is missing (Arch:
`sudo pacman -S wireguard-tools nftables tcpdump`).

The commands below use `sudo .venv/bin/leakprobe`. To avoid sudo, open a sandbox shell with
`scripts/sandbox.sh bash` and use `uv run leakprobe` instead. Everything in the sandbox
disappears when you exit the shell.

## 1. Bring up the leaky lab

```bash
sudo .venv/bin/leakprobe lab up --profile wg-default-leaky
```

The table shows the four `lp-*` namespaces, the running canary/beacon and the two fake
resolvers, plus a recent WireGuard handshake. The profile is a typical "it works" setup:
WireGuard carries all IPv4, but IPv6 is left on, DNS still goes to the ISP resolver, and
there is no firewall.

## 2. Measure it

```bash
sudo .venv/bin/leakprobe run --mode lab --profile wg-default-leaky
```

`run` reuses the lab from step 1. Expected result (exit code 1):

| Test | Result | What it shows |
|---|---|---|
| LP-ROUTE-01 | PASS | IPv4 routing looks correct... |
| LP-V6-01 | **FAIL** | ...but IPv6 probes leave on `c-phys` from `fd00:100::2` |
| LP-DNS-01 | **FAIL** | the ISP resolver logged the unique `lp-xxxxxxxx.leakprobe.test` label |
| LP-KILL-01 | **FAIL** | after `ip link set wg0 down`, probe traffic leaks in every trial |
| LP-START-01 | **FAIL** | ~100 packets leak while the tunnel is coming back up |
| LP-SPLIT-01 | PASS | no bypass sockets or rules |
| LP-EGRESS-01 | **FAIL** | IPv6 and DNS packets on the physical interface in normal operation |
| LP-IDENT-01 | PASS | the beacon sees the VPN exit `192.0.2.2` over IPv4 |

Points worth making:
- **Routing is not protection.** LP-ROUTE-01 passes and IPv4 identity looks right, but the
  capture shows IPv6 and DNS leaving outside the tunnel.
- **The kill-switch leak window.** After a link-down, wg-quick-style routing falls back to
  the main table. Traffic then leaks for the whole observation window: each trial reports
  about 300 leaked packets at 100 pps, with the window reaching about 3000 ms (the
  `--post` length). A real client crash leaks until someone notices.
- **Every FAIL comes with a fix** under "Remediation", filled in with this lab's names:
  - the nftables kill switch
  - `AllowedIPs = 0.0.0.0/0, ::/0`
  - `DNS = 10.66.0.1` and the `resolvectl` equivalents
  - the `disable_ipv6` sysctl

Save the report as Markdown or JSON (`report` can re-render the JSON later without root):

```bash
sudo .venv/bin/leakprobe run --profile wg-default-leaky -f json -o leaky.json
leakprobe report leaky.json --format md
```

`docs/sample-report.md` is such a report, from a 3-trial run.

## 3. Apply the fixes: the hardened profile

```bash
sudo .venv/bin/leakprobe lab down
sudo .venv/bin/leakprobe lab up --profile wg-hardened
sudo .venv/bin/leakprobe run --mode lab --profile wg-hardened
```

`wg-hardened` applies exactly the fixes the leaky report suggested: full-tunnel
`AllowedIPs`, tunnel DNS and the nftables kill switch, loaded before the tunnel starts.
Expected result: all PASS (exit code 0). LP-KILL-01 reports 0 leaked packets across 20
trials, and LP-EGRESS-01 sees only endpoint and housekeeping packets.

To show the kill switch on its own, compare fault methods against the running lab:

```bash
sudo .venv/bin/leakprobe drop-test --method delete-iface --trials 10
sudo .venv/bin/leakprobe drop-test --method endpoint-block --trials 10   # dead tunnel, iface up
```

## 4. Validate the tool: the matrix

```bash
sudo .venv/bin/leakprobe lab down
sudo .venv/bin/leakprobe matrix --trials 5 --save-dir reports/ -o matrix.md
```

This builds each of the seven profiles in turn, runs the full suite, and compares the
results with the profile's `expected:` ground truth. Expect about 5 minutes. The output
is a profiles x tests table with a mark for every cell that matches or disagrees. It also
reports agreement, plus precision and recall for detecting FAIL. The target is 100%
agreement with 100% precision and recall. To re-score the saved reports later without
root:

```bash
leakprobe matrix --from-dir reports/
```

Profiles worth pointing at:
- `wg-tunnelvision`: LP-ROUTE-01 fails with the CVE-2024-3661 message, and the fix lists the
  exact `ip route del` commands for the injected `/1` routes.
- `wg-ipv6-leak`: an IPv4-only kill switch passes LP-KILL-01 but still fails LP-V6-01.
- `control-broken`: the tunnel never comes up, and every test with ground truth fails.

## 5. Clean up

```bash
sudo .venv/bin/leakprobe lab down     # removes every lp-* namespace, even after a crash
```
