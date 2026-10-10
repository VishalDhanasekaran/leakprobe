# LeakProbe report

- **Overall:** FAIL
- **Mode:** lab
- **Started:** 2026-10-10T13:04:39.394523+00:00
- **Tool version:** 0.1.0

## Environment

| Key | Value |
|---|---|
| kernel | 6.18.46-1-lts |
| vpn | wireguard |
| tunnel | wg0 |
| physical | c-phys |
| endpoint | 203.0.113.10:51820 |
| tests | LP-ROUTE-01,LP-V6-01,LP-DNS-01,LP-KILL-01,LP-START-01,LP-SPLIT-01,LP-EGRESS-01,LP-IDENT-01 |
| fault | link-down x 3 trials |
| profile | wg-default-leaky |

## Summary

| Test | Title | Status | Severity | Summary |
|---|---|---|---|---|
| LP-ROUTE-01 | Route audit | PASS | high | All 4 test destinations egress via wg0 |
| LP-V6-01 | IPv6 leak | FAIL | high | 5 IPv6 packets left outside the tunnel |
| LP-DNS-01 | DNS leak | FAIL | high | Untrusted resolver (isp) saw the probe label |
| LP-KILL-01 | Kill switch | FAIL | critical | Leaked in 3/3 trials after link-down: median 295 packets, p95 window 2956 ms |
| LP-START-01 | Startup race | FAIL | medium | 99 probe packets leaked before the tunnel was up |
| LP-SPLIT-01 | Split-tunnel audit | PASS | low | No sockets or rules that bypass the tunnel were found |
| LP-EGRESS-01 | Allowlist audit | FAIL | high | 12 of 31 packets leaked (ipv6 8, dns 4) |
| LP-IDENT-01 | Egress identity | PASS | high | Beacon saw the VPN exit 192.0.2.2 |

## LP-ROUTE-01: Route audit (PASS)

All 4 test destinations egress via wg0

**Evidence**

- 1.1.1.1 -> wg0 (table 51820, 0.0.0.0/0, rule 32765)
- 8.8.8.8 -> wg0 (table 51820, 0.0.0.0/0, rule 32765)
- 9.9.9.9 -> wg0 (table 51820, 0.0.0.0/0, rule 32765)
- 2606:4700:4700::1111 -> c-phys via fd00:100::1 (table main, ::/0, rule 32766) [IPv6 not tunneled; see LP-V6-01]
- 198.51.100.10 -> wg0 (table 51820, 0.0.0.0/0, rule 32765)
- 2001:db8:198::10 -> c-phys via fd00:100::1 (table main, ::/0, rule 32766) [IPv6 not tunneled; see LP-V6-01]

| Metric | Value |
|---|---|
| destinations | 4 |
| outside_tunnel | 0 |
| bypass_routes | 0 |
| ipv6_audited | no |

## LP-V6-01: IPv6 leak (FAIL)

5 IPv6 packets left outside the tunnel

**Evidence**

- route: 2001:db8:198::10 -> c-phys (table main, ::/0, rule 32766)
- IPv6 disabled on physical interface: no
- IPv6 packets leaked on physical interface: 5
- leak: udp fd00:100::2 -> [2001:db8:198::10]:9000
- leak: udp fd00:100::2 -> [2001:db8:198::10]:9000
- leak: udp fd00:100::2 -> [2001:db8:198::10]:9000
- leak: udp fd00:100::2 -> [2001:db8:198::10]:9000
- leak: udp fd00:100::2 -> [2001:db8:198::10]:9000

| Metric | Value |
|---|---|
| ipv6_leak_packets | 5 |
| ipv6_dns_leaks | 0 |
| static | not tunneled |

**Remediation**

```
# WireGuard [Peer]: send every IPv4 and IPv6 destination through the tunnel
AllowedIPs = 0.0.0.0/0, ::/0

# or, if the VPN has no IPv6: disable IPv6 on the physical interface
sysctl -w net.ipv6.conf.c-phys.disable_ipv6=1

# nftables kill switch (load with `nft -f`; keep it loaded before the tunnel starts)
table inet leakprobe_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "wg0" accept
    ip daddr 203.0.113.10 udp dport 51820 accept
    udp sport 68 udp dport 67 accept
    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}

```

## LP-DNS-01: DNS leak (FAIL)

Untrusted resolver (isp) saw the probe label

**Evidence**

- label lp-2fa61dc8.leakprobe.test
- client nameservers: 192.168.100.1
- isp resolver: 192.168.100.2
- vpn resolver: not seen
- system resolution: ok

| Metric | Value |
|---|---|
| isp_queries | 2 |
| vpn_queries | 0 |

**Remediation**

```
# WireGuard [Interface] (wg-quick): use only the tunnel resolver
DNS = 10.66.0.1
# with systemd-resolved: route every lookup to the tunnel link
resolvectl dns wg0 10.66.0.1
resolvectl domain wg0 '~.'
resolvectl default-route c-phys false

# nftables kill switch (load with `nft -f`; keep it loaded before the tunnel starts)
table inet leakprobe_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "wg0" accept
    ip daddr 203.0.113.10 udp dport 51820 accept
    udp sport 68 udp dport 67 accept
    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}

```

## LP-KILL-01: Kill switch (FAIL)

Leaked in 3/3 trials after link-down: median 295 packets, p95 window 2956 ms

**Evidence**

- method link-down, 3 trials, observed 3000 ms after each fault (leak windows cannot exceed this)
- trial 1: 295 probe packets leaked, first after 1.2 ms, last after 2941.6 ms
- trial 2: 296 probe packets leaked, first after 7.3 ms, last after 2957.3 ms
- trial 3: 295 probe packets leaked, first after 3.8 ms, last after 2943.7 ms

| Metric | Value |
|---|---|
| trials | 3 |
| failed_trials | 0 |
| leaked_trials | 3 |
| leak_fraction | 1.0 |
| probe_sent | 1500 |
| leak_packets_mean | 295.33 |
| leak_packets_median | 295.0 |
| leak_packets_p95 | 295.9 |
| leak_packets_max | 296.0 |
| leak_window_ms_mean | 2947.55 |
| leak_window_ms_median | 2943.75 |
| leak_window_ms_p95 | 2955.97 |
| leak_window_ms_max | 2957.33 |
| time_to_first_leak_ms_mean | 4.09 |
| time_to_first_leak_ms_median | 3.77 |
| time_to_first_leak_ms_p95 | 6.94 |
| time_to_first_leak_ms_max | 7.29 |
| method | link-down |

**Remediation**

```
# nftables kill switch (load with `nft -f`; keep it loaded before the tunnel starts)
table inet leakprobe_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "wg0" accept
    ip daddr 203.0.113.10 udp dport 51820 accept
    udp sport 68 udp dport 67 accept
    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}

```

## LP-START-01: Startup race (FAIL)

99 probe packets leaked before the tunnel was up

**Evidence**

- tunnel ready 17.7 ms after bring-up started
- 99 probe packets left on the physical interface over 980 ms before the tunnel was ready
- 97 before bring-up started, 2 during it

| Metric | Value |
|---|---|
| leak_packets | 99 |
| probe_sent | 199 |
| time_to_ready_ms | 17.7 |
| leak_span_ms | 980.1 |

**Remediation**

```
# nftables kill switch (load with `nft -f`; keep it loaded before the tunnel starts)
table inet leakprobe_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "wg0" accept
    ip daddr 203.0.113.10 udp dport 51820 accept
    udp sport 68 udp dport 67 accept
    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}

# load it at boot, before the VPN client, e.g. enable nftables.service with this
# ruleset in /etc/nftables.conf, or in wg-quick:
PreUp = nft -f /etc/nftables.d/leakprobe-killswitch.nft
```

## LP-SPLIT-01: Split-tunnel audit (PASS)

No sockets or rules that bypass the tunnel were found

**Evidence**

- limitation: only sockets bound to a physical address, or whose device binding ss reports (%iface), are visible; per-socket SO_MARK and other per-app routing are not

| Metric | Value |
|---|---|
| bypass_sockets | 0 |
| bypass_rules | 0 |

## LP-EGRESS-01: Allowlist audit (FAIL)

12 of 31 packets leaked (ipv6 8, dns 4)

**Evidence**

- ipv6: udp fd00:100::2 -> [2001:db8:198::10]:9000 (8 pkts)
- dns: udp 192.168.100.2 -> 192.168.100.1:53 (2 pkts)
- dns: udp 192.168.100.1 -> 192.168.100.2:45276 (1 pkt)
- dns: udp 192.168.100.1 -> 192.168.100.2:60962 (1 pkt)

| Metric | Value |
|---|---|
| packets | 31 |
| endpoint | 11 |
| housekeeping | 8 |
| lan | 0 |
| leak | 12 |
| leak_dns | 4 |
| leak_ipv6 | 8 |
| leak_other | 0 |

**Remediation**

```
# nftables kill switch (load with `nft -f`; keep it loaded before the tunnel starts)
table inet leakprobe_killswitch {
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    oifname "wg0" accept
    ip daddr 203.0.113.10 udp dport 51820 accept
    udp sport 68 udp dport 67 accept
    icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept
  }
}


# WireGuard [Interface] (wg-quick): use only the tunnel resolver
DNS = 10.66.0.1
# with systemd-resolved: route every lookup to the tunnel link
resolvectl dns wg0 10.66.0.1
resolvectl domain wg0 '~.'
resolvectl default-route c-phys false

# WireGuard [Peer]: send every IPv4 and IPv6 destination through the tunnel
AllowedIPs = 0.0.0.0/0, ::/0

# or, if the VPN has no IPv6: disable IPv6 on the physical interface
sysctl -w net.ipv6.conf.c-phys.disable_ipv6=1
```

## LP-IDENT-01: Egress identity (PASS)

Beacon saw the VPN exit 192.0.2.2

**Evidence**

- expected exit: 192.0.2.2
- beacon saw: 192.0.2.2

| Metric | Value |
|---|---|
| observed | 192.0.2.2 |
