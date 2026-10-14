// LeakProbe lab presentation. Build: typst compile docs/slides/leakprobe.typ
// Plain Typst (no packages), 16:9.

#let ink = rgb("#1b2333")
#let accent = rgb("#2f6fdf")
#let muted = rgb("#5b6577")
#let soft = rgb("#eef2f8")
#let pass-c = rgb("#1f8a4c")
#let fail-c = rgb("#c23b33")
#let warn-c = rgb("#b7791f")

#set page(paper: "presentation-16-9", margin: (x: 1.6cm, top: 2.6cm, bottom: 1.2cm), fill: white)
#set text(font: ("Noto Sans", "DejaVu Sans"), size: 17pt, fill: ink)
#set par(leading: 0.6em)
#set list(spacing: 0.75em, marker: text(fill: accent)[▸])
#set enum(spacing: 0.75em)
#show raw: set text(font: "DejaVu Sans Mono", size: 0.88em)
#show raw.where(block: true): it => block(
  fill: soft, inset: (x: 12pt, y: 10pt), radius: 4pt, width: 100%, it,
)
#show strong: set text(fill: accent)

#let section = state("section", "")

#let slide(title, sec: none, body) = {
  if sec != none { section.update(sec) }
  page(
    header: context [
      #set text(size: 24pt, weight: "bold")
      #block(width: 100%, inset: (bottom: 6pt), stroke: (bottom: 2pt + accent))[
        #title
        #h(1fr)
        #text(size: 11pt, weight: "regular", fill: muted)[#section.get()]
      ]
    ],
    footer: context [
      #set text(size: 10pt, fill: muted)
      LeakProbe: measuring VPN leaks
      #h(1fr)
      #counter(page).display()
    ],
    body,
  )
}

#let tag(s) = {
  let c = if s == "PASS" { pass-c } else if s == "FAIL" { fail-c } else { warn-c }
  box(fill: c, inset: (x: 5pt, y: 2pt), radius: 3pt, text(fill: white, size: 0.8em, weight: "bold", s))
}

#let callout(body) = block(
  fill: soft, inset: 12pt, radius: 4pt, width: 100%, stroke: (left: 4pt + accent), body,
)

#let node(name, sub) = box(
  stroke: 1.5pt + ink, radius: 5pt, inset: (x: 10pt, y: 8pt), fill: white,
  align(center)[#text(weight: "bold", name) \ #text(size: 11pt, fill: muted, sub)],
)

// ---------------------------------------------------------------- title
#page(margin: 2cm, fill: ink)[
  #set text(fill: white)
  #v(1fr)
  #text(size: 44pt, weight: "bold")[LeakProbe]
  #v(-0.4em)
  #text(size: 22pt, fill: rgb("#a9c4f5"))[Measuring whether a VPN tunnel actually protects your traffic]
  #v(1.2em)
  #line(length: 30%, stroke: 2pt + rgb("#a9c4f5"))
  #v(0.6em)
  #text(size: 16pt)[
    Information Security Lab · Semester IX \
    Vishal D · 71762231059 · 71762231059\@cit.edu.in
  ]
  #v(1fr)
  #text(size: 12pt, fill: rgb("#a9c4f5"))[DNS leaks · IPv6 leaks · route bypass (CVE-2024-3661) · kill-switch failures · startup races · split tunnels]
]

// ================================================================ PROBLEM
#slide([“Connected” is not “protected”], sec: "Problem & objectives")[
  A VPN client shows a green *Connected* badge, but traffic can still leave
  *outside* the tunnel, where the ISP or the local network can see it:

  #grid(columns: (1fr, 1fr), gutter: 18pt,
    [
      - *DNS leak*: queries still go to the ISP resolver
      - *IPv6 leak*: tunnel carries only IPv4, IPv6 goes out directly
      - *Route bypass*: more-specific routes beat the tunnel's default route (TunnelVision, *CVE-2024-3661*)
    ],
    [
      - *Kill-switch failure*: the tunnel drops and traffic falls back to the physical link
      - *Startup race*: packets leave before the first handshake
      - *Split-tunnel surprises*: sockets or `ip rule`s pinned to the physical side
    ],
  )
  #v(0.4em)
  #callout[Users and admins usually only *believe* the VPN works. Online "leak test"
  pages check one thing at one moment, and they don't measure the window *during a failure*.]
]

#slide([Problem definition])[
  #callout[
    *Given* a Linux host with a VPN tunnel, *decide with measured evidence* whether
    any traffic leaves through the physical interface outside the tunnel, in steady
    state, *while the tunnel fails*, and *while it comes up*. Report how much
    leaks and how to fix it.
  ]
  #v(0.6em)
  Constraints that shaped the design:
  - Results must be *reproducible*: no real VPN account, no internet dependence
  - The tool must be *validated*: how do we know the leak detector itself is right?
  - Safety: only private / documentation address ranges; never probe networks we don't own
  - Linux + WireGuard; command-line tool; analysis must work offline on saved data
]

#slide([Objectives])[
  #enum(
    [Turn “I think my VPN protects me” into a *PASS / FAIL / WARN per test*, with evidence.],
    [Build a *deterministic lab* from Linux network namespaces, so every result can be reproduced on one laptop.],
    [*Quantify* the kill-switch leak window in packets and milliseconds over many trials (mean / median / p95 / max).],
    [Give a *remediation snippet* for every failure (nftables kill switch, `AllowedIPs`, DNS pinning, sysctl, route removal).],
    [*Validate the tool itself* against seeded-fault profiles with known ground truth, and report precision / recall.],
  )
  #v(0.4em)
  #text(fill: muted, size: 14pt)[Non-goals: browser-level leaks (WebRTC, in-app DoH), Windows/macOS, a GUI, “proving” there is no leak.]
]

// ================================================================ METHODOLOGY
#slide([Core idea: an allowlist on the physical interface], sec: "Methodology")[
  If the VPN works, the physical NIC should carry *only*:
  #grid(columns: (1fr, 1fr, 1fr), gutter: 14pt,
    callout[*ENDPOINT* \ encrypted UDP to/from the VPN server `IP:port`],
    callout[*HOUSEKEEPING* \ ARP, NDP (ICMPv6 133–137), MLD, DHCPv4/v6],
    callout[*LAN* \ local subnet, only with `--allow-lan`],
  )
  #v(0.3em)
  Everything else is a *LEAK*, tagged `dns` / `ipv6` / `other`.
  #v(0.5em)
  Almost every test is the same pipeline:
  #v(0.2em)
  #align(center)[
    #set text(size: 14pt)
    #node[Scenario][probe / fault / bring-up] #h(4pt) → #h(4pt)
    #node[Capture][tcpdump on phys iface] #h(4pt) → #h(4pt)
    #node[Classifier][allowlist per packet] #h(4pt) → #h(4pt)
    #node[Test logic][Finding + metrics] #h(4pt) → #h(4pt)
    #node[Report][term / JSON / MD + fix]
  ]
  #v(0.3em)
  #text(size: 14pt, fill: muted)[Capture and probing need root; classification and reporting are pure functions over saved data (unit-tested, no root).]
]

#slide([The lab: four network namespaces])[
  #align(center)[
    #set text(size: 14pt)
    #grid(columns: 7, column-gutter: 6pt, align: horizon,
      node[lp-client][192.168.100.2 \ wg0 10.66.0.2], [—],
      node[lp-isp][fake ISP DNS \ NAT → 198.51.100.1], [—],
      node[lp-vpn][endpoint 203.0.113.10:51820 \ VPN DNS · NAT → 192.0.2.2], [—],
      node[lp-inet][canary / beacon \ 198.51.100.10],
    )
    #v(-2pt)
    #text(size: 12pt, fill: muted)[\+ a direct `lp-isp → lp-inet` path, which is the route a leak takes]
  ]
  #v(0.4em)
  #grid(columns: (1fr, 1fr), gutter: 18pt,
    [
      - Capture point: `lp-client` / `c-phys` = *what the ISP sees*
      - The beacon reports the source IP it saw: `192.0.2.2` = via VPN, `198.51.100.1` = leaked
      - Two fake resolvers log every query name
    ],
    [
      - Only RFC 1918 / 5737 / 3849 ranges; never the real internet
      - WireGuard keys generated per run, never written to the repo
      - `lab up` is idempotent; `lab down` removes every `lp-*` object even after a crash (state file + `atexit`)
    ],
  )
]

#slide([Test catalogue])[
  #set text(size: 14.5pt)
  #table(
    columns: (auto, auto, 1fr, auto),
    stroke: none, inset: (x: 8pt, y: 6pt),
    fill: (_, y) => if y == 0 { ink } else if calc.odd(y) { soft } else { white },
    table.header(..([ID], [Test], [How it is measured], [Severity]).map(t => text(fill: white, weight: "bold", t))),
    [`LP-ROUTE-01`], [Route audit], [Simulate the kernel: walk `ip rule`, longest-prefix match; flag bypass routes], [HIGH],
    [`LP-V6-01`], [IPv6 leak], [Send an IPv6 probe, look for it on the physical capture; static `::/0` and sysctl check], [HIGH],
    [`LP-DNS-01`], [DNS leak], [Resolve a unique `lp-<uuid8>.leakprobe.test`; which resolver logged it?], [HIGH],
    [`LP-KILL-01`], [Kill switch], [100 pps probe, inject a tunnel fault, count leaked packets / ms, N trials], [CRITICAL],
    [`LP-START-01`], [Startup race], [Probe while the tunnel comes up; leaks before the first handshake], [MEDIUM],
    [`LP-SPLIT-01`], [Split tunnel], [Sockets pinned to the physical IP; foreign `uidrange` / `fwmark` rules (WARN only)], [LOW],
    [`LP-EGRESS-01`], [Allowlist audit], [Classify every packet seen during the normal-operation window], [HIGH],
    [`LP-IDENT-01`], [Egress identity], [Ask the beacon which source IP it saw], [HIGH],
  )
]

#slide([Measuring the kill-switch leak window])[
  #grid(columns: (1.1fr, 1fr), gutter: 20pt,
    [
      Per trial:
      + start tcpdump on `c-phys`
      + UDP stream to canary, *100 pps*, sequence numbers
      + wait `pre` s → *inject fault* → `t_fault = time.time()`
      + observe `post` s, stop, *always* `restore()` in `finally`
      + leaks = probe-flow LEAK packets with `ts ≥ t_fault`

      Faults: `link-down`, `delete-iface`, `endpoint-block` (dead tunnel, iface up → expected *blackhole*, not leak)
    ],
    [
      ```python
      leaks = [p for p in pkts
               if p.ts >= t_fault
               and classify(p) == LEAK
               and is_probe_flow(p)]
      leak_packets   = len(leaks)
      first_leak_ms  = (leaks[0].ts  - t_fault)*1000
      leak_window_ms = (leaks[-1].ts - t_fault)*1000
      ```
      #text(size: 13pt, fill: muted)[pcap kernel timestamps and `time.time()` on the same host, so the clocks agree.
      Reported over trials: leaked fraction, mean / median / p95 / max.]
    ],
  )
]

#slide([Other measurement techniques])[
  #grid(columns: (1fr, 1fr), gutter: 20pt,
    [
      *DNS leak: unique canary label*
      - Fresh `lp-<uuid8>.leakprobe.test` per run
      - Sent via `getaddrinfo` *and* directly to every configured nameserver
      - Leak ⇔ the *ISP* resolver's log contains the label: no guessing from packets

      *Startup race*
      - Snapshot + delete the tunnel, start capture + stream
      - Bring the tunnel up, poll `wg show latest-handshakes` every 10 ms → `t_ready`
      - Leaks = probe LEAK packets with `ts < t_ready`
    ],
    [
      *Route prediction (TunnelVision)*
      - Re-implements kernel policy routing: rules by priority (`from`, `to`, `fwmark`, `suppress_prefixlength`), then longest prefix, lowest metric, v4 + v6
      - `0.0.0.0/1 + 128.0.0.0/1` via the physical gateway beats `0.0.0.0/0` via `wg0` → FAIL citing *CVE-2024-3661*
      - Works offline on saved `ip -j` JSON, no root needed
    ],
  )
]

#slide([Validating the validator: seeded-fault profiles])[
  #set text(size: 15pt)
  #let P = tag("PASS")
  #let F = tag("FAIL")
  #table(
    columns: (auto, 1fr, auto, auto, auto, auto, auto, auto, auto),
    stroke: none, inset: (x: 5pt, y: 6pt), align: (left, left, center, center, center, center, center, center, center),
    fill: (_, y) => if y == 0 { ink } else if calc.odd(y) { soft } else { white },
    table.header(..([Profile], [Seeded fault], [ROUTE], [V6], [DNS], [KILL], [START], [EGRESS], [IDENT]).map(t => text(fill: white, weight: "bold", t))),
    [`wg-hardened`], [none (all fixes applied)], P, P, P, P, P, P, P,
    [`wg-default-leaky`], [v4-only, ISP DNS, no firewall], P, F, F, F, F, F, P,
    [`wg-ipv6-leak`], [v4-only tunnel + v4-only kill switch], P, F, P, P, P, F, P,
    [`wg-dns-leak`], [resolver left as ISP's], P, P, F, F, F, F, P,
    [`wg-no-killswitch`], [no firewall rule only], P, P, P, F, F, P, P,
    [`wg-tunnelvision`], [DHCP-style `/1 + /1` routes], F, P, P, F, F, F, F,
    [`control-broken`], [tunnel never comes up], F, F, F, F, F, F, F,
  )
  #v(0.3em)
  #set text(size: 15pt)
  Each profile's YAML carries this `expected:` map (ground truth). `leakprobe matrix` builds every
  profile in a fresh lab, runs the full suite and scores it: FAIL = positive class →
  *precision / recall*, plus exact-match agreement. *Target: 100%.*
]

#slide([Validation result: the matrix run])[
  #set text(size: 15.5pt)
  `leakprobe matrix --trials 3` builds all 7 profiles in fresh labs (≈ 5 min, rootless sandbox):
  #v(0.3em)
  #grid(columns: (1fr, 1fr, 1fr, 1fr), gutter: 12pt,
    ..(([Agreement], [48 / 49], [98%]), ([Precision (FAIL)], [100%], [0 false positives]),
       ([Recall (FAIL)], [96%], [24 / 25 leaks caught]), ([Missed leaks], [1], [TP 24 · TN 24 · FP 0 · FN 1]))
      .map(((k, v, d)) => block(fill: soft, inset: 12pt, radius: 4pt, width: 100%)[
        #text(size: 13pt, fill: muted, k) \
        #text(size: 26pt, weight: "bold", fill: accent, v) \
        #text(size: 13pt, d)
      ]),
  )
  #v(0.4em)
  - The one miss: `wg-ipv6-leak` / LP-V6-01 came back *ERROR* instead of FAIL; re-runs FAIL correctly
  - Cause seen on reproduction: under load the capture didn't start in time (`tcpdump not ready after 5 s`)
  - By design, a crashed test is reported as *ERROR* and the run continues. It is *never a silent PASS*, so it gives no false
    sense of safety. Next: retry the capture start-up / allow a longer readiness timeout.
  #callout[Measuring the tool against ground truth exposed a reliability bug that unit tests had missed. That is the point of the matrix.]
]

// ================================================================ USAGE
#slide([Commands and usage], sec: "Commands & usage")[
  #set text(size: 16pt)
  ```bash
  uv sync && uv run leakprobe doctor          # root, ip, wg, nft, tcpdump, kernel module

  leakprobe lab up --profile wg-default-leaky  # build the namespace lab
  leakprobe run --mode lab --profile wg-default-leaky [--tests LP-DNS-01,LP-KILL-01] [--trials 20]
  leakprobe drop-test --method link-down|delete-iface|endpoint-block --trials 25
  leakprobe matrix --trials 5 --save-dir reports/   # all profiles vs ground truth
  leakprobe lab down                                # removes every lp-* object

  # no root needed
  leakprobe analyze capture.pcap --endpoint 203.0.113.10:51820 [--allow-lan]
  leakprobe audit-routes --from-file routes.json
  leakprobe report results.json --format term|json|md
  leakprobe matrix --from-dir reports/

  # real host (prints a probe-traffic notice, needs --yes)
  leakprobe run --mode real --tunnel wg0 --physical eth0 --endpoint IP:PORT --yes
  ```
  Exit codes: `0` all pass · `1` any FAIL (or WARN with `--strict`) · `2` tool / setup error.
  No sudo? `scripts/sandbox.sh uv run leakprobe run …` runs it in an unprivileged user + net namespace.
]

#slide([Demo: leaky configuration])[
  `sudo .venv/bin/leakprobe run --mode lab --profile wg-default-leaky` (3 trials)
  #v(0.2em)
  #set text(size: 14.5pt)
  #table(
    columns: (auto, auto, 1fr),
    stroke: none, inset: (x: 8pt, y: 5pt),
    fill: (_, y) => if calc.odd(y) { soft } else { white },
    [`LP-ROUTE-01`], tag("PASS"), [All 4 IPv4 test destinations egress via `wg0`],
    [`LP-V6-01`], tag("FAIL"), [5 IPv6 packets left from `fd00:100::2` outside the tunnel],
    [`LP-DNS-01`], tag("FAIL"), [The ISP resolver logged the probe label],
    [`LP-KILL-01`], tag("FAIL"), [Leaked in *3/3* trials after link-down: median *295 packets*, p95 window *2956 ms*],
    [`LP-START-01`], tag("FAIL"), [*99* probe packets leaked before the tunnel was up],
    [`LP-SPLIT-01`], tag("PASS"), [No bypass sockets or rules],
    [`LP-EGRESS-01`], tag("FAIL"), [12 of 31 packets leaked (ipv6 8, dns 4)],
    [`LP-IDENT-01`], tag("PASS"), [Beacon saw the VPN exit `192.0.2.2`],
  )
  #v(0.2em)
  #callout[Routing and the IPv4 identity look perfect, yet the capture shows IPv6 and DNS leaving
  outside the tunnel, and after a link-down traffic leaks for the *entire* 3 s observation window.]
]

#slide([Demo: fix it, then re-measure])[
  Every FAIL comes with a fix filled in with this lab's names, e.g. the kill switch:
  #grid(columns: (1.15fr, 1fr), gutter: 18pt,
    [
      ```
      table inet leakprobe_killswitch {
        chain output {
          type filter hook output priority 0;
          policy drop;
          oifname "lo" accept
          oifname "wg0" accept
          ip daddr 203.0.113.10 udp dport 51820 accept
          udp sport 68 udp dport 67 accept
          icmpv6 type { nd-router-solicit,
            nd-neighbor-solicit,
            nd-neighbor-advert } accept
        }
      }
      ```
    ],
    [
      plus `AllowedIPs = 0.0.0.0/0, ::/0`, `DNS = 10.66.0.1`, the `disable_ipv6` sysctl,
      `ip route del` for TunnelVision routes.
      #v(0.4em)
      `wg-hardened` applies exactly these fixes:
      - *all 8 tests PASS*, exit code 0
      - LP-KILL-01: *0 leaked packets* across 20 trials
      - LP-EGRESS-01: only ENDPOINT + HOUSEKEEPING
    ],
  )
]

// ================================================================ INNOVATION
#slide([Innovation and critical thinking (1/2)], sec: "Innovation")[
  - *Allowlist, not blocklist.* We define what may appear on the NIC and treat everything else as a leak,
    so leak types nobody anticipated are still caught.
  - *Static analysis is not enough.* `wg-default-leaky` passes the route audit but leaks IPv6 and DNS.
    LeakProbe pairs a *route predictor* (what the kernel *should* do) with *packet capture* (what it *did*).
  - *Quantified failure, not a yes/no.* The kill switch is measured as a leak *window* in ms and packets with
    p95 over many trials, using same-host kernel timestamps.
  - *Partial fixes are caught.* `wg-ipv6-leak` has an IPv4-only kill switch: it PASSes LP-KILL-01 but still
    FAILs LP-V6-01. Fixing one thing can hide another.
  - *A blackhole is not a leak.* `endpoint-block` (server dead, interface up) is expected to PASS, so the test
    separates “no connectivity” from “unprotected connectivity”.
]

#slide([Innovation and critical thinking (2/2)])[
  #set text(size: 15.5pt)
  - *Testing the tester.* Seven seeded-fault profiles with ground truth; precision / recall for the leak
    detector itself, re-scorable offline from saved JSON.
  - *False positives and negatives found and fixed during measurement:*
    - the kernel sends *MLD* (ICMPv6 130–132, 143) on every IPv6 link, so it is classified as housekeeping, not a leak
    - the first IPv6 probes sat in the *neighbour queue* and never reached the wire, a silent false negative, so the lab primes ARP/NDP
    - disruptive tests (KILL, START) run *outside* the allowlist capture window so they don't contaminate EGRESS
  - *Honest limits.* LP-SPLIT-01 only WARNs: `SO_BINDTODEVICE` / `SO_MARK` are invisible from outside the process.
  - *Safe by construction.* Documentation-range addresses only; the tunnel snapshot used for fault recovery keeps the
    private key *in memory only*; `real` mode needs `--yes`; one subprocess wrapper, never `shell=True`.
  - *Rootless reproducibility.* `scripts/sandbox.sh` runs the whole lab in an unprivileged user + mount + net namespace.
]

#slide([Engineering quality])[
  #grid(columns: (1fr, 1fr), gutter: 24pt,
    [
      *Architecture*
      - Root-only code (`lab/`, `capture/`, `faults/`, `probes/`) is kept apart from pure `analyzers/` and `report/`
      - Each test = pure `evaluate_*()` + `run_*(ctx)`
      - Thin `typer` CLI; pydantic v2 models; JSON round-trip
      - A test that crashes becomes an ERROR finding; the run continues
    ],
    [
      *Verification*
      - *267 unit tests* (no root) + 35 root integration tests
      - Route fixtures = real `ip -j` output; pcaps generated with scapy inside the tests
      - `pytest`, `ruff`, `mypy` clean at every milestone
      - ≈ 4 000 lines of code, ≈ 2 400 lines of tests, 11 milestones (M0–M10)
    ],
  )
]

// ================================================================ CONCLUSION
#slide([Conclusion], sec: "Conclusion")[
  - LeakProbe turns “the VPN says connected” into *measured, reproducible evidence*: 8 tests, each with PASS / FAIL / WARN,
    evidence lines, metrics and a fix.
  - The namespace lab reproduces real failure modes (DNS leak, IPv6 leak, TunnelVision, missing kill switch, startup
    race) on a single laptop with no VPN account.
  - Key finding: a typical “working” WireGuard setup leaked IPv6 and DNS in normal operation, leaked *≈ 3 s of traffic per
    fault*, and leaked *about 100 packets* at every start. The hardened profile leaked *0*.
  - The tool is validated against ground truth instead of being trusted blindly: *98% agreement, 100% precision,
    96% recall* over 7 seeded-fault profiles.
  #v(0.4em)
  *Future work:* real-mode beacon server (authoritative DNS + “your IP is”), OpenVPN profiles, per-trial
  leak-window histograms, app-level (DoH / WebRTC) checks.
  #v(0.4em)
  #callout[A detected leak is evidence. No detected leak is not proof of safety.]
]

#page(margin: 2cm, fill: ink)[
  #set text(fill: white)
  #v(1fr)
  #align(center)[
    #text(size: 40pt, weight: "bold")[Thank you]
    #v(0.3em)
    #text(size: 20pt, fill: rgb("#a9c4f5"))[Questions?]
    #v(1.5em)
    #text(size: 14pt)[Live demo: `leakprobe run --profile wg-default-leaky` → `wg-hardened` → `leakprobe matrix`]
  ]
  #v(1fr)
]
