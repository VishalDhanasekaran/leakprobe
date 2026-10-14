// LeakProbe project report.
// Build: typst compile docs/report/leakprobe-report.typ
#import "@preview/fletcher:0.5.8" as fletcher: diagram, node, edge
#import "@preview/cetz:0.3.4"

#let author = "Vishal D"
#let roll = "71762231059"
#let email = "71762231059@cit.edu.in"

#let accent = rgb("#1f4e9c")
#let soft = rgb("#eef2f8")
#let muted = rgb("#555d6b")
#let pass-c = rgb("#1f8a4c")
#let fail-c = rgb("#c23b33")

#set document(title: "LeakProbe: Measuring VPN Tunnel Leaks on Linux", author: author)
#set page(paper: "a4", margin: (x: 2.3cm, top: 2.3cm, bottom: 2.3cm),
  footer: context align(center, text(size: 9pt, fill: muted, counter(page).display())))
#set text(font: ("Libertinus Serif", "DejaVu Serif"), size: 11pt, lang: "en")
#set par(justify: true, leading: 0.6em, spacing: 0.9em)
#show raw: set text(font: "DejaVu Sans Mono", size: 0.85em)
#show raw.where(block: true): it => block(fill: soft, inset: 7pt, radius: 3pt, width: 100%, it)
#set table(stroke: 0.5pt + rgb("#b8c0cc"), inset: 4.5pt, align: left)
#show table: set text(size: 9.5pt)
#show table: set par(justify: false)
#show table.cell.where(y: 0): set text(weight: "bold")
#show figure.caption: set text(size: 9pt)
#show figure: set block(breakable: false, spacing: 1.1em)
#show figure: set par(justify: false)
#show figure.where(kind: table): set figure.caption(position: top)
#set heading(numbering: "1.1")
#show heading.where(level: 1): set text(size: 14pt, fill: accent)
#show heading.where(level: 1): set block(above: 1.4em, below: 0.8em)
#show heading.where(level: 2): set text(size: 11.5pt, fill: accent)
#set list(indent: 0.5em, spacing: 0.6em)
#set enum(indent: 0.5em, spacing: 0.6em)
#show link: set text(fill: accent)

#let tag(s) = {
  let c = if s == "PASS" { pass-c } else if s == "FAIL" { fail-c } else { rgb("#b7791f") }
  box(fill: c, inset: (x: 3pt, y: 1.5pt), radius: 2pt, text(fill: white, size: 0.75em, weight: "bold", font: "DejaVu Sans", s))
}
#let P = tag("PASS")
#let F = tag("FAIL")
#let note(body) = block(fill: soft, inset: 8pt, radius: 3pt, width: 100%, stroke: (left: 3pt + accent), body)
#let sans(body) = { set par(justify: false); text(font: ("Noto Sans", "DejaVu Sans"), size: 8.5pt, body) }

// ======================================================================= cover page
#page(footer: none, margin: (x: 2.5cm, top: 3cm, bottom: 3cm))[
  #set text(fill: black)
  #set par(justify: false)
  #align(center)[
    #text(size: 17pt, weight: "bold", tracking: 0.5pt)[COIMBATORE INSTITUTE OF TECHNOLOGY]
    #v(0.6em)
    #line(length: 40%, stroke: 0.6pt)
    #v(0.6em)
    #text(size: 16pt)[20MSS94 Information Security]
    #v(-0.2em)
    #text(size: 16pt, style: "italic")[CAT-2 Project Report]
  ]
  #v(1fr)
  #align(center)[
    #text(size: 44pt, weight: "bold")[LeakProbe]
    #v(-0.6em)
    #text(size: 21pt, style: "italic")[Measuring Whether a VPN Tunnel \ Actually Protects Traffic on Linux]
  ]
  #v(1fr)
  #align(center)[
    #text(size: 13pt, style: "italic")[Submitted by]
    #v(0.1em)
    #text(size: 22pt)[#author]
    #v(0.1em)
    #text(size: 15pt)[Roll No. #roll] \
    #text(size: 15pt)[#email]
    #v(0.6em)
    #text(size: 13pt)[October 2026]
  ]
]

// ======================================================================= abstract
#heading(numbering: none, outlined: false)[Abstract]

A VPN client that reports _connected_ can still let traffic leave outside the
encrypted tunnel. DNS queries may go to the ISP resolver, IPv6 may bypass an IPv4-only
tunnel, more-specific routes may override the tunnel (TunnelVision, CVE-2024-3661), and
traffic may fall back to the physical link when the tunnel fails or before it comes up.
*LeakProbe* is a Linux command-line tool that measures these leaks instead of assuming they
don't happen. It treats the physical interface as an *allowlist*: only encrypted traffic to
the VPN endpoint and link-local housekeeping may appear there, and everything else is a leak.
Eight tests cover routing, IPv6, DNS, the kill switch, the startup race, split tunnelling,
overall egress and exit identity. Each one gives PASS / FAIL / WARN with evidence and a fix.
A deterministic four-namespace WireGuard lab reproduces the results without a VPN account,
and seven seeded-fault profiles validate the tool itself: *98 % agreement, 100 % precision,
96 % recall*. On a typical "working" configuration LeakProbe measured IPv6 and DNS leaks,
about 295 leaked packets (≈ 3 s) after every tunnel failure and 99 packets at start-up. The
hardened configuration leaked none.

*Keywords:* VPN leak detection, WireGuard, DNS leak, IPv6 leak, kill switch, TunnelVision,
network namespaces.

#pagebreak()

// ======================================================================= contents
#outline(title: [Contents], depth: 2, indent: auto)
#pagebreak()

// ======================================================================= 1
= Introduction and Problem Definition

A Virtual Private Network (VPN) wraps a host's traffic in an encrypted tunnel, so the local
network and the ISP see only encrypted packets to one endpoint. The guarantee holds only if
*every* packet enters the tunnel. On Linux that depends on several independent subsystems:
policy-routing rules, IPv4 and IPv6 routing tables, the resolver, the firewall, and the
client's behaviour when the tunnel goes down or comes up. Studies of commercial VPN clients
have repeatedly found IPv6 and DNS leakage and broken kill switches @perta2015 @khan2018, and
the 2024 TunnelVision attack showed that a malicious DHCP server can pull traffic out of
almost any routing-based VPN @tunnelvision. Browser "leak test" pages only see one moment from
the browser's viewpoint, and none of them measure what happens *during a failure*.

#note[
  *Problem.* Given a Linux host with a VPN tunnel, decide *with measured evidence* whether any
  traffic leaves the physical interface outside the tunnel, in steady state, while the
  tunnel *fails*, and while it *comes up*. Quantify the leak, explain the cause, and give the fix.
]

*Objectives.*
+ Give a *PASS / FAIL / WARN verdict per test*, with human-readable evidence and metrics.
+ Build a *deterministic lab* from Linux network namespaces, reproducible on one laptop without a VPN account or Internet access.
+ *Quantify* the kill-switch leak window (packets and ms; mean, median, p95, max over N trials).
+ Attach a *remediation snippet* to every failure.
+ *Validate the tool itself* against seeded-fault profiles and report precision and recall.

*Scope.* Linux and WireGuard only. Browser-level leaks (WebRTC, in-app DNS-over-HTTPS),
other operating systems, and networks the user does not own are out of scope. A detected
leak is evidence; no detected leak is not proof of safety.

// ======================================================================= 2
= Background

*WireGuard routing on Linux.* `wg-quick` @wgquick builds a full tunnel with policy routing
instead of replacing the default route (@fig-wgquick). The tunnel's own UDP packets carry
`fwmark 0xca6c`; every unmarked packet is sent to table 51820 (`0.0.0.0/0 dev wg0`). A rule
`lookup main suppress_prefixlength 0` lets the main table answer first for anything more
specific than /0, such as the local subnet. LeakProbe's lab reproduces this layout, and its
route predictor models these rules.

#figure(
  diagram(node-shape: rect,
    spacing: (14mm, 5mm), node-stroke: 0.7pt, node-corner-radius: 3pt, edge-stroke: 0.7pt,
    node((0, 0), sans[packet to _d_], name: <pkt>, fill: soft),
    node((0, 1), sans[rule 32764: `lookup main suppress_prefixlength 0`], name: <r1>),
    node((0, 2), sans[rule 32765: `not fwmark 0xca6c lookup 51820`], name: <r2>),
    node((0, 3), sans[rule 32766: `lookup main`], name: <r3>),
    node((1, 1), sans[main route more specific than /0], name: <lan>),
    node((1, 2), sans[`0.0.0.0/0 dev wg0` → *tunnel*], name: <wg>, fill: rgb("#e3f3e8")),
    node((1, 3), sans[default via ISP → *physical*], name: <phys>),
    edge(<pkt>, <r1>, "->"),
    edge(<r1>, <lan>, "->", sans[/1 … /32]),
    edge(<r1>, <r2>, "->", sans[only /0 → suppressed], label-side: left),
    edge(<r2>, <wg>, "->", sans[unmarked]),
    edge(<r2>, <r3>, "->", sans[marked (WireGuard's UDP)], label-side: left),
    edge(<r3>, <phys>, "->"),
  ),
  caption: [`wg-quick`-style policy routing in the client.],
) <fig-wgquick>

*TunnelVision (CVE-2024-3661).* DHCP option 121 @rfc3442 can push `0.0.0.0/1` and
`128.0.0.0/1` via the physical gateway @tunnelvision @cve20243661. Together they cover all of
IPv4 and beat any /0 under longest-prefix match. The suppress rule only hides /0 routes, so a /1
route in the main table wins at rule 32764 and traffic leaves in clear while the client still
shows _connected_.

#figure(
  table(
    columns: (auto, auto, auto, auto),
    table.header([Route (table)], [Prefix length], [Suppressed by rule 32764?], [Result for 8.8.8.8]),
    [`default via 192.168.100.1` (main)], [/0], [yes], [skipped],
    [`0.0.0.0/0 dev wg0` (51820)], [/0], [—], [would win in a correct setup],
    [`0.0.0.0/1 via 192.168.100.1` (main)], [/1], [*no* (1 > 0)], [*wins at rule 32764 → leak*],
  ),
  caption: [Why TunnelVision defeats `suppress_prefixlength 0` (profile `wg-tunnelvision`).],
)

#figure(
  table(
    columns: (auto, 1fr, auto),
    table.header([Leak class], [Mechanism], [Test]),
    [DNS leak], [Resolver still the ISP's; names resolved outside the tunnel], [LP-DNS-01],
    [IPv6 leak], [Tunnel carries only IPv4 while IPv6 stays routed via the physical link], [LP-V6-01],
    [Route bypass], [More-specific route via the physical gateway beats the tunnel's /0 (TunnelVision)], [LP-ROUTE-01],
    [Kill-switch failure], [Tunnel goes down; routing falls back to the physical default route], [LP-KILL-01],
    [Startup race], [Traffic sent before the first handshake], [LP-START-01],
    [Split-tunnel surprise], [Sockets bound to the physical IP; `uidrange`/foreign `fwmark` rules], [LP-SPLIT-01],
    [Identity leak], [Remote service sees the ISP address, not the VPN exit], [LP-IDENT-01],
  ),
  caption: [Leak classes and the test that covers each.],
)

// ======================================================================= 3
= Methodology and System Design

== Core idea: an allowlist on the physical interface

While the VPN is up, the physical interface may carry only (i) encrypted traffic to and from
the VPN endpoint and (ii) housekeeping: ARP, IPv6 NDP and MLD, DHCPv4/v6 (plus LAN with
`--allow-lan`). *Everything else is a leak.* Defining what is allowed, rather than listing
known-bad traffic, also catches leak types nobody anticipated. Almost every test runs the same
pipeline (@fig-pipeline). Code that needs root (lab, capture, probes, faults) is kept apart
from analysis and reporting, which are pure functions tested without root.

#figure(
  diagram(node-shape: rect,
    spacing: (8mm, 10mm), node-stroke: 0.7pt, node-corner-radius: 3pt, edge-stroke: 0.7pt,
    node((0, 0), sans[*Scenario* \ probe / fault / bring-up], name: <s>),
    node((1, 0), sans[*Capture* \ tcpdump on phys iface], name: <c>),
    node((0, 1), sans[*Parse* \ pcap → `PacketRecord`], name: <p>),
    node((1, 1), sans[*Classify* \ ENDPOINT · HOUSEKEEPING \ LAN · LEAK], name: <k>, fill: soft),
    node((2, 1), sans[*Evaluate* \ `evaluate_*()` → Finding], name: <e>),
    node((3, 1), sans[*Report* \ term · JSON · MD + fix], name: <r>),
    edge(<s>, <c>, "->"), edge(<c>, <p>, "->"), edge(<p>, <k>, "->"), edge(<k>, <e>, "->"), edge(<e>, <r>, "->"),
    node(enclose: (<s>, <c>), stroke: (dash: "dashed", paint: fail-c), inset: 5pt, snap: false),
    node((2.4, 0), text(size: 8pt, fill: fail-c)[← needs root: `lab/`, `capture/`, `faults/`, `probes/`], stroke: none),
    node(enclose: (<p>, <r>), stroke: (dash: "dashed", paint: pass-c), inset: 5pt, snap: false),
    node((1.5, 1.6), text(size: 8pt, fill: pass-c)[pure functions, unit-tested without root: `analyzers/`, `report/`], stroke: none),
  ),
  caption: [The common measurement pipeline.],
) <fig-pipeline>

#figure(
  table(
    columns: (auto, 1fr),
    table.header([Class], [Rule (first match wins)]),
    [ENDPOINT], [UDP/TCP to or from the endpoint IP (and port)],
    [HOUSEKEEPING], [ARP; ICMPv6 NDP 133–137 and MLD 130–132, 143; DHCPv4 67↔68; DHCPv6 546↔547],
    [LAN], [Only with `--allow-lan`: both ends local, or a multicast/broadcast destination],
    [LEAK], [Everything else, tagged `dns` (port 53/853), `ipv6`, or `other`],
  ),
  caption: [Allowlist packet classifier.],
)

== Architecture

#figure(
  {
    set text(font: ("Noto Sans", "DejaVu Sans"), size: 8.5pt)
    let layer(title, items, fill: white) = block(
      width: 100%, inset: 6pt, radius: 3pt, stroke: 0.7pt, fill: fill,
      grid(columns: (2.6cm, 1fr), align: horizon, text(weight: "bold", title),
        grid(columns: items.len(), column-gutter: 4pt,
          ..items.map(i => block(width: 100%, inset: 4pt, radius: 2pt, stroke: 0.5pt + muted, align(center, i))))),
    )
    stack(spacing: 4pt,
      layer([Interface], ([`cli.py` (typer)], [`doctor.py`], [`scripts/run_matrix.py`])),
      layer([Orchestration], ([`orchestrator.py` \ order, ERROR capture], [`matrix.py` \ ground-truth scoring], [`report/remediation.py` \ fix snippets]), fill: soft),
      layer([Tests], ([`route_audit`], [`ipv6_leak`], [`dns_leak`], [`killswitch`], [`startup`], [`split`], [`egress`], [`identity`])),
      grid(columns: (1fr, 1fr), column-gutter: 4pt,
        layer([Privileged], ([`lab/`], [`capture/`], [`probes/`], [`faults/`], [`collectors/`]), fill: rgb("#fbeceb")),
        layer([Pure], ([`analyzers/`], [`report/`], [`models.py`]), fill: rgb("#e3f3e8")),
      ),
      layer([System], ([`util/sh.py` (only subprocess entry)], [`util/netns.py`], [`ip` · `wg` · `nft` · `tcpdump`])),
    )
  },
  kind: image,
  caption: [Layered architecture of LeakProbe.],
) 

A thin `typer` CLI calls the orchestrator. The orchestrator runs eight test modules, each
with a pure `evaluate_*()` and a privileged `run_*(ctx)`. Below that sit the privileged
packages (`lab/`, `capture/`, `probes/`, `faults/`, `collectors/`) and the pure ones
(`analyzers/`, `report/`), linked by pydantic models (@fig-model).
`util/sh.py` is the only module that starts processes. It takes argument lists and never
uses `shell=True`.

#figure(
  {
    set text(font: ("Noto Sans", "DejaVu Sans"), size: 8.5pt)
    let cls(name, fields) = block(stroke: 0.7pt, radius: 3pt, width: 100%, clip: true,
      stack(block(fill: soft, inset: 5pt, width: 100%, text(weight: "bold", name)),
        block(inset: 5pt, width: 100%, raw(fields.join("\n")))))
    diagram(node-shape: rect,
      spacing: (10mm, 8mm), edge-stroke: 0.7pt,
      node((0, 0), cls("Report", ("tool_version: str", "started_at: datetime", "mode: lab | real", "environment: dict", "findings: list[Finding]", "overall: Status")), name: <rep>, width: 4.2cm),
      node((1, 0), cls("Finding", ("test_id: str", "title: str", "status: Status", "severity: Severity", "summary: str", "evidence: list[str]", "metrics: dict", "remediation: str | None")), name: <fin>, width: 4.2cm),
      node((2, 0), cls("PacketRecord", ("ts: float", "iface, l2, l3, proto", "src, dst: str", "sport, dport: int", "size: int", "icmp6_type: int")), name: <pk>, width: 4cm),
      node((0.5, 1), cls("Status", ("PASS FAIL WARN", "SKIP ERROR",)), name: <st>, width: 3cm),
      node((1.5, 1), cls("Severity", ("INFO LOW MEDIUM", "HIGH CRITICAL",)), name: <sv>, width: 3cm),
      edge(<rep>, <fin>, "-|>", sans[1 … \*]),
      edge(<fin>, <st>, "->"), edge(<fin>, <sv>, "->"), edge(<rep>, <st>, "->"),
      edge(<pk>, <fin>, "-->", sans[classified into], label-side: right),
    )
  },
  kind: image,
  caption: [Core data models (`models.py`).],
) <fig-model>

== Laboratory

Four network namespaces form the lab (@fig-topo). Both `lp-isp` and `lp-vpn` masquerade, so
the beacon in `lp-inet` sees `192.0.2.2` for tunnelled traffic and `198.51.100.1` for leaked
traffic. Capture runs in `lp-client` on `c-phys`, which is what the ISP sees. The lab uses only
RFC 1918 / 5737 / 3849 addresses, generates WireGuard keys per run, and `lab down` removes
every `lp-*` object even after a crash.

#figure(
  diagram(node-shape: rect,
    spacing: (8mm, 12mm), node-stroke: 0.8pt, node-corner-radius: 4pt, edge-stroke: 0.8pt,
    node((0, 0), sans[*lp-client* \ c-phys 192.168.100.2 \ wg0 10.66.0.2], name: <c>, fill: soft),
    node((1, 0), sans[*lp-isp* \ ISP DNS 192.168.100.1 \ NAT → 198.51.100.1], name: <i>),
    node((2, 0), sans[*lp-vpn* \ endpoint 203.0.113.10 \ VPN DNS 10.66.0.1 \ NAT → 192.0.2.2], name: <v>),
    node((3, 0), sans[*lp-inet* \ canary + beacon \ 198.51.100.10 \ 2001:db8:198::10], name: <n>),
    edge(<c>, <i>, "-"), edge(<i>, <v>, "-"), edge(<v>, <n>, "-"),
    edge(<i>, <n>, "-", bend: -50deg, stroke: (paint: fail-c, dash: "dashed"), text(fill: fail-c, sans[direct ISP → inet path (*leaks take this route*)]), label-side: right),
    edge(<c>, <v>, "=", bend: 50deg, stroke: pass-c + 1.2pt, text(fill: pass-c, sans[WireGuard tunnel 10.66.0.0/24 · fd66::/64]), label-side: left),
    node((0, 0.6), text(size: 8pt, fill: fail-c)[▲ capture point], stroke: none),
    node((1.5, 1.15), box(width: 1pt, height: 1pt), stroke: none),
  ),
  caption: [Lab topology (private and documentation ranges only).],
) <fig-topo>

== Test methods

#figure(
  table(
    columns: (auto, 1fr, auto),
    table.header([ID], [How it is measured · PASS when], [Severity]),
    [LP-ROUTE-01], [Simulate the kernel: walk `ip rule` by priority (`from`, `to`, `fwmark`, `suppress_prefixlength`), then longest-prefix match with lowest-metric tie-break, for v4 and v6. PASS when every test destination egresses via the tunnel and no more-specific route bypasses it. `0.0.0.0/1 + 128.0.0.0/1` is flagged with the CVE-2024-3661 message.], [HIGH],
    [LP-V6-01], [Static `::/0` and `disable_ipv6` check plus a UDP probe to `2001:db8:198::10`. FAIL on any leaked IPv6 packet.], [HIGH],
    [LP-DNS-01], [Resolve a fresh `lp-<uuid8>.leakprobe.test` via `getaddrinfo` and directly to each nameserver; read both fake resolvers' logs. FAIL if the ISP resolver saw the label.], [HIGH],
    [LP-KILL-01], [100 pps UDP stream, inject a fault, count probe-flow LEAK packets after $t_"fault"$ over N trials (@fig-kill). PASS only if no trial leaks.], [CRITICAL],
    [LP-START-01], [Delete the tunnel, start the probe, bring the tunnel up, poll `wg show latest-handshakes` every 10 ms for $t_"ready"$. FAIL on any leak before $t_"ready"$.], [MEDIUM],
    [LP-SPLIT-01], [`ss -tunap` sockets pinned to the physical side; `uidrange`/foreign-`fwmark` rules. WARN only, because `SO_BINDTODEVICE` is invisible from outside the process.], [LOW],
    [LP-EGRESS-01], [Classify every packet captured during normal operation. PASS when only ENDPOINT / HOUSEKEEPING packets appear.], [HIGH],
    [LP-IDENT-01], [Ask the beacon which source IP it saw. PASS when it is the VPN exit `192.0.2.2`.], [HIGH],
  ),
  caption: [Test catalogue.],
)

*Kill-switch leak window.* Each trial starts tcpdump and a 100 pps probe, waits `pre` = 2 s,
injects a fault (`link-down`, `delete-iface`, or `endpoint-block`, which blackholes the
server while the interface stays up), records $t_"fault"$ = `time.time()`, observes `post` = 3 s,
and always calls `restore()` in `finally`. With $L$ = the probe-flow packets classified LEAK
with $"ts" >= t_"fault"$:
$ "leak_packets" = |L|, quad "leak_window_ms" = (max_(p in L) p."ts" - t_"fault") times 1000 $
Pcap kernel timestamps and `time.time()` come from the same host, so the clocks agree. The
tunnel snapshot used for `restore()`, which includes the private key, is kept in memory only.

#figure(
  table(
    columns: (auto, auto, 1fr),
    table.header([Method], [Action], [What it simulates]),
    [`link-down`], [`ip link set wg0 down`], [Client crash or manual disconnect],
    [`delete-iface`], [`ip link del wg0`], [Tunnel torn down and its routes removed],
    [`endpoint-block`], [nftables drop for the endpoint in `lp-isp`], [Server unreachable while the interface stays up],
  ),
  caption: [Fault injectors (`faults/injector.py`).],
)

#figure(
  {
    set text(font: ("Noto Sans", "DejaVu Sans"), size: 8pt)
    cetz.canvas(length: 1cm, {
      import cetz.draw: *
      for i in range(0, 39) {
        let x = i * 0.25 + 0.1
        let c = if x < 4 { pass-c } else if x < 10 { fail-c } else { muted }
        line((x, -0.15), (x, 0.15), stroke: 0.6pt + c)
      }
      line((-0.2, 0), (12.2, 0), mark: (end: ">"), stroke: 0.8pt)
      content((12.3, 0), [time], anchor: "west")
      let ev(x, lbl, c) = {
        circle((x, 0), radius: 0.09, fill: c, stroke: none)
        content((x, 0.6), text(fill: c, lbl))
      }
      ev(0, [capture + probe start], black)
      ev(4, [fault, $t_"fault"$], fail-c)
      ev(10, [stop, `restore()`], black)
      line((0, -0.55), (4, -0.55), mark: (start: ">", end: ">"), stroke: 0.6pt)
      content((2, -0.85), [`pre` = 2 s])
      line((4, -0.55), (10, -0.55), mark: (start: ">", end: ">"), stroke: 0.6pt)
      content((7, -0.85), [`post` = 3 s])
      line((4, -1.25), (9.85, -1.25), mark: (start: ">", end: ">"), stroke: 0.8pt + fail-c)
      content((6.9, -1.55), text(fill: fail-c)[leak window = last leak − $t_"fault"$ (no kill switch)])
    })
  },
  kind: image,
  caption: [One kill-switch trial. Ticks are probe packets: green in the tunnel, red leaked on `c-phys`.],
) <fig-kill>

== Run orchestration and validation

#figure(
  diagram(node-shape: rect,
    spacing: (7mm, 9mm), node-stroke: 0.7pt, node-corner-radius: 3pt, edge-stroke: 0.7pt,
    node((2, -1.7), sans[select tests, build `RunContext`, start egress capture], name: <sel>),
    node((0, 0), sans[ROUTE], name: <t1>), node((1, 0), sans[V6], name: <t2>),
    node((2, 0), sans[DNS], name: <t3>), node((3, 0), sans[SPLIT], name: <t4>),
    node((4, 0), sans[IDENT], name: <t5>),
    node((2, -0.7), sans[baseline v4/v6 UDP probe], name: <bp>),
    node(enclose: ((0, 0), (4, 0), (2, -0.7)), stroke: (dash: "dashed", paint: accent), inset: 8pt, snap: false),
    node((3.7, -0.7), text(size: 8pt, fill: accent)[LP-EGRESS-01 \ capture window], stroke: none),
    node((0.5, 1.7), sans[LP-START-01 \ tunnel deleted + restored], name: <st>, fill: rgb("#fbeceb")),
    node((2, 1.7), sans[LP-KILL-01 \ N fault trials], name: <kl>, fill: rgb("#fbeceb")),
    node((3.5, 1.7), sans[remediation → \ report → exit code], name: <rp>, fill: soft),
    edge(<sel>, (0, -1.7), <t1>, "->"),
    edge(<t1>, <t2>, "->"), edge(<t2>, <t3>, "->"), edge(<t3>, <t4>, "->"), edge(<t4>, <t5>, "->"),
    edge(<t5>, (4, 0.9), (0.5, 0.9), <st>, "->"),
    node((2.25, 1.12), text(size: 8pt, style: "italic")[egress capture stopped and evaluated], stroke: none),
    edge(<st>, <kl>, "->"), edge(<kl>, <rp>, "->"),
  ),
  caption: [Order of tests in `leakprobe run`.],
) <fig-orch>

`leakprobe run` runs the non-disruptive tests (ROUTE, V6, DNS, SPLIT, IDENT) inside one
LP-EGRESS-01 capture window with a short v4/v6 baseline probe. START and KILL, which tear the
tunnel down on purpose, run afterwards so they cannot contaminate the egress audit. A test
that crashes becomes an ERROR finding and the run continues (@fig-orch). `leakprobe matrix` builds each of
seven lab profiles in a fresh lab, runs the suite and compares the results with the profile's
`expected:` ground truth. FAIL is the positive class:
$ "precision" = "TP" / ("TP" + "FP"), quad "recall" = "TP" / ("TP" + "FN") $

// ======================================================================= 4
= Commands and Usage

```bash
uv sync && uv run leakprobe doctor                 # root, ip, wg, nft, tcpdump, wireguard module
sudo .venv/bin/leakprobe lab up --profile wg-default-leaky
sudo .venv/bin/leakprobe run --mode lab --profile wg-default-leaky [--tests LP-DNS-01,LP-KILL-01] [--trials 20]
sudo .venv/bin/leakprobe drop-test --method link-down|delete-iface|endpoint-block --trials 25
sudo .venv/bin/leakprobe matrix --trials 5 --save-dir reports/
sudo .venv/bin/leakprobe lab down                  # removes every lp-* object
# no root needed
leakprobe analyze capture.pcap --endpoint 203.0.113.10:51820 [--allow-lan]
leakprobe audit-routes --from-file routes.json
leakprobe report results.json --format term|json|md
leakprobe matrix --from-dir reports/
# this host's real tunnel: prints a probe-traffic notice and needs --yes
sudo .venv/bin/leakprobe run --mode real --tunnel wg0 --physical eth0 --endpoint IP:PORT --yes
```

Exit codes: `0` all pass (WARN allowed), `1` any FAIL (or WARN with `--strict`), `2` tool or
setup error, so LeakProbe can gate scripts and CI. Without sudo, `scripts/sandbox.sh uv run
leakprobe …` runs everything in an unprivileged user + mount + network namespace that
disappears on exit.

#figure(
  table(
    columns: (7.2cm, 1fr, auto),
    table.header([Command], [Purpose], [Root]),
    [`doctor`], [Check root, tools, kernel module, namespaces], [no],
    [`lab up --profile NAME`], [Build the lab (idempotent)], [yes],
    [`lab status` / `lab down`], [Inspect / remove every `lp-*` object], [yes],
    [`run --mode lab --profile NAME`], [Run the catalogue; `--tests`, `--trials`, `--method`], [yes],
    [`run --mode real --tunnel wg0` \ `--physical eth0 --endpoint IP:PORT --yes`], [Run against this host's own tunnel], [yes],
    [`drop-test --method M --trials N`], [LP-KILL-01 alone on the running lab], [yes],
    [`matrix [--profiles] [--trials] [--save-dir]`], [Validation matrix over all profiles], [yes],
    [`matrix --from-dir DIR`], [Re-score saved reports], [no],
    [`audit-routes [--from-file F] [--save F]`], [LP-ROUTE-01 on live or saved routing state], [only live],
    [`analyze capture.pcap --endpoint IP:PORT`], [LP-EGRESS-01 on a saved pcap], [no],
    [`report results.json --format term|json|md`], [Re-render a saved JSON report], [no],
  ),
  caption: [LeakProbe command-line interface.],
)

#figure(
  table(
    columns: (auto, 1fr),
    table.header([Profile], [Seeded fault]),
    [`wg-hardened`], [None: `AllowedIPs 0.0.0.0/0, ::/0`, tunnel DNS, nftables kill switch],
    [`wg-default-leaky`], [IPv4-only tunnel, ISP DNS, no kill switch],
    [`wg-ipv6-leak`], [IPv4-only tunnel with an IPv4-only kill switch],
    [`wg-dns-leak`], [Resolver left as the ISP's],
    [`wg-no-killswitch`], [Everything correct except the firewall],
    [`wg-tunnelvision`], [`0.0.0.0/1` + `128.0.0.0/1` via the physical gateway],
    [`control-broken`], [Tunnel never comes up],
  ),
  caption: [Lab profiles shipped with ground truth (`expected:` map).],
)

// ======================================================================= 5
= Testing and Results

*Testing.* 267 unit tests run without root: route predictor on real `ip -j` fixtures, the
classifier on scapy-generated pcaps, leak-window maths, every `evaluate_*()`, orchestration,
remediation, reports and matrix scoring. 35 root integration tests cover the lab, profiles,
faults and end-to-end runs. `ruff` and `mypy --strict` are clean. The project was built in 11
milestones (M0–M10, 2–10 October 2026).

#figure(
  {
    set text(size: 9pt)
    let E = tag("ERROR")
    table(
      columns: (auto, auto, auto, auto, auto, auto, auto, auto, auto),
      align: (left, center, center, center, center, center, center, center, center),
      table.header([Profile], [ROUTE], [V6], [DNS], [KILL], [START], [SPLIT], [EGRESS], [IDENT]),
      [`wg-hardened`], P, P, P, P, P, P, P, P,
      [`wg-default-leaky`], P, F, F, F, F, P, F, P,
      [`wg-ipv6-leak`], P, [#E ✗], P, P, P, P, F, P,
      [`wg-dns-leak`], P, P, F, F, F, P, F, P,
      [`wg-no-killswitch`], P, P, P, F, F, P, P, P,
      [`wg-tunnelvision`], F, P, P, F, F, P, F, F,
      [`control-broken`], F, F, F, F, F, P, F, F,
    )
  },
  caption: [Validation matrix, measured 13 Oct 2026 (`matrix --trials 3`). All cells match ground truth except ✗. *Agreement 48/49 (98 %), precision 100 %, recall 96 %* (TP 24, FP 0, FN 1, TN 24).],
)

*The one disagreement.* On `wg-ipv6-leak`, LP-V6-01 returned ERROR instead of FAIL. Three
re-runs gave the correct FAIL. One re-run hit `tcpdump not ready after 5.0s` in another test,
so a slow capture start-up under load is the likely cause. The tool reported ERROR (exit
code 2), never a false PASS, so precision stays at 100 %. The matrix found a reliability issue
that the unit tests had missed.

#figure(
  table(
    columns: (auto, auto, 1fr),
    table.header([Test], [Status], [Measured on `wg-default-leaky` (3 trials)]),
    [LP-ROUTE-01], P, [All 4 IPv4 test destinations egress via `wg0` (table 51820)],
    [LP-V6-01], F, [5 IPv6 packets left from `fd00:100::2` outside the tunnel],
    [LP-DNS-01], F, [The ISP resolver logged the probe label],
    [LP-KILL-01], F, [Leaked in 3/3 trials after link-down: 295 / 296 / 295 packets, first leak 1–7 ms, p95 window 2956 ms],
    [LP-START-01], F, [99 probe packets leaked before the tunnel was up],
    [LP-SPLIT-01], P, [No bypass sockets or rules],
    [LP-EGRESS-01], F, [12 of 31 packets leaked (ipv6 8, dns 4)],
    [LP-IDENT-01], P, [Beacon saw the VPN exit 192.0.2.2],
  ),
  caption: [Results for a typical "working" configuration (overall FAIL, exit 1).],
)

*Discussion.* Routing and IPv4 identity look perfect, yet the capture shows IPv6 and DNS
leaving in normal operation, so a static audit or an IPv4 browser test would call this setup
safe. After `link-down`, traffic falls back to the physical route within milliseconds and
leaks for the *entire* 3 s window. A real client crash would leak until someone noticed.
`wg-hardened` applies exactly the fixes the report suggests (`AllowedIPs = 0.0.0.0/0, ::/0`,
`DNS = 10.66.0.1`, and the nftables kill switch below, loaded before the tunnel). All eight
tests PASS, with *0 leaked packets across 20 kill-switch trials*.

```
table inet leakprobe_killswitch { chain output { type filter hook output priority 0; policy drop;
  oifname "lo" accept;  oifname "wg0" accept;  ip daddr 203.0.113.10 udp dport 51820 accept
  udp sport 68 udp dport 67 accept
  icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept } }
```

// ======================================================================= 6
== Remediation

Every FAIL or WARN finding carries a fix filled in with the real interface names, endpoint
and resolver. The kill-switch snippet comes from the same function that builds the lab's
hardened firewall, so the advice is exactly what `wg-hardened` applies.

#figure(
  table(
    columns: (auto, 1fr),
    table.header([Finding], [Remediation snippet]),
    [LP-V6-01], [`AllowedIPs = 0.0.0.0/0, ::/0`, or `sysctl net.ipv6.conf.<phys>.disable_ipv6=1`],
    [LP-DNS-01], [`DNS = 10.66.0.1` in the WireGuard config, or `resolvectl dns wg0 10.66.0.1; resolvectl domain wg0 ~.`],
    [LP-KILL-01, LP-START-01], [nftables `inet` output chain with `policy drop` allowing only `lo`, `wg0`, the endpoint and DHCP/NDP, loaded before the tunnel starts],
    [LP-ROUTE-01], [`ip route del 0.0.0.0/1` and `ip route del 128.0.0.0/1`; ignore DHCP option 121 on the VPN-bound interface],
    [LP-SPLIT-01], [Review the listed sockets and `ip rule` entries; remove `uidrange` / foreign-`fwmark` bypasses],
  ),
  caption: [Remediation attached to findings (`report/remediation.py`).],
)

== Sample report output

Each finding in the Markdown or terminal report carries its summary, evidence lines, metrics
and fix. An excerpt from `docs/sample-report.md` (`wg-default-leaky`, 3 trials):

```
LP-KILL-01: Kill switch (FAIL, critical)
Leaked in 3/3 trials after link-down: median 295 packets, p95 window 2956 ms
- method link-down, 3 trials, observed 3000 ms after each fault (leak windows cannot exceed this)
- trial 1: 295 probe packets leaked, first after 1.2 ms, last after 2941.6 ms
- trial 2: 296 probe packets leaked, first after 7.3 ms, last after 2957.3 ms
- trial 3: 295 probe packets leaked, first after 3.8 ms, last after 2943.7 ms

LP-V6-01: IPv6 leak (FAIL, high)
5 IPv6 packets left outside the tunnel
- route: 2001:db8:198::10 -> c-phys (table main, ::/0, rule 32766)
- IPv6 disabled on physical interface: no
- leak: udp fd00:100::2 -> [2001:db8:198::10]:9000
Remediation:
  # WireGuard [Peer]: send every IPv4 and IPv6 destination through the tunnel
  AllowedIPs = 0.0.0.0/0, ::/0
```

= Innovation and Critical Thinking

- *Allowlist, not blocklist.* Defining what may appear on the physical interface catches unknown leak types without new rules.
- *Model plus observation.* The route predictor shows what the kernel *should* do; the capture shows what it *did*. On `wg-default-leaky` the model passes and the capture fails. On `wg-tunnelvision` the model explains the leak and names the route to delete.
- *Measuring failure, not just steady state.* Faults are injected under load, and leak windows are reported in ms and packets with percentiles. `endpoint-block` is a negative control: a dead server should blackhole traffic, not leak it.
- *Partial fixes are exposed.* `wg-ipv6-leak`'s IPv4-only kill switch passes LP-KILL-01 but still fails LP-V6-01.
- *Testing the tester.* Seeded-fault profiles turn the tool's accuracy into precision and recall, which can be re-scored offline. This is how the capture-timeout issue was found.
- *Measurement errors found and fixed.* The kernel sends MLD on every IPv6 link, so it is housekeeping, not a leak. Early IPv6 probes stuck in the neighbour queue never reached the wire, a silent false negative, so `lab up` now primes ARP/NDP. Disruptive tests run outside the egress capture window.
- *Safe and honest by construction.* Documentation addresses only; private keys in memory only; `--yes` required for real mode; a single shell-free subprocess wrapper; split-tunnel findings are WARN only because of `SO_BINDTODEVICE`; a crashed test is ERROR, never PASS.
- *Rootless reproducibility.* `scripts/sandbox.sh` runs the whole lab and test suite without sudo or changes to the host.

// ======================================================================= 7
= Security, Ethics and Limitations

- *Authorised use only.* LeakProbe is for machines and networks the user owns or administers.
- *No real-world probing in the lab.* The lab uses only RFC 1918, RFC 5737 and RFC 3849
  addresses and has no path to the real Internet. Real mode prints a probe-traffic notice and
  requires `--yes`, because it sends traffic and briefly takes the tunnel down.
- *Secrets.* WireGuard keys are generated per run and never committed. Fault snapshots keep the
  private key in memory only.
- *The tool's own attack surface.* It runs as root, so every external command goes through one
  wrapper with argument lists (no shell). Profiles are validated pydantic models, and the
  package is type-checked with `mypy --strict`.
- *Limitations.* A detected leak is evidence; no detected leak is not proof of safety. WebRTC
  and in-app DNS-over-HTTPS are out of scope, `SO_BINDTODEVICE` and `SO_MARK` are invisible
  to LP-SPLIT-01, only WireGuard on Linux is covered, real mode has no beacon server, and
  `tcpdump` start-up can time out under load.

= Conclusion and Future Work

LeakProbe turns "the VPN says connected" into measured, reproducible evidence. One general
definition of a leak, any packet outside the physical-interface allowlist, drives eight tests
that each give a verdict, evidence, metrics and a concrete fix. The namespace lab reproduces
real failure modes, including TunnelVision, on one machine. On it, a typical WireGuard setup
leaked IPv6 and DNS in normal operation, about 3 s of traffic after every crash and about 100
packets at every start. The hardened setup reduced all of these to zero. The tool was
validated rather than trusted: 98 % agreement, 100 % precision and 96 % recall over seven
seeded-fault profiles.

*Future work:* a robust capture start-up (retry and adaptive
timeout) with re-validation to 100 %, a real-mode beacon (HTTP "your IP" plus authoritative
DNS logging), OpenVPN profiles, per-trial leak-window histograms and application-level checks.

#v(0.5em)
#set text(size: 9pt)
#set par(justify: false)
#bibliography("refs.yml", title: [References], style: "ieee")
