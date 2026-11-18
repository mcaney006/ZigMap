# Zigmap architecture and ownership

## Layers

```
cli/args.zig ──> main.zig ──> core/engine.zig (Engine(Transport)) ──> output/report.zig
                    │              │
                    │    ┌─────────┴──────────┬────────────────────────┐
                    │  scan/connect.zig   scan/raw_transport.zig   testing/synthetic_network.zig
                    │  (connect sockets)  (AF_PACKET, Linux)       (virtual clock)
                    │        │                  │
                    │  platform/sys.zig    platform/linux/*, platform/bpf.zig, scan/raw.zig
                    │
                    └──> scan/service_scan.zig (-sV), fingerprint/{service,os}.zig

packet/* : codecs and the frame parser, shared by the raw backend and the tests
```

## Ownership rules

| Resource | Owner | Lifetime |
|---|---|---|
| Probe slots (`probe.Pool`) | Engine | preallocated at init, `2 × group_max + 16` |
| Timers (`TimerHeap`) | Engine | preallocated, keyed by slot id |
| Per-host state (window, RTT, retry FIFO) | Engine, single owner, single thread | scan |
| Port results + bounded evidence ring | Engine (`results[host × ports]`) | scan |
| Sockets | Transport; one fd per in-flight attempt | closed on reply, timeout, or cancel (`SO_LINGER{1,0}`) |
| Target/port lists | caller (arena in `main`) | scan |
| SIGINT flag | process global (signal handlers take no context) | process |

There is no other global mutable state. The engine is single-threaded and
event-driven; no thread per host or port.

## Probe state machine

```
ready -> sent -> awaiting -> classified -> completed
                    |            └-> retry_queued   (inconclusive, e.g. self-connect)
                    └-> timed_out -> retry_queued -> ready (next attempt, generation+1)
                    └-> timed_out -> completed      (attempts exhausted: silent_state)
any live state -> canceled                          (host timeout, SIGINT)
```

`probe.canTransition` is the single source of truth; illegal transitions
panic. Every (re)send bumps the slot's generation. Transports echo
`(slot, generation)` with every reply, so late replies to a previous attempt
or a previous occupant of the slot are counted as `stale` and recorded as
evidence but can never change a classification.

## Scheduling

* **Windows.** Per-host and group windows (slow start / avoidance,
  fixed-point). Only *evidenced loss* shrinks a window: a reply to attempt
  N > 1 proves earlier attempts were lost. Timeouts alone never shrink a
  window, because firewalls drop silently by design (tested:
  `silence alone never shrinks congestion windows`).
* **RTO.** RFC 6298 per host, clamped by `--min/--max-rtt-timeout`. Per-probe
  deadline is `rto << (attempt-1)`; silence does not inflate the host
  estimator, so a filtered port cannot slow down the host's open ports.
* **Deadlines.** Indexed binary heap, O(log n) arm/cancel/expire, O(1) next
  deadline for the poll timeout. Benchmarked against an O(N) sweep in
  `bench/timer_bench.zig`: the sweep is faster at 64 entries, they tie at
  256, and the heap is 4.9x faster at 1,024 and 39x at 16,384.
* **Fairness.** Deficit round robin over hosts with a quantum (default 8).
  Tested: a fully filtered 200 ms host does not slow a healthy host by more
  than 1.5x.
* **Pacing.** Token bucket (`--max-rate`), ~20 ms burst. Tested in
  simulation (no 1 s window exceeds rate + burst) and in the Linux lab.
* **Local pressure.** EMFILE/ENOBUFS/EADDRNOTAVAIL are not target evidence:
  the attempt is undone and requeued and the group window shrinks. With
  nothing in flight the port is reported `unknown/local_resource_exhausted`
  instead of spinning.

## Classification (connect scan)

| Observation | State / reason |
|---|---|
| handshake completed | open / connected |
| ECONNREFUSED | closed / conn_refused |
| EHOSTUNREACH, ENETUNREACH (ICMP seen by kernel) | filtered / host_unreach, net_unreach |
| EACCES/EPERM | filtered / local_policy_denied |
| every attempt silent | filtered / no_response |
| local endpoint == destination | inconclusive / self_connect → retried |
| host timeout or SIGINT first | unknown / host_timeout, canceled |

## Raw backend

```
platform/linux/netlink.zig        route get, link get, neighbour lookup (NETLINK_ROUTE)
platform/netlink_msg.zig          pure netlink attribute parsing (fuzzed)
platform/linux/packet_socket.zig  AF_PACKET with PACKET_AUXDATA and PACKET_STATISTICS,
                                  TPACKET_V3 ring, raw IPv4/IPv6 sockets for loopback
platform/bpf.zig                  16-instruction filter and an interpreter for tests
scan/raw.zig                      pure: probe builders and the Correlator (runs on any OS)
scan/raw_transport.zig            Engine transport: plan, ARP/NDP, send, drain, match
```

`raw_transport.plan` resolves the egress interface, source addresses, MTU
and next hop for each target. `resolveNeighbors` sends Zigmap's own ARP
requests and IPv6 neighbour solicitations for next hops the kernel table
does not know. A target whose next hop never answers is reported `down`
with reason `no_neighbor_reply`.

Correlation rules, all of which must hold:

* the frame is addressed to our source address and to a port in our slot
  range;
* its source matches the slot's current target;
* for TCP: SYN+ACK or RST, and `ack - 1` equals the SipHash ISN for the
  slot's current generation or one of the three before it;
* for ICMP errors: the quoted header is ours and carries the same token
  (TCP sequence, or IP ID for UDP);
* for echo replies: identifier and sequence carry the token.

An older generation is delivered as stale and never changes a result.
Checksums must be `good`, or `partial` only with TP_STATUS_CSUMNOTREADY.
Each poll drains at most 4096 frames so a flood cannot starve the
scheduler. Kernel drops and ring blocks marked lossy are reported in the
capture statistics.

The BPF filter accepts ARP and IPv4 or IPv6 packets addressed to our scan
source address. Everything else, including 802.1Q-tagged frames, is
dropped in the kernel (VLAN offload normally strips tags first). `--no-bpf` disables it, and the correlator still rejects foreign
traffic; the bridge lab checks that the results are identical.

## UDP pacing

Linux limits ICMP errors per destination (about one per second after a
small burst by default). When a host's silence stops being evidence, the
engine's `pace_trigger` sees an ICMP port-unreachable, switches that host
to `paced_pps` probes per second, and counts it in `paced_hosts`. Other
hosts keep their own pace.

## Service detection

`scan/service_scan.zig` runs probes from `fingerprint/probes.zmp` over
non-blocking connects multiplexed with `poll`. For each open port it tries
the probes listed for that port by rarity, then NULL, then other probes up
to `--version-intensity` (at most four). The first matching rule wins.
TLS ports get a TLS 1.2 ClientHello; the server flight is parsed for
version, cipher and certificate subject, issuer, SAN and expiry. Port 53
gets a `version.bind` query over TCP. Unknown stays unknown.

## Platform notes (Zig 0.17.1)

* `std.posix` no longer has `socket`/`connect`/`getsockopt`; Linux uses
  `std.os.linux` raw syscalls (no libc; verified no `PT_INTERP` and no
  dynamic section), macOS uses `std.c` (libSystem is the only stable ABI).
* `main` takes `std.process.Init`; time comes from `std.Io.Clock.awake`.
* Removed/changed in 0.17 and handled here: array `**` repetition (use
  `@splat`), `std.meta.fields` (use `@typeInfo(T).@"struct".field_names`).
