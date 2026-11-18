# Zigmap

A network scanner written entirely in Zig 0.17.1. No C, no libpcap, no
`@cImport`. Linux builds are static and do not link libc.

**Only scan hosts you are authorized to scan.** Targets must be given
explicitly, expansion is capped (`--max-targets`, default 4096), probes are
capped at 1000 per second unless you pass `--max-rate` (0 removes the cap),
and there is no Internet-wide mode, no spoofing and no privilege escalation.

## Features

| Area | What it does |
|---|---|
| Packet codecs | Ethernet/VLAN, ARP, IPv4, IPv6 with extension-header walk, TCP and options, UDP, ICMPv4/v6, NDP. Checksums, a frame parser for Ethernet, raw IP, Linux SLL and BSD null links. Golden vectors and fuzz tests. |
| Connect scan `-sT` | Asynchronous, IPv4 and IPv6, no privileges. epoll on Linux, poll on macOS. |
| SYN scan `-sS` | Linux, IPv4 and IPv6. Route and neighbour data from NETLINK_ROUTE, its own ARP and NDP, AF_PACKET send and capture. |
| UDP scan `-sU` | Linux. ICMP port-unreachable is `closed`, a UDP reply is `open`, silence is `open|filtered`. When a host starts rate-limiting ICMP, Zigmap slows down for that host. |
| Host discovery | ARP or NDP on the local link, otherwise ICMP echo, SYN to 443 and ACK to 80. Without privileges, a connect to 80 and 443. `-sn` for discovery only, `-Pn` to skip it. |
| Engine | RFC 6298 RTO, per-host and global windows that shrink only on evidence of loss, token-bucket rate cap, round-robin fairness, host timeout, SIGINT. |
| Capture | `recvmsg` (default) or a TPACKET_V3 ring, behind a 16-instruction classic BPF filter. |
| Service detection `-sV` | Original probe file (`src/fingerprint/probes.zmp`), banner matching, TLS 1.2 handshake with certificate details, DNS `version.bind`. |
| OS detection `-O` | Uses the SYN/ACK and RST the scan already received. Lab-captured reference only; see `docs/os-fingerprints.md`. |
| Output | Terminal, `--explain`, JSON Lines and JSON (schema `zigmap.v1`), XML. `--stats` adds engine counters, CPU, peak RSS, ports per second and p50/p95/p99 port completion time. |
| Releases | `zig build release` makes stripped static binaries for x86_64 and aarch64 Linux and macOS. Two builds from empty caches are byte-identical. |

Not implemented, and rejected with an error: `-sA`, `-sN`, `-sF`, `-sX`.

## Build and test

```sh
zig build                       # zig-out/bin/zigmap
zig build test                  # 92 unit, golden-vector, fuzz-corpus and simulation tests
zig build bench -Doptimize=ReleaseFast
zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSafe
zig build release               # stripped static binaries in zig-out/release/
sh tests/release/reproducible.sh   # builds the release twice, compares SHA-256
ARCH=aarch64 sh tests/lab/run.sh            # loopback lab in one container
ARCH=aarch64 sh tests/lab/syn_lab.sh        # two containers on Docker bridges
ARCH=aarch64 sh tests/bench/capture_bench.sh
```

GitHub Actions runs `zig build test` on Linux and macOS for every pull
request and every push to `main` (`.github/workflows/ci.yml`), and
cross-compiles the lab helper. The labs and benchmarks need Docker and
root inside containers, so they run locally, not in CI.

The labs need Docker and run only inside throwaway containers and networks.
They never touch the host's routing, ARP, DNS or firewall. Their
listeners, service fakes and UDP noise come from `labtool`
(`tests/lab/labtool.zig`, built by `zig build lab-tools`, never installed
by a plain `zig build`); the TLS fake is `openssl s_server`, and `jq` and
`xmllint` check the JSON and XML output.

## Usage

```sh
zigmap -p 22,80,443,8000-8100 192.0.2.0/28 --exclude 192.0.2.1
zigmap -p - ::1 --explain
zigmap --dry-run -p 1-1024 10.0.0.0/24        # print the plan, send nothing
sudo zigmap -sS -sV -O -p 1-1024 192.0.2.10 -oJ scan.jsonl
sudo zigmap -sU -p 53,123,161 192.0.2.10
sudo zigmap -sn 192.0.2.0/28
```

Raw scans need CAP_NET_RAW (`sudo`, or `setcap cap_net_raw+ep zigmap`).
Without it Zigmap exits with status 77 and says why. It never falls back
to a connect scan.

`--explain` prints the evidence for each port:

```
  18080/tcp open             connected               1  1028 us
      t=      1359 us  attempt 1  sent
      t=      2388 us  attempt 1  reply (connected)
      => open: the TCP handshake completed, so the port accepted a connection
```

## How replies are matched

Each raw probe slot owns one source port (default 61000 and up, outside
Linux's ephemeral range). Probe identity is a keyed SipHash of the target
and attempt:

* SYN: the sequence number. A reply must acknowledge exactly that number.
* UDP: the IP ID, checked in the datagram quoted by an ICMP error.
* ICMP echo: the identifier and sequence.

Replies to an older attempt are counted as stale and never change a result.
A partial checksum is accepted only when the kernel marked the frame
`TP_STATUS_CSUMNOTREADY`.

Targets routed over loopback are sent at layer 3, because the kernel drops
frames injected at layer 2 for 127.0.0.0/8 as martians. Zigmap does not
change `route_localnet` to work around it.

## Verification

* **Golden vectors** from frames the kernel generated, checked against
  tshark's decode and checksums (`docs/fixtures.md`).
* **Fuzzing** of the frame parser, netlink parser, probe-file parser and
  TLS parser (`zig build test --fuzz`).
* **Simulated networks** on a virtual clock: exact classification, 30% reply
  loss without open/closed inversion, fairness, rate cap, stale replies,
  host timeout, self-connect retry, ICMP rate limiting, identical reruns.
* **Loopback lab** (`tests/lab/run.sh`): iptables DROP and REJECT variants,
  `::1`, netem delay and loss, rate cap, target guard, static binary check,
  and agreement with `nmap -sT` and `nmap -sS` on every port. nmap is used
  only as a reference.
* **Bridge lab** (`tests/lab/syn_lab.sh`): SYN over veth with ARP, agreement
  with `nmap -sS` and `nmap -sU`, the three capture paths giving identical
  results, `-sV` against lab service fakes, `-O`, discovery of on-link,
  silent and routed hosts, IPv6 over Ethernet with NDP, delay and loss,
  JSON and XML that parse, and exit 77 without CAP_NET_RAW.

Both labs pass on Linux aarch64 (native) and x86_64 (emulated), kernel
7.2.12, in OrbStack. The bridge lab's results agree with `nmap -sS` on 21
ports and `nmap -sU` on 22 ports. The capture benchmark found that the
unfiltered `recvmsg` path lost replies under load (see Measurements). The
bridge lab found that UDP pacing under a global rate cap spun forever,
because the token bucket dropped fractions of a token at 1 probe per
second; a simulation test now covers it.

## Measurements

These are the only performance figures. They come from loopback inside a
Linux container on Apple silicon, so they measure Zigmap's own overhead,
not a real network.

* Connect scan, 65,535 closed ports, `--max-parallelism 1024 --max-rate 0`, ReleaseSafe,
  10 runs: 131 to 147 ms wall, about 20 ms user and 110 ms system CPU, about
  5 MB peak RSS.
* Timer heap against a linear sweep (`zig build bench`): the sweep is faster
  at 64 timers, they tie at 256, the heap is 4.9× faster at 1,024 and 39×
  at 16,384.

* Capture paths (`tests/bench/capture_bench.sh`): SYN scan of 65,535 closed
  ports on 127.0.0.1, `--max-rate 0`, while two processes flood loopback
  with UDP between other addresses. ReleaseFast, medians of 5 runs, all
  runs correct, no kernel drops. Completion time is when a port was
  classified, from scan start.

  | Capture | Wall ms | CPU ms | Ports/s | p50 ms | p95 ms | p99 ms | Peak RSS KiB | Frames read |
  |---|---|---|---|---|---|---|---|---|
  | `recvmsg` + BPF (default) | 72 | 72 | 904,473 | 36.4 | 68.9 | 71.8 | 5,356 | 131,193 |
  | `recvmsg`, `--no-bpf` | 790 | 789 | 82,916 | 412.3 | 749.8 | 782.0 | 5,356 | 2,212,465 |
  | ring + BPF | 1,400 | 53 | 46,810 | 742.1 | 1,340.5 | 1,385.9 | 13,548 | 131,070 |
  | ring, `--no-bpf` | 123 | 121 | 530,360 | 62.7 | 117.2 | 122.1 | 13,400 | 397,028 |

  The BPF filter keeps the noise out of user space. The ring uses 64 KiB
  blocks; with the filter on, too few frames arrive to fill a block, so
  each wave of replies waits for the kernel's block-retire timer (about
  20 ms here). That is why `recvmsg` is the default. Before Zigmap set
  `PACKET_IGNORE_OUTGOING`, the unfiltered `recvmsg` path took 38 s,
  dropped 2.5 million frames and gave wrong results; Zigmap now also warns
  whenever the kernel reports capture loss.

That connect benchmark also found TCP self-connect on loopback: when the
ephemeral source port equals the target port, the connection succeeds
against itself. Zigmap detects this with `getsockname`, records it as
inconclusive and retries.

## Layout

`docs/architecture.md` covers ownership, the probe state machine,
scheduling and the raw backend. `docs/os-fingerprints.md` covers `-O`.

## Licensing note

Nmap's documentation was read for concepts only. No Nmap code,
`nmap-os-db`, `nmap-service-probes` or NSE scripts are included.
