# OS fingerprints

`-O` reuses the replies a SYN scan already gets: the SYN/ACK from one open
port and the RST from one closed port. It sends no extra probes.

## Features

From the SYN/ACK: TCP option kinds in order, window, window scale, MSS,
SACK permitted, timestamps present, DF bit, observed TTL and the inferred
initial TTL (the smallest of 32, 64, 128, 255 at or above it). From the
RST: window, DF bit, initial TTL.

## Scoring

Each reference is scored as matched weight over total weight:

| Check | Weight |
|---|---|
| option kinds in the same order | 3 |
| SYN/ACK window | 2 |
| window scale | 1 |
| initial TTL | 1 |
| DF bit | 1 |
| RST window and DF (when a closed port was seen) | 1 |

| Confidence | Rule |
|---|---|
| strong | score ≥ 0.95, option order matches, no middlebox flags |
| probable | score ≥ 0.75, option order matches |
| weak | score ≥ 0.5 |
| insufficient | otherwise, or no SYN/ACK at all |

With no open port there is no option evidence, and the verdict is
`insufficient`. TTL is never used on its own.

Middlebox flags lower the ceiling to `probable`: a SYN/ACK with no options
although the probe offered five, an MSS below 1200, or a SYN/ACK and RST
that imply different initial TTLs.

`--explain` prints the observed values and the reason for every check.

## References

| Name | Source | Options | Window | WS | TTL | DF | RST |
|---|---|---|---|---|---|---|---|
| Linux 7.x (default TCP sysctls) | kernel 7.2.12, OrbStack VM, Alpine 3.20 container, default sysctls | MSS, SACK, TS, NOP, WS | 65160 | 10 | 64 | yes | window 0, DF |

The reference was captured in this repository's lab: `tests/lab/syn_lab.sh`
scans a container on a Docker bridge with `-sS -O --packet-trace`, and the
SYN/ACK fields were read from that capture. An earlier guess of window
scale 7 was wrong; the capture showed 10, which follows from the
receiver's memory sizing. Window scale therefore carries weight 1.

Nothing here comes from `nmap-os-db`. To add a reference, capture a real
SYN/ACK and RST from a known system, add an entry with its provenance to
`references` in `src/fingerprint/os.zig`, and add a test with those bytes.
