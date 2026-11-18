# Golden packet fixtures

`src/testing/packet_vectors.zig` embeds frames captured from a real Linux
kernel, so the decoders are checked against bytes Zigmap did not produce.
The raw capture is kept as `docs/fixtures-lo.pcap`.

## Capture procedure (Alpine 3.20 container, own network namespace)

```sh
docker run --rm -v "$OUT:/out" alpine:3.20 sh -c '
  apk add tcpdump busybox-extras
  tcpdump -i lo -w /out/lo.pcap -U -s 0 &
  nc -l -p 8080 &
  sleep 1
  nc -w 1 127.0.0.1 8080 </dev/null       # open
  nc -w 1 127.0.0.1 9 </dev/null          # closed
  nc -w 1 ::1 9 </dev/null                # closed, IPv6
  printf zigmap-probe | nc -u -w 1 127.0.0.1 9
  printf zigmap-probe | nc -u -w 1 ::1 9
'
```

The committed capture was recorded with an earlier client script that made
the same connections and datagrams; the commands above reproduce them
with busybox only.

Expected field values in the tests are tshark's independent decode
(`tshark -r lo.pcap -T fields -e tcp.seq_raw ...`), and full TCP checksums
are tshark's *calculated* values (`-o tcp.check_checksum:TRUE`).

## Checksum offload finding

Locally originated TCP segments on `lo` carry `CHECKSUM_PARTIAL`: the
stored checksum is the folded pseudo-header sum, not a valid checksum
(tshark: "matches partial checksum ... TCP checksum offload"). `ethtool -K
lo tx off` does not change this on the tested kernel. Kernel-generated RSTs
and ICMP errors are checksummed in software and are fully valid.

The parser therefore reports `ChecksumStatus = good | bad | partial |
unverified` instead of a boolean. `partial` must not be treated as `bad` in
loopback/veth labs; the raw backend accepts `partial` only when the kernel
marked the frame TP_STATUS_CSUMNOTREADY.
