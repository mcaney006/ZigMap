#!/bin/sh
# Capture-path benchmark: recvmsg vs TPACKET_V3 ring, each with and without
# the BPF filter, for a full 65535-port SYN scan of 127.0.0.1 in a throwaway
# container while two processes flood loopback with UDP that is NOT
# addressed to 127.0.0.1.
# Reports medians of RUNS runs: wall and CPU time, ports classified per
# second, p50/p95/p99 port completion time, peak RSS, frames read, drops.
# Loopback only: says nothing about NICs.
#   ARCH=aarch64|x86_64  RUNS=5  MODES="recvmsg,no-bpf recvmsg ring,no-bpf ring"
set -eu
ARCH=${ARCH:-aarch64}
RUNS=${RUNS:-5}
case $ARCH in aarch64) PLATFORM=linux/arm64 ;; x86_64) PLATFORM=linux/amd64 ;; *) echo "unknown ARCH $ARCH" >&2; exit 2 ;; esac
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
zig build install lab-tools -Dtarget=$ARCH-linux -Doptimize=ReleaseFast --prefix "zig-out/$ARCH-linux-fast"
docker run --rm --platform $PLATFORM -e RUNS=$RUNS -e MODES="${MODES:-recvmsg,no-bpf recvmsg ring,no-bpf ring}" -v "$ROOT/zig-out/$ARCH-linux-fast/bin:/zm:ro" alpine:3.20 sh -c '
noise() { /zm/labtool udp-noise 127.0.0.3 127.0.0.2 9 & }
noise; noise
sleep 1
median() { sort -n | awk "{a[NR]=\$1} END{print a[int((NR+1)/2)]}"; }
printf "%-16s %8s %8s %9s %8s %8s %8s %8s %11s %7s %5s %s\n" mode wall_ms cpu_ms ports/s p50_ms p95_ms p99_ms rss_KiB frames_seen drops runs result
for m in $MODES; do
  mode=$(echo $m | sed "s/,no-bpf/ --no-bpf/")
  for f in w c f d r t p50 p95 p99; do : >/tmp/$f; done; ok=all-correct
  i=0
  while [ $i -lt $RUNS ]; do
    timeout 120 /zm/zigmap -sS -p - --max-parallelism 1024 --max-rate 0 --stats --capture $mode 127.0.0.1 >/tmp/o 2>&1 || echo "  run $i exit $?" >&2
    grep -q "Summary: 0 open, 65535 closed" /tmp/o || ok=MISMATCH
    sed -n "s/.*wall \([0-9]*\) ms, cpu user \([0-9]*\) ms, sys \([0-9]*\) ms.*/\1 \2 \3/p" /tmp/o | { read w u s; echo $w >>/tmp/w; echo $((u+s)) >>/tmp/c; }
    sed -n "s/.*frames \([0-9]*\), own.*/\1/p" /tmp/o >>/tmp/f
    sed -n "s/.*kernel receive drops \([0-9]*\).*/\1/p" /tmp/o >>/tmp/d
    sed -n "s/.*peak RSS \([0-9]*\) KiB.*/\1/p" /tmp/o >>/tmp/r
    sed -n "s/.*ports classified per second \([0-9]*\);.*/\1/p" /tmp/o >>/tmp/t
    sed -n "s/.*p50 \([0-9.]*\) ms, p95 \([0-9.]*\) ms, p99 \([0-9.]*\) ms.*/\1 \2 \3/p" /tmp/o | { read a b c; echo $a >>/tmp/p50; echo $b >>/tmp/p95; echo $c >>/tmp/p99; }
    i=$((i+1))
  done
  printf "%-16s %8s %8s %9s %8s %8s %8s %8s %11s %7s %5s %s\n" "$m" "$(median </tmp/w)" "$(median </tmp/c)" "$(median </tmp/t)" "$(median </tmp/p50)" "$(median </tmp/p95)" "$(median </tmp/p99)" "$(median </tmp/r)" "$(median </tmp/f)" "$(median </tmp/d)" $RUNS $ok
done
kill $(jobs -p) 2>/dev/null || true'
