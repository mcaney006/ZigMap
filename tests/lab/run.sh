#!/bin/sh
# Builds the Linux binary for ARCH and runs connect_lab.sh in a disposable
# container. Only the container's own network namespace is modified.
#   ARCH=aarch64|x86_64  (default: aarch64)
set -eu
ARCH=${ARCH:-aarch64}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
case $ARCH in
	aarch64) PLATFORM=linux/arm64 ;;
	x86_64) PLATFORM=linux/amd64 ;;
	*) echo "unknown ARCH $ARCH" >&2; exit 2 ;;
esac
cd "$ROOT"
zig build -Dtarget=$ARCH-linux -Doptimize=ReleaseSafe --prefix "zig-out/$ARCH-linux"
docker run --rm --platform $PLATFORM --cap-add NET_ADMIN \
	-v "$ROOT/zig-out/$ARCH-linux/bin:/zm:ro" -v "$ROOT/tests/lab:/lab:ro" \
	alpine:3.20 sh -c 'apk add -q python3 iptables ip6tables iproute2-tc nmap binutils >/dev/null && sh /lab/connect_lab.sh'
