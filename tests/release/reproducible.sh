#!/bin/sh
# Builds the release binaries twice from empty caches and checks that every
# binary is byte-identical. Both builds use the same cache paths so nothing
# path-dependent can differ; the caches are wiped between builds.
# Prints the SHA-256 of each binary on success.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
if command -v sha256sum >/dev/null 2>&1; then h() { sha256sum "$1" | cut -d" " -f1; }; else h() { shasum -a 256 "$1" | cut -d" " -f1; }; fi
for n in 1 2; do
	rm -rf "$WORK/cache" "$WORK/gcache" "$WORK/out"
	ZIG_LOCAL_CACHE_DIR="$WORK/cache" ZIG_GLOBAL_CACHE_DIR="$WORK/gcache" \
		zig build release --build-file "$ROOT/build.zig" --prefix "$WORK/out"
	mv "$WORK/out/release" "$WORK/build$n"
done
rc=0
for f in "$WORK/build1/"*; do
	name=$(basename "$f")
	a=$(h "$f")
	b=$(h "$WORK/build2/$name")
	if [ "$a" = "$b" ]; then echo "ok   $a  $name"; else echo "DIFF $name: $a vs $b"; rc=1; fi
done
exit $rc
