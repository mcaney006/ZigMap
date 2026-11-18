#!/bin/sh
# Turn `zig build release` output into the release assets:
#   OUT/zigmap-<arch>-<os>.tar.gz  (zigmap binary and README.md)
#   OUT/SHA256SUMS
# Archives are deterministic for a given SOURCE_DATE_EPOCH (default: the
# HEAD commit time). Needs GNU tar (the release workflow runs on Ubuntu).
#   sh packaging/package.sh OUT
set -eu
OUT=${1:?usage: package.sh OUT}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
REL="$ROOT/zig-out/release"
EPOCH=${SOURCE_DATE_EPOCH:-$(git -C "$ROOT" log -1 --format=%ct)}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

n=0
for bin in "$REL"/zigmap-*; do
	[ -f "$bin" ] || continue
	name=$(basename "$bin")
	rm -rf "${stage:?}/$name"
	mkdir "$stage/$name"
	cp "$bin" "$stage/$name/zigmap"
	cp "$ROOT/README.md" "$stage/$name/README.md"
	chmod 755 "$stage/$name/zigmap"
	chmod 644 "$stage/$name/README.md"
	tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH" \
		-C "$stage/$name" -cf - zigmap README.md | gzip -n -9 >"$OUT/$name.tar.gz"
	n=$((n + 1))
done
[ $n -gt 0 ] || { echo "no binaries in $REL; run zig build release first" >&2; exit 1; }
(cd "$OUT" && sha256sum zigmap-*.tar.gz >SHA256SUMS)
cat "$OUT/SHA256SUMS"
