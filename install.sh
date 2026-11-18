#!/bin/sh
# Install the zigmap binary from a GitHub release.
#
#   curl -fsSL https://raw.githubusercontent.com/mcaney006/ZigMap/main/install.sh | sh
#
# Environment:
#   ZIGMAP_VERSION      release tag to install, e.g. v0.2.0 (default: latest)
#   ZIGMAP_INSTALL_DIR  where to put the binary (default: /usr/local/bin if
#                       you can write to it, otherwise ~/.local/bin)
#   ZIGMAP_BASE_URL     download from this directory instead of the GitHub
#                       release (a mirror, or file:// for testing)
#
# The download is checked against the release's SHA256SUMS before anything
# is installed. This script never calls sudo; to install somewhere you
# cannot write, run it with the privileges you choose.
set -eu

REPO=mcaney006/ZigMap
VERSION=${ZIGMAP_VERSION:-latest}

say() { printf 'zigmap-install: %s\n' "$*"; }
die() { printf 'zigmap-install: error: %s\n' "$*" >&2; exit 1; }

case $(uname -s) in
Darwin) os=macos ;;
Linux) os=linux ;;
*) die "unsupported OS $(uname -s); prebuilt binaries exist for Linux and macOS (build from source with Zig 0.17.1 otherwise)" ;;
esac
case $(uname -m) in
arm64 | aarch64) arch=aarch64 ;;
x86_64 | amd64) arch=x86_64 ;;
*) die "unsupported CPU $(uname -m); prebuilt binaries exist for x86_64 and aarch64" ;;
esac

if command -v curl >/dev/null 2>&1; then
	fetch() { curl -fsSL --retry 3 -o "$2" "$1"; }
elif command -v wget >/dev/null 2>&1; then
	fetch() { wget -q -O "$2" "$1"; }
else
	die "need curl or wget"
fi
if command -v sha256sum >/dev/null 2>&1; then
	sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
	sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
	die "need sha256sum or shasum to verify the download"
fi

if [ "$VERSION" = latest ]; then
	base="https://github.com/$REPO/releases/latest/download"
else
	case $VERSION in v*) ;; *) VERSION="v$VERSION" ;; esac
	base="https://github.com/$REPO/releases/download/$VERSION"
fi
base=${ZIGMAP_BASE_URL:-$base}
asset="zigmap-$arch-$os.tar.gz"

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t zigmap)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 130' INT TERM

say "downloading $asset ($VERSION)"
fetch "$base/$asset" "$tmp/$asset" || die "could not download $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "could not download $base/SHA256SUMS"

expected=$(awk -v f="$asset" '$2 == f || $2 == "*" f { print $1 }' "$tmp/SHA256SUMS")
[ -n "$expected" ] || die "$asset is not listed in SHA256SUMS"
actual=$(sha256 "$tmp/$asset")
[ "$expected" = "$actual" ] || die "checksum mismatch for $asset (expected $expected, got $actual)"
say "checksum ok"

tar -xzf "$tmp/$asset" -C "$tmp"
[ -f "$tmp/zigmap" ] || die "archive does not contain zigmap"

if [ -n "${ZIGMAP_INSTALL_DIR:-}" ]; then
	dir=$ZIGMAP_INSTALL_DIR
elif [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
	dir=/usr/local/bin
else
	dir="${HOME:?HOME is not set}/.local/bin"
fi
mkdir -p "$dir" 2>/dev/null || die "cannot create $dir"
[ -w "$dir" ] || die "cannot write to $dir; set ZIGMAP_INSTALL_DIR to a directory you own"

# Copy next to the destination, then rename, so a running zigmap is never
# left half-written.
cp "$tmp/zigmap" "$dir/.zigmap.new.$$"
chmod 755 "$dir/.zigmap.new.$$"
mv -f "$dir/.zigmap.new.$$" "$dir/zigmap"

say "installed $("$dir/zigmap" --version) to $dir/zigmap"
case ":$PATH:" in
*":$dir:"*) ;;
*) say "$dir is not on your PATH; add it, for example: export PATH=\"$dir:\$PATH\"" ;;
esac
if [ "$os" = linux ]; then
	say "-sT needs no privileges; -sS and -sU need root or CAP_NET_RAW (sudo setcap cap_net_raw+ep $dir/zigmap)"
fi
say "only scan hosts you are authorized to scan"
