#!/bin/sh
# Build the esc probe (CVE-2022-36449 read/write backend: scan, dump, read32, flip).
# Default output: binaries/esc. Override the path with OUT=... .
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR=$(CDPATH= cd -- "$HERE/../.." && pwd)
OUT=${OUT:-$BIN_DIR/esc}
ZIG=${ZIG:-zig}

if ! command -v "$ZIG" >/dev/null 2>&1; then
	printf 'zig not found: %s\n' "$ZIG" >&2
	printf 'Install Zig or set ZIG to the binary path.\n' >&2
	exit 1
fi

# Zig keeps a global cache in ~/.cache/zig by default; keep everything in
# /tmp so the build does not depend on a writable home directory.
cd "$HERE"
ZIG_GLOBAL_CACHE_DIR=${ZIG_GLOBAL_CACHE_DIR:-/tmp/zig-global} \
ZIG_LOCAL_CACHE_DIR=${ZIG_LOCAL_CACHE_DIR:-/tmp/zig-local} \
"$ZIG" cc -target arm-linux-musleabihf -O2 -static -Wall -Wextra \
	-o "$OUT" \
	cve_2022_36449_escalate.c esc_scan.c reclaim_scan.c \
	bridge_builtin.c

printf 'Built: %s\n' "$OUT"
