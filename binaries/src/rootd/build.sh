#!/bin/sh
# Build rootd with the Android NDK (aarch64-linux-android28).
# Default output: binaries/rootd. Override the path with OUT=... .
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
BIN_DIR=$(CDPATH= cd -- "$HERE/../.." && pwd)
OUT=${OUT:-$BIN_DIR/rootd}
NDK_ROOT=${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-/opt/android-ndk}}
CC_NAMES="aarch64-linux-android28-clang"

CC=
for name in $CC_NAMES; do
	for bin in "$NDK_ROOT"/toolchains/llvm/prebuilt/*/bin/"$name"; do
		if [ -x "$bin" ]; then
			CC=$bin
			break 2
		fi
	done
done

if [ -z "$CC" ]; then
	printf 'Android NDK compiler not found: %s under %s\n' \
		"$CC_NAMES" "$NDK_ROOT" >&2
	printf 'Set ANDROID_NDK_HOME to the Android NDK directory.\n' >&2
	exit 1
fi

cd "$HERE"
"$CC" \
	-std=c11 \
	-O2 \
	-Wall -Wextra -Werror \
	-D_FORTIFY_SOURCE=2 \
	-fstack-protector-strong \
	-Wl,-z,relro,-z,now \
	rootd.c \
	-o "$OUT"

printf 'Built: %s\n' "$OUT"
