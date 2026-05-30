#!/usr/bin/env -S pkgx bash
# Runs under pkgx-provided bash (5.x), not macOS's stock bash 3.2.
#
# Cross-build a fully-static crun for the weft-init embed — for all
# four guest arches — WITHOUT a container. The C cross-compiler is
# `pkgx zig` (zig cc), which bundles musl for every target, so a
# single darwin/arm64 (or linux) host produces linux/{amd64,arm64,
# riscv64,loong64} static binaries with no QEMU, no Docker, no
# cross-gcc zoo.
#
# crun's only non-disableable dep is yajl; musl also lacks GNU argp.
# Both are tiny C libs we cross-compile from source with the same
# zig toolchain. Everything else crun can do without is turned off
# (--disable-caps/seccomp/systemd/bpf/criu/dl), which is correct for
# a micro-VM guest where the VM itself is the isolation boundary.
#
# We build from crun's release *tarball* (which ships a pre-generated
# ./configure), so there's no autoconf/automake/libtool bootstrap —
# sidestepping pkgx's currently-broken libtool wrapper.
#
# Host tools come from pkgx: zig (cross-compiler), make, pkg-config.
# git/curl/sed/tar/file are stock system tools. python3 is only
# probed by crun's configure (the tarball ships pre-generated
# libocispec sources, so it isn't invoked to build the binary); we
# prefer pkgx, falling back to the system interpreter.
#
# Usage:
#   ./zig-build.sh                 # all four arches → crun-build/dist/
#   ./zig-build.sh amd64 arm64     # a subset
#   CRUN_VERSION=1.27.1 ./zig-build.sh

set -euo pipefail

CRUN_VERSION="${CRUN_VERSION:-1.27.1}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Built crun binaries are no longer go:embed'd — the runner packs them into
# the pod initramfs (initbuild.PodInitrd), so this is a staging dir whose
# paths you hand to the runner.
DIST="${DIST:-${HERE}/dist}"
WORK="${WORK:-$HOME/.cache/weft-microvm-init/crun-zig}"

if ! pkgx zig version >/dev/null 2>&1; then
  echo "ERROR: 'pkgx zig' unavailable — install pkgx (https://pkgx.sh)." >&2
  exit 1
fi

# python3: prefer pkgx, fall back to the system interpreter (always
# present on macOS at /usr/bin/python3).
if pkgx python3 --version >/dev/null 2>&1; then
  PYTHON="pkgx python3"
else
  PYTHON="$(command -v python3 || echo /usr/bin/python3)"
fi

# go-arch -> zig target triple (always *-linux-musl for static).
declare -A TRIPLE=(
  [amd64]=x86_64-linux-musl
  [arm64]=aarch64-linux-musl
  [riscv64]=riscv64-linux-musl
  [loong64]=loongarch64-linux-musl
)

ARCHES=("$@")
if [ "${#ARCHES[@]}" -eq 0 ]; then
  ARCHES=(amd64 arm64 riscv64 loong64)
fi

mkdir -p "$DIST" "$WORK"

# --- fetch crun source tarball once (has pre-generated configure) ---
CRUN_SRC="$WORK/crun-$CRUN_VERSION"
if [ ! -x "$CRUN_SRC/configure" ]; then
  mkdir -p "$CRUN_SRC"
  echo ">> fetching crun $CRUN_VERSION source"
  curl -fsSL -m 120 \
    "https://github.com/containers/crun/releases/download/$CRUN_VERSION/crun-$CRUN_VERSION.tar.gz" \
    | tar xz -C "$CRUN_SRC" --strip-components=1
fi

# --- clone the two C deps once ---
[ -d "$WORK/yajl" ] || git clone --depth 1 https://github.com/lloyd/yajl "$WORK/yajl"
[ -d "$WORK/argp" ] || git clone --depth 1 https://github.com/argp-standalone/argp-standalone "$WORK/argp"

build_one() {
  local goarch="$1" triple="${TRIPLE[$1]}"
  local root="$WORK/$goarch" sysroot="$WORK/$goarch/sysroot" bin="$WORK/$goarch/bin"
  echo ">> building crun $CRUN_VERSION for $goarch ($triple)"
  mkdir -p "$bin" "$sysroot/include/yajl" "$sysroot/lib"

  # zig cc/ar wrappers bound to this arch's musl triple.
  cat > "$bin/cc"  <<E
#!/bin/sh
exec pkgx zig cc -target $triple "\$@"
E
  cat > "$bin/ar"  <<E
#!/bin/sh
exec pkgx zig ar "\$@"
E
  cat > "$bin/ranlib" <<E
#!/bin/sh
exec pkgx zig ranlib "\$@"
E
  # pkg-config wrapper so crun's configure finds it from pkgx (not brew).
  cat > "$bin/pkg-config" <<E
#!/bin/sh
exec pkgx pkg-config "\$@"
E
  chmod +x "$bin"/*

  # --- yajl (direct compile; its old CMake fights cmake 4.x) ---
  if [ ! -f "$sysroot/lib/libyajl.a" ]; then
    cp "$WORK"/yajl/src/api/*.h "$sysroot/include/yajl/"
    sed -e 's/${YAJL_MAJOR}/2/' -e 's/${YAJL_MINOR}/1/' -e 's/${YAJL_MICRO}/1/' \
      "$WORK/yajl/src/api/yajl_version.h.cmake" > "$sysroot/include/yajl/yajl_version.h"
    local yo="$root/yajl-obj"; rm -rf "$yo"; mkdir -p "$yo"
    for c in "$WORK"/yajl/src/*.c; do
      "$bin/cc" -c -O2 -I"$WORK/yajl/src" -I"$sysroot/include" "$c" -o "$yo/$(basename "${c%.c}").o"
    done
    "$bin/ar" rcs "$sysroot/lib/libyajl.a" "$yo"/*.o
  fi

  # --- argp-standalone (musl lacks GNU argp) ---
  if [ ! -f "$sysroot/lib/libargp.a" ]; then
    cat > "$WORK/argp/config.h" <<'CFG'
#define HAVE_UNISTD_H 1
#define HAVE_ALLOCA_H 1
#define HAVE_EX_USAGE 1
#define HAVE_ASPRINTF 1
#define HAVE_STRCHRNUL 1
#define HAVE_STRNDUP 1
#define HAVE_MEMPCPY 1
#define HAVE_DECL_PROGRAM_INVOCATION_NAME 0
#define HAVE_DECL_PROGRAM_INVOCATION_SHORT_NAME 0
#define HAVE_DECL_FWRITE_UNLOCKED 0
#define HAVE_DECL_CLEARERR_UNLOCKED 0
#define HAVE_DECL_FEOF_UNLOCKED 0
#define HAVE_DECL_FERROR_UNLOCKED 0
#define HAVE_DECL_FFLUSH_UNLOCKED 0
#define HAVE_DECL_FGETS_UNLOCKED 0
#define HAVE_DECL_FPUTC_UNLOCKED 0
#define HAVE_DECL_FPUTS_UNLOCKED 0
#define HAVE_DECL_FLOCKFILE 0
#define HAVE_DECL_PUTC_UNLOCKED 0
#define HAVE_GCC_ATTRIBUTE 1
#if __GNUC__ && HAVE_GCC_ATTRIBUTE
# define NORETURN __attribute__ ((__noreturn__))
# define PRINTF_STYLE(f, a) __attribute__ ((__format__ (__printf__, f, a)))
# define UNUSED __attribute__ ((__unused__))
#else
# define NORETURN
# define PRINTF_STYLE(f, a)
# define UNUSED
#endif
CFG
    local ao="$root/argp-obj"; rm -rf "$ao"; mkdir -p "$ao"
    for c in argp-ba argp-eexst argp-fmtstream argp-help argp-parse argp-pv argp-pvh; do
      "$bin/cc" -c -O2 -D_GNU_SOURCE -DHAVE_CONFIG_H -I"$WORK/argp" \
        "$WORK/argp/$c.c" -o "$ao/$c.o"
    done
    "$bin/ar" rcs "$sysroot/lib/libargp.a" "$ao"/*.o
    cp "$WORK/argp/argp.h" "$sysroot/include/argp.h"
  fi

  # --- crun (out-of-tree build, static, stripped at link with -s) ---
  local cb="$root/crun-build"; rm -rf "$cb"; mkdir -p "$cb"; cd "$cb"
  PATH="$bin:$PATH" \
  PKG_CONFIG_PATH="$sysroot/lib/pkgconfig" \
  PYTHON="$PYTHON" \
  CC="$bin/cc" AR="$bin/ar" RANLIB="$bin/ranlib" \
  CFLAGS="-O2 -I$sysroot/include" \
  LDFLAGS="-L$sysroot/lib -static -s" \
  YAJL_CFLAGS="-I$sysroot/include" YAJL_LIBS="-L$sysroot/lib -lyajl" \
  "$CRUN_SRC/configure" --host="$triple" \
    --disable-caps --disable-seccomp --disable-systemd \
    --disable-bpf --disable-criu --disable-dl \
    --enable-embedded-blake3 >/dev/null || return 1
  # Default target (all): builds the BUILT_SOURCES — git-version.h
  # (copied from the tarball's .tarball-git-version.h) and .version —
  # before crun itself. `make crun` alone skips BUILT_SOURCES and the
  # compile fails on <git-version.h>.
  pkgx make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)" >/dev/null || return 1

  # Explicit success check: set -e is suppressed for a function used
  # as an `if` condition, so failures must be caught by hand.
  [ -x "$cb/crun" ] || { echo ">> $goarch: crun binary not produced" >&2; return 1; }
  cp "$cb/crun" "$DIST/crun.linux.$goarch"
  chmod +x "$DIST/crun.linux.$goarch"
  printf ">> %-8s %8d bytes  %s\n" "$goarch" \
    "$(wc -c < "$DIST/crun.linux.$goarch")" \
    "$(file -b "$DIST/crun.linux.$goarch" | cut -d, -f1-2)"
}

ok=(); failed=()
for a in "${ARCHES[@]}"; do
  if [ -z "${TRIPLE[$a]:-}" ]; then echo ">> unknown arch '$a'" >&2; failed+=("$a"); continue; fi
  if build_one "$a"; then ok+=("$a"); else failed+=("$a"); fi
done

echo
echo "=== summary ==="
echo "built:   ${ok[*]:-none}  -> $DIST"
echo "failed:  ${failed[*]:-none}"
[ "${#failed[@]}" -eq 0 ]
