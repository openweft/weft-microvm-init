#!/usr/bin/env -S pkgx bash
# Runs under pkgx-provided bash (5.x), not macOS's stock bash 3.2.
#
# Cross-build the CubeFS FUSE client (cfs-client) for the guest arches into
# cfs-build/dist/. Unlike crun (C, needs zig), cfs-client is pure Go and
# CGO-free, so this is just `GOOS/GOARCH go build ./client` per arch — it
# cross-compiles to all of amd64/arm64/riscv64/loong64 from any host.
#
# The runner packs the result into the pod initramfs at bin/cfs-client
# (weft microvm pod-init-build --cfs-client …); it is NOT go:embed'd.
#
# Usage:
#   ./build.sh                  # all four arches
#   ./build.sh arm64            # a subset
#   CFS_VERSION=v3.5.0 ./build.sh

set -euo pipefail

CFS_VERSION="${CFS_VERSION:-master}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="${DIST:-${HERE}/dist}"
WORK="${WORK:-$HOME/.cache/weft-microvm-init/cubefs-src}"

export PATH="/usr/local/go/bin:$PATH"
command -v go >/dev/null || { echo "ERROR: go not found (need /usr/local/go/bin)" >&2; exit 1; }

ARCHES=("$@")
[ "${#ARCHES[@]}" -eq 0 ] && ARCHES=(amd64 arm64 riscv64 loong64)

# Shallow-clone the pinned CubeFS once.
if [ ! -d "$WORK/.git" ]; then
  rm -rf "$WORK"
  git clone --depth 1 --branch "$CFS_VERSION" https://github.com/cubefs/cubefs "$WORK"
fi

mkdir -p "$DIST"
ok=(); failed=()
for a in "${ARCHES[@]}"; do
  if (cd "$WORK" && GOOS=linux GOARCH="$a" CGO_ENABLED=0 \
        go build -trimpath -ldflags='-s -w' -o "$DIST/cfs-client.linux.$a" ./client); then
    printf ">> %-8s %9d bytes  %s\n" "$a" "$(wc -c < "$DIST/cfs-client.linux.$a")" \
      "$(file -b "$DIST/cfs-client.linux.$a" | cut -d, -f1-2)"
    ok+=("$a")
  else
    echo ">> $a: BUILD FAILED" >&2
    failed+=("$a")
  fi
done

echo
echo "=== summary ==="
echo "built:   ${ok[*]:-none}  -> $DIST"
echo "failed:  ${failed[*]:-none}"
[ "${#failed[@]}" -eq 0 ]
