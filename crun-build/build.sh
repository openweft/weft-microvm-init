#!/usr/bin/env -S pkgx bash
# Runs under pkgx-provided bash (5.x), not macOS's stock bash 3.2.
#
# Build static crun binaries locally, one per target arch, into
# crun-build/dist/. The runner packs them into the pod initramfs at
# bin/crun via `weft microvm pod-init-build --crun …`.
#
# Uses `<engine> buildx` with QEMU user-mode emulation so a single
# host (typically darwin/arm64 or linux/amd64) can build all four
# arches. Each arch compiles "natively" inside an emulated Alpine
# container — no cross-gcc, no autotools host/target juggling.
#
# Container engine is configurable via $ENGINE (default: docker).
# colima provides a docker-compatible daemon, so the default works
# once colima is started — no Docker Desktop needed.
#
# Prerequisites (one-time), colima path:
#   brew install colima docker        # docker = CLI client only
#   colima start --cpu 4 --memory 8
#   # register QEMU binfmt handlers inside colima's Linux VM:
#   docker run --privileged --rm tonistiigi/binfmt --install all
#
# Usage:
#   ./build.sh                      # all four arches
#   ./build.sh amd64 arm64          # a subset
#   CRUN_VERSION=1.21 ./build.sh    # pin a crun version
#   ENGINE=nerdctl ./build.sh       # use a different docker-compatible CLI
#
# A failing arch (e.g. no Alpine loongarch64 image yet) is reported
# and skipped, not fatal — the other arches still land in dist/.

set -euo pipefail

CRUN_VERSION="${CRUN_VERSION:-1.20}"
ENGINE="${ENGINE:-docker}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DIST="${DIST:-${HERE}/dist}"
OUT="${HERE}/out"

if ! command -v "${ENGINE%% *}" >/dev/null 2>&1; then
  echo "ERROR: container engine '${ENGINE%% *}' not found in PATH." >&2
  echo "Install colima + docker CLI (brew install colima docker) and run 'colima start', or set ENGINE=<your-cli>." >&2
  exit 1
fi

# go-arch -> docker buildx platform.
declare -A PLATFORM=(
  [amd64]=linux/amd64
  [arm64]=linux/arm64
  [riscv64]=linux/riscv64
  [loong64]=linux/loong64
)

ARCHES=("$@")
if [ "${#ARCHES[@]}" -eq 0 ]; then
  ARCHES=(amd64 arm64 riscv64 loong64)
fi

mkdir -p "${DIST}"

ok=()
failed=()

for goarch in "${ARCHES[@]}"; do
  plat="${PLATFORM[$goarch]:-}"
  if [ -z "${plat}" ]; then
    echo ">> unknown arch '${goarch}' (known: ${!PLATFORM[*]})" >&2
    failed+=("${goarch}")
    continue
  fi

  echo ">> building crun ${CRUN_VERSION} for ${goarch} (${plat}) via ${ENGINE}"
  rm -rf "${OUT}/${goarch}"
  if ${ENGINE} buildx build \
        --platform "${plat}" \
        --build-arg "CRUN_VERSION=${CRUN_VERSION}" \
        --target export \
        --output "type=local,dest=${OUT}/${goarch}" \
        "${HERE}" \
     && [ -f "${OUT}/${goarch}/crun" ]; then
    cp "${OUT}/${goarch}/crun" "${DIST}/crun.linux.${goarch}"
    chmod +x "${DIST}/crun.linux.${goarch}"
    echo ">> ${goarch}: $(wc -c < "${DIST}/crun.linux.${goarch}") bytes -> ${DIST}/crun.linux.${goarch}"
    ok+=("${goarch}")
  else
    echo ">> ${goarch}: BUILD FAILED (often: no Alpine image for this platform yet)" >&2
    failed+=("${goarch}")
  fi
done

echo
echo "=== summary ==="
echo "built:   ${ok[*]:-none}"
echo "skipped: ${failed[*]:-none}"
if [ "${#failed[@]}" -gt 0 ]; then
  cat >&2 <<EOF

One or more arches did not build. For loong64 in particular, Alpine
may not yet ship a loongarch64 image; build crun on a loongarch64
host (or with a loongarch64 toolchain) and drop the static binary at:
  ${DIST}/crun.linux.loong64
EOF
fi
