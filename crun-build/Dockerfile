# Static crun builder.
#
# Built once per target arch via buildx (see build.sh). Alpine's
# musl libc makes a fully-static crun trivial — no glibc NSS traps,
# no per-arch cross-gcc zoo: each arch builds "natively" under QEMU
# user emulation, so crun's autotools just work.
#
# The resulting /crun is a single statically-linked ELF; the runner packs
# it into the pod initramfs at bin/crun via initbuild.PodInitrd.

ARG ALPINE=alpine:3.21

FROM ${ALPINE} AS build
ARG CRUN_VERSION=1.20

# Build deps. libcap/libseccomp/yajl shipped with their *-static
# archives so -all-static can resolve them. argp-standalone supplies
# argp.h, which musl omits. python3 drives crun's libocispec codegen.
RUN apk add --no-cache \
      build-base git bash \
      autoconf automake libtool \
      gettext-dev pkgconf \
      python3 \
      libcap-dev libcap-static \
      libseccomp-dev libseccomp-static \
      yajl-dev yajl-static \
      argp-standalone \
      linux-headers

WORKDIR /src
RUN git clone --depth 1 --branch "${CRUN_VERSION}" https://github.com/containers/crun .

# --disable-systemd: no journald/sd-bus in a micro-VM guest.
# -all-static + the *-static archives → no shared-lib deps at all.
RUN ./autogen.sh \
 && ./configure --enable-static --disable-systemd \
 && make -j"$(nproc)" LDFLAGS="-all-static" \
 && strip crun \
 && ./crun --version \
 && ldd crun 2>&1 | grep -q "not a dynamic executable" \
      || { echo "ERROR: crun is not fully static" >&2; exit 1; }

# Export stage: `buildx --target export --output type=local` pulls
# just the binary out, no image layers.
FROM scratch AS export
COPY --from=build /src/crun /crun
