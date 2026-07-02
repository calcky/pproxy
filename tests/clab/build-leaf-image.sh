#!/usr/bin/env bash
# Build a prewarmed containerlab generic_vm leaf image.
#
# The base image is a vrnetlab container. Runtime packages must be installed into
# the embedded qcow2 VM disk, not into the outer Docker filesystem. This script
# extracts that qcow2, customizes it with libguestfs, then builds a new Docker
# image that contains the customized disk.
#
# Usage:
#   ./tests/clab/build-leaf-image.sh
#   ./tests/clab/build-leaf-image.sh --tag pproxy/ubuntu-noble-leaf:dev --force
#
# Host dependencies:
#   docker and qemu-img. If virt-customize is not installed on the host, the
#   script builds a small Docker helper image with libguestfs-tools.
#
set -euo pipefail

CLAB_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$CLAB_DIR/../.." && pwd)"

BASE_IMAGE="${LEAF_BASE_IMAGE:-vrnetlab/canonical_ubuntu:noble}"
IMAGE_TAG="${LEAF_IMAGE_TAG:-pproxy/ubuntu-noble-leaf:latest}"
CACHE_DIR="${LEAF_IMAGE_CACHE:-$CLAB_DIR/.cache/leaf-image}"
BUILDER_IMAGE="${LEAF_IMAGE_BUILDER:-pproxy/leaf-image-builder:ubuntu24.04-kernel-net}"
QCOW_PATH="${LEAF_QCOW_PATH:-}"
DISK_SIZE="${LEAF_DISK_SIZE:-8G}"
LIBMEMIF_TAG="${LIBMEMIF_VPP_TAG:-v26.06}"
WITH_DPDK=1
WITH_MEMIF=1
FORCE=0
KEEP_WORKDIR=0

usage() {
  cat <<EOF
Usage: $0 [options]

Options:
  --base-image IMAGE    Base vrnetlab image (default: ${BASE_IMAGE})
  --tag IMAGE           Output image tag (default: ${IMAGE_TAG})
  --builder-image IMAGE Docker helper used when host virt-customize is missing
                        (default: ${BUILDER_IMAGE})
  --qcow-path PATH      qcow2 path inside base image; auto-detected by default
  --disk-size SIZE      Expanded guest disk virtual size (default: ${DISK_SIZE})
  --cache-dir DIR       Build cache/work directory (default: ${CACHE_DIR})
  --libmemif-tag TAG    FD.io VPP tag for libmemif (default: ${LIBMEMIF_TAG})
  --no-dpdk             Do not preinstall dpdk package
  --no-memif            Do not preinstall VPP/libmemif
  --force               Rebuild even if output image already exists
  --keep-workdir        Keep temporary workdir for debugging
  -h, --help            Show this help

Environment aliases:
  LEAF_BASE_IMAGE, LEAF_IMAGE_TAG, LEAF_IMAGE_BUILDER, LEAF_QCOW_PATH,
  LEAF_DISK_SIZE, LEAF_IMAGE_CACHE, LIBMEMIF_VPP_TAG, LIBGUESTFS_BACKEND

After building, set leaf1/leaf2 image in tests/clab/pproxy.clab.yml to:
  ${IMAGE_TAG}
EOF
}

die() {
  echo "  ✗ $*" >&2
  exit 1
}

log() {
  echo "  leaf-image: $*"
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "missing '$1'. Install host deps: sudo apt-get install -y qemu-utils docker.io"
}

build_virt_builder_image() {
  if docker image inspect "$BUILDER_IMAGE" >/dev/null 2>&1; then
    return 0
  fi
  local bdir
  bdir="$(mktemp -d "$CACHE_DIR/virt-builder.XXXXXX")"
  cat > "$bdir/Dockerfile" <<'EOF'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
 && apt-get install -y -qq \
      libguestfs-tools qemu-utils ca-certificates linux-image-generic \
      isc-dhcp-client dhcpcd-base \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*
EOF
  log "building Docker virt-customize helper ${BUILDER_IMAGE}"
  docker build -t "$BUILDER_IMAGE" "$bdir"
  rm -rf "$bdir"
}

run_virt_customize() {
  if command -v virt-customize >/dev/null 2>&1; then
    LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}" virt-customize "$@"
  else
    build_virt_builder_image
    docker run --rm --privileged \
      -e "LIBGUESTFS_BACKEND=${LIBGUESTFS_BACKEND:-direct}" \
      -v "${CACHE_DIR}:${CACHE_DIR}:rw" \
      -v "${REPO_ROOT}:${REPO_ROOT}:ro" \
      "$BUILDER_IMAGE" virt-customize "$@"
  fi
}

run_guestfish() {
  if command -v guestfish >/dev/null 2>&1; then
    LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}" guestfish "$@"
  else
    build_virt_builder_image
    docker run --rm --privileged \
      -e "LIBGUESTFS_BACKEND=${LIBGUESTFS_BACKEND:-direct}" \
      -v "${CACHE_DIR}:${CACHE_DIR}:rw" \
      "$BUILDER_IMAGE" guestfish "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-image)
      BASE_IMAGE="${2:?--base-image requires value}"
      shift 2
      ;;
    --base-image=*)
      BASE_IMAGE="${1#--base-image=}"
      shift
      ;;
    --tag)
      IMAGE_TAG="${2:?--tag requires value}"
      shift 2
      ;;
    --tag=*)
      IMAGE_TAG="${1#--tag=}"
      shift
      ;;
    --builder-image)
      BUILDER_IMAGE="${2:?--builder-image requires value}"
      shift 2
      ;;
    --builder-image=*)
      BUILDER_IMAGE="${1#--builder-image=}"
      shift
      ;;
    --qcow-path)
      QCOW_PATH="${2:?--qcow-path requires value}"
      shift 2
      ;;
    --qcow-path=*)
      QCOW_PATH="${1#--qcow-path=}"
      shift
      ;;
    --disk-size)
      DISK_SIZE="${2:?--disk-size requires value}"
      shift 2
      ;;
    --disk-size=*)
      DISK_SIZE="${1#--disk-size=}"
      shift
      ;;
    --cache-dir)
      CACHE_DIR="${2:?--cache-dir requires value}"
      shift 2
      ;;
    --cache-dir=*)
      CACHE_DIR="${1#--cache-dir=}"
      shift
      ;;
    --libmemif-tag)
      LIBMEMIF_TAG="${2:?--libmemif-tag requires value}"
      shift 2
      ;;
    --libmemif-tag=*)
      LIBMEMIF_TAG="${1#--libmemif-tag=}"
      shift
      ;;
    --no-dpdk)
      WITH_DPDK=0
      shift
      ;;
    --no-memif)
      WITH_MEMIF=0
      shift
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --keep-workdir)
      KEEP_WORKDIR=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1"
      ;;
  esac
done

need docker
need qemu-img

if [[ "$WITH_MEMIF" -eq 1 && ! -f "$REPO_ROOT/scripts/install_libmemif.sh" ]]; then
  die "missing $REPO_ROOT/scripts/install_libmemif.sh"
fi

if [[ "$FORCE" -eq 0 ]] && docker image inspect "$IMAGE_TAG" >/dev/null 2>&1; then
  log "image already exists: ${IMAGE_TAG} (use --force to rebuild)"
  exit 0
fi

mkdir -p "$CACHE_DIR"
WORKDIR="$(mktemp -d "$CACHE_DIR/build.XXXXXX")"
CID=""
cleanup() {
  if [[ -n "$CID" ]]; then
    docker rm -f "$CID" >/dev/null 2>&1 || true
  fi
  if [[ "$KEEP_WORKDIR" -eq 0 ]]; then
    rm -rf "$WORKDIR"
  else
    log "kept workdir: $WORKDIR"
  fi
}
trap cleanup EXIT

log "base image: ${BASE_IMAGE}"
log "output tag: ${IMAGE_TAG}"

docker image inspect "$BASE_IMAGE" >/dev/null 2>&1 || {
  log "pulling base image ${BASE_IMAGE}"
  docker pull "$BASE_IMAGE"
}

if [[ -z "$QCOW_PATH" ]]; then
  QCOW_PATH="$(
    docker run --rm --entrypoint sh "$BASE_IMAGE" \
      -lc 'find / -maxdepth 1 -type f -name "*.qcow2" -print -quit'
  )"
fi
[[ -n "$QCOW_PATH" ]] || die "could not auto-detect qcow2 path in ${BASE_IMAGE}"

QCOW_NAME="$(basename "$QCOW_PATH")"
QCOW_LOCAL="$WORKDIR/$QCOW_NAME"

log "extracting ${QCOW_PATH}"
CID="$(docker create "$BASE_IMAGE")"
docker cp "${CID}:${QCOW_PATH}" "$QCOW_LOCAL"
docker rm -f "$CID" >/dev/null
CID=""

log "source disk:"
qemu-img info "$QCOW_LOCAL" | sed 's/^/    /'

if [[ -n "$DISK_SIZE" ]]; then
  log "expanding guest disk to ${DISK_SIZE}"
  qemu-img resize -f qcow2 "$QCOW_LOCAL" "$DISK_SIZE"
  run_guestfish -a "$QCOW_LOCAL" <<'EOF'
run
part-expand-gpt /dev/sda
part-resize /dev/sda 1 -34
resize2fs /dev/sda1
EOF
  log "expanded disk:"
  qemu-img info "$QCOW_LOCAL" | sed 's/^/    /'
fi

BASE_DEPS_CMD=$(cat <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
  curl ca-certificates gnupg apt-transport-https \
  libbpf1 libxdp1 gdb binutils netcat-openbsd python3-psutil gdbserver \
  liburing2 git cmake make g++ pkg-config
apt-get install -y -qq libelf1t64 2>/dev/null || apt-get install -y -qq libelf1
apt-get install -y -qq libpcap0.8t64 2>/dev/null || apt-get install -y -qq libpcap0.8
apt-get install -y -qq xdp-tools bpftrace 2>/dev/null || true
install -d -m 0755 /opt/pproxy /etc/sysctl.d
printf '%s\n%s\n' 'vm.nr_hugepages = 0' 'vm.hugetlb_shm_group = 0' > /etc/sysctl.d/80-vpp.conf
printf '%s\n%s\n' 'vm.nr_hugepages = 0' 'vm.hugetlb_shm_group = 0' > /etc/sysctl.d/99-pproxy-vpp.conf
EOF
)

DPDK_CMD=$(cat <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq dpdk dpdk-kmods-dkms 2>/dev/null \
  || apt-get install -y -qq dpdk 2>/dev/null \
  || true
EOF
)

FDIO_VPP_CMD=$(cat <<'EOF'
set -eu
export DEBIAN_FRONTEND=noninteractive
install -d -m 0755 /etc/sysctl.d
printf '%s\n%s\n' 'vm.nr_hugepages = 0' 'vm.hugetlb_shm_group = 0' > /etc/sysctl.d/80-vpp.conf
printf '%s\n%s\n' '#!/bin/sh' 'exit 101' > /usr/sbin/policy-rc.d
chmod 755 /usr/sbin/policy-rc.d
if ! test -f /etc/apt/sources.list.d/fdio_release.list; then
  tmp_fdio="$(mktemp)"
  curl -fsSL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh -o "$tmp_fdio"
  bash "$tmp_fdio"
  rm -f "$tmp_fdio"
fi
apt-get update -qq
apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold vpp vpp-plugin-core 2>/dev/null \
  || apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold vpp
rm -f /usr/sbin/policy-rc.d
systemctl disable vpp 2>/dev/null || true
rm -f /etc/systemd/system/multi-user.target.wants/vpp.service
EOF
)

LIBMEMIF_CMD=$(cat <<EOF
set -eu
export LIBMEMIF_VPP_TAG='${LIBMEMIF_TAG}'
if ! PKG_CONFIG_PATH="/usr/local/lib/pkgconfig:/usr/local/lib/x86_64-linux-gnu/pkgconfig:\${PKG_CONFIG_PATH:-}" pkg-config --exists libmemif 2>/dev/null; then
  /opt/pproxy/install_libmemif.sh /usr/local
fi
EOF
)

CLEAN_CMD=$(cat <<'EOF'
set -eu
ldconfig 2>/dev/null || true
apt-get clean
rm -rf /var/lib/apt/lists/* /tmp/libmemif-build /tmp/fdio_release* /tmp/*.deb
EOF
)

VC=(virt-customize -a "$QCOW_LOCAL")
VC+=(--run-command "$BASE_DEPS_CMD")
if [[ "$WITH_DPDK" -eq 1 ]]; then
  VC+=(--run-command "$DPDK_CMD")
fi
if [[ "$WITH_MEMIF" -eq 1 ]]; then
  VC+=(--mkdir /opt/pproxy)
  VC+=(--copy-in "$REPO_ROOT/scripts/install_libmemif.sh:/opt/pproxy")
  VC+=(--chmod 0755:/opt/pproxy/install_libmemif.sh)
  VC+=(--run-command "$FDIO_VPP_CMD")
  VC+=(--run-command "$LIBMEMIF_CMD")
fi
VC+=(--run-command "$CLEAN_CMD")

log "customizing guest disk (this can take several minutes)"
run_virt_customize "${VC[@]:1}"

log "customized disk:"
qemu-img info "$QCOW_LOCAL" | sed 's/^/    /'

cat > "$WORKDIR/Dockerfile" <<EOF
FROM ${BASE_IMAGE}
COPY ${QCOW_NAME} ${QCOW_PATH}
LABEL pproxy.leaf-preinstalled="true"
LABEL pproxy.leaf-base="${BASE_IMAGE}"
LABEL pproxy.leaf-libmemif-tag="${LIBMEMIF_TAG}"
EOF

log "building Docker image ${IMAGE_TAG}"
docker build -t "$IMAGE_TAG" "$WORKDIR"

log "done: ${IMAGE_TAG}"
cat <<EOF

Use it by changing leaf1/leaf2 in tests/clab/pproxy.clab.yml:

    image: ${IMAGE_TAG}

Then run:

    ./tests/clab/perf.sh --matrix --skip-build
EOF
