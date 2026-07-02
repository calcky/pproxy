#!/usr/bin/env bash
# scripts/install_libmemif.sh -- 从 FD.io VPP extras/libmemif 构建并安装 libmemif
#
# 用法: ./scripts/install_libmemif.sh [PREFIX]
#   PREFIX 默认 /usr/local
#
# Ubuntu 默认 apt 无 libmemif-dev；Dockerfile / clab leaf 在需要 memif 时调用本脚本。
set -euo pipefail

PREFIX="${1:-/usr/local}"
TAG="${LIBMEMIF_VPP_TAG:-v26.06}"
WORKDIR="${LIBMEMIF_BUILD_DIR:-/tmp/libmemif-build}"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "install_libmemif: missing $1" >&2
    exit 1
  }
}

need git
need cmake
need make
need pkg-config

rm -rf "$WORKDIR"
mkdir -p "$WORKDIR"
cd "$WORKDIR"

if [[ ! -d vpp/.git ]]; then
  if ! git clone --depth 1 --branch "$TAG" --filter=blob:none --sparse \
      https://github.com/FDio/vpp.git vpp; then
    rm -rf vpp
    git clone --depth 1 --filter=blob:none --sparse https://github.com/FDio/vpp.git vpp
  fi
  git -C vpp sparse-checkout set extras/libmemif
fi

mkdir -p vpp/extras/libmemif/build
cd vpp/extras/libmemif/build
cmake .. -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_BUILD_TYPE=Release
make -j"$(nproc 2>/dev/null || echo 2)"
make install
ldconfig 2>/dev/null || true

mkdir -p "${PREFIX}/include/memif" "${PREFIX}/lib/pkgconfig"
if [[ -f "${PREFIX}/include/libmemif.h" && ! -f "${PREFIX}/include/memif/memif.h" ]]; then
  ln -sf ../libmemif.h "${PREFIX}/include/memif/memif.h"
elif [[ -f "${PREFIX}/include/memif.h" && ! -f "${PREFIX}/include/memif/memif.h" ]]; then
  ln -sf ../memif.h "${PREFIX}/include/memif/memif.h"
fi
cat > "${PREFIX}/lib/pkgconfig/libmemif.pc" <<EOF
prefix=${PREFIX}
exec_prefix=\${prefix}
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: libmemif
Description: FD.io memif userspace library
Version: 26.06
Libs: -L\${libdir} -lmemif
Cflags: -I\${includedir}
EOF

if ! PKG_CONFIG_PATH="${PREFIX}/lib/pkgconfig:${PREFIX}/lib/x86_64-linux-gnu/pkgconfig:${PKG_CONFIG_PATH:-}" \
     pkg-config --exists libmemif 2>/dev/null; then
  echo "install_libmemif: pkg-config libmemif not found under ${PREFIX}" >&2
  exit 1
fi
echo "install_libmemif: ok (prefix=${PREFIX}, tag=${TAG})"
