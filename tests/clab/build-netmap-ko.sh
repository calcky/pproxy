#!/usr/bin/env bash
# 在宿主机 Docker 内为指定内核版本编译 netmap.ko（--no-drivers），供 deploy.sh 分发到 leaf VM。
#
# 用法:
#   ./tests/clab/build-netmap-ko.sh <kernel-release>
#   ./tests/clab/build-netmap-ko.sh 6.8.0-51-generic
#
# 输出（缓存）:
#   tests/clab/.cache/netmap/<kernel-release>/netmap.ko
#
# 环境变量:
#   NETMAP_KO_IMAGE   Docker 镜像（默认 ubuntu:24.04，与 clab leaf noble 对齐）
#   NETMAP_MODULE_SHA 与 deploy.sh / third_party/netmap/README.md 一致
#
set -euo pipefail

CLAB_DIR="$(cd "$(dirname "$0")" && pwd)"
KVER="${1:?usage: $0 <kernel-release>}"
: "${NETMAP_MODULE_SHA:=10986ec1479b54552333d4cef913bef3dd159727}"
: "${NETMAP_KO_IMAGE:=ubuntu:24.04}"

OUT_DIR="${CLAB_DIR}/.cache/netmap/${KVER}"
OUT_KO="${OUT_DIR}/netmap.ko"

if [[ -f "$OUT_KO" ]]; then
  echo "  ✓ netmap.ko cache hit: $OUT_KO"
  exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "  ✗ docker 未找到；netmap.ko 需在宿主机 Docker 内编译（或手动设 PPROXY_NETMAP_KO=…）" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

echo "  netmap-ko: docker build (image=${NETMAP_KO_IMAGE}, kver=${KVER}, commit=${NETMAP_MODULE_SHA:0:12}) …"

# -i 必加：否则 heredoc 不会传入容器 stdin
docker run --rm -i \
  -e "KVER=${KVER}" \
  -e "NM_SHA=${NETMAP_MODULE_SHA}" \
  -v "${OUT_DIR}:/out:rw" \
  "${NETMAP_KO_IMAGE}" \
  bash -s <<'INNER'
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
KBUILD="/lib/modules/${KVER}/build"
SRC=/tmp/netmap-src

apt-get update -qq
if ! apt-get install -y -qq build-essential git "linux-headers-${KVER}"; then
  echo "  ✗ apt 无法安装 linux-headers-${KVER}（leaf 内核与 ubuntu:24.04 仓库不一致？）" >&2
  exit 1
fi
if [[ ! -d "$KBUILD" ]]; then
  apt-get install -y -qq linux-headers-generic || true
fi
if [[ ! -d "$KBUILD" ]]; then
  echo "  ✗ kernel headers missing at $KBUILD" >&2
  exit 1
fi

rm -rf "$SRC"
git clone --depth=1 https://github.com/luigirizzo/netmap.git "$SRC"
cur=$(git -C "$SRC" rev-parse HEAD)
if [[ "$cur" != "$NM_SHA" ]]; then
  git -C "$SRC" fetch --depth=200 origin "$NM_SHA"
  git -C "$SRC" -c advice.detachedHead=false checkout "$NM_SHA"
fi

cd "$SRC/LINUX"
./configure --no-drivers --kernel-dir="$KBUILD"
if [[ ! -f "$SRC/GNUmakefile" ]]; then
  echo "  ✗ configure 未生成 GNUmakefile（见 $SRC/LINUX/config.log）" >&2
  tail -30 "$SRC/LINUX/config.log" >&2 || true
  exit 1
fi

make -j"$(nproc)"
if [[ ! -f "$SRC/LINUX/netmap.ko" ]]; then
  echo "  ✗ make 完成但未找到 netmap.ko" >&2
  ls -la "$SRC/LINUX" >&2 || true
  exit 1
fi
install -m 644 "$SRC/LINUX/netmap.ko" /out/netmap.ko
ls -l /out/netmap.ko
echo "  ✓ netmap.ko built for ${KVER}"
INNER
rc=$?
if [[ $rc -ne 0 ]]; then
  echo "  ✗ docker 编译 netmap.ko 失败 (exit=${rc})" >&2
  exit "$rc"
fi

if [[ ! -f "$OUT_KO" ]]; then
  echo "  ✗ docker 编译完成但未找到 $OUT_KO" >&2
  exit 1
fi
