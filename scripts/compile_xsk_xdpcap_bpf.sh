#!/usr/bin/env bash
# 编出 build/xsk_xdpcap.bpf.o，供 PPROXY_XDPCAP_BPF= 与 cloudflare/xdpcap 抓包
#
# 先写到 ${TMPDIR}/…：Docker 绑定宿主机 /workspace 时，直接对 build/ 下 .o 写可能 EPERM
#（WSL/部分挂载）；再由 cp 落盘通常可过。
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/build/xsk_xdpcap.bpf.o"
SRC="${ROOT}/bpf/xsk_xdpcap.bpf.c"
mkdir -p "${ROOT}/build"

TMPOUT="$(mktemp "${TMPDIR:-/tmp}/pproxy-bpf-XXXXXX.bpf.o")"
trap 'rm -f -- "$TMPOUT"' EXIT

if ! command -v clang >/dev/null 2>&1; then
  echo "compile_xsk_xdpcap_bpf: clang not found" >&2
  exit 1
fi

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)   TARCH="x86" ;;
  aarch64)  TARCH="arm64" ;;
  arm64)    TARCH="arm64" ;;
  *)
    echo "compile_xsk_xdpcap_bpf: unsupported uname -m: $ARCH" >&2
    exit 1
    ;;
esac

# multiarch: linux/bpf.h -> linux/types.h -> <asm/types.h>
INC_ARCH=""
if [[ -d /usr/include/x86_64-linux-gnu ]]; then
  INC_ARCH="-I/usr/include/x86_64-linux-gnu"
elif [[ -d /usr/include/aarch64-linux-gnu ]]; then
  INC_ARCH="-I/usr/include/aarch64-linux-gnu"
fi
BPF_PC="$(pkg-config --cflags libbpf 2>/dev/null || true)"

clang -O2 -g -target bpf \
  "-D__TARGET_ARCH_${TARCH}" \
  -Wall \
  -I"${ROOT}/bpf" \
  -I/usr/include \
  $INC_ARCH \
  $BPF_PC \
  -c "$SRC" -o "$TMPOUT"

cp -f -- "$TMPOUT" "$OUT"
