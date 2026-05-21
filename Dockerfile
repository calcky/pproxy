# Dockerfile -- pproxy 构建环境
#
# 仅用于构建（编译期），不打包运行时。
# 包含 gcc / ninja / libbpf / libpcap 等可选后端依赖。

# Ubuntu 24.04 = DPDK 24.x；与 tests/clab pproxy.clab.yml 中 leaf VM (ubuntu:noble) ABI 对齐，
# 否则 build 出来的 pproxy 会链 librte_*.so.23 而 VM 上只有 .so.24。
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libc6-dev \
        meson \
        ninja-build \
        pkg-config \
        ca-certificates \
        libbpf-dev \
        libxdp-dev \
        libpcap-dev \
        libdpdk-dev \
        liburing-dev \
        clang \
        llvm \
        linux-libc-dev \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# 构建时挂载 /workspace；用户身份由 build.sh 通过 -u 注入
WORKDIR /workspace

CMD ["meson", "--version"]
