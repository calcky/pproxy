# Dockerfile -- pproxy 构建环境
#
# 仅用于构建（编译期），不打包运行时。
# 包含 gcc / ninja / libbpf / libpcap 等可选后端依赖。

FROM debian:bookworm-slim

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
        clang \
        llvm \
        linux-libc-dev \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# 构建时挂载 /workspace；用户身份由 build.sh 通过 -u 注入
WORKDIR /workspace

CMD ["meson", "--version"]
