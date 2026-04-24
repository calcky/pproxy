#!/usr/bin/env bash
#
# build.sh -- pproxy 构建编排 (Docker + Meson + Ninja)
#
# 用法:
#   ./build.sh                 # 默认 release 构建
#   ./build.sh --debug         # buildtype=debug
#   ./build.sh --xdp --pcap    # 启用可选 I/O 后端
#   ./build.sh -j 8            # 并行 8 任务
#   ./build.sh clean           # 删除 build/
#   ./build.sh --native        # 不进 docker，直接用宿主机工具链
#   ./build.sh --shell         # 在容器内打开 bash 调试
#   ./build.sh --rebuild-image # 强制重建 docker 镜像
#   ./build.sh --e2e           # 构建完再跑 tests/e2e.sh（需要 root/CAP_NET_ADMIN）
#   ./build.sh -- ninja_args   # 透传 ninja 参数
#
set -euo pipefail
cd "$(dirname "$0")"

IMAGE="pproxy-build:latest"
BUILD_DIR="build"

# ---------- 参数解析 ----------
DEBUG=0
XDP=0
PCAP=0
NETMAP=0
CLEAN=0
NATIVE=0
SHELL_MODE=0
REBUILD_IMG=0
RUN_E2E=0
JOBS="$(nproc 2>/dev/null || echo 4)"
NINJA_PASSTHROUGH=()

usage() {
    sed -n '2,16p' "$0" | sed 's/^# \?//;s/^#//'
    exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --debug)         DEBUG=1 ;;
        --xdp)           XDP=1 ;;
        --pcap)          PCAP=1 ;;
        --netmap)        NETMAP=1 ;;
        --clean|clean)   CLEAN=1 ;;
        --native)        NATIVE=1 ;;
        --shell)         SHELL_MODE=1 ;;
        --rebuild-image) REBUILD_IMG=1 ;;
        --e2e)           RUN_E2E=1 ;;
        -j)              JOBS="$2"; shift ;;
        -j*)             JOBS="${1#-j}" ;;
        -h|--help)       usage 0 ;;
        --)              shift; NINJA_PASSTHROUGH=("$@"); break ;;
        *)               echo "unknown arg: $1" >&2; usage 1 ;;
    esac
    shift
done

log() { printf '\033[1;32m==>\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m!!!\033[0m %s\n' "$*" >&2; }

# ---------- clean ----------
if [[ $CLEAN -eq 1 ]]; then
    log "removing $BUILD_DIR/"
    rm -rf "$BUILD_DIR"
    exit 0
fi

# ---------- meson 选项 ----------
# Docker 时下面会追加 -Dhost_repo_abs= 当前仓库绝对路径，把 DWARF 中 /workspace/... 映到本机（VSCode/GDB 打开源码）
MESON_OPTS=(
    "-Dxdp=$([[ $XDP    -eq 1 ]] && echo true || echo false)"
    "-Dpcap=$([[ $PCAP   -eq 1 ]] && echo true || echo false)"
    "-Dnetmap=$([[ $NETMAP -eq 1 ]] && echo true || echo false)"
    "--buildtype=$([[ $DEBUG -eq 1 ]] && echo debug || echo release)"
)

# 封装 meson/ninja 的调用，兼容宿主/容器两种执行环境
run_build() {
    local runner=("$@")   # 前缀，比如 docker run ... 或 空
    if [[ -d "$BUILD_DIR/meson-info" ]]; then
        log "meson reconfigure: ${MESON_OPTS[*]}"
        "${runner[@]}" meson setup --reconfigure "$BUILD_DIR" "${MESON_OPTS[@]}"
    else
        log "meson setup: ${MESON_OPTS[*]}"
        "${runner[@]}" meson setup "$BUILD_DIR" "${MESON_OPTS[@]}"
    fi
    log "ninja -C $BUILD_DIR -j $JOBS ${NINJA_PASSTHROUGH[*]:-}"
    "${runner[@]}" ninja -C "$BUILD_DIR" -j "$JOBS" \
        ${NINJA_PASSTHROUGH[@]+"${NINJA_PASSTHROUGH[@]}"}
}

# ---------- docker 镜像 ----------
ensure_image() {
    if ! command -v docker >/dev/null 2>&1; then
        err "docker not found; use --native or install docker"
        exit 1
    fi
    if [[ $REBUILD_IMG -eq 1 ]] || ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
        log "building docker image $IMAGE"
        docker build -t "$IMAGE" -f Dockerfile .
    fi
}

# ---------- 主流程 ----------
if [[ $NATIVE -eq 1 ]]; then
    if [[ $SHELL_MODE -eq 1 ]]; then
        exec "${SHELL:-/bin/bash}"
    fi
    for t in meson ninja; do
        if ! command -v "$t" >/dev/null 2>&1; then
            err "$t not found; install it or omit --native"
            exit 1
        fi
    done
    run_build
else
    ensure_image
    _HOST_ABS="$(pwd -P)"
    MESON_OPTS+=("-Dhost_repo_abs=${_HOST_ABS}")
    DOCKER_OPTS=(
        --rm
        -v "$(pwd):/workspace"
        -w /workspace
        -u "$(id -u):$(id -g)"
    )
    # 用户自定义 CFLAGS 仍可传入容器（对 Meson 主工程 c_args 作用有限，见 meson_options host_repo_abs）
    if [[ -n ${CFLAGS+set} && -n ${CFLAGS-} ]]; then
        DOCKER_OPTS+=(-e "CFLAGS=${CFLAGS}")
    fi
    if [[ -n ${CXXFLAGS+set} && -n ${CXXFLAGS-} ]]; then
        DOCKER_OPTS+=(-e "CXXFLAGS=${CXXFLAGS}")
    fi
    if [[ $SHELL_MODE -eq 1 ]]; then
        log "entering shell in $IMAGE"
        exec docker run -it "${DOCKER_OPTS[@]}" "$IMAGE" /bin/bash
    fi
    run_build docker run "${DOCKER_OPTS[@]}" "$IMAGE"
fi

BIN="$BUILD_DIR/pproxy"
if [[ -x "$BIN" ]]; then
    log "built: $BIN ($(stat -c '%s' "$BIN") bytes)"
fi

# ---------- e2e ----------
if [[ $RUN_E2E -eq 1 ]]; then
    log "running tests/e2e.sh"
    ec=0
    bash tests/e2e.sh || ec=$?
    if [[ $ec -eq 77 ]]; then
        err "e2e skipped (need root / CAP_NET_ADMIN)"
        exit 0
    fi
    exit $ec
fi
