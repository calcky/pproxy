#!/usr/bin/env bash
# tests/clab/deploy.sh -- 部署 containerlab 拓扑、配置 leaf 数据面、可选安装并测试 pproxy
#
# 用法:
#   ./deploy.sh                    # 先宿主机 ./build.sh --xdp --pcap，再部署拓扑 + … + pproxy
#   PPROXY_SKIP_BUILD=1 ./deploy.sh  # 不自动编译（已自备 build/pproxy 或仅试拓扑时）
#   ./deploy.sh --no-pproxy        # 只部署拓扑 + 配置 leaf（不跑 build、不装 pproxy）
#   PPROXY_BIN=/path/to/pproxy ./deploy.sh
#   ./deploy.sh --tunnel=tcp        # 隧道协议：默认 udp；可选 tcp、icmp
#   ./deploy.sh --left-io=tun --right-io=kernel_socket   # 左右手 I/O，见 --help
#   ./deploy.sh --left-io=tun --right-io=memif          # 右手 memif + VPP sidecar（af_packet↔memif L2 桥到 WAN）
#   ./deploy.sh --left-io=tun --right-io=netmap          # 右手 netmap；pproxy 用户态 ARP 学习/应答（勿依赖 leaf 内核 ARP）
#   ./deploy.sh --left-io=tun --right-io=io_uring        # 右手 kernel_socket + io_cfg.backend=io_uring（仍走内核协议栈）
#   ./deploy.sh --left-io=tun --right-io=io_uring --io-uring-zc   # 同上 + io_cfg.tx_zc（SEND_ZC）
#   PPROXY_TUNNEL_MODE=icmp ./deploy.sh   # 同上，环境变量（命令行 --tunnel= 优先）
#   ./deploy.sh --gdb              # 各 leaf 用 gdbserver 起 pproxy（与 .vscode/launch.json 端口 2345/2346 一致，便于 VSCode 联调；metrics smoke 会跳过）
#   与 --gdb 时默认在本机起 ssh -L（tests/clab/gdb-tunnel.sh）把 localhost:2345/2346 转到各 VM 上 gdbserver；勿开: --no-gdb-tunnel 或 PPROXY_GDB_TUNNEL=0
#   仅要隧道不要改 gdb 起法:  --gdb-tunnel  或  PPROXY_GDB_TUNNEL=1
#   PPROXY_GDB=0 ./deploy.sh       # 显式用传统 nohup（若以后默认想切 gdb 可用）
#   默认 PPROXY_COREDUMP=1（各 VM 上 core 落 /opt/pproxy；勿需则 PPROXY_COREDUMP=0）
#
# 宿主机 containerlab：
#   默认 **不** 使用 sudo（适合已加入 docker 组、且按 containerlab 文档配好免 sudo 的环境）。
#   若必须提权：CLAB_SUDO=1 ./deploy.sh
#
# 注意：leaf 虚拟机里配 IP/iptables、以及 pproxy 开 TUN 仍用 clab 用户的 sudo（VM 内，与宿主机无关）。
#
# pproxy 使用 tests/clab/config/*.json（勿在 deploy.sh 里内嵌大段 JSON）；
# 选文件：优先 pp{1,2}.<协议>.left-<左手>.right-<右手>.json；否则回退 pp1.json / pp1.udp.json / pp1.icmp.json 等。
# 远程路径：/opt/pproxy/pproxy、/opt/pproxy/pp{1,2}.json、/opt/pproxy/log/pp.log
# 各 leaf 另装 cilium/pwru → /usr/bin/pwru（默认 v1.0.11；PWRU_URL= 可改）
# af_xdp 时 pproxy 使用 libxdp 默认 XDP 即可起服务。若宿主机存在 xsk_xdpcap.bpf.o（自编译，供 cloudflare/xdpcap
# 抓包 hook），本脚本会额外 scp 并设 PPROXY_XDPCAP_BPF；无该文件则跳过并仅告警，不失败。
# 宿主机 .o 路径可覆盖：PPROXY_XDPCAP_BPF=/path/…/xsk_xdpcap.bpf.o
#
# 改 leaf1 的 WAN 地址时：须同步改 tests/clab/config/pp2.json 里 tunnels[0].server（对端 TCP）。
#
# Core dump（各 leaf VM 内 pproxy 若 segfault，core 落 /opt/pproxy/core-*.%e.%p）:
#   默认开启；会设 kernel.core_pattern 且 nohup 前 ulimit -c unlimited；用 gdb: gdb /opt/pproxy/pproxy core-…
#   关闭: PPROXY_COREDUMP=0 ./deploy.sh
#
# 未设 PPROXY_SKIP_BUILD=1 且非 --no-pproxy 时，本脚本会在「[1/5]」前自动在仓库根执行
#   ./build.sh --xdp --pcap [--dpdk] [--memif] [--netmap] [--io-uring]（随 --left-io / --right-io / --ks-backend 追加）
# 以生成与 leaf 上依赖一致的 build/pproxy。
#
# 命令行帮助:  ./deploy.sh --help
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

TOPO="pproxy.clab.yml"
UBUNTU_USER="clab"
UBUNTU_PASS='clab@123'
# 与 deploy 中 configure_ubuntu_leaf 的地址一致（见 generic_vm 拓扑 + 路由）
LEAF1_WAN_IP="172.16.0.2"
LEAF2_WAN_IP="172.16.1.2"
TUNNEL_PORT=19900
MEMIF_SOCKET_PATH="/opt/pproxy/run/memif.sock"
MEMIF_SOCKET_ID=1
MEMIF_INTERFACE_ID=0
PP1_METRICS=19991
PP2_METRICS=19992

# 与 generic_vm.clab.yml 中 prefix: "" 一致
LEAF1_HOST="leaf1"
LEAF2_HOST="leaf2"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CLAB_DIR="$SCRIPT_DIR"
PPROXY_CFG_DIR="${PPROXY_CFG_DIR:-$CLAB_DIR/config}"
PPROXY_BIN="${PPROXY_BIN:-$REPO_ROOT/build/pproxy}"
# 隧道模式：udp（默认）| tcp | icmp → 见 resolve_tunnel_cfgs；与 listen 端口 19900（tcp/udp）一致
: "${PPROXY_TUNNEL_MODE:=udp}"
TUNNEL_MODE="$PPROXY_TUNNEL_MODE"
# 左手/隧道 I/O（可环境变量 PPROXY_LEFT_IO / PPROXY_RIGHT_IO；右手未设时 tcp/udp→kernel_socket，icmp→raw_socket）
PP1_JSON=""
PP2_JSON=""
# resolve_tunnel_cfgs 会写入
DEPLOY_IO_LEFT=""
DEPLOY_IO_RIGHT=""
# 虚拟机内统一安装前缀（与本仓库配置文件路径一致）
VM_PPROXY_ROOT="/opt/pproxy"
VM_PPROXY_BIN="$VM_PPROXY_ROOT/pproxy"
VM_PP1_CFG="$VM_PPROXY_ROOT/pp1.json"
VM_PP2_CFG="$VM_PPROXY_ROOT/pp2.json"
VM_PPROXY_LOG="$VM_PPROXY_ROOT/log/pp.log"
VM_PPROXY_XDPCAP_BPF="${VM_PPROXY_ROOT}/xsk_xdpcap.bpf.o"
# 来自 tests/clab/leaf-bin，与 xsk_xdpcap 配套；仅当配置需 xdpcap 时 scp
VM_XDPCAP_BIN="/usr/local/bin/xdpcap"
# cilium/pwru：配置 leaf 后装到各 VM /usr/bin/pwru（可 PWRU_URL=… 覆盖）
: "${PWRU_URL:=https://github.com/cilium/pwru/releases/download/v1.0.11/pwru-linux-amd64.tar.gz}"
# 1=各 VM 启用 core 到 ${VM_PPROXY_ROOT}/core-*（与 doc/debug.md 一致；默认 1）
: "${PPROXY_COREDUMP:=1}"
# 0=nohup 起 pproxy；1=gdbserver 起（等 VSCode/ gdb 连上后进程才跑完初始化，与 gdb-tunnel.sh / launch.json 同端口）
: "${PPROXY_GDB:=0}"
# 与 .vscode/launch.json、tests/clab/gdb-tunnel.sh 中端口一致
GDBSERVER_PORT_LEAF1=2345
GDBSERVER_PORT_LEAF2=2346

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=15
  -o LogLevel=ERROR
)

deploy_print_help() {
  cat <<'EOF'
tests/clab/deploy.sh — 部署 containerlab 拓扑、配置 leaf、可选编译并安装 pproxy

用法:
  ./deploy.sh [本脚本选项] [其它参数 → 透传给: containerlab deploy -t pproxy.clab.yml …]

本脚本选项:
  --no-pproxy              只部署拓扑与 leaf 网络，不编译、不装 pproxy
  --tunnel=tcp|udp|icmp    隧道协议（默认 udp；也可 PPROXY_TUNNEL_MODE，命令行优先）
  --left-io=KIND           左手 I/O: tun, raw_socket, af_xdp, netmap, pcap, dpdk（默认同环境或 tun）
  --right-io=KIND|auto     隧道 I/O: kernel_socket, raw_socket, tun, af_xdp, netmap, pcap, dpdk, memif, io_uring
                           省略或 auto 时：tcp/udp→kernel_socket，icmp→raw_socket
                           io_uring：等价 kernel_socket + io_cfg.backend=io_uring（需 ./build.sh --io-uring）
                           --io-uring-zc / --no-io-uring-zc  强制开启/关闭 io_cfg.tx_zc（SEND_ZC；默认沿用 JSON 模板）
                           注意：dpdk 需要 hugepages + vfio-pci 已绑指定数据网卡；DPDK 接管后内核不可见，
                                 不能与 kernel_socket 共用同一张卡；router 需静态 ARP
                           memif 需 leaf 上 VPP（memif master）+ libmemif；pproxy 为 slave，经 af_packet 桥到 WAN
                           netmap 需内核 netmap 模块；入向 ARP 由 pproxy 用户态处理，router 可动态 ARP
                           （netmap.ko 在宿主机 Docker 编一次，见 tests/clab/build-netmap-ko.sh）
  --perf-config-dir=DIR    性能测试 JSON 模板目录（等价 PPROXY_PERF_CONFIG_DIR）
  --ks-backend=BACKEND     kernel_socket 热路径：syscall（默认）或 io_uring（与 --right-io=io_uring 等价）
  --gdb / --no-gdb         是否用 gdbserver 起 pproxy（默认 --no-gdb）
  --gdb-tunnel             部署结束后在本机跑 gdb-tunnel.sh（ssh -L 转发 gdb 端口）
  --no-gdb-tunnel          不建立上述转发
  -h, --help               显示本帮助并退出（不部署、不编译）

常用环境变量:
  PPROXY_SKIP_BUILD=1      跳过宿主机 ./build.sh
  PPROXY_BIN=路径          pproxy 可执行文件（默认 仓库/build/pproxy）
  PPROXY_CFG_DIR=路径      配置文件目录（默认 tests/clab/config）
  PPROXY_PERF_CONFIG_DIR=  同 --perf-config-dir（优先于 PPROXY_CFG_DIR 选模板）
  PPROXY_SKIP_SMOKE=1      跳过 [4/5] metrics smoke（perf 矩阵 redeploy 时用）
  --pproxy-only            跳过 clab 重建，仅按 --right-io 做后端准备 + 推配置 + 重启 pproxy
  --matrix-prep            perf --matrix 首次：编全后端、装齐依赖/netmap，仍走完整 clab deploy
  PPROXY_TUNNEL_MODE       同 --tunnel（命令行优先）
  PPROXY_LEFT_IO, PPROXY_RIGHT_IO  同 --left-io / --right-io（命令行优先）
  PPROXY_KS_BACKEND                同 --ks-backend（syscall|io_uring；命令行优先）
  PPROXY_IO_URING_ZC=0|1             同 --no-io-uring-zc / --io-uring-zc（未设则沿用 JSON 模板）
  PPROXY_COREDUMP, PPROXY_GDB, PPROXY_GDB_TUNNEL
  CLAB_SUDO=1              使用 sudo 调用 containerlab
  PPROXY_XDPCAP_BPF=路径   宿主机 xsk_xdpcap.bpf.o（可选；有则随 af_xdp 一起部署到 VM）
  PWRU_URL=URL              pwru 预编译包（默认 Cilium v1.0.11 linux-amd64）
  PPROXY_NETMAP_KO=路径     跳过宿主机 docker 编译，直接使用已有 netmap.ko

更完整的说明见本脚本文件头注释。
EOF
}

CLAB_ARGS=()
SKIP_PPROXY=0
PPROXY_ONLY=0
MATRIX_PREP=0
DEPLOY_HELP=0
for a in "$@"; do
  if [[ "$a" == "--no-pproxy" ]]; then
    SKIP_PPROXY=1
  elif [[ "$a" == "--pproxy-only" ]]; then
    PPROXY_ONLY=1
  elif [[ "$a" == "--matrix-prep" ]]; then
    MATRIX_PREP=1
  elif [[ "$a" == "-h" || "$a" == "--help" ]]; then
    DEPLOY_HELP=1
  elif [[ "$a" == "--gdb" ]]; then
    PPROXY_GDB=1
  elif [[ "$a" == "--no-gdb" ]]; then
    PPROXY_GDB=0
  elif [[ "$a" == "--gdb-tunnel" ]]; then
    PPROXY_GDB_TUNNEL=1
  elif [[ "$a" == "--no-gdb-tunnel" ]]; then
    PPROXY_GDB_TUNNEL=0
  elif [[ "$a" == --tunnel=* ]]; then
    TUNNEL_MODE="${a#--tunnel=}"
  elif [[ "$a" == --left-io=* ]]; then
    PPROXY_LEFT_IO="${a#--left-io=}"
  elif [[ "$a" == --right-io=* ]]; then
    PPROXY_RIGHT_IO="${a#--right-io=}"
  elif [[ "$a" == --ks-backend=* ]]; then
    PPROXY_KS_BACKEND="${a#--ks-backend=}"
  elif [[ "$a" == --io-uring-zc ]]; then
    PPROXY_IO_URING_ZC=1
  elif [[ "$a" == --no-io-uring-zc ]]; then
    PPROXY_IO_URING_ZC=0
  elif [[ "$a" == --perf-config-dir=* ]]; then
    PPROXY_PERF_CONFIG_DIR="${a#--perf-config-dir=}"
  else
    CLAB_ARGS+=("$a")
  fi
done
# perf 模板目录：优先于默认 config/
if [[ -n "${PPROXY_PERF_CONFIG_DIR:-}" ]]; then
  PPROXY_CFG_DIR="$PPROXY_PERF_CONFIG_DIR"
fi
# set -u：未设时为空串；可由 --gdb-tunnel / --no-gdb-tunnel 或环境变量覆盖
: "${PPROXY_GDB_TUNNEL:=}"
# io_uring TX ZC：空=沿用模板；0=关；1=开（--io-uring-zc / --no-io-uring-zc / PPROXY_IO_URING_ZC）
if [[ -n "${PPROXY_IO_URING_ZC:-}" ]]; then
  case "$(printf '%s' "$PPROXY_IO_URING_ZC" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on)  DEPLOY_IO_URING_ZC=1 ;;
    0|false|no|off) DEPLOY_IO_URING_ZC=0 ;;
    *)
      echo "Invalid PPROXY_IO_URING_ZC=${PPROXY_IO_URING_ZC} (use 0, 1, or --io-uring-zc / --no-io-uring-zc)" >&2
      exit 1
      ;;
  esac
else
  DEPLOY_IO_URING_ZC=""
fi

if [[ "$DEPLOY_HELP" -eq 1 ]]; then
  deploy_print_help
  exit 0
fi

if [[ "$PPROXY_ONLY" -eq 1 && "$SKIP_PPROXY" -eq 1 ]]; then
  echo "  ✗ --pproxy-only 不能与 --no-pproxy 同用" >&2
  exit 1
fi

resolve_tunnel_cfgs() {
  TUNNEL_MODE="${TUNNEL_MODE,,}"
  case "$TUNNEL_MODE" in
    tcp|udp|icmp) ;;
    *)
      echo "Invalid tunnel mode: $TUNNEL_MODE (use tcp, udp, or icmp; or PPROXY_TUNNEL_MODE=...)" >&2
      exit 1
      ;;
  esac

  local l r cfg_r ks_be
  l=$(printf '%s' "${PPROXY_LEFT_IO:-tun}" | tr '[:upper:]' '[:lower:]')
  r="${PPROXY_RIGHT_IO:-}"
  r=$(printf '%s' "$r" | tr '[:upper:]' '[:lower:]')
  ks_be=$(printf '%s' "${PPROXY_KS_BACKEND:-syscall}" | tr '[:upper:]' '[:lower:]')
  if [[ -z "$r" || "$r" == "auto" ]]; then
    case "$TUNNEL_MODE" in
      tcp|udp) r=kernel_socket ;;
      icmp) r=raw_socket ;;
    esac
  fi
  if [[ "$r" == "io_uring" ]]; then
    ks_be=io_uring
    r=kernel_socket
  fi
  case "$ks_be" in
    syscall|io_uring) ;;
    *)
      echo "Invalid --ks-backend / PPROXY_KS_BACKEND: ${PPROXY_KS_BACKEND:-syscall} (syscall, io_uring)" >&2
      exit 1
      ;;
  esac
  if [[ "$ks_be" == "io_uring" && "$r" != "kernel_socket" ]]; then
    echo "io_cfg.backend=io_uring 仅适用于 right-io=kernel_socket（或 --right-io=io_uring）" >&2
    exit 1
  fi
  DEPLOY_KS_BACKEND=$ks_be
  cfg_r=$r
  if [[ "$DEPLOY_KS_BACKEND" == "io_uring" ]]; then
    cfg_r=io_uring
  fi

  case "$l" in
    tun|raw_socket|af_xdp|netmap|pcap|dpdk) ;;
    *)
      echo "Invalid --left-io / PPROXY_LEFT_IO: ${PPROXY_LEFT_IO:-tun} (tun, raw_socket, af_xdp, netmap, pcap, dpdk)" >&2
      exit 1
      ;;
  esac
  case "$r" in
    kernel_socket|raw_socket|tun|af_xdp|netmap|pcap|dpdk|memif) ;;
    *)
      echo "Invalid --right-io / PPROXY_RIGHT_IO: $r (kernel_socket, raw_socket, tun, af_xdp, netmap, pcap, dpdk, memif, io_uring, auto)" >&2
      exit 1
      ;;
  esac

  DEPLOY_IO_LEFT=$l
  DEPLOY_IO_RIGHT=$r

  local c1_1 c2_1 c1_2 c2_2
  c1_1="${PPROXY_CFG_DIR}/pp1.${TUNNEL_MODE}.left-${l}.right-${cfg_r}.json"
  c2_1="${PPROXY_CFG_DIR}/pp2.${TUNNEL_MODE}.left-${l}.right-${cfg_r}.json"
  case "$TUNNEL_MODE" in
    tcp)
      c1_2="${PPROXY_CFG_DIR}/pp1.json"
      c2_2="${PPROXY_CFG_DIR}/pp2.json"
      ;;
    udp)
      c1_2="${PPROXY_CFG_DIR}/pp1.udp.json"
      c2_2="${PPROXY_CFG_DIR}/pp2.udp.json"
      ;;
    icmp)
      c1_2="${PPROXY_CFG_DIR}/pp1.icmp.json"
      c2_2="${PPROXY_CFG_DIR}/pp2.icmp.json"
      ;;
  esac

  if [[ -f "$c1_1" && -f "$c2_1" ]]; then
    PP1_JSON=$c1_1
    PP2_JSON=$c2_1
  elif [[ -f "$c1_2" && -f "$c2_2" ]]; then
    PP1_JSON=$c1_2
    PP2_JSON=$c2_2
  else
    echo "  ✗ 未找到与 tunnel=${TUNNEL_MODE} left=${l} right=${cfg_r} 匹配的配置" >&2
    echo "     优先: $c1_1" >&2
    echo "         $c2_1" >&2
    echo "     或回退: $c1_2  +  $c2_2" >&2
    exit 1
  fi
}
resolve_tunnel_cfgs

# 某侧 JSON 中 left.kind 或 tunnels[].io 为 af_xdp 时需加载 xsk_xdpcap.bpf.o（与 pproxy 一致）
pproxy_json_uses_af_xdp() {
  [[ -f "${PP1_JSON:-}" && -f "${PP2_JSON:-}" ]] || return 1
  if [[ ! -s "$PP1_JSON" || ! -s "$PP2_JSON" ]]; then
    echo "  ✗ 配置 JSON 不能为空: ${PP1_JSON} / ${PP2_JSON}" >&2
    exit 1
  fi
  command -v python3 >/dev/null 2>&1 || return 1
  python3 - "$PP1_JSON" "$PP2_JSON" <<'PY'
import json, os, sys
def load(path):
    with open(path, encoding="utf-8") as f:
        raw = f.read()
    if not raw.strip():
        print(f"pproxy_json_uses_af_xdp: 文件为空: {path}", file=sys.stderr)
        sys.exit(2)
    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"pproxy_json_uses_af_xdp: 非有效 JSON: {path}\n  {e}", file=sys.stderr)
        sys.exit(2)
def has_af(d):
    if d.get("left", {}).get("kind") == "af_xdp":
        return True
    for t in d.get("tunnels") or []:
        if t.get("io") == "af_xdp":
            return True
    return False
for p in sys.argv[1:]:
    if not os.path.isfile(p):
        print(f"pproxy_json_uses_af_xdp: 不存在: {p}", file=sys.stderr)
        sys.exit(2)
    d = load(p)
    if has_af(d):
        sys.exit(0)
sys.exit(1)
PY
  local st=$?
  if [[ $st -eq 0 ]]; then
    return 0
  fi
  if [[ $st -eq 2 ]]; then
    echo "  ✗ 无法解析配置以检测 af_xdp（见上方）" >&2
    exit 1
  fi
  return 1
}

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing dependency: $1 (install: $2)" >&2
    exit 1
  }
}

require sshpass "sshpass"
require scp "openssh-client"
require containerlab "containerlab (https://containerlab.dev)"

# 宿主编译：与 pproxy_apt_deps / 拷贝的运行动态库一致（xdp+pcap；
# 左右手任一为 dpdk/netmap 时分别追加 --dpdk / --netmap）
if [[ "$PPROXY_ONLY" -eq 0 && "$SKIP_PPROXY" -eq 0 && "${PPROXY_SKIP_BUILD:-0}" != "1" ]]; then
  BUILD_ARGS=(--xdp --pcap --debug)
  if [[ "$MATRIX_PREP" -eq 1 ]]; then
    BUILD_ARGS+=(--dpdk --memif --netmap --io-uring)
  else
    if [[ "$DEPLOY_IO_LEFT" == "dpdk" || "$DEPLOY_IO_RIGHT" == "dpdk" ]]; then
      BUILD_ARGS+=(--dpdk)
    fi
    if [[ "$DEPLOY_IO_LEFT" == "memif" || "$DEPLOY_IO_RIGHT" == "memif" ]]; then
      BUILD_ARGS+=(--memif)
    fi
    if [[ "$DEPLOY_IO_LEFT" == "netmap" || "$DEPLOY_IO_RIGHT" == "netmap" ]]; then
      BUILD_ARGS+=(--netmap)
    fi
    if [[ "${DEPLOY_KS_BACKEND:-syscall}" == "io_uring" ]]; then
      BUILD_ARGS+=(--io-uring)
    fi
  fi
  echo "=== [0/5] Host: $REPO_ROOT/build.sh ${BUILD_ARGS[*]} ==="
  (cd "$REPO_ROOT" && ./build.sh "${BUILD_ARGS[@]}")
fi

if [[ "$PPROXY_ONLY" -eq 0 ]]; then
  echo "=== [1/5] Deploying containerlab topology ==="
  if [[ "${CLAB_SUDO:-0}" == "1" ]]; then
    echo "  (using: sudo containerlab …; set CLAB_SUDO=0 to try without sudo)"
    sudo containerlab destroy -t "$TOPO" --cleanup 2>/dev/null || true
    sudo containerlab deploy -t "$TOPO" "${CLAB_ARGS[@]:-}"
  else
    echo "  (using: containerlab without sudo; need root? set CLAB_SUDO=1)"
    containerlab destroy -t "$TOPO" --cleanup 2>/dev/null || true
    containerlab deploy -t "$TOPO" "${CLAB_ARGS[@]:-}"
  fi
fi

wait_for_ssh() {
  local label=$1
  local host=$2
  local attempt=0
  local max=72
  while [ "$attempt" -lt "$max" ]; do
    if sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" "echo ok" &>/dev/null; then
      echo "  ✓ ${label} (${host}) is ready for SSH"
      return 0
    fi
    attempt=$((attempt + 1))
    echo "  … waiting for ${label} (${attempt}/${max}, ~5s)"
    sleep 5
  done
  echo "  ✗ ${label} did not accept SSH in time" >&2
  return 1
}

configure_ubuntu_leaf() {
  local label=$1
  local host=$2
  local wan_cidr=$3
  local lan_cidr=$4
  local gw=$5
  local peer_lan_cidr=${6:-}
  local peer_uplink_cidr=${7:-}
  # 1=WAN 留给 DPDK：仍 link up 但不配 IP/路由/MASQUERADE（避免与 vfio-pci 接管冲突）
  local wan_for_dpdk=${8:-0}

  echo "  Configuring ${label} (WAN=${wan_cidr}, LAN=${lan_cidr}, GW=${gw}, wan_for_dpdk=${wan_for_dpdk}) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" bash -s <<EOF
set -euo pipefail
WAN_CIDR='${wan_cidr}'
LAN_CIDR='${lan_cidr}'
GW='${gw}'
LABEL='${label}'
PEER_LAN='${peer_lan_cidr}'
PEER_UPLINK='${peer_uplink_cidr}'
WAN_FOR_DPDK='${wan_for_dpdk}'
SUDO_PASS='${UBUNTU_PASS}'
s() { printf '%s\n' "\$SUDO_PASS" | sudo -S "\$@"; }

MGT_DEV=\$(ip -4 route show default 2>/dev/null | head -1 | sed -n 's/.* dev \\([^ ]*\\).*/\\1/p' || true)
readarray -t ALL < <(ip -br link | awk '\$1 != "lo" { print \$1 }' | sort)
DATA=()
for i in "\${ALL[@]}"; do
  if [[ -n "\$MGT_DEV" && "\$i" == "\$MGT_DEV" ]]; then
    continue
  fi
  DATA+=("\$i")
done
if [[ \${#DATA[@]} -lt 2 && \${#ALL[@]} -ge 3 ]]; then
  DATA=("\${ALL[1]}" "\${ALL[2]}")
elif [[ \${#DATA[@]} -lt 2 ]]; then
  echo "Could not find two data interfaces (have: \${ALL[*]})" >&2
  exit 1
fi
	WAN="\${DATA[0]}"
	LAN="\${DATA[1]}"
	printf 'WAN=%s\nLAN=%s\n' "\$WAN" "\$LAN" | s tee /run/pproxy-devices.env >/dev/null

	if [[ "\$WAN_FOR_DPDK" == "1" ]]; then
  s ip addr flush dev "\$WAN" 2>/dev/null || true
  s ip link set "\$WAN" up
  echo "OK \${LABEL}: WAN=\$WAN (leave for DPDK; no IP/route/MASQ) LAN=\$LAN"
else
  s ip addr flush dev "\$WAN" 2>/dev/null || true
  s ip addr add "\$WAN_CIDR" dev "\$WAN"
  s ip link set "\$WAN" up
fi

s ip addr flush dev "\$LAN" 2>/dev/null || true
s ip addr add "\$LAN_CIDR" dev "\$LAN"
s ip link set "\$LAN" up

# ip_forward 与 WAN 无关：left=tun 时 client→LAN→ppclab 也需要它
s sysctl -w net.ipv4.ip_forward=1 >/dev/null

# WAN 留给 DPDK 时，下面的路由/MASQ 都依附在 WAN 上，整段跳过
if [[ "\$WAN_FOR_DPDK" != "1" ]]; then
  if [[ -n "\$PEER_LAN" ]]; then
    s ip route replace "\$PEER_LAN" via "\$GW" dev "\$WAN" 2>/dev/null || true
  fi
  if [[ -n "\$PEER_UPLINK" ]]; then
    s ip route replace "\$PEER_UPLINK" via "\$GW" dev "\$WAN" 2>/dev/null || true
  fi
  if s iptables -t nat -C POSTROUTING -o "\$WAN" -j MASQUERADE 2>/dev/null; then
    :
  else
    s iptables -t nat -A POSTROUTING -o "\$WAN" -j MASQUERADE
  fi
  echo "OK \${LABEL}: WAN=\$WAN LAN=\$LAN"
fi

# WAN/LAN devname 给宿主侧 capture（PPDEV: 行）；prefix 不变方便 grep
echo "PPDEV: \${LABEL} WAN=\$WAN LAN=\$LAN"
EOF
  echo "  ✓ ${label} done"
}

# cilium/pwru：宿主机拉 tarball → scp → 各 leaf 解压到 /usr/bin
leaf_install_pwru() {
  echo "  pwru: fetching ${PWRU_URL} …"
  local tmp tgz
  tmp=$(mktemp -d)
  tgz="$tmp/pwru.tgz"
  if ! curl -fsSL "$PWRU_URL" -o "$tgz"; then
    echo "  ⚠ pwru: download failed（网络问题，可选 debug 工具，跳过不影响 pproxy）" >&2
    rm -rf "$tmp"
    return 0
  fi
  local rhost
  for rhost in "$LEAF1_HOST" "$LEAF2_HOST"; do
    echo "  pwru: ${rhost} → /usr/bin/pwru …"
    sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$tgz" \
      "${UBUNTU_USER}@${rhost}:/tmp/pwru-linux-amd64.tgz"
    sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${rhost}" \
      bash -s -- "$UBUNTU_PASS" <<'EOW'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s tar -xzf /tmp/pwru-linux-amd64.tgz -C /usr/bin
rm -f /tmp/pwru-linux-amd64.tgz
EOW
  done
  rm -rf "$tmp"
  echo "  ✓ pwru on leaf1 + leaf2 (/usr/bin/pwru)"
}

# ---------- pproxy: 装动态库、拷二进制、发配置、起进程、简单检查 ----------
pproxy_apt_deps() {
  local host=$1
  local need_dpdk="${2:-0}"
  local need_uring="${3:-0}"
  local need_memif="${4:-0}"
  echo "  pproxy: installing runtime libs on ${host} (dpdk=${need_dpdk}, io_uring=${need_uring}, memif=${need_memif}) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$need_dpdk" "$need_uring" "$need_memif" <<'EOA'
set -euo pipefail
SUDO_PASS="$1"
NEED_DPDK="$2"
NEED_IO_URING="$3"
NEED_MEMIF="$4"
s() { printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"; }
export DEBIAN_FRONTEND=noninteractive
s apt-get update -qq
s apt-get install -y -qq curl ca-certificates libbpf1 libxdp1 gdb binutils netcat-openbsd python3-psutil 2>/dev/null \
  || true
if ! command -v gdbserver >/dev/null 2>&1; then
  s apt-get install -y -qq gdbserver
fi
s apt-get install -y -qq libelf1t64 2>/dev/null || s apt-get install -y -qq libelf1
s apt-get install -y -qq libpcap0.8t64 2>/dev/null || s apt-get install -y -qq libpcap0.8
if ! s apt-get install -y -qq xdp-tools bpftrace; then
  echo "  … note: xdp-tools/bpftrace install failed (optional; check apt sources / release)" >&2
fi
if [[ "$NEED_IO_URING" == "1" ]]; then
  s apt-get install -y -qq liburing2 2>/dev/null \
    || s apt-get install -y -qq liburing2t64 2>/dev/null \
    || echo "  ✗ liburing2 安装失败（请人工 apt install liburing2）" >&2
fi
if [[ "$NEED_DPDK" == "1" ]]; then
  # dpdk metapackage 通过 Recommends 拉对应 ABI 的 librte-*（Debian12→.so.23, Ubuntu24.04→.so.24）；
  # 别再写死 libdpdk23，Ubuntu noble 没这个名字
  s apt-get install -y -qq dpdk dpdk-kmods-dkms 2>/dev/null \
    || s apt-get install -y -qq dpdk \
    || echo "  ✗ DPDK 包安装失败（请人工执行 apt install dpdk）" >&2
fi
if [[ "$NEED_MEMIF" == "1" ]]; then
  s apt-get install -y -qq git cmake make g++ pkg-config 2>/dev/null || true
  if ! command -v vpp >/dev/null 2>&1; then
    if ! test -f /etc/apt/sources.list.d/fdio_release.list; then
      tmp_fdio=$(mktemp)
      if curl -fsSL https://packagecloud.io/install/repositories/fdio/release/script.deb.sh -o "$tmp_fdio"; then
        s bash "$tmp_fdio" || echo "  ✗ FD.io apt repo 安装失败" >&2
      else
        echo "  ✗ FD.io apt repo 脚本下载失败" >&2
      fi
      rm -f "$tmp_fdio"
      test -f /etc/apt/sources.list.d/fdio_release.list \
        || echo "  ✗ FD.io apt repo 安装失败" >&2
    fi
    s apt-get update -qq
    # VPP packages enable/start a systemd service and apply 1024 hugepages by
    # default. In the 1GB clab leaf VM that can starve later apt/cmake work.
    s sh -c 'printf "%s\n%s\n" "#!/bin/sh" "exit 101" > /usr/sbin/policy-rc.d'
    s chmod 755 /usr/sbin/policy-rc.d
    s sh -c 'mkdir -p /etc/sysctl.d && printf "%s\n%s\n" "vm.nr_hugepages = 0" "vm.hugetlb_shm_group = 0" > /etc/sysctl.d/80-vpp.conf'
    s apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold vpp vpp-plugin-core 2>/dev/null \
      || s apt-get install -y -qq -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold vpp \
      || echo "  ✗ VPP 包安装失败（请人工 apt install vpp vpp-plugin-core）" >&2
    s rm -f /usr/sbin/policy-rc.d
    s systemctl disable --now vpp 2>/dev/null || true
    s pkill -x vpp_main 2>/dev/null || true
    s pkill -f '^vpp -c ' 2>/dev/null || true
    s sh -c 'printf "%s\n%s\n" "vm.nr_hugepages = 0" "vm.hugetlb_shm_group = 0" > /etc/sysctl.d/99-pproxy-vpp.conf'
    s sysctl -w vm.nr_hugepages=0 >/dev/null 2>&1 || true
  fi
  if ! pkg-config --exists libmemif 2>/dev/null; then
    if [[ -x /opt/pproxy/install_libmemif.sh ]]; then
      s /opt/pproxy/install_libmemif.sh /usr/local || true
    fi
  fi
fi
EOA
}

# DPDK 运行依赖：hugepages + vfio + vfio-pci（含 QEMU virtio 用的 no-IOMMU 模式）；不绑定具体网卡
pproxy_dpdk_runtime_setup() {
  local host=$1
  echo "  pproxy: dpdk runtime: 1024 hugepages(2M) + vfio (no-IOMMU) + vfio-pci on ${host} …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" <<'EOD'
set -euo pipefail
SUDO_PASS="$1"
s() { printf '%s\n' "$SUDO_PASS" | sudo -S -p '' "$@"; }
# 先把之前残留的 pproxy 干掉释放 hugepage，再 reset 一下 nr_hugepages（避免碎片）
s pkill -9 -f '/opt/pproxy/pproxy' 2>/dev/null || true
s pkill -9 -f gdbserver 2>/dev/null || true
sleep 0.3
# 64 个 2M hugepage = 128MB，刚好覆盖 nframes=2048 (~5MB)+EAL 内部开销，留够 RAM 给 apt/pproxy
s sh -c 'echo 0 > /proc/sys/vm/nr_hugepages' 2>/dev/null || true
s sh -c 'echo 64 > /proc/sys/vm/nr_hugepages' 2>/dev/null \
  || echo "  ✗ 写 nr_hugepages 失败（内核可能未启用 hugetlb 或权限不足）" >&2
GOT=$(cat /proc/sys/vm/nr_hugepages 2>/dev/null || echo 0)
if [[ "$GOT" -lt 16 ]]; then
  echo "  ⚠ nr_hugepages 实际仅 $GOT 个 (2M)；VM RAM 太小，DPDK mempool 可能 ENOMEM" >&2
fi
s mkdir -p /mnt/huge 2>/dev/null || true
s mountpoint -q /mnt/huge || s mount -t hugetlbfs none /mnt/huge 2>/dev/null \
  || echo "  ⚠ /mnt/huge 挂载失败（DPDK 仍会用 --in-memory 启动）" >&2
# QEMU virtio guest 没有 IOMMU；vfio 必须开 unsafe no-iommu 才能绑 PCI 设备
s modprobe vfio enable_unsafe_noiommu_mode=1 2>/dev/null \
  || s sh -c 'echo Y > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode' 2>/dev/null \
  || echo "  ⚠ 无法启用 vfio no-IOMMU 模式（VFIO 绑卡可能失败）" >&2
s modprobe vfio-pci 2>/dev/null \
  || echo "  ⚠ modprobe vfio-pci 失败（容器/受限内核可能不支持）" >&2
echo "  pproxy: dpdk runtime ready on $(hostname)"
EOD
}

# 探测 leaf 上的 WAN devname / WAN MAC / WAN PCI；DPDK 接管前调；输出到调用方 stdout 由调用方 capture
# 格式: "WAN_DEV WAN_MAC PCI_ADDR"
probe_leaf_wan_info() {
  local host=$1
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" bash -s <<'EOI'
set -euo pipefail
MGT_DEV=$(ip -4 route show default 2>/dev/null | head -1 | sed -n 's/.* dev \([^ ]*\).*/\1/p' || true)
SAVED_WAN=$(sed -n 's/^WAN=//p' /run/pproxy-devices.env 2>/dev/null | head -1 || true)
if [[ -n "$SAVED_WAN" && -d "/sys/class/net/$SAVED_WAN" ]]; then
  WAN="$SAVED_WAN"
elif WAN=$(ip -o -4 addr show scope global 2>/dev/null | awk '$4 ~ /^172[.]16[.]/ { print $2; exit }') && [[ -n "$WAN" ]]; then
  :
else
  WAN=""
fi
readarray -t ALL < <(ip -br link | awk '$1 != "lo" { print $1 }' | sort)
DATA=()
for i in "${ALL[@]}"; do
  [[ -n "$MGT_DEV" && "$i" == "$MGT_DEV" ]] && continue
  DATA+=("$i")
done
[[ ${#DATA[@]} -lt 2 && ${#ALL[@]} -ge 3 ]] && DATA=("${ALL[1]}" "${ALL[2]}")
: "${WAN:=${DATA[0]}}"
MAC=$(cat "/sys/class/net/$WAN/address")
# /sys/class/net/<if>/device 对 virtio 来说是 virtio<N>（不是 PCI 地址）；向上走找第一个 PCI 节点
P=$(readlink -f "/sys/class/net/$WAN/device" 2>/dev/null || echo "")
PCI=""
while [[ -n "$P" && "$P" != "/" ]]; do
  B=$(basename "$P")
  if [[ "$B" =~ ^[0-9a-f]{4}:[0-9a-f]{2}:[0-9a-f]{2}\.[0-9a-f]$ ]]; then
    PCI="$B"
    break
  fi
  P=$(dirname "$P")
done
echo "$WAN $MAC $PCI"
EOI
}

# 把 leaf 上指定 PCI 设备从 virtio-net 解绑、绑到 vfio-pci。需先调用 pproxy_dpdk_runtime_setup。
pproxy_dpdk_bind_wan() {
  local host=$1
  local wan_dev=$2
  local pci=$3
  echo "  pproxy: bind ${host}:${wan_dev} (${pci}) → vfio-pci …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$wan_dev" "$pci" <<'EOB'
set -euo pipefail
PASS="$1"; WAN="$2"; PCI="$3"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s ip link set "$WAN" down 2>/dev/null || true
DEVBIND=""
for p in /usr/share/dpdk/usertools/dpdk-devbind.py /usr/bin/dpdk-devbind.py /usr/local/bin/dpdk-devbind.py; do
  [[ -x "$p" || -f "$p" ]] && DEVBIND="$p" && break
done
if [[ -z "$DEVBIND" ]]; then
  echo "  ✗ dpdk-devbind.py 未找到（请确认 apt install dpdk 成功）" >&2
  exit 1
fi
s python3 "$DEVBIND" --bind=vfio-pci "$PCI"
s python3 "$DEVBIND" --status-dev net | head -40
EOB
}

# perf 矩阵切换离开 dpdk 时：尽量把 WAN 还回内核 virtio 驱动
pproxy_dpdk_restore_kernel_wan() {
  local host=$1
  echo "  pproxy: restore kernel WAN on ${host} (if vfio-bound) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$host" <<'EOR'
set -euo pipefail
PASS="$1"
HOST="$2"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s pkill -f '/opt/pproxy/pproxy' 2>/dev/null || true
s pkill -f '/opt/pproxy/pp1.json' 2>/dev/null || true
s pkill -f '/opt/pproxy/pp2.json' 2>/dev/null || true
sleep 0.5
MGT=$(ip -4 route show default 2>/dev/null | head -1 | sed -n 's/.* dev \([^ ]*\).*/\1/p' || true)
DEVBIND=""
for p in /usr/share/dpdk/usertools/dpdk-devbind.py /usr/bin/dpdk-devbind.py /usr/local/bin/dpdk-devbind.py; do
  [[ -x "$p" || -f "$p" ]] && DEVBIND="$p" && break
done
[[ -n "$DEVBIND" ]] || exit 0
mapfile -t VFIO_PCIS < <(s python3 "$DEVBIND" --status-dev net 2>/dev/null | awk '/drv=vfio-pci/ { print $1 }')
[[ ${#VFIO_PCIS[@]} -gt 0 ]] || exit 0
for PCI in "${VFIO_PCIS[@]}"; do
  s timeout 15s python3 "$DEVBIND" --bind=virtio-pci "$PCI" 2>/dev/null \
    || s timeout 15s python3 "$DEVBIND" --bind=virtio_net "$PCI" 2>/dev/null \
    || true
done
WAN=$(sed -n 's/^WAN=//p' /run/pproxy-devices.env 2>/dev/null | head -1 || true)
for _ in $(seq 1 20); do
  [[ -z "$WAN" || -d "/sys/class/net/$WAN" ]] && break
  sleep 0.2
done
if [[ -n "$WAN" && -d "/sys/class/net/$WAN" ]]; then
  s ip link set "$WAN" up 2>/dev/null || true
  echo "  ✓ ${HOST}: WAN ${WAN} (${VFIO_PCIS[*]}) back to kernel driver"
else
  while read -r name _; do
    [[ "$name" == "lo" ]] && continue
    [[ -n "$MGT" && "$name" == "$MGT" ]] && continue
    s ip link set "$name" up 2>/dev/null || true
  done < <(ip -br link | awk '{print $1}')
  echo "  ✓ ${HOST}: vfio net device(s) ${VFIO_PCIS[*]} back to kernel driver"
fi
EOR
}

router_clear_static_arp() {
  echo "  pproxy: router 清除 DPDK 静态 ARP …"
  docker exec router sh -c "ip neigh del 172.16.0.2 dev eth1 2>/dev/null || true; \
    ip neigh del 172.16.1.2 dev eth2 2>/dev/null || true" >/dev/null 2>&1 || true
}

# memif 场景：停 leaf 上 VPP sidecar（切换离开 memif 时调用）
pproxy_vpp_memif_stop() {
  local host=$1
  echo "  pproxy: stopping VPP memif sidecar on ${host} …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" <<'EOV'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s systemctl stop vpp 2>/dev/null || true
s pkill -x vpp_main 2>/dev/null || true
s pkill -f '^vpp -c ' 2>/dev/null || true
sleep 0.3
EOV
}

# memif 场景：起 VPP（memif master + af_packet↔WAN L2 xconnect），供 pproxy slave 连接
pproxy_vpp_memif_setup() {
  local host=$1
  local wan_dev=$2
  echo "  pproxy: VPP memif sidecar on ${host} (WAN=${wan_dev}, socket=${MEMIF_SOCKET_PATH}) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$wan_dev" "$MEMIF_SOCKET_PATH" "$MEMIF_SOCKET_ID" "$MEMIF_INTERFACE_ID" <<'EOV'
set -euo pipefail
PASS="$1"
WAN="$2"
SOCK="$3"
SID="$4"
IFID="$5"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s systemctl stop vpp 2>/dev/null || true
s pkill -x vpp_main 2>/dev/null || true
s pkill -f '^vpp -c ' 2>/dev/null || true
sleep 0.3
s install -d -m 0755 /opt/pproxy/run /opt/pproxy/log /run/vpp /etc/vpp
s rm -f "$SOCK" /run/vpp/cli.sock /run/vpp/api.sock /run/vpp/stats.sock /run/vpp/memif.sock 2>/dev/null || true
cat >/tmp/pproxy-vpp-startup.conf <<VPP
unix {
  log /opt/pproxy/log/vpp.log
  full-coredump
  cli-listen /run/vpp/cli.sock
  gid root
}
api-segment {
  gid root
}
plugins {
  plugin default { disable }
  plugin memif_plugin.so { enable }
  plugin af_packet_plugin.so { enable }
}
memory {
  main-heap-size 256M
  main-heap-page-size 4K
}
statseg {
  size 16M
}
buffers {
  buffers-per-numa 1024
}
cpu {
  main-core 1
}
VPP
s install -m 0644 /tmp/pproxy-vpp-startup.conf /etc/vpp/startup.conf
rm -f /tmp/pproxy-vpp-startup.conf
cat >/tmp/pproxy-vpp-init.cli <<CLI
create memif socket id ${SID} filename ${SOCK}
create interface memif socket-id ${SID} id ${IFID} master
set interface state memif${SID}/${IFID} up
create host-interface name ${WAN}
set interface state host-${WAN} up
set interface l2 xconnect memif${SID}/${IFID} host-${WAN}
set interface l2 xconnect host-${WAN} memif${SID}/${IFID}
CLI
s install -m 0644 /tmp/pproxy-vpp-init.cli /opt/pproxy/vpp-init.cli
rm -f /tmp/pproxy-vpp-init.cli
if ! command -v vpp >/dev/null 2>&1; then
  echo "  ✗ vpp 未安装（apt install vpp vpp-plugin-core）" >&2
  exit 1
fi
s nohup vpp -c /etc/vpp/startup.conf >> /opt/pproxy/log/vpp.log 2>&1 < /dev/null &
for i in $(seq 1 30); do
  if s test -S /run/vpp/cli.sock 2>/dev/null; then
    break
  fi
  sleep 0.2
done
if ! s test -S /run/vpp/cli.sock 2>/dev/null; then
  echo "  ✗ VPP cli.sock 未就绪" >&2
  s tail -n 40 /opt/pproxy/log/vpp.log 2>/dev/null || true
  exit 1
fi
vpp_cli() {
  local cmd="$1"
  if ! s vppctl -s /run/vpp/cli.sock "$cmd"; then
    echo "  ✗ VPP CLI failed: $cmd" >&2
    s tail -n 80 /opt/pproxy/log/vpp.log 2>/dev/null || true
    s vppctl -s /run/vpp/cli.sock show log 2>/dev/null || true
    s vppctl -s /run/vpp/cli.sock show interface 2>/dev/null || true
    exit 1
  fi
}
vpp_cli "create memif socket id ${SID} filename ${SOCK}"
vpp_cli "create interface memif socket-id ${SID} id ${IFID} master"
vpp_cli "set interface state memif${SID}/${IFID} up"
vpp_cli "create host-interface name ${WAN}"
vpp_cli "set interface state host-${WAN} up"
vpp_cli "set interface l2 xconnect memif${SID}/${IFID} host-${WAN}"
vpp_cli "set interface l2 xconnect host-${WAN} memif${SID}/${IFID}"
if ! s test -S "$SOCK" 2>/dev/null; then
  echo "  ✗ memif socket 未创建: $SOCK" >&2
  s vppctl -s /run/vpp/cli.sock show memif 2>/dev/null || true
  s vppctl -s /run/vpp/cli.sock show interface 2>/dev/null || true
  exit 1
fi
iface_out="$(s vppctl -s /run/vpp/cli.sock show interface 2>/dev/null || true)"
grep -q "host-${WAN}" <<< "$iface_out" || {
  echo "  ✗ VPP host interface 未创建: host-${WAN}" >&2
  printf '%s\n' "$iface_out" >&2
  exit 1
}
echo "  ✓ VPP memif ready on $(hostname) (socket=$SOCK)"
EOV
}

# [3.5/5] 按右手 I/O 探测/绑卡（--pproxy-only 与完整 deploy 共用）
deploy_io_backend_prep() {
  if [[ "$DEPLOY_IO_RIGHT" != "dpdk" ]]; then
    pproxy_dpdk_restore_kernel_wan "$LEAF1_HOST"
    pproxy_dpdk_restore_kernel_wan "$LEAF2_HOST"
    router_clear_static_arp
  fi
  if [[ "$DEPLOY_IO_RIGHT" != "memif" ]]; then
    pproxy_vpp_memif_stop "$LEAF1_HOST"
    pproxy_vpp_memif_stop "$LEAF2_HOST"
  fi

  if [[ "$DEPLOY_IO_RIGHT" == "dpdk" ]]; then
    echo ""
    echo "=== [3.5/5] DPDK: probe → runtime → bind vfio-pci → router static ARP ==="
    read -r LEAF1_WAN_DEV DPDK_LEAF1_WAN_MAC DPDK_LEAF1_PCI < <(probe_leaf_wan_info "$LEAF1_HOST")
    read -r LEAF2_WAN_DEV DPDK_LEAF2_WAN_MAC DPDK_LEAF2_PCI < <(probe_leaf_wan_info "$LEAF2_HOST")
    echo "  leaf1: WAN=${LEAF1_WAN_DEV} MAC=${DPDK_LEAF1_WAN_MAC} PCI=${DPDK_LEAF1_PCI}"
    echo "  leaf2: WAN=${LEAF2_WAN_DEV} MAC=${DPDK_LEAF2_WAN_MAC} PCI=${DPDK_LEAF2_PCI}"
    if [[ -z "$DPDK_LEAF1_PCI" || -z "$DPDK_LEAF2_PCI" ]]; then
      echo "  ✗ probe 未拿到 PCI 地址（leaf 上 /sys/class/net/<wan>/device readlink 失败？）" >&2
      exit 1
    fi
    DPDK_LEAF1_PEER_MAC=$(router_iface_mac eth1)
    DPDK_LEAF2_PEER_MAC=$(router_iface_mac eth2)
    echo "  router: eth1 MAC=${DPDK_LEAF1_PEER_MAC} (leaf1 next-hop); eth2 MAC=${DPDK_LEAF2_PEER_MAC} (leaf2 next-hop)"
    if [[ -z "$DPDK_LEAF1_PEER_MAC" || -z "$DPDK_LEAF2_PEER_MAC" ]]; then
      echo "  ✗ 取 router eth1/eth2 MAC 失败" >&2
      exit 1
    fi
    pproxy_apt_deps "$LEAF1_HOST" 1 0
    pproxy_apt_deps "$LEAF2_HOST" 1 0
    pproxy_dpdk_runtime_setup "$LEAF1_HOST"
    pproxy_dpdk_runtime_setup "$LEAF2_HOST"
    pproxy_dpdk_bind_wan "$LEAF1_HOST" "$LEAF1_WAN_DEV" "$DPDK_LEAF1_PCI"
    pproxy_dpdk_bind_wan "$LEAF2_HOST" "$LEAF2_WAN_DEV" "$DPDK_LEAF2_PCI"
    router_set_static_arp "172.16.0.2" "$DPDK_LEAF1_WAN_MAC" \
                          "172.16.1.2" "$DPDK_LEAF2_WAN_MAC"
    export DPDK_LEAF1_PCI DPDK_LEAF2_PCI DPDK_LEAF1_PEER_MAC DPDK_LEAF2_PEER_MAC
  elif [[ "$DEPLOY_IO_RIGHT" == "netmap" ]]; then
    echo ""
    echo "=== [3.5/5] netmap: probe WAN ifname for io_cfg ==="
    read -r LEAF1_WAN_DEV _ _ < <(probe_leaf_wan_info "$LEAF1_HOST")
    read -r LEAF2_WAN_DEV _ _ < <(probe_leaf_wan_info "$LEAF2_HOST")
    echo "  leaf1: WAN=${LEAF1_WAN_DEV}"
    echo "  leaf2: WAN=${LEAF2_WAN_DEV}"
    if [[ -z "$LEAF1_WAN_DEV" || -z "$LEAF2_WAN_DEV" ]]; then
      echo "  ✗ probe 未拿到 WAN 网卡名" >&2
      exit 1
    fi
    export LEAF1_WAN_DEV LEAF2_WAN_DEV
  elif [[ "$DEPLOY_IO_RIGHT" == "memif" ]]; then
    echo ""
    echo "=== [3.5/5] memif: probe WAN + router next-hop MAC ==="
    read -r LEAF1_WAN_DEV _ _ < <(probe_leaf_wan_info "$LEAF1_HOST")
    read -r LEAF2_WAN_DEV _ _ < <(probe_leaf_wan_info "$LEAF2_HOST")
    echo "  leaf1: WAN=${LEAF1_WAN_DEV}"
    echo "  leaf2: WAN=${LEAF2_WAN_DEV}"
    if [[ -z "$LEAF1_WAN_DEV" || -z "$LEAF2_WAN_DEV" ]]; then
      echo "  ✗ probe 未拿到 WAN 网卡名" >&2
      exit 1
    fi
    MEMIF_LEAF1_PEER_MAC=$(router_iface_mac eth1)
    MEMIF_LEAF2_PEER_MAC=$(router_iface_mac eth2)
    echo "  router: eth1 MAC=${MEMIF_LEAF1_PEER_MAC}; eth2 MAC=${MEMIF_LEAF2_PEER_MAC}"
    if [[ -z "$MEMIF_LEAF1_PEER_MAC" || -z "$MEMIF_LEAF2_PEER_MAC" ]]; then
      echo "  ✗ 取 router eth1/eth2 MAC 失败" >&2
      exit 1
    fi
    export LEAF1_WAN_DEV LEAF2_WAN_DEV MEMIF_LEAF1_PEER_MAC MEMIF_LEAF2_PEER_MAC
  elif [[ "${DEPLOY_KS_BACKEND:-syscall}" == "io_uring" ]]; then
    echo ""
    echo "=== [3.5/5] io_uring: probe WAN ifname for io_cfg.ifname (SO_BINDTODEVICE) ==="
    read -r LEAF1_WAN_DEV _ _ < <(probe_leaf_wan_info "$LEAF1_HOST")
    read -r LEAF2_WAN_DEV _ _ < <(probe_leaf_wan_info "$LEAF2_HOST")
    echo "  leaf1: WAN=${LEAF1_WAN_DEV}"
    echo "  leaf2: WAN=${LEAF2_WAN_DEV}"
    if [[ -z "$LEAF1_WAN_DEV" || -z "$LEAF2_WAN_DEV" ]]; then
      echo "  ✗ probe 未拿到 WAN 网卡名" >&2
      exit 1
    fi
    export LEAF1_WAN_DEV LEAF2_WAN_DEV
  fi
}

# router 容器写两条静态 ARP：leaf{1,2} 的 WAN IP → 各自 WAN MAC（DPDK 接管后内核 ARP 学不到）
# 同时返回 router 在 eth1/eth2 上的 MAC，给 leaf 侧 pproxy 配 peer_mac
router_set_static_arp() {
  local leaf1_ip=$1
  local leaf1_mac=$2
  local leaf2_ip=$3
  local leaf2_mac=$4
  echo "  pproxy: router 静态 ARP: ${leaf1_ip}→${leaf1_mac} (eth1), ${leaf2_ip}→${leaf2_mac} (eth2) …"
  docker exec router sh -c "ip neigh replace ${leaf1_ip} lladdr ${leaf1_mac} nud permanent dev eth1 \
                         && ip neigh replace ${leaf2_ip} lladdr ${leaf2_mac} nud permanent dev eth2" >/dev/null
}

# 取 router 容器内 eth1/eth2 的 MAC，作为 leaf1/leaf2 pproxy 的 peer_mac（next-hop）
router_iface_mac() {
  local ifname=$1
  docker exec router cat "/sys/class/net/${ifname}/address"
}

# netmap 内核模块 commit（与 third_party/netmap/ vendored 头、build-netmap-ko.sh 一致）
NETMAP_MODULE_SHA="10986ec1479b54552333d4cef913bef3dd159727"

# 读 leaf VM 内核版本（generic_vm 上 uname -r）
pproxy_leaf_kernel_release() {
  local host=$1
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" "uname -r"
}

# 宿主机 Docker 编译 netmap.ko（按 kver 缓存）；结果写入 NETMAP_KO_BUILT
pproxy_build_netmap_ko_host() {
  local kver=$1
  if [[ -n "${PPROXY_NETMAP_KO:-}" && -f "$PPROXY_NETMAP_KO" ]]; then
    NETMAP_KO_BUILT=$PPROXY_NETMAP_KO
    echo "  pproxy: 使用 PPROXY_NETMAP_KO=${NETMAP_KO_BUILT}"
    return 0
  fi
  local ko="${CLAB_DIR}/.cache/netmap/${kver}/netmap.ko"
  if [[ ! -x "${CLAB_DIR}/build-netmap-ko.sh" ]]; then
    echo "  ✗ 缺少 ${CLAB_DIR}/build-netmap-ko.sh" >&2
    exit 1
  fi
  NETMAP_MODULE_SHA="$NETMAP_MODULE_SHA" "${CLAB_DIR}/build-netmap-ko.sh" "$kver"
  if [[ ! -f "$ko" ]]; then
    echo "  ✗ netmap.ko 未生成: $ko" >&2
    exit 1
  fi
  NETMAP_KO_BUILT=$ko
}

# 把宿主机编好的 netmap.ko 装到单台 leaf 并 modprobe（不在 leaf 上编译）
pproxy_install_netmap_on_leaf() {
  local host=$1
  local ko="${NETMAP_KO_BUILT:?netmap.ko 未构建}"
  echo "  pproxy: install netmap.ko on ${host} (from ${ko}) …"
  if sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    "lsmod 2>/dev/null | grep -q '^netmap\b' && test -e /dev/netmap"; then
    echo "  ✓ ${host}: netmap module already loaded; /dev/netmap present"
    return 0
  fi
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$ko" \
    "${UBUNTU_USER}@${host}:/tmp/netmap.ko"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" <<'EON'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
KREL="$(uname -r)"
MOD="/lib/modules/${KREL}/extra/netmap.ko"
s install -d "/lib/modules/${KREL}/extra"
s install -m 644 /tmp/netmap.ko "$MOD"
rm -f /tmp/netmap.ko
s depmod -a
s modprobe netmap
ls -l /dev/netmap
lsmod | grep '^netmap\b' || { echo "  ✗ netmap not in lsmod" >&2; exit 1; }
echo "  ✓ netmap kernel module loaded on $(hostname)"
EON
}

# 左右手任一为 netmap：宿主机 docker 编一次 ko，再分发到各 leaf
pproxy_install_netmap() {
  local k1 k2
  k1=$(pproxy_leaf_kernel_release "$LEAF1_HOST")
  k2=$(pproxy_leaf_kernel_release "$LEAF2_HOST")
  echo "  pproxy: leaf kernel: ${LEAF1_HOST}=${k1}  ${LEAF2_HOST}=${k2}"
  if [[ "$k1" != "$k2" ]]; then
    echo "  ⚠ leaf1/leaf2 内核版本不同（${k1} vs ${k2}）；按 ${LEAF1_HOST}=${k1} 编译 netmap.ko" >&2
    echo "     若 ${LEAF2_HOST} 加载失败，请对 ${k2} 再跑 build-netmap-ko.sh 或设 PPROXY_NETMAP_KO=" >&2
  fi
  pproxy_build_netmap_ko_host "$k1"
  pproxy_install_netmap_on_leaf "$LEAF1_HOST"
  pproxy_install_netmap_on_leaf "$LEAF2_HOST"
}

pproxy_remote_prepare() {
  local host=$1
  echo "  pproxy: mkdir $VM_PPROXY_ROOT on ${host} …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" bash -s -- "$UBUNTU_PASS" "$UBUNTU_USER" <<'EOP'
set -euo pipefail
PASS="$1"
U="$2"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s install -d -m 0755 -o "$U" -g "$U" -- /opt/pproxy /opt/pproxy/log /opt/pproxy/run
EOP
}

pproxy_coredump_setup() {
  local host=$1
  [[ "$PPROXY_COREDUMP" == "1" ]] || return 0
  echo "  pproxy: coredump → ${VM_PPROXY_ROOT}/core-* (kernel.core_pattern + 启动时 ulimit) on ${host} …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$VM_PPROXY_ROOT" <<'EOC'
set -euo pipefail
PASS="$1" ROOT="$2"
PATTERN="${ROOT}/core-%e-%p-%t"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s install -d -m 0755 "$ROOT" 2>/dev/null || true
if ! s sysctl -w "kernel.core_pattern=$PATTERN" 2>/dev/null; then
  s sh -c 'printf "%s" "$1" > /proc/sys/kernel/core_pattern' sh "$PATTERN"
fi
EOC
}

pproxy_scp_bin() {
  local host=$1
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$PPROXY_BIN" "${UBUNTU_USER}@${host}:${VM_PPROXY_BIN}"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" "chmod 755 ${VM_PPROXY_BIN}"
}

pproxy_scp_memif_support() {
  local host=$1
  local src="${REPO_ROOT}/scripts/install_libmemif.sh"
  [[ -f "$src" ]] || { echo "  ✗ 缺少 $src" >&2; return 1; }
  echo "  pproxy: scp install_libmemif.sh → ${host}:/opt/pproxy/ …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$src" \
    "${UBUNTU_USER}@${host}:/tmp/install_libmemif.sh"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" <<'EOM'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s install -d -m 0755 /opt/pproxy
s install -m 0755 /tmp/install_libmemif.sh /opt/pproxy/install_libmemif.sh
rm -f /tmp/install_libmemif.sh
EOM
}

pproxy_scp_xdpcap_bpf() {
  local host=$1
  local src=$2
  echo "  pproxy: scp xsk_xdpcap eBPF ${src} → ${host}:${VM_PPROXY_XDPCAP_BPF} …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$src" \
    "${UBUNTU_USER}@${host}:${VM_PPROXY_XDPCAP_BPF}"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    "chmod 644 ${VM_PPROXY_XDPCAP_BPF}"
}

# mgmt 文本命令客户端；与 leaf-bin/xdpcap 同目录
pproxy_scp_pproxy_ctl() {
  local host=$1
  local src="${CLAB_DIR}/leaf-bin/pproxy-ctl"
  if [[ ! -s "$src" ]]; then
    echo "  pproxy: 无 $src（或为空），跳过 pproxy-ctl" >&2
    return 0
  fi
  echo "  pproxy: scp leaf-bin/pproxy-ctl → ${host}:/usr/local/bin/pproxy-ctl …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$src" \
    "${UBUNTU_USER}@${host}:/tmp/pproxy-ctl"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" <<'EOP'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s install -m 0755 /tmp/pproxy-ctl /usr/local/bin/pproxy-ctl
rm -f /tmp/pproxy-ctl
EOP
}

# cloudflare 用户态 xdpcap；与仓库中 leaf-bin 同目录，勿与 pproxy 加载的 eBPF 混淆
pproxy_scp_xdpcap() {
  local host=$1
  local src="${CLAB_DIR}/leaf-bin/xdpcap"
  if [[ ! -f "$src" ]]; then
    echo "  pproxy: 无 $src，跳过用户态 xdpcap" >&2
    return 0
  fi
  echo "  pproxy: scp leaf-bin/xdpcap → ${host}:${VM_XDPCAP_BIN} …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$src" \
    "${UBUNTU_USER}@${host}:/tmp/pproxy-xdpcap"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$VM_XDPCAP_BIN" <<'EOD'
set -euo pipefail
PASS="$1"
DST="$2"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s install -m 0755 /tmp/pproxy-xdpcap "$DST"
rm -f /tmp/pproxy-xdpcap
EOD
}

# DPDK：基于 pp{1,2}.udp.left-tun.right-dpdk.json 模板渲染：填入 PCI / peer_mac / 显式 bind/listen
# 输出: dst 路径覆盖写入
dpdk_render_cfg() {
  local src=$1
  local dst=$2
  local pci=$3
  local peer_mac=$4
  local local_ep=$5
  python3 - "$src" "$dst" "$pci" "$peer_mac" "$local_ep" <<'PY'
import json, sys
src, dst, pci, mac, local_ep = sys.argv[1:6]
with open(src, encoding='utf-8') as f:
    d = json.load(f)
t = d['tunnels'][0]
io = t.setdefault('io_cfg', {})
io['eal_args'] = f"pproxy -l 0,1 -a {pci} --proc-type=primary --in-memory"
io['peer_mac'] = mac
if local_ep:
    if t.get('mode', 'client') == 'server':
        t['listen'] = local_ep
    else:
        t['bind'] = local_ep
with open(dst, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2)
PY
}

# netmap：io_cfg.ifname=netmap:<WAN dev>；client 显式 bind WAN IP（与 dpdk_render_cfg 一致）
netmap_render_cfg() {
  local src=$1
  local dst=$2
  local wan_dev=$3
  local local_ep=${4:-}
  python3 - "$src" "$dst" "$wan_dev" "$local_ep" <<'PY'
import json, sys
src, dst, wan, local_ep = sys.argv[1:5]
with open(src, encoding='utf-8') as f:
    d = json.load(f)
t = d['tunnels'][0]
io = t.setdefault('io_cfg', {})
io['ifname'] = f'netmap:{wan}'
if local_ep:
    if t.get('mode', 'client') == 'server':
        t['listen'] = local_ep
    else:
        t['bind'] = local_ep
with open(dst, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2)
PY
}

# memif：注入 socket_path / peer_mac / listen|bind
memif_render_cfg() {
  local src=$1
  local dst=$2
  local socket_path=$3
  local peer_mac=$4
  local local_ep=${5:-}
  python3 - "$src" "$dst" "$socket_path" "$peer_mac" "$local_ep" <<'PY'
import json, sys
src, dst, sock, mac, local_ep = sys.argv[1:6]
with open(src, encoding='utf-8') as f:
    d = json.load(f)
t = d['tunnels'][0]
io = t.setdefault('io_cfg', {})
io['socket_path'] = sock
io['interface_id'] = io.get('interface_id', 0)
io['is_master'] = False
io['peer_mac'] = mac
if local_ep:
    if t.get('mode', 'client') == 'server':
        t['listen'] = local_ep
    else:
        t['bind'] = local_ep
with open(dst, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2)
PY
}

# io_uring：io 仍为 kernel_socket；注入 backend/ifname/listen|bind；可选 tx_zc
# 第 6 参 tx_zc：空=沿用模板；1=强制 zerocopy；0=强制关闭
uring_render_cfg() {
  local src=$1
  local dst=$2
  local wan_dev=$3
  local local_ep=${4:-}
  local sq_entries=${5:-256}
  local tx_zc=${6:-}
  python3 - "$src" "$dst" "$wan_dev" "$local_ep" "$sq_entries" "$tx_zc" <<'PY'
import json, sys
src, dst, wan, local_ep, sq, tx_zc = sys.argv[1:7]
with open(src, encoding='utf-8') as f:
    d = json.load(f)
t = d['tunnels'][0]
io = t.setdefault('io_cfg', {})
io['backend'] = 'io_uring'
io['sq_entries'] = int(sq)
if wan:
    io['ifname'] = wan
if tx_zc == '1':
    io['zerocopy'] = True
    io['tx_zc'] = True
elif tx_zc == '0':
    io['zerocopy'] = False
    io['tx_zc'] = False
if local_ep:
    if t.get('mode', 'client') == 'server':
        t['listen'] = local_ep
    else:
        t['bind'] = local_ep
with open(dst, 'w', encoding='utf-8') as f:
    json.dump(d, f, indent=2)
PY
}

pproxy_push_cfgs() {
  if [[ ! -f "$PP1_JSON" ]] || [[ ! -f "$PP2_JSON" ]]; then
    echo "  ✗ 缺少配置: $PP1_JSON 或 $PP2_JSON" >&2
    exit 1
  fi
  if [[ ! -s "$PP1_JSON" || ! -s "$PP2_JSON" ]]; then
    echo "  ✗ 配置 JSON 不能为空: $PP1_JSON / $PP2_JSON" >&2
    exit 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; [json.load(open(f,encoding='utf-8')) for f in sys.argv[1:]]" \
      "$PP1_JSON" "$PP2_JSON" || { echo "  ✗ JSON 校验失败: $PP1_JSON / $PP2_JSON" >&2; exit 1; }
    python3 - "$PP1_JSON" "$PP2_JSON" "$DEPLOY_IO_RIGHT" <<'PY' || {
import json, sys
want = sys.argv[3]
for path in sys.argv[1:3]:
    t = json.load(open(path, encoding='utf-8'))['tunnels'][0]
    got = t.get('io', '')
    if got != want:
        print(f"  ✗ {path}: tunnels[0].io={got!r} 与 --right-io={want!r} 不一致", file=sys.stderr)
        sys.exit(1)
PY
      echo "  ✗ 配置 io 与 --right-io 不匹配（勿用回退 JSON 冒充 dpdk/netmap 等）" >&2
      exit 1
    }
  fi

  local pp1_src=$PP1_JSON
  local pp2_src=$PP2_JSON
  # right=dpdk: 渲染一份带 PCI/peer_mac/显式 listen 的 JSON 到 /tmp 再 scp。
  # 依赖全局: DPDK_LEAF1_PCI, DPDK_LEAF2_PCI, DPDK_LEAF1_PEER_MAC, DPDK_LEAF2_PEER_MAC
  if [[ "$DEPLOY_IO_RIGHT" == "dpdk" ]]; then
    : "${DPDK_LEAF1_PCI:?dpdk push: DPDK_LEAF1_PCI 未设置 (probe 漏了?)}"
    : "${DPDK_LEAF2_PCI:?dpdk push: DPDK_LEAF2_PCI 未设置}"
    : "${DPDK_LEAF1_PEER_MAC:?dpdk push: DPDK_LEAF1_PEER_MAC 未设置}"
    : "${DPDK_LEAF2_PEER_MAC:?dpdk push: DPDK_LEAF2_PEER_MAC 未设置}"
    local tmp1=$(mktemp --suffix=.json)
    local tmp2=$(mktemp --suffix=.json)
    dpdk_render_cfg "$PP1_JSON" "$tmp1" "$DPDK_LEAF1_PCI" "$DPDK_LEAF1_PEER_MAC" "${LEAF1_WAN_IP}:${TUNNEL_PORT}"
    # leaf2 client: bind 显式给 leaf2 WAN IP；端口 0 让 pproxy 随机源端口
    dpdk_render_cfg "$PP2_JSON" "$tmp2" "$DPDK_LEAF2_PCI" "$DPDK_LEAF2_PEER_MAC" "${LEAF2_WAN_IP}:0"
    pp1_src=$tmp1
    pp2_src=$tmp2
    echo "  pproxy: DPDK 渲染后 pp1: $(cat "$tmp1" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; print(t.get("listen"), t["io_cfg"]["eal_args"], t["io_cfg"]["peer_mac"])')"
    echo "  pproxy: DPDK 渲染后 pp2: $(cat "$tmp2" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; print(t.get("bind"), t["io_cfg"]["eal_args"], t["io_cfg"]["peer_mac"])')"
  elif [[ "$DEPLOY_IO_RIGHT" == "netmap" ]]; then
    : "${LEAF1_WAN_DEV:?netmap push: LEAF1_WAN_DEV 未设置 (先跑 [3.5/5] probe?)}"
    : "${LEAF2_WAN_DEV:?netmap push: LEAF2_WAN_DEV 未设置}"
    local tmp1=$(mktemp --suffix=.json)
    local tmp2=$(mktemp --suffix=.json)
    netmap_render_cfg "$PP1_JSON" "$tmp1" "$LEAF1_WAN_DEV" "${LEAF1_WAN_IP}:${TUNNEL_PORT}"
    netmap_render_cfg "$PP2_JSON" "$tmp2" "$LEAF2_WAN_DEV" "${LEAF2_WAN_IP}:0"
    pp1_src=$tmp1
    pp2_src=$tmp2
    echo "  pproxy: netmap 渲染后 pp1: $(cat "$tmp1" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; print(t.get("io"), t["io_cfg"]["ifname"])')"
    echo "  pproxy: netmap 渲染后 pp2: $(cat "$tmp2" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; print(t.get("io"), t.get("bind"), t["io_cfg"]["ifname"])')"
  elif [[ "$DEPLOY_IO_RIGHT" == "memif" ]]; then
    : "${MEMIF_LEAF1_PEER_MAC:?memif push: MEMIF_LEAF1_PEER_MAC 未设置 (先跑 [3.5/5] probe?)}"
    : "${MEMIF_LEAF2_PEER_MAC:?memif push: MEMIF_LEAF2_PEER_MAC 未设置}"
    local tmp1=$(mktemp --suffix=.json)
    local tmp2=$(mktemp --suffix=.json)
    memif_render_cfg "$PP1_JSON" "$tmp1" "$MEMIF_SOCKET_PATH" "$MEMIF_LEAF1_PEER_MAC" "${LEAF1_WAN_IP}:${TUNNEL_PORT}"
    memif_render_cfg "$PP2_JSON" "$tmp2" "$MEMIF_SOCKET_PATH" "$MEMIF_LEAF2_PEER_MAC" "${LEAF2_WAN_IP}:0"
    pp1_src=$tmp1
    pp2_src=$tmp2
    echo "  pproxy: memif 渲染后 pp1: $(cat "$tmp1" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; ic=t["io_cfg"]; print(t.get("listen"), ic.get("socket_path"), ic.get("peer_mac"))')"
    echo "  pproxy: memif 渲染后 pp2: $(cat "$tmp2" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; ic=t["io_cfg"]; print(t.get("bind"), ic.get("socket_path"), ic.get("peer_mac"))')"
  elif [[ "${DEPLOY_KS_BACKEND:-syscall}" == "io_uring" ]]; then
    : "${LEAF1_WAN_DEV:?io_uring push: LEAF1_WAN_DEV 未设置 (先跑 [3.5/5] probe?)}"
    : "${LEAF2_WAN_DEV:?io_uring push: LEAF2_WAN_DEV 未设置}"
    local tmp1=$(mktemp --suffix=.json)
    local tmp2=$(mktemp --suffix=.json)
    uring_render_cfg "$PP1_JSON" "$tmp1" "$LEAF1_WAN_DEV" "${LEAF1_WAN_IP}:${TUNNEL_PORT}" 256 "${DEPLOY_IO_URING_ZC:-}"
    uring_render_cfg "$PP2_JSON" "$tmp2" "$LEAF2_WAN_DEV" "${LEAF2_WAN_IP}:0" 256 "${DEPLOY_IO_URING_ZC:-}"
    pp1_src=$tmp1
    pp2_src=$tmp2
    echo "  pproxy: io_uring 渲染后 pp1: $(cat "$tmp1" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; ic=t.get("io_cfg",{}); print(t.get("listen"), ic.get("backend"), ic.get("ifname"), "tx_zc="+str(ic.get("tx_zc", ic.get("zerocopy"))))')"
    echo "  pproxy: io_uring 渲染后 pp2: $(cat "$tmp2" | python3 -c 'import sys,json; d=json.load(sys.stdin); t=d["tunnels"][0]; ic=t.get("io_cfg",{}); print(t.get("bind"), ic.get("backend"), ic.get("ifname"), "tx_zc="+str(ic.get("tx_zc", ic.get("zerocopy"))))')"
  fi

  echo "  pproxy: scp 配置 $pp1_src → ${LEAF1_HOST}:${VM_PP1_CFG} …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$pp1_src" \
    "${UBUNTU_USER}@${LEAF1_HOST}:${VM_PP1_CFG}"
  echo "  pproxy: scp 配置 $pp2_src → ${LEAF2_HOST}:${VM_PP2_CFG} …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$pp2_src" \
    "${UBUNTU_USER}@${LEAF2_HOST}:${VM_PP2_CFG}"

  if [[ "$DEPLOY_IO_RIGHT" == "dpdk" || "$DEPLOY_IO_RIGHT" == "netmap" || "$DEPLOY_IO_RIGHT" == "memif" || "${DEPLOY_KS_BACKEND:-syscall}" == "io_uring" ]]; then
    rm -f "${pp1_src}" "${pp2_src}"
  fi
}

pproxy_stop_leaf() {
  local host=$1 cfg=$2
  echo "  pproxy: stopping on ${host} (${cfg}) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$cfg" <<'EOST'
set -euo pipefail
PASS="$1"
CFG="$2"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s sh -c 'pgrep -f "[/]opt/pproxy/pproxy -c $1" 2>/dev/null | xargs -r kill 2>/dev/null || true' sh "$CFG"
sleep 0.5
EOST
}

pproxy_start() {
  local host=$1 bin=$2 cfg=$3 log=$4
  local gdbport="${5:-0}"
  local xdpcap_on="${6:-0}"
  local xdpcap_bpf_vm="${7:-}"
  local cd_on="${PPROXY_COREDUMP:-1}"
  if [[ "$gdbport" != "0" ]]; then
    echo "  pproxy: starting on ${host} (gdbserver 127.0.0.1:${gdbport} $bin -c $cfg) …"
  else
    echo "  pproxy: starting on ${host} ($bin -c $cfg) …"
  fi
  if [[ "$xdpcap_on" == "1" ]]; then
    echo "    (env: PPROXY_XDPCAP_BPF=$xdpcap_bpf_vm)"
  fi
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$bin" "$cfg" "$log" "$cd_on" "$gdbport" "$xdpcap_on" "$xdpcap_bpf_vm" <<'EOS'
set -euo pipefail
PASS="$1"
BIN="$2"
CFG="$3"
LOG="$4"
CD="$5"
GDBPORT="${6:-0}"
XDPON="${7:-0}"
XDPBF="${8:-}"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s sh -c 'pgrep -f "[/]opt/pproxy/pproxy -c $1" 2>/dev/null | xargs -r kill 2>/dev/null || true' sh "$CFG"
if [[ "$GDBPORT" != "0" ]]; then
  s sh -c 'pgrep -f "[g]dbserver 127.0.0.1:$1" 2>/dev/null | xargs -r kill 2>/dev/null || true' sh "$GDBPORT"
fi
sleep 0.5
# TUN 需 root；标准输出/错入日志（见 /opt/pproxy/log/）
s install -d -m 0755 "$(dirname "$LOG")" 2>/dev/null || true
if [[ "$XDPON" == "1" && -n "$XDPBF" ]]; then
  if [[ "$GDBPORT" != "0" ]]; then
    if [[ "$CD" == "1" ]]; then
      s sh -c "ulimit -c unlimited; nohup env PPROXY_XDPCAP_BPF=\"$XDPBF\" gdbserver 127.0.0.1:${GDBPORT} $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    else
      s sh -c "nohup env PPROXY_XDPCAP_BPF=\"$XDPBF\" gdbserver 127.0.0.1:${GDBPORT} $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    fi
  else
    if [[ "$CD" == "1" ]]; then
      s sh -c "ulimit -c unlimited; nohup env PPROXY_XDPCAP_BPF=\"$XDPBF\" $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    else
      s sh -c "nohup env PPROXY_XDPCAP_BPF=\"$XDPBF\" $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    fi
  fi
else
  if [[ "$GDBPORT" != "0" ]]; then
    if [[ "$CD" == "1" ]]; then
      s sh -c "ulimit -c unlimited; nohup gdbserver 127.0.0.1:${GDBPORT} $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    else
      s sh -c "nohup gdbserver 127.0.0.1:${GDBPORT} $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    fi
  else
    if [[ "$CD" == "1" ]]; then
      s sh -c "ulimit -c unlimited; nohup $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    else
      s sh -c "nohup $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
    fi
  fi
fi
sleep 0.5
# nohup 以 root 写日志；放宽权限便于 clab 用户 tail
s chmod 0644 "$LOG" 2>/dev/null || true
sleep 0.3
EOS
}

wait_vm_http() {
  local host=$1
  local port=$2
  local label=$3
  local n=0
  while [ "$n" -lt 60 ]; do
    if sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
      "curl -sf -m2 http://127.0.0.1:${port}/metrics" 2>/dev/null | head -1 | grep -q .; then
      echo "  ✓ ${label} metrics up (port ${port})"
      return 0
    fi
    n=$((n + 1))
    sleep 1
  done
  echo "  ✗ ${label} metrics not ready" >&2
  return 1
}

pproxy_smoke() {
  echo ""
  echo "=== [4/5] pproxy: binary, configs, start, smoke test ==="
  if [[ ! -x "$PPROXY_BIN" ]]; then
    echo "  ✗ 未找到可执行文件: $PPROXY_BIN" >&2
    echo "     在仓库根执行: ./build.sh --xdp --pcap，或勿设 PPROXY_SKIP_BUILD=1 后重跑本脚本" >&2
    exit 1
  fi
  local USE_XDPCAP=0
  local WANT_AF_XDP=0
  local PPROXY_XDPCAP_BPF_HOST="${PPROXY_XDPCAP_BPF:-$REPO_ROOT/build/xsk_xdpcap.bpf.o}"
  if pproxy_json_uses_af_xdp; then
    WANT_AF_XDP=1
  fi
  if [[ "$WANT_AF_XDP" -eq 1 && -f "$PPROXY_XDPCAP_BPF_HOST" ]]; then
    USE_XDPCAP=1
    echo "  pproxy: 含 af_xdp 且已找到 $PPROXY_XDPCAP_BPF_HOST → 额外部署 xsk_xdpcap eBPF 与（若有）leaf-bin/xdpcap"
  elif [[ "$WANT_AF_XDP" -eq 1 ]]; then
    echo "  ⚠ 含 af_xdp 但未找到 $PPROXY_XDPCAP_BPF_HOST，跳过 xsk_xdpcap/用户态 xdpcap（pproxy 仍走 libxdp 默认 XDP）" >&2
    echo "     需要 xdpcap 抓包 hook 时自编译 .o 并设 PPROXY_XDPCAP_BPF=… 或放入 build/xsk_xdpcap.bpf.o" >&2
  fi
  echo "  Using: $PPROXY_BIN"
  echo "  Tunnel: $TUNNEL_MODE  I/O: left=${DEPLOY_IO_LEFT}  right=${DEPLOY_IO_RIGHT}  ks_backend=${DEPLOY_KS_BACKEND:-syscall}  io_uring_zc=${DEPLOY_IO_URING_ZC:-template}"
  echo "  Config: $PP1_JSON + $PP2_JSON"

  local NEED_DPDK=0
  local NEED_IO_URING=0
  local NEED_MEMIF=0
  if [[ "$MATRIX_PREP" -eq 1 ]]; then
    NEED_DPDK=1
    NEED_IO_URING=1
    NEED_MEMIF=1
  else
    if [[ "$DEPLOY_IO_LEFT" == "dpdk" || "$DEPLOY_IO_RIGHT" == "dpdk" ]]; then
      NEED_DPDK=1
    fi
    if [[ "$DEPLOY_IO_LEFT" == "memif" || "$DEPLOY_IO_RIGHT" == "memif" ]]; then
      NEED_MEMIF=1
    fi
    if [[ "${DEPLOY_KS_BACKEND:-syscall}" == "io_uring" ]]; then
      NEED_IO_URING=1
    fi
    # 全后端 build/pproxy 动态链接 liburing；非 matrix 单场景 deploy 也要装
    if [[ "$PPROXY_ONLY" -eq 0 ]]; then
      NEED_IO_URING=1
    fi
  fi
  pproxy_apt_deps "$LEAF1_HOST" "$NEED_DPDK" "$NEED_IO_URING" "$NEED_MEMIF"
  pproxy_apt_deps "$LEAF2_HOST" "$NEED_DPDK" "$NEED_IO_URING" "$NEED_MEMIF"
  if [[ "$NEED_MEMIF" -eq 1 ]]; then
    pproxy_scp_memif_support "$LEAF1_HOST"
    pproxy_scp_memif_support "$LEAF2_HOST"
    pproxy_apt_deps "$LEAF1_HOST" 0 0 1
    pproxy_apt_deps "$LEAF2_HOST" 0 0 1
  fi
  if [[ "$MATRIX_PREP" -eq 1 || "$DEPLOY_IO_LEFT" == "netmap" || "$DEPLOY_IO_RIGHT" == "netmap" ]]; then
    pproxy_install_netmap
  fi
  if [[ "$PPROXY_ONLY" -eq 0 ]]; then
    pproxy_remote_prepare "$LEAF1_HOST"
    pproxy_remote_prepare "$LEAF2_HOST"
    pproxy_coredump_setup "$LEAF1_HOST"
    pproxy_coredump_setup "$LEAF2_HOST"
  else
    echo "  (--pproxy-only: skip binary/ctl scp and remote prepare)"
  fi
  if [[ "$NEED_DPDK" -eq 1 ]]; then
    pproxy_dpdk_runtime_setup "$LEAF1_HOST"
    pproxy_dpdk_runtime_setup "$LEAF2_HOST"
  fi
  if [[ "$PPROXY_ONLY" -eq 0 ]]; then
    pproxy_scp_bin "$LEAF1_HOST"
    pproxy_scp_bin "$LEAF2_HOST"
    pproxy_scp_pproxy_ctl "$LEAF1_HOST"
    pproxy_scp_pproxy_ctl "$LEAF2_HOST"
    if [[ "$USE_XDPCAP" -eq 1 ]]; then
      pproxy_scp_xdpcap "$LEAF1_HOST"
      pproxy_scp_xdpcap "$LEAF2_HOST"
    fi
  fi
  # af_xdp 必须加载自编译 xsk_xdpcap.bpf.o（含隧道 filter）；--pproxy-only 切换后端时也要 scp
  if [[ "$USE_XDPCAP" -eq 1 ]]; then
    pproxy_scp_xdpcap_bpf "$LEAF1_HOST" "$PPROXY_XDPCAP_BPF_HOST"
    pproxy_scp_xdpcap_bpf "$LEAF2_HOST" "$PPROXY_XDPCAP_BPF_HOST"
  fi
  pproxy_stop_leaf "$LEAF1_HOST" "$VM_PP1_CFG"
  pproxy_stop_leaf "$LEAF2_HOST" "$VM_PP2_CFG"
  pproxy_push_cfgs

  if [[ "$DEPLOY_IO_RIGHT" == "memif" ]]; then
    : "${LEAF1_WAN_DEV:?memif: LEAF1_WAN_DEV 未设置}"
    : "${LEAF2_WAN_DEV:?memif: LEAF2_WAN_DEV 未设置}"
    pproxy_vpp_memif_setup "$LEAF1_HOST" "$LEAF1_WAN_DEV"
    pproxy_vpp_memif_setup "$LEAF2_HOST" "$LEAF2_WAN_DEV"
  fi

  g1=0
  g2=0
  if [[ "$PPROXY_GDB" == "1" ]]; then
    g1=$GDBSERVER_PORT_LEAF1
    g2=$GDBSERVER_PORT_LEAF2
  fi
  pproxy_start "$LEAF1_HOST" "$VM_PPROXY_BIN" "$VM_PP1_CFG" "$VM_PPROXY_LOG" "$g1" "$USE_XDPCAP" "$VM_PPROXY_XDPCAP_BPF"
  pproxy_start "$LEAF2_HOST" "$VM_PPROXY_BIN" "$VM_PP2_CFG" "$VM_PPROXY_LOG" "$g2" "$USE_XDPCAP" "$VM_PPROXY_XDPCAP_BPF"

  if [[ "$PPROXY_GDB" == "1" ]]; then
    echo ""
    echo "  pproxy: PPROXY_GDB=1 — gdbserver 会等远程调试器，进程在 VSCode/ gdb「继续」前可能未完成初始化。"
    echo "  已跳过 metrics / 日志的 smoke 检查。请在本机: ./tests/clab/gdb-tunnel.sh  再在 VSCode F5 连接 localhost:${GDBSERVER_PORT_LEAF1} / :${GDBSERVER_PORT_LEAF2}。"
  elif [[ "${PPROXY_SKIP_SMOKE:-0}" == "1" ]]; then
    echo "  smoke checks skipped (PPROXY_SKIP_SMOKE=1); pproxy started"
  else
    wait_vm_http "$LEAF1_HOST" "$PP1_METRICS" "leaf1"
    wait_vm_http "$LEAF2_HOST" "$PP2_METRICS" "leaf2"

    echo "  Checking metrics (pp_info) …"
    sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${LEAF1_HOST}" \
      "curl -sf -m3 http://127.0.0.1:${PP1_METRICS}/metrics" | grep -q "pp_info" \
      || { echo "  ✗ leaf1 metrics missing pp_info" >&2; exit 1; }
    sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${LEAF2_HOST}" \
      "curl -sf -m3 http://127.0.0.1:${PP2_METRICS}/metrics" | grep -q "pp_info" \
      || { echo "  ✗ leaf2 metrics missing pp_info" >&2; exit 1; }

    echo "  Checking tunnel (${TUNNEL_MODE}) in logs …"
    case "$TUNNEL_MODE" in
      tcp)
        _g1="tcp tunnel listening"
        _g2="tcp tunnel connected"
        ;;
      udp)
        _g1="udp tunnel bound"
        _g2="udp tunnel connected"
        ;;
      icmp)
        _g1="icmp raw_socket listening"
        _g2="icmp raw_socket client ready"
        ;;
    esac
    # stdin → 远端 sudo -S
    printf '%s\n' "$UBUNTU_PASS" | sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" \
      "${UBUNTU_USER}@${LEAF1_HOST}" "sudo -S -p '' tail -n 120 ${VM_PPROXY_LOG}" 2>/dev/null | grep -q "$_g1" \
      || { echo "  ✗ leaf1 log missing '$_g1'" >&2; exit 1; }
    printf '%s\n' "$UBUNTU_PASS" | sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" \
      "${UBUNTU_USER}@${LEAF2_HOST}" "sudo -S -p '' tail -n 120 ${VM_PPROXY_LOG}" 2>/dev/null | grep -q "$_g2" \
      || { echo "  ✗ leaf2 log missing '$_g2'" >&2; exit 1; }

    echo "  OK: pproxy smoke (${TUNNEL_MODE}), leaf1=server leaf2=client -> ${LEAF1_WAN_IP}:${TUNNEL_PORT}"
  fi
  echo ""
  echo "  二进制: ${VM_PPROXY_BIN}"
  echo "  配置:   ${VM_PP1_CFG} / ${VM_PP2_CFG}  (源目录: ${PPROXY_CFG_DIR}/)"
  echo "  日志:   各 leaf 上 ${VM_PPROXY_LOG}  （例: ssh clab@leaf1 \"sudo tail -f ${VM_PPROXY_LOG}\")"
  echo "  停进程: 各 leaf 上需要 sudo 时, 把本脚本的 UBUNTU_PASS 用管道喂给: sudo -S pkill -f 下面路径"
  echo "         ${VM_PP1_CFG}  (leaf1)    ${VM_PP2_CFG}  (leaf2)"
  if [[ "${PPROXY_COREDUMP:-1}" == "1" ]]; then
    echo "  coredump: ${VM_PPROXY_ROOT}/core-pproxy-*.  gdb: gdb ${VM_PPROXY_BIN} ${VM_PPROXY_ROOT}/core-..."
  fi
}

echo ""
if [[ "$PPROXY_ONLY" -eq 1 ]]; then
  echo "=== [--pproxy-only] leaf SSH check ==="
  echo "  SSH targets: ${LEAF1_HOST}, ${LEAF2_HOST}"
  wait_for_ssh leaf1 "$LEAF1_HOST"
  wait_for_ssh leaf2 "$LEAF2_HOST"
  deploy_io_backend_prep
else
  echo "=== [2/5] Waiting for Ubuntu (generic_vm) SSH ==="
  echo "  SSH targets: ${LEAF1_HOST}, ${LEAF2_HOST} (clab 节点名; /etc/hosts 由 containerlab 维护)"
  wait_for_ssh leaf1 "$LEAF1_HOST"
  wait_for_ssh leaf2 "$LEAF2_HOST"

  echo ""
  echo "=== [3/5] Applying Ubuntu data-plane configuration ==="
  WAN_FOR_DPDK=0
  if [[ "$DEPLOY_IO_RIGHT" == "dpdk" ]]; then
    WAN_FOR_DPDK=1
  fi
  configure_ubuntu_leaf leaf1 "$LEAF1_HOST" "172.16.0.2/24" "192.168.0.1/24" "172.16.0.1" "192.168.1.0/24" "172.16.1.0/24" "$WAN_FOR_DPDK"
  configure_ubuntu_leaf leaf2 "$LEAF2_HOST" "172.16.1.2/24" "192.168.1.1/24" "172.16.1.1" "192.168.0.0/24" "172.16.0.0/24" "$WAN_FOR_DPDK"

  deploy_io_backend_prep

  echo ""
  echo "  pwru (eBPF helper): install to /usr/bin on both leaves"
  leaf_install_pwru
fi

if [[ "$SKIP_PPROXY" -eq 0 ]]; then
  pproxy_smoke
else
  echo ""
  echo "=== [4/5] pproxy: skipped (--no-pproxy) ==="
fi

echo ""
echo "=== [5/5] Done ==="
echo "  client1 → 192.168.0.2 (GW 192.168.0.1 on leaf1)"
echo "  client2 → 192.168.1.2 (GW 192.168.1.1 on leaf2)"
echo "  Test: docker exec -it client1 ping -c 3 192.168.1.2"
echo "  Test: docker exec -it client2 ping -c 3 192.168.0.2"

# 本机拉 gdb 端口（避免 generic_vm 上 clab ports 对 VM 内 127.0.0.1 无效，须 ssh -L）
if [[ "$SKIP_PPROXY" -eq 0 ]]; then
  _tun=0
  if [[ "$PPROXY_GDB_TUNNEL" == "1" ]]; then
    _tun=1
  elif [[ "$PPROXY_GDB_TUNNEL" == "0" ]]; then
    _tun=0
  elif [[ -z "$PPROXY_GDB_TUNNEL" && "$PPROXY_GDB" == "1" ]]; then
    _tun=1
  fi
  if [[ "$_tun" == "1" ]]; then
    echo ""
    echo "=== [5.1/5] Host: gdb SSH local forwards (gdb-tunnel.sh → localhost:${GDBSERVER_PORT_LEAF1}/${GDBSERVER_PORT_LEAF2}) ==="
    if [[ -x "$CLAB_DIR/gdb-tunnel.sh" ]]; then
      if "$CLAB_DIR/gdb-tunnel.sh"; then
        echo "  VSCode 可连 miDebuggerServerAddress: localhost:${GDBSERVER_PORT_LEAF1} / :${GDBSERVER_PORT_LEAF2}"
        echo "  停转发:  $CLAB_DIR/gdb-tunnel.sh stop"
      else
        echo "  ⚠ gdb-tunnel.sh 失败；稍后可手跑: $CLAB_DIR/gdb-tunnel.sh" >&2
      fi
    else
      echo "  ⚠ 未找到可执行: $CLAB_DIR/gdb-tunnel.sh" >&2
    fi
  fi
fi
