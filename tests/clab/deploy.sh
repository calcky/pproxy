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
#   ./build.sh --xdp --pcap
# 以生成与 leaf 上 libbpf/libxdp/libpcap 依赖一致的 build/pproxy。宿主机缺依赖则先装或跳过编译。
#
# 命令行帮助:  ./deploy.sh --help
#
set -euo pipefail

cd "$(dirname "$0")"

TOPO="pproxy.clab.yml"
UBUNTU_USER="clab"
UBUNTU_PASS='clab@123'
# 与 deploy 中 configure_ubuntu_leaf 的地址一致（见 generic_vm 拓扑 + 路由）
LEAF1_WAN_IP="172.16.0.2"
TUNNEL_PORT=19900
PP1_METRICS=19991
PP2_METRICS=19992

# 与 generic_vm.clab.yml 中 prefix: "" 一致
LEAF1_HOST="leaf1"
LEAF2_HOST="leaf2"

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLAB_DIR="$(cd "$(dirname "$0")" && pwd)"
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
  --left-io=KIND           左手 I/O: tun, raw_socket, af_xdp, netmap, pcap（默认同环境或 tun）
  --right-io=KIND|auto     隧道 I/O: kernel_socket, raw_socket, tun, af_xdp, netmap, pcap
                           省略或 auto 时：tcp/udp→kernel_socket，icmp→raw_socket
  --gdb / --no-gdb         是否用 gdbserver 起 pproxy（默认 --no-gdb）
  --gdb-tunnel             部署结束后在本机跑 gdb-tunnel.sh（ssh -L 转发 gdb 端口）
  --no-gdb-tunnel          不建立上述转发
  -h, --help               显示本帮助并退出（不部署、不编译）

常用环境变量:
  PPROXY_SKIP_BUILD=1      跳过宿主机 ./build.sh
  PPROXY_BIN=路径          pproxy 可执行文件（默认 仓库/build/pproxy）
  PPROXY_CFG_DIR=路径      配置文件目录（默认 tests/clab/config）
  PPROXY_TUNNEL_MODE       同 --tunnel（命令行优先）
  PPROXY_LEFT_IO, PPROXY_RIGHT_IO  同 --left-io / --right-io（命令行优先）
  PPROXY_COREDUMP, PPROXY_GDB, PPROXY_GDB_TUNNEL
  CLAB_SUDO=1              使用 sudo 调用 containerlab
  PPROXY_XDPCAP_BPF=路径   宿主机 xsk_xdpcap.bpf.o（可选；有则随 af_xdp 一起部署到 VM）

更完整的说明见本脚本文件头注释。
EOF
}

CLAB_ARGS=()
SKIP_PPROXY=0
DEPLOY_HELP=0
for a in "$@"; do
  if [[ "$a" == "--no-pproxy" ]]; then
    SKIP_PPROXY=1
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
  else
    CLAB_ARGS+=("$a")
  fi
done
# set -u：未设时为空串；可由 --gdb-tunnel / --no-gdb-tunnel 或环境变量覆盖
: "${PPROXY_GDB_TUNNEL:=}"

if [[ "$DEPLOY_HELP" -eq 1 ]]; then
  deploy_print_help
  exit 0
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

  local l r
  l=$(printf '%s' "${PPROXY_LEFT_IO:-tun}" | tr '[:upper:]' '[:lower:]')
  r="${PPROXY_RIGHT_IO:-}"
  r=$(printf '%s' "$r" | tr '[:upper:]' '[:lower:]')
  if [[ -z "$r" || "$r" == "auto" ]]; then
    case "$TUNNEL_MODE" in
      tcp|udp) r=kernel_socket ;;
      icmp) r=raw_socket ;;
    esac
  fi

  case "$l" in
    tun|raw_socket|af_xdp|netmap|pcap) ;;
    *)
      echo "Invalid --left-io / PPROXY_LEFT_IO: ${PPROXY_LEFT_IO:-tun} (tun, raw_socket, af_xdp, netmap, pcap)" >&2
      exit 1
      ;;
  esac
  case "$r" in
    kernel_socket|raw_socket|tun|af_xdp|netmap|pcap) ;;
    *)
      echo "Invalid --right-io / PPROXY_RIGHT_IO: $r (kernel_socket, raw_socket, tun, af_xdp, netmap, pcap, auto)" >&2
      exit 1
      ;;
  esac

  DEPLOY_IO_LEFT=$l
  DEPLOY_IO_RIGHT=$r

  local c1_1 c2_1 c1_2 c2_2
  c1_1="${PPROXY_CFG_DIR}/pp1.${TUNNEL_MODE}.left-${l}.right-${r}.json"
  c2_1="${PPROXY_CFG_DIR}/pp2.${TUNNEL_MODE}.left-${l}.right-${r}.json"
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
    echo "  ✗ 未找到与 tunnel=${TUNNEL_MODE} left=${l} right=${r} 匹配的配置" >&2
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

# 宿主编译：与 pproxy_apt_deps / 拷贝的运行动态库一致（xdp+pcap）
if [[ "$SKIP_PPROXY" -eq 0 && "${PPROXY_SKIP_BUILD:-0}" != "1" ]]; then
  echo "=== [0/5] Host: $REPO_ROOT/build.sh --xdp --pcap --debug ==="
  (cd "$REPO_ROOT" && ./build.sh --xdp --pcap --debug)
fi

echo "=== [1/5] Deploying containerlab topology ==="
if [[ "${CLAB_SUDO:-0}" == "1" ]]; then
  echo "  (using: sudo containerlab …; set CLAB_SUDO=0 to try without sudo)"
  sudo containerlab deploy -t "$TOPO" "${CLAB_ARGS[@]:-}"
else
  echo "  (using: containerlab without sudo; need root? set CLAB_SUDO=1)"
  containerlab deploy -t "$TOPO" "${CLAB_ARGS[@]:-}"
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

  echo "  Configuring ${label} (WAN=${wan_cidr}, LAN=${lan_cidr}, GW=${gw}) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" bash -s <<EOF
set -euo pipefail
WAN_CIDR='${wan_cidr}'
LAN_CIDR='${lan_cidr}'
GW='${gw}'
LABEL='${label}'
PEER_LAN='${peer_lan_cidr}'
PEER_UPLINK='${peer_uplink_cidr}'
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

s ip addr flush dev "\$WAN" 2>/dev/null || true
s ip addr add "\$WAN_CIDR" dev "\$WAN"
s ip link set "\$WAN" up

s ip addr flush dev "\$LAN" 2>/dev/null || true
s ip addr add "\$LAN_CIDR" dev "\$LAN"
s ip link set "\$LAN" up

if [[ -n "\$PEER_LAN" ]]; then
  s ip route replace "\$PEER_LAN" via "\$GW" dev "\$WAN" 2>/dev/null || true
fi
if [[ -n "\$PEER_UPLINK" ]]; then
  s ip route replace "\$PEER_UPLINK" via "\$GW" dev "\$WAN" 2>/dev/null || true
fi

s sysctl -w net.ipv4.ip_forward=1 >/dev/null
if s iptables -t nat -C POSTROUTING -o "\$WAN" -j MASQUERADE 2>/dev/null; then
  :
else
  s iptables -t nat -A POSTROUTING -o "\$WAN" -j MASQUERADE
fi
echo "OK \${LABEL}: WAN=\$WAN LAN=\$LAN"
EOF
  echo "  ✓ ${label} done"
}

# ---------- pproxy: 装动态库、拷二进制、发配置、起进程、简单检查 ----------
pproxy_apt_deps() {
  local host=$1
  echo "  pproxy: installing runtime libs on ${host} …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" bash -s <<EOA
set -euo pipefail
SUDO_PASS='${UBUNTU_PASS}'
s() { printf '%s\n' "\$SUDO_PASS" | sudo -S -p '' "\$@"; }
export DEBIAN_FRONTEND=noninteractive
s apt-get update -qq
# 与 build.sh 链接的 libbpf/libxdp/libpcap 匹配；24.04 上部分包名为 *t64
s apt-get install -y -qq curl ca-certificates libbpf1 libxdp1 gdb
if ! command -v gdbserver >/dev/null 2>&1; then
  s apt-get install -y -qq gdbserver
fi
s apt-get install -y -qq libelf1t64 2>/dev/null || s apt-get install -y -qq libelf1
s apt-get install -y -qq libpcap0.8t64 2>/dev/null || s apt-get install -y -qq libpcap0.8
# xdp-loader / xdpdump 等；bpftrace 用于 eBPF 跟踪（部分旧版需启用 universe）
if ! s apt-get install -y -qq xdp-tools bpftrace; then
  echo "  … note: xdp-tools/bpftrace install failed on ${host} (optional; check apt sources / release)" >&2
fi
EOA
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
  printf '%s' "$PATTERN" | s tee /proc/sys/kernel/core_pattern >/dev/null
fi
EOC
}

pproxy_scp_bin() {
  local host=$1
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$PPROXY_BIN" "${UBUNTU_USER}@${host}:${VM_PPROXY_BIN}"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" "chmod 755 ${VM_PPROXY_BIN}"
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
  fi
  echo "  pproxy: scp 配置 $PP1_JSON → ${LEAF1_HOST}:${VM_PP1_CFG} …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$PP1_JSON" \
    "${UBUNTU_USER}@${LEAF1_HOST}:${VM_PP1_CFG}"
  echo "  pproxy: scp 配置 $PP2_JSON → ${LEAF2_HOST}:${VM_PP2_CFG} …"
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$PP2_JSON" \
    "${UBUNTU_USER}@${LEAF2_HOST}:${VM_PP2_CFG}"
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
s pkill -f "pproxy -c $CFG" 2>/dev/null || true
if [[ "$GDBPORT" != "0" ]]; then
  s pkill -f "gdbserver 127.0.0.1:${GDBPORT}" 2>/dev/null || true
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
  echo "  Tunnel: $TUNNEL_MODE  I/O: left=${DEPLOY_IO_LEFT}  right=${DEPLOY_IO_RIGHT}"
  echo "  Config: $PP1_JSON + $PP2_JSON"

  pproxy_apt_deps "$LEAF1_HOST"
  pproxy_apt_deps "$LEAF2_HOST"
  pproxy_remote_prepare "$LEAF1_HOST"
  pproxy_remote_prepare "$LEAF2_HOST"
  pproxy_coredump_setup "$LEAF1_HOST"
  pproxy_coredump_setup "$LEAF2_HOST"
  pproxy_scp_bin "$LEAF1_HOST"
  pproxy_scp_bin "$LEAF2_HOST"
  if [[ "$USE_XDPCAP" -eq 1 ]]; then
    pproxy_scp_xdpcap_bpf "$LEAF1_HOST" "$PPROXY_XDPCAP_BPF_HOST"
    pproxy_scp_xdpcap_bpf "$LEAF2_HOST" "$PPROXY_XDPCAP_BPF_HOST"
    pproxy_scp_xdpcap "$LEAF1_HOST"
    pproxy_scp_xdpcap "$LEAF2_HOST"
  fi
  pproxy_push_cfgs

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
echo "=== [2/5] Waiting for Ubuntu (generic_vm) SSH ==="
echo "  SSH targets: ${LEAF1_HOST}, ${LEAF2_HOST} (clab 节点名; /etc/hosts 由 containerlab 维护)"
wait_for_ssh leaf1 "$LEAF1_HOST"
wait_for_ssh leaf2 "$LEAF2_HOST"

echo ""
echo "=== [3/5] Applying Ubuntu data-plane configuration ==="
configure_ubuntu_leaf leaf1 "$LEAF1_HOST" "172.16.0.2/24" "192.168.0.1/24" "172.16.0.1" "192.168.1.0/24" "172.16.1.0/24"
configure_ubuntu_leaf leaf2 "$LEAF2_HOST" "172.16.1.2/24" "192.168.1.1/24" "172.16.1.1" "192.168.0.0/24" "172.16.0.0/24"

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
