#!/usr/bin/env bash
# tests/clab/deploy.sh -- 部署 containerlab 拓扑、配置 leaf 数据面、可选安装并测试 pproxy
#
# 用法:
#   ./deploy.sh                    # 部署拓扑 + 配置 leaf + 部署 pproxy 并做简单检查
#   ./deploy.sh --no-pproxy        # 只部署拓扑 + 配置 leaf（其余参数仍传给 containerlab）
#   PPROXY_BIN=/path/to/pproxy ./deploy.sh
#
# 宿主机 containerlab：
#   默认 **不** 使用 sudo（适合已加入 docker 组、且按 containerlab 文档配好免 sudo 的环境）。
#   若必须提权：CLAB_SUDO=1 ./deploy.sh
#
# 注意：leaf 虚拟机里配 IP/iptables、以及 pproxy 开 TUN 仍用 clab 用户的 sudo（VM 内，与宿主机无关）。
#
# pproxy 使用 tests/clab/config/*.json（勿在 deploy.sh 里内嵌大段 JSON）；
# 远程路径：/opt/pproxy/pproxy、/opt/pproxy/pp{1,2}.json、/opt/pproxy/log/pp{1,2}.log
#
# 改 leaf1 的 WAN 地址时：须同步改 tests/clab/config/pp2.json 里 tunnels[0].server（对端 TCP）。
#
# 先在本仓库根目录执行 ./build.sh --xdp --pcap 生成 build/pproxy（与 Ubuntu noble 动态库兼容时可直接 scp）
#
set -euo pipefail

cd "$(dirname "$0")"

TOPO="generic_vm.clab.yml"
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
# 与 tests/clab/config/pp1.json 中 listen 端口一致
PP1_JSON="$PPROXY_CFG_DIR/pp1.json"
PP2_JSON="$PPROXY_CFG_DIR/pp2.json"
# 虚拟机内统一安装前缀（与本仓库配置文件路径一致）
VM_PPROXY_ROOT="/opt/pproxy"
VM_PPROXY_BIN="$VM_PPROXY_ROOT/pproxy"
VM_PP1_CFG="$VM_PPROXY_ROOT/pp1.json"
VM_PP2_CFG="$VM_PPROXY_ROOT/pp2.json"
VM_PP1_LOG="$VM_PPROXY_ROOT/log/pp1.log"
VM_PP2_LOG="$VM_PPROXY_ROOT/log/pp2.log"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=15
  -o LogLevel=ERROR
)

CLAB_ARGS=()
SKIP_PPROXY=0
for a in "$@"; do
  if [[ "$a" == "--no-pproxy" ]]; then
    SKIP_PPROXY=1
  else
    CLAB_ARGS+=("$a")
  fi
done

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing dependency: $1 (install: $2)" >&2
    exit 1
  }
}

require sshpass "sshpass"
require scp "openssh-client"
require containerlab "containerlab (https://containerlab.dev)"

echo "=== [1/4] Deploying containerlab topology ==="
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
s apt-get install -y -qq libelf1t64 2>/dev/null || s apt-get install -y -qq libelf1
s apt-get install -y -qq libpcap0.8t64 2>/dev/null || s apt-get install -y -qq libpcap0.8
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

pproxy_scp_bin() {
  local host=$1
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q "$PPROXY_BIN" "${UBUNTU_USER}@${host}:${VM_PPROXY_BIN}"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" "chmod 755 ${VM_PPROXY_BIN}"
}

pproxy_push_cfgs() {
  if [[ ! -f "$PP1_JSON" ]] || [[ ! -f "$PP2_JSON" ]]; then
    echo "  ✗ 缺少配置: $PP1_JSON 或 $PP2_JSON" >&2
    exit 1
  fi
  if command -v python3 >/dev/null 2>&1; then
    python3 -c "import json,sys; [json.load(open(f)) for f in sys.argv[1:]]" \
      "$PP1_JSON" "$PP2_JSON" || { echo "  ✗ JSON 校验失败" >&2; exit 1; }
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
  echo "  pproxy: starting on ${host} ($bin -c $cfg) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" \
    bash -s -- "$UBUNTU_PASS" "$bin" "$cfg" "$log" <<'EOS'
set -euo pipefail
PASS="$1"
BIN="$2"
CFG="$3"
LOG="$4"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s pkill -f "pproxy -c $CFG" 2>/dev/null || true
sleep 0.5
# TUN 需 root；标准输出/错入日志（见 /opt/pproxy/log/）
s install -d -m 0755 "$(dirname "$LOG")" 2>/dev/null || true
s sh -c "nohup $BIN -c $CFG >> $LOG 2>&1 < /dev/null &"
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
  echo "=== [4/4] pproxy: binary, configs, start, smoke test ==="
  if [[ ! -x "$PPROXY_BIN" ]]; then
    echo "  ✗ 未找到可执行文件: $PPROXY_BIN" >&2
    echo "     在仓库根目录先执行: ./build.sh --xdp --pcap" >&2
    exit 1
  fi
  echo "  Using: $PPROXY_BIN"

  pproxy_apt_deps "$LEAF1_HOST"
  pproxy_apt_deps "$LEAF2_HOST"
  pproxy_remote_prepare "$LEAF1_HOST"
  pproxy_remote_prepare "$LEAF2_HOST"
  pproxy_scp_bin "$LEAF1_HOST"
  pproxy_scp_bin "$LEAF2_HOST"
  pproxy_push_cfgs

  pproxy_start "$LEAF1_HOST" "$VM_PPROXY_BIN" "$VM_PP1_CFG" "$VM_PP1_LOG"
  pproxy_start "$LEAF2_HOST" "$VM_PPROXY_BIN" "$VM_PP2_CFG" "$VM_PP2_LOG"

  wait_vm_http "$LEAF1_HOST" "$PP1_METRICS" "leaf1"
  wait_vm_http "$LEAF2_HOST" "$PP2_METRICS" "leaf2"

  echo "  Checking metrics (pp_info) …"
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${LEAF1_HOST}" \
    "curl -sf -m3 http://127.0.0.1:${PP1_METRICS}/metrics" | grep -q "pp_info" \
    || { echo "  ✗ leaf1 metrics missing pp_info" >&2; exit 1; }
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${LEAF2_HOST}" \
    "curl -sf -m3 http://127.0.0.1:${PP2_METRICS}/metrics" | grep -q "pp_info" \
    || { echo "  ✗ leaf2 metrics missing pp_info" >&2; exit 1; }

  echo "  Checking TCP tunnel in logs …"
  # stdin → 远端 sudo -S
  printf '%s\n' "$UBUNTU_PASS" | sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" \
    "${UBUNTU_USER}@${LEAF1_HOST}" "sudo -S -p '' tail -n 80 ${VM_PP1_LOG}" 2>/dev/null | grep -q "tcp tunnel listening" \
    || { echo "  ✗ leaf1 log missing 'tcp tunnel listening'" >&2; exit 1; }
  printf '%s\n' "$UBUNTU_PASS" | sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" \
    "${UBUNTU_USER}@${LEAF2_HOST}" "sudo -S -p '' tail -n 80 ${VM_PP2_LOG}" 2>/dev/null | grep -q "tcp tunnel connected" \
    || { echo "  ✗ leaf2 log missing 'tcp tunnel connected'" >&2; exit 1; }

  echo "  ✓ pproxy smoke test OK (leaf1=server, leaf2=client → ${LEAF1_WAN_IP}:${TUNNEL_PORT})"
  echo ""
  echo "  二进制: ${VM_PPROXY_BIN}"
  echo "  配置:   ${VM_PP1_CFG} / ${VM_PP2_CFG}（源文件: ${PPROXY_CFG_DIR}/）"
  echo "  日志:   tail -f ${VM_PP1_LOG}  |  tail -f ${VM_PP2_LOG}"
  echo "  停进程: ssh clab@leaf1 \"echo '$UBUNTU_PASS' | sudo -S pkill -f ${VM_PP1_CFG}\""
  echo "         ssh clab@leaf2 \"echo '$UBUNTU_PASS' | sudo -S pkill -f ${VM_PP2_CFG}\""
}

echo ""
echo "=== [2/4] Waiting for Ubuntu (generic_vm) SSH ==="
echo "  SSH targets: ${LEAF1_HOST}, ${LEAF2_HOST} (clab 节点名; /etc/hosts 由 containerlab 维护)"
wait_for_ssh leaf1 "$LEAF1_HOST"
wait_for_ssh leaf2 "$LEAF2_HOST"

echo ""
echo "=== [3/4] Applying Ubuntu data-plane configuration ==="
configure_ubuntu_leaf leaf1 "$LEAF1_HOST" "172.16.0.2/24" "192.168.0.1/24" "172.16.0.1" "192.168.1.0/24" "172.16.1.0/24"
configure_ubuntu_leaf leaf2 "$LEAF2_HOST" "172.16.1.2/24" "192.168.1.1/24" "172.16.1.1" "192.168.0.0/24" "172.16.0.0/24"

if [[ "$SKIP_PPROXY" -eq 0 ]]; then
  pproxy_smoke
else
  echo ""
  echo "=== [4/4] pproxy: skipped (--no-pproxy) ==="
fi

echo ""
echo "=== Done ==="
echo "  client1 → 192.168.0.2 (GW 192.168.0.1 on leaf1)"
echo "  client2 → 192.168.1.2 (GW 192.168.1.1 on leaf2)"
echo "  Test: docker exec -it client1 ping -c 3 192.168.1.2"
echo "  Test: docker exec -it client2 ping -c 3 192.168.0.2"