#!/usr/bin/env bash
# gdb-tunnel.sh -- 本机 localhost:2345/2346 转发到各 leaf 上 gdbserver 监听地址（与 launch.json 一致）
#
# 用法:
#   ./gdb-tunnel.sh         # 启动两条 ssh -L
#   ./gdb-tunnel.sh stop    # 结束本脚本记录的转发
#
# 环境: CLAB_SSH_USER CLAB_SSH_PASS CLAB_LEAF1 CLAB_LEAF2（与 deploy.sh 默认一致）
#
set -euo pipefail
cd "$(dirname "$0")"

UBUNTU_USER="${CLAB_SSH_USER:-clab}"
UBUNTU_PASS="${CLAB_SSH_PASS:-clab@123}"
LEAF1="${CLAB_LEAF1:-leaf1}"
LEAF2="${CLAB_LEAF2:-leaf2}"
P1=2345
P2=2346
STATE_DIR="${XDG_RUNTIME_DIR:-/tmp}/pproxy-gdb-tunnel"
STATE="$STATE_DIR/pids"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=15
  -o LogLevel=ERROR
  -n
)

stop() {
  if [[ -f "$STATE" ]]; then
    while read -r p; do
      [[ -n "$p" ]] && kill "$p" 2>/dev/null || true
    done <"$STATE"
    rm -f "$STATE"
  fi
  echo "已尝试停止 $STATE 中的 ssh 转发进程"
}

if [[ "${1:-}" == "stop" ]]; then
  stop
  exit 0
fi

if ! command -v sshpass &>/dev/null; then
  echo "未找到 sshpass。请: apt install sshpass 或自行 ssh -L …" >&2
  exit 1
fi

stop
mkdir -p "$STATE_DIR"
: >"$STATE"

sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" \
  -L "${P1}:127.0.0.1:${P1}" -N -f "$UBUNTU_USER@$LEAF1" &
echo $! >>"$STATE"
sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" \
  -L "${P2}:127.0.0.1:${P2}" -N -f "$UBUNTU_USER@$LEAF2" &
echo $! >>"$STATE"

echo "OK: localhost:${P1} -> ${LEAF1}:127.0.0.1:${P1},  localhost:${P2} -> ${LEAF2}:127.0.0.1:${P2}"
echo "   停: $0 stop"
