#!/usr/bin/env bash
# tests/clab/perf/baseline-direct.sh -- 无 pproxy 直连基线（kernel 转发）
#
# 前提: clab 已 deploy（--no-pproxy 或停掉 pproxy），leaf 上 WAN 路由生效
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

LEAF1_WAN_GW="${LEAF1_WAN_GW:-172.16.0.1}"
PEER_LAN_CIDR="${PEER_LAN_CIDR:-192.168.1.0/24}"

restore_wan_route() {
  local host=$1 peer_cidr=$2 gw=$3
  perf_log "restore WAN route on ${host} for ${peer_cidr} via ${gw}"
  leaf_ssh "$host" bash -s -- "$UBUNTU_PASS" "$peer_cidr" "$gw" <<'EOF'
set -euo pipefail
PASS="$1"
PEER="$2"
GW="$3"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
MGT=$(ip -4 route show default 2>/dev/null | head -1 | sed -n 's/.* dev \([^ ]*\).*/\1/p' || true)
WAN=""
while read -r name _; do
  [[ "$name" == "lo" ]] && continue
  [[ -n "$MGT" && "$name" == "$MGT" ]] && continue
  WAN="$name"
  break
done < <(ip -br link | awk '{print $1}')
[[ -n "$WAN" ]] || { echo "no WAN dev" >&2; exit 1; }
s ip route replace "$PEER" via "$GW" dev "$WAN"
echo "OK route $PEER via $GW dev $WAN"
EOF
}

stop_pproxy() {
  local host=$1
  leaf_ssh "$host" bash -s -- "$UBUNTU_PASS" <<'EOF'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s pkill -f '/opt/pproxy/pproxy' 2>/dev/null || true
s pkill -f '/opt/pproxy/pp1.json' 2>/dev/null || true
s pkill -f '/opt/pproxy/pp2.json' 2>/dev/null || true
EOF
}

stop_pproxy "$LEAF1_HOST"
stop_pproxy "$LEAF2_HOST"
restore_wan_route "$LEAF1_HOST" "$PEER_LAN_CIDR" "$LEAF1_WAN_GW"
restore_wan_route "$LEAF2_HOST" "192.168.0.0/24" "172.16.1.1"
perf_ping_check
perf_log "baseline direct path ready (pproxy stopped, WAN routes restored)"
