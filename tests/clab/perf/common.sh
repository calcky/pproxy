# tests/clab/perf/common.sh -- perf 脚本共享变量与 helper
# shellcheck disable=SC2034
PERF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAB_DIR="$(cd "$PERF_DIR/.." && pwd)"
REPO_ROOT="$(cd "$CLAB_DIR/../.." && pwd)"
RESULTS_DIR="${PERF_RESULTS_DIR:-$CLAB_DIR/results}"
SCENARIOS_FILE="${PERF_SCENARIOS:-$PERF_DIR/scenarios.yaml}"

UBUNTU_USER="${UBUNTU_USER:-clab}"
UBUNTU_PASS="${UBUNTU_PASS:-clab@123}"
LEAF1_HOST="${LEAF1_HOST:-leaf1}"
LEAF2_HOST="${LEAF2_HOST:-leaf2}"
CLAB_LAB="${CLAB_LAB:-pproxy}"
CLIENT1="${CLIENT1:-client1}"
CLIENT2="${CLIENT2:-client2}"
CLIENT1_IP="${CLIENT1_IP:-192.168.0.2}"
CLIENT2_IP="${CLIENT2_IP:-192.168.1.2}"
PP1_METRICS="${PP1_METRICS:-19991}"
PP2_METRICS="${PP2_METRICS:-19992}"

SSH_OPTS=(
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
  -o ConnectTimeout=15
  -o LogLevel=ERROR
)

perf_log() { printf '==> %s\n' "$*"; }
perf_err() { printf '!!! %s\n' "$*" >&2; }

ensure_python_yaml() {
  if python3 -c 'import yaml' 2>/dev/null; then
    return 0
  fi
  if command -v apt-get >/dev/null 2>&1; then
    perf_log "installing python3-yaml (needed to read scenarios.yaml)"
    sudo apt-get update -qq && sudo apt-get install -y -qq python3-yaml || true
  fi
  python3 -c 'import yaml' 2>/dev/null || {
    perf_err "need python3-yaml: sudo apt-get install -y python3-yaml"
    return 1
  }
}

resolve_client_container() {
  local node=$1
  if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$node"; then
    echo "$node"
    return 0
  fi
  local cand
  for cand in "pproxy-${node}" "clab-${CLAB_LAB}-${node}" "${CLAB_LAB}-${node}"; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -qx "$cand"; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

client_exec() {
  local node=$1
  shift
  local ctn
  ctn=$(resolve_client_container "$node") || {
    perf_err "client container not found for node ${node} (is clab deployed?)"
    return 1
  }
  docker exec "$ctn" "$@"
}

leaf_ssh() {
  local host=$1
  shift
  sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" "$@"
}

ensure_iperf3_clients() {
  local node ctn
  for node in "$CLIENT1" "$CLIENT2"; do
    ctn=$(resolve_client_container "$node") || return 1
    docker exec "$ctn" sh -c 'command -v iperf3 >/dev/null 2>&1 || (apk add --no-cache iperf3 2>/dev/null || (apt-get update -qq && apt-get install -y -qq iperf3))' \
      || perf_err "failed to install iperf3 in ${node}"
  done
}

perf_ping_check() {
  perf_wait_connectivity 15
}

perf_wait_connectivity() {
  local max="${1:-60}"
  local i
  for ((i = 1; i <= max; i++)); do
    if client_exec "$CLIENT1" ping -c 1 -W 2 "$CLIENT2_IP" >/dev/null 2>&1; then
      perf_log "connectivity OK: ${CLIENT1} -> ${CLIENT2_IP} (${i}s)"
      return 0
    fi
    if [[ "$i" -eq 1 ]]; then
      perf_log "waiting for path ${CLIENT1} -> ${CLIENT2_IP} (up to ${max}s) …"
    fi
    sleep 1
  done
  perf_err "ping failed after ${max}s"
  return 1
}

perf_stop_pproxy_on_leaf() {
  local host=$1
  leaf_ssh "$host" bash -s -- "$UBUNTU_PASS" <<'EOF' 2>/dev/null || true
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
s pkill -9 -f '/opt/pproxy/pproxy' 2>/dev/null || true
s pkill -9 -f '/opt/pproxy/pp1.json' 2>/dev/null || true
s pkill -9 -f '/opt/pproxy/pp2.json' 2>/dev/null || true
s pkill -9 -f gdbserver 2>/dev/null || true
EOF
}

perf_stop_iperf_clients() {
  local node ctn
  for node in "$CLIENT1" "$CLIENT2"; do
    ctn=$(resolve_client_container "$node" 2>/dev/null) || continue
    docker exec "$ctn" sh -c 'pkill -x iperf3 2>/dev/null || true' 2>/dev/null || true
  done
}

perf_kill_stale_perf_runs() {
  local pid my=$$ ppid=${PPID:-0}
  for pid in $(pgrep -f '[b]ash ./tests/clab/perf\.sh' 2>/dev/null || true); do
    [[ "$pid" -eq "$my" || "$pid" -eq "$ppid" ]] && continue
    perf_log "cleanup: stopping stale perf.sh pid=${pid}"
    kill "$pid" 2>/dev/null || true
  done
  for pid in $(pgrep -f '[b]ash ./tests/clab/deploy\.sh' 2>/dev/null || true); do
    perf_log "cleanup: stopping stale deploy.sh pid=${pid}"
    kill "$pid" 2>/dev/null || true
  done
  sleep 1
  for pid in $(pgrep -f '[b]ash ./tests/clab/perf\.sh' 2>/dev/null || true); do
    [[ "$pid" -eq "$my" || "$pid" -eq "$ppid" ]] && continue
    kill -9 "$pid" 2>/dev/null || true
  done
  for pid in $(pgrep -f '[b]ash ./tests/clab/deploy\.sh' 2>/dev/null || true); do
    kill -9 "$pid" 2>/dev/null || true
  done
}

# 测试开始前清理上次可能残留的 perf / iperf / pproxy / gdb 转发
perf_cleanup_stale() {
  perf_log "cleanup: stale processes from previous runs"
  perf_kill_stale_perf_runs
  if [[ -x "$CLAB_DIR/gdb-tunnel.sh" ]]; then
    "$CLAB_DIR/gdb-tunnel.sh" stop 2>/dev/null || true
  fi
  perf_stop_iperf_clients
  for host in "$LEAF1_HOST" "$LEAF2_HOST"; do
    if sshpass -p "$UBUNTU_PASS" ssh "${SSH_OPTS[@]}" "${UBUNTU_USER}@${host}" true 2>/dev/null; then
      perf_log "cleanup: pproxy/gdb on ${host}"
      perf_stop_pproxy_on_leaf "$host"
    fi
  done
  perf_log "cleanup: done"
}

# iperf 前校验 tunnel；pproxy 重启后可能尚未 ready
perf_check_tunnel() {
  local max="${1:-15}"
  local i
  export EXPECT_PROTO="${EXPECT_PROTO:-udp}"
  export EXPECT_LEFT="${EXPECT_LEFT:-tun}"
  export EXPECT_RIGHT="${EXPECT_RIGHT:-kernel_socket}"
  for ((i = 1; i <= max; i++)); do
    if EXPECT_PROTO="$EXPECT_PROTO" EXPECT_LEFT="$EXPECT_LEFT" EXPECT_RIGHT="$EXPECT_RIGHT" \
      "$PERF_DIR/check-tunnel.sh"; then
      return 0
    fi
    if [[ "$i" -lt "$max" ]]; then
      perf_log "tunnel not ready yet (${i}/${max}), retry in 2s …"
      sleep 2
    fi
  done
  return 1
}
