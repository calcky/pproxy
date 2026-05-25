#!/usr/bin/env bash
# tests/clab/perf/check-tunnel.sh -- iperf 前校验 leaf1/leaf2 tunnel 状态
#
# 环境变量（由 perf.sh 设置）:
#   EXPECT_PROTO=udp|tcp|icmp
#   EXPECT_LEFT=tun|...
#   EXPECT_RIGHT=kernel_socket|io_uring|af_xdp|netmap|dpdk|...
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

EXPECT_PROTO="${EXPECT_PROTO:-udp}"
EXPECT_LEFT="${EXPECT_LEFT:-tun}"
EXPECT_RIGHT="${EXPECT_RIGHT:-kernel_socket}"

check_leaf() {
  local host=$1 role=$2
  local out
  out=$(leaf_ssh "$host" 'pproxy-ctl tunnel 2>/dev/null' || true)
  if [[ -z "$out" ]]; then
    perf_err "${host}: pproxy-ctl tunnel failed (is pproxy running?)"
    return 1
  fi
  perf_log "${host} (${role}):"
  while IFS= read -r ln; do
    [[ -n "$ln" ]] && perf_log "  ${ln}"
  done <<< "$out"

  if ! grep -q "^left: ${EXPECT_LEFT}$" <<< "$out"; then
    local got
    got=$(grep '^left: ' <<< "$out" || echo 'left: ?')
    perf_err "${host}: expected left=${EXPECT_LEFT}, got ${got}"
    return 1
  fi

  local line
  line=$(grep -E '^tunnel\[0\]:' <<< "$out" || true)
  if [[ -z "$line" ]]; then
    perf_err "${host}: missing tunnel[0] line"
    return 1
  fi

  if ! grep -q "proto=${EXPECT_PROTO} " <<< "$line"; then
    perf_err "${host}: expected proto=${EXPECT_PROTO}, got: ${line}"
    return 1
  fi

  case "$EXPECT_RIGHT" in
    io_uring)
      if ! grep -q 'io=kernel_socket' <<< "$line" || ! grep -q 'ks_backend=io_uring' <<< "$line"; then
        perf_err "${host}: expected io_uring (kernel_socket+io_uring), got: ${line}"
        return 1
      fi
      ;;
    *)
      if ! grep -q "io=${EXPECT_RIGHT} " <<< "$line"; then
        perf_err "${host}: expected io=${EXPECT_RIGHT}, got: ${line}"
        return 1
      fi
      ;;
  esac

  if ! grep -q 'ready=yes' <<< "$line"; then
    perf_err "${host}: tunnel not ready: ${line}"
    return 1
  fi

  perf_log "${host}: tunnel OK (proto=${EXPECT_PROTO} right=${EXPECT_RIGHT} ready=yes)"
}

rc=0
check_leaf "$LEAF1_HOST" server || rc=1
check_leaf "$LEAF2_HOST" client || rc=1
exit "$rc"
