#!/usr/bin/env bash
# tests/clab/perf/run-iperf.sh -- 在 client1→client2 跑 iperf3，输出 JSON 到 stdout
#
# 环境变量:
#   IPERF_PROTO=tcp|udp   默认 tcp
#   IPERF_DURATION=10
#   IPERF_PARALLEL=1      并行流数（-P）
#   IPERF_LENGTH=1400     仅 UDP -l
#   IPERF_WARMUP=2        预热秒数（不计入结果；0=跳过）
#   IPERF_CPU_OUT=        若设置，正式 iperf 起/止各快照一次 CPU
#   IPERF_SERVER_IP=192.168.1.2
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

IPERF_PROTO="${IPERF_PROTO:-tcp}"
IPERF_DURATION="${IPERF_DURATION:-10}"
IPERF_DURATION_MAIN="$IPERF_DURATION"
IPERF_PARALLEL="${IPERF_PARALLEL:-1}"
IPERF_LENGTH="${IPERF_LENGTH:-1400}"
IPERF_WARMUP="${IPERF_WARMUP:-2}"
IPERF_SERVER_IP="${IPERF_SERVER_IP:-$CLIENT2_IP}"
IPERF_CPU_OUT="${IPERF_CPU_OUT:-}"

ensure_iperf3_clients

CPU_BEGIN=""
if [[ -n "$IPERF_CPU_OUT" ]]; then
  CPU_BEGIN=$(mktemp)
  chmod +x "$PERF_DIR/collect-cpu.sh" 2>/dev/null || true
fi

# 停掉可能残留的 iperf3
client_exec "$CLIENT2" sh -c 'pkill -x iperf3 2>/dev/null || true' || true
sleep 0.5

client_exec "$CLIENT2" iperf3 -s -1 -D >/dev/null
sleep 1

run_once() {
  local extra=()
  case "$IPERF_PROTO" in
    udp) extra=(-u -b 0 -l "$IPERF_LENGTH") ;;
    tcp) extra=() ;;
    *)
      perf_err "unknown IPERF_PROTO=$IPERF_PROTO"
      return 1
      ;;
  esac
  client_exec "$CLIENT1" iperf3 -c "$IPERF_SERVER_IP" -J \
    -t "$IPERF_DURATION" -P "$IPERF_PARALLEL" "${extra[@]}"
}

if [[ "$IPERF_WARMUP" -gt 0 ]]; then
  IPERF_DURATION="$IPERF_WARMUP" run_once >/dev/null || true
  client_exec "$CLIENT2" sh -c 'pkill -x iperf3 2>/dev/null || true' || true
  sleep 0.5
  client_exec "$CLIENT2" iperf3 -s -1 -D >/dev/null
  sleep 1
fi

IPERF_DURATION="$IPERF_DURATION_MAIN"
if [[ -n "$CPU_BEGIN" ]]; then
  "$PERF_DIR/collect-cpu.sh" --begin "$CPU_BEGIN"
fi
run_once
if [[ -n "$IPERF_CPU_OUT" ]]; then
  "$PERF_DIR/collect-cpu.sh" --end "$CPU_BEGIN" --duration "$IPERF_DURATION_MAIN" --out "$IPERF_CPU_OUT"
  rm -f "$CPU_BEGIN"
fi
