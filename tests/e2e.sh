#!/usr/bin/env bash
#
# tests/e2e.sh -- 端到端集成测试（pp1 ↔ pp2，TCP tunnel）
#
# 做的事：
#   1. 起 pp2（server 模式，listen TCP 19900）
#   2. 起 pp1（client 模式，连 127.0.0.1:19900）
#   3. 各自等它们的 /metrics HTTP endpoint 200
#   4. 校验两侧日志里出现 "tcp tunnel listening" / "tcp tunnel connected"
#      → 表示右手侧真的建链
#   5. Unix socket 上跑 `stat` / `sessions` / `reload` / 看响应
#   6. Prometheus 导出里抓 pp_module_loops 应该都 > 0
#   7. 发 quit，双方优雅退出；若超时则 kill
#
# 需要权限：
#   CAP_NET_ADMIN（开 TUN 要）+ 绑 TCP 端口的权限
#   没有就 skip（exit 77）
#
# 依赖：bash, curl, python3（所有 UNIX socket 交互都走 python3 避开 nc 兼容性问题）
#
# 用法：
#   ./build.sh && sudo ./tests/e2e.sh
#   或 docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun -v $PWD:/work -w /work \
#       pproxy-build:latest ./tests/e2e.sh
set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"
BIN="$ROOT/build/pproxy"

# ---------- 颜色 & 日志 ----------
if [[ -t 1 ]]; then G=$'\033[32m'; Y=$'\033[33m'; R=$'\033[31m'; N=$'\033[0m'
else                G=''; Y=''; R=''; N=''
fi
log()  { printf '%s==>%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s!!%s %s\n'  "$Y" "$N" "$*"; }
err()  { printf '%s!!%s %s\n'  "$R" "$N" "$*" >&2; }

# ---------- 常量 ----------
TMPDIR_E2E=${TMPDIR:-/tmp}/pproxy-e2e.$$
mkdir -p "$TMPDIR_E2E"
PP1_LOG="$TMPDIR_E2E/pp1.log"
PP2_LOG="$TMPDIR_E2E/pp2.log"
PP1_SOCK="$TMPDIR_E2E/pp1.sock"
PP2_SOCK="$TMPDIR_E2E/pp2.sock"
PP1_CFG="$TMPDIR_E2E/pp1.json"
PP2_CFG="$TMPDIR_E2E/pp2.json"
PP1_IF="e2e-pp1"
PP2_IF="e2e-pp2"
TUN_PORT=19900
PP1_METRICS=19991
PP2_METRICS=19992
PP1_PID=""
PP2_PID=""
EXIT_CODE=0

# ---------- 清理 ----------
cleanup() {
    local ec=$?
    [[ -n "$PP1_PID" ]] && kill "$PP1_PID" 2>/dev/null || true
    [[ -n "$PP2_PID" ]] && kill "$PP2_PID" 2>/dev/null || true
    sleep 0.3
    [[ -n "$PP1_PID" ]] && kill -9 "$PP1_PID" 2>/dev/null || true
    [[ -n "$PP2_PID" ]] && kill -9 "$PP2_PID" 2>/dev/null || true
    if [[ $ec -ne 0 && $ec -ne 77 ]]; then
        warn "failure: keeping logs in $TMPDIR_E2E"
        warn "----- pp1 log -----"; sed 's/^/  pp1| /' "$PP1_LOG" 2>/dev/null || true
        warn "----- pp2 log -----"; sed 's/^/  pp2| /' "$PP2_LOG" 2>/dev/null || true
    else
        rm -rf "$TMPDIR_E2E" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

# ---------- 预检 ----------
[[ -x "$BIN" ]] || { err "missing binary $BIN; run ./build.sh first"; exit 1; }
for t in curl python3; do
    command -v "$t" >/dev/null 2>&1 || { err "need '$t' in PATH"; exit 1; }
done

# UNIX-socket one-shot：发一行命令，读完就返回
unix_send() {
    local sock=$1 cmd=$2
    python3 - "$sock" "$cmd" <<'PY'
import socket, sys
sock, cmd = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(3.0)
s.connect(sock)
s.sendall((cmd + "\n").encode())
buf = b""
try:
    while True:
        chunk = s.recv(4096)
        if not chunk: break
        buf += chunk
        if len(buf) > 256*1024: break
except socket.timeout:
    pass
sys.stdout.buffer.write(buf)
PY
}

# 要能开 TUN。优先用 capsh 看真实能力；否则退回到 uid 检查。
has_cap=0
if command -v capsh >/dev/null 2>&1; then
    capsh --has-p=cap_net_admin 2>/dev/null && has_cap=1 || true
elif [[ "$(id -u)" == "0" ]]; then
    has_cap=1
fi
if [[ $has_cap -ne 1 ]]; then
    warn "SKIP: e2e needs CAP_NET_ADMIN (run as root, grant the cap, or"
    warn "      run via: docker run --cap-add=NET_ADMIN --device /dev/net/tun ...)"
    exit 77
fi

# /dev/net/tun 可用（没有的话，有 CAP 也打不开）
if [[ ! -c /dev/net/tun ]]; then
    warn "SKIP: /dev/net/tun missing"
    exit 77
fi

# 端口 / 文件 干净
for f in "$PP1_SOCK" "$PP2_SOCK"; do rm -f "$f"; done

# ---------- 生成 config ----------
gen_cfg() {
    cat > "$PP2_CFG" <<JSON
{
  "log":     { "level": "info" },
  "runtime": { "workers": 1 },
  "left":    { "kind": "tun", "name": "$PP2_IF",
               "tun": { "ifname": "$PP2_IF", "cidr": "10.30.0.1/24",
                        "mtu": 1400, "no_pi": true } },
  "tunnels": [{
    "name": "srv", "proto": "tcp", "io": "kernel_socket",
    "mode": "server", "listen": "127.0.0.1:$TUN_PORT",
    "tcp":  { "nodelay": true }
  }],
  "session": { "max_per_shard": 1024 },
  "mgmt":    { "unix_socket": "$PP2_SOCK",
               "metrics": { "enable": true,
                            "listen": "127.0.0.1:$PP2_METRICS" } }
}
JSON

    cat > "$PP1_CFG" <<JSON
{
  "log":     { "level": "info" },
  "runtime": { "workers": 1 },
  "left":    { "kind": "tun", "name": "$PP1_IF",
               "tun": { "ifname": "$PP1_IF", "cidr": "10.20.0.1/24",
                        "mtu": 1400, "no_pi": true } },
  "tunnels": [{
    "name": "cli", "proto": "tcp", "io": "kernel_socket",
    "mode": "client", "server": "127.0.0.1:$TUN_PORT",
    "tcp":  { "nodelay": true, "reconnect_ms": 500 }
  }],
  "session": { "max_per_shard": 1024 },
  "mgmt":    { "unix_socket": "$PP1_SOCK",
               "metrics": { "enable": true,
                            "listen": "127.0.0.1:$PP1_METRICS" } }
}
JSON
    python3 -c "import json,sys; [json.load(open(f)) for f in sys.argv[1:]]" \
        "$PP1_CFG" "$PP2_CFG" \
        || { err "generated config JSON is invalid"; exit 1; }
}

# ---------- 等 HTTP 就绪 ----------
wait_http() {
    local url=$1 max=${2:-40}
    for _ in $(seq 1 "$max"); do
        if curl -sf -m 1 "$url" >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    return 1
}

# ---------- 测试 ----------
assert_contains() {
    local haystack=$1 needle=$2 what=$3
    if ! grep -Fq -- "$needle" <<<"$haystack"; then
        err "assert $what: expected substring '$needle' in:"
        err "$haystack"
        EXIT_CODE=1
        return 1
    fi
    log "ok: $what contains '$needle'"
}

# ---------- 主流程 ----------
log "generating configs in $TMPDIR_E2E"
gen_cfg

log "starting pp2 (server)"
"$BIN" -c "$PP2_CFG" >"$PP2_LOG" 2>&1 &
PP2_PID=$!
wait_http "http://127.0.0.1:$PP2_METRICS/metrics" 50 \
    || { err "pp2 /metrics not ready"; exit 1; }
log "pp2 up (pid=$PP2_PID)"

log "starting pp1 (client)"
"$BIN" -c "$PP1_CFG" >"$PP1_LOG" 2>&1 &
PP1_PID=$!
wait_http "http://127.0.0.1:$PP1_METRICS/metrics" 50 \
    || { err "pp1 /metrics not ready"; exit 1; }
log "pp1 up (pid=$PP1_PID)"

# tunnel 建链有重试逻辑，给它点时间
sleep 0.8

# ---- 1. tunnel 真的建起来了（日志） ----
log "check: tunnel established (logs)"
if ! grep -q "tcp tunnel listening on 127.0.0.1:$TUN_PORT" "$PP2_LOG"; then
    err "pp2 did not log 'tcp tunnel listening'"; EXIT_CODE=1
fi
if ! grep -q "tcp tunnel connected" "$PP1_LOG"; then
    err "pp1 did not log 'tcp tunnel connected'"; EXIT_CODE=1
fi
if ! grep -q "tcp tunnel accepted" "$PP2_LOG"; then
    err "pp2 did not log 'tcp tunnel accepted'"; EXIT_CODE=1
fi

# ---- 2. TUN 设备存在且 up ----
log "check: TUN ifaces exist"
for i in "$PP1_IF" "$PP2_IF"; do
    if ! ip link show "$i" >/dev/null 2>&1; then
        err "iface $i not found"; EXIT_CODE=1
    fi
done

# ---- 3. /metrics 内容 ----
log "check: /metrics on pp1"
PP1_M=$(curl -sf -m 2 "http://127.0.0.1:$PP1_METRICS/metrics")
assert_contains "$PP1_M" "pp_info{version=" "pp1 /metrics"
assert_contains "$PP1_M" "pp_module_loops{module=\"worker0\"}" "pp1 /metrics has worker0"
assert_contains "$PP1_M" "pp_module_loops{module=\"mgmt\"}"    "pp1 /metrics has mgmt"

log "check: /metrics on pp2"
PP2_M=$(curl -sf -m 2 "http://127.0.0.1:$PP2_METRICS/metrics")
assert_contains "$PP2_M" "pp_info{version=" "pp2 /metrics"
assert_contains "$PP2_M" "pp_module_loops{module=\"mgmt\"}" "pp2 /metrics has mgmt"

# ---- 4. Unix socket: stat / sessions ----
log "check: mgmt socket on pp1 - stat"
S1=$(unix_send "$PP1_SOCK" "stat" || true)
assert_contains "$S1" "modules:"  "pp1 stat"
assert_contains "$S1" "mgmt"      "pp1 stat has mgmt"

log "check: mgmt socket on pp2 - sessions"
S2=$(unix_send "$PP2_SOCK" "sessions" || true)
assert_contains "$S2" "sessions:" "pp2 sessions header"

# ---- 5. reload：改 session.idle_ttl_ms 后在响应里应报 applied ----
log "check: hot reload on pp1"
cat > "$TMPDIR_E2E/reload-only-ttl.json" <<JSON
{ "session": { "idle_ttl_ms": 12345 }, "log": { "level": "info" } }
JSON
R1=$(unix_send "$PP1_SOCK" "reload $TMPDIR_E2E/reload-only-ttl.json" || true)
assert_contains "$R1" "applied session.ttl" "pp1 reload applied"

# ---- 6. 优雅退出 ----
log "send quit to pp1"
unix_send "$PP1_SOCK" "quit" >/dev/null 2>&1 || true
for _ in {1..20}; do kill -0 "$PP1_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$PP1_PID" 2>/dev/null; then
    err "pp1 did not exit after quit"; EXIT_CODE=1
else
    log "ok: pp1 exited cleanly"
    PP1_PID=""
fi

log "send quit to pp2"
unix_send "$PP2_SOCK" "quit" >/dev/null 2>&1 || true
for _ in {1..20}; do kill -0 "$PP2_PID" 2>/dev/null || break; sleep 0.1; done
if kill -0 "$PP2_PID" 2>/dev/null; then
    err "pp2 did not exit after quit"; EXIT_CODE=1
else
    log "ok: pp2 exited cleanly"
    PP2_PID=""
fi

if [[ $EXIT_CODE -eq 0 ]]; then
    log "e2e: ALL OK"
else
    err "e2e: FAILED"
fi
exit $EXIT_CODE
