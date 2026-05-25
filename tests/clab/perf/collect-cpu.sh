#!/usr/bin/env bash
# tests/clab/perf/collect-cpu.sh -- iperf 窗口内采样 leaf CPU
#
# 输出 JSON（每 leaf）:
#   pproxy.total_pct / user_pct / sys_pct  — 进程占用（/proc/pid/stat utime/stime）
#   threads                                 — pproxy 各线程
#   system.user_pct / nice_pct / sys_pct / irq_pct / softirq_pct / idle_pct / ...
#
# 用法: collect-cpu.sh --duration SEC --out cpu.json
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

DURATION=0
OUT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --duration=*) DURATION="${1#--duration=}" ;;
    --duration)   DURATION="$2"; shift ;;
    --out=*)      OUT="${1#--out=}" ;;
    --out)        OUT="$2"; shift ;;
    *) perf_err "unknown arg: $1"; exit 1 ;;
  esac
  shift
done

[[ "$DURATION" -gt 0 && -n "$OUT" ]] || {
  perf_err "usage: collect-cpu.sh --duration SEC --out file.json"
  exit 1
}

sample_leaf() {
  local host=$1
  leaf_ssh "$host" "python3 -" "$DURATION" <<'PY'
import json, os, subprocess, sys, time

duration = int(sys.argv[1])
hz = os.sysconf("SC_CLK_TCK") or 100
ncpu = os.cpu_count() or 1


def find_pproxy_pid():
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", r"/opt/pproxy/pproxy -c /opt/pproxy/pp"],
            text=True,
        ).strip()
    except subprocess.CalledProcessError:
        return None
    pids = [p for p in out.splitlines() if p]
    return int(pids[0]) if pids else None


def read_system_cpu():
    with open("/proc/stat", encoding="utf-8") as f:
        for line in f:
            if line.startswith("cpu "):
                p = line.split()
                return {
                    "user": int(p[1]),
                    "nice": int(p[2]),
                    "system": int(p[3]),
                    "idle": int(p[4]),
                    "iowait": int(p[5]),
                    "irq": int(p[6]),
                    "softirq": int(p[7]),
                    "steal": int(p[8]) if len(p) > 8 else 0,
                }
    return None


def system_pcts(prev, cur):
    keys = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
    deltas = {k: max(0, cur[k] - prev.get(k, cur[k])) for k in keys}
    total = sum(deltas.values()) or 1
    out = {}
    for k in keys:
        out[f"{k}_pct"] = round(deltas[k] / total * 100.0, 2)
    return out


def proc_jiffies(pid):
    with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
        parts = f.read().split()
    return int(parts[13]), int(parts[14])


def thread_jiffies(pid):
    totals = {}
    for tid in os.listdir(f"/proc/{pid}/task"):
        try:
            with open(f"/proc/{pid}/task/{tid}/comm", encoding="utf-8") as f:
                comm = f.read().strip()
            with open(f"/proc/{pid}/task/{tid}/stat", encoding="utf-8") as f:
                parts = f.read().split()
            if len(parts) < 15:
                continue
            j = int(parts[13]) + int(parts[14])
            totals[comm] = totals.get(comm, 0) + j
        except OSError:
            continue
    return totals


pid = find_pproxy_pid()
if not pid:
    print(json.dumps({"error": "pproxy pid not found"}))
    sys.exit(0)

sys_prev = read_system_cpu()
proc_u_prev, proc_s_prev = proc_jiffies(pid)
thr_prev = thread_jiffies(pid)
time.sleep(0.5)
sys_prev = read_system_cpu()
proc_u_prev, proc_s_prev = proc_jiffies(pid)
thr_prev = thread_jiffies(pid)

samples = 0
proc_total_sum = 0.0
proc_user_sum = 0.0
proc_sys_sum = 0.0
thread_sum = {}
sys_sum = {k: 0.0 for k in (
    "user_pct", "nice_pct", "system_pct", "idle_pct",
    "iowait_pct", "irq_pct", "softirq_pct", "steal_pct",
)}

for _ in range(duration):
    time.sleep(1.0)
    sys_cur = read_system_cpu()
    if not sys_cur:
        continue
    proc_u, proc_s = proc_jiffies(pid)
    thr_cur = thread_jiffies(pid)
    if not thr_cur:
        continue

    samples += 1
    du = max(0, proc_u - proc_u_prev)
    ds = max(0, proc_s - proc_s_prev)
    proc_user_sum += (du / hz) / ncpu * 100.0
    proc_sys_sum += (ds / hz) / ncpu * 100.0
    proc_total_sum += ((du + ds) / hz) / ncpu * 100.0
    proc_u_prev, proc_s_prev = proc_u, proc_s

    for comm, j in thr_cur.items():
        delta = max(0, j - thr_prev.get(comm, j))
        pct = (delta / hz) / ncpu * 100.0
        thread_sum[comm] = thread_sum.get(comm, 0.0) + pct
    thr_prev = thr_cur

    sp = system_pcts(sys_prev, sys_cur)
    for k, v in sp.items():
        sys_sum[k] = sys_sum.get(k, 0.0) + v
    sys_prev = sys_cur

if samples == 0:
    print(json.dumps({"error": "no samples", "pid": pid}))
    sys.exit(0)

threads_avg = {k: round(v / samples, 2) for k, v in sorted(thread_sum.items())}
system_avg = {k: round(v / samples, 2) for k, v in sys_sum.items()}
pproxy_avg = {
    "total_pct": round(proc_total_sum / samples, 2),
    "user_pct": round(proc_user_sum / samples, 2),
    "sys_pct": round(proc_sys_sum / samples, 2),
}

print(json.dumps({
    "pid": pid,
    "ncpu": ncpu,
    "samples": samples,
    "process_cpu_avg_pct": pproxy_avg["total_pct"],
    "pproxy": pproxy_avg,
    "system": system_avg,
    "threads": threads_avg,
}, indent=2))
PY
}

LEAF1_TMP=$(mktemp)
LEAF2_TMP=$(mktemp)
trap 'rm -f "$LEAF1_TMP" "$LEAF2_TMP"' EXIT

sample_leaf "$LEAF1_HOST" >"$LEAF1_TMP" &
PID1=$!
sample_leaf "$LEAF2_HOST" >"$LEAF2_TMP" &
PID2=$!
wait "$PID1" "$PID2"

LEAF1_JSON=$(cat "$LEAF1_TMP")
LEAF2_JSON=$(cat "$LEAF2_TMP")

python3 - "$LEAF1_JSON" "$LEAF2_JSON" "$OUT" <<'PY'
import json, sys
leaf1 = json.loads(sys.argv[1] or "{}")
leaf2 = json.loads(sys.argv[2] or "{}")
out = {"leaf1": leaf1, "leaf2": leaf2}
with open(sys.argv[3], "w", encoding="utf-8") as f:
    json.dump(out, f, indent=2)
PY
