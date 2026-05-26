#!/usr/bin/env bash
# tests/clab/perf/collect-cpu.sh -- iperf 正式跑窗口 CPU 快照（起/止各一次）
#
# 用法:
#   collect-cpu.sh --begin state.json          # iperf 正式跑开始前
#   collect-cpu.sh --end state.json --duration SEC --out cpu.json  # iperf 结束后
#
# 输出 JSON（每 leaf）:
#   pproxy.total_per_core_pct — 进程树单核基准 %（可 >100%）
#   system.user_pct / system_pct / softirq_pct / idle_pct — 整段窗口 /proc/stat 占比
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

BEGIN=""
END=""
DURATION=0
OUT=""
MODE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --begin=*) BEGIN="${1#--begin=}"; MODE=begin ;;
    --begin)   BEGIN="$2"; MODE=begin; shift ;;
    --end=*)   END="${1#--end=}"; MODE=end ;;
    --end)     END="$2"; MODE=end; shift ;;
    --duration=*) DURATION="${1#--duration=}" ;;
    --duration)   DURATION="$2"; shift ;;
    --out=*)   OUT="${1#--out=}" ;;
    --out)     OUT="$2"; shift ;;
    *) perf_err "unknown arg: $1"; exit 1 ;;
  esac
  shift
done

case "$MODE" in
  begin)
    [[ -n "$BEGIN" ]] || { perf_err "usage: collect-cpu.sh --begin state.json"; exit 1; }
    ;;
  end)
    [[ -n "$END" && -n "$OUT" && "$DURATION" -gt 0 ]] || {
      perf_err "usage: collect-cpu.sh --end state.json --duration SEC --out cpu.json"
      exit 1
    }
    [[ -f "$END" ]] || { perf_err "begin state not found: $END"; exit 1; }
    ;;
  *)
    perf_err "usage: collect-cpu.sh --begin state.json | --end state.json --duration SEC --out cpu.json"
    exit 1
    ;;
esac

snap_leaf() {
  local host=$1
  leaf_ssh "$host" "python3 -" <<'PY'
import json, os, subprocess, sys

try:
    import psutil
except ImportError:
    psutil = None

hz = os.sysconf("SC_CLK_TCK") or 100
ncpu = psutil.cpu_count(logical=True) if psutil else (os.cpu_count() or 1)


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


def family_pids_proc(root):
    pids = {root}
    by_ppid = {}
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        try:
            with open(f"/proc/{name}/stat", encoding="utf-8") as f:
                parts = f.read().split()
            by_ppid.setdefault(int(parts[3]), []).append(int(name))
        except OSError:
            continue
    stack = [root]
    while stack:
        p = stack.pop()
        for child in by_ppid.get(p, ()):
            if child not in pids:
                pids.add(child)
                stack.append(child)
    return pids


def family_pids(root):
    if psutil:
        try:
            proc = psutil.Process(root)
            pids = {root}
            for child in proc.children(recursive=True):
                try:
                    pids.add(child.pid)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
            return pids
        except psutil.NoSuchProcess:
            return {root}
    return family_pids_proc(root)


def family_cpu_times_sec(pids):
    total_u = total_s = 0.0
    if psutil:
        for pid in pids:
            try:
                t = psutil.Process(pid).cpu_times()
                total_u += t.user
                total_s += t.system
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return total_u, total_s
    for pid in pids:
        try:
            with open(f"/proc/{pid}/stat", encoding="utf-8") as f:
                parts = f.read().split()
            total_u += int(parts[13]) / hz
            total_s += int(parts[14]) / hz
        except OSError:
            continue
    return total_u, total_s


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

pids = family_pids(pid)
fam_u, fam_s = family_cpu_times_sec(pids)
sys_cpu = read_system_cpu()
if not sys_cpu:
    print(json.dumps({"error": "read /proc/stat failed", "pid": pid}))
    sys.exit(0)

print(json.dumps({
    "pid": pid,
    "ncpu": ncpu,
    "child_pids": max(0, len(pids) - 1),
    "fam_user_sec": fam_u,
    "fam_sys_sec": fam_s,
    "system": sys_cpu,
    "threads": thread_jiffies(pid),
}, indent=2))
PY
}

LEAF1_TMP=$(mktemp)
LEAF2_TMP=$(mktemp)
trap 'rm -f "$LEAF1_TMP" "$LEAF2_TMP"' EXIT

snap_leaf "$LEAF1_HOST" >"$LEAF1_TMP" &
PID1=$!
snap_leaf "$LEAF2_HOST" >"$LEAF2_TMP" &
PID2=$!
wait "$PID1" "$PID2"

if [[ "$MODE" == "begin" ]]; then
  python3 - "$LEAF1_TMP" "$LEAF2_TMP" "$BEGIN" <<'PY'
import json, sys
from pathlib import Path

def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))

out = {"leaf1": load(sys.argv[1]), "leaf2": load(sys.argv[2])}
Path(sys.argv[3]).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
PY
  exit 0
fi

python3 - "$END" "$LEAF1_TMP" "$LEAF2_TMP" "$DURATION" "$OUT" <<'PY'
import json, sys
from pathlib import Path

duration = float(sys.argv[4])
begin = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
end_leaf1 = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
end_leaf2 = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
end = {"leaf1": end_leaf1, "leaf2": end_leaf2}

SYS_KEYS = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
SYS_LABEL = {
    "user": "user_pct", "nice": "nice_pct", "system": "system_pct",
    "idle": "idle_pct", "iowait": "iowait_pct", "irq": "irq_pct",
    "softirq": "softirq_pct", "steal": "steal_pct",
}


def system_pcts(prev, cur):
    deltas = {k: max(0, cur[k] - prev.get(k, cur[k])) for k in SYS_KEYS}
    total = sum(deltas.values()) or 1
    return {SYS_LABEL[k]: round(deltas[k] / total * 100.0, 2) for k in SYS_KEYS}


def leaf_result(b, e):
    if b.get("error") or e.get("error"):
        return e if e.get("error") else b
    hz = 100  # thread jiffies only used relatively
    ncpu = int(e.get("ncpu") or b.get("ncpu") or 1)
    du = max(0.0, float(e["fam_user_sec"]) - float(b["fam_user_sec"]))
    ds = max(0.0, float(e["fam_sys_sec"]) - float(b["fam_sys_sec"]))
    u_pc = du / duration * 100.0
    s_pc = ds / duration * 100.0
    pproxy = {
        "user_per_core_pct": round(u_pc, 2),
        "sys_per_core_pct": round(s_pc, 2),
        "total_per_core_pct": round(u_pc + s_pc, 2),
        "user_pct": round(u_pc, 2),
        "sys_pct": round(s_pc, 2),
        "total_pct": round(u_pc + s_pc, 2),
    }
    threads = {}
    thr_b = b.get("threads") or {}
    thr_e = e.get("threads") or {}
    for comm in set(thr_b) | set(thr_e):
        delta = max(0, int(thr_e.get(comm, 0)) - int(thr_b.get(comm, 0)))
        threads[comm] = round((delta / hz) / ncpu / duration * 100.0, 2)
    return {
        "pid": e.get("pid", b.get("pid")),
        "ncpu": ncpu,
        "samples": 1,
        "duration_sec": duration,
        "child_pids": e.get("child_pids", 0),
        "process_cpu_avg_pct": pproxy["total_per_core_pct"],
        "pproxy": pproxy,
        "system": system_pcts(b.get("system") or {}, e.get("system") or {}),
        "threads": dict(sorted(threads.items())),
    }

out = {
    "leaf1": leaf_result(begin.get("leaf1") or {}, end["leaf1"]),
    "leaf2": leaf_result(begin.get("leaf2") or {}, end["leaf2"]),
}
Path(sys.argv[5]).write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
PY
