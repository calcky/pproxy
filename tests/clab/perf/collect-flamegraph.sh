#!/usr/bin/env bash
# tests/clab/perf/collect-flamegraph.sh -- leaf1/leaf2 perf record + speedscope export
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

OUT_DIR=""
DURATION="${PERF_FLAME_DURATION:-5}"
FREQ="${PERF_FLAME_FREQ:-99}"
DELAY="${PERF_FLAME_DELAY:-1}"
RUN_ID=""
PREPARE_ONLY=0

usage() {
  cat >&2 <<EOF
usage:
  collect-flamegraph.sh --prepare
  collect-flamegraph.sh --out DIR [--run-id ID] [--duration SEC] [--freq HZ] [--delay SEC]
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out=*) OUT_DIR="${1#--out=}" ;;
    --out) OUT_DIR="$2"; shift ;;
    --run-id=*) RUN_ID="${1#--run-id=}" ;;
    --run-id) RUN_ID="$2"; shift ;;
    --duration=*) DURATION="${1#--duration=}" ;;
    --duration) DURATION="$2"; shift ;;
    --freq=*) FREQ="${1#--freq=}" ;;
    --freq) FREQ="$2"; shift ;;
    --delay=*) DELAY="${1#--delay=}" ;;
    --delay) DELAY="$2"; shift ;;
    --prepare) PREPARE_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) perf_err "unknown arg: $1"; usage; exit 1 ;;
  esac
  shift
done

if [[ "$PREPARE_ONLY" -eq 0 ]]; then
  [[ -n "$OUT_DIR" ]] || { usage; exit 1; }
  mkdir -p "$OUT_DIR"
  RUN_ID="${RUN_ID:-$(basename "$OUT_DIR")}"
else
  RUN_ID="${RUN_ID:-prepare}"
fi

remote_prepare() {
  local host=$1
  leaf_ssh "$host" bash -s -- "$UBUNTU_PASS" <<'EOF'
set -euo pipefail
PASS="$1"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
export DEBIAN_FRONTEND=noninteractive
if ! perf --version >/dev/null 2>&1; then
  s apt-get update -qq >/dev/null
  s apt-get install -y -qq linux-tools-common linux-tools-generic linux-tools-$(uname -r) >/dev/null 2>&1 \
    || s apt-get install -y -qq linux-tools-common linux-tools-generic linux-perf >/dev/null 2>&1 \
    || s apt-get install -y -qq linux-tools-common linux-tools-generic >/dev/null
fi
s sysctl -w kernel.perf_event_paranoid=1 >/dev/null 2>&1 || true
s sysctl -w kernel.kptr_restrict=0 >/dev/null 2>&1 || true
perf --version >/dev/null
EOF
}

remote_collect() {
  local host=$1
  leaf_ssh "$host" bash -s -- "$UBUNTU_PASS" "$DURATION" "$FREQ" "$DELAY" "$RUN_ID" <<'EOF'
set -euo pipefail
PASS="$1"
DURATION="$2"
FREQ="$3"
DELAY="$4"
RUN_ID="$5"
s() { printf '%s\n' "$PASS" | sudo -S -p '' "$@"; }
pid="$(pgrep -f '/opt/pproxy/pproxy -c /opt/pproxy/pp' | head -n1 || true)"
work="/tmp/pproxy-perf-${RUN_ID}-$(hostname)"
rm -rf "$work"
mkdir -p "$work"
if [[ -z "$pid" ]]; then
  python3 - "$work" <<'PY'
import json, socket, sys
from pathlib import Path
work = Path(sys.argv[1])
(work / "summary.json").write_text(json.dumps({
    "host": socket.gethostname(),
    "error": "pproxy pid not found",
    "samples": 0,
}, indent=2) + "\n", encoding="utf-8")
PY
  tar -C "$work" -czf "$work.tgz" .
  printf '%s\n' "$work.tgz"
  exit 0
fi
sleep "$DELAY"
s perf record -F "$FREQ" -g --call-graph dwarf -p "$pid" -o "$work/perf.data" -- sleep "$DURATION" \
  >"$work/perf-record.log" 2>&1 || true
if [[ -s "$work/perf.data" ]]; then
  s perf script -i "$work/perf.data" >"$work/perf.script" 2>"$work/perf-script.log" || true
fi
samples=0
if [[ -s "$work/perf.script" ]]; then
  samples="$(awk 'BEGIN{n=0} /^[^[:space:]]/{n++} END{print n}' "$work/perf.script" 2>/dev/null || echo 0)"
fi
python3 - "$work" "$pid" "$DURATION" "$FREQ" "$samples" <<'PY'
import json, socket, sys
from pathlib import Path
work = Path(sys.argv[1])
out = {
    "host": socket.gethostname(),
    "pid": int(sys.argv[2]),
    "duration_sec": float(sys.argv[3]),
    "freq_hz": float(sys.argv[4]),
    "samples": int(float(sys.argv[5] or 0)),
    "files": {
        "perf_data": "perf.data",
        "perf_script": "perf.script",
        "perf_record_log": "perf-record.log",
        "perf_script_log": "perf-script.log",
    },
}
if not (work / "perf.script").is_file():
    out["error"] = "perf script not generated"
(work / "summary.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
PY
s chown -R "$(id -u):$(id -g)" "$work" 2>/dev/null || true
tar -C "$work" -czf "$work.tgz" .
printf '%s\n' "$work.tgz"
EOF
}

fetch_leaf() {
  local label=$1
  local host=$2
  local leaf_dir="$OUT_DIR/$label"
  mkdir -p "$leaf_dir"
  perf_log "flamegraph: recording ${label} (${host}) ${DURATION}s @ ${FREQ}Hz"
  local remote_tgz
  remote_tgz="$(remote_collect "$host" | tail -n1)"
  if [[ -z "$remote_tgz" ]]; then
    perf_err "flamegraph: remote collection failed on ${label}"
    return 1
  fi
  sshpass -p "$UBUNTU_PASS" scp "${SSH_OPTS[@]}" -q \
    "${UBUNTU_USER}@${host}:${remote_tgz}" "$leaf_dir/raw.tgz"
  tar -xzf "$leaf_dir/raw.tgz" -C "$leaf_dir"
  if [[ -s "$leaf_dir/perf.script" ]]; then
    python3 "$PERF_DIR/perf-to-speedscope.py" \
      --input "$leaf_dir/perf.script" \
      --output "$leaf_dir/${label}.speedscope.json" \
      --name "${RUN_ID} ${label}" \
      --sample-rate "$FREQ" > "$leaf_dir/speedscope-summary.json"
  fi
  leaf_ssh "$host" "rm -f '$remote_tgz'; rm -rf '${remote_tgz%.tgz}'" >/dev/null 2>&1 || true
}

if [[ "$PREPARE_ONLY" -eq 1 ]]; then
  perf_log "flamegraph: preparing perf on leaf1 + leaf2"
  remote_prepare "$LEAF1_HOST" &
  PID1=$!
  remote_prepare "$LEAF2_HOST" &
  PID2=$!
  RC=0
  wait "$PID1" || RC=1
  wait "$PID2" || RC=1
  exit "$RC"
fi

fetch_leaf leaf1 "$LEAF1_HOST" &
PID1=$!
fetch_leaf leaf2 "$LEAF2_HOST" &
PID2=$!
RC=0
wait "$PID1" || RC=1
wait "$PID2" || RC=1

python3 - "$OUT_DIR" "$RUN_ID" "$DURATION" "$FREQ" <<'PY'
import json, sys
from pathlib import Path
out_dir = Path(sys.argv[1])
manifest = {
    "run_id": sys.argv[2],
    "duration_sec": float(sys.argv[3]),
    "freq_hz": float(sys.argv[4]),
    "viewer": "https://www.speedscope.app/",
    "leaves": {},
}
for leaf in ("leaf1", "leaf2"):
    d = out_dir / leaf
    item = {}
    for name in ("summary.json", "speedscope-summary.json"):
        p = d / name
        if p.is_file():
            item[name.removesuffix(".json")] = json.loads(p.read_text(encoding="utf-8"))
    sp = d / f"{leaf}.speedscope.json"
    if sp.is_file():
        item["speedscope"] = str(sp.relative_to(out_dir))
    item["perf_script"] = str((d / "perf.script").relative_to(out_dir)) if (d / "perf.script").is_file() else ""
    item["perf_data"] = str((d / "perf.data").relative_to(out_dir)) if (d / "perf.data").is_file() else ""
    manifest["leaves"][leaf] = item
(out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
readme = [
    f"# pproxy perf flamegraphs: {sys.argv[2]}",
    "",
    "Open `leaf1/leaf1.speedscope.json` and `leaf2/leaf2.speedscope.json` with https://www.speedscope.app/.",
    "GitHub artifact preview can show the JSON directly; download the artifact for interactive speedscope viewing.",
    "",
]
(out_dir / "README.md").write_text("\n".join(readme), encoding="utf-8")
PY

exit "$RC"
