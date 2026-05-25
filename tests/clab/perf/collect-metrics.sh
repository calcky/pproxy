#!/usr/bin/env bash
# tests/clab/perf/collect-metrics.sh -- 拉取 leaf1/leaf2 Prometheus metrics，输出 JSON
#
# 用法: collect-metrics.sh [out.json]
# 若省略 out.json 则写到 stdout
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

OUT="${1:-}"

fetch_leaf() {
  local host=$1 port=$2
  leaf_ssh "$host" "curl -sf -m5 http://127.0.0.1:${port}/metrics" 2>/dev/null || echo ""
}

MET1=$(fetch_leaf "$LEAF1_HOST" "$PP1_METRICS")
MET2=$(fetch_leaf "$LEAF2_HOST" "$PP2_METRICS")

python3 - "$MET1" "$MET2" "$OUT" <<'PY'
import json, re, sys

def parse_prom(text):
    out = {}
    for line in (text or "").splitlines():
        if not line or line.startswith("#"):
            continue
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\}\s+([0-9.eE+-]+)$', line)
        if m:
            name, labels, val = m.group(1), m.group(2), float(m.group(3))
            mod = ""
            for part in labels.split(","):
                if part.startswith('module="'):
                    mod = part.split('"')[1]
            key = f"{name}|{mod}" if mod else name
            out[key] = val
            continue
        m = re.match(r'^([a-zA-Z_:][a-zA-Z0-9_:]*)\s+([0-9.eE+-]+)$', line)
        if m:
            out[m.group(1)] = float(m.group(2))
    return out

data = {
    "leaf1": parse_prom(sys.argv[1]),
    "leaf2": parse_prom(sys.argv[2]),
    "raw_len": {"leaf1": len(sys.argv[1]), "leaf2": len(sys.argv[2])},
}
text = json.dumps(data, indent=2)
out_path = sys.argv[3]
if out_path:
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(text)
else:
    print(text)
PY
