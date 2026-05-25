#!/usr/bin/env bash
# tests/clab/perf.sh -- clab 性能测试主入口
#
# 用法:
#   ./tests/clab/perf.sh --scenario udp_uring_batch32
#   ./tests/clab/perf.sh --ci                    # 跑 scenarios.yaml 中 ci:true
#   ./tests/clab/perf.sh --matrix              # 全后端（lab 只 deploy 一次，后端切换 --pproxy-only）
#   ./tests/clab/perf.sh --sweep batch_tx=1,8,32,64 --right-io=io_uring
#   ./tests/clab/perf.sh --baseline direct       # 无 pproxy 基线
#   ./tests/clab/perf.sh --scenario udp_uring_batch32 --skip-deploy  # 已 deploy
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")/perf" && pwd)"
CLAB_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=perf/common.sh
source "$PERF_DIR/common.sh"

SKIP_DEPLOY=0
SKIP_BUILD=0
CI_MODE=0
MATRIX=0
MATRIX_LAB_UP=0
MATRIX_MD=""
SWEEP_VAR=""
SWEEP_VALS=""
SCENARIO=""
BASELINE=""
FAIL_ON_THRESHOLD=0
UPDATE_DOC=0
EXTRA_DEPLOY=()

usage() {
  sed -n '3,12p' "$0" | sed 's/^# \?//;s/^#//'
  exit "${1:-0}"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scenario=*) SCENARIO="${1#--scenario=}" ;;
    --scenario)   SCENARIO="$2"; shift ;;
    --ci)         CI_MODE=1 ;;
    --matrix)     MATRIX=1 ;;
    --sweep)      SWEEP_VAR="${2%%=*}"; SWEEP_VALS="${2#*=}"; shift ;;
    --right-io=*) EXTRA_DEPLOY+=(--right-io="${1#--right-io=}") ;;
    --baseline)   BASELINE="$2"; shift ;;
    --skip-deploy) SKIP_DEPLOY=1 ;;
    --skip-build)  SKIP_BUILD=1 ;;
    --fail-on-threshold) FAIL_ON_THRESHOLD=1 ;;
    --update-doc)  UPDATE_DOC=1 ;;
    -h|--help)    usage 0 ;;
    *)            perf_err "unknown arg: $1"; usage 1 ;;
  esac
  shift
done

chmod +x "$PERF_DIR"/run-iperf.sh "$PERF_DIR"/collect-metrics.sh "$PERF_DIR"/collect-cpu.sh \
  "$PERF_DIR"/check-tunnel.sh "$PERF_DIR"/baseline-direct.sh "$PERF_DIR"/cleanup.sh 2>/dev/null || true
mkdir -p "$RESULTS_DIR"
ensure_python_yaml || exit 1
perf_cleanup_stale

list_scenarios() {
  python3 - "$SCENARIOS_FILE" <<'PY'
import sys, yaml
for s in yaml.safe_load(open(sys.argv[1], encoding='utf-8')):
    print(s['name'])
PY
}

list_ci_scenarios() {
  python3 - "$SCENARIOS_FILE" <<'PY'
import sys, yaml
for s in yaml.safe_load(open(sys.argv[1], encoding='utf-8')):
    if s.get('ci'):
        print(s['name'])
PY
}

matrix_scenarios() {
  python3 - "$SCENARIOS_FILE" <<'PY'
import sys, yaml
want = {'udp_kernel','udp_uring_batch32','udp_af_xdp','udp_netmap','udp_dpdk'}
for s in yaml.safe_load(open(sys.argv[1], encoding='utf-8')):
    if s['name'] in want:
        print(s['name'])
PY
}

run_baseline_direct() {
  perf_log "baseline mode: direct (no pproxy)"
  if [[ "$SKIP_DEPLOY" -eq 0 ]]; then
    deploy_args=(--no-pproxy)
    deploy_args+=("${EXTRA_DEPLOY[@]}")
    [[ $SKIP_BUILD -eq 1 ]] && export PPROXY_SKIP_BUILD=1
    "$CLAB_DIR/deploy.sh" "${deploy_args[@]}"
  fi
  "$PERF_DIR/baseline-direct.sh"
  for par in 1 10; do
    perf_log "baseline iperf3: tcp -P ${par} -t 10s"
    IPERF_TMP=$(mktemp)
    IPERF_PROTO=tcp IPERF_WARMUP=2 IPERF_DURATION=10 IPERF_PARALLEL="$par" \
      "$PERF_DIR/run-iperf.sh" > "$IPERF_TMP"
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_baseline_direct_p${par}"
    OUT="$RESULTS_DIR/${RUN_ID}.json"
    python3 "$PERF_DIR/report.py" \
      --scenario baseline_direct \
      --deploy-json "{\"mode\":\"direct\",\"parallel\":$par}" \
      --iperf "$IPERF_TMP" \
      --metrics-before "$PERF_DIR/empty_metrics.json" \
      --metrics-after "$PERF_DIR/empty_metrics.json" \
      --out "$OUT" \
      --mode direct \
      --iperf-proto tcp \
      --thresholds-json '{}'
    rm -f "$IPERF_TMP"
    perf_log "wrote $OUT"
  done
}

run_one_scenario() {
  local name=$1
  local overlay_extra="${2:-}"

  perf_log "=== scenario: $name ==="
  local cfg_dir
  cfg_dir=$(mktemp -d)
  trap 'rm -rf "$cfg_dir"' RETURN

  local meta_json
  meta_json=$(
    python3 "$PERF_DIR/prepare_cfg.py" \
      --scenario-file "$SCENARIOS_FILE" \
      --scenario "$name" \
      --out-dir "$cfg_dir" \
      ${overlay_extra:+--overlay-extra "$overlay_extra"} 2>/dev/null \
      || python3 "$PERF_DIR/prepare_cfg.py" \
           --scenario-file "$SCENARIOS_FILE" \
           --scenario "$name" \
           --out-dir "$cfg_dir"
  )

  if [[ -n "$overlay_extra" ]]; then
    PERF_DIR="$PERF_DIR" python3 - "$cfg_dir" "$overlay_extra" <<'PY'
import json, sys, os, importlib.util
from pathlib import Path
perf = Path(os.environ['PERF_DIR'])
spec = importlib.util.spec_from_file_location('ao', perf / 'apply_overlay.py')
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
cfg = Path(sys.argv[1])
extra = json.loads(sys.argv[2])
for p in cfg.glob('pp*.json'):
    doc = json.loads(p.read_text(encoding='utf-8'))
    p.write_text(json.dumps(mod.apply_overlay(doc, extra), indent=2) + '\n', encoding='utf-8')
PY
    meta_json=$(python3 - "$cfg_dir/scenario.meta.json" "$overlay_extra" <<'PY'
import json, sys
meta = json.load(open(sys.argv[1], encoding='utf-8'))
meta['overlay'].update(json.loads(sys.argv[2]))
print(json.dumps(meta))
PY
)
  fi

  local deploy tunnel left right
  deploy=$(python3 -c "import json,sys; m=json.loads(sys.argv[1]); d=m['deploy']; print(d.get('tunnel','udp'), d.get('left_io','tun'), d.get('right_io','kernel_socket'))" "$meta_json")
  read -r tunnel left right <<< "$deploy"

  if [[ "$SKIP_DEPLOY" -eq 0 ]]; then
    local deploy_args=(--tunnel="$tunnel" --left-io="$left" --right-io="$right")
    deploy_args+=("${EXTRA_DEPLOY[@]}")
    if [[ "$MATRIX" -eq 1 || "$CI_MODE" -eq 1 ]]; then
      if [[ "$MATRIX_LAB_UP" -eq 0 ]]; then
        deploy_args+=(--matrix-prep)
        MATRIX_LAB_UP=1
        perf_log "lab bootstrap: full deploy + all backend deps (once)"
        # bootstrap 需要全后端二进制；忽略 --skip-build
        SKIP_BUILD=0
        unset PPROXY_SKIP_BUILD
      else
        deploy_args+=(--pproxy-only)
        perf_log "reconfig: push cfg + restart pproxy (--pproxy-only)"
        [[ $SKIP_BUILD -eq 1 ]] && export PPROXY_SKIP_BUILD=1
      fi
    else
      [[ $SKIP_BUILD -eq 1 ]] && export PPROXY_SKIP_BUILD=1
    fi
    PPROXY_SKIP_SMOKE=1 \
    PPROXY_CFG_DIR="$cfg_dir" \
      "$CLAB_DIR/deploy.sh" "${deploy_args[@]}"
  fi

  perf_wait_connectivity 60

  EXPECT_PROTO="$tunnel" EXPECT_LEFT="$left" EXPECT_RIGHT="$right"
  perf_check_tunnel 15 || return 1

  local traffic thresholds traffic_proto traffic_duration traffic_warmup
  traffic=$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]).get('traffic',{})))" "$meta_json")
  thresholds=$(python3 -c "import json,sys; print(json.dumps(json.loads(sys.argv[1]).get('thresholds',{})))" "$meta_json")
  read -r traffic_proto traffic_duration traffic_warmup <<< "$(python3 -c "
import json, sys
t = json.loads(sys.argv[1])
print(t.get('proto', 'tcp'), t.get('duration', 10), t.get('warmup', 2))
" "$traffic")"
  mapfile -t PARALLEL_RUNS < <(python3 -c "
import json, sys
t = json.loads(sys.argv[1])
runs = t.get('parallel_runs')
if runs:
    print('\n'.join(str(x) for x in runs))
else:
    print(t.get('parallel', 1))
" "$traffic")

  local met_before met_cur met_after
  met_before=$(mktemp)
  met_cur=$(mktemp)
  "$PERF_DIR/collect-metrics.sh" "$met_before"
  cp "$met_before" "$met_cur"

  local deploy_meta batch_tx
  batch_tx=$(python3 -c "import json,sys; print(json.loads(sys.argv[1]).get('overlay',{}).get('tunnels[0].io_cfg.batch_tx',''))" "$meta_json")

  local par rc=0
  for par in "${PARALLEL_RUNS[@]}"; do
    perf_log "iperf3: ${traffic_proto} -P ${par} -t ${traffic_duration}s"
    local iperf_out met_run_after cpu_out
    iperf_out=$(mktemp)
    met_run_after=$(mktemp)
    cpu_out=$(mktemp)
    export IPERF_PROTO="$traffic_proto"
    export IPERF_DURATION="$traffic_duration"
    export IPERF_PARALLEL="$par"
    export IPERF_WARMUP="$traffic_warmup"
    export IPERF_CPU_OUT="$cpu_out"

    "$PERF_DIR/run-iperf.sh" > "$iperf_out"
    "$PERF_DIR/collect-metrics.sh" "$met_run_after"

    deploy_meta=$(python3 -c "import json; print(json.dumps({'tunnel':'$tunnel','left_io':'$left','right_io':'$right','batch_tx':'$batch_tx','parallel':int('$par'),'duration':int('$traffic_duration')}))")
    RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)_${name}_p${par}"
    OUT="$RESULTS_DIR/${RUN_ID}.json"
    local report_args=(
      --scenario "$name"
      --deploy-json "$deploy_meta"
      --iperf "$iperf_out"
      --metrics-before "$met_cur"
      --metrics-after "$met_run_after"
      --cpu "$cpu_out"
      --out "$OUT"
      --thresholds-json "$thresholds"
      --iperf-proto "$traffic_proto"
    )
    [[ "$FAIL_ON_THRESHOLD" -eq 1 ]] && report_args+=(--fail-on-threshold)
    [[ "$UPDATE_DOC" -eq 1 ]] && report_args+=(--update-doc "$REPO_ROOT/doc/perf.md")
    [[ -n "$MATRIX_MD" ]] && report_args+=(--matrix-md "$MATRIX_MD")

    python3 "$PERF_DIR/report.py" "${report_args[@]}" || rc=1
    rm -f "$iperf_out" "$cpu_out"
    cp "$met_run_after" "$met_cur"
    rm -f "$met_run_after"
    perf_log "wrote $OUT"
  done

  rm -f "$met_before" "$met_cur"
  return "$rc"
}

# empty metrics for baseline report
if [[ ! -f "$PERF_DIR/empty_metrics.json" ]]; then
  echo '{"leaf1":{},"leaf2":{}}' > "$PERF_DIR/empty_metrics.json"
fi

if [[ -n "$BASELINE" ]]; then
  [[ "$BASELINE" == "direct" ]] || { perf_err "unknown baseline: $BASELINE"; exit 1; }
  run_baseline_direct
  exit 0
fi

SCENARIOS_TO_RUN=()
if [[ "$CI_MODE" -eq 1 ]]; then
  mapfile -t SCENARIOS_TO_RUN < <(list_ci_scenarios)
elif [[ "$MATRIX" -eq 1 ]]; then
  mapfile -t SCENARIOS_TO_RUN < <(matrix_scenarios)
elif [[ -n "$SWEEP_VAR" && -n "$SWEEP_VALS" ]]; then
  base="${SCENARIO:-udp_uring_batch32}"
  IFS=',' read -ra vals <<< "$SWEEP_VALS"
  for v in "${vals[@]}"; do
    SCENARIOS_TO_RUN+=("${base}__${SWEEP_VAR}_${v}")
  done
elif [[ -n "$SCENARIO" ]]; then
  SCENARIOS_TO_RUN=("$SCENARIO")
else
  perf_err "specify --scenario, --ci, --matrix, --sweep, or --baseline"
  usage 1
fi

if [[ "$MATRIX" -eq 1 ]]; then
  MATRIX_MD="$RESULTS_DIR/matrix_$(date -u +%Y%m%dT%H%M%SZ).md"
  perf_log "matrix markdown → $MATRIX_MD"
fi

FAIL=0
for item in "${SCENARIOS_TO_RUN[@]}"; do
  if [[ "$item" == *"__"* ]]; then
    base="${item%%__*}"
    rest="${item#*__}"
    key="${rest%%_*}"
    val="${rest#*_}"
    overlay=$(python3 -c "import json; k='tunnels[0].io_cfg.${SWEEP_VAR}'; v='${v}'; print(json.dumps({k: int(v) if v.isdigit() else v}))")
    run_one_scenario "$base" "$overlay" || FAIL=1
  else
    run_one_scenario "$item" || FAIL=1
  fi
done

exit "$FAIL"
