#!/usr/bin/env bash
# tests/clab/perf/cleanup.sh -- 跑 perf 前清理残留进程（可单独执行）
set -euo pipefail

PERF_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=common.sh
source "$PERF_DIR/common.sh"

perf_cleanup_stale "$@"
