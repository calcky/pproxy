# pproxy 性能基线（clab）

在 **CPC** 上、**不经过 pproxy** 时，用 **iperf3** 测得吞吐约 **2.8 Gbit/s**，用作有/无 pproxy 对比的参考基线。

## clab 性能测试框架

拓扑与部署见 [`tests/clab/deploy.sh`](../tests/clab/deploy.sh)。性能脚本在 `tests/clab/perf/`：

| 脚本 | 作用 |
|------|------|
| [`tests/clab/perf.sh`](../tests/clab/perf.sh) | 主入口：deploy → iperf3 → metrics → JSON 结果 |
| [`tests/clab/perf/scenarios.yaml`](../tests/clab/perf/scenarios.yaml) | 场景矩阵（后端、batch_tx、阈值） |
| [`tests/clab/perf/run-iperf.sh`](../tests/clab/perf/run-iperf.sh) | client1 → client2 iperf3（JSON） |
| [`tests/clab/perf/collect-metrics.sh`](../tests/clab/perf/collect-metrics.sh) | leaf metrics 快照 |
| [`tests/clab/perf/baseline-direct.sh`](../tests/clab/perf/baseline-direct.sh) | 停 pproxy、恢复 WAN 路由的直连基线 |
| [`tests/clab/perf/report.py`](../tests/clab/perf/report.py) | 合并结果 → `tests/clab/results/*.json` |
| [`tests/clab/perf/check-tunnel.sh`](../tests/clab/perf/check-tunnel.sh) | iperf 前校验 tunnel ready / proto / io |
| [`tests/clab/perf/collect-cpu.sh`](../tests/clab/perf/collect-cpu.sh) | 正式 iperf 起/止 CPU 快照 |

当前已整理的全后端样例报告：

- [`tests/clab/reports/20260703-matrix-flame.md`](../tests/clab/reports/20260703-matrix-flame.md)：matrix + leaf1/leaf2 perf speedscope 链接
- [`tests/clab/reports/20260702-matrix.md`](../tests/clab/reports/20260702-matrix.md)：matrix 基线报告

这些报告覆盖 `kernel_socket`、`io_uring`、`af_xdp`、`netmap`、`dpdk`、`memif`。

### iperf3 参数

- 协议：**TCP only**（`-P` 并行流，非 UDP）
- 时长：**10s**（warmup **2s**）
- 每个场景跑 **单流（-P 1）** 和 **10 并行流（-P 10）**
- 吞吐取接收端 `sum_received`（goodput）
- 结果 JSON 含 **CPU 占用**（正式 iperf 窗口起止快照：pproxy 单核基准 usr/sys、sys 的 us/sy/si/id、各线程）与 **metrics delta**
- `--matrix` 时每组 iperf 结果追加到 `tests/clab/results/matrix_<timestamp>.md`（列：scenario / right_io / P / Mbps / PPS / L1·L2 各 pp、sys、core-us）
- **L1/L2 sys**：正式 iperf 窗口 `/proc/stat` 占比，仅 `us sy si id`（四项之和 ≤ 100%）
- **PPS**：两 leaf `right_tx` 计数之和 ÷ iperf 时长（tunnel 发包速率）
- **core-us**：pproxy 进程树 core-µs/包（`pp_abs × 10⁶ / worker_pps`）

### matrix 流程

- 首次场景：`--matrix-prep`（完整 clab deploy + 编译全后端二进制）
- 后续场景：`--pproxy-only`（仅推配置 + 重启 pproxy，不重建 lab、不 scp 二进制）
- iperf 前自动 `check-tunnel.sh`（`pproxy-ctl tunnel` 校验 proto/io/ready）

```bash
# 单场景（io_uring + batch_tx=32）
./tests/clab/perf.sh --scenario udp_uring_batch32

# 扫 batch_tx
./tests/clab/perf.sh --sweep batch_tx=1,8,32,64 --scenario udp_uring_batch32

# 全后端 matrix（首次 bootstrap 会编译全后端二进制；后续场景只切配置/重启 pproxy）
./tests/clab/perf.sh --matrix

# IPC 影响矩阵（polling/eventfd/adaptive + backoff/spin/yield）
./tests/clab/perf.sh --ipc-matrix

# 无 pproxy 直连基线
./tests/clab/perf.sh --baseline direct

# CI 固定场景（self-hosted + KVM）
./tests/clab/perf.sh --ci --fail-on-threshold

# 正式 iperf 窗口内在 leaf1/leaf2 各抓 5s perf，并导出 speedscope JSON
./tests/clab/perf.sh --scenario udp_kernel --flamegraph
```

结果写入 `tests/clab/results/`。可选 `--update-doc` 将 Markdown 表追加到本文件。需要长期保留的结果建议整理到 `tests/clab/reports/`。

### IPC 模式和影响报告

pproxy 当前支持三种 ring IPC 模式：

| 模式 | 行为 | 适用观察点 |
|------|------|------------|
| `polling` | 空 ring 时 `nanosleep(poll_backoff_us)` | 低 CPU、较高 wake 延迟 |
| `eventfd` | enqueue 由空变非空时写 eventfd，消费者 `epoll_wait` | 唤醒明确，syscall 成本可见 |
| `adaptive` | 先 `pause/yield` 短等，再退到 eventfd/epoll | 在吞吐和 wake 延迟之间折中 |

配置字段位于 `runtime.rings`：

```json
{
  "runtime": {
    "rings": {
      "ipc_mode": "adaptive",
      "poll_backoff_us": 50,
      "adaptive_spin": 64,
      "adaptive_yield": 8
    }
  }
}
```

`/metrics` 会暴露 ring/IPC 指标，带 `ring`、`index`、`mode` label，例如：

- `pp_ring_ipc_waits`
- `pp_ring_ipc_ready`
- `pp_ring_ipc_wakes`
- `pp_ring_ipc_timeouts`
- `pp_ring_ipc_notifies`
- `pp_ring_ipc_adaptive_spins`
- `pp_ring_enqueue_fail`
- `pp_ring_high_watermark`

生成 IPC 影响报告：

```bash
./tests/clab/perf.sh --ipc-matrix
```

默认基于 `udp_kernel`，扫 `polling`、`eventfd`、`adaptive` 及几组代表性 `poll_backoff_us` / `adaptive_spin` / `adaptive_yield`。输出为 `tests/clab/results/ipc_matrix_<timestamp>.md`，列包含吞吐、PPS、pproxy CPU、core-us/包，以及 IPC waits/ready/wakes/timeouts/notifies 速率。要换基准场景：

```bash
./tests/clab/perf.sh --ipc-matrix --ipc-scenario udp_uring_batch32
```

单点对比可用 overlay：

```bash
./tests/clab/perf.sh --scenario udp_kernel \
  --overlay '{"runtime.rings.ipc_mode":"eventfd","runtime.rings.poll_backoff_us":50}'
```

### Flamegraph / speedscope

`--flamegraph` 会在每个正式 iperf run 同时在 leaf1 和 leaf2 上执行 `perf record`，默认延迟 1 秒后抓 5 秒、99Hz。可用环境变量或参数调整：

```bash
./tests/clab/perf.sh --scenario udp_memif --flamegraph --flame-duration 5 --flame-freq 99 --flame-delay 1
```

输出目录：

```text
tests/clab/results/flamegraphs/<run-id>/
├── manifest.json
├── README.md
├── leaf1/leaf1.speedscope.json
└── leaf2/leaf2.speedscope.json
```

把 `leaf*.speedscope.json` 上传到 <https://www.speedscope.app/> 即可交互查看。GitHub Actions 的 `clab-perf-results` artifact 已上传整个 `tests/clab/results/`，因此也会包含这些 speedscope JSON 和原始 `perf.data` / `perf.script`。

已入仓的报告可直接从 [`20260703-matrix-flame.md`](../tests/clab/reports/20260703-matrix-flame.md) 点击 `L1 flame` / `L2 flame` 打开 speedscope；这些链接使用 raw GitHub JSON 作为 speedscope `profileURL`。如果要生成同类报告，先把 flamegraph 目录整理到报告目录下，再设置 raw URL 前缀：

```bash
PPROXY_SPEEDSCOPE_RAW_BASE=https://raw.githubusercontent.com/calcky/pproxy/main/tests/clab/reports \
  ./tests/clab/perf.sh --matrix --flamegraph
```

未设置 `PPROXY_SPEEDSCOPE_RAW_BASE` 时，报告仍输出本地相对 JSON 链接。

### 2026-07-02 matrix 样例

| scenario | right I/O | P1 Mbps | P10 Mbps | status |
| --- | --- | ---: | ---: | --- |
| `udp_kernel` | `kernel_socket` | 615.053 | 719.887 | pass |
| `udp_uring_batch32` | `io_uring` | 507.100 | 551.783 | pass |
| `udp_af_xdp` | `af_xdp` | 585.304 | 709.166 | pass |
| `udp_netmap` | `netmap` | 893.103 | 1179.392 | pass |
| `udp_dpdk` | `dpdk` | 1552.125 | 629.658 | pass |
| `udp_memif` | `memif` | 653.225 | 659.389 | pass |

本次 memif 通过依赖 `deploy.sh` 在 memif 分支给 router 写静态 ARP：leaf WAN IP → leaf WAN MAC。修复前 VPP memif bridge 已创建，但 router 对 leaf WAN IP 的 ARP 未解析，跨网段 ping 会在等待窗口内失败。

### 流量路径

client1（192.168.0.2）→ leaf1 TUN → pproxy → UDP 隧道 → leaf2 → client2（192.168.1.2）。

pproxy 启动后会 `ip route replace <对端 LAN> dev ppclab*`，跨网段流量经隧道而非 leaf 内核直转发。

### CI

GitHub Actions [`.github/workflows/clab-perf.yml`](../.github/workflows/clab-perf.yml) 在 **self-hosted runner（需 KVM）** 上 weekly / 手动触发，跑 `scenarios.yaml` 中 `ci: true` 的场景并上传 artifact。

---

## 历史记录

| 日期 | 场景 | 吞吐 | 备注 |
|------|------|------|------|
| （手动） | 无 pproxy 直连 | ~2800 Mbps | CPC 参考基线 |
