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
| [`tests/clab/perf/collect-cpu.sh`](../tests/clab/perf/collect-cpu.sh) | iperf 期间 pproxy 进程/线程 CPU 采样 |

### iperf3 参数

- 协议：**TCP only**（`-P` 并行流，非 UDP）
- 时长：**10s**（warmup **2s**）
- 每个场景跑 **单流（-P 1）** 和 **10 并行流（-P 10）**
- 吞吐取接收端 `sum_received`（goodput）
- 结果 JSON 含 **CPU 占用**（pproxy 总/usr/sys、系统 usr/nice/sys/irq/softirq/idle、各线程）与 **metrics delta**
- `--matrix` 时每组 iperf 结果追加到 `tests/clab/results/matrix_<timestamp>.md`（列：scenario / right_io / P / Mbps / PPS / L1·L2 各 pp、u/s、irq/sirq、cpp）
- **PPS**：两 leaf `right_tx` 计数之和 ÷ iperf 时长（tunnel 发包速率）
- **cpp**：各 leaf pproxy 进程 core-µs/包（`CPU% × ncpu × 10⁶ / worker 转发包率`）

### matrix 流程

- 首次场景：`--matrix-prep`（完整 clab deploy + 编译全后端二进制）
- 后续场景：`--pproxy-only`（仅推配置 + 重启 pproxy，不重建 lab、不 scp 二进制）
- iperf 前自动 `check-tunnel.sh`（`pproxy-ctl tunnel` 校验 proto/io/ready）

```bash
# 单场景（io_uring + batch_tx=32）
./tests/clab/perf.sh --scenario udp_uring_batch32

# 扫 batch_tx
./tests/clab/perf.sh --sweep batch_tx=1,8,32,64 --scenario udp_uring_batch32

# 全后端 matrix（首次 bootstrap 会编译全后端；之后 --skip-build 只跳过编译）
./tests/clab/perf.sh --matrix --skip-build

# 无 pproxy 直连基线
./tests/clab/perf.sh --baseline direct

# CI 固定场景（self-hosted + KVM）
./tests/clab/perf.sh --ci --fail-on-threshold
```

结果写入 `tests/clab/results/`。可选 `--update-doc` 将 Markdown 表追加到本文件。

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
