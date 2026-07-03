# containerlab 测试环境

这个目录提供 pproxy 的本地 containerlab 拓扑、leaf VM 预热镜像构建脚本，以及性能测试入口。建议所有命令都从仓库根目录执行。

## 拓扑

默认拓扑在 `pproxy.clab.yml`：

```text
client1 -- leaf1 -- router -- leaf2 -- client2
```

- `client1`：`192.168.0.2/24`
- `client2`：`192.168.1.2/24`
- `leaf1` / `leaf2`：`generic_vm` Ubuntu VM，默认镜像是 `pproxy/ubuntu-noble-leaf:latest`
- `router`：Linux 容器，转发 `172.16.0.0/24` 与 `172.16.1.0/24`

leaf VM 登录信息：

```bash
ssh clab@leaf1
ssh clab@leaf2
# password: clab@123
```

## 前置依赖

宿主机需要：

- Docker
- containerlab
- `qemu-img`
- `sshpass`
- `python3-yaml`

如果宿主机没有 `virt-customize` / `guestfish`，`build-leaf-image.sh` 会自动构建一个带 libguestfs 的 Docker helper 镜像来改 VM qcow2。

默认不使用宿主机 `sudo` 调用 containerlab。宿主机未配置 Docker 免 sudo 时可以加：

```bash
CLAB_SUDO=1 ./tests/clab/deploy.sh ...
```

## 构建 leaf 预热镜像

leaf 是 `generic_vm`，依赖需要装进 VM 的 qcow2，而不是外层 Docker 文件系统。先构建预热镜像可以避免每次部署都在 VM 内安装 DPDK、VPP/libmemif 等依赖。

```bash
./tests/clab/build-leaf-image.sh --tag pproxy/ubuntu-noble-leaf:latest --force
```

常用选项：

```bash
./tests/clab/build-leaf-image.sh --disk-size 10G
./tests/clab/build-leaf-image.sh --no-dpdk
./tests/clab/build-leaf-image.sh --no-memif
./tests/clab/build-leaf-image.sh --libmemif-tag v26.06
```

常用环境变量：

- `LEAF_BASE_IMAGE`：基础 vrnetlab 镜像，默认 `vrnetlab/canonical_ubuntu:noble`
- `LEAF_IMAGE_TAG`：输出镜像 tag，默认 `pproxy/ubuntu-noble-leaf:latest`
- `LEAF_DISK_SIZE`：扩容后的 VM 磁盘大小，默认 `8G`
- `LEAF_IMAGE_CACHE`：构建缓存目录
- `LIBMEMIF_VPP_TAG`：构建 libmemif 使用的 VPP tag

`pproxy.clab.yml` 已经默认引用 `pproxy/ubuntu-noble-leaf:latest`。

## 部署拓扑

只启动拓扑并配置 leaf 网络，不安装 pproxy：

```bash
./tests/clab/deploy.sh --no-pproxy
```

部署默认 UDP tunnel，左侧 TUN，右侧 kernel socket：

```bash
PPROXY_SKIP_BUILD=1 ./tests/clab/deploy.sh --left-io=tun --right-io=kernel_socket
```

切换右侧 I/O 后端：

```bash
./tests/clab/deploy.sh --left-io=tun --right-io=io_uring
./tests/clab/deploy.sh --left-io=tun --right-io=af_xdp
./tests/clab/deploy.sh --left-io=tun --right-io=netmap
./tests/clab/deploy.sh --left-io=tun --right-io=dpdk
./tests/clab/deploy.sh --left-io=tun --right-io=memif
```

已部署拓扑时，只推配置、准备对应后端并重启 pproxy：

```bash
PPROXY_SKIP_BUILD=1 ./tests/clab/deploy.sh --pproxy-only --left-io=tun --right-io=io_uring
```

验证连通性：

```bash
docker exec client1 ping -c 3 192.168.1.2
```

查看状态和日志：

```bash
ssh clab@leaf1 pproxy-ctl tunnel
ssh clab@leaf2 pproxy-ctl tunnel
ssh clab@leaf1 tail -n 100 /opt/pproxy/log/pp.log
ssh clab@leaf1 tail -n 100 /opt/pproxy/log/vpp.log
```

## 性能测试

单场景：

```bash
./tests/clab/perf.sh --scenario udp_kernel
./tests/clab/perf.sh --scenario udp_uring_batch32
./tests/clab/perf.sh --scenario udp_af_xdp
./tests/clab/perf.sh --scenario udp_netmap
./tests/clab/perf.sh --scenario udp_dpdk
./tests/clab/perf.sh --scenario udp_memif
```

跑矩阵：

```bash
./tests/clab/perf.sh --matrix
```

矩阵会先完整部署一次 lab，然后用 `--pproxy-only` 切换后端。每个场景默认跑 TCP iperf3，`-P 1` 和 `-P 10` 各 10 秒，外加 2 秒 warmup。

IPC 影响矩阵：

```bash
./tests/clab/perf.sh --ipc-matrix
./tests/clab/perf.sh --ipc-matrix --ipc-scenario udp_uring_batch32
```

IPC 矩阵默认基于 `udp_kernel`，扫 `runtime.rings.ipc_mode` 的 `polling`、`eventfd`、`adaptive`，并覆盖几组 `poll_backoff_us` / `adaptive_spin` / `adaptive_yield`。结果写到 `tests/clab/results/ipc_matrix_<timestamp>.md`，每行包含吞吐、PPS、pproxy CPU、core-us/包，以及 IPC waits/ready/wakes/timeouts/notifies 速率。

手动指定 IPC 配置也可以直接用 overlay：

```bash
./tests/clab/perf.sh --scenario udp_kernel \
  --overlay '{"runtime.rings.ipc_mode":"adaptive","runtime.rings.poll_backoff_us":50,"runtime.rings.adaptive_spin":64,"runtime.rings.adaptive_yield":8}'
```

直连基线，不经过 pproxy：

```bash
./tests/clab/perf.sh --baseline direct
```

扫参数，例如扫 io_uring `batch_tx`：

```bash
./tests/clab/perf.sh --sweep batch_tx=1,8,32,64 --right-io=io_uring
```

常用选项和环境变量：

- `--skip-build`：跳过宿主机 `./build.sh`
- `--skip-deploy`：复用已经部署好的拓扑
- `--flamegraph`：正式 iperf 窗口内在 leaf1/leaf2 各抓 5s `perf record`，并导出 speedscope JSON
- `--ipc-matrix`：扫 IPC 模式和等待参数，生成 `ipc_matrix_*.md`
- `PERF_RESULTS_DIR=/path/to/results`：指定结果目录
- `PERF_SCENARIOS=/path/to/scenarios.yaml`：指定场景文件
- `PERF_FLAME_DURATION=5` / `PERF_FLAME_FREQ=99` / `PERF_FLAME_DELAY=1`：调整 flamegraph 采样参数

结果写到 `tests/clab/results/`：

- `*.json`：每次 iperf 结果和采集到的 metrics
- `matrix_*.md`：矩阵汇总
- `ipc_matrix_*.md`：IPC 影响矩阵汇总
- `flamegraphs/<run-id>/leaf{1,2}/*.speedscope.json`：`--flamegraph` 生成的 speedscope 火焰图数据，可在 <https://www.speedscope.app/> 打开

每个结果 JSON 的 `metrics_delta.leaf*.ipc_delta` 会记录 ring/IPC 计数的窗口差值，包括：

- `waits` / `ready` / `wakes` / `timeouts` / `notifies`
- `sleeps` / `epolls` / `adaptive_spins` / `adaptive_yields`
- `enqueue_fail` / `dequeue_empty` / `high_watermark`

已入仓报告中的 `L1 flame` / `L2 flame` 链接会打开 speedscope 并自动加载 raw GitHub JSON；`L1 json` / `L2 json` 保留原始 JSON 下载链接。生成需要自动打开 speedscope 的 Markdown 时，可设置 `PPROXY_SPEEDSCOPE_RAW_BASE=https://raw.githubusercontent.com/<owner>/<repo>/<branch>/<report-dir>`；未设置时默认输出本地相对 JSON 链接。

已整理入仓库的样例报告：

- [`tests/clab/reports/20260703-matrix-flame.md`](reports/20260703-matrix-flame.md)：matrix + leaf1/leaf2 perf speedscope 链接
- [`tests/clab/reports/20260702-matrix.md`](reports/20260702-matrix.md)：matrix 基线报告

## 后端说明

- `kernel_socket`：稳定基线，走内核 UDP/TCP socket。
- `io_uring`：仍是 kernel socket I/O，配置为 `io_cfg.backend=io_uring`，可通过 overlay 调 `batch_tx`、`tx_zc` 等参数。
- `af_xdp`：使用 AF_XDP；如果宿主机有 `xsk_xdpcap.bpf.o`，部署脚本会一起推到 VM，否则只跳过抓包 hook。
- `netmap`：需要 leaf 内加载 `netmap.ko`；宿主机可用 `tests/clab/build-netmap-ko.sh` 构建并缓存。
- `dpdk`：需要 hugepages 和 `vfio-pci`，会临时把 WAN 网卡从内核解绑给 DPDK；脚本会尽量恢复，异常时建议重新 deploy。
- `memif`：使用 VPP sidecar 作为 memif master，pproxy 作为 slave，再由 VPP 通过 `af_packet` 桥到 WAN。部署脚本会给 router 写 leaf WAN IP 的静态 ARP，因为 VPP/memif 桥接路径不会由 pproxy 应答 router ARP。当前 `udp_memif` 已在 2026-07-02 的完整 matrix 中通过；相比 kernel socket 仍多一个 VPP sidecar，排障时优先看 `/opt/pproxy/log/vpp.log`、`vppctl show memif` 和 router `ip neigh`。

## 清理和调试

销毁拓扑：

```bash
containerlab destroy -t tests/clab/pproxy.clab.yml --cleanup
```

如果使用宿主机 sudo：

```bash
sudo containerlab destroy -t tests/clab/pproxy.clab.yml --cleanup
```

停止 gdb 端口转发：

```bash
./tests/clab/gdb-tunnel.sh stop
```

清理残留 perf/iperf/pproxy/gdb 进程：

```bash
./tests/clab/perf/cleanup.sh
```

用 gdbserver 启 pproxy：

```bash
./tests/clab/deploy.sh --gdb --gdb-tunnel
```

core dump 默认落在 leaf VM 的 `/opt/pproxy/core-*`，pproxy 日志在 `/opt/pproxy/log/pp.log`。
