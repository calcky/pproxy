# pproxy

一个**纯 C 编写、Linux 专用、按线程粒度模块化**的用户态隧道代理框架。

- **左手侧（Ingress）**：劫持本机/旁路流量，后端可选 `tun / raw_socket(AF_PACKET) / AF_XDP / netmap / pcap / dpdk`
- **DPI 中间层**：五元组会话跟踪、应用层协议识别（TLS SNI / HTTP Host / DNS / QUIC …），对外提供查询接口
- **右手侧（Egress）**：`(proto, io)` 正交两层。proto = `TCP / UDP / ICMP`（可扩展 KCP / QUIC）；io = `kernel_socket(syscall/io_uring) / raw_socket / tun / af_xdp / netmap / pcap / dpdk / memif`。tcp 只能配 kernel_socket（TCP 状态机在内核），udp/icmp 可任选
- **数据平面**：分片无锁、per-CPU mempool、批量收发、SPSC ring，线程之间不持锁

> 本项目仅支持 **Linux**（推荐 5.10+，AF_XDP zero-copy 推荐 5.15+）。不考虑跨平台。

---

## 设计原则

1. **按线程粒度模块化**：每个长生命周期线程 = 一个模块，模块边界清晰、职责单一。
2. **模块间通信只走 ring**：SPSC / MPSC 无锁环，绝不共享可变状态。
3. **共享数据走 RCU 或快照**：Session 查询、配置热更新均不阻塞数据平面。
4. **I/O 后端可插拔**：通过统一 `pp_pkt_io_ops_t` vtable，编译期或运行期挑选。
5. **C99 + GNU 扩展**，无 C++/Rust 依赖；外部依赖按后端启用（libbpf/libxdp、libpcap、libdpdk、liburing、libmemif）。netmap 使用 vendored 用户态头文件。

---

## 线程模型一览

| 线程模块 | 实例数 | 职责 | 输入 | 输出 |
|---|---|---|---|---|
| `main` | 1 | 启动、信号、配置加载、模块编排 | — | — |
| `left_rx` | 1~M | 从左手 I/O 收包，按 flow hash 分片 | I/O 后端 | `worker[i].rx_ring` |
| `worker` | N（≈核数-2） | 解析 + DPI + Session + 封装 | `worker[i].rx_ring` / `worker[i].back_ring` | `right_tx[j].ring` / `left_tx.ring` |
| `right_tx` | 每 tunnel 1 | 与 server 通讯：发包、复用、加密 | `right_tx[j].ring` | tunnel socket |
| `right_rx` | 每 tunnel 1 | 从 server 收包、解隧道头、查 sid 路由 | tunnel socket | `worker[i].back_ring` |
| `left_tx` | 1 | 把还原后的包写回左手 I/O | `left_tx.ring` | I/O 后端 |
| `timer` | 1 | session 老化、心跳、统计聚合 | 内部 timer wheel | 各 worker 控制队列 |
| `mgmt` | 1 | REST / Unix socket，会话查询、配置 reload | HTTP 请求 | RCU 控制指针 |

详细线程模型见 [`doc/threads.mmd`](doc/threads.mmd)。

---

## 架构总览

```
                       ┌─────────────────────────────────────┐
                       │         mgmt 线程（REST API）        │
                       └──────────────┬──────────────────────┘
                                      │ RCU snapshot
   ┌──────────┐    ┌─────────────┐   ▼   ┌─────────────┐    ┌──────────┐
   │ left_rx  │───▶│  hash 分片  │──▶ worker[0..N-1] ──▶│  right_tx   │───▶│  server  │
   │  (1~M)   │    │  SPSC ring  │       (DPI + Session)  │ (per tunl) │    └──────────┘
   └──────────┘    └─────────────┘   ▲   └─────────────┘
        ▲                            │           │
        │                            │           ▼
   ┌──────────┐                ┌─────┴─────┐  ┌──────────┐
   │ left_tx  │◀───────────────│ back_ring │◀─│ right_rx │
   └──────────┘                └───────────┘  └──────────┘
                                                   ▲
                                              ┌────┴─────┐
                                              │  timer   │
                                              └──────────┘
```

完整图：[`doc/architecture.mmd`](doc/architecture.mmd)

---

## 目录布局

按"线程模块"组织 `src/modules/*`，每个子目录就是一个线程模块的全部实现。

```
pproxy/
├── include/pproxy/
│   ├── packet.h           # mbuf / mempool
│   ├── ring.h             # SPSC / MPSC ring
│   ├── flow.h             # FlowKey, hash
│   ├── session.h          # Session, SessionTable（分片）
│   ├── dpi.h              # DPI 插件接口
│   ├── pkt_io.h           # I/O 后端 vtable
│   ├── tunnel.h           # 右手 tunnel vtable
│   ├── module.h           # 线程模块统一接口（init/start/stop）
│   └── log.h
├── src/
│   ├── main.c
│   ├── modules/                   # 一个目录一个线程
│   │   ├── left_rx/
│   │   ├── left_tx/
│   │   ├── worker/
│   │   ├── right_rx/
│   │   ├── right_tx/
│   │   ├── timer/
│   │   └── mgmt/
│   ├── io/                        # I/O 后端（左手 vtable + 右手薄封装合并同文件）
│   │   ├── tun.c / tun.h          # L3 TUN：左手 pp_io_tun + 右手 pp_tun_io_*
│   │   ├── raw_sock.c / raw_sock.h# 左手 AF_PACKET + 右手 AF_INET SOCK_RAW
│   │   ├── ks_sock.c / ks_sock.h  # 右手 kernel socket (UDP/TCP)
│   │   ├── uring_sock.c / .h      # kernel_socket 的 io_uring 后端
│   │   ├── xsk.c / xsk.h          # AF_XDP
│   │   ├── xsk_xdpcap.c / .h      # 可选 XDP 抓包 hook
│   │   ├── netmap.c / netmap.h    # netmap（vendored 头，nm_open API）
│   │   ├── pcap.c / pcap.h        # libpcap
│   │   ├── dpdk.c / dpdk.h        # DPDK PMD
│   │   └── memif.c / memif.h      # VPP memif 右手 I/O helper
│   ├── config/                    # JSON 配置加载与热重载
│   ├── tunnel/                    # 右手 transport（被 right_rx/right_tx 调用）
│   │   ├── tcp.c
│   │   ├── udp.c
│   │   └── icmp.c
│   ├── dpi/                       # 协议识别插件（被 worker 调用）
│   │   ├── tls.c
│   │   ├── http.c
│   │   └── dns.c
│   └── core/                      # 公共设施
│       ├── packet.c               # mbuf / mempool
│       ├── ring.c                 # 无锁环
│       ├── flow.c                 # FlowKey + hash
│       ├── session.c              # 分片 SessionTable
│       └── timer_wheel.c
├── doc/
│   ├── architecture.mmd           # 总体架构
│   ├── threads.mmd                # 线程与队列拓扑
│   ├── modules.mmd                # 模块依赖关系
│   ├── dataflow.mmd               # 端到端时序
│   └── session-state.mmd          # 会话状态机
├── tests/
│   └── clab/                      # containerlab 拓扑、leaf 镜像、性能矩阵
├── scripts/
│   └── install_libmemif.sh        # 从 FD.io VPP extras 构建 libmemif
└── examples/
```

---

## 线程模块统一接口

所有线程模块实现下面这个 vtable，由 `main` 统一编排启动/优雅停止。

```c
typedef struct pp_module {
    const char *name;
    int  (*init)(void *cfg);
    int  (*start)(void);            /* pthread_create 内部完成 */
    void (*stop)(void);             /* 置标志位 + join */
    void (*stat)(struct pp_stat *out);
} pp_module_t;
```

每个模块自己持有：

- 线程句柄、cpu 亲和性
- 输入/输出 ring 的指针
- per-thread mempool / 私有上下文（如 worker 的 SessionTable 分片）
- 统计计数器（cache line 对齐，避免 false sharing）

---

## 关键抽象（C 接口）

### `pp_pkt_io_ops_t` —— 左手 I/O 后端（vtable）

```c
typedef struct pp_pkt_io_ops {
    const char *name;
    pp_io_kind_t kind;
    uint32_t     caps;

    int   (*open)  (const pp_io_cfg_t *cfg, void **out_ctx);
    void  (*close) (void *ctx);
    int   (*rx_burst)(void *ctx, pp_pkt_t **pkts, int max, int timeout_us);
    int   (*tx_burst)(void *ctx, pp_pkt_t **pkts, int n);
    int   (*get_rx_fd)(void *ctx);
    int   (*get_tx_fd)(void *ctx);
    int   (*stat)(void *ctx, char *json, size_t cap);
} pp_pkt_io_ops_t;
```

后端实现：`io/tun.c` `io/raw_sock.c` `io/xsk.c` `io/netmap.c` `io/pcap.c` `io/dpdk.c`

### `pp_tunnel_ops_t` —— 右手 transport（vtable）

```c
typedef struct pp_tunnel_ops {
    const char       *name;
    pp_tunnel_proto_t proto;
    uint32_t          supported_io_mask;
    uint32_t          caps;

    int   (*open)  (const pp_tunnel_cfg_t *cfg, void **out_ctx);
    void  (*close) (void *ctx);
    int   (*connect)(void *ctx);
    int   (*send)(void *ctx, const pp_tun_buf_t *buf);
    int   (*recv)(void *ctx, pp_tun_mbuf_t *out_buf, int timeout_us);
    void  (*session_close)(void *ctx, uint64_t sid);
    int   (*get_rx_fd)(void *ctx);
    int   (*get_tx_fd)(void *ctx);
    int   (*stat)(void *ctx, char *json, size_t cap);
} pp_tunnel_ops_t;
```

实现：`tunnel/tcp.c` `tunnel/udp.c` `tunnel/icmp.c`

`pp_tunnel_ops_t` 只负责 **proto 编码**（怎么把 `sid + payload` 装成 TCP/UDP/ICMP 报文）；
具体怎么把字节发出去由 `cfg.io` 决定，proto 实现内部按 `io` 派发到下面这层：

| proto \ io  | kernel_socket | raw_socket | tun       | pcap        | af_xdp       | netmap        | dpdk            | memif           |
|-------------|:-------------:|:----------:|:---------:|:-----------:|:------------:|:-------------:|:---------------:|:---------------:|
| `tcp`       | ✓ 已实现       | —          | —         | —           | —            | —             | —               | —               |
| `udp`       | ✓ 已实现       | ✓ 已实现    | ✓ 已实现   | ✓ 已实现\*   | ✓ 已实现\*\*  | ✓ 已实现\*\*\* | ✓ 已实现\*\*\*\* (拷贝版) | ✓ 已实现\*\*\*\*\* |
| `icmp`      | —             | ✓ 已实现    | ✓ 已实现   | ✓ 已实现\*   | ✓ 已实现\*\*  | ✓ 已实现\*\*\* | ✓ 已实现\*\*\*\* (拷贝版) | ✓ 已实现\*\*\*\*\* |

图例：`✓` 已落地（带回环测试或冒烟测试）；`○` `supported_io_mask` 里挂了位，但 `open()` 会
返回 `PP_ERR_NOSUPPORT` 直到具体实现补上；`—` 架构上不支持。
`*`       = 需要 `./build.sh --pcap`（启用 libpcap 链接）。
`**`      = 需要 `./build.sh --xdp`（启用 libxdp + libbpf 链接），且运行环境需 `CAP_NET_ADMIN + CAP_BPF`
            且接口支持 XDP（`lo` 一般不行，veth/真实网卡可）。
`***`     = 需要 `./build.sh --netmap`（启用 vendored 头文件，无需系统库），且运行环境需内核加载
            `netmap` 模块、提供 `/dev/netmap`，以及 `CAP_NET_ADMIN`。
`****`    = 需要 `./build.sh --dpdk`（启用 libdpdk pkg-config 链接）+ 运行时 hugepages + 已 vfio-pci 绑定的数据网卡。
            当前是「拷贝版」（rx 把 rte_mbuf memcpy 进 pp_pkt_t，tx 反向），未实现零拷贝。
            DPDK 接管网卡后内核不可见，不能与 `kernel_socket` 共用同一张卡。
`*****`   = 需要 `./build.sh --memif`（启用 libmemif 链接）。pproxy 作为 memif slave，通常配 VPP sidecar
            做 memif master，再通过 `af_packet` 桥到物理/虚拟 WAN。

> - `tcp` 只能走 `kernel_socket`：TCP 状态机在内核里，除非自带用户态 TCP 栈。
> - `kernel_socket` 默认走传统 syscall；构建 `./build.sh --io-uring` 后，可在 `io_cfg.backend="io_uring"` 下使用
>   io_uring socket 路径（支持 `batch_tx`，`tx_zc` 在内核/硬件不支持时自动回退）。
> - `udp` / `icmp` 的 `kernel_socket` 省事、`raw_socket` 绕过 UDP socket 缓存且可自定义端口/IP 头；
>   `tun` 把自建帧写回虚拟设备让内核路由；`pcap` 通过 libpcap 抓包+注入（支持 BPF 过滤）；
>   `af_xdp` / `netmap` / `dpdk` / `memif` 面向低延迟或旁路数据面。
> - `pp_tunnel_ops_t.supported_io_mask` 在 `open()` 时校验 `(proto, io)` 是否合法，
>   不合法直接返回 `PP_ERR_NOSUPPORT`。
> - `raw_socket` / `pcap` 需要 `CAP_NET_RAW`，`tun` 需要 `CAP_NET_ADMIN`；DPDK 需要 hugepages + vfio-pci；
>   memif 需要 libmemif 与 VPP/对端 socket；UDP `raw_socket` 目前仅 IPv4。

#### 右手 io 示例配置片段

```json
"tunnels": [
  {
    "name": "ut0-raw", "proto": "udp", "io": "raw_socket",
    "mode": "client",
    "server": "10.0.0.2:4790",
    "listen": "0.0.0.0:34790",
    "io_cfg": { "ifname": "eth0" }
  },
  {
    "name": "ut1-tun", "proto": "udp", "io": "tun",
    "mode": "client",
    "server": "10.0.0.2:4790",
    "listen": "10.9.9.1:34790",
    "io_cfg": { "ifname": "pp-right-tun0" }    // 专用 tun 设备，不可与左手同名
  },
  {
    "name": "ut2-pcap", "proto": "udp", "io": "pcap",
    "mode": "client",
    "server": "10.0.0.2:4790",
    "listen": "10.0.0.1:34790",
    "io_cfg": {
      "ifname": "eth0",
      "bpf_filter": "",        // 留空则按 (src_port, dst_port) 自动合成
      "snaplen": 2048
    }
  },
  {
    "name": "ic0-tun", "proto": "icmp", "io": "tun",
    "mode": "server",
    "listen": "10.9.9.2:1",
    "io_cfg": { "ifname": "pp-right-itun" }
  },
  {
    "name": "ut3-xdp", "proto": "udp", "io": "af_xdp",
    "mode": "client",
    "server": "10.0.0.2:4790",
    "listen": "10.0.0.1:34790",
    "io_cfg": {
      "ifname": "eth0",            // 必须支持 XDP，不支持 lo
      "queue_id": 0,
      "nframes": 4096,             // 总帧数（rx + tx 各一半）
      "zero_copy": true,           // 硬件支持才有用；不支持会自动回落到 COPY
      "need_wakeup": true
    }
  }
]
```

> AF_XDP 运行时注意：
> - libxdp 会在 open 时自动给 `ifname` 挂一个 `xsks_map` redirect 程序；跑完要记得 `ip link set dev <iface> xdp off`
>   清理（或重启）。需要 `CAP_NET_ADMIN + CAP_BPF` / root。
> - `nframes` 一半留 rx / 一半留 tx；`zero_copy` 需要网卡驱动支持，否则自动降级到 COPY。
> - 若要真正端到端测试，建议用 veth pair + XDP-generic：
>   ```bash
>   ip link add veth-a type veth peer name veth-b
>   ip link set veth-a up && ip link set veth-b up
>   # 两侧分别起 pproxy，ifname 分别指向 veth-a / veth-b
>   ```

### `pp_session_t` —— 会话

```c
typedef struct pp_session {
    pp_flow_key_t key;             /* 五元组 + 方向 */
    uint8_t       state;           /* NEW/EST/FIN/RST */
    uint8_t       app_proto;       /* TLS/HTTP/DNS/... */
    uint64_t      created_ns, last_ns;
    pp_stats_t    up, dn;
    void         *dpi_ctx;
    uint64_t      sid;             /* 全局 session id，用于 tunnel 复用 */
    uint16_t      tunnel_idx;      /* 走哪条右手隧道 */
} pp_session_t;
```

`SessionTable` 按 `hash(key) % N` 分片，**每个 worker 线程独占一片**，零锁。

---

## 数据流（左 → 右，新连接）

1. 应用发 SYN，被路由进 `tun0`
2. `left_rx` 从 tun fd 读出 IP 包 → 计算 hash → 投递到 `worker[k].rx_ring`
3. `worker[k]`：
   1. 解析 IP/TCP 头，得 `flow_key`
   2. `session_table_lookup_or_create` —— 新建 → 状态 `NEW`、分配 `sid`、绑定 `tunnel_idx`
   3. 走 DPI 插件链做协议识别，写 `app_proto`
   4. 封装隧道头 `[sid | meta | payload]`，投递到 `right_tx[j].ring`
4. `right_tx[j]`：批量 `sendmmsg` 到 server

返程：

```
right_rx  →  解隧道头 → sid → worker[k].back_ring
worker[k] →  按 sid 反查 session → 重建 IP 包 → left_tx.ring
left_tx   →  写 tun fd
```

完整时序：[`doc/dataflow.mmd`](doc/dataflow.mmd)

---

## 性能要点

| 项目 | 选择 | 说明 |
|---|---|---|
| 内存 | per-thread `pp_mempool_t` | 预分配 mbuf，无运行时 malloc |
| 拷贝 | mbuf 引用计数 + headroom/tailroom | XDP / netmap 零拷贝可直通 |
| 锁 | 数据平面**完全无锁** | 分片 + SPSC ring + RCU |
| 亲和性 | `pthread_setaffinity_np` 绑核 | 每个 worker 锁定一颗 CPU |
| 批量 | 收发都按 burst（默认 32） | 摊薄系统调用与 cache miss |
| 计数器 | 64B 对齐、per-thread | 避免 false sharing，mgmt 聚合时再相加 |
| 配置 | RCU 指针切换 | 热更新不停服 |

---

## 构建

构建走 **Docker + Meson + Ninja**，由 `build.sh` 编排，宿主机只需要 `docker`。
Meson 负责描述工程、解析依赖、生成 `build.ninja`；Ninja 负责实际编译。

```bash
git clone https://github.com/<you>/pproxy.git
cd pproxy

./build.sh                       # release 构建（默认 -O2）
./build.sh --debug               # buildtype=debug
./build.sh --xdp --pcap --netmap # 启用 AF_XDP / pcap / netmap
./build.sh --dpdk                # 启用 DPDK 后端（需 libdpdk-dev + 运行时 hugepages/vfio）
./build.sh --io-uring            # 启用 kernel_socket 的 io_uring 后端（需 liburing）
./build.sh --memif               # 启用 VPP memif 右手后端（需 libmemif）
./build.sh -j 8                  # 并行
./build.sh clean                 # 删除 build/
./build.sh --shell               # 进容器调试
./build.sh --native              # 跳过 docker，用宿主机的 meson/ninja
./build.sh --e2e                 # 构建完再跑 tests/e2e.sh（需 CAP_NET_ADMIN）
./build.sh -- -t list            # -- 之后透传给 ninja
```

构建产物：`build/pproxy`

运行（需特权）：

```bash
sudo ./build/pproxy -c examples/config.pp1.json

# Unix socket（文本命令）
echo stat     | nc -U /tmp/pproxy.sock
echo sessions | nc -U /tmp/pproxy.sock
echo reload   | nc -U /tmp/pproxy.sock     # 重新读启动时 -c 指定的文件
echo 'reload /etc/pproxy/other.json' | nc -U /tmp/pproxy.sock
echo help     | nc -U /tmp/pproxy.sock

# HTTP Prometheus exporter（需在 config.mgmt.metrics.enable=true）
curl -s http://127.0.0.1:9091/metrics   # 按 config.pp1.json 的监听地址
curl -s http://127.0.0.1:9091/          # 简单索引页
```

### mgmt 接口

| 通道 | 典型用途 | 启用方式 |
|---|---|---|
| Unix socket `/tmp/pproxy.sock` | 运维交互：`stat` / `sessions` / `reload` / `quit` | 默认开；路径可由 `config.mgmt.unix_socket` 覆盖 |
| HTTP `:<port>/metrics` | Prometheus 抓取 | `config.mgmt.metrics = { enable: true, listen: "host:port" }` |
| HTTP `:<port>/` | 人类入口，列出 `/metrics` 链接 | 同上，绑定同一端口 |

### 测试

| 测试                          | 类型                     | 是否需 root |
|-------------------------------|--------------------------|-------------|
| `test_ring` / `test_ring_ipc` | ring / ring IPC 单测     | 否          |
| `test_tunnel_loopback`        | 进程内 TCP/UDP/ICMP 回环 | 否          |
| `test_config_reload`          | 配置热重载单元测试       | 否          |
| `test_mgmt_http`              | Unix socket + HTTP 导出  | 否          |
| `test_af_packet_io`           | AF_PACKET 左手 I/O       | 需要 `CAP_NET_RAW`，不满足时 skip |
| 可选后端测试                  | `pcap` / `xsk` / `netmap` / `dpdk` / `memif` / `uring_sock` | 取决于构建选项与运行环境 |
| `tests/e2e.sh`                | 双进程端到端             | **是**      |

```bash
# 单元测试（部分 I/O 测试缺权限或缺内核模块时会 exit 77 skip）：
./build.sh --native              # 或 ./build.sh，确保已构建
meson test -C build
# 或单独跑核心测试：
./build/test_ring
./build/test_ring_ipc
./build/test_tunnel_loopback
./build/test_config_reload
./build/test_mgmt_http

# E2E（需要 CAP_NET_ADMIN 去开 TUN）：
sudo ./tests/e2e.sh
# 或
./build.sh --e2e
# 或在容器里：
docker run --rm --cap-add=NET_ADMIN --device /dev/net/tun \
    -v "$PWD:/work" -w /work pproxy-build:latest \
    ./tests/e2e.sh
```

`tests/e2e.sh` 会：

1. 生成两份临时配置（pp1 作 client，pp2 作 server，TUN 改名避开生产 `pproxy0`，端口换成 19900/19991/19992）
2. 先起 pp2 再起 pp1，等两边 `/metrics` HTTP 200 才往下走
3. 校验：
   - pp1 日志里有 `tcp tunnel connected`、pp2 日志里有 `tcp tunnel listening` + `tcp tunnel accepted` → 隧道链路真的通了
   - `ip link show` 两个 TUN 都在
   - `/metrics` 里有 `pp_info` + 各模块的 `pp_module_loops`
   - 通过 mgmt Unix socket 发 `stat` / `sessions` / `reload` 响应格式正确
   - 发 `quit` 两端都能在 2 秒内干净退出
4. 失败会把 pp1/pp2 的完整日志打到终端方便排查；成功则清理掉 `/tmp` 里的临时目录

无 root / 无 `CAP_NET_ADMIN` 时脚本直接 `exit 77`（automake skip 语义），不会假失败。

`/metrics` 导出的主要指标：
- `pp_info{version,workers,tunnels}` — 构建/运行信息
- `pp_module_loops{module}` / `pp_module_events_in{module}` / `_out` / `_drops` / `_cpu` — 每个线程模块计数
- `pp_sessions` — 当前 session 总数（快照）
- `pp_sessions_by_app{app}` — 按应用层协议分布（`unknown` / `http` / `tls` / `dns` / `quic` / `ssh` …）

### mgmt `reload` 可热切换字段

- `log.level`
- `session.idle_ttl_ms` / `syn_ttl_ms` / `fin_ttl_ms`
- `dpi.plugins[].enable`（`priority` 改动会提示需重启）

其它字段（`runtime` / `left` / `tunnels` / `mgmt` / `affinity`）变更会在响应里标成 `requires restart`，避免运行中错配资源。

#### 构建依赖

宿主机：`docker`（推荐 20.10+）。

镜像内（`Dockerfile` 自动安装）：
- `gcc` + `libc6-dev` + `meson` + `ninja-build` + `pkg-config`
- `libbpf-dev` + `libxdp-dev` + `libpcap-dev` + `libdpdk-dev` + `liburing-dev`（可选后端用）
- `libmemif`：Ubuntu 默认仓库通常没有 `libmemif-dev`；`Dockerfile` 通过
  [`scripts/install_libmemif.sh`](scripts/install_libmemif.sh) 从 FD.io VPP `extras/libmemif` 构建安装。
- netmap 不依赖系统包：`./build.sh --netmap` 直接复用 `third_party/netmap/` 下 vendored
  的 `<net/netmap_user.h>` (BSD-2-Clause)，无 `-lnetmap`。

#### 运行时权限

- 默认（tun）：`CAP_NET_ADMIN`
- raw_socket：`CAP_NET_RAW`
- AF_XDP：`CAP_BPF`（5.8+）或 root
- netmap：`CAP_NET_ADMIN` + 内核加载 `netmap` 模块（提供 `/dev/netmap`）
- DPDK：root（或 vfio-pci 配好 + 用户在 vfio 设备组）；运行时需 hugepages（`echo N > /proc/sys/vm/nr_hugepages`）和已绑定到 `vfio-pci` 的网卡。`./build.sh --dpdk` 启用编译
- io_uring：`./build.sh --io-uring` 启用编译；运行时仍走 kernel socket 权限模型
- memif：`./build.sh --memif` 启用编译；运行时需要 libmemif 和 VPP/其他 memif master，clab 里由 VPP sidecar 提供

#### 构建文件说明

| 文件 | 作用 |
|---|---|
| `Dockerfile`         | 构建环境镜像（debian-slim + 工具链） |
| `meson.build`        | 工程描述：源码列表、依赖、编译选项 |
| `meson_options.txt`  | 可选构建选项（`xdp` / `pcap` / `netmap` / `dpdk` / `io_uring` / `memif`） |
| `build.sh`           | 解析 flags → 调 `meson setup` → 调度 docker → 跑 `ninja` |
| `.dockerignore`      | 缩小 build context |

---

## 路线图

- [x] 架构 & 线程模型设计
- [x] core：mbuf / mempool / SPSC ring / flow hash
- [x] modules：`main + left_rx(tun) + worker + right_tx + right_rx + left_tx + timer + mgmt`
- [x] DPI 插件框架（`dns` / `tls` / `http` 占位，可通过 config 热启停/改优先级）
- [x] `right_*` 后端：
  - TCP：`kernel_socket`
  - UDP：`kernel_socket` / `raw_socket` / `tun` / `pcap` / `af_xdp` / `netmap` / `dpdk` / `memif`
  - ICMP：`raw_socket` / `tun` / `pcap` / `af_xdp` / `netmap` / `dpdk` / `memif`
  - 三者都有 client + server 模式；`kernel_socket` 可选 `io_cfg.backend=io_uring`（需 `./build.sh --io-uring`）；
    `pcap` 需 `--pcap`，`af_xdp` 需 `--xdp`，`netmap` 需 `--netmap`，`dpdk` 需 `--dpdk`，`memif` 需 `--memif`
- [x] timer wheel + 会话老化（简化版）
- [x] mgmt：Unix socket 文本接口（`help` / `stat` / `sessions` / `reload [path]` / `quit`）
- [x] JSON 配置加载（yyjson）+ CPU 亲和性
- [x] 配置热重载（log.level / session.\*\_ttl\_ms / dpi.plugins[].enable）
- [ ] DPI 插件实体化：TLS SNI 真正解析、HTTP Host、DNS QNAME / 返回 IP
- [x] 右手侧剩余 io：netmap（vendored header-only，nm\_open API；UDP/ICMP client+server）
- [x] 左/右手 DPDK 后端（拷贝版、单 queue；`./build.sh --dpdk`）；
      待办：零拷贝（让 `pp_pkt_t` 挂载 `rte_mbuf`）、多 queue / RSS、用户态 ARP（当前需 `peer_mac` 静态配置）
- [x] 右手侧 memif 后端（libmemif + VPP sidecar；clab matrix 已覆盖 UDP/memif）
- [x] kernel_socket io_uring 后端（`io_cfg.backend=io_uring`，支持 batch_tx / tx_zc 回退）
- [ ] netmap / AF\_XDP 优化：多 ring 聚合、zero-copy 直通（当前左手 rx 仍拷贝到 mempool）、
      真实 peer MAC 学习改进
- [x] 左手侧 I/O 后端 vtable：`tun` / `raw_socket` / `af_xdp` / `pcap` / `netmap` / `dpdk` 均已注册
- [ ] 左手侧 left_rx/left_tx 端到端打通剩余后端的 e2e 测试
- [ ] 左手侧 I/O 后端：继续补齐 AF\_XDP / netmap / pcap / DPDK 的更完整 e2e 与性能验证
- [ ] tunnel 协议：KCP / QUIC 封装（目前只有 TCP/UDP/ICMP 的 `proto`）
- [x] mgmt：Prometheus exporter（`mgmt.metrics.enable`，HTTP `/metrics`）
- [ ] RCU 化 session 快照（当前 snapshot 直接读 worker 槽位，理论上有撕裂）
- [ ] forwarding 策略引擎（按 app\_proto / 5-tuple 选 tunnel），目前固定 `tunnel_idx=0`
- [ ] 多 worker shard 回路真正打通（right\_rx → worker\_back\_ring 的 sid→shard 路由）
- [ ] 单测覆盖扩展：session 老化、worker 路径、DPI chain 排序
- [x] E2E 集成测试（`tests/e2e.sh`：双进程 + /metrics + mgmt socket + reload + 优雅退出）

---

## 文档索引

- [`doc/architecture.mmd`](doc/architecture.mmd) — 总体架构
- [`doc/threads.mmd`](doc/threads.mmd) — 线程与队列拓扑
- [`doc/modules.mmd`](doc/modules.mmd) — 源码模块依赖
- [`doc/dataflow.mmd`](doc/dataflow.mmd) — 端到端时序
- [`doc/session-state.mmd`](doc/session-state.mmd) — 会话状态机
- [`doc/perf.md`](doc/perf.md) — clab 性能测试框架与矩阵记录
- [`doc/debug.md`](doc/debug.md) — clab / 本地常用排障命令
- [`tests/clab/README.md`](tests/clab/README.md) — containerlab 拓扑、leaf 预热镜像、matrix 用法
- [`tests/clab/reports/20260702-matrix.md`](tests/clab/reports/20260702-matrix.md) — 当前全后端 matrix 样例结果

> Mermaid 文档可在 GitHub / VSCode（带 mermaid 插件）/ Obsidian 直接预览。

---

## 许可

见 [LICENSE](LICENSE)。
