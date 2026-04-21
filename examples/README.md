# pproxy 配置示例

> 当前主线代码（MVP）仍是命令行 `-s host:port` 启动并使用硬编码默认值；
> 本目录的 JSON 仅作为 **配置 schema 设计稿**，等 Phase-2 加入 `parse_config()`
> 之后可直接 `pproxy -c examples/config.example.json` 运行。

## 文件清单

| 文件 | 说明 |
|---|---|
| `config.example.json`  | 完整可用的默认配置（tun → tcp，2 worker） |
| `config.snippets.json` | 各 I/O / tunnel 后端的可替换片段 |

## 字段映射到 C 结构

| JSON 段 | C 结构 | 头文件 |
|---|---|---|
| `runtime.mempool`   | `pp_mempool_cfg_t`  | `include/pproxy/packet.h`  |
| `runtime.rings`     | `pp_ring_cfg_t`     | `include/pproxy/ring.h`    |
| `left`              | `pp_io_cfg_t`       | `include/pproxy/pkt_io.h`  |
| `tunnels[]`         | `pp_tunnel_cfg_t`   | `include/pproxy/tunnel.h`  |
| `session`           | `pp_session_cfg_t`  | `include/pproxy/session.h` |
| `dpi.plugins[]`     | `pp_dpi_ops_t`      | `include/pproxy/dpi.h`     |
| `affinity.*`        | `pp_module_t.cpu`   | `include/pproxy/module.h`  |

## 关键字段速查

### `log`
- `level`：`trace` / `debug` / `info` / `warn` / `error`
- `file`：`null` 表示输出到 stderr
- `color`：tty 下是否带 ANSI 颜色

### `runtime`
- `workers`：worker 线程数；session 表分片数同此值
- `mempool.elements`：mbuf 数量；峰值并发包 + ring 缓冲量都来自这里
- `mempool.buf_size`：单个 mbuf 字节数（≥ MTU + 头预留）
- `rings.*_capacity`：每条 SPSC/MPSC ring 槽位数（必须是 2 的幂）

### `left`
左手包 I/O，`kind` 二选一：
`tun` / `raw_socket` / `af_xdp` / `netmap` / `pcap`，各自子段见 `config.snippets.json`。

### `tunnels[]`
右手隧道数组，每条 = `(proto, io)` 组合，独立 `right_tx + right_rx` 线程对：
- `proto`：协议编码 —— `tcp` / `udp` / `icmp`（未来 `kcp` / `quic`）
- `io`：I/O 后端 —— `kernel_socket`（默认）/ `raw_socket` / `af_xdp` / `netmap`
- `server`：远端 `host:port`（client 模式）
- `listen`：本地绑定 `host:port`（server 模式）
- `mode`：`client`（默认）/ `server`
- `bind`：客户端可选本地绑定
- `max_sessions`：本条 tunnel 上承载 session 上限
- 协议字段：`tcp.nodelay` / `tcp.reconnect_ms` / `udp.mtu` / `icmp.identifier_base` / `icmp.reply_only`
- `io_cfg.*`：I/O 后端参数（仅当 `io != kernel_socket` 时填）

兼容矩阵：

| proto \ io | kernel_socket | raw_socket | af_xdp | netmap |
|---|---|---|---|---|
| tcp  | ✅ | ❌ | ❌ | ❌ |
| udp  | ✅ | ✅ | ✅ | ✅ |
| icmp | ⚠️ | ✅ | ✅ | ✅ |
| kcp  | ✅ | ✅ | ✅ | ✅ |
| quic | ✅ | ✅ | ✅ | ✅ |

不支持的组合在 `tunnel_open()` 里返回 `PP_ERR_NOSUPPORT`。

### `session`
- `max_per_shard`：单 shard 容量；总容量 = `workers × max_per_shard`
- `idle_ttl_ms` / `syn_ttl_ms` / `fin_ttl_ms`：状态超时
- `gc_interval_ms`：timer 线程驱动 GC 的节拍

### `dpi`
- `max_pkts_per_session`：每 session 最多喂多少包给 DPI 后早停
- `plugins[].priority`：数字小者先匹配（DNS 5 先于 TLS 10 先于 HTTP 20）

### `affinity`
- 标量：单线程绑核
- 数组：多线程按下标取核（`worker[i]` 绑到 `affinity.worker[i % len]`）
- `-1`：不绑定，由内核调度

## 运行（待 Phase-2 实现 `-c`）

```bash
sudo ./build/pproxy -c examples/config.example.json -L info
```

调试某条配置：

```bash
sudo ./build/pproxy -c examples/config.example.json -L debug --dry-run
```
