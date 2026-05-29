/*
 * runtime.h -- 全局运行时上下文
 *
 * 由 main 创建并填充，所有模块的 init() 都通过它拿到自己需要的资源
 * （邻居模块的 ring、共享 mempool、I/O 后端 ctx 等）。
 */
#ifndef PPROXY_RUNTIME_H
#define PPROXY_RUNTIME_H

#include "pproxy/pproxy.h"
#include "pproxy/packet.h"
#include "pproxy/ring.h"
#include "pproxy/ring_ipc.h"
#include "pproxy/session.h"
#include "pproxy/dpi.h"
#include "pproxy/pkt_io.h"
#include "pproxy/tunnel.h"

#define PP_MAX_WORKERS  8
#define PP_MAX_TUNNELS  4

/* config 阶段填充；资源在随后由 build_runtime_resources 按这些字段实例化。 */
typedef struct pp_runtime {
    /* ---------- 配置字段（可由 JSON 或 defaults 填） ---------- */
    int               n_workers;
    int               n_tunnels;

    pp_mempool_cfg_t  mempool_cfg;

    uint32_t          ring_cap_worker_rx;
    uint32_t          ring_cap_worker_back;
    uint32_t          ring_cap_worker_ctrl;
    uint32_t          ring_cap_right_tx;
    uint32_t          ring_cap_left_tx;

    pp_ring_ipc_cfg_t ring_ipc;

    pp_io_kind_t      left_kind;
    pp_io_cfg_t       left_cfg;
    pp_tunnel_proto_t tun_proto;
    pp_tunnel_cfg_t   tun_cfg[PP_MAX_TUNNELS];

    /* session 默认（per-shard 都取这个） */
    size_t            session_max_per_shard;
    uint64_t          session_idle_ttl_ns;
    uint64_t          session_syn_ttl_ns;
    uint64_t          session_fin_ttl_ns;

    /* mgmt */
    const char       *mgmt_unix_socket;
    bool              metrics_enable;    /* mgmt.metrics.enable */
    bool              metrics_listen_set;/* 是否解析出了有效的 listen endpoint */
    pp_endpoint_t     metrics_listen;    /* mgmt.metrics.listen（HTTP exporter 监听地址） */

    /* 启动时 -c 指定的 config 文件路径；供 mgmt reload 缺省使用。NULL 表示未指定。 */
    const char       *cfg_path;

    /* DPI 插件配置（config 填，main 应用到 chain）
     * dpi_n_plugins == 0 表示"全默认"（所有内置插件启用，各自 baked-in priority）。 */
    struct {
        const char *name;
        bool        enable;
        bool        has_priority;
        int         priority;    /* 仅当 has_priority=true 时有效 */
    } dpi_plugins[PP_DPI_MAX_PLUGINS];
    int dpi_n_plugins;

    /* CPU 亲和性：-1 表示不绑定 */
    struct {
        int left_rx;
        int left_tx;
        int worker  [PP_MAX_WORKERS];
        int right_tx[PP_MAX_TUNNELS];
        int right_rx[PP_MAX_TUNNELS];
        int timer;
        int mgmt;
    } affinity;

    /* loader 内部 strdup 的字符串（pp_config_free 一次性释放） */
    char            **cfg_strings;
    size_t            cfg_strings_n;
    size_t            cfg_strings_cap;

    /* ---------- 共享资源（由 build_runtime_resources 创建） ---------- */
    pp_mempool_t     *pool;
    pp_dpi_chain_t   *dpi;

    /* I/O 后端实例（左手） */
    const pp_pkt_io_ops_t *left_ops;
    void                  *left_ctx;

    /* tunnel 实例（右手） */
    const pp_tunnel_ops_t *tun_ops[PP_MAX_TUNNELS];
    void                  *tun_ctx[PP_MAX_TUNNELS];

    /* 跨模块 ring */
    pp_ring_t        *worker_rx_ring [PP_MAX_WORKERS];   /* left_rx -> worker[i] (SPSC) */
    pp_ring_t        *worker_back_ring[PP_MAX_WORKERS];  /* right_rx -> worker[i] (MPSC) */
    pp_ring_t        *right_tx_ring[PP_MAX_TUNNELS];     /* worker -> right_tx[j] (MPSC) */
    pp_ring_t        *left_tx_ring;                       /* worker -> left_tx (MPSC) */
    pp_ring_t        *worker_ctrl_ring[PP_MAX_WORKERS];  /* timer/mgmt -> worker[i] (MPSC) */

    /* SessionTable 分片，每个 worker 一片；mgmt 用 */
    pp_session_shard_t *shards[PP_MAX_WORKERS];
} pp_runtime_t;

extern pp_runtime_t *g_rt;

#endif
