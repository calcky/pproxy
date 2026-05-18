/*
 * src/main.c -- 程序入口
 *
 * 流程：
 *   1) 解析命令行（-c cfg.json / -L level / -s host:port）
 *   2) apply_defaults(rt)：填 rt 中所有"配置字段"的默认值
 *   3) 若 -c 指定了配置文件：pp_config_load() 覆盖字段
 *   4) 若 -s 指定了上游：覆盖第一条 tunnel 的 server
 *   5) build_runtime_resources(rt)：按 rt 中的字段创建 pool/ring/shard/io/tunnel
 *   6) 注册模块 → init → start → 等信号 → stop → destroy → 释放资源
 */
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <unistd.h>
#include <getopt.h>

#include "pproxy/pproxy.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/ring.h"
#include "pproxy/session.h"
#include "pproxy/dpi.h"
#include "pproxy/pkt_io.h"
#include "pproxy/tunnel.h"
#include "pproxy/module.h"
#include "modules/runtime.h"
#include "modules/modules.h"
#include "config/config.h"

pp_runtime_t *g_rt;

extern pp_module_ops_t pp_mod_left_rx_ops;
extern pp_module_ops_t pp_mod_left_tx_ops;
extern pp_module_ops_t pp_mod_worker_ops;
extern pp_module_ops_t pp_mod_right_rx_ops;
extern pp_module_ops_t pp_mod_right_tx_ops;
extern pp_module_ops_t pp_mod_timer_ops;
extern pp_module_ops_t pp_mod_mgmt_ops;

static atomic_int g_quit;
void pp_main_request_quit(void) { atomic_store(&g_quit, 1); }
static void on_signal(int sig) { (void)sig; pp_main_request_quit(); }

/* ---------- 注册 I/O / tunnel / DPI 后端 ---------- */
static void register_backends(void)
{
    pp_pkt_io_register(&pp_io_tun);
    pp_pkt_io_register(&pp_io_raw_socket);
#ifdef PP_HAVE_XDP
    pp_pkt_io_register(&pp_io_af_xdp);
#endif
#ifdef PP_HAVE_NETMAP
    pp_pkt_io_register(&pp_io_netmap);
#endif
#ifdef PP_HAVE_PCAP
    pp_pkt_io_register(&pp_io_pcap);
#endif
#ifdef PP_HAVE_DPDK
    pp_pkt_io_register(&pp_io_dpdk);
#endif
    pp_tunnel_register(&pp_tunnel_tcp);
    pp_tunnel_register(&pp_tunnel_udp);
    pp_tunnel_register(&pp_tunnel_icmp);
}

/* ---------- 阶段 1：只填"配置字段"，不分配任何资源 ---------- */
static void apply_defaults(pp_runtime_t *rt)
{
    rt->n_workers = 2;
    rt->n_tunnels = 1;

    rt->mempool_cfg = (pp_mempool_cfg_t){
        .nelem = 2048, .buf_size = 2048, .headroom = 64, .cpu = -1,
    };

    rt->ring_cap_worker_rx   = 4096;
    rt->ring_cap_worker_back = 4096;
    rt->ring_cap_worker_ctrl = 256;
    rt->ring_cap_right_tx    = 4096;
    rt->ring_cap_left_tx     = 4096;

    /* 左手默认 tun pproxy0 */
    rt->left_kind             = PP_IO_TUN;
    rt->left_cfg.kind         = PP_IO_TUN;
    rt->left_cfg.name         = "left0";
    rt->left_cfg.u.tun.ifname = "pproxy0";
    rt->left_cfg.u.tun.mtu    = 1500;
    rt->left_cfg.u.tun.no_pi  = true;

    /* 右手默认：单条 tcp to 127.0.0.1:9000 */
    rt->tun_proto                 = PP_PROTO_TCP;
    rt->tun_cfg[0].proto          = PP_PROTO_TCP;
    rt->tun_cfg[0].io             = PP_TIO_KERNEL_SOCKET;
    rt->tun_cfg[0].name           = "primary";
    rt->tun_cfg[0].max_sessions   = 4096;
    rt->tun_cfg[0].u.tcp.nodelay  = true;
    (void)pp_endpoint_parse("127.0.0.1:9000", &rt->tun_cfg[0].server);

    rt->session_max_per_shard = 4096;
    rt->session_idle_ttl_ns   = 300ULL * 1000000000ULL;
    rt->session_syn_ttl_ns    =  30ULL * 1000000000ULL;
    rt->session_fin_ttl_ns    =  30ULL * 1000000000ULL;

    rt->mgmt_unix_socket = NULL;   /* mgmt 目前固定 /tmp/pproxy.sock */

    /* affinity: 全部 -1（不绑核） */
    rt->affinity.left_rx = -1;
    rt->affinity.left_tx = -1;
    rt->affinity.timer   = -1;
    rt->affinity.mgmt    = -1;
    for (int i = 0; i < PP_MAX_WORKERS; i++) rt->affinity.worker[i]   = -1;
    for (int j = 0; j < PP_MAX_TUNNELS; j++) {
        rt->affinity.right_tx[j] = -1;
        rt->affinity.right_rx[j] = -1;
    }
}

/* 按 rt->dpi_plugins[] 查名字，返回 {enable, priority_override}；
 * 若该 name 未在配置里出现，默认 enable=true、不覆盖优先级。 */
static void lookup_dpi_cfg(const pp_runtime_t *rt, const char *name,
                           bool *enable, int *priority_override)
{
    *enable = true;
    *priority_override = -1;
    for (int i = 0; i < rt->dpi_n_plugins; i++) {
        if (strcmp(rt->dpi_plugins[i].name, name) != 0) continue;
        *enable = rt->dpi_plugins[i].enable;
        if (rt->dpi_plugins[i].has_priority)
            *priority_override = rt->dpi_plugins[i].priority;
        return;
    }
}

static void build_dpi_chain(pp_runtime_t *rt)
{
    const pp_dpi_ops_t *known[] = { &pp_dpi_dns, &pp_dpi_tls, &pp_dpi_http };
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        const pp_dpi_ops_t *ops = known[i];
        bool enable; int prio;
        lookup_dpi_cfg(rt, ops->name, &enable, &prio);
        /* 始终注册：即便 config 说 disable，也保留槽位，仅把 enabled 原子位置 false；
         * 这样 mgmt reload 可以热切换而不用重启。 */
        pp_dpi_chain_register_ex(rt->dpi, ops, prio);
        if (!enable) {
            pp_dpi_chain_set_enabled(rt->dpi, ops->name, false);
            PP_INFO("dpi: plugin %s disabled by config (slot kept for hot-reload)",
                    ops->name);
        }
    }
}

/* ---------- 阶段 2：按 rt 中的字段实例化资源 ---------- */
static int build_runtime_resources(pp_runtime_t *rt)
{
    rt->pool = pp_mempool_create(&rt->mempool_cfg);
    if (!rt->pool) return PP_ERR_NOMEM;

    rt->dpi = pp_dpi_chain_create();
    build_dpi_chain(rt);

    /* 左手 I/O */
    rt->left_cfg.pool = rt->pool;
    rt->left_ops      = pp_pkt_io_lookup(rt->left_cfg.kind);
    if (!rt->left_ops) return PP_ERR_NOSUPPORT;
    int r = rt->left_ops->open(&rt->left_cfg, &rt->left_ctx);
    if (r != PP_OK) {
        PP_ERROR("left I/O open failed: %s (need CAP_NET_ADMIN?)", pp_strerror(r));
        return r;
    }

    /* 右手 tunnel（按 proto 查表；open 内部按 io 分发） */
    for (int j = 0; j < rt->n_tunnels; j++) {
        rt->tun_ops[j] = pp_tunnel_lookup(rt->tun_cfg[j].proto);
        if (!rt->tun_ops[j]) {
            PP_ERROR("tunnel[%d]: proto=%d not registered", j, rt->tun_cfg[j].proto);
            return PP_ERR_NOSUPPORT;
        }
        r = rt->tun_ops[j]->open(&rt->tun_cfg[j], &rt->tun_ctx[j]);
        if (r != PP_OK) {
            PP_ERROR("tunnel[%d] open failed: %s", j, pp_strerror(r));
            return r;
        }
    }

    /* SessionTable shards */
    for (int i = 0; i < rt->n_workers; i++) {
        pp_session_cfg_t sc = {
            .max_sessions = rt->session_max_per_shard,
            .idle_ttl_ns  = rt->session_idle_ttl_ns,
            .syn_ttl_ns   = rt->session_syn_ttl_ns,
            .fin_ttl_ns   = rt->session_fin_ttl_ns,
            .shard_id     = (uint16_t)i,
            .shard_total  = (uint16_t)rt->n_workers,
        };
        rt->shards[i] = pp_session_shard_create(&sc);
    }

    /* rings */
    pp_ring_cfg_t rc = { 0 };
    for (int i = 0; i < rt->n_workers; i++) {
        rc.kind = PP_RING_SPSC; rc.name = "worker_rx";
        rc.capacity = rt->ring_cap_worker_rx;
        rt->worker_rx_ring[i] = pp_ring_create(&rc);

        rc.kind = PP_RING_MPSC; rc.name = "worker_back";
        rc.capacity = rt->ring_cap_worker_back;
        rt->worker_back_ring[i] = pp_ring_create(&rc);

        rc.kind = PP_RING_MPSC; rc.name = "worker_ctrl";
        rc.capacity = rt->ring_cap_worker_ctrl;
        rt->worker_ctrl_ring[i] = pp_ring_create(&rc);
    }
    for (int j = 0; j < rt->n_tunnels; j++) {
        rc.kind = PP_RING_MPSC; rc.name = "right_tx";
        rc.capacity = rt->ring_cap_right_tx;
        rt->right_tx_ring[j] = pp_ring_create(&rc);
    }
    rc.kind = PP_RING_MPSC; rc.name = "left_tx";
    rc.capacity = rt->ring_cap_left_tx;
    rt->left_tx_ring = pp_ring_create(&rc);

    return PP_OK;
}

/* ---------- 模块编排 ---------- */
static pp_module_t mod_storage[3 + PP_MAX_WORKERS + 2 * PP_MAX_TUNNELS];
static int mod_n;

static pp_module_t *new_mod(const char *name, int cpu, pp_module_ops_t *ops)
{
    pp_module_t *m = &mod_storage[mod_n++];
    snprintf(m->name, sizeof m->name, "%s", name);
    m->cpu = cpu;
    m->lwp = -1;
    m->ops = ops;
    return m;
}

static int register_modules(pp_runtime_t *rt)
{
    pp_module_register(new_mod("left_rx", rt->affinity.left_rx, &pp_mod_left_rx_ops));
    pp_module_register(new_mod("left_tx", rt->affinity.left_tx, &pp_mod_left_tx_ops));

    char nm[32];
    for (int i = 0; i < rt->n_workers; i++) {
        snprintf(nm, sizeof nm, "worker%d", i);
        pp_module_t *m = new_mod(nm, rt->affinity.worker[i], &pp_mod_worker_ops);
        pp_worker_set_index(m, i);
        pp_module_register(m);
    }
    for (int j = 0; j < rt->n_tunnels; j++) {
        snprintf(nm, sizeof nm, "right_tx%d", j);
        pp_module_t *m = new_mod(nm, rt->affinity.right_tx[j], &pp_mod_right_tx_ops);
        pp_right_tx_set_index(m, j);
        pp_module_register(m);

        snprintf(nm, sizeof nm, "right_rx%d", j);
        m = new_mod(nm, rt->affinity.right_rx[j], &pp_mod_right_rx_ops);
        pp_right_rx_set_index(m, j);
        pp_module_register(m);
    }
    pp_module_register(new_mod("timer", rt->affinity.timer, &pp_mod_timer_ops));
    pp_module_register(new_mod("mgmt",  rt->affinity.mgmt,  &pp_mod_mgmt_ops));
    return PP_OK;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [-c cfg.json] [-L level] [-s host:port]\n"
        "  -c  JSON config file (overrides defaults; -s overrides tunnels[0].server)\n"
        "  -L  log level: trace|debug|info|warn|error (default info)\n"
        "  -s  upstream server endpoint (default 127.0.0.1:9000)\n"
        "ctrl: echo 'help'|'stat'|'sessions'|'reload [path]'|'quit' | nc -U /tmp/pproxy.sock\n",
        prog);
}

int main(int argc, char **argv)
{
    const char     *cfg_path   = NULL;
    const char     *server_cli = NULL;
    pp_log_level_t  lvl_cli    = PP_LOG_INFO;
    bool            lvl_given  = false;

    int c;
    while ((c = getopt(argc, argv, "c:L:s:h")) != -1) {
        switch (c) {
        case 'c': cfg_path = optarg; break;
        case 'L':
            lvl_given = true;
            if      (!strcmp(optarg, "trace")) lvl_cli = PP_LOG_TRACE;
            else if (!strcmp(optarg, "debug")) lvl_cli = PP_LOG_DEBUG;
            else if (!strcmp(optarg, "info"))  lvl_cli = PP_LOG_INFO;
            else if (!strcmp(optarg, "warn"))  lvl_cli = PP_LOG_WARN;
            else if (!strcmp(optarg, "error")) lvl_cli = PP_LOG_ERROR;
            break;
        case 's': server_cli = optarg; break;
        case 'h': default: usage(argv[0]); return c == 'h' ? 0 : 1;
        }
    }

    /* 先按命令行 -L（若有）初始化日志；parse_log 可能再次覆盖 */
    pp_log_init(lvl_given ? lvl_cli : PP_LOG_INFO, NULL);

    register_backends();

    g_rt = calloc(1, sizeof *g_rt);
    if (!g_rt) return 1;

    apply_defaults(g_rt);

    if (cfg_path) {
        if (pp_config_load(cfg_path, g_rt) != PP_OK) return 1;
        g_rt->cfg_path = cfg_path;    /* mgmt reload 缺省路径 */
        /* -L 命令行若已给，相对 JSON 优先：再覆盖回去 */
        if (lvl_given) pp_log_init(lvl_cli, NULL);
    }

    if (server_cli) {
        if (g_rt->tun_cfg[0].mode == PP_TMODE_SERVER) {
            PP_ERROR("-s only valid for client-mode tunnels");
            return 1;
        }
        if (pp_endpoint_parse(server_cli, &g_rt->tun_cfg[0].server) != PP_OK) {
            PP_ERROR("invalid -s endpoint: %s", server_cli);
            return 1;
        }
    }

    char ep[128] = "";
    pp_tunnel_cfg_t *t0 = &g_rt->tun_cfg[0];
    if (t0->mode == PP_TMODE_SERVER) pp_endpoint_format(&t0->listen, ep, sizeof ep);
    else                             pp_endpoint_format(&t0->server, ep, sizeof ep);
    PP_INFO("pproxy %d.%d.%d starting (workers=%d tunnels=%d primary=%s %s)",
            PP_VERSION_MAJOR, PP_VERSION_MINOR, PP_VERSION_PATCH,
            g_rt->n_workers, g_rt->n_tunnels, ep,
            t0->mode == PP_TMODE_SERVER ? "[server]" : "[client]");

    if (build_runtime_resources(g_rt) != PP_OK) return 1;

    if (register_modules(g_rt) != PP_OK) return 1;
    if (pp_module_init_all(NULL)  != PP_OK) return 1;

    signal(SIGINT,  on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);

    if (pp_module_start_all() != PP_OK) return 1;
    PP_INFO("pproxy: all modules started; PID=%d", getpid());

    while (!atomic_load(&g_quit)) {
        struct timespec ts = {0, 200 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    PP_INFO("pproxy: shutting down");

    pp_module_stop_all();
    pp_module_destroy_all();

    if (g_rt->left_ctx) g_rt->left_ops->close(g_rt->left_ctx);
    for (int j = 0; j < g_rt->n_tunnels; j++)
        if (g_rt->tun_ctx[j]) g_rt->tun_ops[j]->close(g_rt->tun_ctx[j]);
    for (int i = 0; i < g_rt->n_workers; i++) {
        pp_session_shard_destroy(g_rt->shards[i]);
        pp_ring_destroy(g_rt->worker_rx_ring[i]);
        pp_ring_destroy(g_rt->worker_back_ring[i]);
        pp_ring_destroy(g_rt->worker_ctrl_ring[i]);
    }
    for (int j = 0; j < g_rt->n_tunnels; j++)
        pp_ring_destroy(g_rt->right_tx_ring[j]);
    pp_ring_destroy(g_rt->left_tx_ring);
    pp_dpi_chain_destroy(g_rt->dpi);
    pp_mempool_destroy(g_rt->pool);
    pp_config_free(g_rt);
    free(g_rt);

    PP_INFO("pproxy: bye");
    return 0;
}
