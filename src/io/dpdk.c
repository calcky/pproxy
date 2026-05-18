/* src/io/dpdk.c -- DPDK PMD I/O
 *
 * 仅在 -Ddpdk=true（PP_HAVE_DPDK）时编译。两部分内容：
 *   (1) 左手 pp_pkt_io_ops_t 下的 dpdk 后端 pp_io_dpdk；
 *   (2) 右手 tunnel 用的 pp_dpdk_io_* 薄封装。
 *
 * 拷贝版语义：rx 把 rte_mbuf 数据 memcpy 进 pp_pkt_t；tx 反向。pp_pkt_t 生命周期
 * 与现有 af_xdp 后端一致，不需要任何上层路径改动。
 */
#ifdef PP_HAVE_DPDK

#include "dpdk.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_ether.h>
#include <rte_version.h>

#include "pproxy/pkt_io.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"

/* ====================================================================
 * 通用：EAL 进程级单例初始化 + 端口生命周期管理
 * ==================================================================== */

#define PP_DPDK_RX_DESC        1024
#define PP_DPDK_TX_DESC        1024
#define PP_DPDK_BURST          32      /* 与 rte_eth_rx_burst 单次量纲一致 */
#define PP_DPDK_DEFAULT_FRAMES 8192
#define PP_DPDK_MIN_FRAMES     1024
#define PP_DPDK_ETH_HDR        14

static pthread_mutex_t g_eal_lock = PTHREAD_MUTEX_INITIALIZER;
static int             g_eal_inited = 0;
static char           *g_eal_first_args = NULL;  /* 调试用：记录首次初始化的参数串 */

/* per-port 状态；本期约束「每端口至多一个 ctx」 */
typedef struct dpdk_port_state {
    bool             configured;
    bool             started;
    int              refcount;     /* 当前 open 的 ctx 数（始终为 0 或 1） */
    struct rte_mempool *pool;
    uint16_t         queue_id;
    uint32_t         nframes;
    uint8_t          mac[6];
    char             ifname[64];
} dpdk_port_state_t;

static dpdk_port_state_t g_ports[RTE_MAX_ETHPORTS];

/* 按空白拆分 eal_args 成 argv（带 argv[0]="pproxy"）；返回需调用方 free(argv) 和 free(buf)。 */
static int tokenize_args(const char *args, int *out_argc, char ***out_argv, char **out_buf)
{
    const char *defaults = "pproxy -l 0 --proc-type=primary --in-memory";
    const char *src = (args && args[0]) ? args : defaults;
    char *buf = strdup(src);
    if (!buf) return PP_ERR_NOMEM;

    if (args && args[0]) {
        /* 用户串里若没显式 argv[0] 习惯，仍预 prepend "pproxy" 兼容 rte_eal_init */
        if (buf[0] != '-' && (buf[0] != 'p' || strncmp(buf, "pproxy", 6) != 0)) {
            char *with0 = NULL;
            if (asprintf(&with0, "pproxy %s", src) < 0) { free(buf); return PP_ERR_NOMEM; }
            free(buf);
            buf = with0;
        }
    }

    int cap = 16;
    char **argv = calloc(cap, sizeof *argv);
    if (!argv) { free(buf); return PP_ERR_NOMEM; }
    int argc = 0;
    char *save = NULL;
    for (char *t = strtok_r(buf, " \t", &save); t; t = strtok_r(NULL, " \t", &save)) {
        if (argc + 1 >= cap) {
            cap *= 2;
            char **nv = realloc(argv, cap * sizeof *nv);
            if (!nv) { free(argv); free(buf); return PP_ERR_NOMEM; }
            argv = nv;
        }
        argv[argc++] = t;
    }
    argv[argc] = NULL;
    *out_argc = argc;
    *out_argv = argv;
    *out_buf  = buf;
    return PP_OK;
}

static int ensure_eal(const char *eal_args)
{
    pthread_mutex_lock(&g_eal_lock);
    if (g_eal_inited) {
        if (eal_args && eal_args[0] && g_eal_first_args
            && strcmp(g_eal_first_args, eal_args) != 0) {
            PP_WARN("dpdk: EAL already initialized with '%s'; new ctx requested '%s' (忽略，复用既有 EAL)",
                    g_eal_first_args, eal_args);
        }
        pthread_mutex_unlock(&g_eal_lock);
        return PP_OK;
    }

    int argc = 0;
    char **argv = NULL;
    char *buf = NULL;
    int rc = tokenize_args(eal_args, &argc, &argv, &buf);
    if (rc != PP_OK) { pthread_mutex_unlock(&g_eal_lock); return rc; }

    int eal_rc = rte_eal_init(argc, argv);
    if (eal_rc < 0) {
        /* strtok_r 已把 buf 改成多段以 NUL 分隔；用 eal_args（或默认串）原文打日志。 */
        PP_ERROR("dpdk: rte_eal_init failed (rc=%d, %s); args=\"%s\"",
                 eal_rc, rte_strerror(rte_errno),
                 (eal_args && eal_args[0]) ? eal_args
                                           : "pproxy -l 0 --proc-type=primary --in-memory");
        free(argv);
        free(buf);
        pthread_mutex_unlock(&g_eal_lock);
        return PP_ERR_IO;
    }
    free(argv);
    g_eal_inited = 1;
    g_eal_first_args = strdup(eal_args ? eal_args : "");
    PP_INFO("dpdk: EAL initialized (consumed %d args; DPDK %s)",
            eal_rc, rte_version());
    free(buf);
    pthread_mutex_unlock(&g_eal_lock);
    return PP_OK;
}

/* 配置 + 启动指定端口，单 rx/tx queue。复用时 refcount++ 即可。 */
static int port_acquire(uint16_t port_id, uint16_t queue_id, uint32_t nframes_req)
{
    if (port_id >= RTE_MAX_ETHPORTS) return PP_ERR_INVAL;
    if (!rte_eth_dev_is_valid_port(port_id)) {
        PP_ERROR("dpdk: invalid port_id=%u (no PMD bound 或未发现该口)", port_id);
        return PP_ERR_INVAL;
    }

    dpdk_port_state_t *st = &g_ports[port_id];
    if (st->configured) {
        if (st->refcount > 0) {
            PP_ERROR("dpdk: port_id=%u 已被另一个 ctx 占用（单 queue 复用未实现）", port_id);
            return PP_ERR_EXIST;
        }
    }

    uint32_t nframes = nframes_req ? nframes_req : PP_DPDK_DEFAULT_FRAMES;
    if (nframes < PP_DPDK_MIN_FRAMES) nframes = PP_DPDK_MIN_FRAMES;

    char pool_name[RTE_MEMPOOL_NAMESIZE];
    snprintf(pool_name, sizeof pool_name, "pp_dpdk_mb_%u", port_id);
    struct rte_mempool *pool = rte_mempool_lookup(pool_name);
    if (!pool) {
        pool = rte_pktmbuf_pool_create(pool_name, nframes, 256, 0,
                                       RTE_MBUF_DEFAULT_BUF_SIZE,
                                       (int)rte_eth_dev_socket_id(port_id));
        if (!pool) {
            PP_ERROR("dpdk: rte_pktmbuf_pool_create(%s) failed: %s",
                     pool_name, rte_strerror(rte_errno));
            return PP_ERR_NOMEM;
        }
    }

    struct rte_eth_conf cfg;
    memset(&cfg, 0, sizeof cfg);
    /* cfg 默认全 0；mq_mode = 0 与 RTE_ETH_MQ_RX_NONE / ETH_MQ_RX_NONE 一致，无需显式设置。 */

    int rc = rte_eth_dev_configure(port_id, 1, 1, &cfg);
    if (rc < 0) {
        PP_ERROR("dpdk: rte_eth_dev_configure(port=%u) rc=%d", port_id, rc);
        return PP_ERR_IO;
    }

    uint16_t rxd = PP_DPDK_RX_DESC, txd = PP_DPDK_TX_DESC;
    (void)rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &rxd, &txd);

    rc = rte_eth_rx_queue_setup(port_id, queue_id, rxd,
                                rte_eth_dev_socket_id(port_id), NULL, pool);
    if (rc < 0) {
        PP_ERROR("dpdk: rx_queue_setup(port=%u q=%u) rc=%d", port_id, queue_id, rc);
        return PP_ERR_IO;
    }
    rc = rte_eth_tx_queue_setup(port_id, queue_id, txd,
                                rte_eth_dev_socket_id(port_id), NULL);
    if (rc < 0) {
        PP_ERROR("dpdk: tx_queue_setup(port=%u q=%u) rc=%d", port_id, queue_id, rc);
        return PP_ERR_IO;
    }

    rc = rte_eth_dev_start(port_id);
    if (rc < 0) {
        PP_ERROR("dpdk: rte_eth_dev_start(port=%u) rc=%d", port_id, rc);
        return PP_ERR_IO;
    }

    (void)rte_eth_promiscuous_enable(port_id);

    struct rte_ether_addr mac;
    if (rte_eth_macaddr_get(port_id, &mac) == 0) {
        memcpy(st->mac, mac.addr_bytes, 6);
    } else {
        memset(st->mac, 0, 6);
    }

    rte_eth_dev_get_name_by_port(port_id, st->ifname);
    st->configured = true;
    st->started    = true;
    st->refcount   = 1;
    st->pool       = pool;
    st->queue_id   = queue_id;
    st->nframes    = nframes;

    PP_INFO("dpdk: port=%u (%s) up: queue=%u rxd=%u txd=%u mbufs=%u mac=%02x:%02x:%02x:%02x:%02x:%02x",
            port_id, st->ifname, queue_id, rxd, txd, nframes,
            st->mac[0], st->mac[1], st->mac[2], st->mac[3], st->mac[4], st->mac[5]);
    return PP_OK;
}

static void port_release(uint16_t port_id)
{
    if (port_id >= RTE_MAX_ETHPORTS) return;
    dpdk_port_state_t *st = &g_ports[port_id];
    if (st->refcount > 0) st->refcount--;
    if (st->refcount == 0 && st->started) {
        rte_eth_dev_stop(port_id);
        rte_eth_dev_close(port_id);
        st->started    = false;
        st->configured = false;
        /* mempool 不主动释放（DPDK 没有可靠的 free API；hugepage 进程退出回收） */
        PP_INFO("dpdk: port=%u stopped", port_id);
    }
}

/* ====================================================================
 * 右手 pp_dpdk_io_* —— 与 xsk 同形态
 * ==================================================================== */

#define PP_DPDK_RX_STASH  9000  /* 单帧 IP 最大；与 xsk rx_stash 一致量级 */

struct pp_dpdk_io {
    uint16_t port_id;
    uint16_t queue_id;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    bool     has_peer_mac;
    char     ifname[64];

    /* rx_burst 收到的若干 mbuf 暂存于此，next_ip 一次返回一条 IP */
    struct rte_mbuf *rx_mbufs[PP_DPDK_BURST];
    uint16_t rx_n;
    uint16_t rx_i;

    /* next_ip 的回归 buffer（去掉 eth 头） */
    uint8_t  rx_stash[PP_DPDK_RX_STASH];
    size_t   rx_stash_len;
};

int pp_dpdk_io_new(struct pp_dpdk_io **out,
                   uint16_t port_id,
                   uint16_t queue_id,
                   uint32_t nframes,
                   const char *eal_args,
                   const uint8_t peer_mac[6])
{
    if (!out) return PP_ERR_INVAL;

    int rc = ensure_eal(eal_args);
    if (rc != PP_OK) return rc;

    rc = port_acquire(port_id, queue_id, nframes);
    if (rc != PP_OK) return rc;

    struct pp_dpdk_io *p = calloc(1, sizeof *p);
    if (!p) { port_release(port_id); return PP_ERR_NOMEM; }

    p->port_id  = port_id;
    p->queue_id = queue_id;
    memcpy(p->src_mac, g_ports[port_id].mac, 6);
    snprintf(p->ifname, sizeof p->ifname, "%s", g_ports[port_id].ifname);
    if (peer_mac) {
        memcpy(p->dst_mac, peer_mac, 6);
        p->has_peer_mac = true;
    }
    /* 没有 peer_mac 时先广播兜底（与 xsk 全 0 行为不同：DPDK 没有内核 ARP，全 0 直接丢） */
    if (!p->has_peer_mac) {
        memset(p->dst_mac, 0xff, 6);
        PP_WARN("dpdk: port=%u 未提供 peer_mac，使用 ff:ff:ff:ff:ff:ff（broadcast）作为兜底 dst_mac",
                port_id);
    }

    *out = p;
    return PP_OK;
}

void pp_dpdk_io_free(struct pp_dpdk_io *p)
{
    if (!p) return;
    /* 释放未消费完的 rx mbufs */
    for (uint16_t i = p->rx_i; i < p->rx_n; i++)
        rte_pktmbuf_free(p->rx_mbufs[i]);
    port_release(p->port_id);
    free(p);
}

int         pp_dpdk_io_get_fd    (const struct pp_dpdk_io *p) { (void)p; return -1; }
uint16_t    pp_dpdk_io_get_port  (const struct pp_dpdk_io *p) { return p ? p->port_id  : 0; }
uint16_t    pp_dpdk_io_get_queue (const struct pp_dpdk_io *p) { return p ? p->queue_id : 0; }
const char *pp_dpdk_io_get_ifname(const struct pp_dpdk_io *p) { return p ? p->ifname   : ""; }

void pp_dpdk_io_get_macs(const struct pp_dpdk_io *p, uint8_t out_src[6], uint8_t out_dst[6])
{
    if (out_src) memset(out_src, 0, 6);
    if (out_dst) memset(out_dst, 0, 6);
    if (!p) return;
    if (out_src) memcpy(out_src, p->src_mac, 6);
    if (out_dst) memcpy(out_dst, p->dst_mac, 6);
}

int pp_dpdk_io_refresh_arp(struct pp_dpdk_io *p, uint32_t l3_peer_be)
{
    (void)p; (void)l3_peer_be;
    /* DPDK 接管网卡后没有内核 ARP；待补：用户态 ARP 自答/学习或 io_cfg.peer_mac 静态配置 */
    return PP_ERR_NOSUPPORT;
}

int pp_dpdk_io_inject_ip(struct pp_dpdk_io *p, const uint8_t *ip, size_t len)
{
    if (!p) return PP_ERR_CLOSED;
    if (len == 0) return PP_ERR_INVAL;

    struct rte_mempool *pool = g_ports[p->port_id].pool;
    if (!pool) return PP_ERR_CLOSED;

    struct rte_mbuf *m = rte_pktmbuf_alloc(pool);
    if (!m) return PP_ERR_AGAIN;

    if (rte_pktmbuf_tailroom(m) < PP_DPDK_ETH_HDR + len) {
        rte_pktmbuf_free(m);
        return PP_ERR_INVAL;
    }

    uint8_t *frame = (uint8_t *)rte_pktmbuf_append(m, (uint16_t)(PP_DPDK_ETH_HDR + len));
    if (!frame) { rte_pktmbuf_free(m); return PP_ERR_NOMEM; }

    memcpy(frame,     p->dst_mac, 6);
    memcpy(frame + 6, p->src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;     /* ETHERTYPE_IPv4 */
    memcpy(frame + PP_DPDK_ETH_HDR, ip, len);

    uint16_t nsent = rte_eth_tx_burst(p->port_id, p->queue_id, &m, 1);
    if (nsent != 1) {
        rte_pktmbuf_free(m);
        return PP_ERR_AGAIN;
    }
    return (int)len;
}

const uint8_t *pp_dpdk_io_next_ip(struct pp_dpdk_io *p, size_t *out_len)
{
    if (!p) return NULL;

    if (p->rx_i >= p->rx_n) {
        p->rx_i = 0;
        p->rx_n = rte_eth_rx_burst(p->port_id, p->queue_id, p->rx_mbufs, PP_DPDK_BURST);
        if (p->rx_n == 0) return NULL;
    }

    struct rte_mbuf *m = p->rx_mbufs[p->rx_i++];
    const uint8_t *frame = rte_pktmbuf_mtod(m, const uint8_t *);
    uint16_t flen = rte_pktmbuf_pkt_len(m);

    size_t off = 0;
    if (flen >= PP_DPDK_ETH_HDR) {
        /* 跳过 VLAN tag（与 xsk 行为一致） */
        if (flen >= PP_DPDK_ETH_HDR + 4 && frame[12] == 0x81 && frame[13] == 0x00)
            off = PP_DPDK_ETH_HDR + 4;
        else
            off = PP_DPDK_ETH_HDR;
    }
    size_t ip_len = (flen > off) ? (size_t)(flen - off) : 0;
    if (ip_len > sizeof p->rx_stash) ip_len = sizeof p->rx_stash;
    memcpy(p->rx_stash, frame + off, ip_len);
    p->rx_stash_len = ip_len;

    rte_pktmbuf_free(m);

    if (out_len) *out_len = ip_len;
    return p->rx_stash;
}

/* ====================================================================
 * (1) 左手 pp_pkt_io_ops_t 下的 dpdk 后端
 * ==================================================================== */

typedef struct dpdk_ctx {
    struct pp_dpdk_io *io;
    pp_mempool_t      *pool;
    uint16_t           port_id;
    uint16_t           queue_id;
} dpdk_ctx_t;

static int dp_open(const pp_io_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->kind != PP_IO_DPDK) return PP_ERR_INVAL;
    if (!cfg->pool) {
        PP_ERROR("dpdk: mempool required for rx");
        return PP_ERR_INVAL;
    }

    dpdk_ctx_t *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->pool     = cfg->pool;
    c->port_id  = cfg->u.dpdk.port_id;
    c->queue_id = cfg->u.dpdk.queue_id;

    int rc = pp_dpdk_io_new(&c->io,
                            cfg->u.dpdk.port_id,
                            cfg->u.dpdk.queue_id,
                            cfg->u.dpdk.nframes,
                            cfg->u.dpdk.eal_args,
                            cfg->u.dpdk.has_peer_mac ? cfg->u.dpdk.peer_mac : NULL);
    if (rc != PP_OK) { free(c); return rc; }
    *out_ctx = c;
    return PP_OK;
}

static void dp_close(void *ctx)
{
    if (!ctx) return;
    dpdk_ctx_t *c = ctx;
    if (c->io) pp_dpdk_io_free(c->io);
    free(c);
}

static int dp_rx(void *ctx, pp_pkt_t **pkts, int max, int timeout_us)
{
    (void)timeout_us;
    dpdk_ctx_t *c = ctx;
    int got = 0;
    for (int i = 0; i < max; i++) {
        size_t n = 0;
        const uint8_t *ip = pp_dpdk_io_next_ip(c->io, &n);
        if (!ip) break;
        pp_pkt_t *p = pp_mempool_alloc(c->pool);
        if (!p) break;
        if (n > p->tailroom) { pp_pkt_put_ref(p); continue; }
        memcpy(p->data, ip, n);
        p->data_len   = (uint16_t)n;
        p->tailroom  -= (uint16_t)n;
        p->origin     = PP_PKT_FROM_XDP;    /* 复用：L3 起始、无 L2 */
        p->meta.l3_off   = 0;
        p->meta.l3_proto = IPPROTO_IP;
        if (n >= sizeof(struct iphdr)) {
            const struct iphdr *ih = (const struct iphdr *)p->data;
            p->meta.l4_proto = ih->protocol;
            p->meta.l4_off   = (uint16_t)(ih->ihl * 4);
        }
        p->meta.rx_ns = pp_now_ns();
        pkts[got++] = p;
    }
    return got;
}

static int dp_tx(void *ctx, pp_pkt_t **pkts, int n)
{
    dpdk_ctx_t *c = ctx;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        pp_pkt_t *p = pkts[i];
        int w = pp_dpdk_io_inject_ip(c->io, p->data, p->data_len);
        if (w < 0) break;
        sent++;
    }
    return sent;
}

static int dp_fd(void *ctx) { (void)ctx; return -1; }

static int dp_stat(void *ctx, char *json, size_t cap)
{
    dpdk_ctx_t *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"dpdk\",\"if\":\"%s\",\"port\":%u,\"queue\":%u}",
        pp_dpdk_io_get_ifname(c->io), c->port_id, c->queue_id);
}

const pp_pkt_io_ops_t pp_io_dpdk = {
    .name      = "dpdk",
    .kind      = PP_IO_DPDK,
    .caps      = PP_IO_CAP_L2 | PP_IO_CAP_BATCH | PP_IO_CAP_BUSY_POLL,
    .open      = dp_open,
    .close     = dp_close,
    .rx_burst  = dp_rx,
    .tx_burst  = dp_tx,
    .get_rx_fd = dp_fd,
    .get_tx_fd = dp_fd,
    .stat      = dp_stat,
};

#endif /* PP_HAVE_DPDK */
