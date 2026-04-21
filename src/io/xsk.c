/* src/io/xsk.c -- AF_XDP / XSK 相关 I/O
 *
 * 本文件同时承载两个角色（两部分都只在 -Dxdp=true 时参与编译）：
 *   1) 左手侧 pp_pkt_io_ops_t 下的 AF_XDP 后端（目前是 stub）；
 *   2) 右手侧 tunnel 用的 "IP 注入/抽取" 薄封装 pp_xsk_io_*。
 */
#ifdef PP_HAVE_XDP

#include "xsk.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <xdp/xsk.h>
#include "pproxy/pkt_io.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"

/* ====================================================================
 * (1) 左手侧 pp_pkt_io_ops_t 下的 AF_XDP 后端
 *
 * 直接复用下面 (2) 的 pp_xsk_io_* 做 UMEM 管理 + ring 交互：
 *   rx_burst：循环 pp_xsk_io_next_ip → 从 mempool 拿 pp_pkt_t → 拷进 data + 填 meta。
 *   tx_burst：逐包 pp_xsk_io_inject_ip。
 *   get_rx/tx_fd：同一个 XSK fd。
 *
 * 要求 CAP_NET_ADMIN + CAP_BPF，且 ifname 所指网卡支持 XDP（libxdp 默认加载
 * redirect 程序；不支持硬件原生 XDP 会 fallback 到 generic/SKB 模式）。
 * ==================================================================== */

typedef struct xsk_ctx {
    struct pp_xsk_io *io;
    pp_mempool_t     *pool;
    char              ifname[IFNAMSIZ];
    uint32_t          queue_id;
} xsk_ctx_t;

static int xdp_open(const pp_io_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->kind != PP_IO_AF_XDP) return PP_ERR_INVAL;
    if (!cfg->pool) {
        PP_ERROR("xsk: mempool required for rx");
        return PP_ERR_INVAL;
    }
    xsk_ctx_t *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->pool = cfg->pool;
    c->queue_id = cfg->u.xdp.queue_id;

    int rc = pp_xsk_io_new(&c->io,
                           cfg->u.xdp.ifname,
                           cfg->u.xdp.queue_id,
                           cfg->u.xdp.nframes,
                           cfg->u.xdp.zero_copy,
                           cfg->u.xdp.need_wakeup,
                           cfg->u.xdp.has_peer_mac ? cfg->u.xdp.peer_mac : NULL);
    if (rc != PP_OK) { free(c); return rc; }

    snprintf(c->ifname, sizeof c->ifname, "%s",
             pp_xsk_io_get_ifname(c->io));
    *out_ctx = c;
    return PP_OK;
}

static void xdp_close(void *ctx)
{
    if (!ctx) return;
    xsk_ctx_t *c = ctx;
    if (c->io) pp_xsk_io_free(c->io);
    free(c);
}

static int xdp_rx(void *ctx, pp_pkt_t **pkts, int max, int timeout_us)
{
    (void)timeout_us;
    xsk_ctx_t *c = ctx;
    int got = 0;
    for (int i = 0; i < max; i++) {
        size_t n = 0;
        const uint8_t *ip = pp_xsk_io_next_ip(c->io, &n);
        if (!ip) break;
        pp_pkt_t *p = pp_mempool_alloc(c->pool);
        if (!p) break;
        if (n > p->tailroom) { pp_pkt_put_ref(p); continue; }
        memcpy(p->data, ip, n);
        p->data_len = (uint16_t)n;
        p->tailroom -= (uint16_t)n;
        p->origin   = PP_PKT_FROM_XDP;
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

static int xdp_tx(void *ctx, pp_pkt_t **pkts, int n)
{
    xsk_ctx_t *c = ctx;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        pp_pkt_t *p = pkts[i];
        int w = pp_xsk_io_inject_ip(c->io, p->data, p->data_len);
        if (w < 0) break;             /* EAGAIN / 关闭等，停手让调用者稍后重试 */
        sent++;
    }
    return sent;
}

static int xdp_fd(void *ctx)
{
    xsk_ctx_t *c = ctx;
    return c && c->io ? pp_xsk_io_get_fd(c->io) : -1;
}

static int xdp_stat(void *ctx, char *json, size_t cap)
{
    xsk_ctx_t *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"af_xdp\",\"if\":\"%s\",\"queue\":%u,\"fd\":%d}",
        c->ifname, c->queue_id, c->io ? pp_xsk_io_get_fd(c->io) : -1);
}

const pp_pkt_io_ops_t pp_io_af_xdp = {
    .name      = "af_xdp",
    .kind      = PP_IO_AF_XDP,
    .caps      = PP_IO_CAP_L2 | PP_IO_CAP_ZEROCOPY | PP_IO_CAP_BATCH | PP_IO_CAP_BUSY_POLL,
    .open      = xdp_open,
    .close     = xdp_close,
    .rx_burst  = xdp_rx,
    .tx_burst  = xdp_tx,
    .get_rx_fd = xdp_fd,
    .get_tx_fd = xdp_fd,
    .stat      = xdp_stat,
};

/* ====================================================================
 * (2) 右手侧 pp_xsk_io_* —— 供 tunnel/udp.c / tunnel/icmp.c 使用
 * ==================================================================== */
#define PP_XSK_FRAME_SIZE     XSK_UMEM__DEFAULT_FRAME_SIZE   /* 4096 */
#define PP_XSK_DEFAULT_FRAMES 4096
#define PP_XSK_MIN_FRAMES     128
#define ETH_HDR_LEN 14

struct pp_xsk_io {
    struct xsk_umem      *umem;
    struct xsk_socket    *xsk;
    void                 *umem_area;
    size_t                umem_size;

    struct xsk_ring_prod  fq;
    struct xsk_ring_cons  cq;
    struct xsk_ring_cons  rx;
    struct xsk_ring_prod  tx;

    int       fd;
    char      ifname[IFNAMSIZ];
    uint32_t  queue_id;
    uint32_t  frame_size;
    uint32_t  nframes;

    uint32_t  rx_base, rx_count;
    uint32_t  tx_base, tx_count;
    uint32_t  tx_next;
    uint32_t  tx_outstanding;

    uint8_t   src_mac[6];
    uint8_t   dst_mac[6];
    bool      need_wakeup;

    uint8_t   rx_stash[PP_XSK_FRAME_SIZE];
    size_t    rx_stash_len;
};

static uint32_t round_up_pow2(uint32_t v)
{
    if (v < 2) return 1;
    v--;
    v |= v >> 1; v |= v >> 2; v |= v >> 4;
    v |= v >> 8; v |= v >> 16;
    return v + 1;
}

static int get_src_mac(const char *ifname, uint8_t mac[6])
{
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return PP_ERR_IO;
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    int r = ioctl(s, SIOCGIFHWADDR, &ifr);
    close(s);
    if (r < 0) return PP_ERR_IO;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return PP_OK;
}

static void reclaim_tx_comp(struct pp_xsk_io *p)
{
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&p->cq, 64, &idx);
    if (!n) return;
    xsk_ring_cons__release(&p->cq, n);
    p->tx_outstanding = (p->tx_outstanding >= n) ? (p->tx_outstanding - n) : 0;
}

int pp_xsk_io_new(struct pp_xsk_io **out,
                  const char *ifname,
                  uint32_t queue_id,
                  uint32_t nframes_req,
                  bool zero_copy,
                  bool need_wakeup,
                  const uint8_t peer_mac[6])
{
    if (!out || !ifname || !ifname[0]) return PP_ERR_INVAL;
    struct pp_xsk_io *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->fd = -1;

    uint32_t nframes = nframes_req ? round_up_pow2(nframes_req) : PP_XSK_DEFAULT_FRAMES;
    if (nframes < PP_XSK_MIN_FRAMES) nframes = PP_XSK_MIN_FRAMES;
    p->frame_size = PP_XSK_FRAME_SIZE;
    p->nframes    = nframes;
    p->rx_base    = 0;
    p->rx_count   = nframes / 2;
    p->tx_base    = nframes / 2;
    p->tx_count   = nframes - p->rx_count;
    p->need_wakeup = need_wakeup;

    snprintf(p->ifname, sizeof p->ifname, "%s", ifname);
    p->queue_id = queue_id;

    if (get_src_mac(ifname, p->src_mac) != PP_OK)
        PP_WARN("xsk: SIOCGIFHWADDR(%s) failed, using zero src MAC", ifname);
    if (peer_mac) memcpy(p->dst_mac, peer_mac, 6);

    p->umem_size = (size_t)p->nframes * p->frame_size;
    p->umem_area = mmap(NULL, p->umem_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
    if (p->umem_area == MAP_FAILED) {
        PP_ERROR("xsk: mmap UMEM %zu bytes: %s", p->umem_size, strerror(errno));
        free(p);
        return PP_ERR_NOMEM;
    }

    struct xsk_umem_config ucfg = {
        .fill_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .comp_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .frame_size     = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags          = 0,
    };
    int rc = xsk_umem__create(&p->umem, p->umem_area, p->umem_size,
                              &p->fq, &p->cq, &ucfg);
    if (rc) {
        PP_ERROR("xsk_umem__create: %s", strerror(-rc));
        munmap(p->umem_area, p->umem_size);
        free(p);
        return PP_ERR_IO;
    }

    struct xsk_socket_config scfg = {
        .rx_size      = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size      = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = 0,
        .xdp_flags    = 0,
        .bind_flags   = (uint16_t)((zero_copy   ? XDP_ZEROCOPY : XDP_COPY) |
                                   (need_wakeup ? XDP_USE_NEED_WAKEUP : 0)),
    };
    rc = xsk_socket__create(&p->xsk, ifname, queue_id, p->umem,
                            &p->rx, &p->tx, &scfg);
    if (rc) {
        PP_ERROR("xsk_socket__create(%s, q=%u): %s "
                 "(need CAP_NET_ADMIN+CAP_BPF, XDP-capable iface)",
                 ifname, queue_id, strerror(-rc));
        xsk_umem__delete(p->umem);
        munmap(p->umem_area, p->umem_size);
        free(p);
        return PP_ERR_IO;
    }
    p->fd = xsk_socket__fd(p->xsk);

    uint32_t idx = 0;
    uint32_t got = xsk_ring_prod__reserve(&p->fq, p->rx_count, &idx);
    if (got != p->rx_count) {
        PP_ERROR("xsk: fill reserve %u got %u", p->rx_count, got);
        xsk_socket__delete(p->xsk);
        xsk_umem__delete(p->umem);
        munmap(p->umem_area, p->umem_size);
        free(p);
        return PP_ERR_IO;
    }
    for (uint32_t i = 0; i < p->rx_count; i++) {
        uint64_t addr = (uint64_t)(p->rx_base + i) * p->frame_size;
        *xsk_ring_prod__fill_addr(&p->fq, idx + i) = addr;
    }
    xsk_ring_prod__submit(&p->fq, p->rx_count);

    PP_INFO("xsk: opened %s queue=%u nframes=%u umem=%zuMB fd=%d zc=%d wakeup=%d",
            p->ifname, p->queue_id, p->nframes,
            p->umem_size >> 20, p->fd, zero_copy, need_wakeup);
    *out = p;
    return PP_OK;
}

void pp_xsk_io_free(struct pp_xsk_io *p)
{
    if (!p) return;
    if (p->xsk)       xsk_socket__delete(p->xsk);
    if (p->umem)      xsk_umem__delete(p->umem);
    if (p->umem_area) munmap(p->umem_area, p->umem_size);
    free(p);
}

int         pp_xsk_io_get_fd    (const struct pp_xsk_io *p) { return p ? p->fd : -1; }
const char *pp_xsk_io_get_ifname(const struct pp_xsk_io *p) { return p ? p->ifname : ""; }
uint32_t    pp_xsk_io_get_queue (const struct pp_xsk_io *p) { return p ? p->queue_id : 0; }

int pp_xsk_io_inject_ip(struct pp_xsk_io *p, const uint8_t *ip, size_t len)
{
    if (!p || !p->xsk) return PP_ERR_CLOSED;
    if (ETH_HDR_LEN + len > p->frame_size) return PP_ERR_INVAL;

    reclaim_tx_comp(p);
    if (p->tx_outstanding >= p->tx_count - 1) return PP_ERR_AGAIN;

    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&p->tx, 1, &idx) != 1) return PP_ERR_AGAIN;

    uint64_t addr = (uint64_t)(p->tx_base + p->tx_next) * p->frame_size;
    p->tx_next = (p->tx_next + 1) % p->tx_count;

    uint8_t *frame = xsk_umem__get_data(p->umem_area, addr);
    memcpy(frame,                   p->dst_mac, 6);
    memcpy(frame + 6,               p->src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;
    memcpy(frame + ETH_HDR_LEN, ip, len);

    struct xdp_desc *d = xsk_ring_prod__tx_desc(&p->tx, idx);
    d->addr = addr;
    d->len  = (uint32_t)(ETH_HDR_LEN + len);
    xsk_ring_prod__submit(&p->tx, 1);
    p->tx_outstanding++;

    if (p->need_wakeup && xsk_ring_prod__needs_wakeup(&p->tx)) {
        if (sendto(p->fd, NULL, 0, MSG_DONTWAIT, NULL, 0) < 0) {
            if (errno != EBUSY && errno != EAGAIN && errno != ENETDOWN)
                PP_WARN("xsk sendto kick: %s", strerror(errno));
        }
    }
    return (int)len;
}

const uint8_t *pp_xsk_io_next_ip(struct pp_xsk_io *p, size_t *out_len)
{
    if (!p || !p->xsk) return NULL;

    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&p->rx, 1, &idx);
    if (n != 1) {
        if (p->need_wakeup && xsk_ring_prod__needs_wakeup(&p->fq))
            (void)recvfrom(p->fd, NULL, 0, MSG_DONTWAIT, NULL, NULL);
        return NULL;
    }

    const struct xdp_desc *d = xsk_ring_cons__rx_desc(&p->rx, idx);
    uint64_t addr = d->addr;
    uint32_t len  = d->len;

    const uint8_t *frame = xsk_umem__get_data(p->umem_area, addr);
    size_t off = 0;
    if (len >= ETH_HDR_LEN) {
        if (len >= ETH_HDR_LEN + 4 && frame[12] == 0x81 && frame[13] == 0x00)
            off = ETH_HDR_LEN + 4;
        else
            off = ETH_HDR_LEN;
    }
    size_t ip_len = (len > off) ? (size_t)(len - off) : 0;
    if (ip_len > sizeof p->rx_stash) ip_len = sizeof p->rx_stash;
    memcpy(p->rx_stash, frame + off, ip_len);
    p->rx_stash_len = ip_len;

    xsk_ring_cons__release(&p->rx, 1);
    uint32_t fidx = 0;
    if (xsk_ring_prod__reserve(&p->fq, 1, &fidx) == 1) {
        *xsk_ring_prod__fill_addr(&p->fq, fidx) = addr;
        xsk_ring_prod__submit(&p->fq, 1);
    }

    if (out_len) *out_len = ip_len;
    return p->rx_stash;
}

#endif /* PP_HAVE_XDP */
