/* src/io/raw_sock.c -- Linux 原始套接字 I/O
 *
 * 一、右手侧（tunnel/udp、tunnel/icmp 复用 raw_socket 路径）：
 *     AF_INET SOCK_RAW，**不** 设 IP_HDRINCL：write 时 buffer 为 L4+载荷（UDP 头+数据或
 *     ICMP 报文），**由内核** 组 IPv4 头。recv 仍收到「IP+载荷」整包（与 tunnel 解析一致）。
 *     需要 CAP_NET_RAW。
 *
 * 二、左手侧（pp_pkt_io_ops_t vtable，名为 pp_io_raw_socket）：
 *     AF_PACKET SOCK_RAW + ETH_P_ALL：收/发完整 L2 以太帧（含目的 MAC）。
 *     rx_burst 只把 IPv4（ethertype 0x0800）交给上层，meta 填 l2_off=0、
 *     l3_off 指向 IP 头；非 IPv4 帧直接丢弃。需要 CAP_NET_RAW。
 */
#include "raw_sock.h"
#include "ks_sock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <unistd.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/pkt_io.h"

/* =============================================================
 * 右手侧：AF_INET SOCK_RAW（无 IP_HDRINCL：用户态不手拼 IP 头）
 * ============================================================= */

void pp_raw_ip_bind_src_v4(int fd, uint32_t src_ip_be)
{
    struct sockaddr_in sin = {
        .sin_family      = AF_INET,
        .sin_port        = 0,
        .sin_addr.s_addr = src_ip_be,
    };
    if (bind(fd, (struct sockaddr *)&sin, sizeof sin) < 0)
        PP_WARN("raw_ip bind src: %s (continuing)", strerror(errno));
}

int pp_raw_ip_open(int ipproto, const char *ifname, int *out_fd)
{
    int fd = socket(AF_INET, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, ipproto);
    if (fd < 0) {
        PP_ERROR("raw_ip socket(proto=%d): %s (need CAP_NET_RAW?)",
                 ipproto, strerror(errno));
        return PP_ERR_IO;
    }
    pp_ks_bind_to_device(fd, ifname);
    *out_fd = fd;
    return PP_OK;
}

int pp_raw_ip_send(int fd, const uint8_t *l4_and_payload, size_t len, uint32_t dst_ip_be)
{
    struct sockaddr_in dst = {
        .sin_family      = AF_INET,
        .sin_port        = 0,
        .sin_addr.s_addr = dst_ip_be,
    };
    ssize_t w = sendto(fd, l4_and_payload, len, 0, (struct sockaddr *)&dst, sizeof dst);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return PP_ERR_AGAIN;
        return PP_ERR_IO;
    }
    return (int)w;
}

int pp_raw_ip_recv(int fd, uint8_t *buf, size_t cap,
                   struct sockaddr *src, socklen_t *src_sl)
{
    ssize_t n = recvfrom(fd, buf, cap, 0, src, src_sl);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return PP_ERR_IO;
    }
    return (int)n;
}

/* =============================================================
 * 左手侧：AF_PACKET L2 抓包 / 注包
 * ============================================================= */

typedef struct afpkt_ctx {
    int              fd;
    int              ifindex;
    pp_mempool_t     *pool;
    char             ifname[IFNAMSIZ];
    uint16_t         snaplen;
    bool             promisc;
} afpkt_ctx_t;

/* 返回 IPv4 起始偏移（相对 data）；非 IPv4 / 太短 返回 UINT16_MAX */
static uint16_t eth_l3_off_ipv4(const uint8_t *data, size_t len)
{
    if (len < 14) return UINT16_MAX;
    uint16_t off = 14;
    if (len >= 18 && data[12] == 0x81 && data[13] == 0x00)
        off = 18;
    if (len < (size_t)off + 12) return UINT16_MAX;
    uint16_t et = (uint16_t)((data[off - 2] << 8) | data[off - 1]);
    if (et != ETH_P_IP) return UINT16_MAX;
    const struct iphdr *ih = (const struct iphdr *)(data + off);
    if (ih->version != 4) return UINT16_MAX;
    if (ih->ihl < 5) return UINT16_MAX;
    uint16_t ihl = (uint16_t)(ih->ihl * 4);
    if (len < (size_t)off + ihl) return UINT16_MAX;
    return off;
}

static int afpkt_open(const pp_io_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->kind != PP_IO_RAW_SOCKET) return PP_ERR_INVAL;
    if (!cfg->pool) {
        PP_ERROR("af_packet: mempool required for rx");
        return PP_ERR_INVAL;
    }
    if (!cfg->u.raw.ifname || !cfg->u.raw.ifname[0]) {
        PP_ERROR("af_packet: ifname required");
        return PP_ERR_INVAL;
    }

    int ifidx = (int)if_nametoindex(cfg->u.raw.ifname);
    if (ifidx <= 0) {
        PP_ERROR("af_packet: if_nametoindex(%s): %s",
                 cfg->u.raw.ifname, strerror(errno));
        return PP_ERR_IO;
    }

    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    htons(ETH_P_ALL));
    if (fd < 0) {
        PP_ERROR("af_packet: socket(AF_PACKET): %s (need CAP_NET_RAW?)",
                 strerror(errno));
        return PP_ERR_IO;
    }

    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = ifidx,
    };
    if (bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        PP_ERROR("af_packet: bind(%s): %s", cfg->u.raw.ifname, strerror(errno));
        close(fd);
        return PP_ERR_IO;
    }

    if (cfg->u.raw.promisc) {
        struct packet_mreq mreq = {0};
        mreq.mr_ifindex = ifidx;
        mreq.mr_type    = PACKET_MR_PROMISC;
        if (setsockopt(fd, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mreq, sizeof mreq) < 0)
            PP_WARN("af_packet: PACKET_MR_PROMISC: %s (continuing)", strerror(errno));
    }

    afpkt_ctx_t *c = calloc(1, sizeof *c);
    if (!c) { close(fd); return PP_ERR_NOMEM; }
    c->fd       = fd;
    c->ifindex  = ifidx;
    c->pool     = cfg->pool;
    c->snaplen  = cfg->u.raw.snaplen ? cfg->u.raw.snaplen : 2048;
    c->promisc  = cfg->u.raw.promisc;
    snprintf(c->ifname, sizeof c->ifname, "%s", cfg->u.raw.ifname);

    PP_INFO("af_packet: opened %s (fd=%d, snaplen=%u, promisc=%d)",
            c->ifname, c->fd, c->snaplen, (int)c->promisc);
    *out_ctx = c;
    return PP_OK;
}

static void afpkt_close(void *ctx)
{
    if (!ctx) return;
    afpkt_ctx_t *c = ctx;
    if (c->fd >= 0) close(c->fd);
    free(c);
}

static int afpkt_rx(void *ctx, pp_pkt_t **pkts, int max, int timeout_us)
{
    (void)timeout_us;
    afpkt_ctx_t *c = ctx;
    int got = 0;
    for (int i = 0; i < max; i++) {
        pp_pkt_t *p = pp_mempool_alloc(c->pool);
        if (!p) break;

        size_t cap = p->tailroom;
        if (c->snaplen > 0 && c->snaplen < cap)
            cap = c->snaplen;

        ssize_t n = recvfrom(c->fd, p->data, cap, 0, NULL, NULL);
        if (n <= 0) {
            pp_pkt_put_ref(p);
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
            if (n < 0) PP_WARN("af_packet recv: %s", strerror(errno));
            break;
        }

        uint16_t l3 = eth_l3_off_ipv4(p->data, (size_t)n);
        if (l3 == UINT16_MAX) {
            pp_pkt_put_ref(p);
            continue;
        }

        const struct iphdr *ih = (const struct iphdr *)(p->data + l3);
        p->data_len  = (uint16_t)n;
        p->tailroom -= (uint16_t)n;
        p->origin    = PP_PKT_FROM_RAW;
        p->meta.l2_off   = 0;
        p->meta.l3_off   = l3;
        p->meta.l3_proto = IPPROTO_IP;
        p->meta.l4_proto = ih->protocol;
        p->meta.l4_off   = (uint16_t)(l3 + ih->ihl * 4);
        p->meta.rx_ns    = pp_now_ns();
        pkts[got++] = p;
    }
    return got;
}

static int afpkt_tx(void *ctx, pp_pkt_t **pkts, int n)
{
    afpkt_ctx_t *c = ctx;
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_ifindex  = c->ifindex,
        .sll_protocol = htons(ETH_P_ALL),
    };
    int sent = 0;
    for (int i = 0; i < n; i++) {
        pp_pkt_t *p = pkts[i];
        if (p->data_len < 14) break;
        ssize_t w = sendto(c->fd, p->data, p->data_len, 0,
                           (struct sockaddr *)&sll, sizeof sll);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            PP_WARN("af_packet send: %s", strerror(errno));
            break;
        }
        sent++;
    }
    return sent;
}

static int afpkt_fd(void *ctx)
{
    afpkt_ctx_t *c = ctx;
    return c ? c->fd : -1;
}

static int afpkt_stat(void *ctx, char *json, size_t cap)
{
    afpkt_ctx_t *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"af_packet\",\"if\":\"%s\",\"fd\":%d,"
        "\"snaplen\":%u,\"promisc\":%s}",
        c->ifname, c->fd, c->snaplen, c->promisc ? "true" : "false");
}

const pp_pkt_io_ops_t pp_io_raw_socket = {
    .name      = "raw_socket",
    .kind      = PP_IO_RAW_SOCKET,
    .caps      = PP_IO_CAP_L2 | PP_IO_CAP_BATCH,
    .open      = afpkt_open,
    .close     = afpkt_close,
    .rx_burst  = afpkt_rx,
    .tx_burst  = afpkt_tx,
    .get_rx_fd = afpkt_fd,
    .get_tx_fd = afpkt_fd,
    .stat      = afpkt_stat,
};
