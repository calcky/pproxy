/* src/tunnel/icmp.c -- ICMP tunnel + tunnel 注册表（proto 层）
 *
 * ICMP 没有 kernel_socket 可用（SOCK_DGRAM IPPROTO_ICMP 只支持 Echo Request
 * 且 reply 会被内核吞掉），因此 ICMP 的 io 候选是：
 *   - raw_socket ✓   src/io/raw_ip
 *   - tun        ✓   src/io/tun_io
 *   - pcap       ✓   src/io/pcap         （-Dpcap=true）
 *   - af_xdp     ✓   src/io/xsk          （-Dxdp=true）
 *   - netmap     ✓   src/io/netmap       （-Dnetmap=true）
 *
 * Wire format（在 ICMP Echo 数据区中）:
 *   仅 payload 字节（标准 8B ICMP 头之后），线路上不携带 sid。
 *
 * 注意：对端为服务端时建议
 *     sysctl -w net.ipv4.icmp_echo_ignore_all=1
 * 否则内核会自动回 Echo Reply，干扰隧道语义。
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include "pproxy/tunnel.h"
#include "pproxy/log.h"
#include "io/ks_sock.h"
#include "io/raw_sock.h"
#include "io/tun.h"
#include "io/pcap.h"
#include "io/xsk.h"
#include "io/dpdk.h"
#include "io/netmap.h"
#include "pproxy/xsk_filt.h"
#ifdef PP_HAVE_MEMIF
#include "io/memif.h"
#endif

#define ICMP_HDR_LEN    8
#define ICMP_TYPE_REQ   8
#define ICMP_TYPE_REPLY 0
#define IC_FRAME_MAX    65535
#define IP_HDR_LEN_MIN  20

struct icmp_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t cksum;
    uint16_t id;
    uint16_t seq;
} PP_PACKED;

struct icmp_ctx {
    int                     fd;
    pp_tunnel_cfg_t         cfg;
    struct sockaddr_storage peer_sa;
    socklen_t               peer_sl;
    bool                    peer_known;
    uint16_t                identifier;
    uint16_t                seq;
    uint16_t                ip_id;
    char                    tun_ifname[IFNAMSIZ];

#ifdef PP_HAVE_PCAP
    struct pp_pcap_io      *pcap;
#endif
#ifdef PP_HAVE_XDP
    struct pp_xsk_io       *xsk;
#endif
#ifdef PP_HAVE_DPDK
    struct pp_dpdk_io      *dpdk;
#endif
#ifdef PP_HAVE_NETMAP
    struct pp_netmap_io    *nm;
#endif
#ifdef PP_HAVE_MEMIF
    struct pp_memif_io     *memif;
#endif
};

/* -------------------- 帧构造 / 解析 -------------------- */

static uint16_t inet_csum16(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += (uint16_t)(p[0] | (p[1] << 8)); p += 2; len -= 2; }
    if (len) sum += p[0];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* 构造 ICMP body：[ICMP_HDR][payload]，返回长度。checksum 会填。 */
static size_t build_icmp_body(uint8_t *buf, size_t cap,
                              uint8_t type, uint16_t id, uint16_t seq,
                              const uint8_t *payload, size_t plen)
{
    size_t total = ICMP_HDR_LEN + plen;
    if (total > cap || total > IC_FRAME_MAX) return 0;
    struct icmp_hdr *h = (struct icmp_hdr *)buf;
    h->type  = type;
    h->code  = 0;
    h->cksum = 0;
    h->id    = htons(id);
    h->seq   = htons(seq);
    memcpy(buf + ICMP_HDR_LEN, payload, plen);
    h->cksum = inet_csum16(buf, total);
    return total;
}

/* 把 body 包进 IPv4 头。返回总长度。 */
static size_t wrap_ip(uint8_t *frame, size_t cap,
                      uint32_t src_ip_be, uint32_t dst_ip_be, uint16_t ip_id,
                      const uint8_t *body, size_t body_len)
{
    size_t ip_hl = IP_HDR_LEN_MIN;
    size_t total = ip_hl + body_len;
    if (total > cap || total > IC_FRAME_MAX) return 0;
    memset(frame, 0, ip_hl);
    struct iphdr *iph = (struct iphdr *)frame;
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tot_len  = htons((uint16_t)total);
    iph->id       = htons(ip_id);
    iph->frag_off = htons(0x4000);         /* DF */
    iph->ttl      = 64;
    iph->protocol = IPPROTO_ICMP;
    iph->saddr    = src_ip_be;
    iph->daddr    = dst_ip_be;
    iph->check    = inet_csum16(iph, ip_hl);
    memcpy(frame + ip_hl, body, body_len);
    return total;
}

/* 解析入包 [IP][ICMP][payload]：跳过 IP+ICMP 头，过滤 id/type。 */
static int parse_icmp_rx(const uint8_t *frame, size_t n, const struct icmp_ctx *c,
                         uint32_t *out_saddr_be,
                         const uint8_t **out_body, size_t *out_body_len)
{
    if (n < sizeof(struct iphdr)) return 0;
    if ((frame[0] >> 4) != 4) return 0;
    size_t ip_hl = (frame[0] & 0x0F) * 4u;
    if (ip_hl < IP_HDR_LEN_MIN) return 0;
    if (n < ip_hl + ICMP_HDR_LEN) return 0;

    const struct iphdr *iph = (const struct iphdr *)frame;
    if (iph->protocol != IPPROTO_ICMP) return 0;

    const struct icmp_hdr *h = (const struct icmp_hdr *)(frame + ip_hl);
    if (c->cfg.mode == PP_TMODE_SERVER) {
        if (h->type != ICMP_TYPE_REQ) return 0;
    } else {
        if (h->type != ICMP_TYPE_REQ && h->type != ICMP_TYPE_REPLY) return 0;
    }
    if (ntohs(h->id) != c->identifier) return 0;

    *out_saddr_be = iph->saddr;
    *out_body     = frame + ip_hl + ICMP_HDR_LEN;
    *out_body_len = n - ip_hl - ICMP_HDR_LEN;
    return 1;
}

static void learn_peer_server_ic(struct icmp_ctx *c, uint32_t saddr_be, const char *tag)
{
    struct sockaddr_in *psin = (struct sockaddr_in *)&c->peer_sa;
    bool changed = !c->peer_known ||
                   psin->sin_addr.s_addr != saddr_be;
    if (!changed) return;
    psin->sin_family      = AF_INET;
    psin->sin_port        = 0;
    psin->sin_addr.s_addr = saddr_be;
    c->peer_sl            = sizeof *psin;
    c->peer_known         = true;
    char a[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &saddr_be, a, sizeof a);
    PP_INFO("icmp %s peer learned: %s", tag, a);
#ifdef PP_HAVE_XDP
    if (c->cfg.io == PP_TIO_AF_XDP && c->xsk) {
        int r = pp_xsk_io_refresh_arp(c->xsk, saddr_be);
        if (r != PP_OK)
            PP_WARN("icmp %s: xsk refresh dst_mac failed (rc=%d) peer %s", tag, r, a);
    }
#endif
#ifdef PP_HAVE_NETMAP
    if (c->cfg.io == PP_TIO_NETMAP && c->nm) {
        int r = pp_netmap_io_refresh_arp(c->nm, saddr_be);
        if (r != PP_OK)
            PP_WARN("icmp %s: netmap refresh dst_mac failed (rc=%d) peer %s", tag, r, a);
    }
#endif
}

static void client_fix_peer(struct icmp_ctx *c)
{
    struct sockaddr_in *sin = (struct sockaddr_in *)&c->peer_sa;
    sin->sin_family      = AF_INET;
    sin->sin_port        = 0;
    sin->sin_addr.s_addr = c->cfg.server.addr.u.v4.s_addr;
    c->peer_sl           = sizeof *sin;
    c->peer_known        = true;
}

/* -------------------- open / close -------------------- */

static int ic_open(const pp_tunnel_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->proto != PP_PROTO_ICMP) return PP_ERR_INVAL;

    switch (cfg->io) {
    case PP_TIO_RAW_SOCKET:
    case PP_TIO_TUN:
        break;
    case PP_TIO_PCAP:
#ifdef PP_HAVE_PCAP
        break;
#else
        PP_ERROR("icmp tunnel: io=pcap requires build with -Dpcap=true");
        return PP_ERR_NOSUPPORT;
#endif
    case PP_TIO_AF_XDP:
#ifdef PP_HAVE_XDP
        break;
#else
        PP_ERROR("icmp tunnel: io=af_xdp requires build with -Dxdp=true");
        return PP_ERR_NOSUPPORT;
#endif
    case PP_TIO_DPDK:
#ifdef PP_HAVE_DPDK
        break;
#else
        PP_ERROR("icmp tunnel: io=dpdk requires build with -Ddpdk=true");
        return PP_ERR_NOSUPPORT;
#endif
    case PP_TIO_KERNEL_SOCKET:
        PP_ERROR("icmp tunnel: io=kernel_socket not supported "
                 "(ICMP has no user-space kernel socket path; use raw_socket)");
        return PP_ERR_NOSUPPORT;
    case PP_TIO_NETMAP:
#ifdef PP_HAVE_NETMAP
        break;
#else
        PP_ERROR("icmp tunnel: io=netmap requires build with -Dnetmap=true");
        return PP_ERR_NOSUPPORT;
#endif
    case PP_TIO_MEMIF:
#ifdef PP_HAVE_MEMIF
        break;
#else
        PP_ERROR("icmp tunnel: io=memif requires build with -Dmemif=true");
        return PP_ERR_NOSUPPORT;
#endif
    default:
        PP_ERROR("icmp tunnel: unknown io=%d", cfg->io);
        return PP_ERR_INVAL;
    }

    const pp_endpoint_t *ep =
        (cfg->mode == PP_TMODE_SERVER) ? &cfg->listen : &cfg->server;
    if (ep->addr.af != PP_AF_INET) {
        PP_ERROR("icmp tunnel: only IPv4 supported in MVP");
        return PP_ERR_NOSUPPORT;
    }

    struct icmp_ctx *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->cfg        = *cfg;
    c->fd         = -1;
    c->identifier = cfg->u.icmp.identifier_base ? cfg->u.icmp.identifier_base
                                                : (uint16_t)(getpid() & 0xFFFF);
    c->seq        = 0;
    *out_ctx = c;
    return PP_OK;
}

static void ic_close(void *ctx)
{
    struct icmp_ctx *c = ctx;
    if (!c) return;
    bool fd_owned_by_helper = false;
#ifdef PP_HAVE_PCAP
    if (c->cfg.io == PP_TIO_PCAP) { pp_pcap_io_free(c->pcap); c->pcap = NULL; fd_owned_by_helper = true; }
#endif
#ifdef PP_HAVE_XDP
    if (c->cfg.io == PP_TIO_AF_XDP) { pp_xsk_io_free(c->xsk); c->xsk = NULL; fd_owned_by_helper = true; }
#endif
#ifdef PP_HAVE_DPDK
    if (c->cfg.io == PP_TIO_DPDK) { pp_dpdk_io_free(c->dpdk); c->dpdk = NULL; fd_owned_by_helper = true; }
#endif
#ifdef PP_HAVE_NETMAP
    if (c->cfg.io == PP_TIO_NETMAP) { pp_netmap_io_free(c->nm); c->nm = NULL; fd_owned_by_helper = true; }
#endif
#ifdef PP_HAVE_MEMIF
    if (c->cfg.io == PP_TIO_MEMIF) { pp_memif_io_free(c->memif); c->memif = NULL; fd_owned_by_helper = true; }
#endif
    if (c->fd >= 0 && !fd_owned_by_helper) close(c->fd);
    free(c);
}

/* -------------------- raw_socket 路径 -------------------- */

static int raw_connect(struct icmp_ctx *c)
{
    int rc = pp_raw_ip_open(IPPROTO_ICMP, NULL, &c->fd);
    if (rc != PP_OK) return rc;

    if (c->cfg.mode == PP_TMODE_SERVER) {
        pp_raw_ip_bind_src_v4(c->fd, c->cfg.listen.addr.u.v4.s_addr);
        char a[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.listen.addr.u.v4, a, sizeof a);
        PP_INFO("icmp raw_socket listening on %s (fd=%d, id=0x%04x)",
                a, c->fd, c->identifier);
    } else {
        client_fix_peer(c);
        PP_INFO("icmp raw_socket client ready (fd=%d, id=0x%04x)",
                c->fd, c->identifier);
    }
    return PP_OK;
}

/* raw_socket 的"帧"只需要 ICMP body，不带 IP 头（内核自己加） */
static int raw_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;

    int w = pp_ks_udp_send(c->fd, body, blen,
                           (struct sockaddr *)&c->peer_sa, c->peer_sl);
    if (w < 0) return w;
    return (int)buf->len;
}

static int raw_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    uint8_t frame[IC_FRAME_MAX];
    struct sockaddr_storage src;
    socklen_t sl = sizeof src;
    int n = pp_ks_udp_recv(c->fd, frame, sizeof frame,
                           (struct sockaddr *)&src, &sl);
    if (n <= 0) return n;

    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(frame, (size_t)n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;

    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "raw_socket");
    return (int)body_len;
}

/* -------------------- tun 路径 -------------------- */

static int tun_connect(struct icmp_ctx *c)
{
    int rc = pp_tun_io_open(c->cfg.io_cfg.tun.ifname, true,
                            c->tun_ifname, &c->fd);
    if (rc != PP_OK) return rc;

    if (c->cfg.mode == PP_TMODE_SERVER) {
        PP_INFO("icmp tun server: iface=%s id=0x%04x fd=%d",
                c->tun_ifname, c->identifier, c->fd);
    } else {
        client_fix_peer(c);
        char a[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.server.addr.u.v4, a, sizeof a);
        PP_INFO("icmp tun client: iface=%s -> %s id=0x%04x fd=%d",
                c->tun_ifname, a, c->identifier, c->fd);
    }
    return PP_OK;
}

static int tun_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;

    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;

    uint8_t frame[IC_FRAME_MAX];
    uint32_t src_ip_be = c->cfg.listen.addr.u.v4.s_addr;
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t tot = wrap_ip(frame, sizeof frame, src_ip_be, dst_ip_be,
                         c->ip_id++, body, blen);
    if (!tot) return PP_ERR_INVAL;

    int w = pp_tun_io_write_ip(c->fd, frame, tot);
    if (w < 0) return w;
    return (int)buf->len;
}

static int tun_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    uint8_t frame[IC_FRAME_MAX];
    int n = pp_tun_io_read_ip(c->fd, frame, sizeof frame);
    if (n <= 0) return n;

    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(frame, (size_t)n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;

    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "tun");
    return (int)body_len;
}

/* -------------------- pcap 路径 -------------------- */
#ifdef PP_HAVE_PCAP
static int pc_connect(struct icmp_ctx *c)
{
    char bpf[128];
    if (c->cfg.io_cfg.pcap.bpf_filter && c->cfg.io_cfg.pcap.bpf_filter[0]) {
        snprintf(bpf, sizeof bpf, "%s", c->cfg.io_cfg.pcap.bpf_filter);
    } else {
        snprintf(bpf, sizeof bpf, "icmp and icmp[4:2] = %u", c->identifier);
    }
    int rc = pp_pcap_io_new(&c->pcap, c->cfg.io_cfg.pcap.ifname,
                            NULL, bpf, c->cfg.io_cfg.pcap.snaplen);
    if (rc != PP_OK) return rc;
    c->fd = pp_pcap_io_get_fd(c->pcap);

    if (c->cfg.mode == PP_TMODE_CLIENT) client_fix_peer(c);
    PP_INFO("icmp pcap: iface=%s id=0x%04x mode=%s",
            pp_pcap_io_get_ifname(c->pcap),
            c->identifier, c->cfg.mode == PP_TMODE_SERVER ? "server" : "client");
    return PP_OK;
}

static int pc_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;
    uint8_t frame[IC_FRAME_MAX];
    uint32_t src_ip_be = c->cfg.listen.addr.u.v4.s_addr;
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t tot = wrap_ip(frame, sizeof frame, src_ip_be, dst_ip_be,
                         c->ip_id++, body, blen);
    if (!tot) return PP_ERR_INVAL;
    int r = pp_pcap_io_inject_ip(c->pcap, frame, tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int pc_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    size_t n = 0;
    const uint8_t *ip = pp_pcap_io_next_ip(c->pcap, &n);
    if (!ip) return 0;
    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(ip, n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;
    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "pcap");
    return (int)body_len;
}
#endif /* PP_HAVE_PCAP */

/* -------------------- af_xdp 路径 -------------------- */
#ifdef PP_HAVE_XDP
static void icmp_af_xdp_tun_log(const struct icmp_ctx *c, const char *xif, uint32_t xq)
{
    char lsn[64] = "", svr[64] = "";
    pp_endpoint_format(&c->cfg.listen, lsn, sizeof lsn);
    pp_endpoint_format(&c->cfg.server, svr, sizeof svr);
    if (c->cfg.mode == PP_TMODE_SERVER) {
        char la[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.listen.addr.u.v4, la, sizeof la);
        PP_INFO("icmp af_xdp tunnel: mode=server if=%s q=%u nframes=%u zc=%d need_wakeup=%d "
                "listen=%s id=0x%04x peer_known=%d server_cfg=%s",
                xif, (unsigned)xq, c->cfg.io_cfg.xdp.nframes,
                c->cfg.io_cfg.xdp.zero_copy ? 1 : 0, c->cfg.io_cfg.xdp.need_wakeup ? 1 : 0,
                la, c->identifier, c->peer_known ? 1 : 0, svr);
    } else {
        char sa[INET_ADDRSTRLEN] = "", da[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.listen.addr.u.v4, sa, sizeof sa);
        inet_ntop(AF_INET, &((struct sockaddr_in *)&c->peer_sa)->sin_addr, da, sizeof da);
        PP_INFO("icmp af_xdp tunnel: mode=client if=%s q=%u nframes=%u zc=%d need_wakeup=%d "
                "listen=%s id=0x%04x peer=%s (dst_mac/ARP 使用对端 %s) server_ep=%s",
                xif, (unsigned)xq, c->cfg.io_cfg.xdp.nframes,
                c->cfg.io_cfg.xdp.zero_copy ? 1 : 0, c->cfg.io_cfg.xdp.need_wakeup ? 1 : 0,
                sa, c->identifier, da, da, svr);
    }
}

static int xc_connect(struct icmp_ctx *c)
{
    if (c->cfg.mode == PP_TMODE_CLIENT) client_fix_peer(c);
    if (c->cfg.listen.addr.u.v4.s_addr == 0 && c->cfg.io_cfg.xdp.ifname
        && c->cfg.io_cfg.xdp.ifname[0]) {
        uint32_t s;
        if (pp_xsk_ifname_first_ipv4(c->cfg.io_cfg.xdp.ifname, &s) == PP_OK) {
            c->cfg.listen.addr.u.v4.s_addr = s;
            c->cfg.listen.addr.af     = PP_AF_INET;
            char a[INET_ADDRSTRLEN] = "";
            struct in_addr _ia = { .s_addr = s };
            inet_ntop(AF_INET, &_ia, a, sizeof a);
            PP_INFO("icmp af_xdp: 未配 listen 源，使用 %s 上 IPv4 %s 为 IP 头源",
                    c->cfg.io_cfg.xdp.ifname, a);
        } else
            PP_WARN("icmp af_xdp: listen 为 0.0.0.0 且无法从 %s 取 IPv4，IP 头源仍为 0.0.0.0",
                    c->cfg.io_cfg.xdp.ifname);
    }
    uint32_t arp_nexthop_be = 0;
    if (c->cfg.mode == PP_TMODE_CLIENT)
        arp_nexthop_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    pp_xsk_filt_t xf;
    memset(&xf, 0, sizeof xf);
    xf.daddr_be = c->cfg.listen.addr.u.v4.s_addr;
    xf.ipproto  = (uint8_t)IPPROTO_ICMP;
    int rc = pp_xsk_io_new(&c->xsk,
                           c->cfg.io_cfg.xdp.ifname,
                           c->cfg.io_cfg.xdp.queue_id,
                           c->cfg.io_cfg.xdp.nframes,
                           c->cfg.io_cfg.xdp.zero_copy,
                           c->cfg.io_cfg.xdp.need_wakeup,
                           NULL,
                           arp_nexthop_be,
                           &xf);
    if (rc != PP_OK) return rc;
    c->fd = pp_xsk_io_get_fd(c->xsk);
    icmp_af_xdp_tun_log(c, pp_xsk_io_get_ifname(c->xsk), pp_xsk_io_get_queue(c->xsk));
    return PP_OK;
}

static int xc_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;
    uint8_t frame[IC_FRAME_MAX];
    uint32_t src_ip_be = c->cfg.listen.addr.u.v4.s_addr;
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t tot = wrap_ip(frame, sizeof frame, src_ip_be, dst_ip_be,
                         c->ip_id++, body, blen);
    if (!tot) return PP_ERR_INVAL;
    int r = pp_xsk_io_inject_ip(c->xsk, frame, tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int xc_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    size_t n = 0;
    const uint8_t *ip = pp_xsk_io_next_ip(c->xsk, &n);
    if (!ip) return 0;
    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(ip, n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;
    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "af_xdp");
    return (int)body_len;
}
#endif /* PP_HAVE_XDP */

/* -------------------- dpdk 路径 -------------------- */
#ifdef PP_HAVE_DPDK
static int dp_connect(struct icmp_ctx *c)
{
    if (c->cfg.mode == PP_TMODE_CLIENT) client_fix_peer(c);
    int rc = pp_dpdk_io_new(&c->dpdk,
                            c->cfg.io_cfg.dpdk.port_id,
                            c->cfg.io_cfg.dpdk.queue_id,
                            c->cfg.io_cfg.dpdk.nframes,
                            c->cfg.io_cfg.dpdk.eal_args,
                            c->cfg.io_cfg.dpdk.has_peer_mac
                                ? c->cfg.io_cfg.dpdk.peer_mac : NULL);
    if (rc != PP_OK) return rc;

    if (c->cfg.mode == PP_TMODE_SERVER) {
        char a[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.listen.addr.u.v4, a, sizeof a);
        PP_INFO("icmp tunnel bound on %s (dpdk port=%u q=%u id=0x%04x)",
                a, pp_dpdk_io_get_port(c->dpdk), pp_dpdk_io_get_queue(c->dpdk),
                c->identifier);
    } else {
        char a[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.server.addr.u.v4, a, sizeof a);
        PP_INFO("icmp tunnel connected (dpdk port=%u q=%u) -> %s id=0x%04x",
                pp_dpdk_io_get_port(c->dpdk), pp_dpdk_io_get_queue(c->dpdk),
                a, c->identifier);
    }
    return PP_OK;
}

static int dp_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;
    uint8_t frame[IC_FRAME_MAX];
    uint32_t src_ip_be = c->cfg.listen.addr.u.v4.s_addr;
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t tot = wrap_ip(frame, sizeof frame, src_ip_be, dst_ip_be,
                         c->ip_id++, body, blen);
    if (!tot) return PP_ERR_INVAL;
    int r = pp_dpdk_io_inject_ip(c->dpdk, frame, tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int dp_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    size_t n = 0;
    const uint8_t *ip = pp_dpdk_io_next_ip(c->dpdk, &n);
    if (!ip) return 0;
    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(ip, n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;
    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "dpdk");
    return (int)body_len;
}
#endif /* PP_HAVE_DPDK */

/* -------------------- netmap 路径 -------------------- */
#ifdef PP_HAVE_NETMAP
static int nm_connect(struct icmp_ctx *c)
{
    if (c->cfg.mode == PP_TMODE_CLIENT) client_fix_peer(c);
    if (c->cfg.listen.addr.u.v4.s_addr == 0 && c->cfg.io_cfg.netmap.ifname
        && c->cfg.io_cfg.netmap.ifname[0]) {
        uint32_t s;
        if (pp_netmap_ifname_first_ipv4(c->cfg.io_cfg.netmap.ifname, &s) == PP_OK) {
            c->cfg.listen.addr.u.v4.s_addr = s;
            c->cfg.listen.addr.af          = PP_AF_INET;
            char a[INET_ADDRSTRLEN] = "";
            struct in_addr _ia = { .s_addr = s };
            inet_ntop(AF_INET, &_ia, a, sizeof a);
            PP_INFO("icmp netmap: 未配 listen 源，使用 %s 上 IPv4 %s 为 IP 头源",
                    c->cfg.io_cfg.netmap.ifname, a);
        } else
            PP_WARN("icmp netmap: listen 为 0.0.0.0 且无法从 %s 取 IPv4，IP 头源仍为 0.0.0.0",
                    c->cfg.io_cfg.netmap.ifname);
    }
    uint32_t arp_nexthop_be = 0;
    if (c->cfg.mode == PP_TMODE_CLIENT)
        arp_nexthop_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;

    int rc = pp_netmap_io_new(&c->nm,
                              c->cfg.io_cfg.netmap.ifname,
                              c->cfg.io_cfg.netmap.nrings,
                              NULL,
                              arp_nexthop_be);
    if (rc != PP_OK) return rc;
    c->fd = pp_netmap_io_get_fd(c->nm);

    char sa[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &c->cfg.listen.addr.u.v4, sa, sizeof sa);
    if (c->cfg.mode == PP_TMODE_SERVER) {
        PP_INFO("icmp netmap server: iface=%s listen=%s id=0x%04x fd=%d",
                pp_netmap_io_get_ifname(c->nm), sa, c->identifier, c->fd);
    } else {
        char da[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &((struct sockaddr_in *)&c->peer_sa)->sin_addr,
                  da, sizeof da);
        PP_INFO("icmp netmap client: iface=%s %s -> %s id=0x%04x fd=%d",
                pp_netmap_io_get_ifname(c->nm), sa, da, c->identifier, c->fd);
    }
    return PP_OK;
}

static int nm_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;
    uint8_t frame[IC_FRAME_MAX];
    uint32_t src_ip_be = c->cfg.listen.addr.u.v4.s_addr;
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t tot = wrap_ip(frame, sizeof frame, src_ip_be, dst_ip_be,
                         c->ip_id++, body, blen);
    if (!tot) return PP_ERR_INVAL;
    int r = pp_netmap_io_inject_ip(c->nm, frame, tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int nm_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    size_t n = 0;
    const uint8_t *ip = pp_netmap_io_next_ip(c->nm, &n);
    if (!ip) return 0;
    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(ip, n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;
    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "netmap");
    return (int)body_len;
}
#endif /* PP_HAVE_NETMAP */

/* -------------------- memif 路径 -------------------- */
#ifdef PP_HAVE_MEMIF
static int mc_connect(struct icmp_ctx *c)
{
    /* src/dst IP 来自 listen（server）/ server（client）端点 */
    const uint8_t *pmac = c->cfg.io_cfg.memif.has_peer_mac
                          ? c->cfg.io_cfg.memif.peer_mac : NULL;
    int rc = pp_memif_io_new(&c->memif,
                             c->cfg.io_cfg.memif.socket_path,
                             c->cfg.io_cfg.memif.interface_id,
                             c->cfg.io_cfg.memif.is_master,
                             c->cfg.io_cfg.memif.ring_size,
                             c->cfg.io_cfg.memif.buffer_size,
                             pmac);
    if (rc != PP_OK) return rc;

    if (c->cfg.mode == PP_TMODE_SERVER) {
        char a[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.listen.addr.u.v4, a, sizeof a);
        PP_INFO("icmp memif tunnel: mode=server socket=%s id=%u listen=%s id=0x%04x",
                c->cfg.io_cfg.memif.socket_path,
                c->cfg.io_cfg.memif.interface_id, a, c->identifier);
    } else {
        char a[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->cfg.server.addr.u.v4, a, sizeof a);
        PP_INFO("icmp memif tunnel: mode=client socket=%s id=%u -> %s id=0x%04x",
                c->cfg.io_cfg.memif.socket_path,
                c->cfg.io_cfg.memif.interface_id, a, c->identifier);
    }
    return PP_OK;
}

static int mc_send(struct icmp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!pp_memif_io_is_connected(c->memif)) {
        pp_memif_io_poll(c->memif, 0);
        return PP_ERR_AGAIN;
    }
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t body[IC_FRAME_MAX];
    uint8_t type = (c->cfg.mode == PP_TMODE_SERVER) ? ICMP_TYPE_REPLY : ICMP_TYPE_REQ;
    size_t blen = build_icmp_body(body, sizeof body, type,
                                  c->identifier, c->seq++,
                                  buf->data, buf->len);
    if (!blen) return PP_ERR_INVAL;
    uint8_t frame[IC_FRAME_MAX];
    uint32_t src_ip_be = c->cfg.listen.addr.u.v4.s_addr;
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t tot = wrap_ip(frame, sizeof frame, src_ip_be, dst_ip_be,
                         c->ip_id++, body, blen);
    if (!tot) return PP_ERR_INVAL;
    int r = pp_memif_io_inject_ip(c->memif, frame, tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int mc_recv(struct icmp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    pp_memif_io_poll(c->memif, 0);
    if (!pp_memif_io_is_connected(c->memif)) return 0;

    size_t n = 0;
    const uint8_t *ip = pp_memif_io_next_ip(c->memif, &n);
    if (!ip) return 0;
    uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    if (parse_icmp_rx(ip, n, c, &saddr_be, &body, &body_len) != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;
    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server_ic(c, saddr_be, "memif");
    return (int)body_len;
}
#endif /* PP_HAVE_MEMIF */

/* -------------------- 顶层 ops 调度 -------------------- */

static int ic_connect(void *ctx)
{
    struct icmp_ctx *c = ctx;
#ifdef PP_HAVE_DPDK
    if (c->cfg.io == PP_TIO_DPDK) return c->dpdk ? PP_OK : dp_connect(c);
#endif
#ifdef PP_HAVE_MEMIF
    if (c->cfg.io == PP_TIO_MEMIF) return c->memif ? PP_OK : mc_connect(c);
#endif
    if (c->fd >= 0) return PP_OK;
    switch (c->cfg.io) {
    case PP_TIO_TUN:        return tun_connect(c);
#ifdef PP_HAVE_PCAP
    case PP_TIO_PCAP:       return pc_connect(c);
#endif
#ifdef PP_HAVE_XDP
    case PP_TIO_AF_XDP:     return xc_connect(c);
#endif
#ifdef PP_HAVE_NETMAP
    case PP_TIO_NETMAP:     return nm_connect(c);
#endif
    default:                return raw_connect(c);
    }
}

static int ic_send(void *ctx, const pp_tun_buf_t *buf)
{
    struct icmp_ctx *c = ctx;
#ifdef PP_HAVE_DPDK
    if (c->cfg.io == PP_TIO_DPDK) return c->dpdk ? dp_send(c, buf) : PP_ERR_CLOSED;
#endif
#ifdef PP_HAVE_MEMIF
    if (c->cfg.io == PP_TIO_MEMIF) return c->memif ? mc_send(c, buf) : PP_ERR_CLOSED;
#endif
    if (c->fd < 0) return PP_ERR_CLOSED;
    switch (c->cfg.io) {
    case PP_TIO_TUN:        return tun_send(c, buf);
#ifdef PP_HAVE_PCAP
    case PP_TIO_PCAP:       return pc_send(c, buf);
#endif
#ifdef PP_HAVE_XDP
    case PP_TIO_AF_XDP:     return xc_send(c, buf);
#endif
#ifdef PP_HAVE_NETMAP
    case PP_TIO_NETMAP:     return nm_send(c, buf);
#endif
    default:                return raw_send(c, buf);
    }
}

static int ic_recv(void *ctx, pp_tun_mbuf_t *out_buf, int timeout_us)
{
    struct icmp_ctx *c = ctx;
#ifdef PP_HAVE_DPDK
    if (c->cfg.io == PP_TIO_DPDK) {
        if (!c->dpdk) return PP_ERR_CLOSED;
        (void)timeout_us;
        return dp_recv(c, out_buf);
    }
#endif
#ifdef PP_HAVE_MEMIF
    if (c->cfg.io == PP_TIO_MEMIF) {
        if (!c->memif) return PP_ERR_CLOSED;
        (void)timeout_us;
        return mc_recv(c, out_buf);
    }
#endif
    if (c->fd < 0) return PP_ERR_CLOSED;

    if (timeout_us > 0) {
        struct pollfd pf = { .fd = c->fd, .events = POLLIN };
        int pr = poll(&pf, 1, timeout_us / 1000);
        if (pr <= 0) return 0;
    }
    switch (c->cfg.io) {
    case PP_TIO_TUN:        return tun_recv(c, out_buf);
#ifdef PP_HAVE_PCAP
    case PP_TIO_PCAP:       return pc_recv(c, out_buf);
#endif
#ifdef PP_HAVE_XDP
    case PP_TIO_AF_XDP:     return xc_recv(c, out_buf);
#endif
#ifdef PP_HAVE_NETMAP
    case PP_TIO_NETMAP:     return nm_recv(c, out_buf);
#endif
    default:                return raw_recv(c, out_buf);
    }
}

static void ic_session_close(void *ctx, uint64_t sid) { (void)ctx; (void)sid; }
static int  ic_get_fd(void *ctx) { return ((struct icmp_ctx *)ctx)->fd; }

static bool ic_tunnel_ready(const struct icmp_ctx *c)
{
#ifdef PP_HAVE_DPDK
    if (c->cfg.io == PP_TIO_DPDK)
        return c->dpdk != NULL;
#endif
#ifdef PP_HAVE_MEMIF
    if (c->cfg.io == PP_TIO_MEMIF)
        return c->memif != NULL && pp_memif_io_is_connected(c->memif);
#endif
    return c->fd >= 0;
}

static int  ic_stat(void *ctx, char *json, size_t cap)
{
    struct icmp_ctx *c = ctx;
    bool ready = ic_tunnel_ready(c);
    return snprintf(json, cap,
        "{\"backend\":\"icmp\",\"io\":\"%s\",\"mode\":\"%s\","
        "\"fd\":%d,\"id\":%u,\"seq\":%u,\"peer_known\":%s,"
        "\"ready\":%s}",
        pp_tunnel_io_name(c->cfg.io),
        c->cfg.mode == PP_TMODE_SERVER ? "server" : "client",
        c->fd, c->identifier, c->seq, c->peer_known ? "true" : "false",
        ready ? "true" : "false");
}

const pp_tunnel_ops_t pp_tunnel_icmp = {
    .name = "icmp", .proto = PP_PROTO_ICMP, .caps = PP_TUN_CAP_MUX,
    .supported_io_mask = PP_TIO_MASK_RAW_SOCKET
                       | PP_TIO_MASK_AF_XDP
                       | PP_TIO_MASK_NETMAP
                       | PP_TIO_MASK_PCAP
                       | PP_TIO_MASK_TUN
                       | PP_TIO_MASK_DPDK
                       | PP_TIO_MASK_MEMIF,
    .open = ic_open, .close = ic_close,
    .connect = ic_connect, .send = ic_send, .recv = ic_recv,
    .session_close = ic_session_close,
    .get_rx_fd = ic_get_fd, .get_tx_fd = ic_get_fd,
    .stat = ic_stat,
};

/* pp_tunnel_register / pp_tunnel_lookup / pp_tunnel_io_name
 * 参见 src/tunnel/registry.c */
