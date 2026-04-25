/* src/tunnel/udp.c -- UDP tunnel（proto 层）
 *
 * 只负责 UDP 隧道的 proto 语义：帧格式、IPv4/UDP 头构造与解析、peer 学习、
 * session 语义。具体"把字节打到线上"的动作都交给 src/io/ 下的模块做：
 *
 *   io=kernel_socket -> src/io/ks_sock
 *   io=raw_socket    -> src/io/raw_ip（仅手拼 UDP 头+载荷；IP 头由内核组）
 *   io=tun           -> src/io/tun_io (+ 手拼 IP+UDP 头)
 *   io=pcap          -> src/io/pcap
 *   io=af_xdp        -> src/io/xsk
 *
 * Wire format（每个 UDP 数据报一帧）：
 *   内核/原始路径上 UDP 载荷即为内层报文，线路上不携带 sid。
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/if.h>
#include "pproxy/tunnel.h"
#include "pproxy/log.h"
#include "io/ks_sock.h"
#include "io/raw_sock.h"
#include "io/tun.h"
#include "io/pcap.h"
#include "io/xsk.h"
#include "pproxy/xsk_filt.h"

#define UDP_RX_MAX      65535
#define L4_UDP_HDR_LEN  8   /* 真正的 UDP 头 */
#define IP_HDR_LEN_MIN  20

struct udp_ctx {
    int                     fd;
    pp_tunnel_cfg_t         cfg;

    /* peer 学习（server） / 固定（client） */
    bool                    peer_known;
    struct sockaddr_storage peer_sa;
    socklen_t               peer_sl;

    /* raw：仅 L4+载荷；tun/pcap/xdp：自造 IP+UDP 头 */
    uint16_t                src_port;
    uint16_t                dst_port;
    uint16_t                listen_port;
    uint32_t                src_ip_be;
    uint16_t                ip_id;

    char                    tun_ifname[IFNAMSIZ];

#ifdef PP_HAVE_PCAP
    struct pp_pcap_io      *pcap;
#endif
#ifdef PP_HAVE_XDP
    struct pp_xsk_io       *xsk;
#endif
};

/* -------------------- IP+UDP 头构造/解析 -------------------- */

static uint16_t inet_csum16(const void *data, size_t len)
{
    const uint8_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += (uint16_t)(p[0] | (p[1] << 8)); p += 2; len -= 2; }
    if (len) sum += p[0];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* 把 payload 填进 frame，形成完整的 IPv4+UDP 报文。返回总长度。 */
static size_t build_ip_udp_frame(uint8_t *frame, size_t cap,
                                 uint32_t src_ip_be, uint32_t dst_ip_be,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint16_t ip_id,
                                 const uint8_t *payload, size_t plen)
{
    const size_t ip_hl   = IP_HDR_LEN_MIN;
    const size_t udp_hl  = L4_UDP_HDR_LEN;
    const size_t udp_tot = udp_hl + plen;
    const size_t ip_tot  = ip_hl + udp_tot;
    if (ip_tot > cap || ip_tot > 65535) return 0;

    memset(frame, 0, ip_hl + udp_hl);
    struct iphdr *iph = (struct iphdr *)frame;
    iph->version  = 4;
    iph->ihl      = 5;
    iph->tot_len  = htons((uint16_t)ip_tot);
    iph->id       = htons(ip_id);
    iph->frag_off = htons(0x4000);      /* DF */
    iph->ttl      = 64;
    iph->protocol = IPPROTO_UDP;
    iph->saddr    = src_ip_be;
    iph->daddr    = dst_ip_be;
    iph->check    = inet_csum16(iph, ip_hl);

    struct udphdr *uh = (struct udphdr *)(frame + ip_hl);
    uh->source = htons(src_port);
    uh->dest   = htons(dst_port);
    uh->len    = htons((uint16_t)udp_tot);
    uh->check  = 0;                     /* IPv4 UDP 校验可选 */

    memcpy(frame + ip_hl + udp_hl, payload, plen);
    return ip_tot;
}

/* raw_socket（无 IP_HDRINCL）：只写 [UDP 头][payload] */
static size_t build_udp_l4(uint8_t *buf, size_t cap,
                          uint16_t src_port, uint16_t dst_port,
                          const uint8_t *payload, size_t plen)
{
    const size_t udp_tot = L4_UDP_HDR_LEN + plen;
    if (udp_tot > cap || udp_tot > 65535) return 0;
    memset(buf, 0, L4_UDP_HDR_LEN);
    struct udphdr *uh = (struct udphdr *)buf;
    uh->source = htons(src_port);
    uh->dest   = htons(dst_port);
    uh->len    = htons((uint16_t)udp_tot);
    uh->check  = 0;
    memcpy(buf + L4_UDP_HDR_LEN, payload, plen);
    return udp_tot;
}

/* 解析入包：成功返回 1，忽略返回 0。 */
static int parse_ip_udp_frame(const uint8_t *frame, size_t n,
                              const struct udp_ctx *c,
                              uint16_t *out_sport, uint32_t *out_saddr_be,
                              const uint8_t **out_body, size_t *out_body_len)
{
    if (n < sizeof(struct iphdr)) return 0;
    if ((frame[0] >> 4) != 4) return 0;
    size_t ip_hl = (frame[0] & 0x0F) * 4u;
    if (ip_hl < IP_HDR_LEN_MIN) return 0;
    if (n < ip_hl + L4_UDP_HDR_LEN) return 0;

    const struct iphdr  *iph = (const struct iphdr  *)frame;
    if (iph->protocol != IPPROTO_UDP) return 0;

    const struct udphdr *uh  = (const struct udphdr *)(frame + ip_hl);
    uint16_t sport = ntohs(uh->source);
    uint16_t dport = ntohs(uh->dest);

    if (dport != c->src_port) return 0;
    if (c->cfg.mode == PP_TMODE_CLIENT && sport != c->dst_port) return 0;

    size_t udp_total = ntohs(uh->len);
    if (udp_total < L4_UDP_HDR_LEN) return 0;
    size_t body_len = udp_total - L4_UDP_HDR_LEN;
    if (n < ip_hl + udp_total) return 0;

    *out_sport     = sport;
    *out_saddr_be  = iph->saddr;
    *out_body      = frame + ip_hl + L4_UDP_HDR_LEN;
    *out_body_len  = body_len;
    return 1;
}

static void learn_peer_server(struct udp_ctx *c, uint32_t saddr_be, uint16_t sport,
                              const char *tag)
{
    struct sockaddr_in *psin = (struct sockaddr_in *)&c->peer_sa;
    bool changed = !c->peer_known ||
                   psin->sin_addr.s_addr != saddr_be ||
                   c->dst_port           != sport;
    if (!changed) return;
    psin->sin_family      = AF_INET;
    psin->sin_port        = 0;
    psin->sin_addr.s_addr = saddr_be;
    c->peer_sl            = sizeof *psin;
    c->dst_port           = sport;
    c->peer_known         = true;
    char a[INET_ADDRSTRLEN] = "";
    inet_ntop(AF_INET, &saddr_be, a, sizeof a);
    PP_INFO("udp %s peer learned: %s:%u", tag, a, sport);
#ifdef PP_HAVE_XDP
    if (c->cfg.io == PP_TIO_AF_XDP && c->xsk) {
        int r = pp_xsk_io_refresh_arp(c->xsk, saddr_be);
        if (r != PP_OK)
            PP_WARN("udp %s: xsk refresh dst_mac failed (rc=%d) peer %s", tag, r, a);
    }
#endif
}

/* -------------------- open / close -------------------- */

static int udp_open(const pp_tunnel_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->proto != PP_PROTO_UDP) return PP_ERR_INVAL;

    switch (cfg->io) {
    case PP_TIO_KERNEL_SOCKET:
    case PP_TIO_RAW_SOCKET:
    case PP_TIO_TUN:
        break;
    case PP_TIO_PCAP:
#ifdef PP_HAVE_PCAP
        break;
#else
        PP_ERROR("udp tunnel: io=pcap requires build with -Dpcap=true");
        return PP_ERR_NOSUPPORT;
#endif
    case PP_TIO_AF_XDP:
#ifdef PP_HAVE_XDP
        break;
#else
        PP_ERROR("udp tunnel: io=af_xdp requires build with -Dxdp=true");
        return PP_ERR_NOSUPPORT;
#endif
    case PP_TIO_NETMAP:
        PP_ERROR("udp tunnel: io=%s not yet implemented", pp_tunnel_io_name(cfg->io));
        return PP_ERR_NOSUPPORT;
    default:
        PP_ERROR("udp tunnel: unknown io=%d", cfg->io);
        return PP_ERR_INVAL;
    }

    if (cfg->io == PP_TIO_RAW_SOCKET ||
        cfg->io == PP_TIO_TUN ||
        cfg->io == PP_TIO_PCAP ||
        cfg->io == PP_TIO_AF_XDP) {
        const pp_endpoint_t *ep =
            (cfg->mode == PP_TMODE_SERVER) ? &cfg->listen : &cfg->server;
        if (ep->addr.af != PP_AF_INET) {
            PP_ERROR("udp %s: only IPv4 supported in MVP",
                     pp_tunnel_io_name(cfg->io));
            return PP_ERR_NOSUPPORT;
        }
    }

    struct udp_ctx *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->cfg = *cfg;
    c->fd  = -1;
    *out_ctx = c;
    return PP_OK;
}

static void udp_close(void *ctx)
{
    struct udp_ctx *c = ctx;
    if (!c) return;
    /* pcap / af_xdp 的 fd 由各自 lib 管，别二次 close */
    bool fd_owned_by_helper = false;
#ifdef PP_HAVE_PCAP
    if (c->cfg.io == PP_TIO_PCAP) { pp_pcap_io_free(c->pcap); c->pcap = NULL; fd_owned_by_helper = true; }
#endif
#ifdef PP_HAVE_XDP
    if (c->cfg.io == PP_TIO_AF_XDP) { pp_xsk_io_free(c->xsk); c->xsk = NULL; fd_owned_by_helper = true; }
#endif
    if (c->fd >= 0 && !fd_owned_by_helper) close(c->fd);
    free(c);
}

/* -------------------- kernel_socket 路径 -------------------- */

static int ks_connect(struct udp_ctx *c)
{
    const pp_endpoint_t *ep =
        (c->cfg.mode == PP_TMODE_SERVER) ? &c->cfg.listen : &c->cfg.server;
    int af = (ep->addr.af == PP_AF_INET6) ? AF_INET6 : AF_INET;

    int rc = pp_ks_udp_open(af, &c->fd);
    if (rc != PP_OK) return rc;

    struct sockaddr_storage ss;
    socklen_t sl = pp_ep_to_sockaddr(ep, &ss);

    if (c->cfg.mode == PP_TMODE_SERVER) {
        rc = pp_ks_udp_bind(c->fd, (struct sockaddr *)&ss, sl);
        if (rc != PP_OK) { close(c->fd); c->fd = -1; return rc; }
        char epstr[64] = ""; pp_endpoint_format(ep, epstr, sizeof epstr);
        PP_INFO("udp tunnel bound on %s (fd=%d), waiting for peer", epstr, c->fd);
    } else {
        rc = pp_ks_udp_connect(c->fd, (struct sockaddr *)&ss, sl);
        if (rc != PP_OK) { close(c->fd); c->fd = -1; return rc; }
        PP_INFO("udp tunnel connected (fd=%d)", c->fd);
    }
    return PP_OK;
}

static int ks_send(struct udp_ctx *c, const pp_tun_buf_t *buf)
{
    if (buf->len > UDP_RX_MAX) return PP_ERR_INVAL;

    int w;
    if (c->cfg.mode == PP_TMODE_SERVER) {
        if (!c->peer_known) return PP_ERR_AGAIN;
        w = pp_ks_udp_send(c->fd, buf->data, buf->len,
                           (struct sockaddr *)&c->peer_sa, c->peer_sl);
    } else {
        w = pp_ks_udp_send(c->fd, buf->data, buf->len, NULL, 0);
    }
    if (w < 0) return w;
    return (int)buf->len;
}

static int ks_recv(struct udp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    struct sockaddr_storage src;
    socklen_t sl = sizeof src;
    int n = pp_ks_udp_recv(c->fd, out_buf->data, out_buf->cap,
                           (struct sockaddr *)&src, &sl);
    if (n <= 0) return n;

    if (c->cfg.mode == PP_TMODE_SERVER) {
        if (!c->peer_known ||
            sl != c->peer_sl ||
            memcmp(&src, &c->peer_sa, sl) != 0) {
            c->peer_sa    = src;
            c->peer_sl    = sl;
            c->peer_known = true;
            char buf[64] = "";
            pp_sockaddr_format((struct sockaddr *)&src, sl, buf, sizeof buf);
            PP_INFO("udp tunnel peer learned: %s", buf);
        }
    }

    out_buf->len = (size_t)n;
    return n;
}

/* -------------------- raw_socket / tun 共用：配置 L3 端口 -------------------- */

static void l3_init_ports(struct udp_ctx *c)
{
    if (c->cfg.mode == PP_TMODE_SERVER) {
        c->listen_port = c->cfg.listen.port;
        c->src_port    = c->cfg.listen.port;
        c->src_ip_be   = c->cfg.listen.addr.u.v4.s_addr;
    } else {
        c->dst_port    = c->cfg.server.port;
        c->src_port    = c->cfg.listen.port
                           ? c->cfg.listen.port
                           : (uint16_t)(32768 + ((uint16_t)getpid() & 0x7FFF));
        c->src_ip_be   = c->cfg.listen.addr.u.v4.s_addr;    /* 0=内核按路由选 */

        struct sockaddr_in *sin = (struct sockaddr_in *)&c->peer_sa;
        sin->sin_family      = AF_INET;
        sin->sin_port        = 0;
        sin->sin_addr.s_addr = c->cfg.server.addr.u.v4.s_addr;
        c->peer_sl           = sizeof *sin;
        c->peer_known        = true;
    }
}

/* -------------------- raw_socket 路径 -------------------- */

static int raw_connect(struct udp_ctx *c)
{
    int rc = pp_raw_ip_open(IPPROTO_UDP, c->cfg.io_cfg.raw.ifname, &c->fd);
    if (rc != PP_OK) return rc;
    l3_init_ports(c);

    if (c->cfg.mode == PP_TMODE_SERVER) {
        PP_INFO("udp raw_socket server: listen_port=%u ifname=%s",
                c->listen_port,
                c->cfg.io_cfg.raw.ifname ? c->cfg.io_cfg.raw.ifname : "(any)");
    } else {
        char sa[INET_ADDRSTRLEN]="", da[INET_ADDRSTRLEN]="";
        inet_ntop(AF_INET, &c->src_ip_be, sa, sizeof sa);
        inet_ntop(AF_INET, &((struct sockaddr_in *)&c->peer_sa)->sin_addr, da, sizeof da);
        PP_INFO("udp raw_socket client: %s:%u -> %s:%u (fd=%d)",
                sa, c->src_port, da, c->dst_port, c->fd);
    }
    return PP_OK;
}

static int raw_send(struct udp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t seg[65535];
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t n = build_udp_l4(seg, sizeof seg,
                            c->src_port, c->dst_port,
                            buf->data, buf->len);
    if (!n) return PP_ERR_INVAL;
    int w = pp_raw_ip_send(c->fd, seg, n, dst_ip_be);
    if (w < 0) return w;
    return (int)buf->len;
}

static int raw_recv(struct udp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    uint8_t frame[UDP_RX_MAX];
    struct sockaddr_storage src;
    socklen_t sl = sizeof src;
    int n = pp_raw_ip_recv(c->fd, frame, sizeof frame,
                           (struct sockaddr *)&src, &sl);
    if (n <= 0) return n;

    uint16_t sport; uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    int r = parse_ip_udp_frame(frame, (size_t)n, c, &sport, &saddr_be, &body, &body_len);
    if (r != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;

    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server(c, saddr_be, sport, "raw_socket");
    return (int)body_len;
}

/* -------------------- tun 路径 -------------------- */
static int tun_connect(struct udp_ctx *c)
{
    int rc = pp_tun_io_open(c->cfg.io_cfg.tun.ifname, true,
                            c->tun_ifname, &c->fd);
    if (rc != PP_OK) return rc;
    l3_init_ports(c);

    if (c->cfg.mode == PP_TMODE_SERVER) {
        PP_INFO("udp tun server: iface=%s listen_port=%u fd=%d",
                c->tun_ifname, c->listen_port, c->fd);
    } else {
        char sa[INET_ADDRSTRLEN]="", da[INET_ADDRSTRLEN]="";
        inet_ntop(AF_INET, &c->src_ip_be, sa, sizeof sa);
        inet_ntop(AF_INET, &((struct sockaddr_in *)&c->peer_sa)->sin_addr, da, sizeof da);
        PP_INFO("udp tun client: iface=%s %s:%u -> %s:%u fd=%d",
                c->tun_ifname, sa, c->src_port, da, c->dst_port, c->fd);
    }
    return PP_OK;
}

static int tun_send(struct udp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t frame[65535];
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t ip_tot = build_ip_udp_frame(frame, sizeof frame,
                                       c->src_ip_be, dst_ip_be,
                                       c->src_port, c->dst_port,
                                       c->ip_id++, buf->data, buf->len);
    if (!ip_tot) return PP_ERR_INVAL;
    int w = pp_tun_io_write_ip(c->fd, frame, ip_tot);
    if (w < 0) return w;
    return (int)buf->len;
}

static int tun_recv(struct udp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    uint8_t frame[UDP_RX_MAX];
    int n = pp_tun_io_read_ip(c->fd, frame, sizeof frame);
    if (n <= 0) return n;

    uint16_t sport; uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    int r = parse_ip_udp_frame(frame, (size_t)n, c, &sport, &saddr_be, &body, &body_len);
    if (r != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;

    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server(c, saddr_be, sport, "tun");
    return (int)body_len;
}

/* -------------------- pcap 路径 -------------------- */
#ifdef PP_HAVE_PCAP
static int pc_connect(struct udp_ctx *c)
{
    l3_init_ports(c);
    char bpf[256];
    if (c->cfg.mode == PP_TMODE_SERVER) {
        snprintf(bpf, sizeof bpf, "udp and dst port %u", c->listen_port);
    } else {
        snprintf(bpf, sizeof bpf,
                 "udp and src port %u and dst port %u",
                 c->dst_port, c->src_port);
    }
    const char *user_bpf = c->cfg.io_cfg.pcap.bpf_filter;
    if (user_bpf && user_bpf[0]) {
        snprintf(bpf, sizeof bpf, "%s", user_bpf);    /* 覆盖默认 */
    }
    int rc = pp_pcap_io_new(&c->pcap,
                            c->cfg.io_cfg.pcap.ifname,
                            NULL,
                            bpf,
                            c->cfg.io_cfg.pcap.snaplen);
    if (rc != PP_OK) return rc;
    c->fd = pp_pcap_io_get_fd(c->pcap);

    if (c->cfg.mode == PP_TMODE_SERVER) {
        PP_INFO("udp pcap server: iface=%s listen_port=%u",
                pp_pcap_io_get_ifname(c->pcap), c->listen_port);
    } else {
        char sa[INET_ADDRSTRLEN]="", da[INET_ADDRSTRLEN]="";
        inet_ntop(AF_INET, &c->src_ip_be, sa, sizeof sa);
        inet_ntop(AF_INET, &((struct sockaddr_in *)&c->peer_sa)->sin_addr, da, sizeof da);
        PP_INFO("udp pcap client: iface=%s %s:%u -> %s:%u",
                pp_pcap_io_get_ifname(c->pcap), sa, c->src_port, da, c->dst_port);
    }
    return PP_OK;
}

static int pc_send(struct udp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t frame[65535];
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t ip_tot = build_ip_udp_frame(frame, sizeof frame,
                                       c->src_ip_be, dst_ip_be,
                                       c->src_port, c->dst_port,
                                       c->ip_id++, buf->data, buf->len);
    if (!ip_tot) return PP_ERR_INVAL;
    int r = pp_pcap_io_inject_ip(c->pcap, frame, ip_tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int pc_recv(struct udp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    size_t n = 0;
    const uint8_t *ip = pp_pcap_io_next_ip(c->pcap, &n);
    if (!ip) return 0;

    uint16_t sport; uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    int r = parse_ip_udp_frame(ip, n, c, &sport, &saddr_be, &body, &body_len);
    if (r != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;

    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server(c, saddr_be, sport, "pcap");
    return (int)body_len;
}
#endif  /* PP_HAVE_PCAP */

/* -------------------- af_xdp 路径 -------------------- */
#ifdef PP_HAVE_XDP
static void udp_af_xdp_tun_log(const struct udp_ctx *c, const char *xif, uint32_t xq)
{
    char lsn[64] = "", svr[64] = "";
    char sm[24] = "n/a", dm[24] = "n/a";
    uint8_t src_mac[6], dst_mac[6];
    if (c->xsk) {
        pp_xsk_io_get_macs(c->xsk, src_mac, dst_mac);
        snprintf(sm, sizeof sm, "%02x:%02x:%02x:%02x:%02x:%02x",
                 src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        snprintf(dm, sizeof dm, "%02x:%02x:%02x:%02x:%02x:%02x",
                 dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    }
    pp_endpoint_format(&c->cfg.listen, lsn, sizeof lsn);
    pp_endpoint_format(&c->cfg.server, svr, sizeof svr);
    if (c->cfg.mode == PP_TMODE_SERVER) {
        PP_INFO("udp af_xdp tunnel: mode=server if=%s q=%u nframes=%u zc=%d need_wakeup=%d "
                "src_mac=%s dst_mac=%s listen_ep=%s listen_port=%u src_ip=0x%08x peer_known=%d server_cfg=%s",
                xif, (unsigned)xq, c->cfg.io_cfg.xdp.nframes,
                c->cfg.io_cfg.xdp.zero_copy ? 1 : 0, c->cfg.io_cfg.xdp.need_wakeup ? 1 : 0,
                sm, dm, lsn, c->listen_port, c->src_ip_be, c->peer_known ? 1 : 0, svr);
    } else {
        char sa[INET_ADDRSTRLEN] = "", da[INET_ADDRSTRLEN] = "";
        inet_ntop(AF_INET, &c->src_ip_be, sa, sizeof sa);
        inet_ntop(AF_INET, &((struct sockaddr_in *)&c->peer_sa)->sin_addr, da, sizeof da);
        PP_INFO("udp af_xdp tunnel: mode=client if=%s q=%u nframes=%u zc=%d need_wakeup=%d "
                "src_mac=%s dst_mac=%s flow %s:%u -> %s:%u listen_ep=%s (ARP 目标 %s)",
                xif, (unsigned)xq, c->cfg.io_cfg.xdp.nframes,
                c->cfg.io_cfg.xdp.zero_copy ? 1 : 0, c->cfg.io_cfg.xdp.need_wakeup ? 1 : 0,
                sm, dm, sa, c->src_port, da, c->dst_port, lsn, da);
    }
}

static int xc_connect(struct udp_ctx *c)
{
    l3_init_ports(c);
    /* 手拼 IP+UDP 时 0.0.0.0 不能当合法源；未配 bind / listen 时用 XDP 口上的主 IPv4。 */
    if (c->src_ip_be == 0 && c->cfg.io_cfg.xdp.ifname && c->cfg.io_cfg.xdp.ifname[0]) {
        uint32_t s;
        if (pp_xsk_ifname_first_ipv4(c->cfg.io_cfg.xdp.ifname, &s) == PP_OK) {
            c->src_ip_be = s;
            char a[INET_ADDRSTRLEN] = "";
            struct in_addr _ia = { .s_addr = s };
            inet_ntop(AF_INET, &_ia, a, sizeof a);
            PP_INFO("udp af_xdp: listen 未设源(0.0.0.0)，使用 %s 上 IPv4 %s 作为发包头源",
                    c->cfg.io_cfg.xdp.ifname, a);
        } else {
            PP_WARN("udp af_xdp: listen 为 0.0.0.0 且无法从 %s 取 IPv4，IP 头源将仍为 0.0.0.0",
                    c->cfg.io_cfg.xdp.ifname);
        }
    }
    uint32_t arp_nexthop_be = 0;
    if (c->cfg.mode == PP_TMODE_CLIENT)
        arp_nexthop_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    pp_xsk_filt_t xf;
    memset(&xf, 0, sizeof xf);
    xf.daddr_be = c->src_ip_be;
    xf.ipproto  = (uint8_t)IPPROTO_UDP;
    if (c->cfg.mode == PP_TMODE_SERVER)
        xf.dport_be = htons(c->listen_port);
    else
        xf.dport_be = htons(c->src_port);
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

    /* 与 kernel_socket 一致，供 tests/clab/deploy.sh 等做日志 grep。 */
    if (c->cfg.mode == PP_TMODE_SERVER) {
        const pp_endpoint_t *ep = &c->cfg.listen;
        char epstr[64] = "";
        pp_endpoint_format(ep, epstr, sizeof epstr);
        PP_INFO("udp tunnel bound on %s (fd=%d), waiting for peer", epstr, c->fd);
    } else {
        PP_INFO("udp tunnel connected (fd=%d)", c->fd);
    }

    const char *xif = pp_xsk_io_get_ifname(c->xsk);
    uint32_t    xq  = pp_xsk_io_get_queue(c->xsk);
    udp_af_xdp_tun_log(c, xif, xq);
    return PP_OK;
}

static int xc_send(struct udp_ctx *c, const pp_tun_buf_t *buf)
{
    if (!c->peer_known) return PP_ERR_AGAIN;
    uint8_t frame[65535];
    uint32_t dst_ip_be = ((struct sockaddr_in *)&c->peer_sa)->sin_addr.s_addr;
    size_t ip_tot = build_ip_udp_frame(frame, sizeof frame,
                                       c->src_ip_be, dst_ip_be,
                                       c->src_port, c->dst_port,
                                       c->ip_id++, buf->data, buf->len);
    if (!ip_tot) return PP_ERR_INVAL;
    int r = pp_xsk_io_inject_ip(c->xsk, frame, ip_tot);
    if (r < 0) return r;
    return (int)buf->len;
}

static int xc_recv(struct udp_ctx *c, pp_tun_mbuf_t *out_buf)
{
    size_t n = 0;
    const uint8_t *ip = pp_xsk_io_next_ip(c->xsk, &n);
    if (!ip) return 0;

    uint16_t sport; uint32_t saddr_be;
    const uint8_t *body; size_t body_len;
    int r = parse_ip_udp_frame(ip, n, c, &sport, &saddr_be, &body, &body_len);
    if (r != 1) return 0;
    if (out_buf->cap < body_len) return PP_ERR_NOMEM;
    memcpy(out_buf->data, body, body_len);
    out_buf->len = body_len;

    if (c->cfg.mode == PP_TMODE_SERVER)
        learn_peer_server(c, saddr_be, sport, "af_xdp");
    return (int)body_len;
}
#endif  /* PP_HAVE_XDP */

/* -------------------- 顶层 ops 调度 -------------------- */

static int udp_connect(void *ctx)
{
    struct udp_ctx *c = ctx;
    if (c->fd >= 0) return PP_OK;
    switch (c->cfg.io) {
    case PP_TIO_RAW_SOCKET: return raw_connect(c);
    case PP_TIO_TUN:        return tun_connect(c);
#ifdef PP_HAVE_PCAP
    case PP_TIO_PCAP:       return pc_connect(c);
#endif
#ifdef PP_HAVE_XDP
    case PP_TIO_AF_XDP:     return xc_connect(c);
#endif
    default:                return ks_connect(c);
    }
}

static int udp_send(void *ctx, const pp_tun_buf_t *buf)
{
    struct udp_ctx *c = ctx;
    if (c->fd < 0) return PP_ERR_CLOSED;
    switch (c->cfg.io) {
    case PP_TIO_RAW_SOCKET: return raw_send(c, buf);
    case PP_TIO_TUN:        return tun_send(c, buf);
#ifdef PP_HAVE_PCAP
    case PP_TIO_PCAP:       return pc_send(c, buf);
#endif
#ifdef PP_HAVE_XDP
    case PP_TIO_AF_XDP:     return xc_send(c, buf);
#endif
    default:                return ks_send (c, buf);
    }
}

static int udp_recv(void *ctx, pp_tun_mbuf_t *out_buf, int timeout_us)
{
    struct udp_ctx *c = ctx;
    if (c->fd < 0) return PP_ERR_CLOSED;

    if (timeout_us > 0) {
        struct pollfd pf = { .fd = c->fd, .events = POLLIN };
        int pr = poll(&pf, 1, timeout_us / 1000);
        if (pr <= 0) return 0;
    }
    switch (c->cfg.io) {
    case PP_TIO_RAW_SOCKET: return raw_recv(c, out_buf);
    case PP_TIO_TUN:        return tun_recv(c, out_buf);
#ifdef PP_HAVE_PCAP
    case PP_TIO_PCAP:       return pc_recv(c, out_buf);
#endif
#ifdef PP_HAVE_XDP
    case PP_TIO_AF_XDP:     return xc_recv(c, out_buf);
#endif
    default:                return ks_recv (c, out_buf);
    }
}

static void udp_session_close(void *ctx, uint64_t sid) { (void)ctx; (void)sid; }
static int  udp_get_fd(void *ctx) { return ((struct udp_ctx *)ctx)->fd; }
static int  udp_stat(void *ctx, char *json, size_t cap)
{
    struct udp_ctx *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"udp\",\"io\":\"%s\",\"mode\":\"%s\","
        "\"fd\":%d,\"src_port\":%u,\"dst_port\":%u,\"peer_known\":%s}",
        pp_tunnel_io_name(c->cfg.io),
        c->cfg.mode == PP_TMODE_SERVER ? "server" : "client",
        c->fd, c->src_port, c->dst_port, c->peer_known ? "true" : "false");
}

const pp_tunnel_ops_t pp_tunnel_udp = {
    .name  = "udp", .proto = PP_PROTO_UDP, .caps = PP_TUN_CAP_MUX,
    .supported_io_mask = PP_TIO_MASK_KERNEL_SOCKET
                       | PP_TIO_MASK_RAW_SOCKET
                       | PP_TIO_MASK_AF_XDP
                       | PP_TIO_MASK_NETMAP
                       | PP_TIO_MASK_PCAP
                       | PP_TIO_MASK_TUN,
    .open = udp_open, .close = udp_close,
    .connect = udp_connect, .send = udp_send, .recv = udp_recv,
    .session_close = udp_session_close,
    .get_rx_fd = udp_get_fd, .get_tx_fd = udp_get_fd,
    .stat = udp_stat,
};
