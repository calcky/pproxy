/* src/io/netmap.c -- netmap 相关 I/O
 *
 * 本文件同时承载两个角色（仅 -Dnetmap=true / PP_HAVE_NETMAP 时编译）：
 *   1) 左手侧 pp_pkt_io_ops_t 下的 NETMAP 后端 pp_io_netmap；
 *   2) 右手侧 tunnel 用的 "IP 注入/抽取" 薄封装 pp_netmap_io_*。
 *
 * 选 classic nm_open() API（third_party/netmap/net/netmap_user.h，header-only），
 * 不依赖 libnetmap.so。运行时仍需要内核加载 netmap 模块、提供 /dev/netmap。
 */
#ifdef PP_HAVE_NETMAP

/* netmap_user.h 里的 D()/RD() 宏会展开 fprintf；项目用 PP_INFO 取代之，
 * 这里把 NETMAP_WITH_LIBS 打开以拉入 nm_open / nm_inject / nm_nextpkt 等
 * 静态内联实现。 */
#define NETMAP_WITH_LIBS
#include "netmap.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <poll.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/if_arp.h>     /* ATF_COM */
#include <linux/if_ether.h>
#include <net/netmap_user.h>
#include "pproxy/pkt_io.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"

#define PP_NM_ETH_HDR     14
#define PP_NM_RX_STASH    2048

struct pp_netmap_io {
    struct nm_desc *nmd;
    int             fd;
    char            ifname[IFNAMSIZ];   /* 含端口前缀，如 "netmap:eth0" */
    char            phyif[IFNAMSIZ];    /* 去前缀的纯接口名，仅用于 ARP/MAC 查询 */
    uint8_t         src_mac[6];
    uint8_t         dst_mac[6];
    uint8_t         rx_stash[PP_NM_RX_STASH];
    size_t          rx_stash_len;
};

/* ====================================================================
 * (A) 内部 helper：从 ifname 取物理口名 / src MAC / 第一个 IPv4 / ARP
 *     基本是 src/io/xsk.c 里同名 helper 的本地副本，做必要重命名以避免
 *     符号冲突；这里不抽出公共库以免一次性触动 xsk.c 的稳定路径。
 * ==================================================================== */

/* "netmap:eth0", "netmap:eth0-0", "vale0:1" → 物理网卡名 "eth0" / "vale0:1"。
 * 实现策略：去掉 "netmap:" / "vale" 之外的前缀；vale 端口本身没有 ifaddr，
 * 这里如果检测到 vale: 就把 phyif 留空，让后续 ARP 调用 short-circuit。 */
static void nm_strip_prefix(const char *full, char *phyif, size_t cap)
{
    if (!full || !phyif || !cap) {
        if (phyif && cap) phyif[0] = '\0';
        return;
    }
    const char *p = full;
    if (!strncmp(p, "netmap:", 7)) p += 7;
    else if (!strncmp(p, "vale", 4)) {
        /* vale 是虚拟交换机，没有 Linux ifaddr，给空字符串触发跳过 */
        phyif[0] = '\0';
        return;
    } else if (!strncmp(p, "valeXX:", 7)) {
        phyif[0] = '\0';
        return;
    }
    /* "eth0-0" / "eth0^" / "eth0/T" 这些后缀 nm_open 自己解析；
     * 我们做 ifr_name 时需要纯接口名，截到第一个非 ifname 合法字符。 */
    size_t i = 0;
    while (p[i] && i + 1 < cap) {
        char c = p[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '_')
            phyif[i] = c;
        else
            break;
        i++;
    }
    phyif[i] = '\0';
}

static int nm_get_src_mac(const char *phyif, uint8_t mac[6])
{
    if (!phyif || !phyif[0]) return PP_ERR_INVAL;
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return PP_ERR_IO;
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", phyif);
    int r = ioctl(s, SIOCGIFHWADDR, &ifr);
    close(s);
    if (r < 0) return PP_ERR_IO;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    return PP_OK;
}

static int nm_get_ifaddr_v4(const char *phyif, struct in_addr *out)
{
    if (!phyif || !phyif[0] || !out) return -1;
    int ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) return -1;
    struct ifreq ifa;
    memset(&ifa, 0, sizeof ifa);
    snprintf(ifa.ifr_name, sizeof ifa.ifr_name, "%s", phyif);
    int r = ioctl(ctl, SIOCGIFADDR, &ifa);
    close(ctl);
    if (r < 0) return -1;
    if (ifa.ifr_addr.sa_family != AF_INET) return -1;
    *out = ((struct sockaddr_in *)&ifa.ifr_addr)->sin_addr;
    if (out->s_addr == htonl(INADDR_ANY)) return -1;
    return 0;
}

static int nm_mac_is_zero(const uint8_t m[6])
{
    return m[0] == 0 && m[1] == 0 && m[2] == 0
        && m[3] == 0 && m[4] == 0 && m[5] == 0;
}

static void nm_arp_trigger(const char *phyif, uint32_t dst_be)
{
    if (dst_be == 0 || !phyif || !phyif[0]) return;
    {
        uint32_t h = ntohl(dst_be);
        if (h == 0xFFFFFFFFu || (h & 0xf0000000u) == 0xe0000000u) return;
    }
    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return;

    struct in_addr laddr;
    if (nm_get_ifaddr_v4(phyif, &laddr) == 0) {
        struct sockaddr_in b = {0};
        b.sin_family = AF_INET;
        b.sin_addr   = laddr;
        (void)bind(s, (struct sockaddr *)&b, sizeof b);
    } else {
#ifdef SO_BINDTODEVICE
        size_t len = strnlen(phyif, IFNAMSIZ - 1);
        if (len > 0)
            (void)setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, phyif, (socklen_t)(len + 1));
#endif
    }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = dst_be;
    a.sin_port    = htons(9);
    char z = 0;
    (void)sendto(s, &z, 1, 0, (struct sockaddr *)&a, sizeof a);
    close(s);
}

static int nm_parse_hwaddr(const char *s, uint8_t mac[6])
{
    unsigned a[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)(a[i] & 0xFF);
    return 0;
}

static int nm_arp_loose(const char *want_ip, uint8_t out_mac[6],
                        char *out_dev, size_t devcap)
{
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[256];
    if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
    while (fgets(line, sizeof line, f)) {
        char ip[64], htype[32], flags[32], macstr[32], mask[32], dev[64];
        if (sscanf(line, "%63s %31s %31s %31s %31s %63s",
                   ip, htype, flags, macstr, mask, dev) < 6)
            continue;
        if (strcmp(ip, want_ip) != 0) continue;
        long flg = strtol(flags, NULL, 0);
        if ((flg & ATF_COM) == 0) continue;
        if (nm_parse_hwaddr(macstr, out_mac) != 0) continue;
        if (nm_mac_is_zero(out_mac)) continue;
        if (out_dev && devcap) snprintf(out_dev, devcap, "%s", dev);
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static int nm_arp_from_proc(const char *phyif, uint32_t ip_be,
                            uint8_t out_mac[6], int max_wait_ms)
{
    char want[INET_ADDRSTRLEN];
    struct in_addr in = { .s_addr = ip_be };
    if (!inet_ntop(AF_INET, &in, want, sizeof want)) return -1;

    nm_arp_trigger(phyif, ip_be);
    usleep(30 * 1000);

    for (int ms = 0; ms < max_wait_ms; ms += 20) {
        if (ms == 500) nm_arp_trigger(phyif, ip_be);
        FILE *f = fopen("/proc/net/arp", "r");
        if (!f) return -1;
        char line[256];
        if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
        while (fgets(line, sizeof line, f)) {
            char ip[64], htype[32], flags[32], macstr[32], mask[32], dev[64];
            if (sscanf(line, "%63s %31s %31s %31s %31s %63s",
                       ip, htype, flags, macstr, mask, dev) < 6)
                continue;
            if (phyif && phyif[0] && strcmp(dev, phyif) != 0) continue;
            if (strcmp(ip, want) != 0) continue;
            long flg = strtol(flags, NULL, 0);
            if ((flg & ATF_COM) == 0) continue;
            if (nm_parse_hwaddr(macstr, out_mac) != 0) continue;
            if (nm_mac_is_zero(out_mac)) continue;
            fclose(f);
            return 0;
        }
        fclose(f);
        {
            char odev[IFNAMSIZ] = "";
            if (nm_arp_loose(want, out_mac, odev, sizeof odev) == 0) {
                if (odev[0] && phyif && phyif[0] && strcmp(odev, phyif) != 0)
                    PP_WARN("netmap: ARP for %s is on %s, not on configured if %s",
                            want, odev, phyif);
                return 0;
            }
        }
        usleep(20 * 1000);
    }
    return -1;
}

static int nm_ifname_popen_safe(const char *n)
{
    if (!n || !*n) return 0;
    for (const char *p = n; *p; p++) {
        char c = *p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_')
            continue;
        return 0;
    }
    return 1;
}

static void nm_route_arp_target(const char *phyif, uint32_t dst_be,
                                uint32_t *out_arp_be)
{
    *out_arp_be = dst_be;
    char dst_str[INET_ADDRSTRLEN];
    struct in_addr di = { .s_addr = dst_be };
    if (!inet_ntop(AF_INET, &di, dst_str, sizeof dst_str)) return;

    char b_oif[320] = "", b_plain[300];
    snprintf(b_plain, sizeof b_plain, "ip -4 route get %s 2>/dev/null", dst_str);
    if (phyif && phyif[0] && nm_ifname_popen_safe(phyif))
        snprintf(b_oif, sizeof b_oif,
                 "ip -4 route get %s oif %s 2>/dev/null", dst_str, phyif);

    const char *order[2];
    int n = 0;
    if (b_oif[0]) order[n++] = b_oif;
    order[n++] = b_plain;

    char line[512];
    for (int k = 0; k < n; k++) {
        FILE *fp = popen(order[k], "r");
        if (!fp) continue;
        if (!fgets(line, sizeof line, fp)) { pclose(fp); continue; }
        pclose(fp);
        *out_arp_be = dst_be;
        const char *via = strstr(line, " via ");
        if (via) {
            via += 5;
            char gw[64];
            if (sscanf(via, "%63s", gw) == 1) {
                struct in_addr a;
                if (inet_pton(AF_INET, gw, &a) == 1)
                    *out_arp_be = a.s_addr;
            }
        }
        return;
    }
}

static void nm_mac_fmt(const uint8_t m[6], char *buf, size_t cap)
{
    snprintf(buf, cap, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

static int nm_fill_dst_mac(struct pp_netmap_io *p, uint32_t l3_dst_be,
                           const uint8_t *peer_mac_opt)
{
    if (!p->phyif[0]) {
        /* vale: 等无 ifaddr 的情景 — 没法查 ARP，只能用 peer_mac 或全 0 */
        if (peer_mac_opt) {
            memcpy(p->dst_mac, peer_mac_opt, 6);
            return PP_OK;
        }
        return PP_ERR_AGAIN;
    }
    uint32_t arp_for = l3_dst_be;
    nm_route_arp_target(p->phyif, l3_dst_be, &arp_for);
    if (arp_for != l3_dst_be) {
        char pa[INET_ADDRSTRLEN] = "", pb[INET_ADDRSTRLEN] = "";
        struct in_addr aa = { .s_addr = l3_dst_be }, ab = { .s_addr = arp_for };
        inet_ntop(AF_INET, &aa, pa, sizeof pa);
        inet_ntop(AF_INET, &ab, pb, sizeof pb);
        PP_INFO("netmap: L3 目的 %s -> 按路由邻居/ARP 目标 %s", pa, pb);
    }
    if (nm_arp_from_proc(p->phyif, arp_for, p->dst_mac, 2000) == 0) {
        char dm[24], ipe[INET_ADDRSTRLEN];
        struct in_addr ia = { .s_addr = arp_for };
        inet_ntop(AF_INET, &ia, ipe, sizeof ipe);
        nm_mac_fmt(p->dst_mac, dm, sizeof dm);
        PP_INFO("netmap: %s dst_mac from ARP (lookup key %s) -> %s",
                p->phyif, ipe, dm);
        return PP_OK;
    }
    if (peer_mac_opt) {
        memcpy(p->dst_mac, peer_mac_opt, 6);
        char dm2[24];
        nm_mac_fmt(p->dst_mac, dm2, sizeof dm2);
        PP_INFO("netmap: dst_mac fallback peer_mac=%s", dm2);
        return PP_OK;
    }
    return PP_ERR_AGAIN;
}

/* ====================================================================
 * (B) 公共 API：pp_netmap_io_*
 * ==================================================================== */

int pp_netmap_ifname_first_ipv4(const char *ifname, uint32_t *out_saddr_be)
{
    if (!ifname || !ifname[0] || !out_saddr_be) return PP_ERR_INVAL;
    char phyif[IFNAMSIZ] = "";
    nm_strip_prefix(ifname, phyif, sizeof phyif);
    struct in_addr a;
    if (nm_get_ifaddr_v4(phyif, &a) != 0) return PP_ERR_AGAIN;
    *out_saddr_be = a.s_addr;
    return PP_OK;
}

int pp_netmap_io_new(struct pp_netmap_io **out,
                     const char *ifname,
                     uint32_t nrings,
                     const uint8_t peer_mac[6],
                     uint32_t arp_nexthop_be)
{
    (void)nrings;   /* MVP: 由 nm_open 默认绑全部 ring；未来可加后缀 -N */
    if (!out || !ifname || !ifname[0]) return PP_ERR_INVAL;

    struct pp_netmap_io *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->fd = -1;
    snprintf(p->ifname, sizeof p->ifname, "%s", ifname);
    nm_strip_prefix(ifname, p->phyif, sizeof p->phyif);

    if (p->phyif[0]) {
        if (nm_get_src_mac(p->phyif, p->src_mac) != PP_OK)
            PP_WARN("netmap: SIOCGIFHWADDR(%s) failed, src MAC stays zero",
                    p->phyif);
        else {
            char sm[24]; nm_mac_fmt(p->src_mac, sm, sizeof sm);
            PP_INFO("netmap: %s src_mac=%s", p->phyif, sm);
        }
    }

    if (arp_nexthop_be) {
        if (nm_fill_dst_mac(p, arp_nexthop_be, peer_mac) != PP_OK && !peer_mac)
            PP_INFO("netmap: %s dst_mac unset (all zero)", p->ifname);
    } else if (peer_mac) {
        memcpy(p->dst_mac, peer_mac, 6);
        char dm[24]; nm_mac_fmt(p->dst_mac, dm, sizeof dm);
        PP_INFO("netmap: %s dst_mac from peer_mac=%s", p->ifname, dm);
    } else {
        PP_INFO("netmap: %s dst_mac unset (all zero, no arp_nexthop/peer_mac)",
                p->ifname);
    }

    p->nmd = nm_open(p->ifname, NULL, 0, NULL);
    if (!p->nmd) {
        PP_ERROR("netmap: nm_open(%s) failed: %s "
                 "(need /dev/netmap, kernel module loaded; CAP_NET_ADMIN)",
                 p->ifname, strerror(errno));
        free(p);
        return PP_ERR_IO;
    }
    p->fd = NETMAP_FD(p->nmd);
    PP_INFO("netmap: opened %s fd=%d tx_rings=[%u..%u] rx_rings=[%u..%u]",
            p->ifname, p->fd,
            p->nmd->first_tx_ring, p->nmd->last_tx_ring,
            p->nmd->first_rx_ring, p->nmd->last_rx_ring);
    *out = p;
    return PP_OK;
}

void pp_netmap_io_free(struct pp_netmap_io *p)
{
    if (!p) return;
    if (p->nmd) nm_close(p->nmd);
    free(p);
}

int         pp_netmap_io_get_fd    (const struct pp_netmap_io *p) { return p ? p->fd : -1; }
const char *pp_netmap_io_get_ifname(const struct pp_netmap_io *p) { return p ? p->ifname : ""; }

void pp_netmap_io_get_macs(const struct pp_netmap_io *p,
                           uint8_t out_src[6], uint8_t out_dst[6])
{
    if (out_src) memset(out_src, 0, 6);
    if (out_dst) memset(out_dst, 0, 6);
    if (!p) return;
    if (out_src) memcpy(out_src, p->src_mac, 6);
    if (out_dst) memcpy(out_dst, p->dst_mac, 6);
}

int pp_netmap_io_refresh_arp(struct pp_netmap_io *p, uint32_t l3_peer_be)
{
    if (!p || !l3_peer_be) return PP_ERR_INVAL;
    return nm_fill_dst_mac(p, l3_peer_be, NULL);
}

int pp_netmap_io_inject_ip(struct pp_netmap_io *p, const uint8_t *ip, size_t len)
{
    if (!p || !p->nmd) return PP_ERR_CLOSED;
    if (PP_NM_ETH_HDR + len > 65535) return PP_ERR_INVAL;

    uint8_t frame[65535 + PP_NM_ETH_HDR];
    memcpy(frame,                   p->dst_mac, 6);
    memcpy(frame + 6,               p->src_mac, 6);
    frame[12] = 0x08; frame[13] = 0x00;
    memcpy(frame + PP_NM_ETH_HDR, ip, len);
    size_t tot = PP_NM_ETH_HDR + len;

    int r = nm_inject(p->nmd, frame, tot);
    if (r == 0) return PP_ERR_AGAIN;        /* TX ring 满 */

    /* nm_inject 只填 ring，没 NIOCTXSYNC；用 poll(0) kick 内核发包 */
    struct pollfd pf = { .fd = p->fd, .events = POLLOUT };
    (void)poll(&pf, 1, 0);
    return (int)len;
}

const uint8_t *pp_netmap_io_next_ip(struct pp_netmap_io *p, size_t *out_len)
{
    if (!p || !p->nmd) return NULL;

    /* 触发 NIOCRXSYNC：让内核把新到包 push 进 ring；超时 0 = 不阻塞 */
    struct pollfd pf = { .fd = p->fd, .events = POLLIN };
    (void)poll(&pf, 1, 0);

    struct nm_pkthdr hdr;
    u_char *frame = nm_nextpkt(p->nmd, &hdr);
    if (!frame) return NULL;

    size_t flen = hdr.caplen;
    size_t off = 0;
    if (flen >= PP_NM_ETH_HDR) {
        if (flen >= PP_NM_ETH_HDR + 4 && frame[12] == 0x81 && frame[13] == 0x00)
            off = PP_NM_ETH_HDR + 4;
        else
            off = PP_NM_ETH_HDR;
    }
    size_t ip_len = (flen > off) ? (size_t)(flen - off) : 0;
    if (ip_len > sizeof p->rx_stash) ip_len = sizeof p->rx_stash;
    memcpy(p->rx_stash, frame + off, ip_len);
    p->rx_stash_len = ip_len;

    if (out_len) *out_len = ip_len;
    return p->rx_stash;
}

/* ====================================================================
 * (C) 左手 pp_pkt_io_ops_t —— 直接复用 (B) 段做 rx/tx
 * ==================================================================== */

typedef struct nm_left_ctx {
    struct pp_netmap_io *io;
    pp_mempool_t        *pool;
    char                 ifname[IFNAMSIZ];
    uint32_t             nrings;
} nm_left_ctx_t;

static int nm_open_left(const pp_io_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->kind != PP_IO_NETMAP) return PP_ERR_INVAL;
    if (!cfg->pool) {
        PP_ERROR("netmap: mempool required for rx");
        return PP_ERR_INVAL;
    }
    if (!cfg->u.netmap.ifname || !cfg->u.netmap.ifname[0]) {
        PP_ERROR("netmap: cfg->u.netmap.ifname is required (e.g. \"netmap:eth0\")");
        return PP_ERR_INVAL;
    }
    nm_left_ctx_t *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->pool   = cfg->pool;
    c->nrings = cfg->u.netmap.nrings;

    int rc = pp_netmap_io_new(&c->io, cfg->u.netmap.ifname,
                              cfg->u.netmap.nrings, NULL, 0);
    if (rc != PP_OK) { free(c); return rc; }
    snprintf(c->ifname, sizeof c->ifname, "%s",
             pp_netmap_io_get_ifname(c->io));
    *out_ctx = c;
    return PP_OK;
}

static void nm_close_left(void *ctx)
{
    if (!ctx) return;
    nm_left_ctx_t *c = ctx;
    if (c->io) pp_netmap_io_free(c->io);
    free(c);
}

static int nm_rx(void *ctx, pp_pkt_t **pkts, int max, int timeout_us)
{
    (void)timeout_us;
    nm_left_ctx_t *c = ctx;
    int got = 0;
    for (int i = 0; i < max; i++) {
        size_t n = 0;
        const uint8_t *ip = pp_netmap_io_next_ip(c->io, &n);
        if (!ip) break;
        pp_pkt_t *p = pp_mempool_alloc(c->pool);
        if (!p) break;
        if (n > p->tailroom) { pp_pkt_put_ref(p); continue; }
        memcpy(p->data, ip, n);
        p->data_len = (uint16_t)n;
        p->tailroom -= (uint16_t)n;
        p->origin   = PP_PKT_FROM_NETMAP;
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

static int nm_tx(void *ctx, pp_pkt_t **pkts, int n)
{
    nm_left_ctx_t *c = ctx;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        pp_pkt_t *p = pkts[i];
        int w = pp_netmap_io_inject_ip(c->io, p->data, p->data_len);
        if (w < 0) break;
        sent++;
    }
    return sent;
}

static int nm_fd_left(void *ctx)
{
    nm_left_ctx_t *c = ctx;
    return c && c->io ? pp_netmap_io_get_fd(c->io) : -1;
}

static int nm_stat(void *ctx, char *json, size_t cap)
{
    nm_left_ctx_t *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"netmap\",\"if\":\"%s\",\"nrings\":%u,\"fd\":%d}",
        c->ifname, c->nrings, c->io ? pp_netmap_io_get_fd(c->io) : -1);
}

const pp_pkt_io_ops_t pp_io_netmap = {
    .name      = "netmap",
    .kind      = PP_IO_NETMAP,
    .caps      = PP_IO_CAP_L2 | PP_IO_CAP_ZEROCOPY | PP_IO_CAP_BATCH | PP_IO_CAP_BUSY_POLL,
    .open      = nm_open_left,
    .close     = nm_close_left,
    .rx_burst  = nm_rx,
    .tx_burst  = nm_tx,
    .get_rx_fd = nm_fd_left,
    .get_tx_fd = nm_fd_left,
    .stat      = nm_stat,
};

#endif /* PP_HAVE_NETMAP */
