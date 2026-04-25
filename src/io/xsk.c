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
#include <sys/ioctl.h>          /* SIOCGIFADDR, SIOCGIFHWADDR */
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <net/if_arp.h>     /* ATF_COM */
#include <linux/if_ether.h>
#include <linux/if_xdp.h>
#include <xdp/xsk.h>
#include "pproxy/pkt_io.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "xsk_i.h"
#include "xsk_xdpcap.h"
#include <sys/stat.h>

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
                           cfg->u.xdp.has_peer_mac ? cfg->u.xdp.peer_mac : NULL,
                           cfg->u.xdp.arp_nexthop_be,
                           &cfg->u.xdp.xdp_filt);
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

/* 本接口第一个 IPv4，用于 bind，使发探测包时走与 XDP 同一出口（不依赖 SO_BINDTODEVICE 能力）。 */
static int get_ifaddr_v4(const char *ifname, struct in_addr *out)
{
    if (!ifname || !ifname[0] || !out) return -1;
    int ctl = socket(AF_INET, SOCK_DGRAM, 0);
    if (ctl < 0) return -1;
    struct ifreq ifa;
    memset(&ifa, 0, sizeof ifa);
    snprintf(ifa.ifr_name, sizeof ifa.ifr_name, "%s", ifname);
    int r = ioctl(ctl, SIOCGIFADDR, &ifa);
    close(ctl);
    if (r < 0) return -1;
    if (ifa.ifr_addr.sa_family != AF_INET) return -1;
    *out = ((struct sockaddr_in *)&ifa.ifr_addr)->sin_addr;
    if (out->s_addr == htonl(INADDR_ANY)) return -1;
    return 0;
}

static int arp_mac_is_zero(const uint8_t m[6])
{
    return m[0] == 0 && m[1] == 0 && m[2] == 0
           && m[3] == 0 && m[4] == 0 && m[5] == 0;
}

/* 发一条 UDP 探测，促使内核对到 dst 的路径做 ARP。优先 bind 到 ifname 的 IPv4 再 sendto。 */
static void arp_nexthop_trigger(const char *ifname, uint32_t dst_be)
{
    if (dst_be == 0) return;
    {
        uint32_t h = ntohl(dst_be);
        if (h == 0xFFFFFFFFu || (h & 0xf0000000u) == 0xe0000000u) /* 广播/组播 */
            return;
    }

    int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s < 0) return;

    struct in_addr laddr;
    if (ifname && ifname[0] && get_ifaddr_v4(ifname, &laddr) == 0) {
        struct sockaddr_in b = {0};
        b.sin_family = AF_INET;
        b.sin_addr   = laddr;
        b.sin_port   = 0;
        (void)bind(s, (struct sockaddr *)&b, sizeof b);
    } else {
#ifdef SO_BINDTODEVICE
        if (ifname && ifname[0]) {
            size_t len = strnlen(ifname, IFNAMSIZ - 1);
            if (len > 0)
                (void)setsockopt(s, SOL_SOCKET, SO_BINDTODEVICE, ifname, (socklen_t)(len + 1));
        }
#endif
    }

    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = dst_be;
    a.sin_port    = htons(9); /* discard */
    char z = 0;
    (void)sendto(s, &z, 1, 0, (struct sockaddr *)&a, sizeof a);
    close(s);
}

/* 将 IPv4 邻居 MAC 从 /proc/net/arp 读出。先 trigger 再轮询。 */
static int parse_hwaddr_arp(const char *s, uint8_t mac[6])
{
    unsigned a[6];
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &a[0], &a[1], &a[2], &a[3], &a[4], &a[5]) != 6)
        return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)(a[i] & 0xFF);
    return 0;
}

/* 不按 Device 过滤：与 ifname 同一轮询未命中时用（邻居表已更新但 Device 列与配置名不同等） */
static int arp_nexthop_loose(const char *want_ip, uint8_t out_mac[6], char *out_dev, size_t devcap)
{
    FILE *f = fopen("/proc/net/arp", "r");
    if (!f) return -1;
    char line[256];
    if (!fgets(line, sizeof line, f)) { fclose(f); return -1; }
    while (fgets(line, sizeof line, f)) {
        char ip[64], htype[32], flags[32], macstr[32], mask[32], dev[64];
        if (sscanf(line, "%63s %31s %31s %31s %31s %63s", ip, htype, flags, macstr, mask, dev) < 6)
            continue;
        if (strcmp(ip, want_ip) != 0) continue;
        long flg = strtol(flags, NULL, 0);
        if ((flg & ATF_COM) == 0) continue;
        if (parse_hwaddr_arp(macstr, out_mac) != 0) continue;
        if (arp_mac_is_zero(out_mac)) continue;
        if (out_dev && devcap) snprintf(out_dev, devcap, "%s", dev);
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static int arp_nexthop_from_proc(const char *ifname, uint32_t ip_be, uint8_t out_mac[6], int max_wait_ms)
{
    char want[INET_ADDRSTRLEN];
    struct in_addr in = { .s_addr = ip_be };
    if (!inet_ntop(AF_INET, &in, want, sizeof want)) return -1;

    arp_nexthop_trigger(ifname, ip_be);
    usleep(30 * 1000); /* 给内核发 ARP 与写邻居表留一点时间 */

    for (int ms = 0; ms < max_wait_ms; ms += 20) {
        if (ms == 500) arp_nexthop_trigger(ifname, ip_be);
        FILE *f = fopen("/proc/net/arp", "r");
        if (!f) return -1;
        char line[256];
        if (!fgets(line, sizeof line, f)) { fclose(f); return -1; } /* 跳过表头 */
        while (fgets(line, sizeof line, f)) {
            char ip[64], htype[32], flags[32], macstr[32], mask[32], dev[64];
            if (sscanf(line, "%63s %31s %31s %31s %31s %63s", ip, htype, flags, macstr, mask, dev) < 6)
                continue;
            if (strcmp(dev, ifname) != 0) continue;
            if (strcmp(ip, want) != 0) continue;
            long flg = strtol(flags, NULL, 0);
            if ((flg & ATF_COM) == 0) continue; /* 未完成/无有效 MAC，忽略该行 */
            if (parse_hwaddr_arp(macstr, out_mac) != 0) continue;
            if (arp_mac_is_zero(out_mac)) continue;
            fclose(f);
            return 0;
        }
        fclose(f);
        {
            char odev[IFNAMSIZ] = "";
            if (arp_nexthop_loose(want, out_mac, odev, sizeof odev) == 0) {
                if (odev[0] && strcmp(odev, ifname) != 0) {
                    PP_WARN("xsk: ARP for %s is on %s, not on configured if %s; using that neighbor MAC (确认 XDP 口与到对端的路由是否一致)",
                            want, odev, ifname);
                }
                return 0;
            }
        }
        usleep(20 * 1000);
    }
    return -1;
}

/* ifname 仅允许 alnum 与 ._-，避免经 sh -c 传 popen 时注入。 */
static int xsk_ifname_popen_safe(const char *n)
{
    if (!n || !*n) return 0;
    for (const char *p = n; *p; p++) {
        char c = *p;
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.'
            || c == '-' || c == '_')
            continue;
        return 0;
    }
    return 1;
}

/* 用 `ip route get` 得到 L3 下一跳：直连时用 dst，经网关时用 via（邻居表里是网关的 MAC）。 */
static void xsk_route_arp_target(const char *ifname, uint32_t dst_be, uint32_t *out_arp_be)
{
    *out_arp_be = dst_be;
    char dst_str[INET_ADDRSTRLEN];
    struct in_addr di = { .s_addr = dst_be };
    if (!inet_ntop(AF_INET, &di, dst_str, sizeof dst_str)) return;

    char b_oif[320] = "", b_plain[300];
    snprintf(b_plain, sizeof b_plain, "ip -4 route get %s 2>/dev/null", dst_str);
    if (ifname && ifname[0] && xsk_ifname_popen_safe(ifname))
        snprintf(b_oif, sizeof b_oif, "ip -4 route get %s oif %s 2>/dev/null", dst_str, ifname);

    const char *order[2];
    int n = 0;
    if (b_oif[0]) order[n++] = b_oif;
    order[n++] = b_plain;

    char line[512];
    for (int k = 0; k < n; k++) {
        FILE *fp = popen(order[k], "r");
        if (!fp) continue;
        if (!fgets(line, sizeof line, fp)) {
            pclose(fp);
            continue;
        }
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

static void mac_fmt_s(const uint8_t m[6], char *buf, size_t cap)
{
    snprintf(buf, cap, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
}

/* 按 L3 目的写 p->dst_mac；peer_mac_opt 仅在邻居表查不到时使用。成功得到非全 0 MAC 返回 PP_OK。 */
static int xsk_fill_dst_mac(struct pp_xsk_io *p, const char *ifname, uint32_t l3_dst_be,
                            const uint8_t *peer_mac_opt)
{
    uint32_t arp_for = l3_dst_be;
    xsk_route_arp_target(ifname, l3_dst_be, &arp_for);
    {
        char pa[INET_ADDRSTRLEN] = "", pb[INET_ADDRSTRLEN] = "";
        struct in_addr aa = { .s_addr = l3_dst_be }, ab = { .s_addr = arp_for };
        inet_ntop(AF_INET, &aa, pa, sizeof pa);
        inet_ntop(AF_INET, &ab, pb, sizeof pb);
        if (arp_for != l3_dst_be)
            PP_INFO("xsk: L3 目的 %s -> 按路由邻居/ARP 目标 %s (非直连则为网关)", pa, pb);
    }
    if (arp_nexthop_from_proc(ifname, arp_for, p->dst_mac, 2000) == 0) {
        char dm[24], ipe[INET_ADDRSTRLEN];
        struct in_addr ia = { .s_addr = arp_for };
        inet_ntop(AF_INET, &ia, ipe, sizeof ipe);
        mac_fmt_s(p->dst_mac, dm, sizeof dm);
        PP_INFO("xsk: %s dst_mac from ARP (lookup key %s) -> %s", ifname, ipe, dm);
        return PP_OK;
    }
    char ipe2[INET_ADDRSTRLEN], ipe3[INET_ADDRSTRLEN];
    struct in_addr ia2 = { .s_addr = arp_for }, ia3 = { .s_addr = l3_dst_be };
    inet_ntop(AF_INET, &ia2, ipe2, sizeof ipe2);
    inet_ntop(AF_INET, &ia3, ipe3, sizeof ipe3);
    PP_WARN("xsk: 无完整邻居项用于 ARP 键 %s (L3 对端为 %s)；需 ip(8) 解析 via，或 `ip neigh` / peer_mac",
            ipe2, ipe3);
    if (peer_mac_opt) {
        memcpy(p->dst_mac, peer_mac_opt, 6);
        char dm2[24];
        mac_fmt_s(p->dst_mac, dm2, sizeof dm2);
        PP_INFO("xsk: dst_mac fallback peer_mac=%s", dm2);
        return PP_OK;
    }
    return PP_ERR_AGAIN;
}

int pp_xsk_io_refresh_arp(struct pp_xsk_io *p, uint32_t l3_peer_be)
{
    if (!p || !l3_peer_be) return PP_ERR_INVAL;
    return xsk_fill_dst_mac(p, p->ifname, l3_peer_be, NULL);
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
                  const uint8_t peer_mac[6],
                  uint32_t arp_nexthop_be,
                  const pp_xsk_filt_t *xdp_filt)
{
    if (!out || !ifname || !ifname[0]) return PP_ERR_INVAL;
    struct pp_xsk_io *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->fd = -1;
    if (xdp_filt) p->xdp_filt = *xdp_filt;

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

    if (get_src_mac(ifname, p->src_mac) != PP_OK) {
        PP_WARN("xsk: SIOCGIFHWADDR(%s) failed, using zero src MAC", ifname);
    } else {
        char sm[24];
        mac_fmt_s(p->src_mac, sm, sizeof sm);
        PP_INFO("xsk: %s src_mac=%s", ifname, sm);
    }

    if (arp_nexthop_be) {
        if (xsk_fill_dst_mac(p, ifname, arp_nexthop_be, peer_mac) != PP_OK && !peer_mac)
            PP_INFO("xsk: %s dst_mac unset (all zero)", ifname);
    } else if (peer_mac) {
        memcpy(p->dst_mac, peer_mac, 6);
        char dm3[24];
        mac_fmt_s(p->dst_mac, dm3, sizeof dm3);
        PP_INFO("xsk: %s dst_mac from peer_mac=%s", ifname, dm3);
    } else
        PP_INFO("xsk: %s dst_mac unset (all zero, no arp_nexthop/peer_mac)", ifname);

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

    const char *xdpcap_bpf = getenv("PPROXY_XDPCAP_BPF");
    if (xdpcap_bpf && xdpcap_bpf[0] && access(xdpcap_bpf, R_OK) == 0) {
        int prc = pp_xdpcap_xsk_create(p, xdpcap_bpf, zero_copy, need_wakeup);
        if (prc != PP_OK) {
            xsk_umem__delete(p->umem);
            munmap(p->umem_area, p->umem_size);
            free(p);
            return prc;
        }
    } else {
        if (xdpcap_bpf && xdpcap_bpf[0])
            PP_WARN("PPROXY_XDPCAP_BPF=%s unreadable, using libxdp default XDP",
                    xdpcap_bpf);
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
    }

    uint32_t idx = 0;
    uint32_t got = xsk_ring_prod__reserve(&p->fq, p->rx_count, &idx);
    if (got != p->rx_count) {
        PP_ERROR("xsk: fill reserve %u got %u", p->rx_count, got);
        if (p->xdpcap_obj) pp_xdpcap_cleanup(p);
        else if (p->xsk)  xsk_socket__delete(p->xsk);
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
    if (p->xdpcap_obj) pp_xdpcap_cleanup(p);
    else if (p->xsk)  xsk_socket__delete(p->xsk);
    if (p->umem)      xsk_umem__delete(p->umem);
    if (p->umem_area) munmap(p->umem_area, p->umem_size);
    free(p);
}

int         pp_xsk_io_get_fd    (const struct pp_xsk_io *p) { return p ? p->fd : -1; }
const char *pp_xsk_io_get_ifname(const struct pp_xsk_io *p) { return p ? p->ifname : ""; }
uint32_t    pp_xsk_io_get_queue (const struct pp_xsk_io *p) { return p ? p->queue_id : 0; }

void pp_xsk_io_get_macs(const struct pp_xsk_io *p, uint8_t out_src[6], uint8_t out_dst[6])
{
    if (out_src) memset(out_src, 0, 6);
    if (out_dst) memset(out_dst, 0, 6);
    if (!p) return;
    if (out_src) memcpy(out_src, p->src_mac, 6);
    if (out_dst) memcpy(out_dst, p->dst_mac, 6);
}

int pp_xsk_ifname_first_ipv4(const char *ifname, uint32_t *out_saddr_be)
{
    if (!ifname || !ifname[0] || !out_saddr_be) return PP_ERR_INVAL;
    struct in_addr a;
    if (get_ifaddr_v4(ifname, &a) != 0) return PP_ERR_AGAIN;
    *out_saddr_be = a.s_addr;
    return PP_OK;
}

int pp_xsk_io_inject_ip(struct pp_xsk_io *p, const uint8_t *ip, size_t len)
{
    if (!p || !p->xsk) return PP_ERR_CLOSED;
    if (PP_XSK_ETH_HDR + len > p->frame_size) return PP_ERR_INVAL;

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
    memcpy(frame + PP_XSK_ETH_HDR, ip, len);

    struct xdp_desc *d = xsk_ring_prod__tx_desc(&p->tx, idx);
    d->addr = addr;
    d->len  = (uint32_t)(PP_XSK_ETH_HDR + len);
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
    if (len >= PP_XSK_ETH_HDR) {
        if (len >= PP_XSK_ETH_HDR + 4 && frame[12] == 0x81 && frame[13] == 0x00)
            off = PP_XSK_ETH_HDR + 4;
        else
            off = PP_XSK_ETH_HDR;
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
