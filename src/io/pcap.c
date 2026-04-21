/* src/io/pcap.c -- libpcap 相关 I/O
 *
 * 本文件同时承载两个角色：
 *   1) 左手侧 pp_pkt_io_ops_t 下的 PCAP 后端（目前是 stub）；
 *   2) 右手侧 tunnel 用的 "IP 注入/抽取" 薄封装 pp_pcap_io_*。
 *
 * 都只在 -Dpcap=true 时参与编译。
 */
#ifdef PP_HAVE_PCAP

#include "pcap.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>
#include "pproxy/pkt_io.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"

/* ====================================================================
 * (1) 左手侧 pp_pkt_io_ops_t 下的 PCAP 后端
 *
 * 打开 pcap_live（非阻塞），用下方 (2) 的 pp_pcap_io_* 做逐包收发。
 * rx_burst：从 pcap 抽一批 IP 帧，拷进 pp_mempool 分配的 pp_pkt_t，填 meta。
 * tx_burst：把 pp_pkt_t 的 IP 内容原样注回网卡（DLT_EN10MB 会附加以太头）。
 * ==================================================================== */

typedef struct pc_ctx {
    struct pp_pcap_io *io;
    pp_mempool_t      *pool;
    char               ifname[IFNAMSIZ];
    uint16_t           snaplen;
} pc_ctx_t;

static int pc_open(const pp_io_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->kind != PP_IO_PCAP) return PP_ERR_INVAL;
    if (!cfg->pool) {
        PP_ERROR("pcap: mempool required for rx");
        return PP_ERR_INVAL;
    }
    pc_ctx_t *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->pool    = cfg->pool;
    c->snaplen = cfg->u.pcap.snaplen ? cfg->u.pcap.snaplen : 2048;

    int rc = pp_pcap_io_new(&c->io,
                            cfg->u.pcap.ifname,
                            cfg->u.pcap.has_peer_mac ? cfg->u.pcap.peer_mac : NULL,
                            cfg->u.pcap.bpf,
                            c->snaplen);
    if (rc != PP_OK) { free(c); return rc; }

    snprintf(c->ifname, sizeof c->ifname, "%s",
             pp_pcap_io_get_ifname(c->io));
    *out_ctx = c;
    return PP_OK;
}

static void pc_close(void *ctx)
{
    if (!ctx) return;
    pc_ctx_t *c = ctx;
    if (c->io) pp_pcap_io_free(c->io);
    free(c);
}

static int pc_rx(void *ctx, pp_pkt_t **pkts, int max, int timeout_us)
{
    (void)timeout_us;
    pc_ctx_t *c = ctx;
    int got = 0;
    for (int i = 0; i < max; i++) {
        size_t n = 0;
        const uint8_t *ip = pp_pcap_io_next_ip(c->io, &n);
        if (!ip) break;

        pp_pkt_t *p = pp_mempool_alloc(c->pool);
        if (!p) break;
        if (n > p->tailroom) {
            pp_pkt_put_ref(p);
            continue;               /* 截断掉的包，安全起见丢弃 */
        }
        memcpy(p->data, ip, n);
        p->data_len = (uint16_t)n;
        p->tailroom -= (uint16_t)n;
        p->origin   = PP_PKT_FROM_PCAP;
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

static int pc_tx(void *ctx, pp_pkt_t **pkts, int n)
{
    pc_ctx_t *c = ctx;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        pp_pkt_t *p = pkts[i];
        int w = pp_pcap_io_inject_ip(c->io, p->data, p->data_len);
        if (w < 0) break;
        sent++;
    }
    return sent;
}

static int pc_fd(void *ctx)
{
    pc_ctx_t *c = ctx;
    return c && c->io ? pp_pcap_io_get_fd(c->io) : -1;
}

static int pc_stat(void *ctx, char *json, size_t cap)
{
    pc_ctx_t *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"pcap\",\"if\":\"%s\",\"fd\":%d,\"snaplen\":%u}",
        c->ifname, c->io ? pp_pcap_io_get_fd(c->io) : -1, c->snaplen);
}

const pp_pkt_io_ops_t pp_io_pcap = {
    .name      = "pcap",
    .kind      = PP_IO_PCAP,
    .caps      = PP_IO_CAP_L2 | PP_IO_CAP_BATCH,
    .open      = pc_open,
    .close     = pc_close,
    .rx_burst  = pc_rx,
    .tx_burst  = pc_tx,
    .get_rx_fd = pc_fd,
    .get_tx_fd = pc_fd,
    .stat      = pc_stat,
};

/* ====================================================================
 * (2) 右手侧 pp_pcap_io_* —— 供 tunnel/udp.c / tunnel/icmp.c 使用
 * ==================================================================== */
struct pp_pcap_io {
    pcap_t   *pc;
    int       fd;
    int       datalink;
    char      ifname[IFNAMSIZ];
    uint8_t   src_mac[6];
    uint8_t   dst_mac[6];
};

int pp_pcap_io_new(struct pp_pcap_io **out,
                   const char *ifname,
                   const uint8_t peer_mac[6],
                   const char *bpf,
                   uint32_t snaplen)
{
    if (!out || !ifname || !ifname[0]) return PP_ERR_INVAL;
    struct pp_pcap_io *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->fd = -1;

    char errbuf[PCAP_ERRBUF_SIZE] = "";
    uint32_t snap = snaplen ? snaplen : 65535;
    p->pc = pcap_open_live(ifname, (int)snap, 1 /* promisc */,
                           1 /* to_ms */, errbuf);
    if (!p->pc) {
        PP_ERROR("pcap_open_live(%s): %s", ifname, errbuf);
        free(p);
        return PP_ERR_IO;
    }
    if (pcap_setnonblock(p->pc, 1, errbuf) < 0) {
        PP_ERROR("pcap_setnonblock: %s", errbuf);
        pcap_close(p->pc); free(p);
        return PP_ERR_IO;
    }
    p->fd       = pcap_get_selectable_fd(p->pc);
    p->datalink = pcap_datalink(p->pc);
    snprintf(p->ifname, sizeof p->ifname, "%s", ifname);

    if (p->datalink != DLT_EN10MB &&
        p->datalink != DLT_RAW &&
        p->datalink != DLT_NULL &&
        p->datalink != DLT_LINUX_SLL) {
        PP_ERROR("pcap: datalink=%d (%s) not supported, need EN10MB / RAW / NULL / LINUX_SLL",
                 p->datalink, pcap_datalink_val_to_name(p->datalink));
        pcap_close(p->pc); free(p);
        return PP_ERR_NOSUPPORT;
    }

    if (p->datalink == DLT_EN10MB) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s >= 0) {
            struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
            snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
            if (ioctl(s, SIOCGIFHWADDR, &ifr) == 0)
                memcpy(p->src_mac, ifr.ifr_hwaddr.sa_data, 6);
            close(s);
        }
    }
    if (peer_mac) memcpy(p->dst_mac, peer_mac, 6);

    if (bpf && bpf[0]) {
        struct bpf_program prog;
        if (pcap_compile(p->pc, &prog, bpf, 1, PCAP_NETMASK_UNKNOWN) < 0) {
            PP_ERROR("pcap_compile('%s'): %s", bpf, pcap_geterr(p->pc));
            pcap_close(p->pc); free(p);
            return PP_ERR_INVAL;
        }
        if (pcap_setfilter(p->pc, &prog) < 0) {
            PP_ERROR("pcap_setfilter: %s", pcap_geterr(p->pc));
            pcap_freecode(&prog);
            pcap_close(p->pc); free(p);
            return PP_ERR_INVAL;
        }
        pcap_freecode(&prog);
    }

    PP_INFO("pcap: opened %s (dlt=%s, fd=%d, bpf='%s')",
            p->ifname, pcap_datalink_val_to_name(p->datalink),
            p->fd, bpf ? bpf : "");
    *out = p;
    return PP_OK;
}

void pp_pcap_io_free(struct pp_pcap_io *p)
{
    if (!p) return;
    if (p->pc) pcap_close(p->pc);
    free(p);
}

int         pp_pcap_io_get_fd    (const struct pp_pcap_io *p) { return p ? p->fd : -1; }
const char *pp_pcap_io_get_ifname(const struct pp_pcap_io *p) { return p ? p->ifname : ""; }

int pp_pcap_io_inject_ip(struct pp_pcap_io *p, const uint8_t *ip, size_t len)
{
    if (!p || !p->pc) return PP_ERR_CLOSED;
    uint8_t buf[65535 + 16];
    const uint8_t *out = ip;
    size_t out_len = len;

    switch (p->datalink) {
    case DLT_EN10MB: {
        if (14 + len > sizeof buf) return PP_ERR_INVAL;
        memcpy(buf,     p->dst_mac, 6);
        memcpy(buf + 6, p->src_mac, 6);
        buf[12] = 0x08; buf[13] = 0x00;       /* ethertype IPv4 */
        memcpy(buf + 14, ip, len);
        out = buf; out_len = 14 + len;
        break;
    }
    case DLT_NULL: {
        if (4 + len > sizeof buf) return PP_ERR_INVAL;
        uint32_t fam = 2;
        memcpy(buf, &fam, 4);
        memcpy(buf + 4, ip, len);
        out = buf; out_len = 4 + len;
        break;
    }
    case DLT_RAW:
    default:
        break;
    }

    if (pcap_inject(p->pc, out, (int)out_len) < 0) {
        PP_WARN("pcap_inject: %s", pcap_geterr(p->pc));
        return PP_ERR_IO;
    }
    return (int)len;
}

const uint8_t *pp_pcap_io_next_ip(struct pp_pcap_io *p, size_t *out_len)
{
    if (!p || !p->pc) return NULL;
    struct pcap_pkthdr *hdr = NULL;
    const u_char *data = NULL;
    int r = pcap_next_ex(p->pc, &hdr, &data);
    if (r != 1) return NULL;

    size_t off = 0;
    switch (p->datalink) {
    case DLT_EN10MB:
        if (hdr->caplen < 14) return NULL;
        if (hdr->caplen >= 18 && data[12] == 0x81 && data[13] == 0x00)
            off = 18;
        else
            off = 14;
        break;
    case DLT_NULL:
        if (hdr->caplen < 4) return NULL;
        off = 4;
        break;
    case DLT_LINUX_SLL:
        if (hdr->caplen < 16) return NULL;
        off = 16;
        break;
    case DLT_RAW:
        off = 0;
        break;
    default:
        return NULL;
    }
    if (hdr->caplen <= off) return NULL;
    *out_len = hdr->caplen - off;
    return data + off;
}

#endif /* PP_HAVE_PCAP */
