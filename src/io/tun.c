/* src/io/tun.c -- Linux TUN 后端 + 右手侧薄封装
 *
 * 一、右手侧（tunnel/udp、tunnel/icmp 复用）：pp_tun_io_open/read_ip/write_ip
 *    逐包 read/write IP 帧，不依赖 pp_mempool / pp_pkt_t。
 *
 * 二、左手侧（pp_pkt_io_ops_t vtable，名为 pp_io_tun）：
 *    IFF_TUN | IFF_NO_PI（可选）设备；rx_burst/tx_burst 批量走 read/write；
 *    包是 L3（IP）起始，没有以太头。内部复用本文件的 pp_tun_io_* 打开设备。
 */
#include "tun.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>

#include "pproxy/log.h"
#include "pproxy/pkt_io.h"

/* =============================================================
 * 右手侧：/dev/net/tun 薄封装
 * ============================================================= */

int pp_tun_io_open(const char *ifname, bool no_pi,
                   char out_ifname[IFNAMSIZ], int *out_fd)
{
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
        PP_ERROR("tun: open(/dev/net/tun): %s", strerror(errno));
        return PP_ERR_IO;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | (no_pi ? IFF_NO_PI : 0);
    if (ifname && ifname[0])
        snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "%s", ifname);
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        PP_ERROR("tun: TUNSETIFF(%s): %s",
                 (ifname && ifname[0]) ? ifname : "<auto>", strerror(errno));
        close(fd);
        return PP_ERR_IO;
    }
    if (out_ifname) snprintf(out_ifname, IFNAMSIZ, "%s", ifr.ifr_name);
    *out_fd = fd;
    return PP_OK;
}

int pp_tun_io_write_ip(int fd, const uint8_t *ip, size_t len)
{
    ssize_t w = write(fd, ip, len);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return PP_ERR_AGAIN;
        return PP_ERR_IO;
    }
    return (int)w;
}

int pp_tun_io_read_ip(int fd, uint8_t *buf, size_t cap)
{
    ssize_t n = read(fd, buf, cap);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return PP_ERR_IO;
    }
    return (int)n;
}

/* =============================================================
 * 左手侧：pp_pkt_io_ops_t vtable（pp_io_tun）
 * ============================================================= */

struct tun_ctx {
    int           fd;
    pp_mempool_t *pool;
    char          ifname[IFNAMSIZ];
    uint16_t      mtu;
};

static int tun_open(const pp_io_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->kind != PP_IO_TUN) return PP_ERR_INVAL;
    struct tun_ctx *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->pool = cfg->pool;
    c->mtu  = cfg->u.tun.mtu ? cfg->u.tun.mtu : 1500;

    int rc = pp_tun_io_open(cfg->u.tun.ifname, cfg->u.tun.no_pi,
                            c->ifname, &c->fd);
    if (rc != PP_OK) { free(c); return rc; }

    PP_INFO("tun: opened %s (fd=%d, mtu=%u)", c->ifname, c->fd, c->mtu);
    *out_ctx = c;
    return PP_OK;
}

static void tun_close(void *ctx)
{
    if (!ctx) return;
    struct tun_ctx *c = ctx;
    if (c->fd >= 0) close(c->fd);
    free(c);
}

static int tun_rx_burst(void *ctx, pp_pkt_t **pkts, int max, int timeout_us)
{
    (void)timeout_us;
    struct tun_ctx *c = ctx;
    int got = 0;
    for (int i = 0; i < max; i++) {
        pp_pkt_t *p = pp_mempool_alloc(c->pool);
        if (!p) break;
        int n = pp_tun_io_read_ip(c->fd, p->data, p->tailroom);
        if (n <= 0) {
            pp_pkt_put_ref(p);
            if (n < 0) PP_WARN("tun read: io error");
            break;
        }
        p->data_len  = (uint16_t)n;
        p->tailroom -= (uint16_t)n;
        p->origin    = PP_PKT_FROM_TUN;
        p->meta.l3_off   = 0;
        p->meta.l3_proto = IPPROTO_IP;
        if (p->data_len >= sizeof(struct iphdr)) {
            const struct iphdr *ih = (const struct iphdr *)p->data;
            p->meta.l4_proto = ih->protocol;
            p->meta.l4_off   = (uint16_t)(ih->ihl * 4);
        }
        p->meta.rx_ns = pp_now_ns();
        pkts[got++] = p;
    }
    return got;
}

static int tun_tx_burst(void *ctx, pp_pkt_t **pkts, int n)
{
    struct tun_ctx *c = ctx;
    int sent = 0;
    for (int i = 0; i < n; i++) {
        pp_pkt_t *p = pkts[i];
        int w = pp_tun_io_write_ip(c->fd, p->data, p->data_len);
        if (w == PP_ERR_AGAIN) break;
        if (w < 0) { PP_WARN("tun write: io error"); break; }
        sent++;
    }
    return sent;
}

static int tun_get_fd(void *ctx) { return ((struct tun_ctx *)ctx)->fd; }

static int tun_stat(void *ctx, char *json, size_t cap)
{
    struct tun_ctx *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"tun\",\"if\":\"%s\",\"fd\":%d,\"mtu\":%u}",
        c->ifname, c->fd, c->mtu);
}

const pp_pkt_io_ops_t pp_io_tun = {
    .name      = "tun",
    .kind      = PP_IO_TUN,
    .caps      = PP_IO_CAP_L3 | PP_IO_CAP_BATCH,
    .open      = tun_open,
    .close     = tun_close,
    .rx_burst  = tun_rx_burst,
    .tx_burst  = tun_tx_burst,
    .get_rx_fd = tun_get_fd,
    .get_tx_fd = tun_get_fd,
    .stat      = tun_stat,
};
