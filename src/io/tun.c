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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/wait.h>
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

/* left.tun.cidr：ip link up + ip route（不配地址），把 prefix 导向本 TUN。 */
static int tun_ifname_ok(const char *s)
{
    if (!s || !s[0]) return 0;
    size_t n = strnlen(s, IFNAMSIZ);
    if (n == 0 || n >= IFNAMSIZ) return 0;
    for (size_t i = 0; i < n; i++) {
        if (!isalnum((unsigned char)s[i]) && s[i] != '-' && s[i] != '_' && s[i] != '.')
            return 0;
    }
    return 1;
}

static int parse_ipv4_cidr(const char *s,
                           unsigned *a, unsigned *b, unsigned *c, unsigned *d, unsigned *p)
{
    if (!s || !*s) return PP_ERR_INVAL;
    if (sscanf(s, "%u.%u.%u.%u / %u", a, b, c, d, p) != 5) {
        if (sscanf(s, "%u.%u.%u.%u/%u", a, b, c, d, p) != 5) return PP_ERR_INVAL;
    }
    if (*a > 255u || *b > 255u || *c > 255u || *d > 255u || *p > 32u) return PP_ERR_INVAL;
    if (*p == 0) return PP_ERR_INVAL;
    return PP_OK;
}

static int run_ip(char *const argv[])
{
    pid_t pid = fork();
    if (pid < 0) {
        PP_ERROR("tun: fork: %s", strerror(errno));
        return PP_ERR_IO;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    int st = 0;
    if (waitpid(pid, &st, 0) < 0) {
        PP_ERROR("tun: waitpid: %s", strerror(errno));
        return PP_ERR_IO;
    }
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return PP_ERR_IO;
    return PP_OK;
}

/* 内核里是否已有 prefix 经 ifname 的 on-link 路由（用于 add 报 File exists 时视为成功） */
static int tun_route_present(const char *route_s, const char *ifb)
{
    char cmd[160];
    snprintf(cmd, sizeof cmd, "ip -4 route show to %s 2>/dev/null", route_s);
    FILE *f = popen(cmd, "r");
    if (!f) return 0;
    char line[256];
    int ok = 0;
    while (fgets(line, sizeof line, f)) {
        /* 例: 192.168.1.0/24 dev ppclab1 scope link */
        if (strstr(line, ifb) && strstr(line, "dev")) {
            ok = 1;
            break;
        }
    }
    pclose(f);
    return ok;
}

/* 根据 a.b.c.d/p 得到网段，仅 ip route，不配本机地址。 */
static int tun_apply_cidr(const char *ifname, const char *cidr)
{
    if (!cidr || !cidr[0]) return PP_OK;
    if (!tun_ifname_ok(ifname)) {
        PP_ERROR("tun: invalid ifname for cidr");
        return PP_ERR_INVAL;
    }
    unsigned a, b, c, d, p;
    if (parse_ipv4_cidr(cidr, &a, &b, &c, &d, &p) != PP_OK) {
        PP_ERROR("tun: left.tun.cidr must be IPv4 a.b.c.d/len, got '%s'", cidr);
        return PP_ERR_INVAL;
    }
    uint32_t host = ((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | (uint32_t)d;
    uint32_t mask = (p >= 32u) ? UINT32_MAX : (UINT32_MAX << (32u - p));
    uint32_t net  = host & mask;
    unsigned na = (unsigned)((net >> 24) & 0xffu);
    unsigned nb = (unsigned)((net >> 16) & 0xffu);
    unsigned nc = (unsigned)((net >> 8) & 0xffu);
    unsigned nd = (unsigned)(net & 0xffu);
    char route_s[40];
    snprintf(route_s, sizeof route_s, "%u.%u.%u.%u/%u", na, nb, nc, nd, p);

    {
        char ifb[IFNAMSIZ];
        snprintf(ifb, sizeof ifb, "%s", ifname);
        char *argv1[] = { "ip", "link", "set", "dev", ifb, "up", NULL };
        if (run_ip(argv1) != PP_OK) {
            PP_ERROR("tun: `ip link set dev %s up` failed (need `ip` in PATH, root?)", ifb);
            return PP_ERR_IO;
        }
    }
    {
        char ifb[IFNAMSIZ];
        snprintf(ifb, sizeof ifb, "%s", ifname);
        char rts[40];
        snprintf(rts, sizeof rts, "%s", route_s);
        /* replace 可覆盖经 GW 的旧路由；已存在且 dev 正确时 add 会报 EEXIST，下面兜底 */
        char *try_rep[]  = { "ip", "route", "replace", rts, "dev", ifb, NULL };
        char *try_add[]  = { "ip", "route", "add", rts, "dev", ifb, NULL };
        if (run_ip(try_rep) == PP_OK) {
            PP_INFO("tun: `ip route replace` %s dev %s", rts, ifb);
            return PP_OK;
        }
        if (run_ip(try_add) == PP_OK) {
            PP_INFO("tun: `ip route add` %s dev %s", rts, ifb);
            return PP_OK;
        }
        if (tun_route_present(rts, ifb)) {
            PP_INFO("tun: route %s already via dev %s (ok)", rts, ifb);
            return PP_OK;
        }
        PP_ERROR("tun: `ip route` %s dev %s failed", rts, ifb);
        return PP_ERR_IO;
    }
}

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

    if (cfg->u.tun.cidr && cfg->u.tun.cidr[0]) {
        rc = tun_apply_cidr(c->ifname, cfg->u.tun.cidr);
        if (rc != PP_OK) {
            close(c->fd);
            free(c);
            return rc;
        }
    }

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
