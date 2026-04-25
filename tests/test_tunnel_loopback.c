/* tests/test_tunnel_loopback.c
 *
 * 同进程内起 TCP/UDP server-mode ctx + client-mode ctx，通过 127.0.0.1 互传一帧，
 * 验证 server_try_accept / peer-learning / 帧格式读写。
 *
 * 不走 main 的 left-I/O、ring、worker 链路；纯 ops 级 loopback。
 */
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <time.h>
#include <unistd.h>
#include "pproxy/tunnel.h"
#include "pproxy/log.h"

#define PORT_TCP     29301
#define PORT_UDP     29302
#define PORT_UDP_RAW_S 29303   /* server 端 */
#define PORT_UDP_RAW_C 29304   /* client 端 */
#define PORT_UDP_PCAP_S 29305
#define PORT_UDP_PCAP_C 29306

static int ep(pp_endpoint_t *out, const char *host, uint16_t port)
{
    char s[64]; snprintf(s, sizeof s, "%s:%u", host, port);
    return pp_endpoint_parse(s, out);
}

/* 等 cond 为 true，每 poll_ms 轮询一次，最多 timeout_ms */
#define WAIT_FOR(cond, timeout_ms, poll_ms) do {                               \
    int _waited = 0;                                                           \
    while (!(cond) && _waited < (timeout_ms)) {                                \
        struct timespec _ts = {0, (long)(poll_ms) * 1000000};                  \
        nanosleep(&_ts, NULL);                                                 \
        _waited += (poll_ms);                                                  \
    }                                                                          \
} while (0)

static int test_tcp(void)
{
    printf("=== TCP loopback (server↔client) ===\n");
    pp_tunnel_cfg_t scfg = {0}, ccfg = {0};
    scfg.proto = PP_PROTO_TCP; scfg.io = PP_TIO_KERNEL_SOCKET;
    scfg.mode  = PP_TMODE_SERVER;
    scfg.u.tcp.nodelay = true;
    if (ep(&scfg.listen, "127.0.0.1", PORT_TCP) != PP_OK) { printf("ep listen fail\n"); return 1; }

    ccfg = scfg; ccfg.mode = PP_TMODE_CLIENT;
    if (ep(&ccfg.server, "127.0.0.1", PORT_TCP) != PP_OK) { printf("ep server fail\n"); return 1; }

    void *sctx = NULL, *cctx = NULL;
    if (pp_tunnel_tcp.open(&scfg, &sctx) != PP_OK) { printf("server open fail\n"); return 1; }
    if (pp_tunnel_tcp.connect(sctx) != PP_OK)      { printf("server listen fail\n"); return 1; }

    /* 给 server 一点时间进入 listen 再 connect */
    struct timespec ts = {0, 50 * 1000 * 1000}; nanosleep(&ts, NULL);

    if (pp_tunnel_tcp.open(&ccfg, &cctx) != PP_OK) { printf("client open fail\n"); return 1; }
    if (pp_tunnel_tcp.connect(cctx) != PP_OK)      { printf("client connect fail\n"); return 1; }

    /* client -> server: send 一帧 */
    const char *msg_c2s = "hello-from-client";
    pp_tun_buf_t buf = { .data = (const uint8_t *)msg_c2s, .len = strlen(msg_c2s) };
    int w = pp_tunnel_tcp.send(cctx, &buf);
    if (w <= 0) { printf("client send fail (%d)\n", w); return 1; }
    printf("  client -> server: sent %zu bytes\n", buf.len);

    /* server 接收；第一次 recv 会触发 accept */
    uint8_t rx[256]; pp_tun_mbuf_t mb = { .data = rx, .cap = sizeof rx };
    int r = 0;
    for (int i = 0; i < 100 && r == 0; i++) {
        r = pp_tunnel_tcp.recv(sctx, &mb, 0);
        if (r == 0) { struct timespec t = {0, 10 * 1000 * 1000}; nanosleep(&t, NULL); }
    }
    if (r <= 0 || mb.len != strlen(msg_c2s) || memcmp(mb.data, msg_c2s, mb.len) != 0) {
        printf("  server recv mismatch (r=%d len=%zu)\n", r, mb.len);
        return 1;
    }
    printf("  server recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    /* server -> client */
    const char *msg_s2c = "reply-from-server";
    buf.data = (const uint8_t *)msg_s2c; buf.len = strlen(msg_s2c);
    w = pp_tunnel_tcp.send(sctx, &buf);
    if (w <= 0) { printf("server send fail (%d)\n", w); return 1; }

    mb.len = 0;
    r = 0;
    for (int i = 0; i < 100 && r == 0; i++) {
        r = pp_tunnel_tcp.recv(cctx, &mb, 0);
        if (r == 0) { struct timespec t = {0, 10 * 1000 * 1000}; nanosleep(&t, NULL); }
    }
    if (r <= 0 || memcmp(mb.data, msg_s2c, mb.len) != 0) {
        printf("  client recv mismatch (r=%d)\n", r); return 1;
    }
    printf("  client recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    pp_tunnel_tcp.close(cctx);
    pp_tunnel_tcp.close(sctx);
    printf("=== TCP OK ===\n\n");
    return 0;
}

static int test_udp(void)
{
    printf("=== UDP loopback (server↔client) ===\n");
    pp_tunnel_cfg_t scfg = {0}, ccfg = {0};
    scfg.proto = PP_PROTO_UDP; scfg.io = PP_TIO_KERNEL_SOCKET;
    scfg.mode  = PP_TMODE_SERVER;
    if (ep(&scfg.listen, "127.0.0.1", PORT_UDP) != PP_OK) return 1;

    ccfg = scfg; ccfg.mode = PP_TMODE_CLIENT;
    if (ep(&ccfg.server, "127.0.0.1", PORT_UDP) != PP_OK) return 1;

    void *sctx = NULL, *cctx = NULL;
    if (pp_tunnel_udp.open(&scfg, &sctx) != PP_OK) return 1;
    if (pp_tunnel_udp.connect(sctx)     != PP_OK) return 1;
    if (pp_tunnel_udp.open(&ccfg, &cctx) != PP_OK) return 1;
    if (pp_tunnel_udp.connect(cctx)     != PP_OK) return 1;

    const char *msg = "ping-udp";
    pp_tun_buf_t buf = { .data = (const uint8_t *)msg, .len = strlen(msg) };
    if (pp_tunnel_udp.send(cctx, &buf) <= 0) return 1;

    uint8_t rx[256]; pp_tun_mbuf_t mb = { .data = rx, .cap = sizeof rx };
    int r = pp_tunnel_udp.recv(sctx, &mb, 500000);
    if (r <= 0 || mb.len != strlen(msg) || memcmp(mb.data, msg, mb.len) != 0) {
        printf("server recv fail (r=%d len=%zu)\n", r, mb.len);
        return 1;
    }
    printf("  server recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    /* server 回包，peer 应在上条 recv 时已学到 */
    const char *rep = "pong-udp";
    buf.data = (const uint8_t *)rep; buf.len = strlen(rep);
    if (pp_tunnel_udp.send(sctx, &buf) <= 0) return 1;

    mb.len = 0;
    r = pp_tunnel_udp.recv(cctx, &mb, 500000);
    if (r <= 0 || mb.len != strlen(rep) || memcmp(mb.data, rep, mb.len) != 0) {
        printf("client recv fail\n");
        return 1;
    }
    printf("  client recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    pp_tunnel_udp.close(cctx);
    pp_tunnel_udp.close(sctx);
    printf("=== UDP OK ===\n\n");
    return 0;
}

/* 检查本进程是否能创建 SOCK_RAW IPPROTO_UDP — 无 CAP_NET_RAW 时会 EPERM */
static int can_raw_udp(void)
{
    int fd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    if (fd < 0) return 0;
    close(fd);
    return 1;
}

/* 检查本进程是否能开 /dev/net/tun 并 TUNSETIFF（需 CAP_NET_ADMIN） */
static int can_tun(void)
{
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) return 0;
    struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, sizeof ifr.ifr_name, "pp-test-cap%d", getpid() & 0xffff);
    int ok = (ioctl(fd, TUNSETIFF, &ifr) == 0);
    close(fd);
    return ok;
}

static int test_udp_raw(void)
{
    printf("=== UDP loopback, io=raw_socket ===\n");
    pp_tunnel_cfg_t scfg = {0}, ccfg = {0};

    /* server：listen 127.0.0.1:PORT_UDP_RAW_S */
    scfg.proto = PP_PROTO_UDP; scfg.io = PP_TIO_RAW_SOCKET;
    scfg.mode  = PP_TMODE_SERVER;
    if (ep(&scfg.listen, "127.0.0.1", PORT_UDP_RAW_S) != PP_OK) return 1;

    /* client：server=127.0.0.1:PORT_UDP_RAW_S，listen 作为本地源绑定 */
    ccfg.proto = PP_PROTO_UDP; ccfg.io = PP_TIO_RAW_SOCKET;
    ccfg.mode  = PP_TMODE_CLIENT;
    if (ep(&ccfg.server, "127.0.0.1", PORT_UDP_RAW_S) != PP_OK) return 1;
    if (ep(&ccfg.listen, "127.0.0.1", PORT_UDP_RAW_C) != PP_OK) return 1;

    void *sctx = NULL, *cctx = NULL;
    if (pp_tunnel_udp.open(&scfg, &sctx) != PP_OK) { printf("  server open fail\n"); return 1; }
    if (pp_tunnel_udp.connect(sctx)      != PP_OK) { printf("  server connect fail\n"); return 1; }
    if (pp_tunnel_udp.open(&ccfg, &cctx) != PP_OK) { printf("  client open fail\n"); return 1; }
    if (pp_tunnel_udp.connect(cctx)      != PP_OK) { printf("  client connect fail\n"); return 1; }

    /* client -> server */
    const char *msg = "ping-udp-raw";
    pp_tun_buf_t buf = { .data = (const uint8_t *)msg, .len = strlen(msg) };
    int w = pp_tunnel_udp.send(cctx, &buf);
    if (w <= 0) { printf("  client send fail (%d)\n", w); return 1; }

    uint8_t rx[512]; pp_tun_mbuf_t mb = { .data = rx, .cap = sizeof rx };
    int r = 0;
    for (int i = 0; i < 100 && r == 0; i++) {
        r = pp_tunnel_udp.recv(sctx, &mb, 10 * 1000);   /* 10ms */
    }
    if (r <= 0 || mb.len != strlen(msg) || memcmp(mb.data, msg, mb.len) != 0) {
        printf("  server recv mismatch (r=%d len=%zu)\n", r, mb.len);
        pp_tunnel_udp.close(cctx); pp_tunnel_udp.close(sctx);
        return 1;
    }
    printf("  server recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    /* server -> client */
    const char *rep = "pong-udp-raw";
    buf.data = (const uint8_t *)rep; buf.len = strlen(rep);
    w = pp_tunnel_udp.send(sctx, &buf);
    if (w <= 0) { printf("  server send fail (%d)\n", w); return 1; }

    mb.len = 0;
    r = 0;
    for (int i = 0; i < 100 && r == 0; i++) {
        r = pp_tunnel_udp.recv(cctx, &mb, 10 * 1000);
    }
    if (r <= 0 || mb.len != strlen(rep) || memcmp(mb.data, rep, mb.len) != 0) {
        printf("  client recv mismatch (r=%d)\n", r);
        pp_tunnel_udp.close(cctx); pp_tunnel_udp.close(sctx);
        return 1;
    }
    printf("  client recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    pp_tunnel_udp.close(cctx);
    pp_tunnel_udp.close(sctx);
    printf("=== UDP raw_socket OK ===\n\n");
    return 0;
}

/* TUN 冒烟：open+connect+close，验证帧构造路径能启动。
 * 端到端收发要靠复杂路由/netns，这里不做。 */
static int smoke_udp_tun(void)
{
    printf("=== UDP tun smoke (open/connect/close) ===\n");
    pp_tunnel_cfg_t cfg = {0};
    cfg.proto = PP_PROTO_UDP; cfg.io = PP_TIO_TUN;
    cfg.mode  = PP_TMODE_SERVER;
    cfg.io_cfg.tun.ifname = "pp-test-utun";
    if (ep(&cfg.listen, "10.99.0.1", 4790) != PP_OK) return 1;

    void *ctx = NULL;
    if (pp_tunnel_udp.open(&cfg, &ctx) != PP_OK) { printf("  open fail\n"); return 1; }
    if (pp_tunnel_udp.connect(ctx)     != PP_OK) { printf("  connect fail\n"); return 1; }
    pp_tunnel_udp.close(ctx);
    printf("=== UDP tun smoke OK ===\n\n");
    return 0;
}

static int smoke_icmp_tun(void)
{
    printf("=== ICMP tun smoke (open/connect/close) ===\n");
    pp_tunnel_cfg_t cfg = {0};
    cfg.proto = PP_PROTO_ICMP; cfg.io = PP_TIO_TUN;
    cfg.mode  = PP_TMODE_CLIENT;
    cfg.io_cfg.tun.ifname = "pp-test-itun";
    /* port 在 ICMP 上可写 :1 等占位；:0 亦合法（见 endpoint 解析） */
    if (ep(&cfg.server, "10.99.0.2", 1) != PP_OK) return 1;

    void *ctx = NULL;
    if (pp_tunnel_icmp.open(&cfg, &ctx) != PP_OK) { printf("  open fail\n"); return 1; }
    if (pp_tunnel_icmp.connect(ctx)     != PP_OK) { printf("  connect fail\n"); return 1; }
    pp_tunnel_icmp.close(ctx);
    printf("=== ICMP tun smoke OK ===\n\n");
    return 0;
}

#ifdef PP_HAVE_PCAP
/* pcap 回环：两端都用 io=pcap 绑 lo，BPF 自动合成，互相 inject + capture */
static int test_udp_pcap(void)
{
    printf("=== UDP loopback, io=pcap (iface=lo) ===\n");
    pp_tunnel_cfg_t scfg = {0}, ccfg = {0};

    scfg.proto = PP_PROTO_UDP; scfg.io = PP_TIO_PCAP;
    scfg.mode  = PP_TMODE_SERVER;
    scfg.io_cfg.pcap.ifname  = "lo";
    scfg.io_cfg.pcap.snaplen = 2048;
    if (ep(&scfg.listen, "127.0.0.1", PORT_UDP_PCAP_S) != PP_OK) return 1;

    ccfg.proto = PP_PROTO_UDP; ccfg.io = PP_TIO_PCAP;
    ccfg.mode  = PP_TMODE_CLIENT;
    ccfg.io_cfg.pcap.ifname  = "lo";
    ccfg.io_cfg.pcap.snaplen = 2048;
    if (ep(&ccfg.server, "127.0.0.1", PORT_UDP_PCAP_S) != PP_OK) return 1;
    if (ep(&ccfg.listen, "127.0.0.1", PORT_UDP_PCAP_C) != PP_OK) return 1;

    void *sctx=NULL, *cctx=NULL;
    if (pp_tunnel_udp.open(&scfg, &sctx) != PP_OK) { printf("  server open fail\n"); return 1; }
    if (pp_tunnel_udp.connect(sctx)      != PP_OK) { printf("  server connect fail\n"); return 1; }
    if (pp_tunnel_udp.open(&ccfg, &cctx) != PP_OK) { printf("  client open fail\n"); return 1; }
    if (pp_tunnel_udp.connect(cctx)      != PP_OK) { printf("  client connect fail\n"); return 1; }

    const char *msg = "ping-udp-pcap";
    pp_tun_buf_t buf = { .data = (const uint8_t *)msg, .len = strlen(msg) };
    if (pp_tunnel_udp.send(cctx, &buf) <= 0) {
        printf("  client send fail\n"); goto fail;
    }

    uint8_t rx[512]; pp_tun_mbuf_t mb = { .data = rx, .cap = sizeof rx };
    int r = 0;
    for (int i = 0; i < 200 && r == 0; i++)
        r = pp_tunnel_udp.recv(sctx, &mb, 10 * 1000);
    if (r <= 0 || mb.len != strlen(msg) || memcmp(mb.data, msg, mb.len) != 0) {
        printf("  server recv mismatch (r=%d len=%zu)\n", r, mb.len);
        goto fail;
    }
    printf("  server recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    const char *rep = "pong-udp-pcap";
    buf.data = (const uint8_t *)rep; buf.len = strlen(rep);
    if (pp_tunnel_udp.send(sctx, &buf) <= 0) {
        printf("  server send fail\n"); goto fail;
    }
    mb.len = 0; r = 0;
    for (int i = 0; i < 200 && r == 0; i++)
        r = pp_tunnel_udp.recv(cctx, &mb, 10 * 1000);
    if (r <= 0 || mb.len != strlen(rep) || memcmp(mb.data, rep, mb.len) != 0) {
        printf("  client recv mismatch (r=%d)\n", r);
        goto fail;
    }
    printf("  client recv: bytes=%zu '%.*s' OK\n",
           mb.len, (int)mb.len, (const char *)mb.data);

    pp_tunnel_udp.close(cctx); pp_tunnel_udp.close(sctx);
    printf("=== UDP pcap OK ===\n\n");
    return 0;
fail:
    pp_tunnel_udp.close(cctx); pp_tunnel_udp.close(sctx);
    return 1;
}
#endif  /* PP_HAVE_PCAP */

#ifdef PP_HAVE_XDP
/* af_xdp 冒烟：验证 udp_open/udp_close 的 af_xdp 分发路径
 *
 * 不要求 open 成功——在 loopback / 无 CAP_NET_ADMIN 的环境里它必然失败
 * （libxdp 需要 CAP_NET_ADMIN+CAP_BPF 加载 redirect 程序，且 lo 不支持 XDP）。
 * 我们要确认的是：接线没崩；非 OK 时能优雅返回；open/close 路径都被走到。
 */
static int smoke_udp_xdp(void)
{
    printf("=== UDP af_xdp smoke (open/connect/close on lo) ===\n");
    pp_tunnel_cfg_t cfg = {0};
    cfg.proto = PP_PROTO_UDP; cfg.io = PP_TIO_AF_XDP;
    cfg.mode  = PP_TMODE_CLIENT;
    cfg.io_cfg.xdp.ifname      = "lo";
    cfg.io_cfg.xdp.queue_id    = 0;
    cfg.io_cfg.xdp.nframes     = 256;
    cfg.io_cfg.xdp.zero_copy   = false;
    cfg.io_cfg.xdp.need_wakeup = true;
    if (ep(&cfg.server, "127.0.0.1", 29400) != PP_OK) return 1;
    if (ep(&cfg.listen, "127.0.0.1", 29401) != PP_OK) return 1;

    void *ctx = NULL;
    if (pp_tunnel_udp.open(&cfg, &ctx) != PP_OK) {
        printf("  open returned err (expected on non-XDP iface) OK\n");
        return 0;
    }
    int rc = pp_tunnel_udp.connect(ctx);
    if (rc != PP_OK) {
        printf("  connect returned err=%d on lo (expected) OK\n", rc);
    } else {
        printf("  connect OK (XDP-capable iface!) — closing\n");
    }
    pp_tunnel_udp.close(ctx);
    printf("=== UDP af_xdp smoke OK ===\n\n");
    return 0;
}
#endif  /* PP_HAVE_XDP */

int main(void)
{
    pp_log_init(PP_LOG_INFO, NULL);
    if (test_tcp() != 0) return 1;
    if (test_udp() != 0) return 1;
    if (!can_raw_udp()) {
        printf("=== UDP raw_socket: SKIP (no CAP_NET_RAW) ===\n\n");
    } else if (test_udp_raw() != 0) {
        return 1;
    }
    if (!can_tun()) {
        printf("=== tun smoke: SKIP (no /dev/net/tun or CAP_NET_ADMIN) ===\n\n");
    } else {
        if (smoke_udp_tun()  != 0) return 1;
        if (smoke_icmp_tun() != 0) return 1;
    }
#ifdef PP_HAVE_PCAP
    if (!can_raw_udp()) {
        /* pcap 在 Linux 也需要 CAP_NET_RAW 或 setcap cap_net_raw+eip */
        printf("=== UDP pcap: SKIP (no CAP_NET_RAW) ===\n\n");
    } else if (test_udp_pcap() != 0) {
        return 1;
    }
#else
    printf("=== UDP pcap: SKIP (build without -Dpcap=true) ===\n\n");
#endif
#ifdef PP_HAVE_XDP
    if (smoke_udp_xdp() != 0) return 1;
#else
    printf("=== UDP af_xdp: SKIP (build without -Dxdp=true) ===\n\n");
#endif
    printf("ALL OK\n");
    return 0;
}
