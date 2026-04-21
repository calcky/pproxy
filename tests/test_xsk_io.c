/* tests/test_xsk_io.c
 *
 * 验证 src/io/xsk.c 左手 vtable（pp_io_af_xdp）：
 *   - 创建 veth pair (xsk-testA <-> xsk-testB)
 *   - 在 A 上 open XSK 后端
 *   - tx_burst 注入一个 IPv4+UDP 包
 *   - B 上用 AF_PACKET 抓包校验收到
 *
 * 需要 CAP_NET_ADMIN + CAP_BPF + /sbin/ip 工具。
 * 任何环境不满足 → exit 77 (skip)。
 * -Dxdp=true 才会被编译进构建。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/pkt_io.h"

#define IF_A       "xsk-testA"
#define IF_B       "xsk-testB"
#define TEST_DPORT 29888
#define TEST_SPORT 29887

static int run(const char *cmd)
{
    int rc = system(cmd);
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

static void cleanup_veth(void)
{
    run("ip link del " IF_A " 2>/dev/null");
}

static int setup_veth(void)
{
    cleanup_veth();                   /* 确保干净 */
    if (run("ip link add " IF_A " type veth peer name " IF_B
            " 2>/dev/null") != 0) return -1;
    if (run("ip link set " IF_A " up 2>/dev/null") != 0) return -1;
    if (run("ip link set " IF_B " up 2>/dev/null") != 0) return -1;
    /* 等一下，让 link state 稳定 */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    return 0;
}

static int open_afpacket_on(const char *ifname)
{
    int fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                    htons(ETH_P_ALL));
    if (fd < 0) return -1;
    struct sockaddr_ll sll = {
        .sll_family   = AF_PACKET,
        .sll_protocol = htons(ETH_P_ALL),
        .sll_ifindex  = (int)if_nametoindex(ifname),
    };
    if (sll.sll_ifindex == 0 || bind(fd, (struct sockaddr *)&sll, sizeof sll) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static uint16_t inet_csum16(const void *buf, size_t len)
{
    uint32_t sum = 0;
    const uint16_t *p = buf;
    while (len >= 2) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static size_t build_udp(uint8_t *buf, size_t cap,
                        uint32_t saddr_be, uint32_t daddr_be,
                        uint16_t sport, uint16_t dport,
                        const void *payload, size_t plen)
{
    size_t iplen = 20 + 8 + plen;
    if (cap < iplen) return 0;
    struct iphdr  *ip  = (struct iphdr  *)buf;
    struct udphdr *udp = (struct udphdr *)(buf + 20);
    memset(ip, 0, 20);
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tot_len  = htons((uint16_t)iplen);
    ip->id       = htons(0xcafe);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr    = saddr_be;
    ip->daddr    = daddr_be;
    ip->check    = inet_csum16(ip, 20);
    udp->source  = htons(sport);
    udp->dest    = htons(dport);
    udp->len     = htons((uint16_t)(8 + plen));
    udp->check   = 0;
    memcpy(buf + 20 + 8, payload, plen);
    return iplen;
}

static int skip(const char *why, pp_mempool_t *pool)
{
    printf("SKIP: %s\n", why);
    if (pool) pp_mempool_destroy(pool);
    cleanup_veth();
    return 77;
}

int main(void)
{
    pp_mempool_cfg_t mp_cfg = {
        .nelem = 64, .buf_size = 2048, .headroom = 64, .cpu = -1,
    };
    pp_mempool_t *pool = pp_mempool_create(&mp_cfg);
    if (!pool) { fprintf(stderr, "mempool_create failed\n"); return 1; }

    if (system("command -v ip >/dev/null 2>&1") != 0)
        return skip("'ip' tool not found", pool);
    if (setup_veth() != 0)
        return skip("veth setup failed (need CAP_NET_ADMIN)", pool);

    /* B 端先开 AF_PACKET，免得 XSK inject 时丢包 */
    int pfd = open_afpacket_on(IF_B);
    if (pfd < 0) { cleanup_veth(); pp_mempool_destroy(pool);
                   return skip("AF_PACKET bind on peer failed", NULL); }

    pp_io_cfg_t cfg = {0};
    cfg.kind               = PP_IO_AF_XDP;
    cfg.name               = "test-xsk";
    cfg.pool               = pool;
    cfg.u.xdp.ifname       = IF_A;
    cfg.u.xdp.queue_id     = 0;
    cfg.u.xdp.nframes      = 256;
    cfg.u.xdp.zero_copy    = false;  /* veth 不支持 ZC，强制 copy 模式 */
    cfg.u.xdp.need_wakeup  = true;
    /* peer_mac：从 B 端读 MAC 作为目的，保证 A 的 tx 到 B 时不会被 kernel 丢 */
    {
        char path[128];
        snprintf(path, sizeof path, "/sys/class/net/%s/address", IF_B);
        FILE *fp = fopen(path, "r");
        if (fp) {
            unsigned m[6] = {0};
            if (fscanf(fp, "%x:%x:%x:%x:%x:%x",
                       &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                for (int i = 0; i < 6; i++) cfg.u.xdp.peer_mac[i] = (uint8_t)m[i];
                cfg.u.xdp.has_peer_mac = true;
            }
            fclose(fp);
        }
    }

    void *ctx = NULL;
    int rc = pp_io_af_xdp.open(&cfg, &ctx);
    if (rc != PP_OK) {
        close(pfd);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return skip("pp_io_af_xdp.open failed (need CAP_BPF + XDP-capable kernel)",
                    NULL);
    }

    int fd = pp_io_af_xdp.get_rx_fd(ctx);
    printf("xsk opened on %s (fd=%d)\n", IF_A, fd);
    char st[256] = {0};
    pp_io_af_xdp.stat(ctx, st, sizeof st);
    printf("stat=%s\n", st);

    /* 构造 UDP/IP 包 */
    pp_pkt_t *tx = pp_mempool_alloc(pool);
    if (!tx) { fprintf(stderr, "mempool alloc fail\n"); goto fail; }
    uint32_t saddr, daddr;
    inet_pton(AF_INET, "10.99.0.1",  &saddr);
    inet_pton(AF_INET, "10.99.0.2",  &daddr);
    const char *payload = "xsk-hello";
    size_t n = build_udp(tx->data, tx->tailroom,
                         saddr, daddr, TEST_SPORT, TEST_DPORT,
                         payload, strlen(payload));
    tx->data_len = (uint16_t)n;
    tx->tailroom -= (uint16_t)n;

    pp_pkt_t *tx_arr[1] = { tx };
    int sent = 0;
    for (int i = 0; i < 50 && sent == 0; i++) {
        sent = pp_io_af_xdp.tx_burst(ctx, tx_arr, 1);
        if (sent) break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    pp_pkt_put_ref(tx);
    if (sent != 1) { fprintf(stderr, "tx_burst expected 1, got %d\n", sent); goto fail; }
    printf("tx: injected 1 packet\n");

    /* B 端 AF_PACKET 轮询 */
    uint8_t buf[2048];
    int got = 0;
    for (int i = 0; i < 200 && !got; i++) {
        ssize_t r = recv(pfd, buf, sizeof buf, 0);
        if (r > 0) {
            /* 验证是我们自己的包 */
            if ((size_t)r >= 14 + 20 + 8 &&
                buf[12] == 0x08 && buf[13] == 0x00) {
                const struct iphdr *ih = (const struct iphdr *)(buf + 14);
                if (ih->protocol == IPPROTO_UDP && ih->daddr == daddr) {
                    const struct udphdr *uh = (const struct udphdr *)(buf + 14 + ih->ihl * 4);
                    if (ntohs(uh->dest) == TEST_DPORT) {
                        got = 1;
                        printf("peer rx: got our UDP/IP frame (len=%zd)\n", r);
                        break;
                    }
                }
            }
            continue;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            fprintf(stderr, "peer recv: %s\n", strerror(errno));
            break;
        }
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (!got) { fprintf(stderr, "peer did not see injected packet\n"); goto fail; }

    close(pfd);
    pp_io_af_xdp.close(ctx);
    pp_mempool_destroy(pool);
    cleanup_veth();
    printf("PASS: xsk_io\n");
    return 0;

fail:
    close(pfd);
    pp_io_af_xdp.close(ctx);
    pp_mempool_destroy(pool);
    cleanup_veth();
    return 1;
}
