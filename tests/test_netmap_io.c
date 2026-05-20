/* tests/test_netmap_io.c
 *
 * 验证 src/io/netmap.c 左手 vtable（pp_io_netmap）：
 *   - open / get_rx_fd / stat / close 不崩
 *   - tx_burst 在 vale 虚拟交换机上注入 IP 包，rx_burst 在另一端取回
 *
 * 需要内核加载 netmap 模块（提供 /dev/netmap）+ CAP_NET_ADMIN。
 * 不满足时 exit 77 (skip)。
 *
 * -Dnetmap=true 才会被编译进构建。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/pkt_io.h"

#define TEST_DST_IP  "10.99.99.2"
#define TEST_SRC_IP  "10.99.99.1"
#define TEST_DPORT   29977
#define TEST_SPORT   29978

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
    struct iphdr *ip = (struct iphdr *)buf;
    struct udphdr *udp = (struct udphdr *)(buf + 20);
    memset(ip, 0, 20);
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tot_len  = htons((uint16_t)iplen);
    ip->id       = htons(0xbeef);
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

static int skip(const char *why)
{
    printf("SKIP: %s\n", why);
    return 77;
}

int main(void)
{
    /* 没 /dev/netmap 直接跳过 —— 在 CI / 沙箱里这是常态 */
    if (access("/dev/netmap", F_OK) != 0) {
        return skip("/dev/netmap missing (need `modprobe netmap`)");
    }

    pp_mempool_cfg_t mp_cfg = {
        .nelem = 64, .buf_size = 2048, .headroom = 64, .cpu = -1,
    };
    pp_mempool_t *pool = pp_mempool_create(&mp_cfg);
    if (!pool) { fprintf(stderr, "mempool_create failed\n"); return 1; }

    /* 在同一台 vale 虚拟交换机上开两个端口：a 发，b 收 */
    void *tx_ctx = NULL, *rx_ctx = NULL;
    pp_io_cfg_t tx_cfg = {0}, rx_cfg = {0};
    tx_cfg.kind = rx_cfg.kind = PP_IO_NETMAP;
    tx_cfg.pool = rx_cfg.pool = pool;
    tx_cfg.name = "tx"; rx_cfg.name = "rx";
    tx_cfg.u.netmap.ifname = "vale-pp:a";
    tx_cfg.u.netmap.nrings = 1;
    rx_cfg.u.netmap.ifname = "vale-pp:b";
    rx_cfg.u.netmap.nrings = 1;

    int rc = pp_io_netmap.open(&tx_cfg, &tx_ctx);
    if (rc != PP_OK) {
        pp_mempool_destroy(pool);
        return skip("nm_open(vale-pp:a) failed (need CAP_NET_ADMIN + netmap module)");
    }
    rc = pp_io_netmap.open(&rx_cfg, &rx_ctx);
    if (rc != PP_OK) {
        pp_io_netmap.close(tx_ctx);
        pp_mempool_destroy(pool);
        return skip("nm_open(vale-pp:b) failed");
    }

    char st[256] = {0};
    pp_io_netmap.stat(tx_ctx, st, sizeof st);
    printf("tx stat=%s\n", st);
    pp_io_netmap.stat(rx_ctx, st, sizeof st);
    printf("rx stat=%s\n", st);

    /* 构造 IPv4+UDP 包（注意 pp_netmap_io_inject_ip 内部会自加 14B Ethernet 头） */
    pp_pkt_t *tx = pp_mempool_alloc(pool);
    if (!tx) { fprintf(stderr, "mempool alloc fail\n"); goto fail; }
    uint32_t saddr, daddr;
    inet_pton(AF_INET, TEST_SRC_IP, &saddr);
    inet_pton(AF_INET, TEST_DST_IP, &daddr);
    const char *payload = "netmap-e2e-hello";
    size_t n = build_udp(tx->data, tx->tailroom,
                         saddr, daddr, TEST_SPORT, TEST_DPORT,
                         payload, strlen(payload));
    tx->data_len = (uint16_t)n;
    tx->tailroom -= (uint16_t)n;

    pp_pkt_t *tx_arr[1] = { tx };
    int sent = pp_io_netmap.tx_burst(tx_ctx, tx_arr, 1);
    pp_pkt_put_ref(tx);
    if (sent != 1) {
        fprintf(stderr, "tx_burst expected 1, got %d\n", sent);
        goto fail;
    }
    printf("tx: injected 1 packet on vale-pp:a\n");

    /* rx 端轮询（最多 ~1s）。vale 转发是同步的，但消费侧仍需 NIOCRXSYNC 触发。 */
    int got = 0;
    pp_pkt_t *rx_arr[8] = {0};
    for (int i = 0; i < 200 && got == 0; i++) {
        got = pp_io_netmap.rx_burst(rx_ctx, rx_arr, 8, 0);
        if (got > 0) break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (got <= 0) {
        fprintf(stderr, "rx_burst timeout (got=%d)\n", got);
        goto fail;
    }
    printf("rx: got %d packet(s) on vale-pp:b\n", got);

    pp_pkt_t *rxp = rx_arr[0];
    if (rxp->meta.l3_proto != IPPROTO_IP ||
        rxp->meta.l4_proto != IPPROTO_UDP) {
        fprintf(stderr, "rx meta wrong: l3=%d l4=%d\n",
                rxp->meta.l3_proto, rxp->meta.l4_proto);
        for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);
        goto fail;
    }
    const struct iphdr  *rih = (const struct iphdr  *)rxp->data;
    const struct udphdr *ruh = (const struct udphdr *)(rxp->data + rxp->meta.l4_off);
    if (ntohs(ruh->dest) != TEST_DPORT || rih->daddr != daddr) {
        fprintf(stderr, "rx fields mismatch (dport=%u, daddr ok=%d)\n",
                ntohs(ruh->dest), rih->daddr == daddr);
        for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);
        goto fail;
    }
    printf("rx: meta ok (l4=UDP, dport=%u)\n", ntohs(ruh->dest));

    for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);

    pp_io_netmap.close(rx_ctx);
    pp_io_netmap.close(tx_ctx);
    pp_mempool_destroy(pool);
    printf("PASS: netmap_io\n");
    return 0;

fail:
    if (rx_ctx) pp_io_netmap.close(rx_ctx);
    if (tx_ctx) pp_io_netmap.close(tx_ctx);
    pp_mempool_destroy(pool);
    return 1;
}
