/* tests/test_pcap_io.c
 *
 * 验证 src/io/pcap.c 左手 vtable（pp_io_pcap）：
 *   - open / get_rx_fd / stat / close 不崩
 *   - tx_burst 注入一个 IPv4+UDP 包到 lo，rx_burst 能拿回来
 *
 * 需要 CAP_NET_RAW。没有则 exit 77 (skip)。
 * -Dpcap=true 才会被编译进构建。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/pkt_io.h"

#define TEST_DST_IP  "127.0.0.99"
#define TEST_DPORT   29777
#define TEST_SPORT   29778

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

int main(void)
{
    if (if_nametoindex("lo") == 0) {
        printf("SKIP: 'lo' not found\n");
        return 77;
    }

    pp_mempool_cfg_t mp_cfg = {
        .nelem        = 64,
        .buf_size     = 2048,
        .headroom     = 64,
        .cpu          = -1,
    };
    pp_mempool_t *pool = pp_mempool_create(&mp_cfg);
    if (!pool) { fprintf(stderr, "mempool_create failed\n"); return 1; }

    pp_io_cfg_t cfg = {0};
    cfg.kind          = PP_IO_PCAP;
    cfg.name          = "test-pcap";
    cfg.pool          = pool;
    cfg.u.pcap.ifname = "lo";
    cfg.u.pcap.snaplen = 2048;
    /* 只看我们即将发的特征包，降低 rx 噪声 */
    cfg.u.pcap.bpf    = "udp and dst port 29777";
    /* lo 是 DLT_NULL，peer_mac 用不上 */

    void *ctx = NULL;
    int rc = pp_io_pcap.open(&cfg, &ctx);
    if (rc != PP_OK) {
        if (rc == PP_ERR_IO) {
            /* 典型是 pcap_open_live 返回 EACCES/EPERM */
            printf("SKIP: pcap open on lo failed (need CAP_NET_RAW)\n");
            pp_mempool_destroy(pool);
            return 77;
        }
        fprintf(stderr, "pp_io_pcap.open rc=%d\n", rc);
        pp_mempool_destroy(pool);
        return 1;
    }

    int fd = pp_io_pcap.get_rx_fd(ctx);
    printf("pcap opened on lo (fd=%d)\n", fd);
    if (fd < 0) {
        fprintf(stderr, "expected fd>=0 on Linux lo\n");
        pp_io_pcap.close(ctx); pp_mempool_destroy(pool);
        return 1;
    }

    char stat[256] = {0};
    pp_io_pcap.stat(ctx, stat, sizeof stat);
    printf("stat=%s\n", stat);

    /* 构造一个 UDP/IP 包，src=127.0.0.1, dst=127.0.0.99 */
    pp_pkt_t *tx = pp_mempool_alloc(pool);
    if (!tx) { fprintf(stderr, "mempool alloc fail\n"); goto fail; }
    uint32_t saddr, daddr;
    inet_pton(AF_INET, "127.0.0.1", &saddr);
    inet_pton(AF_INET, TEST_DST_IP, &daddr);
    const char *payload = "pcap-e2e-hello";
    size_t n = build_udp(tx->data, tx->tailroom,
                        saddr, daddr, TEST_SPORT, TEST_DPORT,
                        payload, strlen(payload));
    tx->data_len = (uint16_t)n;
    tx->tailroom -= (uint16_t)n;

    pp_pkt_t *tx_arr[1] = { tx };
    int sent = pp_io_pcap.tx_burst(ctx, tx_arr, 1);
    pp_pkt_put_ref(tx);
    if (sent != 1) {
        fprintf(stderr, "tx_burst expected 1, got %d\n", sent);
        goto fail;
    }
    printf("tx: injected 1 packet\n");

    /* rx：给它最多 1s（非阻塞轮询），只接受过 BPF 的包 */
    int got = 0;
    pp_pkt_t *rx_arr[8] = {0};
    for (int i = 0; i < 200 && got == 0; i++) {
        got = pp_io_pcap.rx_burst(ctx, rx_arr, 8, 0);
        if (got > 0) break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    if (got <= 0) {
        fprintf(stderr, "rx_burst timeout (got=%d)\n", got);
        goto fail;
    }
    printf("rx: got %d packet(s)\n", got);

    /* 验证第一个包的解析 meta */
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
    if (ntohs(ruh->dest) != TEST_DPORT) {
        fprintf(stderr, "rx dport %u != %u\n", ntohs(ruh->dest), TEST_DPORT);
        for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);
        goto fail;
    }
    if (rih->daddr != daddr) {
        fprintf(stderr, "rx daddr mismatch\n");
        for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);
        goto fail;
    }
    printf("rx: meta ok (l4=UDP, dport=%u)\n", ntohs(ruh->dest));

    for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);

    pp_io_pcap.close(ctx);
    pp_mempool_destroy(pool);
    printf("PASS: pcap_io\n");
    return 0;

fail:
    pp_io_pcap.close(ctx);
    pp_mempool_destroy(pool);
    return 1;
}
