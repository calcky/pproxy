/* tests/test_dpdk_io.c
 *
 * 验证 src/io/dpdk.c 左手 vtable（pp_io_dpdk）的 open/tx/close 链路。
 *
 * 用 DPDK 自带的 net_null0 vdev：不需要真实网卡 / hugepages / root。
 * 若 rte_eal_init 因运行环境受限失败（容器无 /dev/cpu、缺 librte_net_null.so 等），
 * exit 77 视作 skip。
 *
 * -Ddpdk=true 才会被编译进构建。
 */
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/pkt_io.h"

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
    ip->id       = htons(0xc0de);
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
    pp_mempool_cfg_t mp_cfg = {
        .nelem    = 64,
        .buf_size = 2048,
        .headroom = 64,
        .cpu      = -1,
    };
    pp_mempool_t *pool = pp_mempool_create(&mp_cfg);
    if (!pool) { fprintf(stderr, "mempool_create failed\n"); return 1; }

    pp_io_cfg_t cfg = {0};
    cfg.kind = PP_IO_DPDK;
    cfg.name = "test-dpdk";
    cfg.pool = pool;
    cfg.u.dpdk.port_id  = 0;
    cfg.u.dpdk.queue_id = 0;
    cfg.u.dpdk.nframes  = 2048;
    /* --no-huge：不要 hugepages；--no-pci：跳过 PCI 扫描；
     * --no-shconf：跳过 shared config（不需要 /var/run/dpdk）；
     * --vdev=net_null0：内置 dummy PMD，tx 直接丢、rx 永远为空。 */
    cfg.u.dpdk.eal_args = "pproxy --no-huge --no-pci --no-shconf --in-memory -l 0 --vdev=net_null0";
    cfg.u.dpdk.has_peer_mac = false;

    void *ctx = NULL;
    int rc = pp_io_dpdk.open(&cfg, &ctx);
    if (rc != PP_OK) {
        /* EAL 在 CI / 容器里可能因 cpu 探测、文件锁等失败 —— 当作 skip。 */
        printf("SKIP: pp_io_dpdk.open rc=%d (likely EAL/PMD unavailable in this env)\n", rc);
        pp_mempool_destroy(pool);
        return 77;
    }
    printf("dpdk opened (port=0, vdev=net_null0)\n");

    /* fd 必须是 -1（DPDK busy poll） */
    int fd = pp_io_dpdk.get_rx_fd(ctx);
    if (fd != -1) {
        fprintf(stderr, "expected get_rx_fd() == -1, got %d\n", fd);
        pp_io_dpdk.close(ctx);
        pp_mempool_destroy(pool);
        return 1;
    }
    char stat[256] = {0};
    pp_io_dpdk.stat(ctx, stat, sizeof stat);
    printf("stat=%s\n", stat);

    /* tx_burst：net_null 接受并丢弃；返回 1 视为成功 */
    pp_pkt_t *tx = pp_mempool_alloc(pool);
    if (!tx) { fprintf(stderr, "mempool alloc fail\n"); goto fail; }
    uint32_t saddr, daddr;
    inet_pton(AF_INET, "10.0.0.1", &saddr);
    inet_pton(AF_INET, "10.0.0.2", &daddr);
    const char *payload = "dpdk-null-hello";
    size_t n = build_udp(tx->data, tx->tailroom,
                         saddr, daddr, 32100, 32200,
                         payload, strlen(payload));
    tx->data_len  = (uint16_t)n;
    tx->tailroom -= (uint16_t)n;

    pp_pkt_t *tx_arr[1] = { tx };
    int sent = pp_io_dpdk.tx_burst(ctx, tx_arr, 1);
    pp_pkt_put_ref(tx);
    if (sent != 1) {
        fprintf(stderr, "tx_burst expected 1, got %d\n", sent);
        goto fail;
    }
    printf("tx: 1 packet accepted by net_null PMD\n");

    /* rx_burst：net_null 不产生入包；预期 0 */
    pp_pkt_t *rx_arr[8] = {0};
    int got = pp_io_dpdk.rx_burst(ctx, rx_arr, 8, 0);
    if (got != 0) {
        fprintf(stderr, "rx_burst expected 0 on net_null, got %d\n", got);
        for (int i = 0; i < got; i++) pp_pkt_put_ref(rx_arr[i]);
        goto fail;
    }
    printf("rx: 0 (net_null produces no inbound)\n");

    pp_io_dpdk.close(ctx);
    pp_mempool_destroy(pool);
    printf("PASS: dpdk_io\n");
    return 0;

fail:
    pp_io_dpdk.close(ctx);
    pp_mempool_destroy(pool);
    return 1;
}
