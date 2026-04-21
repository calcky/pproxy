/* tests/test_af_packet_io.c
 *
 * 验证 src/io/raw_sock.c 左手 vtable（pp_io_raw_socket）：
 *   veth pair → B 端发完整以太 IPv4/UDP 帧 → A 端 rx_burst 收到并解析 meta。
 *
 * 需要 CAP_NET_RAW + iproute2（ip 命令）。不满足 exit 77。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/packet.h"
#include "pproxy/pkt_io.h"

#define IF_A       "afpkt-testA"
#define IF_B       "afpkt-testB"
#define UDP_DPORT  29999
#define UDP_SPORT  29998

static int run_cmd(const char *cmd)
{
    int rc = system(cmd);
    if (rc == -1) return -1;
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

static void cleanup_veth(void) { run_cmd("ip link del " IF_A " 2>/dev/null"); }

static int setup_veth(void)
{
    cleanup_veth();
    if (run_cmd("ip link add " IF_A " type veth peer name " IF_B " 2>/dev/null") != 0)
        return -1;
    if (run_cmd("ip link set " IF_A " up 2>/dev/null") != 0) return -1;
    if (run_cmd("ip link set " IF_B " up 2>/dev/null") != 0) return -1;
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    return 0;
}

static int read_mac(const char *ifname, uint8_t mac[6])
{
    char path[128];
    snprintf(path, sizeof path, "/sys/class/net/%s/address", ifname);
    FILE *fp = fopen(path, "r");
    if (!fp) return -1;
    unsigned m[6];
    int n = fscanf(fp, "%x:%x:%x:%x:%x:%x",
                   &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    fclose(fp);
    if (n != 6) return -1;
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)m[i];
    return 0;
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

static size_t build_eth_udp(uint8_t *buf, size_t cap,
                            const uint8_t dst_mac[6], const uint8_t src_mac[6],
                            uint32_t saddr_be, uint32_t daddr_be,
                            uint16_t sport, uint16_t dport,
                            const void *payload, size_t plen)
{
    size_t ip_len = 20 + 8 + plen;
    size_t tot    = 14 + ip_len;
    if (cap < tot) return 0;
    memcpy(buf, dst_mac, 6);
    memcpy(buf + 6, src_mac, 6);
    buf[12] = 0x08; buf[13] = 0x00;
    struct iphdr *ip = (struct iphdr *)(buf + 14);
    memset(ip, 0, 20);
    ip->version  = 4;
    ip->ihl      = 5;
    ip->tot_len  = htons((uint16_t)ip_len);
    ip->id       = htons(0xabcd);
    ip->ttl      = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr    = saddr_be;
    ip->daddr    = daddr_be;
    ip->check    = inet_csum16(ip, 20);
    struct udphdr *udp = (struct udphdr *)(buf + 14 + 20);
    udp->source = htons(sport);
    udp->dest   = htons(dport);
    udp->len    = htons((uint16_t)(8 + plen));
    udp->check  = 0;
    memcpy(buf + 14 + 20 + 8, payload, plen);
    return tot;
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
    if (system("command -v ip >/dev/null 2>&1") != 0)
        return skip("'ip' not found", NULL);

    pp_mempool_cfg_t mp_cfg = {
        .nelem = 64, .buf_size = 2048, .headroom = 64, .cpu = -1,
    };
    pp_mempool_t *pool = pp_mempool_create(&mp_cfg);
    if (!pool) { fprintf(stderr, "mempool_create failed\n"); return 1; }

    if (setup_veth() != 0)
        return skip("veth setup failed (need CAP_NET_ADMIN)", pool);

    uint8_t mac_a[6], mac_b[6];
    if (read_mac(IF_A, mac_a) != 0 || read_mac(IF_B, mac_b) != 0) {
        pp_mempool_destroy(pool);
        cleanup_veth();
        return skip("read MAC sysfs failed", NULL);
    }

    pp_io_cfg_t cfg = {0};
    cfg.kind          = PP_IO_RAW_SOCKET;
    cfg.name          = "test-afpkt";
    cfg.pool          = pool;
    cfg.u.raw.ifname  = IF_A;
    cfg.u.raw.snaplen = 2048;
    cfg.u.raw.promisc = true;

    void *ctx = NULL;
    int rc = pp_io_raw_socket.open(&cfg, &ctx);
    if (rc != PP_OK) {
        pp_mempool_destroy(pool);
        cleanup_veth();
        return skip("pp_io_raw_socket.open failed (need CAP_NET_RAW)", NULL);
    }

    int afd = pp_io_raw_socket.get_rx_fd(ctx);
    printf("af_packet opened on %s (fd=%d)\n", IF_A, afd);

    /* B 端发一帧给 A */
    int bfd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK | SOCK_CLOEXEC,
                     htons(ETH_P_ALL));
    if (bfd < 0) {
        fprintf(stderr, "B socket: %s\n", strerror(errno));
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }
    int idx_b = (int)if_nametoindex(IF_B);
    if (idx_b <= 0) {
        fprintf(stderr, "if_nametoindex(%s) failed\n", IF_B);
        close(bfd);
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }
    if (bind(bfd, (struct sockaddr *)&(struct sockaddr_ll){
            .sll_family   = AF_PACKET,
            .sll_protocol = htons(ETH_P_ALL),
            .sll_ifindex  = idx_b,
        }, sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr, "B bind: %s\n", strerror(errno));
        close(bfd);
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }

    uint8_t frame[512];
    uint32_t sa, da;
    inet_pton(AF_INET, "10.88.1.1", &sa);
    inet_pton(AF_INET, "10.88.1.2", &da);
    const char *pl = "afpkt-test";
    size_t flen = build_eth_udp(frame, sizeof frame,
                                mac_a, mac_b, sa, da, UDP_SPORT, UDP_DPORT,
                                pl, strlen(pl));
    if (flen == 0) {
        close(bfd);
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }

    if (sendto(bfd, frame, flen, 0,
               (struct sockaddr *)&(struct sockaddr_ll){
                   .sll_family   = AF_PACKET,
                   .sll_ifindex  = idx_b,
                   .sll_protocol = htons(ETH_P_ALL),
               }, sizeof(struct sockaddr_ll)) < 0) {
        fprintf(stderr, "B sendto: %s\n", strerror(errno));
        close(bfd);
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }
    close(bfd);

    pp_pkt_t *batch[8];
    int got = 0;
    for (int t = 0; t < 200 && got == 0; t++) {
        got = pp_io_raw_socket.rx_burst(ctx, batch, 8, 0);
        if (got > 0) break;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 5 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }

    if (got <= 0) {
        fprintf(stderr, "rx_burst got no IPv4 packet\n");
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }

    int ok = 0;
    for (int i = 0; i < got; i++) {
        pp_pkt_t *q = batch[i];
        if (q->meta.l3_proto != IPPROTO_IP || q->meta.l4_proto != IPPROTO_UDP) {
            pp_pkt_put_ref(q);
            continue;
        }
        const struct udphdr *u = (const struct udphdr *)(q->data + q->meta.l4_off);
        if (ntohs(u->dest) == UDP_DPORT) {
            ok = 1;
            printf("rx: IPv4 UDP dport=%u l3_off=%u l4_off=%u data_len=%u\n",
                   UDP_DPORT, q->meta.l3_off, q->meta.l4_off, q->data_len);
        }
        pp_pkt_put_ref(q);
    }
    if (!ok) {
        fprintf(stderr, "did not see UDP dport %u\n", UDP_DPORT);
        pp_io_raw_socket.close(ctx);
        pp_mempool_destroy(pool);
        cleanup_veth();
        return 1;
    }

    pp_io_raw_socket.close(ctx);
    pp_mempool_destroy(pool);
    cleanup_veth();
    printf("PASS: af_packet_io\n");
    return 0;
}
