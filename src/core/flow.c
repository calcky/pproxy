/* core/flow.c -- FlowKey 哈希、归一化、格式化 */
#include <string.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include "pproxy/flow.h"
#include "pproxy/packet.h"

int pp_pkt_parse_l3_ipv4(pp_pkt_t *p)
{
    if (!p) return PP_ERR_INVAL;
    if (p->data_len < sizeof(struct iphdr)) return PP_ERR_PROTO;
    const struct iphdr *ih = (const struct iphdr *)p->data;
    if (ih->version != 4) return PP_ERR_NOSUPPORT;
    uint16_t ihl = (uint16_t)(ih->ihl * 4u);
    if (ihl < 20u || ihl > p->data_len) return PP_ERR_PROTO;
    p->meta.l3_off     = 0;
    p->meta.l3_proto   = IPPROTO_IP;
    p->meta.l4_off     = ihl;
    p->meta.l4_proto   = ih->protocol;
    p->meta.payload_off = UINT16_MAX;
    return PP_OK;
}

/* 简单 splitmix64 风格 hash */
static inline uint64_t mix64(uint64_t x)
{
    x ^= x >> 33; x *= 0xff51afd7ed558ccdULL;
    x ^= x >> 33; x *= 0xc4ceb9fe1a85ec53ULL;
    x ^= x >> 33;
    return x;
}

static int addr_cmp(const pp_addr_t *a, const pp_addr_t *b)
{
    if (a->af != b->af) return (int)a->af - (int)b->af;
    if (a->af == PP_AF_INET)
        return memcmp(&a->u.v4, &b->u.v4, sizeof a->u.v4);
    return memcmp(&a->u.v6, &b->u.v6, sizeof a->u.v6);
}

void pp_flow_key_normalize(pp_flow_key_t *k, pp_flow_dir_t *out_dir)
{
    int c = addr_cmp(&k->src, &k->dst);
    int swap = (c > 0) || (c == 0 && k->sport > k->dport);
    if (out_dir) *out_dir = swap ? PP_DIR_DOWNSTREAM : PP_DIR_UPSTREAM;
    if (swap) {
        pp_addr_t ta = k->src; k->src = k->dst; k->dst = ta;
        uint16_t  tp = k->sport; k->sport = k->dport; k->dport = tp;
    }
}

uint64_t pp_flow_key_hash(const pp_flow_key_t *k)
{
    uint64_t h = (uint64_t)k->l4_proto;
    h ^= (uint64_t)k->sport << 16 | (uint64_t)k->dport;
    if (k->src.af == PP_AF_INET) {
        h ^= (uint64_t)k->src.u.v4.s_addr << 32;
        h ^= (uint64_t)k->dst.u.v4.s_addr;
    } else {
        const uint64_t *s = (const uint64_t *)&k->src.u.v6;
        const uint64_t *d = (const uint64_t *)&k->dst.u.v6;
        h ^= s[0] ^ s[1] ^ d[0] ^ d[1];
    }
    return mix64(h);
}

bool pp_flow_key_equal(const pp_flow_key_t *a, const pp_flow_key_t *b)
{
    return a->l4_proto == b->l4_proto
        && a->sport    == b->sport
        && a->dport    == b->dport
        && addr_cmp(&a->src, &b->src) == 0
        && addr_cmp(&a->dst, &b->dst) == 0;
}

int pp_flow_key_format(const pp_flow_key_t *k, char *buf, size_t cap)
{
    char s[64], d[64];
    if (k->src.af == PP_AF_INET) {
        inet_ntop(AF_INET, &k->src.u.v4, s, sizeof s);
        inet_ntop(AF_INET, &k->dst.u.v4, d, sizeof d);
    } else {
        inet_ntop(AF_INET6, &k->src.u.v6, s, sizeof s);
        inet_ntop(AF_INET6, &k->dst.u.v6, d, sizeof d);
    }
    const char *p = "?";
    switch (k->l4_proto) {
    case IPPROTO_TCP:  p = "tcp";  break;
    case IPPROTO_UDP:  p = "udp";  break;
    case IPPROTO_ICMP: p = "icmp"; break;
    }
    return snprintf(buf, cap, "%s %s:%u -> %s:%u",
                    p, s, k->sport, d, k->dport);
}

int pp_flow_key_from_pkt(const pp_pkt_t *p, pp_flow_key_t *out)
{
    if (!p || !out) return PP_ERR_INVAL;
    if (p->meta.l3_off == UINT16_MAX) return PP_ERR_PROTO;
    memset(out, 0, sizeof *out);
    out->l4_proto = p->meta.l4_proto;

    if (p->meta.l3_proto == IPPROTO_IP) {
        const struct iphdr *ih = (const struct iphdr *)(p->data + p->meta.l3_off);
        out->src.af = PP_AF_INET;
        out->dst.af = PP_AF_INET;
        out->src.u.v4.s_addr = ih->saddr;
        out->dst.u.v4.s_addr = ih->daddr;
    } else {
        return PP_ERR_NOSUPPORT;
    }
    if (p->meta.l4_off != UINT16_MAX) {
        const uint8_t *l4 = p->data + p->meta.l4_off;
        if (out->l4_proto == IPPROTO_TCP) {
            const struct tcphdr *t = (const struct tcphdr *)l4;
            out->sport = ntohs(t->source);
            out->dport = ntohs(t->dest);
        } else if (out->l4_proto == IPPROTO_UDP) {
            const struct udphdr *u = (const struct udphdr *)l4;
            out->sport = ntohs(u->source);
            out->dport = ntohs(u->dest);
        } else if (out->l4_proto == IPPROTO_ICMP) {
            if (p->data_len < p->meta.l4_off + 8) return PP_ERR_PROTO;
            const struct icmphdr *ic = (const struct icmphdr *)l4;
            if (ic->type == ICMP_ECHO || ic->type == ICMP_ECHOREPLY) {
                uint16_t id = ntohs(ic->un.echo.id);
                /* sport/dport 均用 id，normalize 交换后仍一致，echo/reply 同流 */
                out->sport = id;
                out->dport = id;
            }
        }
    }
    return PP_OK;
}
