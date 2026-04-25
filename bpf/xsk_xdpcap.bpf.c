/* SPDX-License-Identifier: GPL-2.0 OR Apache-2.0
 * xsk_xdpcap.bpf.c — AF_XDP redirect + xdpcap_hook
 * 仅将「用户态配置的」入站 IPv4 转给 XSK；默认 daddr/dport/pproto 全 0 时与旧版一致转全部裸 IPv4。
 */
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct pproxy_xsk_filt {
    __u32 daddr;   /* 网络序 目的 IPv4；0=不检查 */
    __u16 dport;  /* 网络序 UDP 目的端口；0=不检查(仅 pproto=UDP) */
    __u8  pproto; /* 0 且 daddr/dport=0: 所有裸 IPv4；17=UDP；1=ICMP */
    __u8  _pad[1];
};

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(map_flags, 0);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct pproxy_xsk_filt);
} pproxy_xsk_filt_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} xdpcap_hook SEC(".maps");

static __always_inline int pproxy_match_and_redirect(struct xdp_md *ctx, __u32 k)
{
    bpf_tail_call(ctx, &xdpcap_hook, 4U);
    return bpf_redirect_map(&xsks_map, k, 0);
}

SEC("xdp")
int xsk_def_prog(struct xdp_md *ctx)
{
    unsigned char *m    = (unsigned char *)(void *)(long)ctx->data;
    void *data_end     = (void *)(long)ctx->data_end;
    __u32 k = ctx->rx_queue_index;

    /* 非裸 IPv4：ARP / 802.1Q 等给内核，否则本机不回应 ARP */
    if (m + 14 > (unsigned char *)data_end)
        return XDP_PASS;
    if (m[12] != 0x08 || m[13] != 0x00)
        return XDP_PASS;

    __u32 fkey = 0;
    struct pproxy_xsk_filt *f = bpf_map_lookup_elem(&pproxy_xsk_filt_map, &fkey);
    if (!f)
        return XDP_PASS;
    if (f->daddr == 0 && f->dport == 0 && f->pproto == 0)
        return pproxy_match_and_redirect(ctx, k);
    if (f->pproto == 0)
        return XDP_PASS; /* 非「全 0 放开」时须显式 ipproto(UDP/ICMP) */

    if (m + 14 + sizeof(struct iphdr) > (unsigned char *)data_end)
        return XDP_PASS;
    struct iphdr *iph = (struct iphdr *)(m + 14);
    if (iph->version != 4)
        return XDP_PASS;
    if (iph->ihl < 5)
        return XDP_PASS;
    __u32 ihl = (__u32)iph->ihl * 4U;
    if (m + 14 + ihl > (unsigned char *)data_end)
        return XDP_PASS;
    if (f->daddr && iph->daddr != f->daddr)
        return XDP_PASS;
    if (f->pproto && iph->protocol != f->pproto)
        return XDP_PASS;
    if (f->pproto == IPPROTO_UDP) {
        if (f->dport == 0)
            return XDP_PASS;
        if (m + 14 + ihl + sizeof(struct udphdr) > (unsigned char *)data_end)
            return XDP_PASS;
        struct udphdr *uh = (struct udphdr *)(m + 14 + ihl);
        if (uh->dest != f->dport)
            return XDP_PASS;
    }
    /* IPPROTO_ICMP: 无端口，L3/协议已匹配 */
    return pproxy_match_and_redirect(ctx, k);
}
