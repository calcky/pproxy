/* src/io/xsk.h -- AF_XDP (XSK) 收发 IP 帧的薄封装
 *
 * 仅在 -Dxdp=true（PP_HAVE_XDP）时启用。
 *
 * 本 header 不 include <xdp/xsk.h>——因为 libbpf 的 linux/bpf.h 跟 pcap/bpf.h
 * struct bpf_insn 冲突。只暴露不透明指针 + API。
 *
 * 约束：
 *   - 只支持 IPv4 / ethernet iface；不支持 loopback（XDP 在 lo 上非标配）
 *   - 未设置 PPROXY_XDPCAP_BPF 时，xsk_socket__create 会加载 libxdp 默认 redirect 程序
 *   - 若设置 PPROXY_XDPCAP_BPF=…/xsk_xdpcap.bpf.o，由自载 eBPF 挂 XDP 并 pin xdpcap_hook，可用 xdpcap 按 hook 抓包（需 bpffs）
 *   - 需 CAP_NET_ADMIN+CAP_BPF
 *   - 目标 MAC：可传 peer_mac，或 arp_nexthop_be（查本机 /proc/net/arp 邻居，失败时回退 peer_mac）
 *   - 全 0 时仅部分场景能通；跨网段时 arp 应对应该出口上的下一跳 IP（邻居项须已在内核表中）
 */
#ifndef PPROXY_IO_XSK_H
#define PPROXY_IO_XSK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pproxy/pproxy.h"
#include "pproxy/xsk_filt.h"

#ifdef PP_HAVE_XDP

struct pp_xsk_io;   /* opaque */

int  pp_xsk_io_new(struct pp_xsk_io **out,
                   const char *ifname,
                   uint32_t queue_id,
                   uint32_t nframes,
                   bool zero_copy,
                   bool need_wakeup,
                   const uint8_t peer_mac[6],
                   uint32_t arp_nexthop_be,
                   const pp_xsk_filt_t *xdp_filt);
void pp_xsk_io_free(struct pp_xsk_io *p);

int         pp_xsk_io_get_fd    (const struct pp_xsk_io *p);
const char *pp_xsk_io_get_ifname(const struct pp_xsk_io *p);
uint32_t    pp_xsk_io_get_queue (const struct pp_xsk_io *p);
/* 注包用的以太网源/目的 MAC（pp_xsk_io_new 时根据接口与 ARP/peer 填入） */
void        pp_xsk_io_get_macs  (const struct pp_xsk_io *p, uint8_t out_src[6], uint8_t out_dst[6]);
int         pp_xsk_ifname_first_ipv4(const char *ifname, uint32_t *out_saddr_be);
/* server 学到对端后调用：按 L3 对端地址更新 eth 目的 MAC（路由 + ARP，无 peer_mac 回退） */
int         pp_xsk_io_refresh_arp(struct pp_xsk_io *p, uint32_t l3_peer_be);

int            pp_xsk_io_inject_ip(struct pp_xsk_io *p, const uint8_t *ip, size_t len);
const uint8_t *pp_xsk_io_next_ip  (struct pp_xsk_io *p, size_t *out_len);

#endif /* PP_HAVE_XDP */
#endif /* PPROXY_IO_XSK_H */
