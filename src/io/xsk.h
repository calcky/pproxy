/* src/io/xsk.h -- AF_XDP (XSK) 收发 IP 帧的薄封装
 *
 * 仅在 -Dxdp=true（PP_HAVE_XDP）时启用。
 *
 * 本 header 不 include <xdp/xsk.h>——因为 libbpf 的 linux/bpf.h 跟 pcap/bpf.h
 * struct bpf_insn 冲突。只暴露不透明指针 + API。
 *
 * 约束：
 *   - 只支持 IPv4 / ethernet iface；不支持 loopback（XDP 在 lo 上非标配）
 *   - xsk_socket__create 会加载 libxdp 默认 redirect 程序，需 CAP_NET_ADMIN+CAP_BPF
 *   - 目标 MAC 默认全 0（仅 lab/veth 场景能收到）；生产需要真实 peer MAC
 */
#ifndef PPROXY_IO_XSK_H
#define PPROXY_IO_XSK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pproxy/pproxy.h"

#ifdef PP_HAVE_XDP

struct pp_xsk_io;   /* opaque */

int  pp_xsk_io_new(struct pp_xsk_io **out,
                   const char *ifname,
                   uint32_t queue_id,
                   uint32_t nframes,
                   bool zero_copy,
                   bool need_wakeup,
                   const uint8_t peer_mac[6]);
void pp_xsk_io_free(struct pp_xsk_io *p);

int         pp_xsk_io_get_fd    (const struct pp_xsk_io *p);
const char *pp_xsk_io_get_ifname(const struct pp_xsk_io *p);
uint32_t    pp_xsk_io_get_queue (const struct pp_xsk_io *p);

int            pp_xsk_io_inject_ip(struct pp_xsk_io *p, const uint8_t *ip, size_t len);
const uint8_t *pp_xsk_io_next_ip  (struct pp_xsk_io *p, size_t *out_len);

#endif /* PP_HAVE_XDP */
#endif /* PPROXY_IO_XSK_H */
