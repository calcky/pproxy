/* pp_xsk_filt — 入站 XDP → XSK 的 IPv4 过滤（与 bpf/pproxy_xsk_filt 布局一致） */
#ifndef PPROXY_XSK_FILT_H
#define PPROXY_XSK_FILT_H

#include <stdint.h>

typedef struct pp_xsk_filt {
    uint32_t daddr_be;  /* 目的 IPv4，网络序；0=不检查 */
    uint16_t dport_be;  /* L4 目的端口，网络序；在 ipproto=UDP 时与 UDP 头比较；0=不检查 */
    uint8_t  ipproto;  /* 0 且 daddr/dport 均 0：全部裸 IPv4 进 XSK；17=只 UDP；1=只 ICMP */
    uint8_t  _pad[1];
} pp_xsk_filt_t;

#endif
