/* xsk_i.h -- pp_xsk_io 内部定义，供 xsk.c / xsk_xdpcap.c 共享 */
#ifndef PPROXY_XSK_I_H
#define PPROXY_XSK_I_H

#include <net/if.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <xdp/xsk.h>
#include "pproxy/xsk_filt.h"

/* 与 <linux/if_ether.h> 一致，仅尺寸 */
#define PP_XSK_ETH_HDR 14U

struct pp_xsk_io {
    struct xsk_umem      *umem;
    struct xsk_socket    *xsk;
    void                 *umem_area;
    size_t                umem_size;

    struct xsk_ring_prod  fq;
    struct xsk_ring_cons  cq;
    struct xsk_ring_cons  rx;
    struct xsk_ring_prod  tx;

    int       fd;
    char      ifname[IFNAMSIZ];
    uint32_t  queue_id;
    uint32_t  frame_size;
    uint32_t  nframes;

    uint32_t  rx_base, rx_count;
    uint32_t  tx_base, tx_count;
    uint32_t  tx_next;
    uint32_t  tx_outstanding;

    uint8_t   src_mac[6];
    uint8_t   dst_mac[6];
    bool      need_wakeup;
    pp_xsk_filt_t xdp_filt;   /* 供 xdpcap eBPF 入站匹配；与 pp_xsk_io_new 入参一致 */

    uint8_t   rx_stash[4096]; /* XSK_UMEM__DEFAULT_FRAME_SIZE */
    size_t    rx_stash_len;

    /* PPROXY_XDPCAP_BPF=… 时：自载 eBPF、xdpcap hook pin（libbpf 指针） */
    void *xdpcap_obj;
    void *xdpcap_link;
    unsigned int xdpcap_ifindex;
    uint32_t     xdpcap_xdp_flags;
    char         xdpcap_pin[512];
};

#endif
