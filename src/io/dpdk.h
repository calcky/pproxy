/* src/io/dpdk.h -- DPDK PMD 收发 IP 帧的薄封装
 *
 * 仅在 -Ddpdk=true（PP_HAVE_DPDK）时启用。
 *
 * 与 src/io/xsk.h 对称：
 *   - 左手 ops 由本文件实现并通过 pp_io_dpdk 注册；
 *   - 右手 tunnel 通过 pp_dpdk_io_* 薄封装注包/抽包。
 *
 * 约束：
 *   - 当前实现为「拷贝版」：rx_burst 时把 rte_mbuf 数据拷进 pp_pkt_t；
 *     tx_burst 反向。失去 DPDK 零拷贝，但 pp_pkt_t 生命周期不变。
 *   - 单端口单 queue (queue_id 默认 0)；多 queue 待补。
 *   - DPDK 独占网卡：本端口被 vfio-pci/uio_pci_generic 绑定后内核不可见。
 *   - 需要 hugepages 与相应权限（root 或 vfio-pci 已设好的 cap）。
 *   - 通过 eal_args 传 EAL 参数；空串/NULL 用默认（-l 0 --proc-type=primary --in-memory）。
 *   - EAL 在进程内只初始化一次；多个 ctx 复用同一份初始化。
 */
#ifndef PPROXY_IO_DPDK_H
#define PPROXY_IO_DPDK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pproxy/pproxy.h"

#ifdef PP_HAVE_DPDK

struct pp_dpdk_io;   /* opaque */

int  pp_dpdk_io_new(struct pp_dpdk_io **out,
                    uint16_t port_id,
                    uint16_t queue_id,
                    uint32_t nframes,
                    const char *eal_args,
                    const uint8_t peer_mac[6]);
void pp_dpdk_io_free(struct pp_dpdk_io *p);

int         pp_dpdk_io_get_fd    (const struct pp_dpdk_io *p);   /* 始终返回 -1 */
uint16_t    pp_dpdk_io_get_port  (const struct pp_dpdk_io *p);
uint16_t    pp_dpdk_io_get_queue (const struct pp_dpdk_io *p);
const char *pp_dpdk_io_get_ifname(const struct pp_dpdk_io *p);
void        pp_dpdk_io_get_macs  (const struct pp_dpdk_io *p, uint8_t out_src[6], uint8_t out_dst[6]);
/* server 学到对端后调用：按 L3 对端地址刷新 eth 目的 MAC（DPDK 没有内核 ARP，目前仅 peer_mac 兜底） */
int         pp_dpdk_io_refresh_arp(struct pp_dpdk_io *p, uint32_t l3_peer_be);

int            pp_dpdk_io_inject_ip(struct pp_dpdk_io *p, const uint8_t *ip, size_t len);
const uint8_t *pp_dpdk_io_next_ip  (struct pp_dpdk_io *p, size_t *out_len);

#endif /* PP_HAVE_DPDK */
#endif /* PPROXY_IO_DPDK_H */
