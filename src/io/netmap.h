/* src/io/netmap.h -- netmap 收发 IP 帧的薄封装
 *
 * 仅在 -Dnetmap=true（PP_HAVE_NETMAP）时启用。
 *
 * 与 src/io/xsk.h / src/io/pcap.h 形态一致：
 *   - 同一份 src/io/netmap.c 同时承载左手 pp_pkt_io_ops_t（pp_io_netmap）
 *     与右手 tunnel 用的 pp_netmap_io_*；本头文件只暴露后者。
 *   - 这里不 include <net/netmap_user.h>，避免把 netmap 私有结构泄漏给
 *     调用方（tunnel/udp.c 等）。只暴露不透明指针 + API。
 *
 * 约束：
 *   - 经典 nm_open() API（header-only），无需 libnetmap.so；运行时仍需要内核
 *     加载 netmap 模块并提供 /dev/netmap。
 *   - ifname 形如 "netmap:eth0"、"vale0:1"、"netmap:eth0-0"（指定 ring）。
 *   - 仅 IPv4 / Ethernet 物理口；MAC 解析方式与 xsk 一致：可显式 peer_mac
 *     或给 arp_nexthop_be 让我们查 /proc/net/arp 邻居表（失败回退 peer_mac）。
 *   - 全 0 dst MAC 时仅 vale: / 局部路径能通；跨网段必须给出有效下一跳 MAC。
 */
#ifndef PPROXY_IO_NETMAP_H
#define PPROXY_IO_NETMAP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pproxy/pproxy.h"

#ifdef PP_HAVE_NETMAP

struct pp_netmap_io;   /* opaque */

int  pp_netmap_io_new(struct pp_netmap_io **out,
                      const char *ifname,
                      uint32_t nrings,
                      const uint8_t peer_mac[6],
                      uint32_t arp_nexthop_be);
void pp_netmap_io_free(struct pp_netmap_io *p);

int         pp_netmap_io_get_fd    (const struct pp_netmap_io *p);
const char *pp_netmap_io_get_ifname(const struct pp_netmap_io *p);
/* 注包用的以太源/目的 MAC（pp_netmap_io_new 时按 ifname/ARP/peer 填好） */
void        pp_netmap_io_get_macs  (const struct pp_netmap_io *p,
                                    uint8_t out_src[6], uint8_t out_dst[6]);
/* server 学到对端 L3 后调用：按 L3 对端地址刷新 eth 目的 MAC */
int         pp_netmap_io_refresh_arp(struct pp_netmap_io *p,
                                     uint32_t l3_peer_be);
/* 取 ifname 上的第一个 IPv4（用于自填 IP 头源地址，与 xsk 等价） */
int         pp_netmap_ifname_first_ipv4(const char *ifname,
                                        uint32_t *out_saddr_be);

int            pp_netmap_io_inject_ip(struct pp_netmap_io *p,
                                      const uint8_t *ip, size_t len);
const uint8_t *pp_netmap_io_next_ip  (struct pp_netmap_io *p, size_t *out_len);

#endif /* PP_HAVE_NETMAP */
#endif /* PPROXY_IO_NETMAP_H */
