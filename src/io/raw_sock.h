/* src/io/raw_sock.h -- Linux 原始套接字 I/O
 *
 * 本文件同时公开两类"raw socket"相关能力，对应左/右手两侧使用场景：
 *
 *   (A) 右手侧 tunnel/{udp,icmp} 的 raw_socket 路径：pp_raw_ip_*
 *       AF_INET SOCK_RAW、**不** 设 IP_HDRINCL。send 仅 L4+载荷，内核加 IPv4 头。
 *       recv 仍为「IP+载荷」整包，供 tunnel 与现有 parse_* 使用。
 *
 *   (B) 左手侧 L2 抓包/注包：AF_PACKET SOCK_RAW + ETH_P_ALL（pp_io_raw_socket），
 *       收完整以太帧；rx 仅把 IPv4（0x0800）交给上层并填 meta（l2_off=0, l3_off）。
 *       由 include/pproxy/pkt_io.h 声明，实现见 src/io/raw_sock.c。无独立 C API。
 *
 * 需要 CAP_NET_RAW。
 */
#ifndef PPROXY_IO_RAW_SOCK_H
#define PPROXY_IO_RAW_SOCK_H

#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include "pproxy/pproxy.h"

/* ---------- (A) 右手侧 AF_INET SOCK_RAW（不手拼 IP 头） ---------- */

/* ipproto：IPPROTO_UDP / IPPROTO_ICMP / 0（收所有协议，不推荐）。
 * bindtodevice_ifname 可为 NULL/""（走路由表）。
 * 成功 *out_fd >= 0。 */
int pp_raw_ip_open(int ipproto, const char *bindtodevice_ifname, int *out_fd);

/* 可选：把 raw fd 绑定到本地 IPv4（只限制源地址，端口无效）。失败不致命。 */
void pp_raw_ip_bind_src_v4(int fd, uint32_t src_ip_be);

/* 发送：buf 为 L4+数据（如 UDP/ICMP 体）；dst_ip_be=目的主机 IPv4（网络序）。
 * 返回 >=0 / PP_ERR_AGAIN / PP_ERR_IO。 */
int pp_raw_ip_send(int fd, const uint8_t *buf, size_t len, uint32_t dst_ip_be);

/* 接收：返回帧长度 >=0 / 0(EAGAIN) / PP_ERR_IO。
 * 如果 out_src_sa 非 NULL 会填入源地址（sockaddr_in）。 */
int pp_raw_ip_recv(int fd, uint8_t *buf, size_t cap,
                   struct sockaddr *out_src_sa, socklen_t *out_src_sl);

#endif /* PPROXY_IO_RAW_SOCK_H */
