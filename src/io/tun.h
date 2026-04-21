/* src/io/tun.h -- Linux TUN 设备 I/O
 *
 * 本文件既承载左手侧 L3 TUN 后端（pp_io_tun，走 pp_pkt_io_ops_t 的
 * rx_burst / tx_burst 批量封装），也承载右手侧 tunnel/{udp,icmp} 复用
 * 的薄封装 pp_tun_io_*（逐包 read/write IP 帧）。
 *
 * 左手侧 vtable 只在 include/pproxy/pkt_io.h 中声明。这里只公开右手 API。
 *
 * 语义：
 *   - pp_tun_io_open：打开 /dev/net/tun、TUNSETIFF、O_NONBLOCK；
 *     ifname 可为 NULL 或空串让内核自动分配名字；成功时把真正得到的
 *     ifname 写回 out_ifname（可能被内核改名）。
 *     no_pi=true 时设置 IFF_NO_PI（推荐；没有 4 字节 packet-info 前缀）。
 *   - pp_tun_io_write_ip：单个 IP 帧写入；返回字节数 / PP_ERR_AGAIN / PP_ERR_IO。
 *   - pp_tun_io_read_ip ：单个 IP 帧读出；返回字节数；EAGAIN 时返回 0；错误时返回 PP_ERR_IO。
 */
#ifndef PPROXY_IO_TUN_H
#define PPROXY_IO_TUN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/if.h>    /* IFNAMSIZ */
#include "pproxy/pproxy.h"

int pp_tun_io_open(const char *ifname,
                   bool        no_pi,
                   char        out_ifname[IFNAMSIZ],
                   int        *out_fd);

int pp_tun_io_write_ip(int fd, const uint8_t *ip, size_t len);
int pp_tun_io_read_ip (int fd, uint8_t *buf, size_t cap);

#endif /* PPROXY_IO_TUN_H */
