/* src/io/memif.h -- VPP memif（共享内存虚拟网卡）右手隧道 I/O 薄封装
 *
 * 仅在 -Dmemif=true（PP_HAVE_MEMIF）时编译。
 *
 * API 与 DPDK/XSK 后端对称：
 *   inject_ip  接受裸 IP 帧，内部在前面加 14 字节 Ethernet 头
 *   next_ip    返回裸 IP 帧指针（已跳过 Ethernet 头）
 *
 * busy-poll 语义：get_fd 始终返回 -1；控制面握手事件由
 * pp_memif_io_poll() 在 send/recv 路径中顺带处理。
 */
#ifndef PPROXY_IO_MEMIF_H
#define PPROXY_IO_MEMIF_H

#ifdef PP_HAVE_MEMIF

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "pproxy/pproxy.h"

struct pp_memif_io;   /* opaque */

/*
 * 创建 memif 实例。
 *   socket_path  -- Unix socket 路径（如 /run/vpp/memif.sock）
 *   interface_id -- memif 接口 ID（VPP 侧须匹配）
 *   is_master    -- true=pproxy 创建 socket（master），false=连 VPP（slave）
 *   ring_size    -- TX/RX ring 槽数；0 → 默认 1024
 *   buffer_size  -- 每个 buffer 字节数；0 → 默认 2048
 *   peer_mac     -- 对端 Ethernet MAC；NULL 或全零时发往 broadcast
 */
int  pp_memif_io_new(struct pp_memif_io **out,
                     const char    *socket_path,
                     uint32_t       interface_id,
                     bool           is_master,
                     uint32_t       ring_size,
                     uint32_t       buffer_size,
                     const uint8_t  peer_mac[6]);

void pp_memif_io_free(struct pp_memif_io *p);

/* 是否已完成握手（on_connect 回调已触发） */
bool pp_memif_io_is_connected(const struct pp_memif_io *p);

/*
 * 发送裸 IP 帧（无 Ethernet 头）。
 * 内部在帧前添加 Ethernet 头（dst=peer_mac，src=本端虚拟 MAC，type=0x0800），
 * 然后写入 memif TX ring。
 *
 * 返回 PP_OK(0) 成功；PP_ERR_AGAIN TX ring 满或未连接；< 0 其他错误。
 */
int  pp_memif_io_inject_ip(struct pp_memif_io *p, const uint8_t *ip, size_t len);

/*
 * 取下一个接收的 IP 帧（已跳过 14 字节 Ethernet 头）。
 * 返回帧指针，*out_len 为 IP 帧字节数；无包时返回 NULL。
 * 当前 burst 消费完后自动 refill 并取下一批。
 */
const uint8_t *pp_memif_io_next_ip(struct pp_memif_io *p, size_t *out_len);

/*
 * 轮询控制面事件（握手/断线/重连）。
 *   timeout_us == 0 : 非阻塞（busy-poll 主路径）
 *   timeout_us >  0 : 至多等待对应微秒
 */
int  pp_memif_io_poll(struct pp_memif_io *p, int timeout_us);

/* 始终返回 -1：memif 数据面为 busy-poll，无 epoll-able fd */
int  pp_memif_io_get_fd(const struct pp_memif_io *p);

/* 更新对端 dst_mac（server 学到 peer 后调用） */
void pp_memif_io_set_peer_mac(struct pp_memif_io *p, const uint8_t mac[6]);

#endif /* PP_HAVE_MEMIF */
#endif /* PPROXY_IO_MEMIF_H */
