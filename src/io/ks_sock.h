/* src/io/ks_sock.h -- kernel socket (UDP/TCP) I/O 薄封装
 *
 * 面向右手侧 tunnel 的 open / bind / listen / accept / connect / send / recv。
 * 目标：tunnel 下的 .c 不再直接调 socket() / bind() / sendto() / read() 这些
 *       syscall，都走这里，以便:
 *        1) 单点管控 sockopt（nonblock / reuseaddr / nodelay / bindtodevice）
 *        2) 以后想换成 io_uring / fstack 只需改这一层
 *        3) 统一错误语义：返回 >=0 / 0(EAGAIN 或 EOF) / 负数 PP_ERR_*
 *
 * 所有 fd 都是 NONBLOCK + CLOEXEC。
 */
#ifndef PPROXY_IO_KS_SOCK_H
#define PPROXY_IO_KS_SOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include "pproxy/pproxy.h"    /* pp_endpoint_t + PP_ERR_* */

/* ---------- 端点工具 ---------- */
/* 将 pp_endpoint_t 填到 sockaddr_storage，返回 sockaddr 长度；失败返回 0。 */
socklen_t pp_ep_to_sockaddr(const pp_endpoint_t *ep, struct sockaddr_storage *ss);

/* 打印 sockaddr 为 "ip:port"，最多写 cap-1 字节；返回写入字节数（不含\0）。 */
int pp_sockaddr_format(const struct sockaddr *sa, socklen_t sl,
                       char *out, size_t cap);

/* ---------- 共用 sockopt ---------- */
void pp_ks_set_nonblock   (int fd);
void pp_ks_set_reuseaddr  (int fd);
void pp_ks_set_tcp_nodelay(int fd, bool on);
void pp_ks_bind_to_device (int fd, const char *ifname);  /* NULL / "" = no-op */

/* ---------- UDP (SOCK_DGRAM) ---------- */
/* 打开一个 UDP socket；af = AF_INET / AF_INET6。成功 *out_fd >= 0。 */
int pp_ks_udp_open(int af, int *out_fd);

/* bind 到本地地址（server 模式）。会预先设 SO_REUSEADDR。 */
int pp_ks_udp_bind   (int fd, const struct sockaddr *sa, socklen_t sl);

/* connect（client 模式 —— 让内核记住 peer，之后可以直接 send/recv）。 */
int pp_ks_udp_connect(int fd, const struct sockaddr *sa, socklen_t sl);

/* 发送：peer != NULL 时走 sendto，否则 send(already-connected)。
 * 返回 >=0 发送字节；EAGAIN/EWOULDBLOCK 返回 PP_ERR_AGAIN；其它错误返回 PP_ERR_IO。 */
int pp_ks_udp_send(int fd, const void *buf, size_t len,
                   const struct sockaddr *peer, socklen_t peer_sl);

/* 接收：peer_* 非 NULL 时返回对端地址。
 * 返回 >=0 接收字节；无数据（EAGAIN）返回 0；其它错误返回 PP_ERR_IO。 */
int pp_ks_udp_recv(int fd, void *buf, size_t cap,
                   struct sockaddr *peer, socklen_t *peer_sl);

/* ---------- TCP (SOCK_STREAM) ---------- */
/* listen_fd：socket + SO_REUSEADDR + bind + listen + NONBLOCK。 */
int pp_ks_tcp_listen (int af,
                      const struct sockaddr *sa, socklen_t sl,
                      int backlog, int *out_fd);

/* accept4(..., SOCK_CLOEXEC|SOCK_NONBLOCK)；无连接时返回 PP_ERR_AGAIN。 */
int pp_ks_tcp_accept (int listen_fd,
                      struct sockaddr *peer, socklen_t *peer_sl,
                      int *out_fd);

/* connect 到 server（阻塞版本，返回后 fd 已设 NONBLOCK）。 */
int pp_ks_tcp_connect(int af,
                      const struct sockaddr *sa, socklen_t sl,
                      int *out_fd);

/* writev + 错误折叠。返回 >=0 / PP_ERR_AGAIN / PP_ERR_IO。 */
int pp_ks_tcp_sendv  (int fd, const struct iovec *iov, int iovcnt);

/* read；EOF 返回 PP_ERR_CLOSED；EAGAIN 返回 0。 */
int pp_ks_tcp_recv   (int fd, void *buf, size_t cap);

#endif /* PPROXY_IO_KS_SOCK_H */
