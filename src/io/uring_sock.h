/* src/io/uring_sock.h -- io_uring 加速的 kernel socket 收发（UDP/TCP 热路径） */
#ifndef PPROXY_URING_SOCK_H
#define PPROXY_URING_SOCK_H

#include <stddef.h>
#include <sys/socket.h>
#include "pproxy/pproxy.h"

#ifdef PP_HAVE_IO_URING

typedef struct pp_uring_sock pp_uring_sock_t;

int  pp_uring_sock_new(int fd, unsigned sq_entries, pp_uring_sock_t **out);
void pp_uring_sock_free(pp_uring_sock_t *p);

int pp_uring_udp_send(pp_uring_sock_t *p, int fd,
                      const void *buf, size_t len,
                      const struct sockaddr *peer, socklen_t peer_sl);
int pp_uring_udp_recv(pp_uring_sock_t *p, int fd,
                      void *buf, size_t cap,
                      struct sockaddr *peer, socklen_t *peer_sl);
int pp_uring_tcp_read(pp_uring_sock_t *p, int fd, void *buf, size_t cap);
int pp_uring_tcp_write(pp_uring_sock_t *p, int fd, const void *buf, size_t len);

#endif /* PP_HAVE_IO_URING */

#endif /* PPROXY_URING_SOCK_H */
