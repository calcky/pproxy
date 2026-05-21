/* src/io/uring_sock.h -- io_uring socket I/O（可选 TX ZC；RX 直接 recv 到调用方 buffer） */
#ifndef PPROXY_URING_SOCK_H
#define PPROXY_URING_SOCK_H

#include <stdbool.h>
#include <stddef.h>
#include <sys/socket.h>
#include "pproxy/pproxy.h"

#ifdef PP_HAVE_IO_URING

typedef struct pp_uring_sock pp_uring_sock_t;

#define PP_URING_TX_ZC_MIN_DEFAULT  8192u

typedef struct pp_uring_send_item {
    const void            *buf;
    size_t                 len;
    const struct sockaddr *peer;
    socklen_t              peer_sl;
} pp_uring_send_item_t;

typedef struct pp_uring_opts {
    unsigned sq_entries;
    bool     tx_zc;
    unsigned tx_zc_min_bytes; /* 低于此长度走 copy send；默认 8192（iperf ~1.4K 不应走 ZC） */
} pp_uring_opts_t;

void pp_uring_opts_defaults(pp_uring_opts_t *o, unsigned sq_entries);

int  pp_uring_sock_new(int fd, const pp_uring_opts_t *opt, pp_uring_sock_t **out);
void pp_uring_sock_free(pp_uring_sock_t *p);

int pp_uring_udp_send(pp_uring_sock_t *p, int fd,
                      const void *buf, size_t len,
                      const struct sockaddr *peer, socklen_t peer_sl);
/* 多 SQE 一次 submit + 批量 reap（copy send；不走 TX ZC） */
int pp_uring_udp_send_burst(pp_uring_sock_t *p, int fd,
                            const pp_uring_send_item_t *items, int n,
                            int *results);
int pp_uring_udp_recv(pp_uring_sock_t *p, int fd,
                      void *buf, size_t cap,
                      struct sockaddr *peer, socklen_t *peer_sl);
int pp_uring_tcp_read(pp_uring_sock_t *p, int fd, void *buf, size_t cap);
int pp_uring_tcp_write(pp_uring_sock_t *p, int fd, const void *buf, size_t len);

#endif /* PP_HAVE_IO_URING */

#endif /* PPROXY_URING_SOCK_H */
