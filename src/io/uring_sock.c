/* src/io/uring_sock.c -- io_uring 封装：单 ring + mutex，供 right_tx/right_rx 共享 fd */
#ifdef PP_HAVE_IO_URING

#include "uring_sock.h"

#include <errno.h>
#include <liburing.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include "pproxy/log.h"

struct pp_uring_sock {
    struct io_uring  ring;
    pthread_mutex_t  lock;
    int              fd;
};

static unsigned clamp_sq(unsigned n)
{
    if (n < 8) return 8;
    if (n > 4096) return 4096;
    return n;
}

static int uring_wait_res(struct pp_uring_sock *p, int *res_out)
{
    struct io_uring_cqe *cqe = NULL;
    int wr = io_uring_wait_cqe(&p->ring, &cqe);
    if (wr < 0) {
        PP_WARN("io_uring: wait_cqe failed errno=%d (%s)", -wr, strerror(-wr));
        return PP_ERR_IO;
    }
    *res_out = cqe->res;
    io_uring_cqe_seen(&p->ring, cqe);
    return PP_OK;
}

static int map_neg_errno(int res)
{
    if (res >= 0) return res;
    if (res == -EAGAIN || res == -EWOULDBLOCK) return PP_ERR_AGAIN;
    if (res == 0) return PP_ERR_CLOSED;
    return PP_ERR_IO;
}

int pp_uring_sock_new(int fd, unsigned sq_entries, pp_uring_sock_t **out)
{
    if (fd < 0 || !out) return PP_ERR_INVAL;

    pp_uring_sock_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;

    sq_entries = clamp_sq(sq_entries);
    int r = io_uring_queue_init(sq_entries, &p->ring, 0);
    if (r < 0) {
        PP_ERROR("io_uring: queue_init(%u) failed errno=%d (%s)",
                 sq_entries, -r, strerror(-r));
        free(p);
        return PP_ERR_IO;
    }

    p->fd = fd;
    if (pthread_mutex_init(&p->lock, NULL) != 0) {
        io_uring_queue_exit(&p->ring);
        free(p);
        return PP_ERR_IO;
    }

    *out = p;
    return PP_OK;
}

void pp_uring_sock_free(pp_uring_sock_t *p)
{
    if (!p) return;
    pthread_mutex_destroy(&p->lock);
    io_uring_queue_exit(&p->ring);
    free(p);
}

int pp_uring_udp_send(pp_uring_sock_t *p, int fd,
                      const void *buf, size_t len,
                      const struct sockaddr *peer, socklen_t peer_sl)
{
    if (!p || fd < 0 || !buf || len == 0) return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_AGAIN;
    }

    if (peer && peer_sl > 0) {
        struct msghdr msg = {0};
        struct iovec iov = { .iov_base = (void *)buf, .iov_len = len };
        msg.msg_name = (void *)peer;
        msg.msg_namelen = peer_sl;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        io_uring_prep_sendmsg(sqe, fd, &msg, 0);
    } else {
        io_uring_prep_send(sqe, fd, buf, len, 0);
    }

    if (io_uring_submit(&p->ring) < 0) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_IO;
    }

    int res = 0;
    int rc = uring_wait_res(p, &res);
    pthread_mutex_unlock(&p->lock);
    if (rc != PP_OK) return rc;
    return map_neg_errno(res);
}

int pp_uring_udp_recv(pp_uring_sock_t *p, int fd,
                      void *buf, size_t cap,
                      struct sockaddr *peer, socklen_t *peer_sl)
{
    if (!p || fd < 0 || !buf || cap == 0) return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_AGAIN;
    }

    struct msghdr msg = {0};
    struct iovec iov = { .iov_base = buf, .iov_len = cap };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    if (peer && peer_sl) {
        msg.msg_name = peer;
        msg.msg_namelen = *peer_sl;
    }
    io_uring_prep_recvmsg(sqe, fd, &msg, 0);

    if (io_uring_submit(&p->ring) < 0) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_IO;
    }

    int res = 0;
    int rc = uring_wait_res(p, &res);
    if (peer_sl && peer)
        *peer_sl = msg.msg_namelen;
    pthread_mutex_unlock(&p->lock);
    if (rc != PP_OK) return rc;
    return map_neg_errno(res);
}

int pp_uring_tcp_read(pp_uring_sock_t *p, int fd, void *buf, size_t cap)
{
    if (!p || fd < 0 || !buf || cap == 0) return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_AGAIN;
    }
    io_uring_prep_read(sqe, fd, buf, cap, 0);

    if (io_uring_submit(&p->ring) < 0) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_IO;
    }

    int res = 0;
    int rc = uring_wait_res(p, &res);
    pthread_mutex_unlock(&p->lock);
    if (rc != PP_OK) return rc;
    return map_neg_errno(res);
}

int pp_uring_tcp_write(pp_uring_sock_t *p, int fd, const void *buf, size_t len)
{
    if (!p || fd < 0 || !buf || len == 0) return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_AGAIN;
    }
    io_uring_prep_write(sqe, fd, buf, len, 0);

    if (io_uring_submit(&p->ring) < 0) {
        pthread_mutex_unlock(&p->lock);
        return PP_ERR_IO;
    }

    int res = 0;
    int rc = uring_wait_res(p, &res);
    pthread_mutex_unlock(&p->lock);
    if (rc != PP_OK) return rc;
    return map_neg_errno(res);
}

#endif /* PP_HAVE_IO_URING */
