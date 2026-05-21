/* src/io/uring_sock.c -- io_uring socket：TX send_zc（池化+异步 NOTIF）；RX direct recv */
#ifdef PP_HAVE_IO_URING

#include "uring_sock.h"

#include <errno.h>
#include <liburing.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include "pproxy/log.h"
#include "pproxy/packet.h"

#ifndef IORING_OP_SENDMSG_ZC
#define IORING_OP_SENDMSG_ZC 47
#endif

#define PP_URING_TX_SLOTS   64u
#define PP_URING_TX_SLOT_CAP 65536u

struct pp_uring_sock {
    struct io_uring  ring;
    pthread_mutex_t  lock;
    int              fd;

    bool             tx_zc_send;
    bool             tx_zc_sendmsg;
    unsigned         tx_zc_min_bytes;

    /* TX ZC 池：数据 copy 进槽位再 send_zc，NOTIF 异步回收，避免每包阻塞等双 CQE */
    void            *tx_pool;
    unsigned         tx_slot_cap;
    bool             slot_busy[PP_URING_TX_SLOTS];
    unsigned         inflight[PP_URING_TX_SLOTS];
    unsigned         inflight_n;
};

void pp_uring_opts_defaults(pp_uring_opts_t *o, unsigned sq_entries)
{
    if (!o) return;
    o->sq_entries        = sq_entries ? sq_entries : 256;
    o->tx_zc             = false;
    o->tx_zc_min_bytes   = PP_URING_TX_ZC_MIN_DEFAULT;
}

static unsigned clamp_sq(unsigned n)
{
    if (n < 8) return 8;
    if (n > 4096) return 4096;
    return n;
}

static bool probe_opcode(struct io_uring *ring, int op)
{
    struct io_uring_probe *pr = io_uring_get_probe_ring(ring);
    if (!pr)
        return false;
    bool ok = io_uring_opcode_supported(pr, op) != 0;
    io_uring_free_probe(pr);
    return ok;
}

static int map_neg_errno(int res)
{
    if (res >= 0) return res;
    if (res == -EAGAIN || res == -EWOULDBLOCK) return PP_ERR_AGAIN;
    if (res == 0) return PP_ERR_CLOSED;
    return PP_ERR_IO;
}

static void *tx_slot_ptr(struct pp_uring_sock *p, unsigned idx)
{
    return (char *)p->tx_pool + (size_t)idx * (size_t)p->tx_slot_cap;
}

static int tx_pool_init(struct pp_uring_sock *p)
{
    long psz = sysconf(_SC_PAGESIZE);
    if (psz < 4096) psz = 4096;

    p->tx_slot_cap = PP_URING_TX_SLOT_CAP;
    size_t total = (size_t)PP_URING_TX_SLOTS * (size_t)p->tx_slot_cap;
    if (posix_memalign(&p->tx_pool, (size_t)psz, total) != 0)
        return PP_ERR_NOMEM;
    memset(p->tx_pool, 0, total);
    return PP_OK;
}

/* 回收已完成的 ZC NOTIF；wait_one 时在无 NOTIF 可 peek 时阻塞等一条 */
static void tx_zc_drain_notifs(struct pp_uring_sock *p, bool wait_one)
{
    for (;;) {
        struct io_uring_cqe *cqe = NULL;
        int pr = io_uring_peek_cqe(&p->ring, &cqe);
        if (pr != 0 || !cqe) {
            if (!wait_one || p->inflight_n == 0)
                return;
            if (io_uring_wait_cqe(&p->ring, &cqe) < 0)
                return;
        }
        if (!(cqe->flags & IORING_CQE_F_NOTIF)) {
            /* 发送 CQE 已在 send 路径同步消化，此处不应出现 */
            if (!wait_one)
                return;
            io_uring_cqe_seen(&p->ring, cqe);
            continue;
        }
        io_uring_cqe_seen(&p->ring, cqe);
        if (p->inflight_n > 0) {
            unsigned sid = p->inflight[0];
            memmove(p->inflight, p->inflight + 1,
                    (size_t)(p->inflight_n - 1) * sizeof(unsigned));
            p->inflight_n--;
            p->slot_busy[sid] = false;
        }
        wait_one = false;
    }
}

static int tx_zc_acquire_slot(struct pp_uring_sock *p, unsigned *idx_out)
{
    for (;;) {
        tx_zc_drain_notifs(p, false);
        for (unsigned i = 0; i < PP_URING_TX_SLOTS; i++) {
            if (!p->slot_busy[i]) {
                *idx_out = i;
                return PP_OK;
            }
        }
        if (p->inflight_n == 0)
            return PP_ERR_AGAIN;
        tx_zc_drain_notifs(p, true);
    }
}

static int uring_wait_one_cqe(struct pp_uring_sock *p, struct io_uring_cqe **cqe_out)
{
    struct io_uring_cqe *cqe = NULL;
    int wr = io_uring_wait_cqe(&p->ring, &cqe);
    if (wr < 0) {
        PP_WARN("io_uring: wait_cqe failed errno=%d (%s)", -wr, strerror(-wr));
        return PP_ERR_IO;
    }
    *cqe_out = cqe;
    return PP_OK;
}

static int uring_wait_res(struct pp_uring_sock *p, int *res_out)
{
    struct io_uring_cqe *cqe = NULL;
    int rc = uring_wait_one_cqe(p, &cqe);
    if (rc != PP_OK) return rc;
    *res_out = cqe->res;
    io_uring_cqe_seen(&p->ring, cqe);
    return PP_OK;
}

static int uring_wait_send_cqe(struct pp_uring_sock *p, int *res_out)
{
    struct io_uring_cqe *cqe = NULL;
    int rc = uring_wait_one_cqe(p, &cqe);
    if (rc != PP_OK) return rc;
    if (cqe->flags & IORING_CQE_F_NOTIF) {
        io_uring_cqe_seen(&p->ring, cqe);
        return PP_ERR_IO;
    }
    *res_out = cqe->res;
    io_uring_cqe_seen(&p->ring, cqe);
    return PP_OK;
}

static bool tx_zc_want(const struct pp_uring_sock *p, size_t len)
{
    return (p->tx_zc_send || p->tx_zc_sendmsg)
        && len >= (size_t)p->tx_zc_min_bytes
        && p->tx_pool != NULL;
}

int pp_uring_sock_new(int fd, const pp_uring_opts_t *opt, pp_uring_sock_t **out)
{
    if (fd < 0 || !out) return PP_ERR_INVAL;

    pp_uring_opts_t defs;
    pp_uring_opts_defaults(&defs, 256);
    const pp_uring_opts_t *o = opt ? opt : &defs;

    pp_uring_sock_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;

    unsigned sq = clamp_sq(o->sq_entries);
    int r = io_uring_queue_init(sq, &p->ring, 0);
    if (r < 0) {
        PP_ERROR("io_uring: queue_init(%u) failed errno=%d (%s)",
                 sq, -r, strerror(-r));
        free(p);
        return PP_ERR_IO;
    }

    p->fd = fd;
    p->tx_zc_min_bytes = o->tx_zc_min_bytes ? o->tx_zc_min_bytes
                                            : PP_URING_TX_ZC_MIN_DEFAULT;

    if (o->tx_zc) {
        p->tx_zc_send    = probe_opcode(&p->ring, IORING_OP_SEND_ZC);
        p->tx_zc_sendmsg = probe_opcode(&p->ring, IORING_OP_SENDMSG_ZC);
        if (!p->tx_zc_send && !p->tx_zc_sendmsg) {
            PP_WARN("io_uring: tx_zc requested but SEND_ZC/SENDMSG_ZC unsupported; copy fallback");
        } else if (tx_pool_init(p) != PP_OK) {
            PP_WARN("io_uring: tx_zc pool alloc failed; copy fallback");
            p->tx_zc_send = p->tx_zc_sendmsg = false;
        } else {
            PP_INFO("io_uring: tx_zc enabled (send=%d sendmsg=%d min_bytes=%u slots=%u)",
                    p->tx_zc_send, p->tx_zc_sendmsg, p->tx_zc_min_bytes,
                    (unsigned)PP_URING_TX_SLOTS);
        }
    }

    if (pthread_mutex_init(&p->lock, NULL) != 0) {
        free(p->tx_pool);
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
    pthread_mutex_lock(&p->lock);
    while (p->inflight_n > 0)
        tx_zc_drain_notifs(p, true);
    pthread_mutex_unlock(&p->lock);
    pthread_mutex_destroy(&p->lock);
    free(p->tx_pool);
    io_uring_queue_exit(&p->ring);
    free(p);
}

static int uring_udp_send_copy(struct pp_uring_sock *p, int fd,
                               const void *buf, size_t len,
                               const struct sockaddr *peer, socklen_t peer_sl)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) return PP_ERR_AGAIN;

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

    if (io_uring_submit(&p->ring) < 0) return PP_ERR_IO;
    int res = 0;
    int rc = uring_wait_res(p, &res);
    if (rc != PP_OK) return rc;
    return map_neg_errno(res);
}

static int uring_udp_send_zc(struct pp_uring_sock *p, int fd,
                             const void *buf, size_t len,
                             const struct sockaddr *peer, socklen_t peer_sl)
{
    if (len > p->tx_slot_cap)
        return uring_udp_send_copy(p, fd, buf, len, peer, peer_sl);

    unsigned sid = 0;
    int rc = tx_zc_acquire_slot(p, &sid);
    if (rc != PP_OK) return rc;

    void *slot = tx_slot_ptr(p, sid);
    memcpy(slot, buf, len);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) {
        p->slot_busy[sid] = false;
        return PP_ERR_AGAIN;
    }

    if (peer && peer_sl > 0) {
        if (!p->tx_zc_sendmsg) {
            p->slot_busy[sid] = false;
            return uring_udp_send_copy(p, fd, buf, len, peer, peer_sl);
        }
        struct msghdr msg = {0};
        struct iovec iov = { .iov_base = slot, .iov_len = len };
        msg.msg_name = (void *)peer;
        msg.msg_namelen = peer_sl;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        io_uring_prep_sendmsg_zc(sqe, fd, &msg, 0);
    } else {
        if (!p->tx_zc_send) {
            p->slot_busy[sid] = false;
            return uring_udp_send_copy(p, fd, buf, len, NULL, 0);
        }
        io_uring_prep_send_zc(sqe, fd, slot, len, 0, 0);
    }

    if (io_uring_submit(&p->ring) < 0) {
        p->slot_busy[sid] = false;
        return PP_ERR_IO;
    }

    int res = 0;
    rc = uring_wait_send_cqe(p, &res);
    if (rc != PP_OK) {
        p->slot_busy[sid] = false;
        return rc;
    }

    p->slot_busy[sid] = true;
    p->inflight[p->inflight_n++] = sid;
    return map_neg_errno(res);
}

int pp_uring_udp_send(pp_uring_sock_t *p, int fd,
                      const void *buf, size_t len,
                      const struct sockaddr *peer, socklen_t peer_sl)
{
    if (!p || fd < 0 || !buf || len == 0) return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);
    int rc;
    if (tx_zc_want(p, len))
        rc = uring_udp_send_zc(p, fd, buf, len, peer, peer_sl);
    else
        rc = uring_udp_send_copy(p, fd, buf, len, peer, peer_sl);
    pthread_mutex_unlock(&p->lock);
    return rc;
}

/* 取一条发送 CQE（跳过 NOTIF）；无 CQE 时 wait */
static int reap_one_send_cqe(struct pp_uring_sock *p, int *res_out)
{
    for (;;) {
        struct io_uring_cqe *cqe = NULL;
        int pr = io_uring_peek_cqe(&p->ring, &cqe);
        if (pr != 0 || !cqe) {
            int rc = uring_wait_one_cqe(p, &cqe);
            if (rc != PP_OK) return rc;
        }
        if (cqe->flags & IORING_CQE_F_NOTIF) {
            io_uring_cqe_seen(&p->ring, cqe);
            if (p->inflight_n > 0) {
                unsigned sid = p->inflight[0];
                memmove(p->inflight, p->inflight + 1,
                        (size_t)(p->inflight_n - 1) * sizeof(unsigned));
                p->inflight_n--;
                p->slot_busy[sid] = false;
            }
            continue;
        }
        *res_out = cqe->res;
        io_uring_cqe_seen(&p->ring, cqe);
        return PP_OK;
    }
}

static int uring_udp_send_burst_locked(struct pp_uring_sock *p, int fd,
                                       const pp_uring_send_item_t *items, int n,
                                       int *results)
{
    tx_zc_drain_notifs(p, false);

    int idx = 0;
    while (idx < n) {
        unsigned space = io_uring_sq_space_left(&p->ring);
        if (space == 0) {
            int dummy = 0;
            int dr = reap_one_send_cqe(p, &dummy);
            if (dr != PP_OK) {
                for (int j = idx; j < n; j++)
                    results[j] = dr;
                return dr;
            }
            space = io_uring_sq_space_left(&p->ring);
        }

        int chunk = n - idx;
        if ((unsigned)chunk > space)
            chunk = (int)space;
        if (chunk <= 0) {
            for (int j = idx; j < n; j++)
                results[j] = PP_ERR_AGAIN;
            return PP_OK;
        }

        struct msghdr msgs[PP_PKT_BURST_MAX];
        struct iovec  iovs[PP_PKT_BURST_MAX];

        for (int i = 0; i < chunk; i++) {
            const pp_uring_send_item_t *it = &items[idx + i];
            struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
            if (!sqe) {
                for (int j = idx + i; j < n; j++)
                    results[j] = PP_ERR_AGAIN;
                return PP_OK;
            }
            if (it->peer && it->peer_sl > 0) {
                iovs[i].iov_base = (void *)it->buf;
                iovs[i].iov_len  = it->len;
                memset(&msgs[i], 0, sizeof msgs[i]);
                msgs[i].msg_name    = (void *)it->peer;
                msgs[i].msg_namelen = it->peer_sl;
                msgs[i].msg_iov     = &iovs[i];
                msgs[i].msg_iovlen  = 1;
                io_uring_prep_sendmsg(sqe, fd, &msgs[i], 0);
            } else {
                io_uring_prep_send(sqe, fd, it->buf, it->len, 0);
            }
        }

        if (io_uring_submit(&p->ring) < 0) {
            for (int j = idx; j < n; j++)
                results[j] = PP_ERR_IO;
            return PP_ERR_IO;
        }

        for (int i = 0; i < chunk; i++) {
            int res = 0;
            int rc = reap_one_send_cqe(p, &res);
            if (rc != PP_OK)
                results[idx + i] = rc;
            else
                results[idx + i] = map_neg_errno(res);
        }
        idx += chunk;
    }
    return PP_OK;
}

int pp_uring_udp_send_burst(pp_uring_sock_t *p, int fd,
                            const pp_uring_send_item_t *items, int n,
                            int *results)
{
    if (!p || fd < 0 || !items || n <= 0 || !results)
        return PP_ERR_INVAL;
    if (n > PP_PKT_BURST_MAX)
        return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);
    int rc = uring_udp_send_burst_locked(p, fd, items, n, results);
    pthread_mutex_unlock(&p->lock);
    return rc;
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

    int rc = PP_ERR_IO;
    if (io_uring_submit(&p->ring) >= 0) {
        int res = 0;
        rc = uring_wait_res(p, &res);
        if (peer_sl && peer)
            *peer_sl = msg.msg_namelen;
        if (rc == PP_OK)
            rc = map_neg_errno(res);
    }

    pthread_mutex_unlock(&p->lock);
    return rc;
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

    int rc = PP_ERR_IO;
    if (io_uring_submit(&p->ring) >= 0) {
        int res = 0;
        rc = uring_wait_res(p, &res);
        if (rc == PP_OK)
            rc = map_neg_errno(res);
    }

    pthread_mutex_unlock(&p->lock);
    return rc;
}

static int uring_tcp_write_copy(struct pp_uring_sock *p, int fd,
                                const void *buf, size_t len)
{
    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) return PP_ERR_AGAIN;
    io_uring_prep_write(sqe, fd, buf, len, 0);
    if (io_uring_submit(&p->ring) < 0) return PP_ERR_IO;
    int res = 0;
    int rc = uring_wait_res(p, &res);
    if (rc != PP_OK) return rc;
    return map_neg_errno(res);
}

static int uring_tcp_write_zc(struct pp_uring_sock *p, int fd,
                              const void *buf, size_t len)
{
    if (len > p->tx_slot_cap || !p->tx_zc_send)
        return uring_tcp_write_copy(p, fd, buf, len);

    unsigned sid = 0;
    int rc = tx_zc_acquire_slot(p, &sid);
    if (rc != PP_OK) return rc;

    void *slot = tx_slot_ptr(p, sid);
    memcpy(slot, buf, len);

    struct io_uring_sqe *sqe = io_uring_get_sqe(&p->ring);
    if (!sqe) {
        p->slot_busy[sid] = false;
        return PP_ERR_AGAIN;
    }
    io_uring_prep_send_zc(sqe, fd, slot, len, 0, 0);
    if (io_uring_submit(&p->ring) < 0) {
        p->slot_busy[sid] = false;
        return PP_ERR_IO;
    }

    int res = 0;
    rc = uring_wait_send_cqe(p, &res);
    if (rc != PP_OK) {
        p->slot_busy[sid] = false;
        return rc;
    }

    p->slot_busy[sid] = true;
    p->inflight[p->inflight_n++] = sid;
    return map_neg_errno(res);
}

int pp_uring_tcp_write(pp_uring_sock_t *p, int fd, const void *buf, size_t len)
{
    if (!p || fd < 0 || !buf || len == 0) return PP_ERR_INVAL;

    pthread_mutex_lock(&p->lock);
    int rc;
    if (tx_zc_want(p, len))
        rc = uring_tcp_write_zc(p, fd, buf, len);
    else
        rc = uring_tcp_write_copy(p, fd, buf, len);
    pthread_mutex_unlock(&p->lock);
    return rc;
}

#endif /* PP_HAVE_IO_URING */
