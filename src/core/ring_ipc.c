/* src/core/ring_ipc.c -- ring IPC wait/notify backends */
#include "pproxy/ring_ipc.h"

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/ring.h"

#ifdef PP_LINUX
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif

struct pp_ring_ipc {
    pp_ring_ipc_cfg_t cfg;
#ifdef PP_LINUX
    int efd; /* eventfd；EVENTFD 模式 */
#endif
};

struct pp_ring_ipc_waiter {
    pp_ring_t **rings;
    int         n_rings;
    int         cap_rings;
#ifdef PP_LINUX
    int  epfd;
    int *efds;
    int  n_efds;
    int  cap_efds;
#endif
    uint32_t backoff_us;
};

static void timespec_from_us(uint32_t us, struct timespec *ts)
{
    ts->tv_sec  = (time_t)(us / 1000000u);
    ts->tv_nsec = (long)(us % 1000000u) * 1000L;
}

static void ipc_sleep_us(uint32_t us)
{
    if (!us) us = 1;
    struct timespec ts;
    timespec_from_us(us, &ts);
    nanosleep(&ts, NULL);
}

#ifdef PP_LINUX
static void drain_eventfd(int efd)
{
    uint64_t v;
    for (;;) {
        ssize_t n = read(efd, &v, sizeof v);
        if (n == (ssize_t)sizeof v) continue;
        if (n < 0 && errno == EAGAIN) return;
        return;
    }
}
#endif

const char *pp_ring_ipc_mode_name(pp_ring_ipc_mode_t mode)
{
    switch (mode) {
    case PP_RING_IPC_POLLING: return "polling";
    case PP_RING_IPC_EVENTFD: return "eventfd";
    default:                  return "unknown";
    }
}

pp_ring_ipc_mode_t pp_ring_ipc_mode_parse(const char *s, bool *ok)
{
    if (ok) *ok = true;
    if (!s || !*s) return PP_RING_IPC_POLLING;
    if (!strcmp(s, "polling")) return PP_RING_IPC_POLLING;
    if (!strcmp(s, "eventfd")) return PP_RING_IPC_EVENTFD;
    if (ok) *ok = false;
    return PP_RING_IPC_POLLING;
}

pp_ring_ipc_t *pp_ring_ipc_create(const pp_ring_ipc_cfg_t *cfg)
{
    if (!cfg) return NULL;
    pp_ring_ipc_t *ipc = calloc(1, sizeof *ipc);
    if (!ipc) return NULL;
    ipc->cfg = *cfg;
    if (!ipc->cfg.poll_backoff_us) ipc->cfg.poll_backoff_us = 50;

#ifndef PP_LINUX
    if (ipc->cfg.mode != PP_RING_IPC_POLLING)
        ipc->cfg.mode = PP_RING_IPC_POLLING;
    return ipc;
#else
    ipc->efd = -1;
    if (ipc->cfg.mode == PP_RING_IPC_EVENTFD) {
        ipc->efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (ipc->efd < 0) {
            free(ipc);
            return NULL;
        }
    }
    return ipc;
#endif
}

void pp_ring_ipc_destroy(pp_ring_ipc_t *ipc)
{
    if (!ipc) return;
#ifdef PP_LINUX
    if (ipc->efd >= 0) close(ipc->efd);
#endif
    free(ipc);
}

void pp_ring_ipc_notify(pp_ring_ipc_t *ipc)
{
    if (!ipc) return;
    switch (ipc->cfg.mode) {
    case PP_RING_IPC_POLLING:
        break;
#ifdef PP_LINUX
    case PP_RING_IPC_EVENTFD:
        if (ipc->efd >= 0) {
            uint64_t one = 1;
            if (write(ipc->efd, &one, sizeof one) < 0) { /* EAGAIN 可忽略 */ }
        }
        break;
#endif
    default:
        break;
    }
}

static bool waiter_any_ready(const pp_ring_ipc_waiter_t *w)
{
    for (int i = 0; i < w->n_rings; i++)
        if (!pp_ring_empty(w->rings[i])) return true;
    return false;
}

pp_ring_ipc_waiter_t *pp_ring_ipc_waiter_create(void)
{
    pp_ring_ipc_waiter_t *w = calloc(1, sizeof *w);
    if (!w) return NULL;
#ifdef PP_LINUX
    w->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (w->epfd < 0) {
        free(w);
        return NULL;
    }
#endif
    return w;
}

void pp_ring_ipc_waiter_add(pp_ring_ipc_waiter_t *w, pp_ring_t *r)
{
    if (!w || !r) return;

    for (int i = 0; i < w->n_rings; i++)
        if (w->rings[i] == r) return;

    if (w->n_rings == w->cap_rings) {
        int ncap = w->cap_rings ? w->cap_rings * 2 : 4;
        pp_ring_t **nb = realloc(w->rings, (size_t)ncap * sizeof *nb);
        if (!nb) return;
        w->rings = nb;
        w->cap_rings = ncap;
    }
    w->rings[w->n_rings++] = r;

    pp_ring_ipc_t *ipc = pp_ring_get_ipc(r);
    if (!ipc || ipc->cfg.mode != PP_RING_IPC_EVENTFD) return;
#ifndef PP_LINUX
    return;
#else
    if (ipc->efd < 0) return;
    for (int i = 0; i < w->n_efds; i++)
        if (w->efds[i] == ipc->efd) return;

    if (w->n_efds == w->cap_efds) {
        int ncap = w->cap_efds ? w->cap_efds * 2 : 4;
        int *nb = realloc(w->efds, (size_t)ncap * sizeof *nb);
        if (!nb) return;
        w->efds = nb;
        w->cap_efds = ncap;
    }
    w->efds[w->n_efds++] = ipc->efd;

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = ipc->efd };
    (void)epoll_ctl(w->epfd, EPOLL_CTL_ADD, ipc->efd, &ev);
#endif
}

void pp_ring_ipc_waiter_wait(pp_ring_ipc_waiter_t *w, uint32_t backoff_us)
{
    if (!w) {
        ipc_sleep_us(backoff_us ? backoff_us : 50);
        return;
    }
    w->backoff_us = backoff_us ? backoff_us : 50;

    if (waiter_any_ready(w)) return;

#ifndef PP_LINUX
    ipc_sleep_us(w->backoff_us);
    return;
#else
    if (w->n_efds > 0) {
        int ms = (int)((w->backoff_us + 999) / 1000);
        if (ms < 1) ms = 1;
        struct epoll_event ev[8];
        int n = epoll_wait(w->epfd, ev, 8, ms);
        if (n > 0) {
            for (int i = 0; i < n; i++)
                drain_eventfd(ev[i].data.fd);
        }
        return;
    }

    ipc_sleep_us(w->backoff_us);
#endif
}

void pp_ring_ipc_waiter_destroy(pp_ring_ipc_waiter_t *w)
{
    if (!w) return;
#ifdef PP_LINUX
    if (w->epfd >= 0) close(w->epfd);
    free(w->efds);
#endif
    free(w->rings);
    free(w);
}
