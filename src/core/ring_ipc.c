/* src/core/ring_ipc.c -- ring IPC wait/notify backends */
#include "pproxy/ring_ipc.h"

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/ring.h"

#ifdef PP_LINUX
#include <sys/epoll.h>
#include <sys/eventfd.h>
#endif

struct pp_ring_ipc {
    pp_ring_ipc_cfg_t cfg;
    atomic_uint_fast64_t notifies;
    atomic_uint_fast64_t waits;
    atomic_uint_fast64_t ready;
    atomic_uint_fast64_t wakes;
    atomic_uint_fast64_t timeouts;
    atomic_uint_fast64_t sleeps;
    atomic_uint_fast64_t epolls;
    atomic_uint_fast64_t adaptive_spins;
    atomic_uint_fast64_t adaptive_yields;
#ifdef PP_LINUX
    int efd; /* eventfd；EVENTFD/ADAPTIVE 模式 */
#endif
};

struct pp_ring_ipc_waiter {
    pp_ring_t **rings;
    int         n_rings;
    int         cap_rings;
#ifdef PP_LINUX
    int  epfd;
    int *efds;
    pp_ring_ipc_t **efd_ipcs;
    int  n_efds;
    int  cap_efds;
#endif
    uint32_t backoff_us;
};

#define IPC_INC(ipc, field) \
    atomic_fetch_add_explicit(&(ipc)->field, 1, memory_order_relaxed)
#define IPC_ADD(ipc, field, n) \
    atomic_fetch_add_explicit(&(ipc)->field, (uint64_t)(n), memory_order_relaxed)

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
static inline void pp_ipc_cpu_relax(void) { _mm_pause(); }
#elif defined(__aarch64__)
static inline void pp_ipc_cpu_relax(void)
{
    __asm__ __volatile__("yield" ::: "memory");
}
#else
static inline void pp_ipc_cpu_relax(void) { }
#endif

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
    case PP_RING_IPC_ADAPTIVE: return "adaptive";
    default:                  return "unknown";
    }
}

pp_ring_ipc_mode_t pp_ring_ipc_mode_parse(const char *s, bool *ok)
{
    if (ok) *ok = true;
    if (!s || !*s) return PP_RING_IPC_POLLING;
    if (!strcmp(s, "polling")) return PP_RING_IPC_POLLING;
    if (!strcmp(s, "eventfd")) return PP_RING_IPC_EVENTFD;
    if (!strcmp(s, "adaptive")) return PP_RING_IPC_ADAPTIVE;
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
    if (!ipc->cfg.adaptive_spin) ipc->cfg.adaptive_spin = 64;
    if (!ipc->cfg.adaptive_yield) ipc->cfg.adaptive_yield = 8;

#ifndef PP_LINUX
    if (ipc->cfg.mode == PP_RING_IPC_EVENTFD)
        ipc->cfg.mode = PP_RING_IPC_POLLING;
    return ipc;
#else
    ipc->efd = -1;
    if (ipc->cfg.mode == PP_RING_IPC_EVENTFD
        || ipc->cfg.mode == PP_RING_IPC_ADAPTIVE) {
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
    IPC_INC(ipc, notifies);
    switch (ipc->cfg.mode) {
    case PP_RING_IPC_POLLING:
        break;
#ifdef PP_LINUX
    case PP_RING_IPC_EVENTFD:
    case PP_RING_IPC_ADAPTIVE:
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

pp_ring_ipc_mode_t pp_ring_ipc_mode(const pp_ring_ipc_t *ipc)
{
    return ipc ? ipc->cfg.mode : PP_RING_IPC_POLLING;
}

void pp_ring_ipc_stats(const pp_ring_ipc_t *ipc, pp_ring_ipc_stats_t *out)
{
    if (!out) return;
    memset(out, 0, sizeof *out);
    if (!ipc) return;
    out->notifies = atomic_load_explicit(&ipc->notifies, memory_order_relaxed);
    out->waits = atomic_load_explicit(&ipc->waits, memory_order_relaxed);
    out->ready = atomic_load_explicit(&ipc->ready, memory_order_relaxed);
    out->wakes = atomic_load_explicit(&ipc->wakes, memory_order_relaxed);
    out->timeouts = atomic_load_explicit(&ipc->timeouts, memory_order_relaxed);
    out->sleeps = atomic_load_explicit(&ipc->sleeps, memory_order_relaxed);
    out->epolls = atomic_load_explicit(&ipc->epolls, memory_order_relaxed);
    out->adaptive_spins = atomic_load_explicit(&ipc->adaptive_spins, memory_order_relaxed);
    out->adaptive_yields = atomic_load_explicit(&ipc->adaptive_yields, memory_order_relaxed);
}

static bool waiter_any_ready(const pp_ring_ipc_waiter_t *w)
{
    for (int i = 0; i < w->n_rings; i++)
        if (!pp_ring_empty(w->rings[i])) return true;
    return false;
}

static void waiter_inc_all(const pp_ring_ipc_waiter_t *w,
                           void (*fn)(pp_ring_ipc_t *ipc))
{
    for (int i = 0; i < w->n_rings; i++) {
        pp_ring_ipc_t *ipc = pp_ring_get_ipc(w->rings[i]);
        if (ipc) fn(ipc);
    }
}

static void stat_wait(pp_ring_ipc_t *ipc) { IPC_INC(ipc, waits); }
static void stat_timeout(pp_ring_ipc_t *ipc) { IPC_INC(ipc, timeouts); }
static void stat_sleep(pp_ring_ipc_t *ipc) { IPC_INC(ipc, sleeps); }

static void waiter_inc_ready_rings(const pp_ring_ipc_waiter_t *w)
{
    for (int i = 0; i < w->n_rings; i++) {
        if (pp_ring_empty(w->rings[i])) continue;
        pp_ring_ipc_t *ipc = pp_ring_get_ipc(w->rings[i]);
        if (ipc) IPC_INC(ipc, ready);
    }
}

static int waiter_max_adaptive_spin(const pp_ring_ipc_waiter_t *w)
{
    uint32_t v = 0;
    for (int i = 0; i < w->n_rings; i++) {
        pp_ring_ipc_t *ipc = pp_ring_get_ipc(w->rings[i]);
        if (ipc && ipc->cfg.mode == PP_RING_IPC_ADAPTIVE
            && ipc->cfg.adaptive_spin > v)
            v = ipc->cfg.adaptive_spin;
    }
    return (int)v;
}

static int waiter_max_adaptive_yield(const pp_ring_ipc_waiter_t *w)
{
    uint32_t v = 0;
    for (int i = 0; i < w->n_rings; i++) {
        pp_ring_ipc_t *ipc = pp_ring_get_ipc(w->rings[i]);
        if (ipc && ipc->cfg.mode == PP_RING_IPC_ADAPTIVE
            && ipc->cfg.adaptive_yield > v)
            v = ipc->cfg.adaptive_yield;
    }
    return (int)v;
}

static void waiter_add_adaptive_spins(const pp_ring_ipc_waiter_t *w, uint64_t n)
{
    if (!n) return;
    for (int i = 0; i < w->n_rings; i++) {
        pp_ring_ipc_t *ipc = pp_ring_get_ipc(w->rings[i]);
        if (ipc && ipc->cfg.mode == PP_RING_IPC_ADAPTIVE)
            IPC_ADD(ipc, adaptive_spins, n);
    }
}

static void waiter_add_adaptive_yields(const pp_ring_ipc_waiter_t *w, uint64_t n)
{
    if (!n) return;
    for (int i = 0; i < w->n_rings; i++) {
        pp_ring_ipc_t *ipc = pp_ring_get_ipc(w->rings[i]);
        if (ipc && ipc->cfg.mode == PP_RING_IPC_ADAPTIVE)
            IPC_ADD(ipc, adaptive_yields, n);
    }
}

static bool waiter_adaptive_ready(pp_ring_ipc_waiter_t *w)
{
    int spins = waiter_max_adaptive_spin(w);
    for (int i = 0; i < spins; i++) {
        pp_ipc_cpu_relax();
        if (waiter_any_ready(w)) {
            waiter_add_adaptive_spins(w, (uint64_t)i + 1);
            waiter_inc_ready_rings(w);
            return true;
        }
    }
    waiter_add_adaptive_spins(w, (uint64_t)spins);

    int yields = waiter_max_adaptive_yield(w);
    for (int i = 0; i < yields; i++) {
        sched_yield();
        if (waiter_any_ready(w)) {
            waiter_add_adaptive_yields(w, (uint64_t)i + 1);
            waiter_inc_ready_rings(w);
            return true;
        }
    }
    waiter_add_adaptive_yields(w, (uint64_t)yields);
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
    if (!ipc || (ipc->cfg.mode != PP_RING_IPC_EVENTFD
                 && ipc->cfg.mode != PP_RING_IPC_ADAPTIVE)) return;
#ifndef PP_LINUX
    return;
#else
    if (ipc->efd < 0) return;
    for (int i = 0; i < w->n_efds; i++)
        if (w->efds[i] == ipc->efd) return;

    if (w->n_efds == w->cap_efds) {
        int ncap = w->cap_efds ? w->cap_efds * 2 : 4;
        int *nb = malloc((size_t)ncap * sizeof *nb);
        pp_ring_ipc_t **ni = malloc((size_t)ncap * sizeof *ni);
        if (!nb || !ni) {
            free(nb);
            free(ni);
            return;
        }
        if (w->n_efds > 0) {
            memcpy(nb, w->efds, (size_t)w->n_efds * sizeof *nb);
            memcpy(ni, w->efd_ipcs, (size_t)w->n_efds * sizeof *ni);
        }
        free(w->efds);
        free(w->efd_ipcs);
        w->efds = nb;
        w->efd_ipcs = ni;
        w->cap_efds = ncap;
    }
    w->efds[w->n_efds++] = ipc->efd;
    w->efd_ipcs[w->n_efds - 1] = ipc;

    struct epoll_event ev = { .events = EPOLLIN, .data.fd = ipc->efd };
    (void)epoll_ctl(w->epfd, EPOLL_CTL_ADD, ipc->efd, &ev);
#endif
}

#ifdef PP_LINUX
static pp_ring_ipc_t *waiter_ipc_for_efd(const pp_ring_ipc_waiter_t *w, int efd)
{
    for (int i = 0; i < w->n_efds; i++)
        if (w->efds[i] == efd) return w->efd_ipcs[i];
    return NULL;
}

static void waiter_inc_epolls(const pp_ring_ipc_waiter_t *w)
{
    for (int i = 0; i < w->n_efds; i++)
        if (w->efd_ipcs[i]) IPC_INC(w->efd_ipcs[i], epolls);
}

static void waiter_inc_efd_timeouts(const pp_ring_ipc_waiter_t *w)
{
    for (int i = 0; i < w->n_efds; i++)
        if (w->efd_ipcs[i]) IPC_INC(w->efd_ipcs[i], timeouts);
}
#endif

void pp_ring_ipc_waiter_wait(pp_ring_ipc_waiter_t *w, uint32_t backoff_us)
{
    if (!w) {
        ipc_sleep_us(backoff_us ? backoff_us : 50);
        return;
    }
    w->backoff_us = backoff_us ? backoff_us : 50;

    waiter_inc_all(w, stat_wait);
    if (waiter_any_ready(w)) {
        waiter_inc_ready_rings(w);
        return;
    }

    if (waiter_adaptive_ready(w)) return;

#ifndef PP_LINUX
    waiter_inc_all(w, stat_sleep);
    ipc_sleep_us(w->backoff_us);
    if (!waiter_any_ready(w))
        waiter_inc_all(w, stat_timeout);
    return;
#else
    if (w->n_efds > 0) {
        int ms = (int)((w->backoff_us + 999) / 1000);
        if (ms < 1) ms = 1;
        struct epoll_event ev[8];
        waiter_inc_epolls(w);
        int n = epoll_wait(w->epfd, ev, 8, ms);
        if (n > 0) {
            for (int i = 0; i < n; i++) {
                drain_eventfd(ev[i].data.fd);
                pp_ring_ipc_t *ipc = waiter_ipc_for_efd(w, ev[i].data.fd);
                if (ipc) IPC_INC(ipc, wakes);
            }
        } else if (n == 0) {
            waiter_inc_efd_timeouts(w);
        }
        return;
    }

    waiter_inc_all(w, stat_sleep);
    ipc_sleep_us(w->backoff_us);
    if (!waiter_any_ready(w))
        waiter_inc_all(w, stat_timeout);
#endif
}

void pp_ring_ipc_waiter_destroy(pp_ring_ipc_waiter_t *w)
{
    if (!w) return;
#ifdef PP_LINUX
    if (w->epfd >= 0) close(w->epfd);
    free(w->efds);
    free(w->efd_ipcs);
#endif
    free(w->rings);
    free(w);
}
