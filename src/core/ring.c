/* core/ring.c -- SPSC + MPSC 无锁环（指针元素） */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include "pproxy/ring.h"

struct pp_ring {
    pp_ring_kind_t kind;
    size_t         capacity;
    size_t         mask;          /* capacity - 1 */
    char           name[32];

    /* SPSC: head 由 producer 写、consumer 读；tail 反之 */
    /* MPSC: head 多 producer 用 CAS 抢；tail 仅 consumer */
    atomic_size_t  head PP_CACHELINE_ALIGN;
    atomic_size_t  tail PP_CACHELINE_ALIGN;

    void          *slots[] PP_CACHELINE_ALIGN;
};

static int is_pow2(size_t n) { return n > 0 && (n & (n - 1)) == 0; }

pp_ring_t *pp_ring_create(const pp_ring_cfg_t *cfg)
{
    if (!cfg || !is_pow2(cfg->capacity)) return NULL;
    pp_ring_t *r = aligned_alloc(PP_CACHELINE,
                                 ((sizeof(pp_ring_t) + sizeof(void *) * cfg->capacity
                                   + PP_CACHELINE - 1) / PP_CACHELINE) * PP_CACHELINE);
    if (!r) return NULL;
    memset(r, 0, sizeof *r + sizeof(void *) * cfg->capacity);
    r->kind     = cfg->kind;
    r->capacity = cfg->capacity;
    r->mask     = cfg->capacity - 1;
    if (cfg->name) snprintf(r->name, sizeof r->name, "%s", cfg->name);
    atomic_init(&r->head, 0);
    atomic_init(&r->tail, 0);
    return r;
}

void pp_ring_destroy(pp_ring_t *r) { free(r); }

size_t pp_ring_capacity(const pp_ring_t *r) { return r->capacity; }

size_t pp_ring_size(const pp_ring_t *r)
{
    size_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    size_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
    return h - t;
}

bool pp_ring_empty(const pp_ring_t *r) { return pp_ring_size(r) == 0; }
bool pp_ring_full (const pp_ring_t *r) { return pp_ring_size(r) >= r->capacity; }

/* ---------- 入队 ---------- */
int pp_ring_enqueue(pp_ring_t *r, void *elem)
{
    if (r->kind == PP_RING_SPSC) {
        size_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
        size_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
        if (h - t >= r->capacity) return 0;
        r->slots[h & r->mask] = elem;
        atomic_store_explicit(&r->head, h + 1, memory_order_release);
        return 1;
    } else { /* MPSC: CAS 抢 head */
        size_t h, nh;
        do {
            h  = atomic_load_explicit(&r->head, memory_order_relaxed);
            size_t t = atomic_load_explicit(&r->tail, memory_order_acquire);
            if (h - t >= r->capacity) return 0;
            nh = h + 1;
        } while (!atomic_compare_exchange_weak_explicit(
                    &r->head, &h, nh,
                    memory_order_acq_rel, memory_order_relaxed));
        r->slots[h & r->mask] = elem;
        return 1;
    }
}

int pp_ring_enqueue_burst(pp_ring_t *r, void *const *elems, int n)
{
    int sent = 0;
    for (int i = 0; i < n; i++) {
        if (pp_ring_enqueue(r, elems[i]) == 0) break;
        sent++;
    }
    return sent;
}

/* ---------- 出队（单消费者，SPSC/MPSC 都一样） ---------- */
int pp_ring_dequeue(pp_ring_t *r, void **elem)
{
    size_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    size_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    if (h == t) return 0;
    *elem = r->slots[t & r->mask];
    atomic_store_explicit(&r->tail, t + 1, memory_order_release);
    return 1;
}

int pp_ring_dequeue_burst(pp_ring_t *r, void **elems, int n)
{
    int got = 0;
    for (int i = 0; i < n; i++) {
        if (pp_ring_dequeue(r, &elems[got]) == 0) break;
        got++;
    }
    return got;
}
