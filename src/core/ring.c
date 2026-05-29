/* core/ring.c -- 无锁环：统一为四下标序线发布（SPSC 与 MPSC 同一套实现）
 *
 * 单生产者+单消费者时无跨生产者序要求，自旋在 prod_tail / cons_tail 上通常立即满足。
 * PP_RING_SPSC / PP_RING_MPSC 仅作「预期用法」标记，无第二套数据路径。
 *
 * 编译可定义 PP_RING_USE_CPU_BACKOFF=0 关闭自旋内 pause/yield 提示（x86: _mm_pause）；
 * 默认可不定义，等价于 1。供 benchmark 对比。 */
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdatomic.h>
#include "pproxy/ring.h"
#include "pproxy/ring_ipc.h"

#ifndef PP_RING_USE_CPU_BACKOFF
#define PP_RING_USE_CPU_BACKOFF 1
#endif

#if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)
#include <immintrin.h>
static inline void pp_cpu_backoff(void) { _mm_pause(); }
#elif defined(__aarch64__)
static inline void pp_cpu_backoff(void)
{
    __asm__ __volatile__("yield" ::: "memory");
}
#else
static inline void pp_cpu_backoff(void) { }
#endif

static void spin_until_eq(atomic_size_t *a, size_t need)
{
    unsigned s = 0;
    while (atomic_load_explicit(a, memory_order_acquire) != need) {
        if (s < 64) {
#if PP_RING_USE_CPU_BACKOFF
            pp_cpu_backoff();
#else
            /* 纯忙等，仅用于与 pause/yield 提示对比 */
            (void)0;
#endif
        } else
            sched_yield();
        s++;
    }
}

struct pp_ring {
    pp_ring_kind_t   kind;            /* 仅记录创建时的「用法」；算法不区分 */
    size_t           capacity;
    size_t           mask;
    char             name[32];
    /* prod/consumer 序线，与 j_ring 式 MPSC 相同；亦覆盖 SPSC 单线程情形 */
    atomic_size_t    prod_head PP_CACHELINE_ALIGN;
    atomic_size_t    prod_tail PP_CACHELINE_ALIGN;
    atomic_size_t    cons_head PP_CACHELINE_ALIGN;
    atomic_size_t    cons_tail PP_CACHELINE_ALIGN;
    pp_ring_ipc_t   *ipc;
    void *slots[] PP_CACHELINE_ALIGN;
};

static int is_pow2(size_t n) { return n > 0 && (n & (n - 1)) == 0; }

pp_ring_t *pp_ring_create(const pp_ring_cfg_t *cfg)
{
    if (!cfg || !is_pow2(cfg->capacity)) return NULL;
    if (cfg->kind != PP_RING_SPSC && cfg->kind != PP_RING_MPSC) return NULL;
    pp_ring_t *r = aligned_alloc(PP_CACHELINE,
                                 ((sizeof(pp_ring_t) + sizeof(void *) * cfg->capacity
                                   + PP_CACHELINE - 1) / PP_CACHELINE) * PP_CACHELINE);
    if (!r) return NULL;
    memset(r, 0, sizeof *r + sizeof(void *) * cfg->capacity);
    r->kind     = cfg->kind;
    r->capacity = cfg->capacity;
    r->mask     = cfg->capacity - 1;
    if (cfg->name) snprintf(r->name, sizeof r->name, "%s", cfg->name);
    atomic_init(&r->prod_head, 0);
    atomic_init(&r->prod_tail, 0);
    atomic_init(&r->cons_head, 0);
    atomic_init(&r->cons_tail, 0);
    return r;
}

void pp_ring_destroy(pp_ring_t *r)
{
    if (!r) return;
    if (r->ipc) {
        pp_ring_ipc_destroy(r->ipc);
        r->ipc = NULL;
    }
    free(r);
}

size_t pp_ring_capacity(const pp_ring_t *r) { return r->capacity; }

size_t pp_ring_size(const pp_ring_t *r)
{
    size_t pt = atomic_load_explicit(&r->prod_tail, memory_order_acquire);
    size_t ct = atomic_load_explicit(&r->cons_tail, memory_order_acquire);
    return pt - ct;
}

bool pp_ring_empty(const pp_ring_t *r) { return pp_ring_size(r) == 0; }
bool pp_ring_full (const pp_ring_t *r) { return pp_ring_size(r) >= r->capacity; }

void pp_ring_attach_ipc(pp_ring_t *r, pp_ring_ipc_t *ipc)
{
    if (!r) return;
    if (r->ipc && r->ipc != ipc)
        pp_ring_ipc_destroy(r->ipc);
    r->ipc = ipc;
}

pp_ring_ipc_t *pp_ring_get_ipc(const pp_ring_t *r)
{
    return r ? r->ipc : NULL;
}

static void ring_post_enqueue(pp_ring_t *r, bool was_empty, int n)
{
    if (n > 0 && was_empty && r->ipc)
        pp_ring_ipc_notify(r->ipc);
}

int pp_ring_enqueue(pp_ring_t *r, void *elem)
{
    bool was_empty = pp_ring_empty(r);
    size_t old_ph, new_ph, old_ct;
    do {
        old_ph = atomic_load_explicit(&r->prod_head, memory_order_relaxed);
        old_ct = atomic_load_explicit(&r->cons_tail, memory_order_acquire);
        if (r->capacity - (old_ph - old_ct) < 1) return 0;
        new_ph = old_ph + 1;
    } while (!atomic_compare_exchange_weak_explicit(
                &r->prod_head, &old_ph, new_ph,
                memory_order_acq_rel, memory_order_relaxed));

    r->slots[old_ph & r->mask] = elem;

    spin_until_eq(&r->prod_tail, old_ph);
    atomic_store_explicit(&r->prod_tail, new_ph, memory_order_release);
    ring_post_enqueue(r, was_empty, 1);
    return 1;
}

int pp_ring_enqueue_burst(pp_ring_t *r, void *const *elems, int n)
{
    if (n <= 0) return 0;
    bool was_empty = pp_ring_empty(r);
    size_t old_ph, new_ph, old_ct;
    size_t entries = (size_t)n;
    do {
        old_ph = atomic_load_explicit(&r->prod_head, memory_order_relaxed);
        old_ct = atomic_load_explicit(&r->cons_tail, memory_order_acquire);
        if (r->capacity - (old_ph - old_ct) < entries) return 0;
        new_ph = old_ph + entries;
    } while (!atomic_compare_exchange_weak_explicit(
                &r->prod_head, &old_ph, new_ph,
                memory_order_acq_rel, memory_order_relaxed));

    for (size_t i = 0; i < entries; i++) {
        r->slots[(old_ph + i) & r->mask] = elems[i];
    }

    spin_until_eq(&r->prod_tail, old_ph);
    atomic_store_explicit(&r->prod_tail, new_ph, memory_order_release);
    ring_post_enqueue(r, was_empty, (int)entries);
    return (int)entries;
}

int pp_ring_dequeue(pp_ring_t *r, void **elem)
{
    size_t old_ch, new_ch, old_pt;
    do {
        old_ch = atomic_load_explicit(&r->cons_head, memory_order_relaxed);
        old_pt = atomic_load_explicit(&r->prod_tail, memory_order_acquire);
        if (old_pt - old_ch < 1) return 0;
        new_ch = old_ch + 1;
    } while (!atomic_compare_exchange_weak_explicit(
                &r->cons_head, &old_ch, new_ch,
                memory_order_acq_rel, memory_order_relaxed));

    *elem = r->slots[old_ch & r->mask];

    spin_until_eq(&r->cons_tail, old_ch);
    atomic_store_explicit(&r->cons_tail, new_ch, memory_order_release);
    return 1;
}

int pp_ring_dequeue_burst(pp_ring_t *r, void **elems, int n)
{
    if (n <= 0) return 0;
    size_t old_ch, new_ch, old_pt, to_get;
    do {
        old_ch = atomic_load_explicit(&r->cons_head, memory_order_relaxed);
        old_pt = atomic_load_explicit(&r->prod_tail, memory_order_acquire);
        size_t avail = old_pt - old_ch;
        if (avail < 1) return 0;
        to_get = (size_t)n < avail ? (size_t)n : avail;
        new_ch = old_ch + to_get;
    } while (!atomic_compare_exchange_weak_explicit(
                &r->cons_head, &old_ch, new_ch,
                memory_order_acq_rel, memory_order_relaxed));

    for (size_t i = 0; i < to_get; i++) {
        elems[i] = r->slots[(old_ch + i) & r->mask];
    }

    spin_until_eq(&r->cons_tail, old_ch);
    atomic_store_explicit(&r->cons_tail, new_ch, memory_order_release);
    return (int)to_get;
}
