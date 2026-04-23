/* tests/test_ring.c -- pp_ring 单元：单线程、burst、满环、多生产者+单消费者 */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pproxy/ring.h"

#define OK(msg)  do { puts(msg); } while (0)
#define FAIL(fmt, ...) do { fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); return 1; } while (0)

static int new_ring(size_t cap, pp_ring_kind_t k, const char *name, pp_ring_t **out)
{
    pp_ring_cfg_t c = { .kind = k, .capacity = cap, .name = name, .numa_node = -1 };
    *out = pp_ring_create(&c);
    return *out ? 0 : -1;
}

/* ---------- 创建校验 ---------- */
static int test_create_fail(void)
{
    pp_ring_t *r;
    if (pp_ring_create(NULL) != NULL) FAIL("create(NULL) 应失败");
    pp_ring_cfg_t c = { .kind = PP_RING_SPSC, .capacity = 3, .name = "x" };
    r = pp_ring_create(&c);
    if (r != NULL) FAIL("非法 capacity=3 应失败");
    c.capacity = 64;
    c.kind     = 99; /* 非法 */
    r = pp_ring_create(&c);
    if (r != NULL) FAIL("非法 kind 应失败");
    OK("  create 拒绝非法参数");
    return 0;
}

/* ---------- 单线程 SPSC 语义：顺序、burst、空/满 ---------- */
static int test_single_thread_spsc(void)
{
    pp_ring_t *r;
    if (new_ring(8, PP_RING_SPSC, "spsc1", &r) != 0) FAIL("create");
    for (int i = 0; i < 5; i++) {
        if (pp_ring_enqueue(r, (void *)(uintptr_t)(100 + i)) != 1) FAIL("enqueue %d", i);
    }
    if (pp_ring_size(r) != 5) FAIL("size 应为 5, got %zu", pp_ring_size(r));
    for (int i = 0; i < 5; i++) {
        void *p;
        if (pp_ring_dequeue(r, &p) != 1) FAIL("dequeue %d", i);
        if (p != (void *)(uintptr_t)(100 + i)) FAIL("顺序: 望 %d 得 %u", 100 + i, (unsigned)(uintptr_t)p);
    }
    if (!pp_ring_empty(r)) FAIL("应变空");
    void *d = NULL;
    if (pp_ring_dequeue(r, &d) != 0) FAIL("空环应 0 出队");
    pp_ring_destroy(r);
    OK("  单线程顺序 5 条");
    return 0;
}

static int test_burst(void)
{
    pp_ring_t *r;
    if (new_ring(16, PP_RING_SPSC, "burst", &r) != 0) FAIL("create");
    void  *in[4]  = { (void *)1, (void *)2, (void *)3, (void *)4 };
    void  *out[4] = { 0 };
    if (pp_ring_enqueue_burst(r, in, 4) != 4) FAIL("enqueue_burst");
    if (pp_ring_dequeue_burst(r, out, 4) != 4) FAIL("dequeue_burst");
    for (int i = 0; i < 4; i++) {
        if (out[i] != in[i]) FAIL("burst[%d]", i);
    }
    if (!pp_ring_empty(r)) FAIL("应变空");
    pp_ring_destroy(r);
    OK("  burst 4+4");
    return 0;
}

static int test_full_ring(void)
{
    pp_ring_t *r;
    if (new_ring(4, PP_RING_MPSC, "full", &r) != 0) FAIL("create");
    for (int i = 0; i < 4; i++) {
        if (pp_ring_enqueue(r, (void *)(uintptr_t)i) != 1) FAIL("enqueue 填满 %d", i);
    }
    if (pp_ring_size(r) != 4) FAIL("size=4");
    if (pp_ring_enqueue(r, (void *)99) != 0) FAIL("环满应 0 入队");
    void *p;
    if (pp_ring_dequeue(r, &p) != 1) FAIL("dequeue1");
    if (p != (void *)0) FAIL("val");
    if (pp_ring_enqueue(r, (void *)7) != 1) FAIL("有槽后应能入队");
    pp_ring_destroy(r);
    OK("  满再入队失败、出队后槽位可复用");
    return 0;
}

/* MPSC 创建与单线程用（同实现） */
static int test_kinds_both_work(void)
{
    pp_ring_t *a, *b;
    if (new_ring(8, PP_RING_SPSC, "k0", &a) != 0) FAIL("SPSC");
    if (new_ring(8, PP_RING_MPSC, "k1", &b) != 0) FAIL("MPSC");
    if (pp_ring_capacity(a) != 8 || pp_ring_capacity(b) != 8) FAIL("cap");
    pp_ring_destroy(a);
    pp_ring_destroy(b);
    OK("  SPSC / MPSC 均可创建");
    return 0;
}

/* ---------- 多生产者 + 主线程单消费者（并发）---------- */
#define MPSC_THREADS   4
#define MPSC_PER    2000
#define MPSC_CAP    4096

typedef struct mpsc_st {
    pp_ring_t *r;
    int        tid;  /* 0..MPSC_THREADS-1 */
} mpsc_st;

static void *mpsc_producer(void *v)
{
    mpsc_st *s  = (mpsc_st *)v;
    for (int j = 0; j < MPSC_PER; j++) {
        void *p = (void *)(uintptr_t)((size_t)s->tid * (size_t)MPSC_PER + (size_t)j);
        while (pp_ring_enqueue(s->r, p) == 0)
            sched_yield();
    }
    return NULL;
}

static int test_mpsc_multiprod(void)
{
    pp_ring_t *r;
    if (new_ring(MPSC_CAP, PP_RING_MPSC, "mpsc", &r) != 0) FAIL("create mpsc");
    int total = MPSC_THREADS * MPSC_PER;
    unsigned *seen = (unsigned *)calloc((size_t)total, sizeof *seen);
    if (!seen) FAIL("calloc");
    mpsc_st                 args[MPSC_THREADS];
    pthread_t               t[MPSC_THREADS];
    for (int i = 0; i < MPSC_THREADS; i++) {
        args[i] = (mpsc_st){ r, i };
        if (pthread_create(&t[i], NULL, mpsc_producer, &args[i]) != 0) {
            free(seen);
            FAIL("pthread_create %d: %s", i, strerror(errno));
        }
    }
    int got = 0;
    while (got < total) {
        void *p;
        if (pp_ring_dequeue(r, &p) == 1) {
            uintptr_t u = (uintptr_t)p;
            if (u >= (unsigned)total) {
                free(seen);
                FAIL("指针越界: %p", p);
            }
            seen[u]++;
            got++;
        } else
            sched_yield();
    }
    for (int k = 0; k < total; k++) {
        if (seen[k] != 1) {
            unsigned sk = seen[k];
            free(seen);
            FAIL("键 %d 应出现 1 次, got %u", k, sk);
        }
    }
    for (int i = 0; i < MPSC_THREADS; i++)
        pthread_join(t[i], NULL);
    if (!pp_ring_empty(r) || pp_ring_size(r) != 0) FAIL("消费后应空");
    free(seen);
    pp_ring_destroy(r);
    printf("  多生产 + 单消费校验全集 (%d 条)\n", total);
    return 0;
}

int main(void)
{
    if (test_create_fail() != 0) return 1;
    if (test_single_thread_spsc() != 0) return 1;
    if (test_burst() != 0) return 1;
    if (test_full_ring() != 0) return 1;
    if (test_kinds_both_work() != 0) return 1;
    if (test_mpsc_multiprod() != 0) return 1;
    puts("test_ring: OK");
    return 0;
}
