/* tests/test_ring_bench.c -- MPSC 多生产者+单消费者耗时（同 ring.c 宏 PP_RING_USE_CPU_BACKOFF） */
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "pproxy/ring.h"

#ifndef PP_RING_USE_CPU_BACKOFF
#define PP_RING_USE_CPU_BACKOFF 1
#endif

#define BENCH_NPROD  8
#define BENCH_PER    20000                 /* 每生产线程入队数 */
#define BENCH_CAP    32768                 /* 2 的幂，需容下争用下多槽占用 */
#define BENCH_WARM   3
#define BENCH_ROUNDS 15

struct prod_arg {
    pp_ring_t *r;
    int        id;
    int        n;
};

static void *prod(void *v)
{
    struct prod_arg *a = (struct prod_arg *)v;
    for (int j = 0; j < a->n; j++) {
        void *p = (void *)(uintptr_t)((size_t)a->id * (size_t)a->n + (size_t)j);
        while (pp_ring_enqueue(a->r, p) == 0)
            sched_yield();
    }
    return NULL;
}

static int run_once(long *out_ns)
{
    pp_ring_cfg_t c = { .kind = PP_RING_MPSC, .capacity = (size_t)BENCH_CAP, .name = "bench", .numa_node = -1 };
    pp_ring_t     *r = pp_ring_create(&c);
    if (!r) return -1;

    pthread_t         th[BENCH_NPROD];
    struct prod_arg   args[BENCH_NPROD];
    int const         nprod = BENCH_NPROD;
    int const         per   = BENCH_PER;
    int          total  = nprod * per;
    size_t        capsz = (size_t)total * sizeof(uint8_t);
    if (total <= 0 || capsz / sizeof(uint8_t) != (size_t)total) {
        pp_ring_destroy(r);
        return -1;
    }
    uint8_t *seen = (uint8_t *)calloc((size_t)total, 1);
    if (!seen) {
        pp_ring_destroy(r);
        return -1;
    }

    for (int i = 0; i < nprod; i++) {
        args[i] = (struct prod_arg){ r, i, per };
        if (pthread_create(&th[i], NULL, prod, &args[i]) != 0) {
            for (int k = 0; k < i; k++) pthread_join(th[k], NULL);
            free(seen);
            pp_ring_destroy(r);
            return -1;
        }
    }

    struct timespec t0, t1;
    if (clock_gettime(CLOCK_MONOTONIC, &t0) != 0) {
        for (int i = 0; i < nprod; i++) pthread_join(th[i], NULL);
        free(seen);
        pp_ring_destroy(r);
        return -1;
    }

    int got = 0;
    while (got < total) {
        void *p;
        if (pp_ring_dequeue(r, &p) == 1) {
            uintptr_t u = (uintptr_t)p;
            if (u < (unsigned)total) {
                if (seen[u] != 0) {
                    for (int i = 0; i < nprod; i++) pthread_join(th[i], NULL);
                    free(seen);
                    pp_ring_destroy(r);
                    return -2; /* 重复或错误 */
                }
                seen[u] = 1;
            }
            got++;
        } else
            sched_yield();
    }
    for (int i = 0; i < nprod; i++) pthread_join(th[i], NULL);
    if (clock_gettime(CLOCK_MONOTONIC, &t1) != 0) {
        free(seen);
        pp_ring_destroy(r);
        return -1;
    }

    for (int k = 0; k < total; k++) {
        if (seen[k] != 1) {
            free(seen);
            pp_ring_destroy(r);
            return -2;
        }
    }

    long ns = (t1.tv_sec - t0.tv_sec) * 1000000000L + (t1.tv_nsec - t0.tv_nsec);
    *out_ns = ns;
    free(seen);
    pp_ring_destroy(r);
    return 0;
}

int main(void)
{
    for (int w = 0; w < BENCH_WARM; w++) {
        long dummy;
        if (run_once(&dummy) != 0) {
            fprintf(stderr, "test_ring_bench: warmup 失败\n");
            return 1;
        }
    }

    long best = -1;
    for (int r = 0; r < BENCH_ROUNDS; r++) {
        long ns;
        if (run_once(&ns) != 0) {
            fprintf(stderr, "test_ring_bench: 轮次 %d 失败\n", r);
            return 1;
        }
        if (best < 0 || ns < best) best = ns;
    }
    if (best < 0) return 1;

    int  total  = BENCH_NPROD * BENCH_PER;
    long ns_int = (total > 0) ? (best / (long)total) : 0;
    int  ppb = PP_RING_USE_CPU_BACKOFF;
    /* 单行输出便于脚本解析 */
    printf("PP_RING_USE_CPU_BACKOFF=%d nprod=%d per=%d cap=%d total_enq=%d time_ns_best_of_%d=%ld ns_per_dequeue=%ld\n",
           ppb, BENCH_NPROD, BENCH_PER, BENCH_CAP, total, (int)BENCH_ROUNDS, best, ns_int);
    return 0;
}
