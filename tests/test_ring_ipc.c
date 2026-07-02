/* tests/test_ring_ipc.c -- ring IPC：eventfd 唤醒 / polling idle */
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pproxy/ring.h"
#include "pproxy/ring_ipc.h"

#define OK(msg)  do { puts(msg); } while (0)
#define FAIL(fmt, ...) do { fprintf(stderr, "FAIL: " fmt "\n", ##__VA_ARGS__); return 1; } while (0)

static pp_ring_t *new_ring_with_ipc(pp_ring_ipc_mode_t mode)
{
    pp_ring_cfg_t rc = {
        .kind = PP_RING_SPSC, .capacity = 8, .name = "ipc", .numa_node = -1,
    };
    pp_ring_t *r = pp_ring_create(&rc);
    if (!r) return NULL;

    pp_ring_ipc_cfg_t ic = { .mode = mode, .poll_backoff_us = 1000 };
    pp_ring_ipc_t *ipc = pp_ring_ipc_create(&ic);
    if (!ipc) {
        pp_ring_destroy(r);
        return NULL;
    }
    pp_ring_attach_ipc(r, ipc);
    return r;
}

static void waiter_idle_one(pp_ring_t *r, uint32_t backoff_us)
{
    pp_ring_ipc_waiter_t *w = pp_ring_ipc_waiter_create();
    if (!w) return;
    pp_ring_ipc_waiter_add(w, r);
    pp_ring_ipc_waiter_wait(w, backoff_us);
    pp_ring_ipc_waiter_destroy(w);
}

typedef struct prod_arg {
    pp_ring_t *ring;
    int        delay_ms;
} prod_arg_t;

static void *producer(void *arg)
{
    prod_arg_t *a = arg;
    if (a->delay_ms > 0)
        usleep((useconds_t)a->delay_ms * 1000u);
    if (pp_ring_enqueue(a->ring, (void *)(uintptr_t)42) != 1)
        return (void *)(uintptr_t)1;
    return NULL;
}

static int test_eventfd_no_lost_wakeup(void)
{
#ifndef PP_LINUX
    OK("  eventfd lost-wakeup (skip: non-Linux)");
    return 0;
#else
    pp_ring_t *r = new_ring_with_ipc(PP_RING_IPC_EVENTFD);
    if (!r) FAIL("create ring+eventfd");

    prod_arg_t pa = { .ring = r, .delay_ms = 0 };
    pthread_t th;
    if (pthread_create(&th, NULL, producer, &pa) != 0) FAIL("pthread_create");
    pthread_join(th, NULL);

    if (!pp_ring_empty(r)) {
        waiter_idle_one(r, 50000);
        if (pp_ring_empty(r)) FAIL("eventfd idle 后环仍空");
    }

    void *p = NULL;
    if (pp_ring_dequeue(r, &p) != 1 || p != (void *)(uintptr_t)42)
        FAIL("dequeue after idle");

    pp_ring_destroy(r);
    OK("  eventfd 无丢唤醒");
    return 0;
#endif
}

static int test_eventfd_wake_after_idle(void)
{
#ifndef PP_LINUX
    OK("  eventfd wake-after-idle (skip: non-Linux)");
    return 0;
#else
    pp_ring_t *r = new_ring_with_ipc(PP_RING_IPC_EVENTFD);
    if (!r) FAIL("create ring+eventfd");

    prod_arg_t pa = { .ring = r, .delay_ms = 5 };
    pthread_t th;
    if (pthread_create(&th, NULL, producer, &pa) != 0) FAIL("pthread_create");

    waiter_idle_one(r, 50000);

    pthread_join(th, NULL);
    void *p = NULL;
    if (pp_ring_dequeue(r, &p) != 1 || p != (void *)(uintptr_t)42)
        FAIL("dequeue after wake");

    pp_ring_destroy(r);
    OK("  eventfd idle 后唤醒");
    return 0;
#endif
}

static int test_polling_idle(void)
{
    pp_ring_t *r = new_ring_with_ipc(PP_RING_IPC_POLLING);
    if (!r) FAIL("create ring+polling");
    waiter_idle_one(r, 1000);
    if (!pp_ring_empty(r)) FAIL("polling idle 不应改变环状态");
    pp_ring_destroy(r);
    OK("  polling idle");
    return 0;
}

static int test_waiter_multi_eventfd(void)
{
#ifndef PP_LINUX
    OK("  waiter multi-eventfd (skip: non-Linux)");
    return 0;
#else
    pp_ring_t *a = new_ring_with_ipc(PP_RING_IPC_EVENTFD);
    pp_ring_t *b = new_ring_with_ipc(PP_RING_IPC_EVENTFD);
    if (!a || !b) FAIL("create rings");

    pp_ring_ipc_waiter_t *w = pp_ring_ipc_waiter_create();
    if (!w) FAIL("waiter_create");
    pp_ring_ipc_waiter_add(w, a);
    pp_ring_ipc_waiter_add(w, b);

    prod_arg_t pa = { .ring = b, .delay_ms = 0 };
    pthread_t th;
    if (pthread_create(&th, NULL, producer, &pa) != 0) FAIL("pthread_create");
    pthread_join(th, NULL);

    pp_ring_ipc_waiter_wait(w, 50000);

    void *p = NULL;
    if (pp_ring_dequeue(b, &p) != 1 || p != (void *)(uintptr_t)42)
        FAIL("eventfd ring b dequeue after waiter");

    pp_ring_ipc_waiter_destroy(w);
    pp_ring_destroy(a);
    pp_ring_destroy(b);
    OK("  waiter multi-eventfd");
    return 0;
#endif
}

static int test_ipc_mode_parse(void)
{
    bool ok;
    if (pp_ring_ipc_mode_parse("futex", &ok) != PP_RING_IPC_POLLING || ok)
        FAIL("futex 应解析失败并回退 polling");
    if (pp_ring_ipc_mode_parse("eventfd", &ok) != PP_RING_IPC_EVENTFD || !ok)
        FAIL("eventfd parse");
    OK("  ipc_mode parse");
    return 0;
}

int main(void)
{
    int rc = 0;
    rc |= test_polling_idle();
    rc |= test_eventfd_no_lost_wakeup();
    rc |= test_eventfd_wake_after_idle();
    rc |= test_waiter_multi_eventfd();
    rc |= test_ipc_mode_parse();
    return rc ? 1 : 0;
}
