/* src/modules/timer/timer.c -- 老化、心跳
 *
 * 模块边界：init() 把 g_rt 中需要的指针快照到 priv，主循环只读 priv。
 */
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "../runtime.h"

typedef struct tm_priv {
    /* injected at init() */
    pp_ring_t **ctrl_rings;     /* size = n_workers */
    int         n_workers;
    /* counters */
    uint64_t loops, ticks;
} tm_priv_t;

static int tm_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    tm_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->ctrl_rings = g_rt->worker_ctrl_ring;
    p->n_workers  = g_rt->n_workers;
    m->priv = p;
    return PP_OK;
}

static void *tm_loop(void *arg)
{
    pp_module_t *m = arg;
    tm_priv_t   *p = m->priv;
    pp_thread_setup(m, m->name, m->cpu);
    PP_INFO("%s: started", m->name);

    while (!pp_module_should_quit(m)) {
        struct timespec ts = {1, 0};        /* 1 秒 tick */
        nanosleep(&ts, NULL);
        if (pp_module_should_quit(m)) break;
        p->ticks++;

        for (int i = 0; i < p->n_workers; i++) {
            pp_ctl_msg_t *msg = calloc(1, sizeof *msg);
            if (!msg) continue;
            msg->op = PP_CTL_GC_TICK;
            if (pp_ring_enqueue(p->ctrl_rings[i], msg) == 0) free(msg);
        }
        p->loops++;
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int tm_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, tm_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void tm_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void tm_destroy(pp_module_t *m) { free(m->priv); m->priv = NULL; }

static void tm_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    tm_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops      = p ? p->loops : 0;
    s->events_out = p ? p->ticks : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_timer_ops = {
    .init = tm_init, .start = tm_start, .stop = tm_stop,
    .destroy = tm_destroy, .stat = tm_stat,
};
