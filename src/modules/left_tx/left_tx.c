/* src/modules/left_tx/left_tx.c -- 左手发包线程 */
#include <pthread.h>
#include <stdlib.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "../runtime.h"

typedef struct ltx_priv {
    uint64_t loops, in, out, drops;
} ltx_priv_t;

static int ltx_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    ltx_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    m->priv = p;
    return PP_OK;
}

static void *ltx_loop(void *arg)
{
    pp_module_t *m = arg;
    ltx_priv_t  *p = m->priv;
    pp_thread_setup(m->name, m->cpu);
    PP_INFO("%s: started", m->name);

    pp_pkt_t *batch[PP_PKT_BURST_MAX];
    while (!pp_module_should_quit(m)) {
        int n = pp_ring_dequeue_burst(g_rt->left_tx_ring,
                                      (void **)batch, PP_PKT_BURST_MAX);
        if (n <= 0) {
            struct timespec ts = {0, 100 * 1000};   /* 0.1ms */
            nanosleep(&ts, NULL);
            p->loops++; continue;
        }
        p->in += n;
        int sent = g_rt->left_ops->tx_burst(g_rt->left_ctx, batch, n);
        p->out += sent;
        p->drops += (n - sent);
        for (int i = 0; i < n; i++) pp_pkt_put_ref(batch[i]);
        p->loops++;
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int ltx_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, ltx_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void ltx_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void ltx_destroy(pp_module_t *m)
{
    free(m->priv); m->priv = NULL;
}

static void ltx_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    ltx_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops      = p ? p->loops : 0;
    s->events_in  = p ? p->in : 0;
    s->events_out = p ? p->out : 0;
    s->drops      = p ? p->drops : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_left_tx_ops = {
    .init = ltx_init, .start = ltx_start, .stop = ltx_stop,
    .destroy = ltx_destroy, .stat = ltx_stat,
};
