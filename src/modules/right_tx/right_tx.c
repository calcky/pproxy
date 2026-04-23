/* src/modules/right_tx/right_tx.c -- 右手发包线程（每条 tunnel 一个） */
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "pproxy/drop.h"
#include "../runtime.h"
#include "../modules.h"

typedef struct rtx_priv {
    int      idx;                       /* tunnel idx */
    uint64_t loops, in, out, drops;
} rtx_priv_t;

int pp_right_tx_set_index(pp_module_t *m, int idx)
{
    rtx_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->idx = idx; m->priv = p;
    return PP_OK;
}

static int rtx_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    if (!m->priv) return PP_ERR_INVAL;
    rtx_priv_t *p = m->priv;
    /* 主动 connect 一次（同步）；失败由 send 时再重试 */
    if (g_rt->tun_ops[p->idx]->connect)
        g_rt->tun_ops[p->idx]->connect(g_rt->tun_ctx[p->idx]);
    return PP_OK;
}

static void *rtx_loop(void *arg)
{
    pp_module_t *m = arg;
    rtx_priv_t  *p = m->priv;
    pp_thread_setup(m, m->name, m->cpu);
    PP_INFO("%s: started (tunnel=%d)", m->name, p->idx);

    pp_pkt_t *batch[PP_PKT_BURST_MAX];
    while (!pp_module_should_quit(m)) {
        int n = pp_ring_dequeue_burst(g_rt->right_tx_ring[p->idx],
                                      (void **)batch, PP_PKT_BURST_MAX);
        if (n <= 0) {
            struct timespec ts = {0, 200 * 1000};
            nanosleep(&ts, NULL);
            p->loops++; continue;
        }
        p->in += n;
        for (int i = 0; i < n; i++) {
            pp_pkt_t *pkt = batch[i];
            uint64_t sid = pkt->meta.sid ? pkt->meta.sid : pkt->meta.flow_hash;
            pp_tun_buf_t b = { .data = pkt->data, .len = pkt->data_len };
            int r = g_rt->tun_ops[p->idx]->send(g_rt->tun_ctx[p->idx], sid, &b);
            if (r < 0) {
                pp_drop_by_sid(g_rt, sid, 1, "right_tx", "tunnel send failed");
                p->drops++;
            } else
                p->out++;
            pp_pkt_put_ref(pkt);
        }
        p->loops++;
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int rtx_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, rtx_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void rtx_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void rtx_destroy(pp_module_t *m) { free(m->priv); m->priv = NULL; }

static void rtx_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    rtx_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops = p ? p->loops : 0;
    s->events_in  = p ? p->in : 0;
    s->events_out = p ? p->out : 0;
    s->drops      = p ? p->drops : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_right_tx_ops = {
    .init = rtx_init, .start = rtx_start, .stop = rtx_stop,
    .destroy = rtx_destroy, .stat = rtx_stat,
};
