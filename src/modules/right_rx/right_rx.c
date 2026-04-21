/* src/modules/right_rx/right_rx.c -- 右手收包线程（每条 tunnel 一个） */
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "../runtime.h"
#include "../modules.h"

typedef struct rrx_priv {
    int      idx;
    uint64_t loops, in, out, drops;
} rrx_priv_t;

int pp_right_rx_set_index(pp_module_t *m, int idx)
{
    rrx_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->idx = idx; m->priv = p;
    return PP_OK;
}

static int rrx_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    return m->priv ? PP_OK : PP_ERR_INVAL;
}

static void *rrx_loop(void *arg)
{
    pp_module_t *m = arg;
    rrx_priv_t  *p = m->priv;
    pp_thread_setup(m->name, m->cpu);
    PP_INFO("%s: started (tunnel=%d)", m->name, p->idx);

    while (!pp_module_should_quit(m)) {
        pp_pkt_t *pkt = pp_mempool_alloc(g_rt->pool);
        if (!pkt) {
            struct timespec ts = {0, 200 * 1000};
            nanosleep(&ts, NULL);
            p->loops++; continue;
        }
        pp_tun_mbuf_t mb = { .data = pkt->data,
                             .cap  = pkt->buf_len - pkt->headroom,
                             .len  = 0 };
        uint64_t sid;
        int r = g_rt->tun_ops[p->idx]->recv(g_rt->tun_ctx[p->idx], &sid, &mb, 100000);
        if (r <= 0) {
            pp_pkt_put_ref(pkt);
            p->loops++;
            if (r < 0) {
                struct timespec ts = {0, 1000 * 1000};
                nanosleep(&ts, NULL);
            }
            continue;
        }
        pkt->data_len      = (uint16_t)mb.len;
        pkt->tailroom     -= (uint16_t)mb.len;
        pkt->origin        = PP_PKT_FROM_TUNNEL;
        pkt->meta.flow_hash = sid;            /* 暂存 sid */
        pkt->meta.rx_ns    = pp_now_ns();
        p->in++;

        int shard = (int)(pp_sid_shard(sid) % (uint16_t)g_rt->n_workers);
        if (pp_ring_enqueue(g_rt->worker_back_ring[shard], pkt) == 0) {
            pp_pkt_put_ref(pkt); p->drops++;
        } else {
            p->out++;
        }
        p->loops++;
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int rrx_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, rrx_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void rrx_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void rrx_destroy(pp_module_t *m) { free(m->priv); m->priv = NULL; }

static void rrx_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    rrx_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops = p ? p->loops : 0;
    s->events_in  = p ? p->in : 0;
    s->events_out = p ? p->out : 0;
    s->drops      = p ? p->drops : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_right_rx_ops = {
    .init = rrx_init, .start = rrx_start, .stop = rrx_stop,
    .destroy = rrx_destroy, .stat = rrx_stat,
};
