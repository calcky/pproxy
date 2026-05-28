/* src/modules/right_rx/right_rx.c -- 右手收包线程（每条 tunnel 一个）
 *
 * 模块边界：init() 把 g_rt 中需要的指针快照到 priv，主循环只读 priv。
 */
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "pproxy/drop.h"
#include "pproxy/flow.h"
#include "pproxy/packet.h"
#include "../runtime.h"
#include "../modules.h"

typedef struct rrx_priv {
    int      idx;
    /* injected at init() */
    const pp_tunnel_ops_t *tun_ops;
    void                  *tun_ctx;
    pp_mempool_t          *pool;
    pp_ring_t            **back_rings;  /* size = n_workers */
    int                    n_workers;
    /* counters */
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
    if (!m->priv) return PP_ERR_INVAL;
    rrx_priv_t *p = m->priv;
    p->tun_ops    = g_rt->tun_ops[p->idx];
    p->tun_ctx    = g_rt->tun_ctx[p->idx];
    p->pool       = g_rt->pool;
    p->back_rings = g_rt->worker_back_ring;
    p->n_workers  = g_rt->n_workers;
    return PP_OK;
}

static void *rrx_loop(void *arg)
{
    pp_module_t *m = arg;
    rrx_priv_t  *p = m->priv;
    pp_thread_setup(m, m->name, m->cpu);
    PP_INFO("%s: started (tunnel=%d)", m->name, p->idx);

    while (!pp_module_should_quit(m)) {
        pp_pkt_t *pkt = pp_mempool_alloc(p->pool);
        if (!pkt) {
            struct timespec ts = {0, 200 * 1000};
            nanosleep(&ts, NULL);
            p->loops++; continue;
        }
        pp_tun_mbuf_t mb = { .data = pkt->data,
                             .cap  = pkt->buf_len - pkt->headroom,
                             .len  = 0 };
        int r = p->tun_ops->recv(p->tun_ctx, &mb, 100000);
        if (r <= 0) {
            pp_pkt_put_ref(pkt);
            p->loops++;
            if (r < 0) {
                struct timespec ts = {0, 1000 * 1000};
                nanosleep(&ts, NULL);
            } else {
                /* r==0：多数 tunnel 已在 poll 上等过；兜底线程极快自旋（如旧 TCP 立即 EAGAIN） */
                struct timespec ts = {0, 200 * 1000};
                nanosleep(&ts, NULL);
            }
            continue;
        }
        pkt->data_len      = (uint16_t)mb.len;
        pkt->tailroom     -= (uint16_t)mb.len;
        pkt->origin        = PP_PKT_FROM_TUNNEL;
        pkt->meta.rx_ns    = pp_now_ns();
        p->in++;

        /* 与 left_rx 相同：按五元组 hash 选 worker，否则与 lookup_or_create 分片不一致。
         * 共享 helper pp_flow_shard() 记录此契约。 */
        if (pp_pkt_parse_l3_ipv4(pkt) != PP_OK) {
            pp_drop_orphan_pkt(0, PP_ORPHAN_RRX_L3, "right_rx",
                                "parse_l3_ipv4 failed", pkt);
            pp_pkt_put_ref(pkt);
            p->drops++;
            p->loops++;
            continue;
        }
        pp_flow_key_t fk;
        pp_flow_dir_t fdir;
        if (pp_flow_key_from_pkt(pkt, &fk) != PP_OK) {
            pp_drop_orphan_pkt(0, PP_ORPHAN_RRX_BAD_KEY, "right_rx",
                                "flow_key_from_pkt failed", pkt);
            pp_pkt_put_ref(pkt);
            p->drops++;
            p->loops++;
            continue;
        }
        pp_flow_key_normalize(&fk, &fdir);
        int shard = pp_flow_shard(&fk, p->n_workers);
        pkt->meta.shard = (uint16_t)shard;
        if (pp_ring_enqueue(p->back_rings[shard], pkt) == 0) {
            pp_drop_orphan(0, PP_ORPHAN_RRX_WKR_BACK_RING, "right_rx",
                           "worker_back ring full", &fk);
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
