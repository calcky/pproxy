/* src/modules/worker/worker.c -- DPI worker 线程
 *
 * 每个 worker 线程通过环境变量 PP_WORKER_IDX 之类不可靠，改为：
 * main 创建 N 个 pp_module_t（name="worker0".."worker_{N-1}"），
 * priv 中保存自己的 shard idx。
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "../runtime.h"
#include "../modules.h"

typedef struct wk_priv {
    int      idx;                       /* 0..n_workers-1 */
    uint64_t loops, in, out, drops;
} wk_priv_t;

/* 由 main 在创建 pp_module_t 时调用 */
int pp_worker_set_index(pp_module_t *m, int idx)
{
    wk_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;
    p->idx = idx;
    m->priv = p;
    return PP_OK;
}

static int wk_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    if (!m->priv) return PP_ERR_INVAL;   /* 必须先 pp_worker_set_index */
    return PP_OK;
}

/* 处理一条左向包：DPI + 决定 tunnel + 投递 */
static void process_upstream(wk_priv_t *p, pp_pkt_t *pkt)
{
    int idx = p->idx;
    pp_session_shard_t *sh = g_rt->shards[idx];
    pp_flow_key_t k;
    if (pp_flow_key_from_pkt(pkt, &k) != PP_OK) {
        pp_pkt_put_ref(pkt); p->drops++; return;
    }
    pp_flow_dir_t dir;
    pp_flow_key_normalize(&k, &dir);

    bool is_new;
    pp_session_t *s = pp_session_lookup_or_create(sh, &k, &is_new);
    if (!s) { pp_pkt_put_ref(pkt); p->drops++; return; }

    /* 设 payload 偏移（简化：tcp 假定无 options） */
    if (pkt->meta.l4_off != UINT16_MAX && pkt->meta.payload_off == UINT16_MAX) {
        pkt->meta.payload_off = pkt->meta.l4_off
            + (pkt->meta.l4_proto == 6 ? 20 : 8);
        if (pkt->meta.payload_off <= pkt->data_len)
            pkt->meta.payload_len = pkt->data_len - pkt->meta.payload_off;
    }

    pp_dpi_chain_run(g_rt->dpi, s, pkt, dir);

    s->last_ns = pp_now_ns();
    s->up.pkts++;
    s->up.bytes += pkt->data_len;
    if (s->state == PP_SS_NEW) s->state = PP_SS_EST;

    /* 选 tunnel：MVP 简单取模 */
    int j = s->tunnel_idx % g_rt->n_tunnels;

    /* 用 mbuf 复用：把整个 IP 包当 payload 发出去 */
    pp_tun_buf_t tb = { .data = pkt->data, .len = pkt->data_len };
    /* 这里同步调用 tunnel send 也行，但放在 right_tx 线程里更整洁。
     * 为了简单：把 (sid, pkt) 打包入 right_tx ring；
     *   - 复用 pp_pkt_t 自身：在 meta.flow_hash 暂存 sid（hack）
     *     更正式做法是封装 pp_tx_item_t。
     */
    pkt->meta.flow_hash = s->sid;
    if (pp_ring_enqueue(g_rt->right_tx_ring[j], pkt) == 0) {
        pp_pkt_put_ref(pkt); p->drops++;
    } else {
        p->out++;
    }
    (void)tb;
}

/* 处理一条右向（tunnel 收上来的）包：查 sid -> 还原 -> 投 left_tx */
static void process_downstream(wk_priv_t *p, pp_pkt_t *pkt)
{
    pp_session_shard_t *sh = g_rt->shards[p->idx];
    uint64_t sid = pkt->meta.flow_hash;     /* 同样 hack */
    pp_session_t *s = pp_session_lookup_by_sid(sh, sid);
    if (!s) { pp_pkt_put_ref(pkt); p->drops++; return; }

    s->last_ns = pp_now_ns();
    s->dn.pkts++;
    s->dn.bytes += pkt->data_len;

    if (pp_ring_enqueue(g_rt->left_tx_ring, pkt) == 0) {
        pp_pkt_put_ref(pkt); p->drops++;
    } else {
        p->out++;
    }
}

static void process_ctrl(wk_priv_t *p)
{
    pp_session_shard_t *sh = g_rt->shards[p->idx];
    void *msg;
    while (pp_ring_dequeue(g_rt->worker_ctrl_ring[p->idx], &msg) == 1) {
        pp_ctl_msg_t *m = msg;
        switch (m->op) {
        case PP_CTL_GC_TICK:
            pp_session_gc(sh, pp_now_ns());
            break;
        case PP_CTL_KICK_SESSION: {
            pp_session_t *s = pp_session_lookup_by_sid(sh, m->arg0);
            if (s) pp_session_remove(sh, s);
            break;
        }
        default: break;
        }
        free(m);
    }
}

static void *wk_loop(void *arg)
{
    pp_module_t *m = arg;
    wk_priv_t   *p = m->priv;
    pp_thread_setup(m->name, m->cpu);
    PP_INFO("%s: started (shard=%d)", m->name, p->idx);

    pp_pkt_t *batch[PP_PKT_BURST_MAX];
    while (!pp_module_should_quit(m)) {
        int idle = 1;

        int n = pp_ring_dequeue_burst(g_rt->worker_rx_ring[p->idx],
                                      (void **)batch, PP_PKT_BURST_MAX);
        if (n > 0) {
            p->in += n;
            for (int i = 0; i < n; i++) process_upstream(p, batch[i]);
            idle = 0;
        }
        n = pp_ring_dequeue_burst(g_rt->worker_back_ring[p->idx],
                                  (void **)batch, PP_PKT_BURST_MAX);
        if (n > 0) {
            p->in += n;
            for (int i = 0; i < n; i++) process_downstream(p, batch[i]);
            idle = 0;
        }
        process_ctrl(p);
        p->loops++;
        if (idle) {
            struct timespec ts = {0, 50 * 1000};
            nanosleep(&ts, NULL);
        }
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int wk_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, wk_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void wk_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void wk_destroy(pp_module_t *m)
{
    free(m->priv); m->priv = NULL;
}

static void wk_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    wk_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops = p ? p->loops : 0;
    s->events_in  = p ? p->in : 0;
    s->events_out = p ? p->out : 0;
    s->drops      = p ? p->drops : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_worker_ops = {
    .init = wk_init, .start = wk_start, .stop = wk_stop,
    .destroy = wk_destroy, .stat = wk_stat,
};
