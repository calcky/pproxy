/* src/modules/worker/worker.c -- DPI worker 线程
 *
 * 每个 worker 线程通过环境变量 PP_WORKER_IDX 之类不可靠，改为：
 * main 创建 N 个 pp_module_t（name="worker0".."worker_{N-1}"），
 * priv 中保存自己的 shard idx。
 *
 * 模块边界：init() 把 g_rt 中需要的指针快照到 priv，主循环只读 priv。
 */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "pproxy/drop.h"
#include "pproxy/flow.h"
#include "pproxy/packet.h"
#include "pproxy/ring_ipc.h"
#include "../runtime.h"
#include "../modules.h"

typedef struct wk_priv {
    int      idx;                       /* 0..n_workers-1 */
    /* injected at init() */
    pp_runtime_t           *rt;             /* 仅给 pp_drop_by_sid 用 */
    pp_session_shard_t     *shard;
    pp_dpi_chain_t         *dpi;
    pp_ring_t              *rx_ring;
    pp_ring_t              *back_ring;
    pp_ring_t              *ctrl_ring;
    pp_ring_t              *left_tx_ring;
    pp_ring_t             **right_tx_rings;  /* size = n_tunnels */
    int                     n_tunnels;
    pp_ring_ipc_waiter_t   *ipc_waiter;
    uint32_t                poll_backoff_us;
    /* counters */
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
    wk_priv_t *p = m->priv;
    p->rt              = g_rt;
    p->shard           = g_rt->shards[p->idx];
    p->dpi             = g_rt->dpi;
    p->rx_ring         = g_rt->worker_rx_ring[p->idx];
    p->back_ring       = g_rt->worker_back_ring[p->idx];
    p->ctrl_ring       = g_rt->worker_ctrl_ring[p->idx];
    p->left_tx_ring    = g_rt->left_tx_ring;
    p->right_tx_rings  = g_rt->right_tx_ring;
    p->n_tunnels       = g_rt->n_tunnels;
    p->poll_backoff_us = g_rt->ring_ipc.poll_backoff_us;
    p->ipc_waiter      = pp_ring_ipc_waiter_create();
    if (!p->ipc_waiter) return PP_ERR_NOMEM;
    pp_ring_ipc_waiter_add(p->ipc_waiter, p->rx_ring);
    pp_ring_ipc_waiter_add(p->ipc_waiter, p->back_ring);
    pp_ring_ipc_waiter_add(p->ipc_waiter, p->ctrl_ring);
    return PP_OK;
}

/* 处理一条左向包：DPI + 决定 tunnel + 投递 */
static void process_upstream(wk_priv_t *p, pp_pkt_t *pkt)
{
    pp_flow_key_t k;
    if (pp_flow_key_from_pkt(pkt, &k) != PP_OK) {
        pp_drop_orphan_pkt(1, PP_ORPHAN_WK_UP_BAD_KEY, "worker",
                           "flow_key_from_pkt failed", pkt);
        pp_pkt_put_ref(pkt); p->drops++; return;
    }
    pp_flow_dir_t dir;
    pp_flow_key_normalize(&k, &dir);

    bool is_new;
    pp_session_t *s = pp_session_lookup_or_create(p->shard, &k, &is_new);
    if (!s) {
        pp_drop_orphan(1, PP_ORPHAN_WK_UP_TABLE_FULL, "worker",
                       "session table full (lookup_or_create)", &k);
        pp_pkt_put_ref(pkt); p->drops++; return;
    }

    /* 设 payload 偏移（简化：tcp 假定无 options） */
    if (pkt->meta.l4_off != UINT16_MAX && pkt->meta.payload_off == UINT16_MAX) {
        pkt->meta.payload_off = pkt->meta.l4_off
            + (pkt->meta.l4_proto == 6 ? 20 : 8);
        if (pkt->meta.payload_off <= pkt->data_len)
            pkt->meta.payload_len = pkt->data_len - pkt->meta.payload_off;
    }

    pp_dpi_chain_run(p->dpi, s, pkt, dir);

    s->last_ns = pp_now_ns();
    if (s->state == PP_SS_NEW) s->state = PP_SS_EST;

    /* 选 tunnel：MVP 简单取模 */
    int j = s->tunnel_idx % p->n_tunnels;

    /* 用 mbuf 复用：把整个 IP 包当 payload 发出去 */
    pp_tun_buf_t tb = { .data = pkt->data, .len = pkt->data_len };
    /* 这里同步调用 tunnel send 也行，但放在 right_tx 线程里更整洁。
     * 为了简单：把 (sid, pkt) 打包入 right_tx ring；
     *   - 复用 pp_pkt_t 自身：在 meta.flow_hash 暂存 sid（hack）
     *     更正式做法是封装 pp_tx_item_t。
     */
    pkt->meta.flow_hash = s->sid;
    pkt->meta.sid       = s->sid;
    if (pp_ring_enqueue(p->right_tx_rings[j], pkt) == 0) {
        pp_drop_session(s, 1, "worker", "right_tx ring full");
        pp_pkt_put_ref(pkt); p->drops++;
    } else {
        s->up.pkts++;
        s->up.bytes += pkt->data_len;
        p->out++;
    }
    (void)tb;
}

/* 处理一条右向（tunnel 收上来的）包：按内层五元组 lookup_or_create，与对端首包 sid 无关 */
static void process_downstream(wk_priv_t *p, pp_pkt_t *pkt)
{
    if (pkt->meta.l3_off == UINT16_MAX) {
        if (pp_pkt_parse_l3_ipv4(pkt) != PP_OK) {
            pp_drop_orphan_pkt(0, PP_ORPHAN_WK_DN_L3, "worker",
                               "parse_l3_ipv4 failed", pkt);
            pp_pkt_put_ref(pkt);
            p->drops++;
            return;
        }
    }
    pp_flow_key_t k;
    if (pp_flow_key_from_pkt(pkt, &k) != PP_OK) {
        pp_drop_orphan_pkt(0, PP_ORPHAN_WK_DN_BAD_KEY, "worker",
                           "flow_key_from_pkt failed", pkt);
        pp_pkt_put_ref(pkt);
        p->drops++;
        return;
    }
    pp_flow_dir_t dir;
    pp_flow_key_normalize(&k, &dir);
    bool         is_new;
    pp_session_t *s = pp_session_lookup_or_create(p->shard, &k, &is_new);
    (void)is_new;
    if (!s) {
        pp_drop_orphan(0, PP_ORPHAN_WK_DN_TABLE_FULL, "worker",
                       "session table full (lookup_or_create)", &k);
        pp_pkt_put_ref(pkt);
        p->drops++;
        return;
    }
    if (s->state == PP_SS_NEW) s->state = PP_SS_EST;

    s->last_ns = pp_now_ns();

    pkt->meta.sid = s->sid;
    if (pp_ring_enqueue(p->left_tx_ring, pkt) == 0) {
        pp_drop_session(s, 0, "worker", "left_tx ring full");
        pp_pkt_put_ref(pkt); p->drops++;
    } else {
        s->dn.pkts++;
        s->dn.bytes += pkt->data_len;
        p->out++;
    }
}

static void process_ctrl(wk_priv_t *p)
{
    void *msg;
    while (pp_ring_dequeue(p->ctrl_ring, &msg) == 1) {
        pp_ctl_msg_t *m = msg;
        switch (m->op) {
        case PP_CTL_GC_TICK:
            pp_session_gc(p->shard, pp_now_ns());
            break;
        case PP_CTL_KICK_SESSION: {
            pp_session_t *s = pp_session_lookup_by_sid(p->shard, m->arg0);
            if (s) pp_session_remove(p->shard, s);
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
    pp_thread_setup(m, m->name, m->cpu);
    PP_INFO("%s: started (shard=%d)", m->name, p->idx);

    pp_pkt_t *batch[PP_PKT_BURST_MAX];
    while (!pp_module_should_quit(m)) {
        int idle = 1;

        int n = pp_ring_dequeue_burst(p->rx_ring,
                                      (void **)batch, PP_PKT_BURST_MAX);
        if (n > 0) {
            p->in += n;
            for (int i = 0; i < n; i++) process_upstream(p, batch[i]);
            idle = 0;
        }
        n = pp_ring_dequeue_burst(p->back_ring,
                                  (void **)batch, PP_PKT_BURST_MAX);
        if (n > 0) {
            p->in += n;
            for (int i = 0; i < n; i++) process_downstream(p, batch[i]);
            idle = 0;
        }
        process_ctrl(p);
        p->loops++;
        if (idle)
            pp_ring_ipc_waiter_wait(p->ipc_waiter, p->poll_backoff_us);
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
    wk_priv_t *p = m->priv;
    if (p) {
        pp_ring_ipc_waiter_destroy(p->ipc_waiter);
        free(p);
    }
    m->priv = NULL;
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
