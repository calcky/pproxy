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

/* 高带宽时 UDP/TCP 隧道 send 常见 PP_ERR_AGAIN（内核发送缓冲满）；短重试避免立刻按会话 drop。 */
#define RTX_SEND_AGAIN_MAX   10
#define RTX_SEND_AGAIN_NS    (200 * 1000L)   /* 每轮 0.2ms，合计约 2ms */

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

static void rtx_nanosleep_again(void)
{
    struct timespec ts = {0, RTX_SEND_AGAIN_NS};
    nanosleep(&ts, NULL);
}

static int rtx_send_one(int idx, const pp_tun_buf_t *b)
{
    int r;
    for (int a = 0; ; a++) {
        r = g_rt->tun_ops[idx]->send(g_rt->tun_ctx[idx], b);
        if (r != PP_ERR_AGAIN) break;
        if (a >= RTX_SEND_AGAIN_MAX) break;
        rtx_nanosleep_again();
    }
    return r;
}

#ifdef PP_HAVE_IO_URING
static bool rtx_use_uring_burst(int idx)
{
    const pp_tunnel_cfg_t *tc = &g_rt->tun_cfg[idx];
    return tc->io == PP_TIO_KERNEL_SOCKET
        && tc->proto == PP_PROTO_UDP
        && tc->io_cfg.ks.backend == PP_KS_BACKEND_IO_URING
        && tc->io_cfg.ks.batch_tx > 1;
}

static void rtx_handle_send_result(rtx_priv_t *p, pp_pkt_t *pkt, uint64_t sid, int r)
{
    if (r < 0) {
        PP_TRACE("right_tx: tunnel send failed: %s (r=%d)", pp_strerror(r), r);
        pp_drop_by_sid(g_rt, sid, 1, "right_tx", "tunnel send failed");
        p->drops++;
    } else {
        p->out++;
    }
    pp_pkt_put_ref(pkt);
}

static void rtx_burst_send(rtx_priv_t *p, pp_pkt_t **batch, int n)
{
    pp_tun_buf_t bufs[PP_PKT_BURST_MAX];
    pp_pkt_t    *valid[PP_PKT_BURST_MAX];
    uint64_t     sids[PP_PKT_BURST_MAX];
    int          results[PP_PKT_BURST_MAX];
    int          nv = 0;

    for (int i = 0; i < n; i++) {
        pp_pkt_t *pkt = batch[i];
        if (!PP_TUN_TX_PAYLOAD_LEN_OK(pkt->data_len)) {
            pp_drop_orphan_pkt(0, PP_ORPHAN_RTX_BAD_PKT, "right_tx",
                               "bad pkt length", pkt);
            pp_pkt_put_ref(pkt);
            p->drops++;
            continue;
        }
        bufs[nv].data = pkt->data;
        bufs[nv].len  = pkt->data_len;
        valid[nv]     = pkt;
        sids[nv]      = pkt->meta.sid ? pkt->meta.sid : pkt->meta.flow_hash;
        nv++;
    }
    if (nv <= 0)
        return;

    unsigned btx = g_rt->tun_cfg[p->idx].io_cfg.ks.batch_tx;
    if (btx > PP_PKT_BURST_MAX)
        btx = PP_PKT_BURST_MAX;

    for (int off = 0; off < nv; off += (int)btx) {
        int chunk = nv - off;
        if (chunk > (int)btx)
            chunk = (int)btx;

        int brc = pp_udp_ks_send_burst(g_rt->tun_ctx[p->idx],
                                       bufs + off, chunk, results + off);
        if (brc < 0) {
            for (int i = off; i < off + chunk; i++) {
                int r = rtx_send_one(p->idx, &bufs[i]);
                rtx_handle_send_result(p, valid[i], sids[i], r);
            }
            continue;
        }

        for (int i = off; i < off + chunk; i++) {
            int r = results[i];
            if (r == PP_ERR_AGAIN)
                r = rtx_send_one(p->idx, &bufs[i]);
            rtx_handle_send_result(p, valid[i], sids[i], r);
        }
    }
}
#endif

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

#ifdef PP_HAVE_IO_URING
        if (rtx_use_uring_burst(p->idx)) {
            rtx_burst_send(p, batch, n);
            p->loops++;
            continue;
        }
#endif

        for (int i = 0; i < n; i++) {
            pp_pkt_t *pkt = batch[i];
            if (!PP_TUN_TX_PAYLOAD_LEN_OK(pkt->data_len)) {
                pp_drop_orphan_pkt(0, PP_ORPHAN_RTX_BAD_PKT, "right_tx",
                                    "bad pkt length", pkt);
                pp_pkt_put_ref(pkt);
                p->drops++;
                continue;
            }
            uint64_t sid = pkt->meta.sid ? pkt->meta.sid : pkt->meta.flow_hash;
            pp_tun_buf_t b = { .data = pkt->data, .len = pkt->data_len };
            int r = rtx_send_one(p->idx, &b);
#ifdef PP_HAVE_IO_URING
            rtx_handle_send_result(p, pkt, sid, r);
#else
            if (r < 0) {
                PP_TRACE("right_tx: tunnel send failed: %s (r=%d)", pp_strerror(r), r);
                pp_drop_by_sid(g_rt, sid, 1, "right_tx", "tunnel send failed");
                p->drops++;
            } else
                p->out++;
            pp_pkt_put_ref(pkt);
#endif
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
