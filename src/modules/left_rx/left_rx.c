/* src/modules/left_rx/left_rx.c -- 左手收包线程
 *
 * 主循环：
 *   1) 在 fd 上 epoll_wait（若后端支持），或 busy poll；
 *   2) rx_burst 拉一批包；
 *   3) 解析 FlowKey -> 计算 hash -> 投递到对应 worker rx_ring；
 *   4) 队列满则丢弃 + drops++（暂不背压）。
 *
 * 模块边界：init() 把 g_rt 中需要的指针快照到 priv，主循环只读 priv。
 */
#include <pthread.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "pproxy/drop.h"
#include "pproxy/flow.h"
#include "../runtime.h"

typedef struct lrx_priv {
    int        epfd;
    int        rx_fd;
    /* injected at init() */
    const pp_pkt_io_ops_t *left_ops;
    void                  *left_ctx;
    pp_ring_t            **worker_rx_rings;   /* size = n_workers */
    int                    n_workers;
    /* counters */
    uint64_t   loops, in, out, drops;
} lrx_priv_t;

static int lrx_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    lrx_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;

    p->left_ops        = g_rt->left_ops;
    p->left_ctx        = g_rt->left_ctx;
    p->worker_rx_rings = g_rt->worker_rx_ring;
    p->n_workers       = g_rt->n_workers;

    p->rx_fd = p->left_ops->get_rx_fd ? p->left_ops->get_rx_fd(p->left_ctx) : -1;
    if (p->rx_fd >= 0) {
        p->epfd = epoll_create1(EPOLL_CLOEXEC);
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = p->rx_fd };
        epoll_ctl(p->epfd, EPOLL_CTL_ADD, p->rx_fd, &ev);
    } else {
        p->epfd = -1;
    }
    m->priv = p;
    return PP_OK;
}

static void *lrx_loop(void *arg)
{
    pp_module_t *m = arg;
    lrx_priv_t  *p = m->priv;
    pp_thread_setup(m, m->name, m->cpu);
    PP_INFO("%s: started (fd=%d)", m->name, p->rx_fd);

    pp_pkt_t *batch[PP_PKT_BURST_MAX];
    while (!pp_module_should_quit(m)) {
        if (p->epfd >= 0) {
            struct epoll_event ev;
            int n = epoll_wait(p->epfd, &ev, 1, 100);
            if (n <= 0) { p->loops++; continue; }
        }
        int n = p->left_ops->rx_burst(p->left_ctx, batch, PP_PKT_BURST_MAX, 0);
        if (n <= 0) { p->loops++; continue; }
        p->in += n;

        for (int i = 0; i < n; i++) {
            pp_pkt_t *pkt = batch[i];
            pp_flow_key_t k;
            if (pp_flow_key_from_pkt(pkt, &k) != PP_OK) {
                pp_drop_orphan_pkt(1, PP_ORPHAN_LRX_BAD_KEY, "left_rx",
                                    "flow_key_from_pkt failed", pkt);
                pp_pkt_put_ref(pkt); p->drops++; continue;
            }
            pp_flow_dir_t dir;
            pp_flow_key_normalize(&k, &dir);
            uint64_t h = pp_flow_key_hash(&k);
            /* shard 与 right_rx 一致：见 pp_flow_shard() 契约 */
            int idx = (int)(h % (uint64_t)p->n_workers);
            pkt->meta.shard     = (uint16_t)idx;
            pkt->meta.flow_hash = h;

            if (pp_ring_enqueue(p->worker_rx_rings[idx], pkt) == 0) {
                pp_drop_orphan(1, PP_ORPHAN_LRX_WKR_RX_RING, "left_rx",
                               "worker_rx ring full", &k);
                pp_pkt_put_ref(pkt); p->drops++;
            } else {
                p->out++;
            }
        }
        p->loops++;
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int lrx_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, lrx_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void lrx_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void lrx_destroy(pp_module_t *m)
{
    lrx_priv_t *p = m->priv;
    if (!p) return;
    if (p->epfd >= 0) close(p->epfd);
    free(p);
    m->priv = NULL;
}

static void lrx_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    lrx_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops = p ? p->loops : 0;
    s->events_in  = p ? p->in : 0;
    s->events_out = p ? p->out : 0;
    s->drops      = p ? p->drops : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_left_rx_ops = {
    .init = lrx_init, .start = lrx_start, .stop = lrx_stop,
    .destroy = lrx_destroy, .stat = lrx_stat,
};
