/* core/drop.c -- 丢包日志与计数 */
#include <stdatomic.h>
#include <stdio.h>
#include "pproxy/drop.h"
#include "pproxy/flow.h"
#include "pproxy/log.h"
#include "pproxy/packet.h"
#include "pproxy/session.h"
#include "pproxy/pproxy.h"
#include "../modules/runtime.h"

static _Atomic uint64_t g_orphan[PP_ORPHAN__N];

static const char *orphan_name(pp_orphan_drop_t k)
{
    static const char *const names[PP_ORPHAN__N] = {
        "lrx_flow_key",
        "lrx_worker_rx_ring_full",
        "rrx_l3_parse",
        "rrx_flow_key",
        "rrx_worker_back_ring_full",
        "wk_up_flow_key",
        "wk_up_session_table_full",
        "wk_up_right_tx_ring_full",
        "wk_down_l3_parse",
        "wk_down_flow_key",
        "wk_down_session_table_full",
        "wk_down_left_tx_ring_full",
    };
    if ((unsigned)k < PP_ORPHAN__N) return names[k];
    return "unknown";
}

void pp_drop_orphan_get(pp_drop_orphan_totals_t *out)
{
    if (!out) return;
    for (int i = 0; i < PP_ORPHAN__N; i++)
        out->v[i] = atomic_load_explicit(
            &g_orphan[i], memory_order_relaxed);
}

void pp_drop_session(struct pp_session *s, int up_path,
                     const char *where, const char *reason)
{
    if (!s) return;
    if (up_path)
        (void)atomic_fetch_add_explicit(&s->up.drops, 1, memory_order_relaxed);
    else
        (void)atomic_fetch_add_explicit(&s->dn.drops, 1, memory_order_relaxed);
    char kbuf[128];
    pp_flow_key_format(&s->key, kbuf, sizeof kbuf);
    PP_TRACE("drop: where=%s sid=%lx up=%d flow=%s reason=%s",
             where, (unsigned long)s->sid, up_path, kbuf, reason);
}

void pp_drop_orphan(int up_path, pp_orphan_drop_t kind, const char *where,
                    const char *reason, const pp_flow_key_t *k_opt)
{
    if ((unsigned)kind < PP_ORPHAN__N)
        (void)atomic_fetch_add_explicit(&g_orphan[kind], 1, memory_order_relaxed);
    if (k_opt) {
        char kbuf[128];
        pp_flow_key_format(k_opt, kbuf, sizeof kbuf);
        PP_TRACE("drop(orphan): where=%s path=%s kind=%s up=%d flow=%s reason=%s",
                 where, "orphan", orphan_name(kind), up_path, kbuf, reason);
    } else {
        PP_TRACE("drop(orphan): where=%s kind=%s up=%d reason=%s (no 5-tuple)",
                 where, orphan_name(kind), up_path, reason);
    }
}

void pp_drop_orphan_pkt(int up_path, pp_orphan_drop_t kind, const char *where,
                        const char *reason, const pp_pkt_t *pkt)
{
    pp_flow_key_t fk;
    if (pkt && pp_flow_key_from_pkt(pkt, &fk) == PP_OK)
        pp_drop_orphan(up_path, kind, where, reason, &fk);
    else
        pp_drop_orphan(up_path, kind, where, reason, NULL);
}

void pp_drop_by_sid(pp_runtime_t *rt, uint64_t sid, int up_path,
                    const char *where, const char *reason)
{
    if (!sid) {
        PP_TRACE("drop: where=%s sid=0 up=%d reason=%s (no session id on mbuf)",
                 where, up_path, reason);
        return;
    }
    if (!rt) return;
    uint16_t sh = pp_sid_shard(sid);
    if (sh >= (uint16_t)rt->n_workers || !rt->shards[sh]) {
        PP_TRACE("drop: where=%s sid=%lx up=%d reason=%s (invalid shard)",
                 where, (unsigned long)sid, up_path, reason);
        return;
    }
    pp_session_t *s = pp_session_lookup_by_sid(rt->shards[sh], sid);
    if (s)
        pp_drop_session(s, up_path, where, reason);
    else
        PP_TRACE("drop: where=%s sid=%lx up=%d reason=%s (session not found, maybe expired)",
                 where, (unsigned long)sid, up_path, reason);
}
