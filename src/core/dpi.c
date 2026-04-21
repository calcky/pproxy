/* core/dpi.c -- DPI 插件链 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "pproxy/dpi.h"
#include "pproxy/log.h"

#define PP_DPI_MAX_PROBE_PKTS 8     /* 前 N 个包内做识别 */

struct pp_dpi_chain_node {
    const pp_dpi_ops_t *ops;
    uint8_t             effective_prio;
    atomic_bool         enabled;       /* 热开关，运行时可变 */
};

struct pp_dpi_chain {
    struct pp_dpi_chain_node plugins[PP_DPI_MAX_PLUGINS];
    int                      n;
};

pp_dpi_chain_t *pp_dpi_chain_create(void)
{
    return calloc(1, sizeof(pp_dpi_chain_t));
}

void pp_dpi_chain_destroy(pp_dpi_chain_t *c) { free(c); }

int pp_dpi_chain_register_ex(pp_dpi_chain_t *c, const pp_dpi_ops_t *ops,
                             int priority_override)
{
    if (!c || !ops) return PP_ERR_INVAL;
    if (c->n >= PP_DPI_MAX_PLUGINS) return PP_ERR_FULL;
    if (ops->global_init && ops->global_init() != PP_OK) return PP_ERR_GENERIC;

    uint8_t prio = (priority_override >= 0 && priority_override <= 255)
                 ? (uint8_t)priority_override
                 : ops->priority;

    /* 按 effective_prio 升序插入；移动时手动处理 atomic_bool（不能用聚合赋值） */
    int i = c->n;
    while (i > 0 && c->plugins[i - 1].effective_prio > prio) {
        c->plugins[i].ops            = c->plugins[i - 1].ops;
        c->plugins[i].effective_prio = c->plugins[i - 1].effective_prio;
        atomic_store(&c->plugins[i].enabled,
                     atomic_load(&c->plugins[i - 1].enabled));
        i--;
    }
    c->plugins[i].ops            = ops;
    c->plugins[i].effective_prio = prio;
    atomic_store(&c->plugins[i].enabled, true);
    c->n++;
    PP_INFO("dpi: registered %s (proto=%u, prio=%u%s)",
            ops->name, ops->app_proto, prio,
            (prio != ops->priority) ? " [override]" : "");
    return PP_OK;
}

int pp_dpi_chain_register(pp_dpi_chain_t *c, const pp_dpi_ops_t *ops)
{
    return pp_dpi_chain_register_ex(c, ops, -1);
}

int pp_dpi_chain_set_enabled(pp_dpi_chain_t *c, const char *name, bool enabled)
{
    if (!c || !name) return PP_ERR_INVAL;
    for (int i = 0; i < c->n; i++) {
        if (strcmp(c->plugins[i].ops->name, name) != 0) continue;
        atomic_store(&c->plugins[i].enabled, enabled);
        PP_INFO("dpi: plugin %s enabled=%s (hot)", name, enabled ? "true" : "false");
        return PP_OK;
    }
    return PP_ERR_NOTFOUND;
}

int pp_dpi_chain_run(pp_dpi_chain_t *c, pp_session_t *s,
                     const pp_pkt_t *p, pp_flow_dir_t dir)
{
    if (!c || !s || !p) return PP_ERR_INVAL;
    if (s->dpi_pkts >= PP_DPI_MAX_PROBE_PKTS) return PP_OK;
    s->dpi_pkts++;

    if (s->app_proto != PP_APP_UNKNOWN) {
        /* 已识别：找回插件继续 parse（不看 enabled：允许 session 沿用已有识别） */
        for (int i = 0; i < c->n; i++) {
            const pp_dpi_ops_t *op = c->plugins[i].ops;
            if (op->app_proto == s->app_proto) {
                pp_dpi_verdict_t v = op->parse(s, p, dir);
                if (v == PP_DPI_DONE) s->dpi_pkts = PP_DPI_MAX_PROBE_PKTS;
                return PP_OK;
            }
        }
        return PP_OK;
    }

    /* 未识别：依次 probe，跳过被热开关关闭的 */
    for (int i = 0; i < c->n; i++) {
        if (!atomic_load_explicit(&c->plugins[i].enabled, memory_order_relaxed))
            continue;
        const pp_dpi_ops_t *op = c->plugins[i].ops;
        if (!(op->l4_mask & (1u << s->key.l4_proto))) continue;
        pp_dpi_verdict_t v = op->probe(s, p);
        if (v == PP_DPI_MATCH) {
            if (op->ctx_init) op->ctx_init(s);
            s->app_proto = op->app_proto;
            op->parse(s, p, dir);
            return PP_OK;
        }
    }
    return PP_OK;
}
