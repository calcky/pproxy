/* core/module.c -- 模块注册表 */
#include <stdlib.h>
#include <string.h>
#include "pproxy/module.h"
#include "pproxy/log.h"

#define PP_MODULE_MAX  16

static pp_module_t *g_mods[PP_MODULE_MAX];
static int          g_n;

int pp_module_register(pp_module_t *m)
{
    if (!m || !m->ops) return PP_ERR_INVAL;
    if (g_n >= PP_MODULE_MAX) return PP_ERR_FULL;
    g_mods[g_n++] = m;
    atomic_store(&m->state, PP_MOD_REGISTERED);
    PP_INFO("module: registered %s (cpu=%d)", m->name, m->cpu);
    return PP_OK;
}

pp_module_t *pp_module_find(const char *name)
{
    for (int i = 0; i < g_n; i++)
        if (strcmp(g_mods[i]->name, name) == 0) return g_mods[i];
    return NULL;
}

int pp_module_init_all(void *cfg)
{
    for (int i = 0; i < g_n; i++) {
        if (g_mods[i]->ops->init) {
            int r = g_mods[i]->ops->init(g_mods[i], cfg);
            if (r != PP_OK) {
                PP_ERROR("module init failed: %s (%s)",
                         g_mods[i]->name, pp_strerror(r));
                return r;
            }
            atomic_store(&g_mods[i]->state, PP_MOD_INITED);
        }
    }
    return PP_OK;
}

int pp_module_start_all(void)
{
    for (int i = 0; i < g_n; i++) {
        if (g_mods[i]->ops->start) {
            int r = g_mods[i]->ops->start(g_mods[i]);
            if (r != PP_OK) {
                PP_ERROR("module start failed: %s (%s)",
                         g_mods[i]->name, pp_strerror(r));
                return r;
            }
            atomic_store(&g_mods[i]->state, PP_MOD_RUNNING);
        }
    }
    return PP_OK;
}

void pp_module_stop_all(void)
{
    /* 反序停止：先停 left_rx 减少入流量，再停 worker，再停 right_* */
    for (int i = g_n - 1; i >= 0; i--) {
        if (g_mods[i]->ops->stop) {
            atomic_store(&g_mods[i]->state, PP_MOD_STOPPING);
            g_mods[i]->ops->stop(g_mods[i]);
            atomic_store(&g_mods[i]->state, PP_MOD_STOPPED);
        }
    }
}

void pp_module_destroy_all(void)
{
    for (int i = g_n - 1; i >= 0; i--) {
        if (g_mods[i]->ops->destroy)
            g_mods[i]->ops->destroy(g_mods[i]);
    }
    g_n = 0;
}

int pp_module_walk(pp_module_walk_cb cb, void *user)
{
    for (int i = 0; i < g_n; i++) {
        int r = cb(g_mods[i], user);
        if (r != PP_OK) return r;
    }
    return PP_OK;
}
