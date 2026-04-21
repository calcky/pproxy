/* src/io/registry.c -- I/O 后端注册表 */
#include <string.h>
#include "pproxy/pkt_io.h"

#define PP_IO_MAX 8
static const pp_pkt_io_ops_t *g_ops[PP_IO_MAX];
static int g_n;

int pp_pkt_io_register(const pp_pkt_io_ops_t *ops)
{
    if (!ops) return PP_ERR_INVAL;
    if (g_n >= PP_IO_MAX) return PP_ERR_FULL;
    g_ops[g_n++] = ops;
    return PP_OK;
}

const pp_pkt_io_ops_t *pp_pkt_io_lookup(pp_io_kind_t kind)
{
    for (int i = 0; i < g_n; i++)
        if (g_ops[i]->kind == kind) return g_ops[i];
    return NULL;
}
