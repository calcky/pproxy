/* src/dpi/http.c -- HTTP Host 识别（stub） */
#include <string.h>
#include "pproxy/dpi.h"
#include <netinet/in.h>

static pp_dpi_verdict_t http_probe(const pp_session_t *s, const pp_pkt_t *p)
{
    (void)s;
    if (p->meta.payload_len < 4) return PP_DPI_NEED_MORE;
    const char *d = (const char *)(p->data + p->meta.payload_off);
    static const char *const verbs[] = {"GET ","POST","HEAD","PUT ","DELE","OPTI"};
    for (size_t i = 0; i < sizeof verbs / sizeof verbs[0]; i++)
        if (memcmp(d, verbs[i], 4) == 0) return PP_DPI_MATCH;
    return PP_DPI_NO_MATCH;
}

static pp_dpi_verdict_t http_parse(pp_session_t *s, const pp_pkt_t *p, pp_flow_dir_t dir)
{
    (void)s; (void)p; (void)dir;
    /* TODO: 解析 Host header */
    return PP_DPI_DONE;
}

const pp_dpi_ops_t pp_dpi_http = {
    .name = "http", .app_proto = PP_APP_HTTP, .priority = 20,
    .l4_mask = (1u << IPPROTO_TCP),
    .probe = http_probe, .parse = http_parse,
};
