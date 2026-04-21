/* src/dpi/tls.c -- TLS ClientHello SNI 识别（stub） */
#include "pproxy/dpi.h"
#include <netinet/in.h>

static pp_dpi_verdict_t tls_probe(const pp_session_t *s, const pp_pkt_t *p)
{
    (void)s;
    if (p->meta.payload_len < 6) return PP_DPI_NEED_MORE;
    const uint8_t *d = p->data + p->meta.payload_off;
    /* 0x16 = Handshake, 0x0301/0x0303 = TLS1.0/1.2 */
    if (d[0] == 0x16 && d[1] == 0x03) return PP_DPI_MATCH;
    return PP_DPI_NO_MATCH;
}

static pp_dpi_verdict_t tls_parse(pp_session_t *s, const pp_pkt_t *p, pp_flow_dir_t dir)
{
    (void)s; (void)p; (void)dir;
    /* TODO: 解析 ClientHello SNI 并存到 dpi_ctx */
    return PP_DPI_DONE;
}

const pp_dpi_ops_t pp_dpi_tls = {
    .name = "tls", .app_proto = PP_APP_TLS, .priority = 10,
    .l4_mask = (1u << IPPROTO_TCP),
    .probe = tls_probe, .parse = tls_parse,
};
