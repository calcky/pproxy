/* src/dpi/dns.c -- DNS 识别（stub） */
#include "pproxy/dpi.h"
#include <netinet/in.h>

static pp_dpi_verdict_t dns_probe(const pp_session_t *s, const pp_pkt_t *p)
{
    (void)s;
    /* DNS over UDP 通常 dport=53 */
    if (s->key.l4_proto == IPPROTO_UDP &&
        (s->key.dport == 53 || s->key.sport == 53))
        return PP_DPI_MATCH;
    (void)p;
    return PP_DPI_NO_MATCH;
}

static pp_dpi_verdict_t dns_parse(pp_session_t *s, const pp_pkt_t *p, pp_flow_dir_t dir)
{
    (void)s; (void)p; (void)dir;
    return PP_DPI_DONE;
}

const pp_dpi_ops_t pp_dpi_dns = {
    .name = "dns", .app_proto = PP_APP_DNS, .priority = 5,
    .l4_mask = (1u << IPPROTO_UDP),
    .probe = dns_probe, .parse = dns_parse,
};
