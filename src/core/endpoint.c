/* core/endpoint.c -- 解析 [::1]:443 / 1.2.3.4:80 / host.example.com:80 */
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "pproxy/pproxy.h"

/* 域名解析 fallback：inet_pton 失败时走 getaddrinfo，取第一条结果。
 * 仅在 startup 解析配置时调用，同步阻塞无妨。 */
static int resolve_host(const char *host, pp_endpoint_t *out)
{
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo *res = NULL;
    int rc = getaddrinfo(host, NULL, &hints, &res);
    if (rc != 0 || !res) return PP_ERR_INVAL;

    int ret = PP_OK;
    if (res->ai_family == AF_INET) {
        out->addr.af = PP_AF_INET;
        out->addr.u.v4 = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
    } else if (res->ai_family == AF_INET6) {
        out->addr.af = PP_AF_INET6;
        out->addr.u.v6 = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    } else {
        ret = PP_ERR_INVAL;
    }
    freeaddrinfo(res);
    return ret;
}

int pp_endpoint_parse(const char *str, pp_endpoint_t *out)
{
    if (!str || !out) return PP_ERR_INVAL;
    char buf[256];
    snprintf(buf, sizeof buf, "%s", str);

    char *host, *port;
    if (buf[0] == '[') {
        char *end = strchr(buf, ']');
        if (!end || end[1] != ':') return PP_ERR_INVAL;
        *end = 0;
        host = buf + 1;
        port = end + 2;
        out->addr.af = PP_AF_INET6;
        if (inet_pton(AF_INET6, host, &out->addr.u.v6) != 1) return PP_ERR_INVAL;
    } else {
        char *colon = strrchr(buf, ':');
        if (!colon) return PP_ERR_INVAL;
        *colon = 0;
        host = buf;
        port = colon + 1;
        /* 先试纯 IPv4，再 IPv6，再域名 */
        out->addr.af = PP_AF_INET;
        if (inet_pton(AF_INET, host, &out->addr.u.v4) != 1) {
            if (inet_pton(AF_INET6, host, &out->addr.u.v6) == 1) {
                out->addr.af = PP_AF_INET6;
            } else if (resolve_host(host, out) != PP_OK) {
                return PP_ERR_INVAL;
            }
        }
    }
    long p = strtol(port, NULL, 10);
    if (p <= 0 || p > 65535) return PP_ERR_INVAL;
    out->port = (uint16_t)p;
    return PP_OK;
}

int pp_endpoint_format(const pp_endpoint_t *ep, char *buf, size_t cap)
{
    char tmp[64];
    if (ep->addr.af == PP_AF_INET6) {
        inet_ntop(AF_INET6, &ep->addr.u.v6, tmp, sizeof tmp);
        return snprintf(buf, cap, "[%s]:%u", tmp, ep->port);
    } else {
        inet_ntop(AF_INET, &ep->addr.u.v4, tmp, sizeof tmp);
        return snprintf(buf, cap, "%s:%u", tmp, ep->port);
    }
}
