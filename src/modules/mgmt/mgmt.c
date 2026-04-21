/* src/modules/mgmt/mgmt.c -- 控制通道（Unix socket 文本协议 + 可选 HTTP metrics）
 *
 * Unix socket（默认 /tmp/pproxy.sock，可被 config.mgmt.unix_socket 覆盖）：
 *   help                -- 打印命令列表
 *   stat                -- 拉取所有模块统计
 *   sessions            -- 拉取 session 快照
 *   reload [path]       -- 热重载 JSON
 *   quit                -- 触发进程优雅退出（调试用）
 *
 * HTTP exporter（当 config.mgmt.metrics.enable=true 时开启）：
 *   GET /metrics        -- Prometheus 文本格式
 *   GET /               -- 简单 HTML 索引
 *   其它                -- 404
 *
 * 所有 I/O 在 mgmt 单线程内以 select 轮询，避免引入新的线程/锁。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "pproxy/module.h"
#include "pproxy/log.h"
#include "../runtime.h"
#include "../../config/config.h"

#define PP_MGMT_SOCK_DEFAULT  "/tmp/pproxy.sock"
#define MG_REQ_BUF            4096
#define MG_RESP_BUF           16384

typedef struct mg_priv {
    int         lfd;                 /* Unix socket listen fd */
    int         hfd;                 /* HTTP TCP listen fd；< 0 表示 metrics 关 */
    const char *sock_path;           /* 记住删 socket 文件时用 */
    uint64_t    loops, requests;
} mg_priv_t;

extern void pp_main_request_quit(void);     /* main.c 提供 */

/* ---------- 帮助文本 ---------- */

static const char HELP_TEXT[] =
    "commands:\n"
    "  help                   -- this message\n"
    "  stat                   -- module statistics\n"
    "  sessions               -- session snapshot\n"
    "  reload [path]          -- hot-reload JSON (log.level, session.*_ttl_ms,\n"
    "                            dpi.plugins[].enable); path defaults to\n"
    "                            the file given via -c at startup\n"
    "  quit                   -- shut the process down (debug only)\n";

/* ---------- 统计收集 ---------- */

/* 用于 pp_module_walk 把每个模块统计追加到一个 buffer。 */
struct stat_acc {
    char  *buf;
    size_t cap;
    size_t pos;
    /* 如果非 NULL，则按 Prometheus 行格式写，否则走人类可读格式。 */
    int    prom;
};

static void acc_printf(struct stat_acc *a, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
static void acc_printf(struct stat_acc *a, const char *fmt, ...)
{
    if (a->pos >= a->cap - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(a->buf + a->pos, a->cap - a->pos, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    a->pos += (size_t)n;
    if (a->pos >= a->cap) a->pos = a->cap - 1;
}

static int stat_walk_human(pp_module_t *m, void *user)
{
    struct stat_acc *a = user;
    pp_mod_stat_t s; memset(&s, 0, sizeof s);
    if (m->ops->stat) m->ops->stat(m, &s);
    acc_printf(a, "  %-12s loops=%lu in=%lu out=%lu drops=%lu cpu=%u\n",
        s.name, (unsigned long)s.loops,
        (unsigned long)s.events_in, (unsigned long)s.events_out,
        (unsigned long)s.drops, s.cpu);
    return PP_OK;
}

static int stat_walk_prom(pp_module_t *m, void *user)
{
    struct stat_acc *a = user;
    pp_mod_stat_t s; memset(&s, 0, sizeof s);
    if (m->ops->stat) m->ops->stat(m, &s);

    acc_printf(a, "pp_module_loops{module=\"%s\"} %lu\n",
               s.name, (unsigned long)s.loops);
    acc_printf(a, "pp_module_events_in{module=\"%s\"} %lu\n",
               s.name, (unsigned long)s.events_in);
    acc_printf(a, "pp_module_events_out{module=\"%s\"} %lu\n",
               s.name, (unsigned long)s.events_out);
    acc_printf(a, "pp_module_drops{module=\"%s\"} %lu\n",
               s.name, (unsigned long)s.drops);
    if (s.cpu != UINT32_MAX)
        acc_printf(a, "pp_module_cpu{module=\"%s\"} %u\n", s.name, s.cpu);
    return PP_OK;
}

/* ---------- unix socket 文本命令 ---------- */

static void write_all(int fd, const char *buf, size_t n)
{
    while (n > 0) {
        ssize_t w = write(fd, buf, n);
        if (w < 0) { if (errno == EINTR) continue; return; }
        if (w == 0) return;
        buf += w; n -= (size_t)w;
    }
}

static void handle_unix(int cfd)
{
    char req[256] = {0};
    ssize_t n = read(cfd, req, sizeof req - 1);
    if (n <= 0) return;
    while (n > 0 && (req[n - 1] == '\n' || req[n - 1] == '\r')) req[--n] = 0;

    char resp[MG_RESP_BUF]; resp[0] = 0;
    struct stat_acc a = { .buf = resp, .cap = sizeof resp, .pos = 0, .prom = 0 };

    if (strcmp(req, "help") == 0 || req[0] == '?') {
        acc_printf(&a, "%s", HELP_TEXT);
    } else if (strcmp(req, "stat") == 0 || strcmp(req, "stats") == 0) {
        acc_printf(&a, "modules:\n");
        pp_module_walk(stat_walk_human, &a);
    } else if (strcmp(req, "sessions") == 0) {
        pp_session_view_t views[64];
        int got = pp_session_snapshot(g_rt->shards, g_rt->n_workers,
                                      NULL, views, 64);
        acc_printf(&a, "sessions: %d\n", got);
        for (int i = 0; i < got; i++) {
            char k[128];
            pp_flow_key_format(&views[i].key, k, sizeof k);
            acc_printf(&a,
                "  sid=%lx state=%u app=%u  %s  up=%lu/%lu dn=%lu/%lu\n",
                (unsigned long)views[i].sid, views[i].state, views[i].app_proto, k,
                (unsigned long)views[i].up.pkts, (unsigned long)views[i].up.bytes,
                (unsigned long)views[i].dn.pkts, (unsigned long)views[i].dn.bytes);
        }
    } else if (strncmp(req, "reload", 6) == 0
               && (req[6] == 0 || req[6] == ' ' || req[6] == '\t')) {
        const char *path = req + 6;
        while (*path == ' ' || *path == '\t') path++;
        if (*path == 0) path = NULL;
        pp_config_reload(path, g_rt, resp, sizeof resp);
        a.pos = strlen(resp);
    } else if (strcmp(req, "quit") == 0) {
        acc_printf(&a, "ok, quitting\n");
        write_all(cfd, resp, a.pos);
        close(cfd);
        pp_main_request_quit();
        return;
    } else {
        acc_printf(&a, "unknown command: '%s' (try 'help')\n", req);
    }
    write_all(cfd, resp, a.pos);
}

/* ---------- HTTP exporter ---------- */

/* 读直到 "\r\n\r\n" 或 buf 满。返回读到的字节数（>=0），<0 出错。 */
static ssize_t http_read_request(int cfd, char *buf, size_t cap)
{
    size_t have = 0;
    while (have < cap - 1) {
        ssize_t n = read(cfd, buf + have, cap - 1 - have);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) break;
        have += (size_t)n;
        buf[have] = 0;
        if (strstr(buf, "\r\n\r\n")) break;
        if (strstr(buf, "\n\n"))     break;   /* 容忍 curl -0 等非标准 */
    }
    return (ssize_t)have;
}

static size_t build_metrics(char *body, size_t cap)
{
    struct stat_acc a = { .buf = body, .cap = cap, .pos = 0, .prom = 1 };

    /* session 统计（所有 shard 求和；快照上限 1024 条就够用了） */
    pp_session_view_t views[1024];
    int got = pp_session_snapshot(g_rt->shards, g_rt->n_workers,
                                  NULL, views, 1024);

    acc_printf(&a, "# HELP pp_info Build info as constant labels\n");
    acc_printf(&a, "# TYPE pp_info gauge\n");
    acc_printf(&a, "pp_info{version=\"%s\",workers=\"%d\",tunnels=\"%d\"} 1\n",
               "0.1.0", g_rt->n_workers, g_rt->n_tunnels);

    acc_printf(&a, "# HELP pp_module_loops Main-loop iterations per module\n");
    acc_printf(&a, "# TYPE pp_module_loops counter\n");
    /* 这里 walk 会把 loops/in/out/drops/cpu 五个都打出来。
     * 为保持 Prometheus 对 HELP/TYPE 只声明一次，我们自己手动声明其它 4 个。 */
    acc_printf(&a, "# HELP pp_module_events_in Events received by module\n");
    acc_printf(&a, "# TYPE pp_module_events_in counter\n");
    acc_printf(&a, "# HELP pp_module_events_out Events forwarded by module\n");
    acc_printf(&a, "# TYPE pp_module_events_out counter\n");
    acc_printf(&a, "# HELP pp_module_drops Events dropped by module\n");
    acc_printf(&a, "# TYPE pp_module_drops counter\n");
    acc_printf(&a, "# HELP pp_module_cpu CPU id the module is pinned to\n");
    acc_printf(&a, "# TYPE pp_module_cpu gauge\n");
    pp_module_walk(stat_walk_prom, &a);

    acc_printf(&a, "# HELP pp_sessions Active sessions across all shards (snapshot)\n");
    acc_printf(&a, "# TYPE pp_sessions gauge\n");
    acc_printf(&a, "pp_sessions %d\n", got);

    /* 按 app_proto 聚合 */
    unsigned cnt[8] = {0};
    for (int i = 0; i < got; i++) {
        unsigned p = views[i].app_proto < 8 ? views[i].app_proto : 0;
        cnt[p]++;
    }
    static const char *app_names[8] = {
        "unknown", "http", "tls", "dns", "quic", "ssh", "reserved6", "reserved7"
    };
    acc_printf(&a, "# HELP pp_sessions_by_app Active sessions broken down by app_proto\n");
    acc_printf(&a, "# TYPE pp_sessions_by_app gauge\n");
    for (int p = 0; p < 8; p++)
        acc_printf(&a, "pp_sessions_by_app{app=\"%s\"} %u\n", app_names[p], cnt[p]);

    return a.pos;
}

static const char INDEX_HTML[] =
    "<!doctype html>\n"
    "<html><head><meta charset=\"utf-8\"><title>pproxy</title></head>\n"
    "<body>\n"
    "<h1>pproxy</h1>\n"
    "<ul>\n"
    "  <li><a href=\"/metrics\">/metrics</a> &mdash; Prometheus exposition</li>\n"
    "</ul>\n"
    "<p>For interactive control, use the Unix socket:<br>\n"
    "<code>echo help | nc -U /tmp/pproxy.sock</code></p>\n"
    "</body></html>\n";

static void http_send(int cfd, int status, const char *status_text,
                      const char *ctype, const char *body, size_t blen)
{
    char hdr[256];
    int n = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, status_text, ctype, blen);
    if (n < 0) return;
    write_all(cfd, hdr, (size_t)n);
    if (body && blen) write_all(cfd, body, blen);
}

static void handle_http(int cfd)
{
    char req[MG_REQ_BUF] = {0};
    ssize_t n = http_read_request(cfd, req, sizeof req);
    if (n <= 0) return;

    /* 解析第一行：METHOD  PATH  VERSION */
    char method[8] = {0}, path[128] = {0};
    if (sscanf(req, "%7s %127s", method, path) != 2) {
        http_send(cfd, 400, "Bad Request", "text/plain", "bad request\n", 12);
        return;
    }
    if (strcmp(method, "GET") != 0) {
        http_send(cfd, 405, "Method Not Allowed",
                  "text/plain", "GET only\n", 9);
        return;
    }

    if (strcmp(path, "/metrics") == 0) {
        static char body[MG_RESP_BUF * 4];      /* 64KB 够放到 64 workers */
        size_t blen = build_metrics(body, sizeof body);
        http_send(cfd, 200, "OK",
                  "text/plain; version=0.0.4; charset=utf-8", body, blen);
        return;
    }
    if (strcmp(path, "/") == 0) {
        http_send(cfd, 200, "OK", "text/html; charset=utf-8",
                  INDEX_HTML, sizeof INDEX_HTML - 1);
        return;
    }
    http_send(cfd, 404, "Not Found", "text/plain", "not found\n", 10);
}

/* ---------- 建监听 ---------- */

static int open_unix_listener(const char *path)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct sockaddr_un un = { .sun_family = AF_UNIX };
    snprintf(un.sun_path, sizeof un.sun_path, "%s", path);
    unlink(un.sun_path);
    if (bind(fd, (struct sockaddr *)&un, sizeof un) < 0 || listen(fd, 4) < 0) {
        PP_ERROR("mgmt bind/listen %s: %s", path, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

static socklen_t ep_to_sa(const pp_endpoint_t *ep, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof *ss);
    if (ep->addr.af == PP_AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port   = htons(ep->port);
        s->sin6_addr   = ep->addr.u.v6;
        return sizeof *s;
    }
    struct sockaddr_in *s = (struct sockaddr_in *)ss;
    s->sin_family = AF_INET;
    s->sin_port   = htons(ep->port);
    s->sin_addr   = ep->addr.u.v4;
    return sizeof *s;
}

static int open_http_listener(const pp_endpoint_t *ep)
{
    int af = (ep->addr.af == PP_AF_INET6) ? AF_INET6 : AF_INET;
    int fd = socket(af, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int on = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_storage ss;
    socklen_t slen = ep_to_sa(ep, &ss);
    if (bind(fd, (struct sockaddr *)&ss, slen) < 0
        || listen(fd, 8) < 0) {
        char ebuf[64]; pp_endpoint_format(ep, ebuf, sizeof ebuf);
        PP_ERROR("mgmt metrics bind/listen %s: %s", ebuf, strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

/* ---------- 模块生命周期 ---------- */

static int mg_init(pp_module_t *m, void *cfg)
{
    (void)cfg;
    mg_priv_t *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;

    const char *sock = (g_rt && g_rt->mgmt_unix_socket && *g_rt->mgmt_unix_socket)
                     ? g_rt->mgmt_unix_socket
                     : PP_MGMT_SOCK_DEFAULT;
    p->sock_path = sock;
    p->lfd = open_unix_listener(sock);
    if (p->lfd < 0) { free(p); return PP_ERR_IO; }
    PP_INFO("mgmt: listening on %s", sock);

    p->hfd = -1;
    if (g_rt && g_rt->metrics_enable && g_rt->metrics_listen_set) {
        p->hfd = open_http_listener(&g_rt->metrics_listen);
        if (p->hfd < 0) {
            PP_WARN("mgmt: metrics listener failed, continuing without it");
        } else {
            char ebuf[64];
            pp_endpoint_format(&g_rt->metrics_listen, ebuf, sizeof ebuf);
            PP_INFO("mgmt: metrics listening on http://%s/metrics", ebuf);
        }
    }

    m->priv = p;
    return PP_OK;
}

static void *mg_loop(void *arg)
{
    pp_module_t *m = arg;
    mg_priv_t   *p = m->priv;
    pp_thread_setup(m->name, m->cpu);
    PP_INFO("%s: started", m->name);

    while (!pp_module_should_quit(m)) {
        fd_set rs; FD_ZERO(&rs);
        int maxfd = -1;
        if (p->lfd >= 0) { FD_SET(p->lfd, &rs); if (p->lfd > maxfd) maxfd = p->lfd; }
        if (p->hfd >= 0) { FD_SET(p->hfd, &rs); if (p->hfd > maxfd) maxfd = p->hfd; }
        struct timeval tv = { .tv_sec = 0, .tv_usec = 200 * 1000 };
        int r = select(maxfd + 1, &rs, NULL, NULL, &tv);
        p->loops++;
        if (r <= 0) continue;

        if (p->lfd >= 0 && FD_ISSET(p->lfd, &rs)) {
            int cfd = accept(p->lfd, NULL, NULL);
            if (cfd >= 0) {
                handle_unix(cfd);
                close(cfd);
                p->requests++;
            }
        }
        if (p->hfd >= 0 && FD_ISSET(p->hfd, &rs)) {
            int cfd = accept(p->hfd, NULL, NULL);
            if (cfd >= 0) {
                handle_http(cfd);
                close(cfd);
                p->requests++;
            }
        }
    }
    PP_INFO("%s: stopped", m->name);
    return NULL;
}

static int mg_start(pp_module_t *m)
{
    return pthread_create(&m->tid, NULL, mg_loop, m) == 0 ? PP_OK : PP_ERR_GENERIC;
}

static void mg_stop(pp_module_t *m)
{
    atomic_store(&m->quit, 1);
    pthread_join(m->tid, NULL);
}

static void mg_destroy(pp_module_t *m)
{
    mg_priv_t *p = m->priv;
    if (!p) return;
    if (p->lfd >= 0) close(p->lfd);
    if (p->hfd >= 0) close(p->hfd);
    if (p->sock_path) unlink(p->sock_path);
    free(p);
    m->priv = NULL;
}

static void mg_stat(pp_module_t *m, pp_mod_stat_t *s)
{
    mg_priv_t *p = m->priv;
    snprintf(s->name, sizeof s->name, "%s", m->name);
    s->loops      = p ? p->loops : 0;
    s->events_in  = p ? p->requests : 0;
    s->cpu        = (m->cpu >= 0) ? (uint32_t)m->cpu : UINT32_MAX;
}

pp_module_ops_t pp_mod_mgmt_ops = {
    .init = mg_init, .start = mg_start, .stop = mg_stop,
    .destroy = mg_destroy, .stat = mg_stat,
};
