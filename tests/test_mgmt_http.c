/* tests/test_mgmt_http.c -- mgmt HTTP exporter 烟测
 *
 * 目标：
 *   1. 不依赖 TUN / root，直接拉起 mgmt 模块
 *   2. 连到 /metrics，断言返回的 Prometheus 文本包含关键行
 *   3. 连到 /，断言返回 HTML
 *   4. 连到 /bogus，断言 404
 *
 * 构造：搭一个最小 pp_runtime_t，注册 mgmt 模块，让它自建 Unix+HTTP 监听，
 * 然后在 main 线程用 connect+read 跑 HTTP。
 */
#include <assert.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "pproxy/pproxy.h"
#include "pproxy/log.h"
#include "pproxy/module.h"
#include "pproxy/dpi.h"
#include "pproxy/ring.h"
#include "pproxy/ring_ipc.h"
#include "pproxy/session.h"
#include "../src/modules/runtime.h"

extern pp_module_ops_t pp_mod_mgmt_ops;

pp_runtime_t *g_rt = NULL;

/* main.c 里 mgmt 会调 pp_main_request_quit：测试里无需真正退出。 */
void pp_main_request_quit(void);
void pp_main_request_quit(void) { }

/* ---------- 简易 HTTP 客户端 ---------- */

static int tcp_connect_v4(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    struct sockaddr_in sa = {
        .sin_family = AF_INET,
        .sin_port   = htons(port),
    };
    sa.sin_addr.s_addr = htonl(0x7f000001);
    for (int tries = 0; tries < 50; tries++) {
        if (connect(fd, (struct sockaddr *)&sa, sizeof sa) == 0) return fd;
        struct timespec ts = { .tv_sec = 0, .tv_nsec = 50 * 1000 * 1000 };
        nanosleep(&ts, NULL);
    }
    close(fd);
    return -1;
}

static int http_get(uint16_t port, const char *path, char *out, size_t cap)
{
    int fd = tcp_connect_v4(port);
    if (fd < 0) return -1;
    char req[256];
    int n = snprintf(req, sizeof req,
                     "GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", path);
    if (write(fd, req, (size_t)n) != n) { close(fd); return -1; }
    size_t got = 0;
    while (got < cap - 1) {
        ssize_t r = read(fd, out + got, cap - 1 - got);
        if (r <= 0) break;
        got += (size_t)r;
    }
    out[got] = 0;
    close(fd);
    return (int)got;
}

/* ---------- 辅助断言 ---------- */
#define ASSERT_HAS(resp, needle) do {                                         \
    if (!strstr((resp), (needle))) {                                          \
        fprintf(stderr, "FAIL: expected substring '%s' in:\n%s\n",            \
                (needle), (resp));                                            \
        exit(1);                                                              \
    }                                                                         \
} while (0)

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    pp_log_init(PP_LOG_INFO, "-");

    pp_runtime_t rt;
    memset(&rt, 0, sizeof rt);
    rt.n_workers = 1;
    rt.n_tunnels = 1;
    rt.ring_ipc.mode = PP_RING_IPC_ADAPTIVE;
    rt.ring_ipc.poll_backoff_us = 50;
    rt.ring_ipc.adaptive_spin = 8;
    rt.ring_ipc.adaptive_yield = 2;
    /* 选一个不常占用的高端口；如果被占了测试会失败，属于可接受 */
    uint16_t port = 19091;
    rt.mgmt_unix_socket = "/tmp/pproxy_mgmt_http_test.sock";
    rt.metrics_enable = true;
    rt.metrics_listen_set = true;
    rt.metrics_listen.addr.af = PP_AF_INET;
    rt.metrics_listen.addr.u.v4.s_addr = htonl(0x7f000001);
    rt.metrics_listen.port = port;

    /* 建 dpi chain + 1 shard，让 /metrics 里 session 快照 walker 不炸 */
    rt.dpi = pp_dpi_chain_create();
    assert(rt.dpi);
    pp_session_cfg_t scfg = {
        .max_sessions = 32,
        .idle_ttl_ns = 60ULL * 1000000000ULL,
        .syn_ttl_ns  = 30ULL * 1000000000ULL,
        .fin_ttl_ns  = 30ULL * 1000000000ULL,
        .shard_id = 0, .shard_total = 1,
    };
    rt.shards[0] = pp_session_shard_create(&scfg);
    assert(rt.shards[0]);

    pp_ring_cfg_t rcfg = {
        .kind = PP_RING_SPSC,
        .capacity = 8,
        .name = "worker_rx",
        .numa_node = -1,
    };
    rt.worker_rx_ring[0] = pp_ring_create(&rcfg);
    assert(rt.worker_rx_ring[0]);
    pp_ring_ipc_t *ipc = pp_ring_ipc_create(&rt.ring_ipc);
    assert(ipc);
    pp_ring_attach_ipc(rt.worker_rx_ring[0], ipc);
    assert(pp_ring_enqueue(rt.worker_rx_ring[0], (void *)(uintptr_t)1) == 1);

    g_rt = &rt;

    /* 注册 mgmt 模块 */
    static pp_module_t mod_mgmt;
    memset(&mod_mgmt, 0, sizeof mod_mgmt);
    snprintf(mod_mgmt.name, sizeof mod_mgmt.name, "mgmt");
    mod_mgmt.cpu = -1;
    mod_mgmt.ops = &pp_mod_mgmt_ops;
    int r = pp_module_register(&mod_mgmt);
    assert(r == PP_OK);
    r = pp_module_init_all(NULL);
    assert(r == PP_OK);
    r = pp_module_start_all();
    assert(r == PP_OK);

    /* 给 select 一点启动时间 */
    struct timespec ts = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&ts, NULL);

    char buf[65536] = {0};

    /* ---- GET /metrics ---- */
    int n = http_get(port, "/metrics", buf, sizeof buf);
    assert(n > 0);
    if (getenv("PRINT_METRICS")) {
        fputs("---- /metrics ----\n", stdout);
        fputs(buf, stdout);
        fputs("---- end ----\n", stdout);
    }
    ASSERT_HAS(buf, "HTTP/1.1 200 OK");
    ASSERT_HAS(buf, "Content-Type: text/plain");
    ASSERT_HAS(buf, "# TYPE pp_module_loops counter");
    ASSERT_HAS(buf, "pp_info{version=");
    ASSERT_HAS(buf, "pp_module_loops{module=\"mgmt\"}");
    ASSERT_HAS(buf, "pp_sessions 0");
    ASSERT_HAS(buf, "pp_sessions_by_app{app=\"unknown\"}");
    ASSERT_HAS(buf, "pp_session_drops_sum{dir=\"up\"}");
    ASSERT_HAS(buf, "pp_drop_orphan{kind=\"lrx_flow_key\"}");
    ASSERT_HAS(buf, "pp_ring_size{ring=\"worker_rx\",index=\"0\",mode=\"adaptive\"}");
    ASSERT_HAS(buf, "pp_ring_ipc_notifies{ring=\"worker_rx\",index=\"0\",mode=\"adaptive\"}");
    ASSERT_HAS(buf, "pp_ring_high_watermark{ring=\"worker_rx\",index=\"0\",mode=\"adaptive\"}");

    /* ---- GET / ---- */
    memset(buf, 0, sizeof buf);
    n = http_get(port, "/", buf, sizeof buf);
    assert(n > 0);
    ASSERT_HAS(buf, "HTTP/1.1 200 OK");
    ASSERT_HAS(buf, "Content-Type: text/html");
    ASSERT_HAS(buf, "/metrics");

    /* ---- GET /bogus → 404 ---- */
    memset(buf, 0, sizeof buf);
    n = http_get(port, "/bogus", buf, sizeof buf);
    assert(n > 0);
    ASSERT_HAS(buf, "HTTP/1.1 404");

    /* ---- unix socket: stat ---- */
    int ufd = socket(AF_UNIX, SOCK_STREAM, 0);
    assert(ufd >= 0);
    struct sockaddr_un un = { .sun_family = AF_UNIX };
    snprintf(un.sun_path, sizeof un.sun_path, "%s", rt.mgmt_unix_socket);
    assert(connect(ufd, (struct sockaddr *)&un, sizeof un) == 0);
    const char *cmd = "stat\n";
    assert(write(ufd, cmd, strlen(cmd)) == (ssize_t)strlen(cmd));
    memset(buf, 0, sizeof buf);
    ssize_t got = read(ufd, buf, sizeof buf - 1);
    assert(got > 0);
    close(ufd);
    ASSERT_HAS(buf, "modules:");
    ASSERT_HAS(buf, "mgmt");

    pp_module_stop_all();
    pp_module_destroy_all();

    pp_dpi_chain_destroy(rt.dpi);
    pp_session_shard_destroy(rt.shards[0]);
    pp_ring_destroy(rt.worker_rx_ring[0]);
    unlink(rt.mgmt_unix_socket);

    printf("test_mgmt_http: OK\n");
    return 0;
}
