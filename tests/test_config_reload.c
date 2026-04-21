/* tests/test_config_reload.c -- pp_config_reload 单元测试
 *
 * 不依赖 main.c / 任何 I/O 线程 / root 权限。
 * 自己搭一个最小 pp_runtime_t（dpi chain + 1 session shard），
 * 写一份小 JSON 到 /tmp，再验证 reload 后各字段是否按预期生效。
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pproxy/pproxy.h"
#include "pproxy/log.h"
#include "pproxy/dpi.h"
#include "pproxy/session.h"
#include "../src/modules/runtime.h"
#include "../src/config/config.h"

/* runtime.h 声明了 extern g_rt；需要一个定义以便链接。 */
pp_runtime_t *g_rt = NULL;

/* ---------- mock DPI 插件 ---------- */

static pp_dpi_verdict_t mock_probe(const pp_session_t *s, const pp_pkt_t *p)
{
    (void)s; (void)p;
    return PP_DPI_NO_MATCH;
}
static pp_dpi_verdict_t mock_parse(pp_session_t *s, const pp_pkt_t *p, pp_flow_dir_t d)
{
    (void)s; (void)p; (void)d;
    return PP_DPI_DONE;
}
static const pp_dpi_ops_t mock_dns = {
    .name = "dns", .app_proto = PP_APP_DNS, .priority = 5,
    .l4_mask = (1u << 17),           /* UDP */
    .probe = mock_probe, .parse = mock_parse,
};
static const pp_dpi_ops_t mock_tls = {
    .name = "tls", .app_proto = PP_APP_TLS, .priority = 10,
    .l4_mask = (1u << 6),            /* TCP */
    .probe = mock_probe, .parse = mock_parse,
};

/* ---------- helpers ---------- */

static void write_file(const char *path, const char *body)
{
    FILE *fp = fopen(path, "w");
    assert(fp);
    fputs(body, fp);
    fclose(fp);
}

#define ASSERT_HAS(resp, needle) do {                                         \
    if (!strstr((resp), (needle))) {                                          \
        fprintf(stderr, "FAIL: expected substring '%s' in response:\n%s\n",   \
                (needle), (resp));                                            \
        exit(1);                                                              \
    }                                                                         \
} while (0)

/* ---------- main ---------- */

int main(void)
{
    pp_log_init(PP_LOG_INFO, "-");

    pp_runtime_t rt;
    memset(&rt, 0, sizeof rt);
    rt.n_workers            = 1;
    rt.session_idle_ttl_ns  = 300ULL * 1000000000ULL;
    rt.session_syn_ttl_ns   =  30ULL * 1000000000ULL;
    rt.session_fin_ttl_ns   =  30ULL * 1000000000ULL;

    rt.dpi = pp_dpi_chain_create();
    assert(rt.dpi);
    assert(pp_dpi_chain_register_ex(rt.dpi, &mock_dns, -1) == PP_OK);
    assert(pp_dpi_chain_register_ex(rt.dpi, &mock_tls, -1) == PP_OK);

    pp_session_cfg_t scfg = {
        .max_sessions = 64,
        .idle_ttl_ns  = rt.session_idle_ttl_ns,
        .syn_ttl_ns   = rt.session_syn_ttl_ns,
        .fin_ttl_ns   = rt.session_fin_ttl_ns,
        .shard_id     = 0,
        .shard_total  = 1,
    };
    rt.shards[0] = pp_session_shard_create(&scfg);
    assert(rt.shards[0]);

    /* ---- 1) 正常 reload：覆盖 log/ttl/dpi，未知插件跳过，
     *      priority/tunnels 标记 requires restart ---- */
    const char *tmp = "/tmp/pproxy_reload_test.json";
    const char *body =
        "{\n"
        "  \"log\":     { \"level\": \"debug\" },\n"
        "  \"session\": { \"idle_ttl_ms\": 9999, \"syn_ttl_ms\": 77, \"fin_ttl_ms\": 66 },\n"
        "  \"dpi\": { \"plugins\": [\n"
        "    { \"name\": \"dns\", \"enable\": false },\n"
        "    { \"name\": \"tls\", \"enable\": true, \"priority\": 1 },\n"
        "    { \"name\": \"not-a-plugin\", \"enable\": false }\n"
        "  ] },\n"
        "  \"tunnels\": []\n"
        "}\n";
    write_file(tmp, body);

    char resp[4096] = {0};
    int r = pp_config_reload(tmp, &rt, resp, sizeof resp);
    assert(r == PP_OK);
    fputs(resp, stdout);

    assert(rt.session_idle_ttl_ns == 9999ULL * 1000000ULL);
    assert(rt.session_syn_ttl_ns  ==   77ULL * 1000000ULL);
    assert(rt.session_fin_ttl_ns  ==   66ULL * 1000000ULL);

    ASSERT_HAS(resp, "applied log.level=debug");
    ASSERT_HAS(resp, "applied session.ttl");
    ASSERT_HAS(resp, "applied dpi.dns.enable=false");
    ASSERT_HAS(resp, "applied dpi.tls.enable=true");
    ASSERT_HAS(resp, "dpi.tls.priority requires restart");
    ASSERT_HAS(resp, "'not-a-plugin'");
    ASSERT_HAS(resp, "'tunnels' section present");

    /* ---- 2) path=NULL & cfg_path=NULL -> PP_ERR_NOTFOUND ---- */
    char resp2[512] = {0};
    r = pp_config_reload(NULL, &rt, resp2, sizeof resp2);
    assert(r == PP_ERR_NOTFOUND);
    ASSERT_HAS(resp2, "no config path");

    /* ---- 3) 设置 cfg_path，NULL path -> 使用 cfg_path ---- */
    rt.cfg_path = tmp;
    memset(resp, 0, sizeof resp);
    r = pp_config_reload(NULL, &rt, resp, sizeof resp);
    assert(r == PP_OK);
    ASSERT_HAS(resp, tmp);

    /* ---- 4) 指向不存在的文件 -> PP_ERR_INVAL ---- */
    char resp3[512] = {0};
    r = pp_config_reload("/tmp/definitely-does-not-exist.json",
                         &rt, resp3, sizeof resp3);
    assert(r == PP_ERR_INVAL);
    ASSERT_HAS(resp3, "reload error");

    /* ---- 5) 空 JSON：什么都不做但应返回 OK ---- */
    const char *tmp2 = "/tmp/pproxy_reload_empty.json";
    write_file(tmp2, "{}\n");
    memset(resp, 0, sizeof resp);
    r = pp_config_reload(tmp2, &rt, resp, sizeof resp);
    assert(r == PP_OK);
    ASSERT_HAS(resp, "0 applied, 0 notes");
    unlink(tmp2);

    pp_dpi_chain_destroy(rt.dpi);
    pp_session_shard_destroy(rt.shards[0]);
    pp_config_free(&rt);
    unlink(tmp);

    printf("test_config_reload: OK\n");
    return 0;
}
