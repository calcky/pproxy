/*
 * dpi.h -- DPI 插件接口（应用层协议识别）
 *
 * 每个插件实现一组回调：
 *   probe()   -- 看一眼包，返回 PP_DPI_MATCH/NO_MATCH/NEED_MORE
 *   parse()   -- 进入深度解析，更新 dpi_ctx；返回是否还需要后续包
 *   destroy() -- 释放 dpi_ctx
 *
 * worker 持有一条插件链（pp_dpi_chain_t），新 session 来时按优先级
 * 依次 probe；命中则后续包只走该插件 parse，直到 done。
 */
#ifndef PPROXY_DPI_H
#define PPROXY_DPI_H

#include "pproxy/pproxy.h"
#include "pproxy/session.h"
#include "pproxy/packet.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pp_dpi_verdict {
    PP_DPI_NO_MATCH    = 0,
    PP_DPI_MATCH       = 1,
    PP_DPI_NEED_MORE   = 2,
    PP_DPI_DONE        = 3,     /* parse 完成，后续包不再喂 */
} pp_dpi_verdict_t;

typedef struct pp_dpi_ops {
    const char *name;
    uint8_t     app_proto;      /* pp_app_proto_t */
    uint8_t     priority;       /* 数字小优先 */
    uint8_t     _pad[2];
    uint32_t    l4_mask;        /* (1u<<IPPROTO_TCP) | (1u<<IPPROTO_UDP) 等 */

    /* 全局一次初始化（注册时调用） */
    int  (*global_init)(void);
    void (*global_fini)(void);

    /* 每会话创建/销毁 dpi_ctx */
    int  (*ctx_init)  (pp_session_t *s);
    void (*ctx_destroy)(pp_session_t *s);

    /* probe：仅快速指纹判断；不能修改 ctx */
    pp_dpi_verdict_t (*probe)(const pp_session_t *s, const pp_pkt_t *p);

    /* parse：深度解析；可以更新 ctx 与 session.app_proto 等 */
    pp_dpi_verdict_t (*parse)(pp_session_t *s, const pp_pkt_t *p,
                              pp_flow_dir_t dir);
} pp_dpi_ops_t;

/* ---------- 插件链 ---------- */
typedef struct pp_dpi_chain pp_dpi_chain_t;

#define PP_DPI_MAX_PLUGINS  16

pp_dpi_chain_t *pp_dpi_chain_create(void);
void            pp_dpi_chain_destroy(pp_dpi_chain_t *c);

/* 注册插件；插件在程序生命周期内只能注册一次。
 * - pp_dpi_chain_register    使用 ops->priority
 * - pp_dpi_chain_register_ex 若 priority_override >= 0 则覆盖为该值，否则同上 */
int  pp_dpi_chain_register   (pp_dpi_chain_t *c, const pp_dpi_ops_t *ops);
int  pp_dpi_chain_register_ex(pp_dpi_chain_t *c, const pp_dpi_ops_t *ops,
                              int priority_override);

/* 热开关：按 name 原子切换 enabled（立即对新包生效；已识别的 session 不受影响）。
 *   PP_OK        -- 找到并切换（即便值没变也返回 OK）
 *   PP_ERR_NOTFOUND -- chain 里无此名字的插件 */
int  pp_dpi_chain_set_enabled(pp_dpi_chain_t *c, const char *name, bool enabled);

/* worker 主路径调用：
 *   - 若 session 还未识别（app_proto == UNKNOWN）：尝试 probe + parse；
 *   - 若已识别：仅在 dpi_pkts < N 时继续 parse；
 *   - 内部维护 session.dpi_pkts、session.app_proto。
 */
int pp_dpi_chain_run(pp_dpi_chain_t *c, pp_session_t *s,
                     const pp_pkt_t *p, pp_flow_dir_t dir);

/* ---------- 内置插件（位于 src/dpi/） ---------- */
extern const pp_dpi_ops_t pp_dpi_tls;
extern const pp_dpi_ops_t pp_dpi_http;
extern const pp_dpi_ops_t pp_dpi_dns;

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_DPI_H */
