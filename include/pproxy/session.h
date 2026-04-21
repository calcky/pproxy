/*
 * session.h -- 会话表
 *
 * SessionTable 按 hash(key) % N 分片：
 *   - 每个 worker 线程独占一个 shard，写操作完全无锁；
 *   - mgmt 线程通过 RCU snapshot 只读访问，不阻塞 worker。
 *
 * Session 同时按两个键索引：
 *   1) FlowKey   -> 主键，worker 内查找
 *   2) sid       -> 全局 64-bit id，right_rx 拿到 sid 直接 O(1) 路由回 worker
 *      sid 高位编码 shard 号，低位是 shard 内的 slot 索引。
 */
#ifndef PPROXY_SESSION_H
#define PPROXY_SESSION_H

#include "pproxy/pproxy.h"
#include "pproxy/flow.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 状态机 ---------- */
typedef enum pp_sess_state {
    PP_SS_NEW        = 0,
    PP_SS_SYN_SENT   = 1,
    PP_SS_EST        = 2,
    PP_SS_CLOSE_WAIT = 3,
    PP_SS_RST        = 4,
    PP_SS_TIMEOUT    = 5,
    PP_SS_CLOSED     = 6,
} pp_sess_state_t;

/* ---------- 协议识别结果 ---------- */
typedef enum pp_app_proto {
    PP_APP_UNKNOWN = 0,
    PP_APP_HTTP    = 1,
    PP_APP_TLS     = 2,
    PP_APP_DNS     = 3,
    PP_APP_QUIC    = 4,
    PP_APP_SSH     = 5,
    /* ... 由 dpi 插件注册扩展 */
} pp_app_proto_t;

/* ---------- 单向计数器（per-direction） ---------- */
typedef struct pp_stats {
    uint64_t pkts;
    uint64_t bytes;
    uint64_t drops;
    uint64_t retrans;
} pp_stats_t;

/* ---------- 会话主体 ----------
 * 注意：跨 cacheline 布局；高频字段（state/last_ns/stats）放第一行。
 */
typedef struct pp_session {
    /* hot: cacheline 0 */
    uint64_t        sid;            /* 全局 id；高 16 位 = shard */
    uint64_t        last_ns;
    uint8_t         state;          /* pp_sess_state_t */
    uint8_t         app_proto;      /* pp_app_proto_t */
    uint16_t        tunnel_idx;     /* 走哪条右手 tunnel */
    uint16_t        flags;
    uint16_t        dpi_pkts;       /* 已喂给 DPI 的包数（用于早停） */
    pp_stats_t      up;
    pp_stats_t      dn;

    /* cold: cacheline 1+ */
    pp_flow_key_t   key;
    uint64_t        created_ns;
    void           *dpi_ctx;        /* DPI 插件私有上下文 */
    void           *user_ctx;       /* 业务自定义 */
} PP_CACHELINE_ALIGN pp_session_t;

/* ---------- SessionTable（单个分片） ---------- */
typedef struct pp_session_shard pp_session_shard_t;

typedef struct pp_session_cfg {
    size_t   max_sessions;          /* 每分片容量上限 */
    uint64_t idle_ttl_ns;           /* EST 状态空闲超时 */
    uint64_t syn_ttl_ns;
    uint64_t fin_ttl_ns;
    uint16_t shard_id;              /* 0..N-1 */
    uint16_t shard_total;           /* N */
} pp_session_cfg_t;

pp_session_shard_t *pp_session_shard_create(const pp_session_cfg_t *cfg);
void                pp_session_shard_destroy(pp_session_shard_t *sh);

/* worker 内调用，无锁 */
pp_session_t *pp_session_lookup(pp_session_shard_t *sh, const pp_flow_key_t *k);
pp_session_t *pp_session_lookup_or_create(pp_session_shard_t *sh,
                                          const pp_flow_key_t *k,
                                          bool *out_is_new);
pp_session_t *pp_session_lookup_by_sid(pp_session_shard_t *sh, uint64_t sid);
void          pp_session_remove(pp_session_shard_t *sh, pp_session_t *s);

/* 老化：返回清理条数；由 worker 自己驱动（收到 PP_CTL_GC_TICK 时） */
int pp_session_gc(pp_session_shard_t *sh, uint64_t now_ns);

/* 热更新 TTL（mgmt reload 使用）。非原子写；timer/GC 每轮读一次，竞争无危害。 */
void pp_session_shard_set_ttl(pp_session_shard_t *sh,
                              uint64_t idle_ttl_ns,
                              uint64_t syn_ttl_ns,
                              uint64_t fin_ttl_ns);

/* sid 编解码 */
PP_INLINE uint16_t pp_sid_shard(uint64_t sid)  { return (uint16_t)(sid >> 48); }
PP_INLINE uint64_t pp_sid_make(uint16_t shard, uint64_t slot)
                                              { return ((uint64_t)shard << 48) | (slot & 0xFFFFFFFFFFFFULL); }

/* ---------- mgmt 查询接口（RCU snapshot） ---------- */
typedef struct pp_session_view {
    uint64_t        sid;
    pp_flow_key_t   key;
    uint8_t         state;
    uint8_t         app_proto;
    uint64_t        created_ns;
    uint64_t        last_ns;
    pp_stats_t      up, dn;
} pp_session_view_t;

typedef struct pp_session_filter {
    bool        has_src; pp_addr_t src;
    bool        has_dst; pp_addr_t dst;
    bool        has_app; uint8_t   app;
    bool        has_state; uint8_t state;
} pp_session_filter_t;

/* mgmt 调用：从所有 shard 拉取当前快照，匹配 filter 写入 out（最多 max 条） */
int pp_session_snapshot(pp_session_shard_t *const *shards, int n_shards,
                        const pp_session_filter_t *filter,
                        pp_session_view_t *out, int max);

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_SESSION_H */
