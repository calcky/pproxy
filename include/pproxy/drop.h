/*
 * drop.h -- 丢包：TRACE 日志、会话上 atomic 累加、无法归属 session 的孤儿计数
 *
 * 路径（与 session 的 up/dn 一致，对应 mgmt 里可读的 rx/tx 语义）:
 *   up_path=1: 向 tunnel/服务端路径（如 左口→worker→right_tx）上的丢包
 *   up_path=0: 自 tunnel 回左口路径（如 right_rx→worker→left_tx）上的丢包
 */
#ifndef PPROXY_DROP_H
#define PPROXY_DROP_H

#include <stdint.h>
#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pp_session;
struct pp_flow_key;
struct pp_pkt;
struct pp_runtime; /* pp_runtime_t in runtime.h */

typedef enum {
    /* left_rx: 在绑定 session 前丢包 */
    PP_ORPHAN_LRX_BAD_KEY = 0,
    PP_ORPHAN_LRX_WKR_RX_RING,
    /* right_rx */
    PP_ORPHAN_RRX_L3,
    PP_ORPHAN_RRX_BAD_KEY,
    PP_ORPHAN_RRX_WKR_BACK_RING,
    /* worker: 有/无五元组见具体调用 */
    PP_ORPHAN_WK_UP_BAD_KEY,
    PP_ORPHAN_WK_UP_TABLE_FULL,
    PP_ORPHAN_WK_UP_RIGHT_TX_RING,
    PP_ORPHAN_WK_DN_L3,
    PP_ORPHAN_WK_DN_BAD_KEY,
    PP_ORPHAN_WK_DN_TABLE_FULL,
    PP_ORPHAN_WK_DN_LEFT_TX_RING,
    PP_ORPHAN__N
} pp_orphan_drop_t;

typedef struct pp_drop_orphan_totals {
    uint64_t v[PP_ORPHAN__N];
} pp_drop_orphan_totals_t;

/* 已 lookup 到的 session：累加 up/dn.drops，并打一条 TRACE */
void pp_drop_session(struct pp_session *s, int up_path,
                     const char *where, const char *reason);

/* 无 session：孤儿计数 + TRACE；k 可为 NULL（无五元组时） */
void pp_drop_orphan(int up_path, pp_orphan_drop_t kind, const char *where,
                    const char *reason, const struct pp_flow_key *k_opt);

/* 仅 sid 知（right_tx/left_tx）：归属会话 drops；sid==0 时只打 TRACE、不计入 session */
void pp_drop_by_sid(struct pp_runtime *rt, uint64_t sid, int up_path,
                    const char *where, const char *reason);

/* 从 pkt 尽量取五元组打 TRACE 并做孤儿计数；失败则日志中无 flow */
void pp_drop_orphan_pkt(int up_path, pp_orphan_drop_t kind, const char *where,
                        const char *reason, const struct pp_pkt *pkt);

void pp_drop_orphan_get(pp_drop_orphan_totals_t *out);

#ifdef __cplusplus
}
#endif
#endif
