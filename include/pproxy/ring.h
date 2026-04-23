/*
 * ring.h -- 无锁环形队列
 *
 * 统一为四下标序线发布（与常见 j_ring / DPDK 式做法一致，无互斥）：
 *   入队：CAS prod_head → 写 slot → 自旋至 prod_tail==old_ph → 发布 prod_tail；
 *   出队：CAS cons_head → 读 slot → 自旋至 cons_tail==old_ch → 发布 cons_tail。
 * `PP_RING_SPSC` / `PP_RING_MPSC` 仅表示预期用法，**实现相同**；单生产者+单消费者时
 * 无跨生产者重序，自旋极短。多生产者+单消费者为无锁 MPSC。
 *
 * 对 `src/core/ring.c` 可编译期定义 `PP_RING_USE_CPU_BACKOFF`：默认 1，自旋阶段使用
 * `pause`/`yield` 提示；为 0 时该阶段为忙等（见 `doc/ring.md` 基准）。
 *
 * 元素类型限定为指针（pp_pkt_t* 或控制消息指针）。
 */
#ifndef PPROXY_RING_H
#define PPROXY_RING_H

#include <stdatomic.h>
#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 通用句柄（不透明） ---------- */
typedef struct pp_ring pp_ring_t;

typedef enum pp_ring_kind {
    PP_RING_SPSC = 0,
    PP_RING_MPSC = 1,
} pp_ring_kind_t;

typedef struct pp_ring_cfg {
    pp_ring_kind_t kind;            /* SPSC / MPSC 创建相同环；见头文件说明 */
    size_t         capacity;        /* 必须是 2 的幂 */
    int            numa_node;       /* -1 = 不绑定 */
    const char    *name;            /* 调试用 */
} pp_ring_cfg_t;

pp_ring_t *pp_ring_create(const pp_ring_cfg_t *cfg);
void       pp_ring_destroy(pp_ring_t *r);

size_t     pp_ring_capacity(const pp_ring_t *r);
size_t     pp_ring_size(const pp_ring_t *r);
bool       pp_ring_empty(const pp_ring_t *r);
bool       pp_ring_full (const pp_ring_t *r);

/* ---------- 入队 / 出队（指针元素） ----------
 * 返回实际处理条数；0 表示空/满。
 */
int pp_ring_enqueue (pp_ring_t *r, void *elem);
int pp_ring_dequeue (pp_ring_t *r, void **elem);

int pp_ring_enqueue_burst(pp_ring_t *r, void *const *elems, int n);
int pp_ring_dequeue_burst(pp_ring_t *r, void **elems, int n);

/* ---------- 控制消息（worker ctrl_ring 用） ----------
 * 跨线程下发命令的小型联合体；不分配，按值塞进 ring。
 */
typedef enum pp_ctl_op {
    PP_CTL_NONE = 0,
    PP_CTL_GC_TICK,
    PP_CTL_KICK_SESSION,        /* 强制清理某 session */
    PP_CTL_RELOAD_CFG,
    PP_CTL_DUMP_STATS,
    PP_CTL_QUIT,
} pp_ctl_op_t;

typedef struct pp_ctl_msg {
    uint32_t op;                /* pp_ctl_op_t */
    uint32_t flags;
    uint64_t arg0;              /* 例：sid */
    uint64_t arg1;
    void    *ptr;               /* 可选：指向 mgmt 分配的请求 */
} pp_ctl_msg_t;

/* 控制消息走单独通道（同样是 SPSC ring，元素是 pp_ctl_msg_t* 指针，
 * 由发送方 mempool 分配，接收方处理后 free）。 */

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_RING_H */
