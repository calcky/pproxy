/*
 * module.h -- 线程模块统一接口
 *
 * pproxy 的线程模块（left_rx / left_tx / worker / right_rx / right_tx /
 * timer / mgmt）都实现这个 vtable，由 main 线程统一编排：
 *
 *   register -> init -> start (pthread_create) -> ... -> stop (set quit & join)
 *               -> destroy
 *
 * 模块自身负责：
 *   - 建立线程
 *   - 持有自己的 ring/mempool/上下文
 *   - 在主循环里检查 atomic 退出标志
 */
#ifndef PPROXY_MODULE_H
#define PPROXY_MODULE_H

#include <pthread.h>
#include <stdatomic.h>
#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PP_MODULE_NAME_MAX  32

/* ---------- 模块统计快照（mgmt 拉取用） ---------- */
typedef struct pp_mod_stat {
    char     name[PP_MODULE_NAME_MAX];
    uint64_t loops;             /* 主循环跑了多少圈 */
    uint64_t events_in;         /* 收到事件数（包/消息） */
    uint64_t events_out;
    uint64_t drops;
    uint64_t errors;
    uint64_t last_active_ns;
    uint32_t cpu;               /* 绑核号；UINT32_MAX 表示未绑 */
} pp_mod_stat_t;

/* ---------- 模块自身上下文（每个模块的私有 struct 内嵌它） ---------- */
typedef struct pp_module {
    char            name[PP_MODULE_NAME_MAX];
    pthread_t       tid;
    int             cpu;            /* -1 表示不绑核 */
    atomic_int      quit;           /* 主循环检查；0 = run, 1 = stop */
    atomic_int      state;          /* pp_mod_state_t */
    void           *priv;           /* 模块自定义 */
    const struct pp_module_ops *ops;
} pp_module_t;

typedef enum pp_mod_state {
    PP_MOD_REGISTERED = 0,
    PP_MOD_INITED     = 1,
    PP_MOD_RUNNING    = 2,
    PP_MOD_STOPPING   = 3,
    PP_MOD_STOPPED    = 4,
} pp_mod_state_t;

/* ---------- 模块 vtable ---------- */
typedef struct pp_module_ops {
    /* 解析 cfg 块并完成 init（不开线程） */
    int   (*init)   (pp_module_t *m, void *cfg);

    /* 启动线程；内部 pthread_create，把主循环跑起来 */
    int   (*start)  (pp_module_t *m);

    /* 优雅停止；置 quit 标志后 join */
    void  (*stop)   (pp_module_t *m);

    /* 释放 init 阶段分配的资源 */
    void  (*destroy)(pp_module_t *m);

    /* 拉取实时统计（无锁，只读 cache-aligned 计数器） */
    void  (*stat)   (pp_module_t *m, pp_mod_stat_t *out);
} pp_module_ops_t;

/* ---------- 全局注册表（main 用） ---------- */
int  pp_module_register(pp_module_t *m);
int  pp_module_init_all(void *global_cfg);
int  pp_module_start_all(void);
void pp_module_stop_all(void);
void pp_module_destroy_all(void);

/* 遍历器（mgmt 用） */
typedef int (*pp_module_walk_cb)(pp_module_t *m, void *user);
int  pp_module_walk(pp_module_walk_cb cb, void *user);

pp_module_t *pp_module_find(const char *name);

/* ---------- 主循环辅助 ---------- */
PP_INLINE bool pp_module_should_quit(const pp_module_t *m)
{
    return atomic_load_explicit(&m->quit, memory_order_relaxed) != 0;
}

/* 设置当前线程名 + 绑核（模块 start 内部调用） */
int pp_thread_setup(const char *name, int cpu);

/* ---------- 内置模块实例（具体定义在各 modules/<x>/<x>.c 中） ---------- */
extern pp_module_ops_t pp_mod_left_rx_ops;
extern pp_module_ops_t pp_mod_left_tx_ops;
extern pp_module_ops_t pp_mod_worker_ops;
extern pp_module_ops_t pp_mod_right_rx_ops;
extern pp_module_ops_t pp_mod_right_tx_ops;
extern pp_module_ops_t pp_mod_timer_ops;
extern pp_module_ops_t pp_mod_mgmt_ops;

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_MODULE_H */
