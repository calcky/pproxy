/*
 * ring_ipc.h -- ring 消费者 idle 等待 / 生产者唤醒（与 pp_ring 数据面解耦）
 *
 * 模式（runtime.rings.ipc_mode，数据面 ring 统一）:
 *   polling  -- nanosleep(backoff)（默认）
 *   eventfd  -- enqueue 后 eventfd 唤醒；消费者 epoll_wait
 *   futex    -- Linux futex WAIT/WAKE；worker 多 ring 用 futex_waitv(2)
 *
 * worker_ctrl_ring：ipc_mode=polling 时固定 eventfd（控制面需唤醒）；
 * eventfd/futex 时与 ipc_mode 一致。
 */
#ifndef PPROXY_RING_IPC_H
#define PPROXY_RING_IPC_H

#include <stdint.h>
#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pp_ring;
typedef struct pp_ring pp_ring_t;

typedef enum pp_ring_ipc_mode {
    PP_RING_IPC_POLLING = 0,
    PP_RING_IPC_EVENTFD,
    PP_RING_IPC_FUTEX,
} pp_ring_ipc_mode_t;

typedef struct pp_ring_ipc_cfg {
    pp_ring_ipc_mode_t mode;
    uint32_t           poll_backoff_us;   /* polling / 兜底；默认 50 */
} pp_ring_ipc_cfg_t;

struct pp_ring_ipc;
typedef struct pp_ring_ipc pp_ring_ipc_t;

struct pp_ring_ipc_waiter;
typedef struct pp_ring_ipc_waiter pp_ring_ipc_waiter_t;

pp_ring_ipc_t *pp_ring_ipc_create(const pp_ring_ipc_cfg_t *cfg);
void           pp_ring_ipc_destroy(pp_ring_ipc_t *ipc);

/* 绑定到 ring；destroy ring 时会一并 destroy ipc */
void pp_ring_attach_ipc(pp_ring_t *r, pp_ring_ipc_t *ipc);

/* 生产者：成功入队后由 ring.c 在「由空变非空」时自动 notify */
void pp_ring_ipc_notify(pp_ring_ipc_t *ipc);

/* 消费者 idle：单 ring 也建 waiter（init 时 add，循环里 wait）；多 ring 见 worker */
pp_ring_ipc_waiter_t *pp_ring_ipc_waiter_create(void);
void                  pp_ring_ipc_waiter_add(pp_ring_ipc_waiter_t *w, pp_ring_t *r);
void                  pp_ring_ipc_waiter_wait(pp_ring_ipc_waiter_t *w, uint32_t backoff_us);
void                  pp_ring_ipc_waiter_destroy(pp_ring_ipc_waiter_t *w);

const char *pp_ring_ipc_mode_name(pp_ring_ipc_mode_t mode);
pp_ring_ipc_mode_t pp_ring_ipc_mode_parse(const char *s, bool *ok);

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_RING_IPC_H */
