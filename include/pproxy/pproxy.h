/*
 * pproxy.h -- 公共类型、错误码、宏定义
 *
 * 所有 pproxy 头文件的公共基础。仅依赖标准库与 Linux 头。
 */
#ifndef PPROXY_PPROXY_H
#define PPROXY_PPROXY_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- 版本 ---------- */
#define PP_VERSION_MAJOR  0
#define PP_VERSION_MINOR  1
#define PP_VERSION_PATCH  0

/* ---------- 编译期工具宏 ---------- */
#define PP_CACHELINE        64
#define PP_CACHELINE_ALIGN  __attribute__((aligned(PP_CACHELINE)))
#define PP_PACKED           __attribute__((packed))
#define PP_UNUSED           __attribute__((unused))
#define PP_INLINE           static inline __attribute__((always_inline))
#define PP_LIKELY(x)        __builtin_expect(!!(x), 1)
#define PP_UNLIKELY(x)      __builtin_expect(!!(x), 0)
#define PP_ARRAY_SIZE(a)    (sizeof(a) / sizeof((a)[0]))

#define PP_MIN(a, b)        ((a) < (b) ? (a) : (b))
#define PP_MAX(a, b)        ((a) > (b) ? (a) : (b))

/* ---------- 错误码 ----------
 * 约定：成功返回 0；正数为业务返回值（如收到包数）；负数为错误码。
 */
#define PP_OK                0
#define PP_ERR_GENERIC      (-1)
#define PP_ERR_NOMEM        (-2)
#define PP_ERR_INVAL        (-3)
#define PP_ERR_AGAIN        (-4)   /* would block / 队列空满 */
#define PP_ERR_NOTFOUND     (-5)
#define PP_ERR_EXIST        (-6)
#define PP_ERR_FULL         (-7)
#define PP_ERR_EMPTY        (-8)
#define PP_ERR_CLOSED       (-9)
#define PP_ERR_TIMEOUT      (-10)
#define PP_ERR_IO           (-11)
#define PP_ERR_PROTO        (-12)
#define PP_ERR_NOSUPPORT    (-13)

const char *pp_strerror(int err);

/* ---------- 网络通用类型 ---------- */
typedef enum pp_af {
    PP_AF_INET  = 4,
    PP_AF_INET6 = 6,
} pp_af_t;

/* IPv4/v6 地址联合体 */
typedef struct pp_addr {
    pp_af_t af;
    union {
        struct in_addr  v4;
        struct in6_addr v6;
    } u;
} pp_addr_t;

/* (addr, port) endpoint */
typedef struct pp_endpoint {
    pp_addr_t addr;
    uint16_t  port;       /* host order */
} pp_endpoint_t;

int  pp_endpoint_parse(const char *str, pp_endpoint_t *out);
int  pp_endpoint_format(const pp_endpoint_t *ep, char *buf, size_t cap);

/* right_tx → tunnel 单帧载荷上界（与常见以太 MTU 一致） */
#define PP_TUN_TX_PAYLOAD_MAX  1500U
#define PP_TUN_TX_PAYLOAD_LEN_OK(len) \
    ((len) > 0U && (len) <= PP_TUN_TX_PAYLOAD_MAX)

/* ---------- 时间 ---------- */
PP_INLINE uint64_t pp_now_ns(void)
{
    extern uint64_t pp__now_ns_impl(void);   /* core/time.c */
    return pp__now_ns_impl();
}

/* ---------- 全局上下文（由 main 持有） ----------
 * 任意线程都可以读，配置走 RCU 切换。
 */
typedef struct pp_ctx pp_ctx_t;     /* 不透明 */

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_PPROXY_H */
