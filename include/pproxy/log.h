/*
 * log.h -- 轻量日志宏（线程安全、运行期可调级别）
 */
#ifndef PPROXY_LOG_H
#define PPROXY_LOG_H

#include <stdio.h>
#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum pp_log_level {
    PP_LOG_TRACE = 0,
    PP_LOG_DEBUG = 1,
    PP_LOG_INFO  = 2,
    PP_LOG_WARN  = 3,
    PP_LOG_ERROR = 4,
    PP_LOG_FATAL = 5,
} pp_log_level_t;

/* 全局当前阈值；低于此级别的调用直接被分支预测短路 */
extern pp_log_level_t pp_log_threshold;

int  pp_log_init(pp_log_level_t lvl, const char *path /* NULL = stderr */);
void pp_log_set_level(pp_log_level_t lvl);

/* 真正的写日志函数（thread-safe，内部加锁或使用 per-thread buffer） */
void pp_log(pp_log_level_t lvl,
            const char *file, int line, const char *func,
            const char *fmt, ...) __attribute__((format(printf, 5, 6)));

#define PP_LOG(lvl, ...) do {                                           \
    if (PP_UNLIKELY((lvl) >= pp_log_threshold))                         \
        pp_log((lvl), __FILE__, __LINE__, __func__, __VA_ARGS__);       \
} while (0)

#define PP_TRACE(...)  PP_LOG(PP_LOG_TRACE, __VA_ARGS__)
#define PP_DEBUG(...)  PP_LOG(PP_LOG_DEBUG, __VA_ARGS__)
#define PP_INFO(...)   PP_LOG(PP_LOG_INFO,  __VA_ARGS__)
#define PP_WARN(...)   PP_LOG(PP_LOG_WARN,  __VA_ARGS__)
#define PP_ERROR(...)  PP_LOG(PP_LOG_ERROR, __VA_ARGS__)
#define PP_FATAL(...)  do { PP_LOG(PP_LOG_FATAL, __VA_ARGS__); abort(); } while (0)

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_LOG_H */
