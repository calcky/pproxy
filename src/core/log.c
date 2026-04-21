/* core/log.c -- 简单 thread-safe 日志 */
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/syscall.h>
#include "pproxy/log.h"

pp_log_level_t pp_log_threshold = PP_LOG_INFO;

static FILE           *g_fp     = NULL;
static pthread_mutex_t g_lock   = PTHREAD_MUTEX_INITIALIZER;
static const char *level_str[] = {"TRC", "DBG", "INF", "WRN", "ERR", "FTL"};

int pp_log_init(pp_log_level_t lvl, const char *path)
{
    pp_log_threshold = lvl;
    if (path && *path && strcmp(path, "-") != 0) {
        FILE *fp = fopen(path, "a");
        if (!fp) return PP_ERR_IO;
        g_fp = fp;
    } else {
        g_fp = stderr;
    }
    return PP_OK;
}

void pp_log_set_level(pp_log_level_t lvl) { pp_log_threshold = lvl; }

void pp_log(pp_log_level_t lvl,
            const char *file, int line, const char *func,
            const char *fmt, ...)
{
    if (!g_fp) g_fp = stderr;

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char tbuf[32];
    strftime(tbuf, sizeof tbuf, "%H:%M:%S", &tm);

    pid_t tid = (pid_t)syscall(SYS_gettid);
    const char *base = strrchr(file, '/');
    base = base ? base + 1 : file;

    char body[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(body, sizeof body, fmt, ap);
    va_end(ap);

    pthread_mutex_lock(&g_lock);
    fprintf(g_fp, "%s.%03ld [%s] [%d] %s:%d %s() %s\n",
            tbuf, ts.tv_nsec / 1000000,
            level_str[lvl], tid, base, line, func, body);
    fflush(g_fp);
    pthread_mutex_unlock(&g_lock);
}
