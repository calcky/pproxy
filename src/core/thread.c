/* core/thread.c -- 线程命名 + 绑核 */
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "pproxy/module.h"
#include "pproxy/log.h"

int pp_thread_setup(pp_module_t *m, const char *name, int cpu)
{
#ifdef __linux__
    if (m)
        m->lwp = (int32_t)syscall(SYS_gettid);
#else
    (void)m;
#endif
    if (name && *name) {
        char tn[16];
        snprintf(tn, sizeof tn, "%s", name);
        pthread_setname_np(pthread_self(), tn);
    }
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (pthread_setaffinity_np(pthread_self(), sizeof set, &set) != 0) {
            PP_WARN("setaffinity(cpu=%d) failed for %s", cpu, name ? name : "?");
            return PP_ERR_GENERIC;
        }
    }
    return PP_OK;
}
