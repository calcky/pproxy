/* core/time.c -- 单调时钟 */
#include <time.h>
#include "pproxy/pproxy.h"

uint64_t pp__now_ns_impl(void);

uint64_t pp__now_ns_impl(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}
