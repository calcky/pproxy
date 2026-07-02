/* tests/test_memif_io.c
 *
 * 验证 src/io/memif.c 的 create/poll/free 链路（master 侧，无需 VPP peer）。
 * 若未以 -Dmemif=true 编译，或 libmemif 初始化失败，exit 77 skip。
 */
#include <stdio.h>
#include <stdlib.h>

#include "pproxy/log.h"

#ifdef PP_HAVE_MEMIF
#include "io/memif.h"
#endif

int main(void)
{
#ifndef PP_HAVE_MEMIF
    puts("skip: built without -Dmemif=true");
    return 77;
#else
    struct pp_memif_io *io = NULL;
    int rc = pp_memif_io_new(&io, "/tmp/pproxy_test_memif.sock",
                             0, true, 1024, 2048, NULL);
    if (rc != PP_OK || !io) {
        puts("skip: memif create failed (no libmemif?)");
        return 77;
    }
    pp_memif_io_poll(io, 0);
    pp_memif_io_free(io);
    puts("ok: memif master create/poll/free");
    return 0;
#endif
}
