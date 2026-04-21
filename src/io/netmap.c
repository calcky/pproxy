/* src/io/netmap.c -- netmap 后端（stub，仅 NETMAP=1 时编译） */
#ifdef PP_HAVE_NETMAP
#include "pproxy/pkt_io.h"

static int nm_open(const pp_io_cfg_t *cfg, void **out_ctx) { (void)cfg; (void)out_ctx; return PP_ERR_NOSUPPORT; }
static void nm_close(void *ctx) { (void)ctx; }
static int nm_rx(void *c, pp_pkt_t **p, int m, int t) { (void)c; (void)p; (void)m; (void)t; return 0; }
static int nm_tx(void *c, pp_pkt_t **p, int n) { (void)c; (void)p; (void)n; return 0; }
static int nm_fd(void *c) { (void)c; return -1; }

const pp_pkt_io_ops_t pp_io_netmap = {
    .name = "netmap", .kind = PP_IO_NETMAP,
    .caps = PP_IO_CAP_L2 | PP_IO_CAP_ZEROCOPY | PP_IO_CAP_BATCH,
    .open = nm_open, .close = nm_close,
    .rx_burst = nm_rx, .tx_burst = nm_tx,
    .get_rx_fd = nm_fd, .get_tx_fd = nm_fd,
};
#endif
