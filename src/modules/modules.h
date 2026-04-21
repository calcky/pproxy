/*
 * modules.h -- 模块间共享的辅助函数 prototype（避免 -Wmissing-prototypes）
 */
#ifndef PPROXY_MODULES_H
#define PPROXY_MODULES_H

#include "pproxy/module.h"

#ifdef __cplusplus
extern "C" {
#endif

int pp_worker_set_index(pp_module_t *m, int idx);
int pp_right_tx_set_index(pp_module_t *m, int idx);
int pp_right_rx_set_index(pp_module_t *m, int idx);
void pp_main_request_quit(void);

#ifdef __cplusplus
}
#endif
#endif
