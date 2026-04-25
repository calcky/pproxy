/* xsk_xdpcap.h -- PPROXY_XDPCAP_BPF=… 时自载 eBPF、pin xdpcap_hook，与 cloudflare/xdpcap 抓包 */
#ifndef PPROXY_XSK_XDPCAP_H
#define PPROXY_XSK_XDPCAP_H

#include <stdbool.h>

struct pp_xsk_io;

int  pp_xdpcap_xsk_create(struct pp_xsk_io *p,
                          const char *bpf_object_path,
                          bool zero_copy,
                          bool need_wakeup);
void pp_xdpcap_cleanup(struct pp_xsk_io *p);

#endif
