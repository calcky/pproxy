/* src/io/pcap.h -- libpcap 收发 IP 帧的薄封装
 *
 * 仅在 -Dpcap=true 时由 build 启用（PP_HAVE_PCAP）。不启用时整个 .c 文件内容为空。
 *
 * 本 header 故意不 include <pcap/pcap.h>——因为 pcap 的 bpf.h 会跟 libbpf
 * (linux/bpf.h) 里 struct bpf_insn 冲突。这里只暴露不透明指针 + API。
 */
#ifndef PPROXY_IO_PCAP_H
#define PPROXY_IO_PCAP_H

#include <stdint.h>
#include <stddef.h>
#include "pproxy/pproxy.h"

#ifdef PP_HAVE_PCAP

struct pp_pcap_io;    /* opaque */

int                pp_pcap_io_new(struct pp_pcap_io **out,
                                  const char *ifname,
                                  const uint8_t peer_mac[6],
                                  const char *bpf,
                                  uint32_t snaplen);
void               pp_pcap_io_free(struct pp_pcap_io *p);

int                pp_pcap_io_get_fd    (const struct pp_pcap_io *p);
const char        *pp_pcap_io_get_ifname(const struct pp_pcap_io *p);

int                pp_pcap_io_inject_ip(struct pp_pcap_io *p,
                                        const uint8_t *ip, size_t len);
const uint8_t     *pp_pcap_io_next_ip  (struct pp_pcap_io *p, size_t *out_len);

#endif /* PP_HAVE_PCAP */
#endif /* PPROXY_IO_PCAP_H */
