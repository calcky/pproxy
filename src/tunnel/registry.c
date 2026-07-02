/* src/tunnel/registry.c -- tunnel 协议注册表
 *
 * 各协议模块（tcp.c / udp.c / icmp.c）只负责定义 pp_tunnel_<proto>
 * 这个 pp_tunnel_ops_t 实例，main 启动时调 pp_tunnel_register 把它挂进来。
 * 查表时按 pp_tunnel_proto_t 索引。
 *
 * 顺带提供 pp_tunnel_io_name —— 把 pp_tunnel_io_t 枚举格式化成字符串，
 * 日志/stats 用得到。
 */
#include "pproxy/tunnel.h"

#define PP_TUN_MAX 8
static const pp_tunnel_ops_t *g_tops[PP_TUN_MAX];
static int g_tn;

int pp_tunnel_register(const pp_tunnel_ops_t *ops)
{
    if (!ops) return PP_ERR_INVAL;
    if (g_tn >= PP_TUN_MAX) return PP_ERR_FULL;
    g_tops[g_tn++] = ops;
    return PP_OK;
}

const pp_tunnel_ops_t *pp_tunnel_lookup(pp_tunnel_proto_t proto)
{
    for (int i = 0; i < g_tn; i++)
        if (g_tops[i]->proto == proto) return g_tops[i];
    return NULL;
}

const char *pp_tunnel_io_name(pp_tunnel_io_t io)
{
    switch (io) {
    case PP_TIO_KERNEL_SOCKET: return "kernel_socket";
    case PP_TIO_RAW_SOCKET:    return "raw_socket";
    case PP_TIO_AF_XDP:        return "af_xdp";
    case PP_TIO_NETMAP:        return "netmap";
    case PP_TIO_PCAP:          return "pcap";
    case PP_TIO_TUN:           return "tun";
    case PP_TIO_DPDK:          return "dpdk";
    case PP_TIO_MEMIF:         return "memif";
    default:                   return "unknown";
    }
}
