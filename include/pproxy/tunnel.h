/*
 * tunnel.h -- 右手 Tunnel 抽象（vtable）
 *
 * 一条 tunnel = (proto, io) 组合：
 *   proto = 协议编码     —— TCP/UDP/ICMP/KCP/QUIC，决定 wire format 与 sid 复用
 *   io    = I/O 后端     —— kernel_socket / raw_socket / af_xdp / netmap
 *
 * proto 与 io 在概念上正交：
 *   - tcp 必须配 kernel_socket（除非自带用户态 TCP 栈）
 *   - udp / icmp / kcp / quic 都可以选 kernel_socket（默认）或 raw_socket / af_xdp / netmap
 *
 * 每个 proto 实现注册一份 ops；ops->open() 内根据 cfg->io 选具体 I/O 路径。
 * 不支持的 (proto, io) 组合在 open() 中返回 PP_ERR_NOSUPPORT。
 */
#ifndef PPROXY_TUNNEL_H
#define PPROXY_TUNNEL_H

#include "pproxy/pproxy.h"
#include "pproxy/packet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---------- proto：协议编码 ---------- */
typedef enum pp_tunnel_proto {
    PP_PROTO_TCP  = 0,
    PP_PROTO_UDP  = 1,
    PP_PROTO_ICMP = 2,
    PP_PROTO_KCP  = 3,
    PP_PROTO_QUIC = 4,
} pp_tunnel_proto_t;

/* ---------- io：包传输机制 ---------- */
typedef enum pp_tunnel_io {
    PP_TIO_KERNEL_SOCKET = 0,   /* socket()/connect()/send()，走内核协议栈 */
    PP_TIO_RAW_SOCKET    = 1,   /* SOCK_RAW，内核仍做路由/ARP，但自填 L4 头 */
    PP_TIO_AF_XDP        = 2,   /* AF_XDP，零拷贝 */
    PP_TIO_NETMAP        = 3,   /* netmap，零拷贝 */
    PP_TIO_PCAP          = 4,   /* libpcap，BPF 过滤 + pcap_inject */
    PP_TIO_TUN           = 5,   /* 通过 TUN 设备重注入（让内核路由） */
} pp_tunnel_io_t;

/* I/O 能力位（用于 ops->supported_io_mask） */
#define PP_TIO_BIT(io)              (1u << (io))
#define PP_TIO_MASK_KERNEL_SOCKET   PP_TIO_BIT(PP_TIO_KERNEL_SOCKET)
#define PP_TIO_MASK_RAW_SOCKET      PP_TIO_BIT(PP_TIO_RAW_SOCKET)
#define PP_TIO_MASK_AF_XDP          PP_TIO_BIT(PP_TIO_AF_XDP)
#define PP_TIO_MASK_NETMAP          PP_TIO_BIT(PP_TIO_NETMAP)
#define PP_TIO_MASK_PCAP            PP_TIO_BIT(PP_TIO_PCAP)
#define PP_TIO_MASK_TUN             PP_TIO_BIT(PP_TIO_TUN)

/* 判断/字符串化 */
const char *pp_tunnel_io_name(pp_tunnel_io_t io);

/* ---------- proto 能力位 ---------- */
#define PP_TUN_CAP_RELIABLE     (1u << 0)   /* 自带可靠传输 */
#define PP_TUN_CAP_ENCRYPTED    (1u << 1)
#define PP_TUN_CAP_MUX          (1u << 2)   /* 多 sid 复用一条物理连接 */
#define PP_TUN_CAP_KEEPALIVE    (1u << 3)

/* ---------- mode：一条 tunnel 是"发起方"还是"监听方" ---------- */
typedef enum pp_tunnel_mode {
    PP_TMODE_CLIENT = 0,    /* connect() 到 server / sendto server */
    PP_TMODE_SERVER = 1,    /* listen()/bind()，peer 由对端首包决定 */
} pp_tunnel_mode_t;

/* ---------- 配置 ---------- */
typedef struct pp_tunnel_cfg {
    pp_tunnel_proto_t proto;        /* 协议编码 */
    pp_tunnel_io_t    io;           /* I/O 后端；缺省由调用方填 KERNEL_SOCKET */
    pp_tunnel_mode_t  mode;         /* client / server */
    const char       *name;
    pp_endpoint_t     server;       /* 远端（client 模式必填） */
    pp_endpoint_t     bind;         /* 本地 bind（client 模式可选） */
    pp_endpoint_t     listen;       /* 本地 listen（server 模式必填） */
    uint32_t          max_sessions;
    uint32_t          keepalive_ms;

    /* 协议特定字段 */
    union {
        struct { bool   nodelay; uint32_t reconnect_ms; } tcp;
        struct { uint16_t mtu; }                          udp;
        struct { uint16_t identifier_base; bool reply_only; } icmp;
    } u;

    /* I/O 特定字段（仅当 io != KERNEL_SOCKET 时才用到） */
    union {
        struct {
            /* 可选：仅 bind(SO_BINDTODEVICE) 限定出口。不填走路由表。 */
            const char *ifname;
        } raw;
        struct {
            const char *ifname;
            uint32_t    queue_id;
            uint32_t    nframes;
            bool        zero_copy;
            bool        need_wakeup;
        } xdp;
        struct {
            const char *ifname;
            uint32_t    nrings;
        } netmap;
        struct {
            const char *ifname;        /* capture 设备，如 eth0 */
            const char *bpf_filter;    /* 可选 BPF 过滤器 */
            uint32_t    snaplen;
        } pcap;
        struct {
            const char *ifname;        /* 右手 tun 设备名，通常要另起 */
        } tun;
    } io_cfg;

    pp_mempool_t *pool;
} pp_tunnel_cfg_t;

/* 收/发的载荷视图（tunnel 不感知 mbuf 头预留） */
typedef struct pp_tun_buf {
    const uint8_t *data;
    size_t         len;
} pp_tun_buf_t;

typedef struct pp_tun_mbuf {
    uint8_t *data;
    size_t   len;
    size_t   cap;
} pp_tun_mbuf_t;

typedef struct pp_tunnel_ops {
    const char       *name;
    pp_tunnel_proto_t proto;
    uint32_t          supported_io_mask;   /* 见 PP_TIO_MASK_* */
    uint32_t          caps;                /* 见 PP_TUN_CAP_* */

    int   (*open)  (const pp_tunnel_cfg_t *cfg, void **out_ctx);
    void  (*close) (void *ctx);

    int   (*connect)(void *ctx);
    int   (*send)(void *ctx, uint64_t sid, const pp_tun_buf_t *buf);
    int   (*recv)(void *ctx, uint64_t *out_sid, pp_tun_mbuf_t *out_buf,
                  int timeout_us);

    void  (*session_close)(void *ctx, uint64_t sid);

    int   (*get_rx_fd)(void *ctx);
    int   (*get_tx_fd)(void *ctx);

    int   (*stat)(void *ctx, char *json, size_t cap);
} pp_tunnel_ops_t;

/* 注册表（按 proto 索引；具体 io 由 ops->open() 内部分发） */
const pp_tunnel_ops_t *pp_tunnel_lookup(pp_tunnel_proto_t proto);
int                    pp_tunnel_register(const pp_tunnel_ops_t *ops);

/* 内置实现 */
extern const pp_tunnel_ops_t pp_tunnel_tcp;
extern const pp_tunnel_ops_t pp_tunnel_udp;
extern const pp_tunnel_ops_t pp_tunnel_icmp;

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_TUNNEL_H */
