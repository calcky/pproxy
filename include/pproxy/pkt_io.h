/*
 * pkt_io.h -- 左手 I/O 后端抽象（vtable）
 *
 * 后端实现：tun / raw_socket / xdp / netmap / pcap
 *
 * 由 left_rx 线程持有 ctx 调用 rx_burst；
 * 由 left_tx 线程持有同一个 ctx（或对称的 tx 端）调用 tx_burst。
 *
 * 部分后端（XDP / netmap）rx 与 tx 必须同核绑定，需要 split_rx_tx=false；
 * 部分后端（tun socket）可以分两个 fd，互不影响。
 */
#ifndef PPROXY_PKT_IO_H
#define PPROXY_PKT_IO_H

#include "pproxy/pproxy.h"
#include "pproxy/packet.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 后端能力位 */
#define PP_IO_CAP_L2          (1u << 0)   /* 收/发以太帧 */
#define PP_IO_CAP_L3          (1u << 1)   /* 收/发 IP 包（tun） */
#define PP_IO_CAP_ZEROCOPY    (1u << 2)   /* XDP UMEM / netmap */
#define PP_IO_CAP_BATCH       (1u << 3)
#define PP_IO_CAP_BUSY_POLL   (1u << 4)   /* 不应在 fd 上 epoll，必须 busy poll */
#define PP_IO_CAP_OFFLOAD_CSUM (1u << 5)

typedef enum pp_io_kind {
    PP_IO_TUN        = 0,
    PP_IO_RAW_SOCKET = 1,
    PP_IO_AF_XDP     = 2,
    PP_IO_NETMAP     = 3,
    PP_IO_PCAP       = 4,
} pp_io_kind_t;

/* 配置（联合体便于不同后端复用） */
typedef struct pp_io_cfg {
    pp_io_kind_t kind;
    const char  *name;          /* 调试用 */
    union {
        struct {
            const char *ifname;     /* "tun0" */
            const char *cidr;       /* "10.20.0.0/24" */
            uint16_t    mtu;
            bool        no_pi;      /* IFF_NO_PI */
        } tun;
        struct {
            const char *ifname;
            uint16_t    snaplen;
            bool        promisc;
        } raw;
        struct {
            const char *ifname;
            uint32_t    queue_id;
            uint32_t    nframes;
            bool        zero_copy;
            bool        need_wakeup;
            uint8_t     peer_mac[6];/* 注包时填入 Ethernet dst */
            bool        has_peer_mac;
        } xdp;
        struct {
            const char *ifname;     /* "netmap:eth0" 或 "vale0:1" */
            uint32_t    nrings;
        } netmap;
        struct {
            const char *ifname;
            uint16_t    snaplen;
            int         buffer_size;
            const char *bpf;        /* 可选 BPF 过滤表达式；NULL/空串不过滤 */
            uint8_t     peer_mac[6];/* 注包时填入 Ethernet dst（DLT_EN10MB 需要） */
            bool        has_peer_mac;
        } pcap;
    } u;
    pp_mempool_t *pool;         /* 用于分配 rx mbuf；可为 NULL（后端自带 UMEM 时） */
} pp_io_cfg_t;

/* vtable */
typedef struct pp_pkt_io_ops {
    const char *name;
    pp_io_kind_t kind;
    uint32_t     caps;

    int   (*open)  (const pp_io_cfg_t *cfg, void **out_ctx);
    void  (*close) (void *ctx);

    /* 收一批；返回收到的数量；0 表示无数据；负数为错误。
     * timeout_us = 0  非阻塞；
     * timeout_us > 0  阻塞至多这么久；
     * timeout_us < 0  调用方决定（结合 fd + epoll）。 */
    int   (*rx_burst)(void *ctx, pp_pkt_t **pkts, int max, int timeout_us);

    /* 发一批；返回成功发出的数量；调用方负责对未发出包的处理（重试/丢弃） */
    int   (*tx_burst)(void *ctx, pp_pkt_t **pkts, int n);

    /* 用于事件驱动；返回 -1 表示该后端必须 busy poll */
    int   (*get_rx_fd)(void *ctx);
    int   (*get_tx_fd)(void *ctx);

    /* 状态查询（mgmt 用） */
    int   (*stat)(void *ctx, char *json, size_t cap);
} pp_pkt_io_ops_t;

/* 注册表（编译期或运行期都可用） */
const pp_pkt_io_ops_t *pp_pkt_io_lookup(pp_io_kind_t kind);
int                    pp_pkt_io_register(const pp_pkt_io_ops_t *ops);

/* 内置后端 */
extern const pp_pkt_io_ops_t pp_io_tun;
extern const pp_pkt_io_ops_t pp_io_raw_socket;
extern const pp_pkt_io_ops_t pp_io_af_xdp;
extern const pp_pkt_io_ops_t pp_io_netmap;
extern const pp_pkt_io_ops_t pp_io_pcap;

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_PKT_IO_H */
