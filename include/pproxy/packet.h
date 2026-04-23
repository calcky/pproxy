/*
 * packet.h -- 数据包对象（mbuf）+ per-thread mempool
 *
 * 设计要点：
 *   - 每个 worker / I/O 线程持有自己的 mempool，分配释放无锁；
 *   - mbuf 内嵌引用计数，跨线程仅传指针；
 *   - 预留 headroom / tailroom，以支持原地封装/解封装（避免拷贝）；
 *   - 对 XDP / netmap zero-copy 路径，data 区可指向外部 UMEM。
 */
#ifndef PPROXY_PACKET_H
#define PPROXY_PACKET_H

#include <stdatomic.h>
#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 数据包来源 / 类型，决定 L2 是否存在等 */
typedef enum pp_pkt_origin {
    PP_PKT_FROM_TUN     = 0,    /* L3 起始（无 L2 头） */
    PP_PKT_FROM_RAW     = 1,    /* L2 起始（有以太头） */
    PP_PKT_FROM_XDP     = 2,    /* AF_XDP UMEM */
    PP_PKT_FROM_NETMAP  = 3,
    PP_PKT_FROM_PCAP    = 4,
    PP_PKT_FROM_TUNNEL  = 5,    /* 右手 tunnel 解封后 */
    PP_PKT_FROM_LOCAL   = 6,    /* 内部生成（如心跳） */
} pp_pkt_origin_t;

/* L2/L3/L4 解析结果偏移（字节）；UINT16_MAX 表示无效 */
typedef struct pp_pkt_meta {
    uint16_t l2_off;
    uint16_t l3_off;
    uint16_t l4_off;
    uint16_t payload_off;
    uint16_t payload_len;
    uint8_t  l3_proto;          /* IPPROTO_IP / IPPROTO_IPV6 */
    uint8_t  l4_proto;          /* IPPROTO_TCP / UDP / ICMP */
    uint16_t shard;             /* 计算好的 worker 分片号 */
    uint64_t flow_hash;         /* FlowKey hash 或 (upstream) 上送 right_tx 时复用为 sid */
    uint64_t sid;               /* 会话 id；0=未设；与 worker/隧道路径上一致时便于 tx 侧丢包归会话 */
    uint64_t rx_ns;             /* 收到的时间戳 */
} pp_pkt_meta_t;

/* mbuf 主体；尽量塞进 1~2 个 cacheline */
typedef struct pp_pkt {
    /* --- 控制头：cacheline 0 --- */
    atomic_int       refcnt;            /* 跨线程持有时 +1 */
    uint16_t         buf_len;           /* 整个 buf 容量 */
    uint16_t         headroom;          /* data 之前的可用空间 */
    uint16_t         data_len;          /* 当前有效数据长度 */
    uint16_t         tailroom;          /* data 之后的可用空间 */
    uint8_t          origin;            /* pp_pkt_origin_t */
    uint8_t          owner_thread;      /* 调试用：分配它的线程 id */
    uint16_t         _pad0;
    struct pp_mempool *pool;            /* 归还时使用 */
    void            *priv;              /* I/O 后端可挂私有指针（如 UMEM 描述符） */

    /* --- meta：cacheline 1 --- */
    pp_pkt_meta_t    meta;

    /* --- buf：紧随其后或外置（zero-copy 时为 NULL） --- */
    uint8_t         *data;              /* = buf_base + headroom */
    uint8_t         *buf_base;          /* mempool 分配的 base；外置时为 NULL */
} PP_CACHELINE_ALIGN pp_pkt_t;

/* 内联取/置数据指针 */
PP_INLINE uint8_t *pp_pkt_data(pp_pkt_t *p)        { return p->data; }
PP_INLINE uint16_t pp_pkt_len(const pp_pkt_t *p)   { return p->data_len; }
PP_INLINE uint16_t pp_pkt_headroom(const pp_pkt_t *p)  { return p->headroom; }
PP_INLINE uint16_t pp_pkt_tailroom(const pp_pkt_t *p)  { return p->tailroom; }

/* 推/弹首部空间（封装/解封装隧道头时高频调用） */
int pp_pkt_push(pp_pkt_t *p, uint16_t n);   /* headroom -= n; data -= n */
int pp_pkt_pull(pp_pkt_t *p, uint16_t n);   /* headroom += n; data += n */
int pp_pkt_put (pp_pkt_t *p, uint16_t n);   /* tailroom -= n; data_len += n */
int pp_pkt_trim(pp_pkt_t *p, uint16_t n);   /* tailroom += n; data_len -= n */

/* 引用计数 */
PP_INLINE void pp_pkt_get(pp_pkt_t *p) { atomic_fetch_add_explicit(&p->refcnt, 1, memory_order_relaxed); }
void pp_pkt_put_ref(pp_pkt_t *p);   /* refcnt-- == 0 时归还 mempool */

/* ---------- mempool ---------- */
typedef struct pp_mempool pp_mempool_t;

typedef struct pp_mempool_cfg {
    size_t   nelem;             /* mbuf 数量 */
    uint16_t buf_size;          /* 每个 mbuf 的 data 区容量（含 head/tailroom） */
    uint16_t headroom;          /* 默认预留 */
    int      cpu;               /* 绑定 NUMA 节点对应的 CPU；-1 不绑定 */
    bool     use_hugepages;
} pp_mempool_cfg_t;

pp_mempool_t *pp_mempool_create(const pp_mempool_cfg_t *cfg);
void          pp_mempool_destroy(pp_mempool_t *mp);

pp_pkt_t     *pp_mempool_alloc(pp_mempool_t *mp);
int           pp_mempool_alloc_bulk(pp_mempool_t *mp, pp_pkt_t **out, int n);
void          pp_mempool_free(pp_pkt_t *p);     /* 内部由 pp_pkt_put_ref 调用 */

/* ---------- batch ---------- */
#define PP_PKT_BURST_MAX  64

typedef struct pp_pkt_batch {
    int       n;
    pp_pkt_t *pkts[PP_PKT_BURST_MAX];
} pp_pkt_batch_t;

PP_INLINE void pp_pkt_batch_init(pp_pkt_batch_t *b) { b->n = 0; }
PP_INLINE int  pp_pkt_batch_full(const pp_pkt_batch_t *b) { return b->n >= PP_PKT_BURST_MAX; }

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_PACKET_H */
