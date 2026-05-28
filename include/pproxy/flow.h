/*
 * flow.h -- 五元组 FlowKey 与哈希
 *
 * FlowKey 是 SessionTable 的 key。同一条 TCP 连接不论收发方向，
 * 都映射到同一个 normalized key（小端在前），保证 ingress/egress
 * 落到同一个 worker 分片。
 */
#ifndef PPROXY_FLOW_H
#define PPROXY_FLOW_H

#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct pp_flow_key {
    pp_addr_t src;
    pp_addr_t dst;
    uint16_t  sport;        /* host order */
    uint16_t  dport;
    uint8_t   l4_proto;     /* IPPROTO_TCP / UDP / ICMP */
    uint8_t   _pad[3];
} pp_flow_key_t;

/* 方向标记（运行时携带，不进 key） */
typedef enum pp_flow_dir {
    PP_DIR_UPSTREAM   = 0,  /* client -> server */
    PP_DIR_DOWNSTREAM = 1,
} pp_flow_dir_t;

/* 把任意方向的五元组归一化为「小端在前」，保证同向哈希一致 */
void pp_flow_key_normalize(pp_flow_key_t *k, pp_flow_dir_t *out_dir);

/* 哈希；64-bit，便于直接做 hash & (N-1) */
uint64_t pp_flow_key_hash(const pp_flow_key_t *k);

/* hash(key) % n_workers —— left_rx 上行、right_rx 兜底回路共用，
 * 保证 normalize 一致前提下两端落到同一 shard。
 * 未来真正接入 "sid 高 16 位编码 shard" 的隧道头后，下游只对
 * "解隧道头失败 / sid 未知" 的兜底走本函数。 */
PP_INLINE int pp_flow_shard(const pp_flow_key_t *k, int n_workers)
{
    return (int)(pp_flow_key_hash(k) % (uint64_t)n_workers);
}

bool pp_flow_key_equal(const pp_flow_key_t *a, const pp_flow_key_t *b);

/* 调试打印：tcp 1.2.3.4:5678 -> 5.6.7.8:443 */
int  pp_flow_key_format(const pp_flow_key_t *k, char *buf, size_t cap);

/* 从已解析好的 pp_pkt_meta_t 中提取 FlowKey；成功返回 0 */
struct pp_pkt;
int  pp_flow_key_from_pkt(const struct pp_pkt *p, pp_flow_key_t *out);

/* 数据从 L3 IPv4 起始时填充 meta（tunnel 解封后、或 TUN 已带 IP） */
int  pp_pkt_parse_l3_ipv4(struct pp_pkt *p);

#ifdef __cplusplus
}
#endif
#endif /* PPROXY_FLOW_H */
