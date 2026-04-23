/* core/session.c -- 单分片 SessionTable
 *
 * 简化实现：
 *   - 用开放地址的 slot 数组（容量上限固定）
 *   - flow_key -> slot 通过 hash 探测
 *   - sid -> slot 通过 sid 低位直接索引（sid 是分配出来的）
 *   - 没有 RCU；mgmt snapshot 直接拷贝快照（只读 worker 的状态）
 *   - 实际用于高并发可换 cuckoo / RCU hash table
 */
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include "pproxy/session.h"
#include "pproxy/log.h"

struct pp_session_shard {
    pp_session_cfg_t cfg;
    pp_session_t    *slots;     /* 大小 = cfg.max_sessions */
    uint8_t         *used;      /* 0 = free, 1 = used */
    /* free slot 栈 */
    uint32_t        *free_stack;
    int              nfree;
    /* hash → slot 的链 head（开链法） */
    uint32_t        *hash_head; /* size = max_sessions, UINT32_MAX 表空 */
    uint32_t        *next_idx;  /* size = max_sessions, 拉链 */

    uint64_t         next_seq;  /* sid 低位单调递增（用 slot idx 即可） */
};

#define PP_SLOT_NONE  UINT32_MAX

pp_session_shard_t *pp_session_shard_create(const pp_session_cfg_t *cfg)
{
    if (!cfg || cfg->max_sessions == 0) return NULL;
    pp_session_shard_t *sh = calloc(1, sizeof *sh);
    if (!sh) return NULL;
    sh->cfg        = *cfg;
    sh->slots      = calloc(cfg->max_sessions, sizeof(pp_session_t));
    sh->used       = calloc(cfg->max_sessions, 1);
    sh->free_stack = malloc(sizeof(uint32_t) * cfg->max_sessions);
    sh->hash_head  = malloc(sizeof(uint32_t) * cfg->max_sessions);
    sh->next_idx   = malloc(sizeof(uint32_t) * cfg->max_sessions);
    if (!sh->slots || !sh->used || !sh->free_stack
        || !sh->hash_head || !sh->next_idx) {
        pp_session_shard_destroy(sh);
        return NULL;
    }
    for (size_t i = 0; i < cfg->max_sessions; i++) {
        sh->free_stack[i] = (uint32_t)(cfg->max_sessions - 1 - i);
        sh->hash_head[i]  = PP_SLOT_NONE;
        sh->next_idx[i]   = PP_SLOT_NONE;
    }
    sh->nfree = (int)cfg->max_sessions;
    return sh;
}

void pp_session_shard_set_ttl(pp_session_shard_t *sh,
                              uint64_t idle_ttl_ns,
                              uint64_t syn_ttl_ns,
                              uint64_t fin_ttl_ns)
{
    if (!sh) return;
    sh->cfg.idle_ttl_ns = idle_ttl_ns;
    sh->cfg.syn_ttl_ns  = syn_ttl_ns;
    sh->cfg.fin_ttl_ns  = fin_ttl_ns;
}

void pp_session_shard_destroy(pp_session_shard_t *sh)
{
    if (!sh) return;
    free(sh->slots);
    free(sh->used);
    free(sh->free_stack);
    free(sh->hash_head);
    free(sh->next_idx);
    free(sh);
}

static uint32_t bucket_of(pp_session_shard_t *sh, const pp_flow_key_t *k)
{
    return (uint32_t)(pp_flow_key_hash(k) % sh->cfg.max_sessions);
}

pp_session_t *pp_session_lookup(pp_session_shard_t *sh, const pp_flow_key_t *k)
{
    uint32_t b = bucket_of(sh, k);
    for (uint32_t i = sh->hash_head[b]; i != PP_SLOT_NONE; i = sh->next_idx[i]) {
        if (pp_flow_key_equal(&sh->slots[i].key, k))
            return &sh->slots[i];
    }
    return NULL;
}

pp_session_t *pp_session_lookup_or_create(pp_session_shard_t *sh,
                                          const pp_flow_key_t *k,
                                          bool *out_is_new)
{
    pp_session_t *s = pp_session_lookup(sh, k);
    if (s) { if (out_is_new) *out_is_new = false; return s; }

    if (sh->nfree == 0) {
        if (out_is_new) *out_is_new = false;
        return NULL;
    }
    uint32_t idx = sh->free_stack[--sh->nfree];
    s = &sh->slots[idx];
    memset(s, 0, sizeof *s);
    atomic_init(&s->up.drops, 0);
    atomic_init(&s->dn.drops, 0);
    s->key        = *k;
    s->state      = PP_SS_NEW;
    s->app_proto  = PP_APP_UNKNOWN;
    s->created_ns = s->last_ns = pp_now_ns();
    s->sid        = pp_sid_make(sh->cfg.shard_id, idx);
    sh->used[idx] = 1;

    uint32_t b = bucket_of(sh, k);
    sh->next_idx[idx]  = sh->hash_head[b];
    sh->hash_head[b]   = idx;

    if (out_is_new) *out_is_new = true;
    return s;
}

pp_session_t *pp_session_lookup_by_sid(pp_session_shard_t *sh, uint64_t sid)
{
    if (pp_sid_shard(sid) != sh->cfg.shard_id) return NULL;
    uint64_t idx = sid & 0xFFFFFFFFFFFFULL;
    if (idx >= sh->cfg.max_sessions || !sh->used[idx]) return NULL;
    return &sh->slots[idx];
}

void pp_session_remove(pp_session_shard_t *sh, pp_session_t *s)
{
    if (!s) return;
    uint64_t idx = s->sid & 0xFFFFFFFFFFFFULL;
    if (idx >= sh->cfg.max_sessions || !sh->used[idx]) return;

    /* 从拉链摘除 */
    uint32_t b = bucket_of(sh, &s->key);
    uint32_t prev = PP_SLOT_NONE, cur = sh->hash_head[b];
    while (cur != PP_SLOT_NONE && cur != (uint32_t)idx) {
        prev = cur; cur = sh->next_idx[cur];
    }
    if (cur == (uint32_t)idx) {
        if (prev == PP_SLOT_NONE) sh->hash_head[b] = sh->next_idx[cur];
        else                      sh->next_idx[prev] = sh->next_idx[cur];
    }
    sh->used[idx] = 0;
    sh->next_idx[idx] = PP_SLOT_NONE;
    sh->free_stack[sh->nfree++] = (uint32_t)idx;
    s->state = PP_SS_CLOSED;
}

int pp_session_gc(pp_session_shard_t *sh, uint64_t now_ns)
{
    int n = 0;
    for (size_t i = 0; i < sh->cfg.max_sessions; i++) {
        if (!sh->used[i]) continue;
        pp_session_t *s = &sh->slots[i];
        uint64_t ttl = sh->cfg.idle_ttl_ns;
        if (s->state == PP_SS_NEW || s->state == PP_SS_SYN_SENT)
            ttl = sh->cfg.syn_ttl_ns;
        else if (s->state == PP_SS_CLOSE_WAIT)
            ttl = sh->cfg.fin_ttl_ns;
        if (now_ns - s->last_ns > ttl) {
            pp_session_remove(sh, s);
            n++;
        }
    }
    return n;
}

int pp_session_snapshot(pp_session_shard_t *const *shards, int n_shards,
                        const pp_session_filter_t *filter,
                        pp_session_view_t *out, int max)
{
    int n = 0;
    for (int si = 0; si < n_shards && n < max; si++) {
        pp_session_shard_t *sh = shards[si];
        if (!sh) continue;
        for (size_t i = 0; i < sh->cfg.max_sessions && n < max; i++) {
            if (!sh->used[i]) continue;
            pp_session_t *s = &sh->slots[i];
            if (filter) {
                if (filter->has_app   && filter->app   != s->app_proto) continue;
                if (filter->has_state && filter->state != s->state)     continue;
                /* src/dst filter 暂略，如需则 memcmp pp_addr_t */
            }
            pp_session_view_t *v = &out[n++];
            v->sid        = s->sid;
            v->key        = s->key;
            v->state      = s->state;
            v->app_proto  = s->app_proto;
            v->created_ns = s->created_ns;
            v->last_ns     = s->last_ns;
            v->up.pkts     = s->up.pkts;
            v->up.bytes    = s->up.bytes;
            v->up.drops    = (uint64_t)atomic_load_explicit(
                &s->up.drops, memory_order_relaxed);
            v->up.retrans  = s->up.retrans;
            v->dn.pkts     = s->dn.pkts;
            v->dn.bytes    = s->dn.bytes;
            v->dn.drops    = (uint64_t)atomic_load_explicit(
                &s->dn.drops, memory_order_relaxed);
            v->dn.retrans  = s->dn.retrans;
        }
    }
    return n;
}
