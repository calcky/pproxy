/* core/packet.c -- mbuf + per-thread mempool（free-list 风格） */
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include "pproxy/packet.h"
#include "pproxy/log.h"

struct pp_mempool {
    pp_mempool_cfg_t cfg;
    pthread_mutex_t  lock;       /* 仅 alloc/free 时短暂持有；同 worker 内
                                    实际从未跨线程，但保留锁以便 mgmt 查询。 */
    pp_pkt_t       **freelist;   /* 栈式 free-list */
    int              nfree;
    pp_pkt_t        *all;        /* 整块 mbuf 数组，便于一次性释放 */
    uint8_t         *all_buf;    /* 整块 data buffer */
    size_t           nelem;
};

pp_mempool_t *pp_mempool_create(const pp_mempool_cfg_t *cfg)
{
    if (!cfg || cfg->nelem == 0 || cfg->buf_size == 0) return NULL;
    pp_mempool_t *mp = calloc(1, sizeof *mp);
    if (!mp) return NULL;
    mp->cfg   = *cfg;
    mp->nelem = cfg->nelem;

    mp->all     = aligned_alloc(PP_CACHELINE,
                                ((sizeof(pp_pkt_t) * cfg->nelem
                                  + PP_CACHELINE - 1) / PP_CACHELINE) * PP_CACHELINE);
    mp->all_buf = aligned_alloc(PP_CACHELINE,
                                ((size_t)cfg->buf_size * cfg->nelem
                                  + PP_CACHELINE - 1) & ~(PP_CACHELINE - 1));
    mp->freelist = malloc(sizeof(pp_pkt_t *) * cfg->nelem);
    if (!mp->all || !mp->all_buf || !mp->freelist) goto fail;
    memset(mp->all, 0, sizeof(pp_pkt_t) * cfg->nelem);

    pthread_mutex_init(&mp->lock, NULL);
    for (size_t i = 0; i < cfg->nelem; i++) {
        pp_pkt_t *p = &mp->all[i];
        p->buf_base = mp->all_buf + (size_t)cfg->buf_size * i;
        p->buf_len  = cfg->buf_size;
        p->headroom = cfg->headroom;
        p->tailroom = cfg->buf_size - cfg->headroom;
        p->data     = p->buf_base + cfg->headroom;
        p->data_len = 0;
        p->pool     = mp;
        atomic_init(&p->refcnt, 0);
        mp->freelist[i] = p;
    }
    mp->nfree = (int)cfg->nelem;
    return mp;
fail:
    free(mp->all); free(mp->all_buf); free(mp->freelist); free(mp);
    return NULL;
}

void pp_mempool_destroy(pp_mempool_t *mp)
{
    if (!mp) return;
    pthread_mutex_destroy(&mp->lock);
    free(mp->all); free(mp->all_buf); free(mp->freelist); free(mp);
}

pp_pkt_t *pp_mempool_alloc(pp_mempool_t *mp)
{
    pp_pkt_t *p = NULL;
    pthread_mutex_lock(&mp->lock);
    if (mp->nfree > 0) {
        p = mp->freelist[--mp->nfree];
    }
    pthread_mutex_unlock(&mp->lock);
    if (!p) return NULL;
    /* 复位 */
    p->headroom = mp->cfg.headroom;
    p->tailroom = mp->cfg.buf_size - mp->cfg.headroom;
    p->data     = p->buf_base + p->headroom;
    p->data_len = 0;
    memset(&p->meta, 0, sizeof p->meta);
    p->meta.l2_off = p->meta.l3_off = p->meta.l4_off = p->meta.payload_off = UINT16_MAX;
    atomic_store_explicit(&p->refcnt, 1, memory_order_relaxed);
    return p;
}

int pp_mempool_alloc_bulk(pp_mempool_t *mp, pp_pkt_t **out, int n)
{
    int got = 0;
    pthread_mutex_lock(&mp->lock);
    int avail = mp->nfree < n ? mp->nfree : n;
    for (int i = 0; i < avail; i++)
        out[got++] = mp->freelist[--mp->nfree];
    pthread_mutex_unlock(&mp->lock);
    for (int i = 0; i < got; i++) {
        pp_pkt_t *p = out[i];
        p->headroom = mp->cfg.headroom;
        p->tailroom = mp->cfg.buf_size - mp->cfg.headroom;
        p->data     = p->buf_base + p->headroom;
        p->data_len = 0;
        memset(&p->meta, 0, sizeof p->meta);
        p->meta.l2_off = p->meta.l3_off = p->meta.l4_off = p->meta.payload_off = UINT16_MAX;
        atomic_store_explicit(&p->refcnt, 1, memory_order_relaxed);
    }
    return got;
}

void pp_mempool_free(pp_pkt_t *p)
{
    if (!p || !p->pool) return;
    pp_mempool_t *mp = p->pool;
    pthread_mutex_lock(&mp->lock);
    if (mp->nfree < (int)mp->nelem)
        mp->freelist[mp->nfree++] = p;
    pthread_mutex_unlock(&mp->lock);
}

void pp_pkt_put_ref(pp_pkt_t *p)
{
    if (!p) return;
    if (atomic_fetch_sub_explicit(&p->refcnt, 1, memory_order_acq_rel) == 1)
        pp_mempool_free(p);
}

int pp_pkt_push(pp_pkt_t *p, uint16_t n)
{
    if (n > p->headroom) return PP_ERR_NOMEM;
    p->headroom -= n;
    p->data     -= n;
    p->data_len += n;
    return PP_OK;
}
int pp_pkt_pull(pp_pkt_t *p, uint16_t n)
{
    if (n > p->data_len) return PP_ERR_INVAL;
    p->headroom += n;
    p->data     += n;
    p->data_len -= n;
    return PP_OK;
}
int pp_pkt_put(pp_pkt_t *p, uint16_t n)
{
    if (n > p->tailroom) return PP_ERR_NOMEM;
    p->tailroom -= n;
    p->data_len += n;
    return PP_OK;
}
int pp_pkt_trim(pp_pkt_t *p, uint16_t n)
{
    if (n > p->data_len) return PP_ERR_INVAL;
    p->tailroom += n;
    p->data_len -= n;
    return PP_OK;
}
