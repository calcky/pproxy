/* src/io/memif.c -- VPP memif 右手隧道 I/O 薄封装（拷贝版）
 *
 * 仅在 -Dmemif=true（PP_HAVE_MEMIF）时编译。
 *
 * API 与 DPDK/XSK 后端对称：
 *   inject_ip  取 IP 帧，前置 14B Ethernet 头后写入 memif TX ring
 *   next_ip    从 memif RX ring 取 Ethernet 帧，跳过 14B 头返回 IP 帧指针
 *
 * RX 懒归还：burst 全部消费完后，在下一次 next_ip 取新 burst 前批量 refill，
 * 确保调用方在 next_ip 返回到下次调用 next_ip 之间可安全读取返回的指针。
 */
#ifdef PP_HAVE_MEMIF

#include "memif.h"
#include "pproxy/log.h"

#include <stdlib.h>
#include <string.h>
#include <libmemif.h>

#define PP_MEMIF_RING_DEFAULT    1024u
#define PP_MEMIF_BUF_DEFAULT     2048u
#define PP_MEMIF_BURST_MAX       64
#define PP_MEMIF_ETH_HDR         14    /* dst(6) + src(6) + type(2) */

struct pp_memif_io {
    memif_socket_handle_t  socket;
    memif_conn_handle_t    conn;
    bool                   is_connected;
    bool                   is_master;
    uint32_t               ring_size;
    uint32_t               buffer_size;
    uint8_t                src_mac[6];   /* 本端虚拟 MAC（locally-administered） */
    uint8_t                dst_mac[6];   /* 对端 MAC；全零时用 broadcast */
    /* RX batch 状态 */
    memif_buffer_t         rx_bufs[PP_MEMIF_BURST_MAX];
    uint16_t               rx_count;    /* 本 burst 帧数 */
    uint16_t               rx_cur;      /* 已消费帧数 */
};

/* ---------- libmemif 回调 ---------- */

static int on_connect(memif_conn_handle_t conn, void *priv)
{
    struct pp_memif_io *p = priv;
    p->is_connected = true;
    PP_INFO("memif: link up (conn=%p)", (void *)conn);
    memif_refill_queue(conn, 0, -1, 0);   /* 预填满 RX ring */
    return MEMIF_ERR_SUCCESS;
}

static int on_disconnect(memif_conn_handle_t conn, void *priv)
{
    struct pp_memif_io *p = priv;
    p->is_connected = false;
    p->rx_count     = 0;
    p->rx_cur       = 0;
    PP_INFO("memif: link down (conn=%p)", (void *)conn);
    return MEMIF_ERR_SUCCESS;
}

static int on_interrupt(memif_conn_handle_t conn, void *priv, uint16_t qid)
{
    (void)conn; (void)priv; (void)qid;
    return MEMIF_ERR_SUCCESS;
}

/* ---------- 公共接口 ---------- */

int pp_memif_io_new(struct pp_memif_io **out,
                    const char    *socket_path,
                    uint32_t       interface_id,
                    bool           is_master,
                    uint32_t       ring_size,
                    uint32_t       buffer_size,
                    const uint8_t  peer_mac[6])
{
    if (!out || !socket_path || socket_path[0] == '\0') return PP_ERR_INVAL;

    struct pp_memif_io *p = calloc(1, sizeof *p);
    if (!p) return PP_ERR_NOMEM;

    p->is_master   = is_master;
    p->ring_size   = ring_size   ? ring_size   : PP_MEMIF_RING_DEFAULT;
    p->buffer_size = buffer_size ? buffer_size : PP_MEMIF_BUF_DEFAULT;

    /* 本端虚拟 MAC：locally-administered，按接口 ID 区分 */
    p->src_mac[0] = 0x02;
    p->src_mac[1] = 0x00;
    p->src_mac[2] = 'p';
    p->src_mac[3] = 'm';
    p->src_mac[4] = (uint8_t)((interface_id >> 8) & 0xff);
    p->src_mac[5] = (uint8_t)(interface_id & 0xff);

    /* 对端 MAC：全零时用 broadcast */
    if (peer_mac) {
        memcpy(p->dst_mac, peer_mac, 6);
    }
    static const uint8_t zero_mac[6] = {0};
    if (memcmp(p->dst_mac, zero_mac, 6) == 0) {
        memset(p->dst_mac, 0xff, 6);   /* ff:ff:ff:ff:ff:ff */
    }

    /* 创建 Unix domain socket */
    memif_socket_args_t sargs;
    memset(&sargs, 0, sizeof sargs);
    strncpy(sargs.path, socket_path, sizeof(sargs.path) - 1);
    snprintf(sargs.app_name, sizeof(sargs.app_name), "pproxy");
    if (!is_master) {
        /* libmemif v26：slave 通过 socket 定时器自动发连接请求 */
        sargs.connection_request_timer.it_value.tv_nsec = 100 * 1000 * 1000;
        sargs.connection_request_timer.it_interval      = sargs.connection_request_timer.it_value;
    }

    int rc = memif_create_socket(&p->socket, &sargs, NULL);
    if (rc != MEMIF_ERR_SUCCESS) {
        PP_ERROR("memif: create_socket(%s) failed: %s",
                 socket_path, memif_strerror(rc));
        free(p);
        return PP_ERR_IO;
    }

    /* 计算 log2(ring_size)；libmemif 要求 2 的幂 */
    uint32_t rs = p->ring_size;
    uint8_t  log2_rs = 0;
    while (rs > 1) { rs >>= 1; log2_rs++; }

    /* 创建 memif 连接（Ethernet 模式） */
    memif_conn_args_t cargs;
    memset(&cargs, 0, sizeof cargs);
    cargs.socket         = p->socket;
    cargs.interface_id   = interface_id;
    cargs.is_master      = (uint8_t)(is_master ? 1 : 0);
    cargs.mode           = MEMIF_INTERFACE_MODE_ETHERNET;
    cargs.log2_ring_size = log2_rs;
    cargs.buffer_size    = (uint16_t)p->buffer_size;
    snprintf((char *)cargs.interface_name, sizeof(cargs.interface_name),
             "pproxy%u", interface_id);

    rc = memif_create(&p->conn, &cargs,
                      on_connect, on_disconnect, on_interrupt, p);
    if (rc != MEMIF_ERR_SUCCESS) {
        PP_ERROR("memif: create(id=%u) failed: %s",
                 interface_id, memif_strerror(rc));
        memif_delete_socket(&p->socket);
        free(p);
        return PP_ERR_IO;
    }

    PP_INFO("memif: %s socket=%s id=%u ring=%u buf=%u",
            is_master ? "master" : "slave",
            socket_path, interface_id, p->ring_size, p->buffer_size);

    *out = p;
    return PP_OK;
}

void pp_memif_io_free(struct pp_memif_io *p)
{
    if (!p) return;
    if (p->conn)   memif_delete(&p->conn);
    if (p->socket) memif_delete_socket(&p->socket);
    free(p);
}

bool pp_memif_io_is_connected(const struct pp_memif_io *p)
{
    return p && p->is_connected;
}

void pp_memif_io_set_peer_mac(struct pp_memif_io *p, const uint8_t mac[6])
{
    if (p && mac) memcpy(p->dst_mac, mac, 6);
}

int pp_memif_io_inject_ip(struct pp_memif_io *p, const uint8_t *ip, size_t len)
{
    if (!p || !ip || len == 0) return PP_ERR_INVAL;
    if (!p->is_connected)      return PP_ERR_AGAIN;

    size_t total = PP_MEMIF_ETH_HDR + len;
    if (total > p->buffer_size) return PP_ERR_INVAL;

    memif_buffer_t buf;
    memset(&buf, 0, sizeof buf);
    uint16_t nalloced = 0;

    int rc = memif_buffer_alloc(p->conn, 0, &buf, 1, &nalloced, (uint32_t)total);
    if (rc != MEMIF_ERR_SUCCESS || nalloced == 0)
        return PP_ERR_AGAIN;   /* TX ring 满 */

    /* 构造 Ethernet 头：dst + src + ethertype 0x0800（IPv4） */
    uint8_t *frame = (uint8_t *)buf.data;
    memcpy(frame,     p->dst_mac, 6);
    memcpy(frame + 6, p->src_mac, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    memcpy(frame + PP_MEMIF_ETH_HDR, ip, len);
    buf.len = (uint32_t)total;

    uint16_t nsent = 0;
    rc = memif_tx_burst(p->conn, 0, &buf, 1, &nsent);
    if (rc != MEMIF_ERR_SUCCESS || nsent == 0)
        return PP_ERR_AGAIN;

    return PP_OK;
}

const uint8_t *pp_memif_io_next_ip(struct pp_memif_io *p, size_t *out_len)
{
    if (!p || !p->is_connected || !out_len) return NULL;

    /* burst 消费完：批量归还已消费槽，再取新 burst */
    if (p->rx_cur >= p->rx_count) {
        if (p->rx_count > 0)
            memif_refill_queue(p->conn, 0, p->rx_count, 0);
        p->rx_count = 0;
        p->rx_cur   = 0;
        int rc = memif_rx_burst(p->conn, 0,
                                p->rx_bufs, PP_MEMIF_BURST_MAX,
                                &p->rx_count);
        if (rc != MEMIF_ERR_SUCCESS || p->rx_count == 0)
            return NULL;
    }

    memif_buffer_t *b = &p->rx_bufs[p->rx_cur++];
    /* 跳过 Ethernet 头，仅返回 IP 帧 */
    if (b->len <= PP_MEMIF_ETH_HDR)
        return NULL;

    *out_len = b->len - PP_MEMIF_ETH_HDR;
    return (const uint8_t *)b->data + PP_MEMIF_ETH_HDR;
}

int pp_memif_io_poll(struct pp_memif_io *p, int timeout_us)
{
    if (!p) return PP_ERR_INVAL;
    int ms = (timeout_us > 0) ? (timeout_us / 1000) : 0;
    int rc = memif_poll_event(p->socket, ms);
    if (rc != MEMIF_ERR_SUCCESS && rc != MEMIF_ERR_AGAIN)
        return PP_ERR_IO;
    return PP_OK;
}

int pp_memif_io_get_fd(const struct pp_memif_io *p)
{
    (void)p;
    return -1;   /* busy-poll，无 epoll-able fd */
}

#endif /* PP_HAVE_MEMIF */
