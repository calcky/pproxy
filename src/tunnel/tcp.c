/* src/tunnel/tcp.c -- TCP tunnel 后端（proto 层）
 *
 * 只负责 TCP 隧道的 proto 语义：帧格式 + 服务端 accept 复位等。
 * 所有 socket / connect / accept / writev / read 的 syscall 都走 src/io/ks_sock。
 *
 * 简化协议（载荷格式）：
 *   [u64 sid][u16 len][payload ...]  循环
 *
 * 单连接复用所有 sid，应用层自己加帧头分包。
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include "pproxy/tunnel.h"
#include "pproxy/log.h"
#include "io/ks_sock.h"

#define TCP_FRAME_HDR  10  /* 8B sid + 2B len */
/* server：right_tx 里等 accept 时不可用 poll(listen,-1)，否则 right_rx 先 accept 后 listen 不再就绪，会永久阻塞 */
#define TCP_SERVER_WAIT_CONN_MS  100
/* EAGAIN 后等 POLLOUT：同用有界等待，避免 poll(,-1) 在 right_tx 线程里占死一条 syscall */
#define TCP_POLLOUT_WAIT_MS  TCP_SERVER_WAIT_CONN_MS
/* 单帧最大 10+65535；高吞吐时需容纳未完成帧 + 多帧尾巴，64K 在 iperf 时易满导致 read(0) 误判 */
#define TCP_RX_BUF     (256u * 1024u)

struct tcp_ctx {
    pp_tunnel_cfg_t  cfg;
    int              listen_fd;     /* server: 监听 fd；client: -1 */
    int              conn_fd;       /* 当前业务 fd；<0 表示未建立 */
    uint8_t          rxbuf[TCP_RX_BUF];
    size_t           rxlen;
};

static int tcp_open(const pp_tunnel_cfg_t *cfg, void **out_ctx)
{
    if (!cfg || cfg->proto != PP_PROTO_TCP) return PP_ERR_INVAL;
    if (cfg->io != PP_TIO_KERNEL_SOCKET) {
        PP_ERROR("tcp tunnel: only io=kernel_socket is supported, got io=%d", cfg->io);
        return PP_ERR_NOSUPPORT;
    }
    struct tcp_ctx *c = calloc(1, sizeof *c);
    if (!c) return PP_ERR_NOMEM;
    c->cfg       = *cfg;
    c->listen_fd = -1;
    c->conn_fd   = -1;
    *out_ctx = c;
    return PP_OK;
}

static void tcp_close(void *ctx)
{
    struct tcp_ctx *c = ctx;
    if (!c) return;
    if (c->conn_fd   >= 0) close(c->conn_fd);
    if (c->listen_fd >= 0) close(c->listen_fd);
    free(c);
}

/* client：connect；server：listen（不 accept） */
static int tcp_connect(void *ctx)
{
    struct tcp_ctx *c = ctx;

    if (c->cfg.mode == PP_TMODE_SERVER) {
        if (c->listen_fd >= 0) return PP_OK;
        int af = (c->cfg.listen.addr.af == PP_AF_INET6) ? AF_INET6 : AF_INET;
        struct sockaddr_storage ss;
        socklen_t sl = pp_ep_to_sockaddr(&c->cfg.listen, &ss);
        int rc = pp_ks_tcp_listen(af, (struct sockaddr *)&ss, sl, 16, &c->listen_fd);
        if (rc != PP_OK) return rc;
        char ep[64] = ""; pp_endpoint_format(&c->cfg.listen, ep, sizeof ep);
        PP_INFO("tcp tunnel listening on %s (fd=%d)", ep, c->listen_fd);
        return PP_OK;
    }

    /* client */
    if (c->conn_fd >= 0) return PP_OK;
    int af = (c->cfg.server.addr.af == PP_AF_INET6) ? AF_INET6 : AF_INET;
    struct sockaddr_storage ss;
    socklen_t sl = pp_ep_to_sockaddr(&c->cfg.server, &ss);
    int rc = pp_ks_tcp_connect(af, (struct sockaddr *)&ss, sl, &c->conn_fd);
    if (rc != PP_OK) return rc;
    pp_ks_set_tcp_nodelay(c->conn_fd, c->cfg.u.tcp.nodelay);
    PP_INFO("tcp tunnel connected (fd=%d)", c->conn_fd);
    return PP_OK;
}

/* server 模式：尝试 accept 一条；返回是否已接到 conn */
static bool server_try_accept(struct tcp_ctx *c)
{
    if (c->conn_fd >= 0) return true;
    if (c->listen_fd < 0) return false;

    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    int fd = -1;
    int rc = pp_ks_tcp_accept(c->listen_fd, (struct sockaddr *)&ss, &sl, &fd);
    if (rc != PP_OK) return false;
    pp_ks_set_tcp_nodelay(fd, c->cfg.u.tcp.nodelay);
    c->conn_fd = fd;
    c->rxlen   = 0;

    char ep[64] = "";
    pp_sockaddr_format((struct sockaddr *)&ss, sl, ep, sizeof ep);
    PP_INFO("tcp tunnel accepted conn from %s (fd=%d)", ep, c->conn_fd);
    return true;
}

/* 业务连接失效时复位（保留 listen_fd）；err=0 不打印 errno */
static void drop_conn_e(struct tcp_ctx *c, const char *why, int err)
{
    if (c->conn_fd >= 0) {
        if (err != 0)
            PP_WARN("tcp tunnel: conn lost (%s) errno=%d (%s); fd=%d closed", why, err,
                    strerror(err), c->conn_fd);
        else
            PP_WARN("tcp tunnel: conn lost (%s); fd=%d closed", why, c->conn_fd);
        close(c->conn_fd);
        c->conn_fd = -1;
    }
    c->rxlen = 0;
}
static void drop_conn(struct tcp_ctx *c, const char *why) { drop_conn_e(c, why, 0); }

/* 非阻塞 read 在 EAGAIN 时立即返回，若无 poll 则与 right_rx 形成紧循环、采样总落在 read() 上。 */
static int tcp_wait_readable(int fd, int timeout_ms)
{
    if (fd < 0) return -1;
    struct pollfd p = { .fd = fd, .events = POLLIN };
    return poll(&p, 1, timeout_ms);
}

/*
 * server 收路径拆成「只 accept」与「只读 conn」两段，避免混在同一循环里难排查。
 * 本段仅 listen/accept（及一次 poll listen），对 conn 不做 read。
 * 注意：若用 for(;;)+poll 可读 且 accept 仍失败（如 EMFILE），会 poll 立即返回、形成热转。
 * 故每轮「先试 accept → 至多阻塞等一次 → 再试 accept」，失败则返回 0 由上层下轮再进。
 * 返回：1=已有 conn；0=本周期无新连接； -1=无 listen；-2=poll 错误。
 */
static int server_ensure_connected(struct tcp_ctx *c, int tmo_ms)
{
    if (c->conn_fd >= 0) return 1;
    if (c->cfg.mode != PP_TMODE_SERVER) return c->conn_fd >= 0 ? 1 : -1;
    if (c->listen_fd < 0) return -1;

    if (server_try_accept(c)) return 1;
    if (c->conn_fd >= 0) return 1;

    int acc_ms = (tmo_ms < 0) ? TCP_SERVER_WAIT_CONN_MS : tmo_ms;
    int pr     = tcp_wait_readable(c->listen_fd, acc_ms);
    if (pr < 0) return -2;
    if (pr == 0) return 0;

    if (server_try_accept(c)) return 1;
    if (c->conn_fd >= 0) return 1;
    return 0;
}

/* 仅 conn_fd 已就绪：组帧 + read(conn)，不碰 listen_fd */
static int tcp_conn_recv(struct tcp_ctx *c, uint64_t *out_sid, pp_tun_mbuf_t *out_buf, int tmo_ms)
{
    for (;;) {
        if (c->conn_fd < 0) return PP_ERR_CLOSED;

        if (c->rxlen >= (size_t)TCP_FRAME_HDR) {
            uint64_t sid;
            uint16_t len;
            memcpy(&sid, c->rxbuf, 8);
            sid = be64toh(sid);
            memcpy(&len, c->rxbuf + 8, 2);
            len = ntohs(len);
            if (c->rxlen < (size_t)TCP_FRAME_HDR + len) {
                /* 缺尾，下面对 conn read */
            } else {
                if (out_buf->cap < len) return PP_ERR_NOMEM;
                memcpy(out_buf->data, c->rxbuf + TCP_FRAME_HDR, len);
                out_buf->len  = len;
                *out_sid = sid;
                size_t consumed = (size_t)TCP_FRAME_HDR + len;
                memmove(c->rxbuf, c->rxbuf + consumed, c->rxlen - consumed);
                c->rxlen -= consumed;
                return (int)len;
            }
        }

        size_t room = sizeof c->rxbuf - c->rxlen;
        if (room == 0) {
            PP_WARN("tcp tunnel: rx buffer full (rxlen=%zu) incomplete frame, closing", c->rxlen);
            drop_conn(c, "rx buffer full");
            return PP_ERR_IO;
        }
        int n = pp_ks_tcp_recv(c->conn_fd, c->rxbuf + c->rxlen, room);
        if (n == PP_ERR_CLOSED) {
            drop_conn(c, "peer closed");
            return 0;
        }
        if (n == PP_ERR_IO) {
            int e = errno;
            drop_conn_e(c, "recv error", e);
            return PP_ERR_IO;
        }
        if (n > 0) {
            c->rxlen += (size_t)n;
            continue;
        }
        if (tcp_wait_readable(c->conn_fd, tmo_ms) <= 0) return 0;
    }
}

static int tcp_send(void *ctx, uint64_t sid, const pp_tun_buf_t *buf)
{
    struct tcp_ctx *c = ctx;
    if (buf->len > 65535) return PP_ERR_INVAL;

    uint8_t hdr[TCP_FRAME_HDR];
    uint64_t sid_be = htobe64(sid);
    uint16_t len_be = htons((uint16_t)buf->len);
    memcpy(hdr,     &sid_be, 8);
    memcpy(hdr + 8, &len_be, 2);

    struct iovec iov[2] = {
        { hdr, sizeof hdr },
        { (void *)buf->data, buf->len },
    };

    /* 非阻塞 writev 遇 EAGAIN 时不可向 right_tx 抛 PP_ERR_AGAIN，否则对端背压会当 drop 丢包。
     * 在 tunnel 内 poll 到可写/可接受连接后再重发整帧。
     * server：conn 可能由 right_rx 的 tcp_recv→server_try_accept 建立，须定期醒转以发现 conn_fd。 */
    for (;;) {
        if (c->cfg.mode == PP_TMODE_SERVER && c->conn_fd < 0) {
            if (!server_try_accept(c)) {
                if (c->listen_fd < 0) return PP_ERR_CLOSED;
                /* 另一线程可能已 accept，勿在 listen 上无限阻塞 */
                if (c->conn_fd >= 0) continue;
                struct pollfd p = { .fd = c->listen_fd, .events = POLLIN };
                if (poll(&p, 1, TCP_SERVER_WAIT_CONN_MS) < 0) return PP_ERR_IO;
                continue;
            }
        }
        if (c->conn_fd < 0) return PP_ERR_CLOSED;

        int w = pp_ks_tcp_sendv(c->conn_fd, iov, 2);
        if (w == PP_ERR_AGAIN) {
            struct pollfd p = { .fd = c->conn_fd, .events = POLLOUT };
            if (poll(&p, 1, TCP_POLLOUT_WAIT_MS) < 0) return PP_ERR_IO;
            continue; /* 超时也继续重试 writev，不向上抛 PP_ERR_AGAIN（见上注释） */
        }
        if (w < 0) {
            int e = errno;
            drop_conn_e(c, "send error", e);
            return PP_ERR_IO;
        }
        return w;
    }
}

static int tcp_recv(void *ctx, uint64_t *out_sid, pp_tun_mbuf_t *out_buf, int timeout_us)
{
    struct tcp_ctx *c  = ctx;
    int tmo_ms = (timeout_us < 0) ? -1 : (int)((unsigned)(timeout_us + 999) / 1000);

    for (;;) {
        if (c->conn_fd < 0) {
            if (c->cfg.mode == PP_TMODE_SERVER) {
                int sc = server_ensure_connected(c, tmo_ms);
                if (sc == 0) return 0;
                if (sc == -1) return 0; /* 无 listen，与历史行为一致可改为 PP_ERR_CLOSED */
                if (sc == -2) return PP_ERR_IO;
            } else
                return PP_ERR_CLOSED;
        }
        if (c->conn_fd < 0) return PP_ERR_CLOSED;

        int r = tcp_conn_recv(c, out_sid, out_buf, tmo_ms);
        if (r == PP_ERR_NOMEM) return r;
        if (r == PP_ERR_IO) return r;
        return r; /* >0 一帧; 0 本周期无完整帧/对端关/EAGAIN */
    }
}

static void tcp_session_close(void *ctx, uint64_t sid) { (void)ctx; (void)sid; }
static int  tcp_get_fd(void *ctx)
{
    struct tcp_ctx *c = ctx;
    return c->conn_fd >= 0 ? c->conn_fd : c->listen_fd;
}
static int  tcp_stat(void *ctx, char *json, size_t cap)
{
    struct tcp_ctx *c = ctx;
    return snprintf(json, cap,
        "{\"backend\":\"tcp\",\"mode\":\"%s\",\"listen_fd\":%d,\"conn_fd\":%d}",
        c->cfg.mode == PP_TMODE_SERVER ? "server" : "client",
        c->listen_fd, c->conn_fd);
}

const pp_tunnel_ops_t pp_tunnel_tcp = {
    .name = "tcp", .proto = PP_PROTO_TCP,
    .supported_io_mask = PP_TIO_MASK_KERNEL_SOCKET,
    .caps = PP_TUN_CAP_RELIABLE | PP_TUN_CAP_MUX,
    .open = tcp_open, .close = tcp_close,
    .connect = tcp_connect, .send = tcp_send, .recv = tcp_recv,
    .session_close = tcp_session_close,
    .get_rx_fd = tcp_get_fd, .get_tx_fd = tcp_get_fd,
    .stat = tcp_stat,
};
