/* src/io/ks_sock.c -- kernel socket I/O 薄封装（见 .h） */
#include "ks_sock.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "pproxy/log.h"

/* ---------- endpoint 工具 ---------- */
socklen_t pp_ep_to_sockaddr(const pp_endpoint_t *ep, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof *ss);
    if (!ep) return 0;
    if (ep->addr.af == PP_AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
        s->sin6_family = AF_INET6;
        s->sin6_port   = htons(ep->port);
        s->sin6_addr   = ep->addr.u.v6;
        return sizeof *s;
    }
    struct sockaddr_in *s = (struct sockaddr_in *)ss;
    s->sin_family = AF_INET;
    s->sin_port   = htons(ep->port);
    s->sin_addr   = ep->addr.u.v4;
    return sizeof *s;
}

int pp_sockaddr_format(const struct sockaddr *sa, socklen_t sl,
                       char *out, size_t cap)
{
    if (!sa || cap == 0) return 0;
    char a[INET6_ADDRSTRLEN] = "";
    uint16_t port = 0;
    if (sa->sa_family == AF_INET && sl >= (socklen_t)sizeof(struct sockaddr_in)) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)sa;
        inet_ntop(AF_INET, &s->sin_addr, a, sizeof a);
        port = ntohs(s->sin_port);
    } else if (sa->sa_family == AF_INET6 && sl >= (socklen_t)sizeof(struct sockaddr_in6)) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)sa;
        inet_ntop(AF_INET6, &s->sin6_addr, a, sizeof a);
        port = ntohs(s->sin6_port);
    } else {
        return 0;
    }
    return snprintf(out, cap, "%s:%u", a, port);
}

/* ---------- sockopt ---------- */
void pp_ks_set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

void pp_ks_set_reuseaddr(int fd)
{
    int one = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
}

void pp_ks_set_tcp_nodelay(int fd, bool on)
{
    int v = on ? 1 : 0;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof v);
}

void pp_ks_bind_to_device(int fd, const char *ifname)
{
    if (!ifname || !ifname[0]) return;
    if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, strlen(ifname)) < 0)
        PP_WARN("SO_BINDTODEVICE(%s): %s", ifname, strerror(errno));
}

/* ---------- UDP ---------- */
int pp_ks_udp_open(int af, int *out_fd)
{
    int fd = socket(af, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        PP_ERROR("udp socket(%d): %s", af, strerror(errno));
        return PP_ERR_IO;
    }
    *out_fd = fd;
    return PP_OK;
}

int pp_ks_udp_bind(int fd, const struct sockaddr *sa, socklen_t sl)
{
    pp_ks_set_reuseaddr(fd);
    if (bind(fd, sa, sl) < 0) {
        PP_ERROR("udp bind: %s", strerror(errno));
        return PP_ERR_IO;
    }
    return PP_OK;
}

int pp_ks_udp_connect(int fd, const struct sockaddr *sa, socklen_t sl)
{
    if (connect(fd, sa, sl) < 0) {
        PP_ERROR("udp connect: %s", strerror(errno));
        return PP_ERR_IO;
    }
    return PP_OK;
}

int pp_ks_udp_send(int fd, const void *buf, size_t len,
                   const struct sockaddr *peer, socklen_t peer_sl)
{
    ssize_t w = peer ? sendto(fd, buf, len, 0, peer, peer_sl)
                     : send  (fd, buf, len, 0);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return PP_ERR_AGAIN;
        return PP_ERR_IO;
    }
    return (int)w;
}

int pp_ks_udp_recv(int fd, void *buf, size_t cap,
                   struct sockaddr *peer, socklen_t *peer_sl)
{
    ssize_t n = peer ? recvfrom(fd, buf, cap, 0, peer, peer_sl)
                     : recv    (fd, buf, cap, 0);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return PP_ERR_IO;
    }
    return (int)n;
}

/* ---------- TCP ---------- */
int pp_ks_tcp_listen(int af,
                     const struct sockaddr *sa, socklen_t sl,
                     int backlog, int *out_fd)
{
    int fd = socket(af, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        PP_ERROR("tcp socket: %s", strerror(errno));
        return PP_ERR_IO;
    }
    pp_ks_set_reuseaddr(fd);
    if (bind(fd, sa, sl) < 0) {
        PP_ERROR("tcp listen bind: %s", strerror(errno));
        close(fd);
        return PP_ERR_IO;
    }
    if (listen(fd, backlog ? backlog : 16) < 0) {
        PP_ERROR("tcp listen: %s", strerror(errno));
        close(fd);
        return PP_ERR_IO;
    }
    pp_ks_set_nonblock(fd);
    *out_fd = fd;
    return PP_OK;
}

int pp_ks_tcp_accept(int listen_fd,
                     struct sockaddr *peer, socklen_t *peer_sl,
                     int *out_fd)
{
    int fd = accept4(listen_fd, peer, peer_sl, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return PP_ERR_AGAIN;
        return PP_ERR_IO;
    }
    *out_fd = fd;
    return PP_OK;
}

int pp_ks_tcp_connect(int af,
                      const struct sockaddr *sa, socklen_t sl,
                      int *out_fd)
{
    int fd = socket(af, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        PP_ERROR("tcp socket: %s", strerror(errno));
        return PP_ERR_IO;
    }
    if (connect(fd, sa, sl) < 0) {
        PP_ERROR("tcp connect: %s", strerror(errno));
        close(fd);
        return PP_ERR_IO;
    }
    pp_ks_set_nonblock(fd);
    *out_fd = fd;
    return PP_OK;
}

int pp_ks_tcp_sendv(int fd, const struct iovec *iov, int iovcnt)
{
    ssize_t w = writev(fd, iov, iovcnt);
    if (w < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return PP_ERR_AGAIN;
        return PP_ERR_IO;
    }
    return (int)w;
}

int pp_ks_tcp_recv(int fd, void *buf, size_t cap)
{
    ssize_t n = read(fd, buf, cap);
    if (n == 0) return PP_ERR_CLOSED;
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return PP_ERR_IO;
    }
    return (int)n;
}
