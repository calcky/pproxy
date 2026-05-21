/* tests/test_uring_sock.c -- io_uring UDP send/recv smoke（127.0.0.1） */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "io/ks_sock.h"
#include "io/uring_sock.h"
#include "pproxy/log.h"

#define PORT 29400

int main(void)
{
#ifndef PP_HAVE_IO_URING
    printf("SKIP: io_uring not enabled at build time\n");
    return 77;
#endif

    int sfd = -1, cfd = -1;
    pp_uring_sock_t *s_ur = NULL, *c_ur = NULL;

    if (pp_ks_udp_open(AF_INET, &sfd) != PP_OK) { printf("server open fail\n"); return 1; }
    if (pp_ks_udp_open(AF_INET, &cfd) != PP_OK) { printf("client open fail\n"); return 1; }

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (pp_ks_udp_bind(sfd, (struct sockaddr *)&sin, sizeof sin) != PP_OK) {
        printf("bind fail\n"); return 1;
    }

    if (pp_ks_udp_connect(cfd, (struct sockaddr *)&sin, sizeof sin) != PP_OK) {
        printf("connect fail\n"); return 1;
    }

    if (pp_uring_sock_new(sfd, 64, &s_ur) != PP_OK ||
        pp_uring_sock_new(cfd, 64, &c_ur) != PP_OK) {
        printf("uring init fail\n"); return 1;
    }

    const char *msg = "uring-ping";
    int w = pp_uring_udp_send(c_ur, cfd, msg, strlen(msg), NULL, 0);
    if (w != (int)strlen(msg)) {
        printf("send fail w=%d\n", w); return 1;
    }

    char buf[64] = {0};
    struct sockaddr_storage peer;
    socklen_t sl = sizeof peer;
    int r = pp_uring_udp_recv(s_ur, sfd, buf, sizeof buf - 1, (struct sockaddr *)&peer, &sl);
    if (r != (int)strlen(msg) || memcmp(buf, msg, strlen(msg)) != 0) {
        printf("recv mismatch r=%d buf='%s'\n", r, buf); return 1;
    }

    printf("test_uring_sock OK\n");
    pp_uring_sock_free(c_ur);
    pp_uring_sock_free(s_ur);
    close(cfd);
    close(sfd);
    return 0;
}
