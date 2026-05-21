/* tests/test_uring_sock.c -- io_uring UDP：copy / TX ZC */
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include "io/ks_sock.h"
#include "io/uring_sock.h"
#include "pproxy/log.h"

#define PORT 29400

static int udp_loopback(pp_uring_opts_t *opt, const char *tag)
{
    int sfd = -1, cfd = -1;
    pp_uring_sock_t *s_ur = NULL, *c_ur = NULL;

    if (pp_ks_udp_open(AF_INET, &sfd) != PP_OK) return 1;
    if (pp_ks_udp_open(AF_INET, &cfd) != PP_OK) return 1;

    struct sockaddr_in sin = {0};
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (pp_ks_udp_bind(sfd, (struct sockaddr *)&sin, sizeof sin) != PP_OK) return 1;
    if (pp_ks_udp_connect(cfd, (struct sockaddr *)&sin, sizeof sin) != PP_OK) return 1;

    if (pp_uring_sock_new(sfd, opt, &s_ur) != PP_OK ||
        pp_uring_sock_new(cfd, opt, &c_ur) != PP_OK) {
        printf("  %s: uring init fail\n", tag);
        return 1;
    }

    const char *msg = "uring-ping";
    int w = pp_uring_udp_send(c_ur, cfd, msg, strlen(msg), NULL, 0);
    if (w != (int)strlen(msg)) {
        printf("  %s: send fail w=%d\n", tag, w);
        return 1;
    }

    char buf[64] = {0};
    struct sockaddr_storage peer;
    socklen_t sl = sizeof peer;
    int r = pp_uring_udp_recv(s_ur, sfd, buf, sizeof buf - 1, (struct sockaddr *)&peer, &sl);
    if (r != (int)strlen(msg) || memcmp(buf, msg, strlen(msg)) != 0) {
        printf("  %s: recv mismatch r=%d buf='%s'\n", tag, r, buf);
        return 1;
    }

    pp_uring_sock_free(c_ur);
    pp_uring_sock_free(s_ur);
    close(cfd);
    close(sfd);
    printf("  %s OK\n", tag);
    return 0;
}

int main(void)
{
#ifndef PP_HAVE_IO_URING
    printf("SKIP: io_uring not enabled at build time\n");
    return 77;
#endif

    pp_uring_opts_t base;
    pp_uring_opts_defaults(&base, 64);

    printf("=== test_uring_sock copy ===\n");
    if (udp_loopback(&base, "copy") != 0) return 1;

    pp_uring_opts_t zc = base;
    zc.tx_zc = true;
    printf("=== test_uring_sock tx_zc ===\n");
    if (udp_loopback(&zc, "tx_zc") != 0) return 1;

    printf("=== test_uring_sock send_burst ===\n");
    {
        int sfd = -1, cfd = -1;
        pp_uring_sock_t *s_ur = NULL, *c_ur = NULL;

        if (pp_ks_udp_open(AF_INET, &sfd) != PP_OK) return 1;
        if (pp_ks_udp_open(AF_INET, &cfd) != PP_OK) return 1;

        struct sockaddr_in sin = {0};
        sin.sin_family = AF_INET;
        sin.sin_port = htons(PORT + 1);
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

        if (pp_ks_udp_bind(sfd, (struct sockaddr *)&sin, sizeof sin) != PP_OK) return 1;
        if (pp_ks_udp_connect(cfd, (struct sockaddr *)&sin, sizeof sin) != PP_OK) return 1;

        pp_uring_opts_t opt;
        pp_uring_opts_defaults(&opt, 128);
        if (pp_uring_sock_new(sfd, &opt, &s_ur) != PP_OK ||
            pp_uring_sock_new(cfd, &opt, &c_ur) != PP_OK) {
            printf("  send_burst: uring init fail\n");
            return 1;
        }

        enum { NBURST = 32 };
        char payloads[NBURST][16];
        pp_uring_send_item_t items[NBURST];
        int results[NBURST];
        for (int i = 0; i < NBURST; i++) {
            snprintf(payloads[i], sizeof payloads[i], "burst-%02d", i);
            items[i].buf     = payloads[i];
            items[i].len     = strlen(payloads[i]);
            items[i].peer    = NULL;
            items[i].peer_sl = 0;
        }

        if (pp_uring_udp_send_burst(c_ur, cfd, items, NBURST, results) != PP_OK) {
            printf("  send_burst: burst call fail\n");
            return 1;
        }
        for (int i = 0; i < NBURST; i++) {
            if (results[i] != (int)items[i].len) {
                printf("  send_burst: item %d result=%d want=%zu\n",
                       i, results[i], items[i].len);
                return 1;
            }
        }

        for (int i = 0; i < NBURST; i++) {
            char buf[32] = {0};
            struct sockaddr_storage peer;
            socklen_t sl = sizeof peer;
            int r = pp_uring_udp_recv(s_ur, sfd, buf, sizeof buf - 1,
                                      (struct sockaddr *)&peer, &sl);
            if (r <= 0) {
                printf("  send_burst: recv fail i=%d r=%d\n", i, r);
                return 1;
            }
            if (strncmp(buf, "burst-", 6) != 0) {
                printf("  send_burst: unexpected payload '%s'\n", buf);
                return 1;
            }
        }

        pp_uring_sock_free(c_ur);
        pp_uring_sock_free(s_ur);
        close(cfd);
        close(sfd);
        printf("  send_burst OK\n");
    }

    printf("test_uring_sock ALL OK\n");
    return 0;
}
