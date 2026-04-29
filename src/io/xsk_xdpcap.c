/* xsk_xdpcap.c -- 加载自编译 xsk_xdpcap.bpf.o，attach XDP、INHIBIT libxdp 内建程序、写 xsks_map、pin xdpcap_hook */
#ifdef PP_HAVE_XDP

#include "xsk_xdpcap.h"
#include "pproxy/log.h"
#include "pproxy/pproxy.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>
#include <xdp/xsk.h>
#include "xsk_i.h"

#ifndef XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD
#define XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD (1U << 1)
#endif

/* 须与 bpf/xsk_xdpcap.bpf.c 中 xdpcap_hook.max_entries 及 xdpcap HookMapABI 一致（见 xdpcap internal） */
#ifndef HOOK_MAP_MAX_ENTRIES
#define HOOK_MAP_MAX_ENTRIES 4
#endif

static uint32_t xdpcap_env_xdp_flags(void)
{
    const char *e = getenv("PPROXY_XDPCAP_SKB");
    if (e && e[0] == '1' && e[1] == '\0')
        return XDP_FLAGS_SKB_MODE;
    return 0;
}

static void bump_memlock(void)
{
    struct rlimit l = { RLIM_INFINITY, RLIM_INFINITY };
    (void)setrlimit(RLIMIT_MEMLOCK, &l);
}

static void sanitize_for_pin(const char *ifname, char *buf, size_t n)
{
    size_t j = 0;
    for (size_t i = 0; ifname[i] && j + 1 < n; i++) {
        unsigned char c = (unsigned char)ifname[i];
        if (c == '/' || c == '\0' || c == '.')
            buf[j++] = '_';
        else
            buf[j++] = (char)c;
    }
    buf[j] = '\0';
}

void pp_xdpcap_cleanup(struct pp_xsk_io *p)
{
    if (!p || !p->xdpcap_obj) return;

    if (p->xsk) {
        (void)xsk_socket__delete(p->xsk);
        p->xsk = NULL;
    }
    p->fd = -1;

    if (p->xdpcap_ifindex) {
        struct bpf_xdp_attach_opts xo = {};
        xo.sz = sizeof(xo);
        (void)bpf_xdp_detach((int)p->xdpcap_ifindex, p->xdpcap_xdp_flags, &xo);
        p->xdpcap_ifindex = 0;
    }

    if (p->xdpcap_link) {
        struct bpf_link *lk = p->xdpcap_link;
        p->xdpcap_link = NULL;
        (void)bpf_link__destroy(lk);
    }

    if (p->xdpcap_pin[0]) {
        (void)unlink(p->xdpcap_pin);
        p->xdpcap_pin[0] = '\0';
    }

    struct bpf_object *obj = p->xdpcap_obj;
    p->xdpcap_obj = NULL;
    bpf_object__close(obj);
}

int pp_xdpcap_xsk_create(struct pp_xsk_io *p,
                        const char *bpf_object_path,
                        bool zero_copy,
                        bool need_wakeup)
{
    if (!p || !bpf_object_path || !bpf_object_path[0]) return PP_ERR_INVAL;

    bump_memlock();

    struct bpf_map_create_opts mopts = {};
    mopts.sz = sizeof(mopts);
    int hook_fd = bpf_map_create(BPF_MAP_TYPE_PROG_ARRAY, "xdpcap_hook",
                                (int)sizeof(int), (int)sizeof(int),
                                HOOK_MAP_MAX_ENTRIES, &mopts);
    if (hook_fd < 0) {
        PP_ERROR("xdpcap: bpf_map_create hook map: %s", strerror(-hook_fd));
        return PP_ERR_IO;
    }

    struct bpf_object *obj = bpf_object__open_file(bpf_object_path, NULL);
    if (!obj) {
        PP_ERROR("xdpcap: bpf_object__open_file(%s) failed: %s",
                 bpf_object_path, strerror(errno));
        (void)close(hook_fd);
        return PP_ERR_IO;
    }
    p->xdpcap_obj = obj;

    struct bpf_map *m_xsks  = bpf_object__find_map_by_name(obj, "xsks_map");
    struct bpf_map *m_hook  = bpf_object__find_map_by_name(obj, "xdpcap_hook");
    struct bpf_map *m_filt  = bpf_object__find_map_by_name(obj, "pproxy_xsk_filt_map");
    if (!m_xsks || !m_hook || !m_filt) {
        PP_ERROR("xdpcap: missing xsks_map, xdpcap_hook or pproxy_xsk_filt_map in %s",
                 bpf_object_path);
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        (void)close(hook_fd);
        return PP_ERR_IO;
    }

    int rfd = bpf_map__reuse_fd(m_hook, hook_fd);
    if (rfd != 0) {
        PP_ERROR("xdpcap: bpf_map__reuse_fd: %s", strerror(-rfd));
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        (void)close(hook_fd);
        return PP_ERR_IO;
    }

    __u32 need = p->queue_id + 1;
    __u32 max = 64;
    if (need > 64) {
        for (max = 128; max < need && max < 0x7fff; max *= 2)
            ;
    }
    if (need > max) {
        PP_ERROR("xdpcap: queue_id %u too large for xsks_map (max %u)", p->queue_id, max);
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }
    (void)bpf_map__set_max_entries(m_xsks, max);

    if (bpf_object__load(obj) != 0) {
        PP_ERROR("xdpcap: bpf_object__load failed: %s", strerror(errno));
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_hook");
    if (!prog) {
        PP_ERROR("xdpcap: no program xdp_hook in %s", bpf_object_path);
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }

    unsigned int ifi = if_nametoindex(p->ifname);
    if (ifi == 0) {
        PP_ERROR("xdpcap: if_nametoindex(%s): %s", p->ifname, strerror(errno));
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }

    struct bpf_xdp_attach_opts xopts = {};
    xopts.sz = sizeof(xopts);
    uint32_t xdp_flags = xdpcap_env_xdp_flags();

    int err = bpf_xdp_attach((int)ifi, bpf_program__fd(prog), xdp_flags, &xopts);
    if (err) {
        PP_ERROR("xdpcap: AttachXDP on %s: %s "
                 "(hint: native/driver XDP may fail on some NICs or VMs)",
                 p->ifname, strerror(-err));
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }
    p->xdpcap_ifindex = ifi;
    p->xdpcap_xdp_flags = xdp_flags;

    char safe[IFNAMSIZ];
    sanitize_for_pin(p->ifname, safe, sizeof safe);
    (void)snprintf(p->xdpcap_pin, sizeof p->xdpcap_pin,
                  "/sys/fs/bpf/pproxy_xdpcap_%s", safe);

    (void)unlink(p->xdpcap_pin);
    if (bpf_map__pin(m_hook, p->xdpcap_pin) != 0) {
        PP_ERROR("xdpcap: bpf_map__pin(hook) -> %s: %s (bpffs mounted?)",
                 p->xdpcap_pin, strerror(errno));
        struct bpf_xdp_attach_opts xo = {};
        xo.sz = sizeof(xo);
        (void)bpf_xdp_detach((int)ifi, xdp_flags, &xo);
        p->xdpcap_ifindex = 0;
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }

    struct xsk_socket_config scfg = {
        .rx_size = XSK_RING_CONS__DEFAULT_NUM_DESCS,
        .tx_size = XSK_RING_PROD__DEFAULT_NUM_DESCS,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags    = 0,
        .bind_flags   = (uint16_t)((zero_copy   ? XDP_ZEROCOPY : XDP_COPY) |
                                   (need_wakeup ? XDP_USE_NEED_WAKEUP : 0)),
    };

    int xrc = xsk_socket__create(&p->xsk, p->ifname, p->queue_id, p->umem,
                                    &p->rx, &p->tx, &scfg);
    if (xrc) {
        PP_ERROR("xsk_socket__create(%s) inhibit: %s", p->ifname, strerror(-xrc));
        p->xsk = NULL;
        (void)unlink(p->xdpcap_pin);
        p->xdpcap_pin[0] = '\0';
        {
            struct bpf_xdp_attach_opts xo = {};
            xo.sz = sizeof(xo);
            (void)bpf_xdp_detach((int)ifi, xdp_flags, &xo);
        }
        p->xdpcap_ifindex = 0;
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }
    p->fd = xsk_socket__fd(p->xsk);

    int xsks_fd = bpf_map__fd(m_xsks);
    __u32 k = p->queue_id;
    int xsk_fd = p->fd;
    __u32 ufd = (__u32)xsk_fd;
    if (bpf_map_update_elem(xsks_fd, &k, &ufd, BPF_ANY) != 0) {
        PP_ERROR("xdpcap: xsks_map update q=%u: %s", p->queue_id, strerror(errno));
        (void)xsk_socket__delete(p->xsk);
        p->xsk = NULL;
        p->fd = -1;
        (void)unlink(p->xdpcap_pin);
        p->xdpcap_pin[0] = '\0';
        {
            struct bpf_xdp_attach_opts xo = {};
            xo.sz = sizeof(xo);
            (void)bpf_xdp_detach((int)ifi, xdp_flags, &xo);
        }
        p->xdpcap_ifindex = 0;
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }

    __u32 fkey = 0;
    if (bpf_map__update_elem(m_filt, &fkey, sizeof fkey, &p->xdp_filt,
                             sizeof(p->xdp_filt), BPF_ANY) != 0) {
        PP_ERROR("xdpcap: pproxy_xsk_filt_map update: %s", strerror(errno));
        (void)xsk_socket__delete(p->xsk);
        p->xsk = NULL;
        p->fd = -1;
        (void)unlink(p->xdpcap_pin);
        p->xdpcap_pin[0] = '\0';
        {
            struct bpf_xdp_attach_opts xo = {};
            xo.sz = sizeof(xo);
            (void)bpf_xdp_detach((int)ifi, xdp_flags, &xo);
        }
        p->xdpcap_ifindex = 0;
        p->xdpcap_obj = NULL;
        bpf_object__close(obj);
        return PP_ERR_IO;
    }

    PP_INFO("xdpcap: PPROXY XDP on %s q=%u, hook pin: %s",
            p->ifname, p->queue_id, p->xdpcap_pin);
    return PP_OK;
}

#endif /* PP_HAVE_XDP */
