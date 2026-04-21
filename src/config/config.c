/*
 * src/config/config.c -- JSON 配置加载器（yyjson 后端）
 *
 * 只做"字符串 → C 结构体字段"映射；资源创建在 main.c 里。
 * 缺字段取 defaults；未知字段发 PP_WARN，不中断加载。
 */
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "yyjson.h"
#include "pproxy/pproxy.h"
#include "pproxy/log.h"
#include "pproxy/pkt_io.h"
#include "pproxy/tunnel.h"
#include "../modules/runtime.h"
#include "config.h"

/* ---------- 小工具 ---------- */

/* strdup 并挂到 rt 的字符串池里，由 pp_config_free 一次性释放。 */
static const char *dup_to_rt(pp_runtime_t *rt, const char *s)
{
    if (!s) return NULL;
    if (rt->cfg_strings_n == rt->cfg_strings_cap) {
        size_t ncap = rt->cfg_strings_cap ? rt->cfg_strings_cap * 2 : 16;
        char **nbuf = realloc(rt->cfg_strings, ncap * sizeof *nbuf);
        if (!nbuf) return NULL;
        rt->cfg_strings = nbuf;
        rt->cfg_strings_cap = ncap;
    }
    char *dup = strdup(s);
    if (!dup) return NULL;
    rt->cfg_strings[rt->cfg_strings_n++] = dup;
    return dup;
}

static const char *jstr(yyjson_val *obj, const char *key, const char *dflt)
{
    yyjson_val *v = yyjson_obj_get(obj, key);
    if (v && yyjson_is_str(v)) return yyjson_get_str(v);
    return dflt;
}

static int64_t jint(yyjson_val *obj, const char *key, int64_t dflt)
{
    yyjson_val *v = yyjson_obj_get(obj, key);
    if (!v) return dflt;
    if (yyjson_is_int(v) || yyjson_is_uint(v)) return yyjson_get_sint(v);
    if (yyjson_is_real(v)) return (int64_t)yyjson_get_real(v);
    return dflt;
}

static bool jbool(yyjson_val *obj, const char *key, bool dflt)
{
    yyjson_val *v = yyjson_obj_get(obj, key);
    if (v && yyjson_is_bool(v)) return yyjson_get_bool(v);
    return dflt;
}

/* 解析 endpoint。返回：
 *   PP_OK           —— 字段存在且解析成功
 *   PP_ERR_NOTFOUND —— 字段不存在（out 未改动）
 *   PP_ERR_INVAL    —— 字段存在但解析失败 */
static int jendpoint(yyjson_val *obj, const char *key, pp_endpoint_t *out)
{
    yyjson_val *v = yyjson_obj_get(obj, key);
    if (!v || !yyjson_is_str(v)) return PP_ERR_NOTFOUND;
    const char *s = yyjson_get_str(v);
    if (!s || !*s) return PP_ERR_NOTFOUND;
    return pp_endpoint_parse(s, out);
}

/* ---------- log ---------- */

static pp_log_level_t parse_log_level(const char *s)
{
    if (!s) return PP_LOG_INFO;
    if (!strcmp(s, "trace")) return PP_LOG_TRACE;
    if (!strcmp(s, "debug")) return PP_LOG_DEBUG;
    if (!strcmp(s, "info"))  return PP_LOG_INFO;
    if (!strcmp(s, "warn"))  return PP_LOG_WARN;
    if (!strcmp(s, "error")) return PP_LOG_ERROR;
    PP_WARN("config: unknown log.level '%s', fallback to info", s);
    return PP_LOG_INFO;
}

static void parse_log(yyjson_val *root)
{
    yyjson_val *log = yyjson_obj_get(root, "log");
    if (!log || !yyjson_is_obj(log)) return;
    pp_log_level_t lvl  = parse_log_level(jstr(log, "level", "info"));
    const char    *file = jstr(log, "file", NULL);
    pp_log_init(lvl, file);
    /* color 字段暂不生效；log.c 的配色靠 isatty(stderr) */
}

/* ---------- runtime ---------- */

static void parse_runtime(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *r = yyjson_obj_get(root, "runtime");
    if (!r || !yyjson_is_obj(r)) return;

    rt->n_workers = (int)jint(r, "workers", rt->n_workers);
    if (rt->n_workers < 1)             rt->n_workers = 1;
    if (rt->n_workers > PP_MAX_WORKERS) rt->n_workers = PP_MAX_WORKERS;

    yyjson_val *mp = yyjson_obj_get(r, "mempool");
    if (mp && yyjson_is_obj(mp)) {
        rt->mempool_cfg.nelem    = (size_t)jint(mp, "elements", (int64_t)rt->mempool_cfg.nelem);
        rt->mempool_cfg.buf_size = (size_t)jint(mp, "buf_size", (int64_t)rt->mempool_cfg.buf_size);
        rt->mempool_cfg.headroom = (uint16_t)jint(mp, "headroom", rt->mempool_cfg.headroom);
        rt->mempool_cfg.cpu      = (int)jint(mp, "cpu", rt->mempool_cfg.cpu);
    }

    yyjson_val *rg = yyjson_obj_get(r, "rings");
    if (rg && yyjson_is_obj(rg)) {
        rt->ring_cap_worker_rx   = (uint32_t)jint(rg, "worker_rx_capacity",   rt->ring_cap_worker_rx);
        rt->ring_cap_worker_back = (uint32_t)jint(rg, "worker_back_capacity", rt->ring_cap_worker_back);
        rt->ring_cap_worker_ctrl = (uint32_t)jint(rg, "worker_ctrl_capacity", rt->ring_cap_worker_ctrl);
        rt->ring_cap_right_tx    = (uint32_t)jint(rg, "right_tx_capacity",    rt->ring_cap_right_tx);
        rt->ring_cap_left_tx     = (uint32_t)jint(rg, "left_tx_capacity",     rt->ring_cap_left_tx);
    }
}

/* ---------- left（I/O 后端） ---------- */

static pp_io_kind_t parse_io_kind(const char *s, bool *ok)
{
    *ok = true;
    if (!s)                        { *ok = false; return PP_IO_TUN; }
    if (!strcmp(s, "tun"))         return PP_IO_TUN;
    if (!strcmp(s, "raw_socket"))  return PP_IO_RAW_SOCKET;
    if (!strcmp(s, "af_xdp"))      return PP_IO_AF_XDP;
    if (!strcmp(s, "netmap"))      return PP_IO_NETMAP;
    if (!strcmp(s, "pcap"))        return PP_IO_PCAP;
    *ok = false;
    return PP_IO_TUN;
}

static int parse_left(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *left = yyjson_obj_get(root, "left");
    if (!left || !yyjson_is_obj(left)) return PP_OK;

    const char *kind_s = jstr(left, "kind", "tun");
    bool ok = false;
    pp_io_kind_t kind = parse_io_kind(kind_s, &ok);
    if (!ok) {
        PP_ERROR("config: unknown left.kind '%s'", kind_s);
        return PP_ERR_INVAL;
    }
    rt->left_kind     = kind;
    rt->left_cfg.kind = kind;
    rt->left_cfg.name = dup_to_rt(rt, jstr(left, "name", "left0"));

    /* 按 kind 取对应子对象填 union */
    switch (kind) {
    case PP_IO_TUN: {
        yyjson_val *o = yyjson_obj_get(left, "tun");
        if (o && yyjson_is_obj(o)) {
            rt->left_cfg.u.tun.ifname = dup_to_rt(rt, jstr(o, "ifname", "pproxy0"));
            rt->left_cfg.u.tun.cidr   = dup_to_rt(rt, jstr(o, "cidr", NULL));
            rt->left_cfg.u.tun.mtu    = (uint16_t)jint(o, "mtu", 1500);
            rt->left_cfg.u.tun.no_pi  = jbool(o, "no_pi", true);
        }
        break;
    }
    case PP_IO_RAW_SOCKET: {
        yyjson_val *o = yyjson_obj_get(left, "raw");
        if (o && yyjson_is_obj(o)) {
            rt->left_cfg.u.raw.ifname  = dup_to_rt(rt, jstr(o, "ifname", "eth0"));
            rt->left_cfg.u.raw.snaplen = (uint16_t)jint(o, "snaplen", 2048);
            rt->left_cfg.u.raw.promisc = jbool(o, "promisc", false);
        }
        break;
    }
    case PP_IO_AF_XDP: {
        yyjson_val *o = yyjson_obj_get(left, "xdp");
        if (o && yyjson_is_obj(o)) {
            rt->left_cfg.u.xdp.ifname      = dup_to_rt(rt, jstr(o, "ifname", "eth0"));
            rt->left_cfg.u.xdp.queue_id    = (uint32_t)jint(o, "queue_id", 0);
            rt->left_cfg.u.xdp.nframes     = (uint32_t)jint(o, "nframes", 4096);
            rt->left_cfg.u.xdp.zero_copy   = jbool(o, "zero_copy", true);
            rt->left_cfg.u.xdp.need_wakeup = jbool(o, "need_wakeup", true);
            const char *mac = jstr(o, "peer_mac", NULL);
            if (mac && mac[0]) {
                unsigned m[6] = {0};
                if (sscanf(mac, "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++)
                        rt->left_cfg.u.xdp.peer_mac[i] = (uint8_t)m[i];
                    rt->left_cfg.u.xdp.has_peer_mac = true;
                } else {
                    PP_WARN("config: left.xdp.peer_mac='%s' invalid, ignored", mac);
                }
            }
        }
        break;
    }
    case PP_IO_NETMAP: {
        yyjson_val *o = yyjson_obj_get(left, "netmap");
        if (o && yyjson_is_obj(o)) {
            rt->left_cfg.u.netmap.ifname = dup_to_rt(rt, jstr(o, "ifname", "netmap:eth0"));
            rt->left_cfg.u.netmap.nrings = (uint32_t)jint(o, "nrings", 1);
        }
        break;
    }
    case PP_IO_PCAP: {
        yyjson_val *o = yyjson_obj_get(left, "pcap");
        if (o && yyjson_is_obj(o)) {
            rt->left_cfg.u.pcap.ifname      = dup_to_rt(rt, jstr(o, "ifname", "eth0"));
            rt->left_cfg.u.pcap.snaplen     = (uint16_t)jint(o, "snaplen", 2048);
            rt->left_cfg.u.pcap.buffer_size = (int)jint(o, "buffer_size", 4194304);
            rt->left_cfg.u.pcap.bpf         = dup_to_rt(rt, jstr(o, "bpf", NULL));
            const char *mac = jstr(o, "peer_mac", NULL);
            if (mac && mac[0]) {
                unsigned m[6] = {0};
                if (sscanf(mac, "%x:%x:%x:%x:%x:%x",
                           &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for (int i = 0; i < 6; i++)
                        rt->left_cfg.u.pcap.peer_mac[i] = (uint8_t)m[i];
                    rt->left_cfg.u.pcap.has_peer_mac = true;
                } else {
                    PP_WARN("config: left.pcap.peer_mac='%s' invalid, ignored", mac);
                }
            }
        }
        break;
    }
    }
    return PP_OK;
}

/* ---------- tunnels[] ---------- */

static pp_tunnel_proto_t parse_proto(const char *s, bool *ok)
{
    *ok = true;
    if (!s)                       { *ok = false; return PP_PROTO_TCP; }
    if (!strcmp(s, "tcp"))        return PP_PROTO_TCP;
    if (!strcmp(s, "udp"))        return PP_PROTO_UDP;
    if (!strcmp(s, "icmp"))       return PP_PROTO_ICMP;
    if (!strcmp(s, "kcp"))        return PP_PROTO_KCP;
    if (!strcmp(s, "quic"))       return PP_PROTO_QUIC;
    *ok = false;
    return PP_PROTO_TCP;
}

static pp_tunnel_io_t parse_tio(const char *s, bool *ok)
{
    *ok = true;
    if (!s)                              { *ok = false; return PP_TIO_KERNEL_SOCKET; }
    if (!strcmp(s, "kernel_socket"))     return PP_TIO_KERNEL_SOCKET;
    if (!strcmp(s, "raw_socket"))        return PP_TIO_RAW_SOCKET;
    if (!strcmp(s, "af_xdp"))            return PP_TIO_AF_XDP;
    if (!strcmp(s, "netmap"))            return PP_TIO_NETMAP;
    if (!strcmp(s, "pcap"))              return PP_TIO_PCAP;
    if (!strcmp(s, "tun"))               return PP_TIO_TUN;
    *ok = false;
    return PP_TIO_KERNEL_SOCKET;
}

static int parse_one_tunnel(yyjson_val *t, pp_tunnel_cfg_t *cfg, pp_runtime_t *rt)
{
    bool ok;
    cfg->proto = parse_proto(jstr(t, "proto", "tcp"), &ok);
    if (!ok) { PP_ERROR("config: unknown tunnel.proto"); return PP_ERR_INVAL; }

    cfg->io = parse_tio(jstr(t, "io", "kernel_socket"), &ok);
    if (!ok) { PP_ERROR("config: unknown tunnel.io"); return PP_ERR_INVAL; }

    cfg->name         = dup_to_rt(rt, jstr(t, "name", "tun0"));
    cfg->max_sessions = (uint32_t)jint(t, "max_sessions", 4096);
    cfg->keepalive_ms = (uint32_t)jint(t, "keepalive_ms", 30000);

    /* mode：client / server */
    const char *mode = jstr(t, "mode", "client");
    if (!strcmp(mode, "server"))      cfg->mode = PP_TMODE_SERVER;
    else if (!strcmp(mode, "client")) cfg->mode = PP_TMODE_CLIENT;
    else {
        PP_ERROR("config: unknown tunnel.mode '%s'", mode);
        return PP_ERR_INVAL;
    }

    /* client 必填 server；server 必填 listen */
    if (cfg->mode == PP_TMODE_CLIENT) {
        int r = jendpoint(t, "server", &cfg->server);
        if (r == PP_ERR_NOTFOUND) {
            PP_ERROR("config: client tunnel requires tunnel.server (host:port)");
            return PP_ERR_INVAL;
        }
        if (r != PP_OK) {
            PP_ERROR("config: invalid tunnel.server '%s'", jstr(t, "server", ""));
            return PP_ERR_INVAL;
        }
        (void)jendpoint(t, "bind", &cfg->bind);
    } else {
        int r = jendpoint(t, "listen", &cfg->listen);
        if (r == PP_ERR_NOTFOUND) {
            PP_ERROR("config: server tunnel requires tunnel.listen (host:port)");
            return PP_ERR_INVAL;
        }
        if (r != PP_OK) {
            PP_ERROR("config: invalid tunnel.listen '%s'", jstr(t, "listen", ""));
            return PP_ERR_INVAL;
        }
        /* server 也可选 server 字段（作为可打印的"预期 peer"，非必填） */
        (void)jendpoint(t, "server", &cfg->server);
    }

    /* 协议字段 */
    switch (cfg->proto) {
    case PP_PROTO_TCP: {
        yyjson_val *o = yyjson_obj_get(t, "tcp");
        cfg->u.tcp.nodelay      = jbool(o, "nodelay", true);
        cfg->u.tcp.reconnect_ms = (uint32_t)jint(o, "reconnect_ms", 2000);
        break;
    }
    case PP_PROTO_UDP: {
        yyjson_val *o = yyjson_obj_get(t, "udp");
        cfg->u.udp.mtu = (uint16_t)jint(o, "mtu", 1400);
        break;
    }
    case PP_PROTO_ICMP: {
        yyjson_val *o = yyjson_obj_get(t, "icmp");
        cfg->u.icmp.identifier_base = (uint16_t)jint(o, "identifier_base", 0);
        cfg->u.icmp.reply_only      = jbool(o, "reply_only", false);
        break;
    }
    default:
        PP_WARN("config: proto=%d (kcp/quic) not yet implemented", cfg->proto);
    }

    /* io 字段（仅 non-kernel_socket 用到） */
    yyjson_val *ioc = yyjson_obj_get(t, "io_cfg");
    if (ioc && yyjson_is_obj(ioc)) {
        switch (cfg->io) {
        case PP_TIO_RAW_SOCKET:
            cfg->io_cfg.raw.ifname = dup_to_rt(rt, jstr(ioc, "ifname", "eth0"));
            break;
        case PP_TIO_AF_XDP:
            cfg->io_cfg.xdp.ifname      = dup_to_rt(rt, jstr(ioc, "ifname", "eth0"));
            cfg->io_cfg.xdp.queue_id    = (uint32_t)jint(ioc, "queue_id", 0);
            cfg->io_cfg.xdp.nframes     = (uint32_t)jint(ioc, "nframes", 4096);
            cfg->io_cfg.xdp.zero_copy   = jbool(ioc, "zero_copy", true);
            cfg->io_cfg.xdp.need_wakeup = jbool(ioc, "need_wakeup", true);
            break;
        case PP_TIO_NETMAP:
            cfg->io_cfg.netmap.ifname = dup_to_rt(rt, jstr(ioc, "ifname", "netmap:eth0"));
            cfg->io_cfg.netmap.nrings = (uint32_t)jint(ioc, "nrings", 1);
            break;
        case PP_TIO_PCAP:
            cfg->io_cfg.pcap.ifname     = dup_to_rt(rt, jstr(ioc, "ifname", "eth0"));
            cfg->io_cfg.pcap.bpf_filter = dup_to_rt(rt, jstr(ioc, "bpf_filter", ""));
            cfg->io_cfg.pcap.snaplen    = (uint32_t)jint(ioc, "snaplen", 65535);
            break;
        case PP_TIO_TUN:
            cfg->io_cfg.tun.ifname = dup_to_rt(rt, jstr(ioc, "ifname", "pp-tx0"));
            break;
        case PP_TIO_KERNEL_SOCKET:
        default:
            break;
        }
    }
    return PP_OK;
}

static int parse_tunnels(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *arr = yyjson_obj_get(root, "tunnels");
    if (!arr || !yyjson_is_arr(arr)) return PP_OK;

    size_t n = yyjson_arr_size(arr);
    if (n == 0) return PP_OK;
    if (n > PP_MAX_TUNNELS) {
        PP_WARN("config: tunnels[%zu] capped to %d", n, PP_MAX_TUNNELS);
        n = PP_MAX_TUNNELS;
    }
    rt->n_tunnels = (int)n;

    size_t idx, max; yyjson_val *t;
    yyjson_arr_foreach(arr, idx, max, t) {
        if (idx >= n) break;
        int r = parse_one_tunnel(t, &rt->tun_cfg[idx], rt);
        if (r != PP_OK) return r;
    }
    /* 第一条的 proto 作为默认 tun_proto（历史兼容字段） */
    rt->tun_proto = rt->tun_cfg[0].proto;
    return PP_OK;
}

/* ---------- session ---------- */

static void parse_session(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *s = yyjson_obj_get(root, "session");
    if (!s || !yyjson_is_obj(s)) return;

    rt->session_max_per_shard = (size_t)jint(s, "max_per_shard", (int64_t)rt->session_max_per_shard);

    int64_t idle_ms = jint(s, "idle_ttl_ms", (int64_t)(rt->session_idle_ttl_ns / 1000000ULL));
    int64_t syn_ms  = jint(s, "syn_ttl_ms",  (int64_t)(rt->session_syn_ttl_ns  / 1000000ULL));
    int64_t fin_ms  = jint(s, "fin_ttl_ms",  (int64_t)(rt->session_fin_ttl_ns  / 1000000ULL));
    rt->session_idle_ttl_ns = (uint64_t)idle_ms * 1000000ULL;
    rt->session_syn_ttl_ns  = (uint64_t)syn_ms  * 1000000ULL;
    rt->session_fin_ttl_ns  = (uint64_t)fin_ms  * 1000000ULL;
    /* gc_interval_ms 暂由 timer 模块固定节拍，未生效 */
}

/* ---------- mgmt ---------- */

static void parse_mgmt(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *m = yyjson_obj_get(root, "mgmt");
    if (!m || !yyjson_is_obj(m)) return;
    const char *sock = jstr(m, "unix_socket", NULL);
    if (sock) rt->mgmt_unix_socket = dup_to_rt(rt, sock);

    yyjson_val *mt = yyjson_obj_get(m, "metrics");
    if (mt && yyjson_is_obj(mt)) {
        rt->metrics_enable = jbool(mt, "enable", false);
        int r = jendpoint(mt, "listen", &rt->metrics_listen);
        if (r == PP_OK) {
            rt->metrics_listen_set = true;
        } else if (r == PP_ERR_INVAL) {
            PP_WARN("config: mgmt.metrics.listen is invalid; disabling exporter");
            rt->metrics_enable = false;
        } else if (rt->metrics_enable) {
            PP_WARN("config: mgmt.metrics.enable=true but listen missing; "
                    "disabling exporter");
            rt->metrics_enable = false;
        }
    }
}

/* ---------- affinity ---------- */

/* 从数组拿第 i 个元素，存在则返回其整值，否则返回 dflt。 */
static int jarr_int(yyjson_val *arr, size_t i, int dflt)
{
    if (!arr || !yyjson_is_arr(arr)) return dflt;
    yyjson_val *v = yyjson_arr_get(arr, i);
    if (!v) return dflt;
    if (yyjson_is_int(v) || yyjson_is_uint(v)) return (int)yyjson_get_sint(v);
    return dflt;
}

static void parse_affinity(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *a = yyjson_obj_get(root, "affinity");
    if (!a || !yyjson_is_obj(a)) return;

    rt->affinity.left_rx = (int)jint(a, "left_rx", rt->affinity.left_rx);
    rt->affinity.left_tx = (int)jint(a, "left_tx", rt->affinity.left_tx);
    rt->affinity.timer   = (int)jint(a, "timer",   rt->affinity.timer);
    rt->affinity.mgmt    = (int)jint(a, "mgmt",    rt->affinity.mgmt);

    /* worker / right_tx / right_rx 为数组，按下标对齐 */
    yyjson_val *wk = yyjson_obj_get(a, "worker");
    for (int i = 0; i < rt->n_workers && i < PP_MAX_WORKERS; i++)
        rt->affinity.worker[i] = jarr_int(wk, (size_t)i, rt->affinity.worker[i]);

    yyjson_val *tx = yyjson_obj_get(a, "right_tx");
    yyjson_val *rx = yyjson_obj_get(a, "right_rx");
    for (int j = 0; j < rt->n_tunnels && j < PP_MAX_TUNNELS; j++) {
        rt->affinity.right_tx[j] = jarr_int(tx, (size_t)j, rt->affinity.right_tx[j]);
        rt->affinity.right_rx[j] = jarr_int(rx, (size_t)j, rt->affinity.right_rx[j]);
    }
}

/* ---------- dpi.plugins[] ---------- */

static void parse_dpi(yyjson_val *root, pp_runtime_t *rt)
{
    yyjson_val *d = yyjson_obj_get(root, "dpi");
    if (!d || !yyjson_is_obj(d)) return;
    yyjson_val *arr = yyjson_obj_get(d, "plugins");
    if (!arr || !yyjson_is_arr(arr)) return;

    size_t idx, max; yyjson_val *v;
    yyjson_arr_foreach(arr, idx, max, v) {
        if (rt->dpi_n_plugins >= PP_DPI_MAX_PLUGINS) {
            PP_WARN("config: dpi.plugins truncated to %d entries", PP_DPI_MAX_PLUGINS);
            break;
        }
        const char *name = jstr(v, "name", NULL);
        if (!name || !*name) {
            PP_WARN("config: dpi.plugins[%zu] missing name, skipped", idx);
            continue;
        }
        int slot = rt->dpi_n_plugins++;
        rt->dpi_plugins[slot].name   = dup_to_rt(rt, name);
        rt->dpi_plugins[slot].enable = jbool(v, "enable", true);

        yyjson_val *p = yyjson_obj_get(v, "priority");
        if (p && (yyjson_is_int(p) || yyjson_is_uint(p))) {
            rt->dpi_plugins[slot].has_priority = true;
            rt->dpi_plugins[slot].priority     = (int)yyjson_get_sint(p);
        }
    }
}

/* ---------- 未生效字段的友好提示 ---------- */

static void warn_unhandled(yyjson_val *root)
{
    (void)root;   /* 目前没有尚未接入的顶层字段 */
}

/* ---------- 入口 ---------- */

int pp_config_load(const char *path, pp_runtime_t *rt)
{
    if (!path || !rt) return PP_ERR_INVAL;

    yyjson_read_err err;
    yyjson_doc *doc = yyjson_read_file(path,
                                       YYJSON_READ_ALLOW_COMMENTS
                                       | YYJSON_READ_ALLOW_TRAILING_COMMAS,
                                       NULL, &err);
    if (!doc) {
        PP_ERROR("config: parse %s failed: %s (pos=%zu)", path, err.msg, err.pos);
        return PP_ERR_INVAL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        PP_ERROR("config: root must be an object");
        yyjson_doc_free(doc);
        return PP_ERR_INVAL;
    }

    parse_log(root);
    parse_runtime(root, rt);

    int r = parse_left(root, rt);
    if (r != PP_OK) { yyjson_doc_free(doc); return r; }

    r = parse_tunnels(root, rt);
    if (r != PP_OK) { yyjson_doc_free(doc); return r; }

    parse_session(root, rt);
    parse_mgmt(root, rt);
    parse_affinity(root, rt);
    parse_dpi(root, rt);
    warn_unhandled(root);

    yyjson_doc_free(doc);
    PP_INFO("config: loaded %s (workers=%d tunnels=%d left=%s)",
            path, rt->n_workers, rt->n_tunnels,
            rt->left_cfg.name ? rt->left_cfg.name : "?");
    return PP_OK;
}

void pp_config_free(pp_runtime_t *rt)
{
    if (!rt || !rt->cfg_strings) return;
    for (size_t i = 0; i < rt->cfg_strings_n; i++) free(rt->cfg_strings[i]);
    free(rt->cfg_strings);
    rt->cfg_strings = NULL;
    rt->cfg_strings_n = rt->cfg_strings_cap = 0;
}

/* ---------- 热重载 ---------- */

/* 向 out 追加一行；out_pos 会就地更新。超出 cap 时静默截断。 */
static void appendf(char *out, size_t cap, size_t *pos, const char *fmt, ...)
    __attribute__((format(printf, 4, 5)));
static void appendf(char *out, size_t cap, size_t *pos, const char *fmt, ...)
{
    if (!out || cap == 0 || *pos >= cap - 1) return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *pos, cap - *pos, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    *pos += (size_t)n;
    if (*pos >= cap) *pos = cap - 1;
}

int pp_config_reload(const char *path, pp_runtime_t *rt, char *out, size_t cap)
{
    if (!rt) return PP_ERR_INVAL;
    if (!path || !*path) path = rt->cfg_path;
    if (!path || !*path) {
        if (out && cap) snprintf(out, cap,
            "reload error: no config path (startup was not given -c)\n");
        return PP_ERR_NOTFOUND;
    }

    yyjson_read_err err;
    yyjson_doc *doc = yyjson_read_file(path,
                                       YYJSON_READ_ALLOW_COMMENTS
                                       | YYJSON_READ_ALLOW_TRAILING_COMMAS,
                                       NULL, &err);
    if (!doc) {
        if (out && cap) snprintf(out, cap,
            "reload error: parse %s failed: %s (pos=%zu)\n",
            path, err.msg, err.pos);
        return PP_ERR_INVAL;
    }
    yyjson_val *root = yyjson_doc_get_root(doc);
    if (!yyjson_is_obj(root)) {
        yyjson_doc_free(doc);
        if (out && cap) snprintf(out, cap, "reload error: root must be object\n");
        return PP_ERR_INVAL;
    }

    size_t pos = 0;
    int applied = 0, notes = 0;
    appendf(out, cap, &pos, "reload %s:\n", path);

    /* ---- log.level（热） ---- */
    yyjson_val *log = yyjson_obj_get(root, "log");
    if (log && yyjson_is_obj(log)) {
        const char *lvl_s = jstr(log, "level", NULL);
        if (lvl_s) {
            pp_log_level_t new_lvl = parse_log_level(lvl_s);
            pp_log_set_level(new_lvl);
            appendf(out, cap, &pos, "  applied log.level=%s\n", lvl_s);
            applied++;
        }
        if (yyjson_obj_get(log, "file")) {
            appendf(out, cap, &pos, "  note: log.file requires restart\n");
            notes++;
        }
    }

    /* ---- session.*_ttl_ms（热） ---- */
    yyjson_val *s = yyjson_obj_get(root, "session");
    if (s && yyjson_is_obj(s)) {
        yyjson_val *vi = yyjson_obj_get(s, "idle_ttl_ms");
        yyjson_val *vy = yyjson_obj_get(s, "syn_ttl_ms");
        yyjson_val *vf = yyjson_obj_get(s, "fin_ttl_ms");
        if (vi || vy || vf) {
            uint64_t idle = vi ? (uint64_t)jint(s, "idle_ttl_ms", 0) * 1000000ULL
                               : rt->session_idle_ttl_ns;
            uint64_t syn  = vy ? (uint64_t)jint(s, "syn_ttl_ms",  0) * 1000000ULL
                               : rt->session_syn_ttl_ns;
            uint64_t fin  = vf ? (uint64_t)jint(s, "fin_ttl_ms",  0) * 1000000ULL
                               : rt->session_fin_ttl_ns;
            rt->session_idle_ttl_ns = idle;
            rt->session_syn_ttl_ns  = syn;
            rt->session_fin_ttl_ns  = fin;
            for (int k = 0; k < rt->n_workers; k++) {
                if (rt->shards[k])
                    pp_session_shard_set_ttl(rt->shards[k], idle, syn, fin);
            }
            appendf(out, cap, &pos,
                "  applied session.ttl (idle=%llu syn=%llu fin=%llu ms)\n",
                (unsigned long long)(idle / 1000000ULL),
                (unsigned long long)(syn  / 1000000ULL),
                (unsigned long long)(fin  / 1000000ULL));
            applied++;
        }
        if (yyjson_obj_get(s, "max_per_shard")) {
            appendf(out, cap, &pos, "  note: session.max_per_shard requires restart\n");
            notes++;
        }
    }

    /* ---- dpi.plugins[].enable（热）；priority 变更提示重启 ---- */
    yyjson_val *d = yyjson_obj_get(root, "dpi");
    if (d && yyjson_is_obj(d)) {
        yyjson_val *arr = yyjson_obj_get(d, "plugins");
        if (arr && yyjson_is_arr(arr)) {
            size_t idx, mx; yyjson_val *v;
            yyjson_arr_foreach(arr, idx, mx, v) {
                const char *name = jstr(v, "name", NULL);
                if (!name) continue;

                yyjson_val *en = yyjson_obj_get(v, "enable");
                if (en && yyjson_is_bool(en)) {
                    bool e = yyjson_get_bool(en);
                    int r = pp_dpi_chain_set_enabled(rt->dpi, name, e);
                    if (r == PP_OK) {
                        appendf(out, cap, &pos,
                            "  applied dpi.%s.enable=%s\n",
                            name, e ? "true" : "false");
                        applied++;
                    } else {
                        appendf(out, cap, &pos,
                            "  note: dpi plugin '%s' not registered; ignored\n",
                            name);
                        notes++;
                    }
                }
                if (yyjson_obj_get(v, "priority")) {
                    appendf(out, cap, &pos,
                        "  note: dpi.%s.priority requires restart\n", name);
                    notes++;
                }
            }
        }
    }

    /* ---- 其它顶层字段：仅提示（不深入 diff） ---- */
    static const char *const cold_keys[] = {
        "runtime", "left", "tunnels", "mgmt", "affinity",
    };
    for (size_t i = 0; i < sizeof(cold_keys) / sizeof(cold_keys[0]); i++) {
        if (yyjson_obj_get(root, cold_keys[i])) {
            appendf(out, cap, &pos,
                "  note: '%s' section present; requires restart to take effect\n",
                cold_keys[i]);
            notes++;
        }
    }

    appendf(out, cap, &pos, "done: %d applied, %d notes\n", applied, notes);

    yyjson_doc_free(doc);
    PP_INFO("config: reload %s applied=%d notes=%d", path, applied, notes);
    return PP_OK;
}
