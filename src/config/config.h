/*
 * src/config/config.h -- JSON 配置加载器
 *
 * 读取 `examples/config.example.json` 风格的配置文件，填充 pp_runtime_t。
 * 不涉及真实资源分配（mempool/ring/I/O 打开/session shard 创建）——
 * 这些仍然由 main.c 的 build_runtime_resources() 完成；
 * 本模块只负责"字符串 → C 结构体字段"的映射。
 *
 * 设计要点：
 *   - 缺失字段取默认值（与 build_default_runtime 一致），而不是报错
 *   - 未知字段发 PP_WARN，不中断加载
 *   - 不支持的字段（affinity、dpi.plugins[].enable、mgmt.metrics）
 *     先解析但未生效，会打 WARN 提示
 *   - 所有 JSON 内的字符串在调用 pp_config_load 返回后立即失效；
 *     loader 内部把需要持久化的字符串（ifname/name 等）strdup 到 rt 自己的 buf
 */
#ifndef PPROXY_CONFIG_H
#define PPROXY_CONFIG_H

#include "pproxy/pproxy.h"

#ifdef __cplusplus
extern "C" {
#endif

struct pp_runtime;

/* 从 JSON 文件加载配置到 rt。
 * 失败返回 PP_ERR_*；成功时 rt 中的 n_workers / left_cfg / tun_cfg[] 等字段已填好，
 * 但资源（pool / ring / io / tunnel ctx / session shards）尚未创建。 */
int pp_config_load(const char *path, struct pp_runtime *rt);

/* 释放 loader 内部 strdup 的字符串（main 退出时调用） */
void pp_config_free(struct pp_runtime *rt);

/* 热重载：在 rt 已经运行的情况下重新读取 JSON 文件，
 * 只把"可热切换的字段"原地应用到 rt（log.level / dpi.plugins[].enable /
 * session.*_ttl_ms），其它字段若与当前不同，追加 "requires restart" 说明。
 *
 * 参数：
 *   path    -- JSON 文件路径
 *   rt      -- 运行中的 runtime
 *   out     -- 人类可读的应用摘要缓冲区（mgmt 把它回给客户端）
 *   cap     -- out 的容量（含末尾 '\0'）
 *
 * 返回：
 *   PP_OK             -- 解析成功；out 中列出每一条处理结果
 *   PP_ERR_INVAL      -- 文件打不开 / JSON 解析失败
 *   PP_ERR_NOTFOUND   -- path 为 NULL 且 rt->cfg_path 也为空 */
int pp_config_reload(const char *path, struct pp_runtime *rt,
                     char *out, size_t cap);

#ifdef __cplusplus
}
#endif
#endif
