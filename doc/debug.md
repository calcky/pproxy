# pproxy 常用调试命令

本地或 lab 里排障时按需执行；端口、路径以你的 `json` 为准（以下为 clab 默认例）。

## 日志

```bash
# 看最近输出
tail -f /opt/pproxy/log/pp1.log
tail -f /opt/pproxy/log/pp2.log

# 提高详细度：配置里 "log": { "level": "debug" } 后重启进程
```

## Prometheus 指标（HTTP）

`pp1.json` 里常见 `127.0.0.1:19991`，`pp2` 常见 `19992`。

```bash
# 各模块收/发/丢包（left_rx / worker0 / right_tx0 / right_rx0 / left_tx 等）
curl -s http://127.0.0.1:19991/metrics | grep -E 'pp_module_(events|drops)'

# 持续对比（数字应随业务增长；drops 长期为 0 较健康）
watch -n1 'curl -s http://127.0.0.1:19992/metrics | grep pp_module_'
```

含义简要：

- `left_rx`：从 TUN 读入
- `right_rx0`：从隧道收
- `worker0`：worker 处理条数（含左环 + 右环）
- `right_tx0`：往隧道发；`drops` 为 `send` 返回真错。TCP 隧道曾把 **可恢复** 的 `EAGAIN`（对端发窗满）当 drop；现于 `src/tunnel/tcp.c` 内 `poll` 可写/可 `accept` 后重发整帧，背压时不再误涨
- `left_tx`：写回 TUN
- `pp_module_drops{module="worker0"}`：解析失败、会话表满、环满等会涨

## Unix 管理套接字（文本命令）

配置项 `mgmt.unix_socket`，clab 默认：`/opt/pproxy/run/pp.sock`。

`deploy.sh` 会把 `pproxy-ctl` 装到 leaf VM 的 `/usr/local/bin/pproxy-ctl`，比手写 `nc` 方便：

```bash
pproxy-ctl stat
pproxy-ctl sessions
pproxy-ctl help
# 自定义 sock：PPROXY_SOCK=/path/to.sock pproxy-ctl stat
```

等价于：

```bash
echo stat     | sudo nc -U /opt/pproxy/run/pp.sock
echo sessions | sudo nc -U /opt/pproxy/run/pp.sock
echo help     | sudo nc -U /opt/pproxy/run/pp.sock
```

## 路由与 TUN（导流是否进 ppclab*）

```bash
# 发往对端网段时是否走本机 TUN（例：leaf1 上去 192.168.1.x）
ip route get 192.168.1.2
ip -br a
ip route show | head -20
```

## TCP 隧道是否通

`pp1` 监听、对端 `server` 应对准 **leaf1 的 WAN IP:隧道端口**（例 `172.16.0.2:19900`）。

```bash
# leaf1：监听
ss -ltn | grep 19900

# leaf2：到对端的已建连（本机源端口随机，筛对端）
ss -tn | grep '172.16.0.2:19900'
```

## 抓内层包（确认进 TUN 的 IP）

```bash
sudo tcpdump -i ppclab1 -n -c 30
```

## clab / SSH 上快速一组

在**能 ssh 到 leaf** 的环境（见 `tests/clab/deploy.sh` 里 `LEAF1_WAN_IP`、端口与 `pp2.json` 中 `tunnels[0].server` 保持一致）：

```bash
ssh clab@leaf1 'ip route get 192.168.1.2; tail -n 20 /opt/pproxy/log/pp1.log'
ssh clab@leaf2 'ip route get 192.168.0.2; tail -n 20 /opt/pproxy/log/pp2.log'
```

## Core 文件（segfault 后用 gdb 分析）

在 **clab 里**：**`./tests/clab/deploy.sh` 默认即启用**（`PPROXY_COREDUMP=1`），会在各 leaf VM 上设置 `kernel.core_pattern` 为 `/opt/pproxy/core-%e-%p-%t` 且 **`nohup` 前 `ulimit -c unlimited`**，见 `deploy.sh` 中 `pproxy_coredump_setup` / 头注释。不需要时设 **`PPROXY_COREDUMP=0`**。

手动调试时，在**运行 pproxy 的 shell** 里或启动脚本**同一行**先放开核心限制，并指定**生成路径为 `/opt/pproxy`**（需 **root** 写内核参数；进程若以 **sudo** 起，core 会按 root 的 `cwd`/pattern 走）。

**1. 目录与权限**

```bash
sudo install -d -m 0755 -o root -g root /opt/pproxy
```

**2. 本会话允许写 core（若用 `deploy.sh` / `nohup`，在写 `nohup` 的 shell 里先执行）**

```bash
ulimit -c unlimited
# 可选：看当前软限制
# ulimit -a | grep core
```

**3. 指定 core 落盘到 `/opt/pproxy`（重启后失效，可改用下面 4. 持久化）**

先看重定向方式（**若以 `|` 开头**，说明被 **apport** 等接走，需改成文件路径**或**关 apport 再试）：

```bash
cat /proc/sys/kernel/core_pattern
```

改为写到目录（`%e` 可执行名、`%p` pid、`%t` 时间戳，防覆盖）：

```bash
echo '/opt/pproxy/core-%e-%p-%t' | sudo tee /proc/sys/kernel/core_pattern
# 同效果（一行）
# sudo sysctl -w kernel.core_pattern=/opt/pproxy/core-%e-%p-%t
```

**4. 持久化（可选）**

```bash
echo 'kernel.core_pattern=/opt/pproxy/core-%e-%p-%t' | sudo tee /etc/sysctl.d/60-pproxy-coredump.conf
sudo sysctl -p /etc/sysctl.d/60-pproxy-coredump.conf
```

若仍无文件：看 **`dmesg`** 里 `core_pattern` 是否被 **systemd-coredump** 接管，此时可用 **`coredumpctl gdb`** 取 core；**WSL/容器** 对 core 也常有额外限制。

**5. 用 gdb 打开**

```bash
gdb -q /opt/pproxy/pproxy /opt/pproxy/core-pproxy-12345-...
(gdb) bt full
```

## VSCode + gdbserver 联调（leaf1 / leaf2）

1. **带符号构建并部署**（与线上一致）：`./tests/clab/deploy.sh` 已默认 `--debug` 编译并拷贝 `build/pproxy` → 各 leaf 的 `/opt/pproxy/pproxy`。本机保留同一次构建的 `build/pproxy`，供 VSCode 找符号。若希望**部署时**即在各 VM 上用 **`gdbserver` 起 pproxy**（绑定 `127.0.0.1:2345` / `2346`），可 **`./tests/clab/deploy.sh --gdb`** 或 **`PPROXY_GDB=1 ./tests/clab/deploy.sh`**；此时会**跳过**需进程已跑起来的 metrics 自动检查（gdbserver 会等远程调试器再往下执行）。仅跑传统 **`nohup`**：`--no-gdb` 或 **`PPROXY_GDB=0`**。
2. **SSH 端口转发**（本机 `localhost:2345` / `2346` 对应各 VM 上 `gdbserver`）：
   - **`./tests/clab/deploy.sh --gdb`** 结束后会**自动**跑 **`gdb-tunnel.sh`**（除非 `--no-gdb-tunnel` / `PPROXY_GDB_TUNNEL=0`）；非 `--gdb` 也可单独要隧道：`--gdb-tunnel` 或 `PPROXY_GDB_TUNNEL=1`。  
   - 手动：`./tests/clab/gdb-tunnel.sh`（与 `deploy.sh` 相同 `clab@leaf1` / `leaf2`、密码可用 `CLAB_SSH_PASS` 覆盖）；结束用 `./tests/clab/gdb-tunnel.sh stop`。
   - 或手动两条 `ssh -L 2345:127.0.0.1:2345 -N -f clab@leaf1` 与 `2346` + `leaf2`。
3. **在每台 leaf 上**（先停掉 `deploy` 用 `nohup` 起的实例，避免重复占配置/端口）：  
   `gdbserver 127.0.0.1:2345 /opt/pproxy/pproxy -c /opt/pproxy/pp1.json`（leaf1），leaf2 把端口与 `pp2.json` 换成 `2346`。
4. **VSCode**：安装 **C/C++** 扩展；用工作区里的 **`.vscode/launch.json`**，选 **「pproxy: gdbserver leaf1」** / **leaf2**，或 **compound「pproxy: leaf1 + leaf2」** 同时下断。**路径/打不开源文件/断点飘**：`launch.json` 里已对 GDB 做了 **`set substitute-path /workspace ${workspaceFolder}`**；**重新整编**时，**非 `--native` 的 `./build.sh`** 会通过 **Meson `-Dhost_repo_abs=<本机仓库绝对路径>`** 写入 **`-fdebug-prefix-map`**，使 DWARF 与本地 `src/...` 一致（**仅**设环境变量 `CFLAGS` 在 Meson 下不可靠）。若老二进制里仍是 `/workspace/...`，依赖上述 **substitute-path** 或临时加 **`sourceFileMap`**: `"/workspace"` → `${workspaceFolder}`。

## 相关配置路径（clab 约定）

- 配置：`/opt/pproxy/pp1.json`、`/opt/pproxy/pp2.json`
- 二进制：`/opt/pproxy/pproxy`
- 指标端口与 `mgmt` 以各自 json 为准

更完整的拓扑与排障层次说明见 `tests/clab/deploy.sh` 文件头注释。
