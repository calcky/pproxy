# `pp_ring` 与 MPSC 自旋

`src/core/ring.c` 在序线发布前会自旋等待 `prod_tail` / `cons_tail` 到指定序号。自旋前 64 次迭代内，默认在 x86 上执行 `_mm_pause()`、在 AArch64 上 `yield` 等 **CPU 退避**（`pp_cpu_backoff`），以减轻对总线/功耗的压力；第 64 次之后用 `sched_yield()`。

## 宏 `PP_RING_USE_CPU_BACKOFF`

- **未定义**或定义为 **1**（默认）：前 64 次迭代使用 `pp_cpu_backoff()`。
- 定义为 **0**：前 64 次为**空忙等**（`nop` 语义，仅作对比/调试）；仍会在第 64 次后 `sched_yield()`。

`pproxy` 主目标正常编译不传递该宏，即 **默认 1**。

在 Meson 中可为 **同一** `src/core/ring.c` 指定不同的编译参数，以链接出对比程序（见下）。

## 功能单测

```text
ninja -C build test_ring && ./build/test_ring
```

覆盖非法参数、单线程、burst、满环、多生产 + 单消费校验全集。

## 多生产者基准

可执行目标（`meson` 在 `./build` 中生成）：

- `test_ring_bench`：`ring.c` 带 `-DPP_RING_USE_CPU_BACKOFF=1`
- `test_ring_bench_nobackoff`：带 `-DPP_RING_USE_CPU_BACKOFF=0`

二者共用 `tests/test_ring_bench.c`：8 个生产者、**每线程 20000** 次入队、环容量 **32768**、主线程单消费者出队至 `8×20000=160000` 次；**预热 3 次**，正式测 **15 轮** 取**最短**墙钟；输出中 `ns_per_dequeue` 为总时间除以 160000（单次出队均摊，负载更长、方差可略收）。

```bash
ninja -C build test_ring_bench test_ring_bench_nobackoff
./build/test_ring_bench
./build/test_ring_bench_nobackoff
```

## 示例结果（本仓库一次样例跑数）

*环境：x86_64，约 20 逻辑核（容器/CI 中）。长基准 + 多轮取 min 后仍**仅作相对趋势**；换机/换负载勿直接套用绝对值。*

| `PP_RING_USE_CPU_BACKOFF` | `time_ns_best_of_15` (约) | `ns_per_dequeue` (约) |
|----------------------------|----------------------------|------------------------|
| 1 | 23 621 814 | 147 |
| 0 | 37 869 724 | 236 |

**提升（上表为同环境一次长基准结果；`T1`= 开启退避总纳秒，`T0` = 关闭）**

- **墙钟总时加速比** `T0 / T1`：约 **1.60×**（总时长约缩短 **38%**，即 `1 − T1/T0` ≈ 38%）。
- **每 dequeue 均摊**（`ns0`=236 `ns1`=147）：约 **1.6× 更快**；降幅 `(236−147)/236` 约 **38%**。

*关闭退避*时前 64 次自旋为纯忙等，MPSC 争用下常放大 CPU/总线/调度成本；*开启* `_mm_pause` / `yield` 有利于压低 wall time。*换机/频率策略不同，比值为趋势参考，以本机两次可执行文件输出为准。*

## 与 `pp_ring` API

公共头为 `include/pproxy/ring.h`；`PP_RING_SPSC` / `PP_RING_MPSC` 创建同一套四下标实现，仅作「预期用途」标签。
