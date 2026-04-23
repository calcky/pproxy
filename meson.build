# pproxy 主构建描述
project('pproxy', 'c',
  version: '0.1.0',
  license: 'MIT',
  default_options: [
    'c_std=gnu99',
    'warning_level=2',
    'buildtype=release',
  ],
)

cc = meson.get_compiler('c')

# ---------- 全局编译选项 ----------
add_project_arguments(
  '-D_GNU_SOURCE',
  '-DPP_LINUX',
  '-Wshadow',
  '-Wpointer-arith',
  '-Wcast-align',
  '-Wmissing-prototypes',
  '-Wstrict-prototypes',
  '-Wno-unused-parameter',
  '-Wno-unused-function',
  '-Wno-format-truncation',
  '-fno-strict-aliasing',
  language: 'c',
)

# ---------- 依赖 ----------
deps = [
  dependency('threads'),
  cc.find_library('rt'),
  cc.find_library('dl'),
]

if get_option('xdp')
  deps += dependency('libbpf')
  deps += dependency('libxdp')
  add_project_arguments('-DPP_HAVE_XDP', language: 'c')
endif

if get_option('pcap')
  deps += dependency('libpcap')
  add_project_arguments('-DPP_HAVE_PCAP', language: 'c')
endif

if get_option('netmap')
  add_project_arguments('-DPP_HAVE_NETMAP', language: 'c')
endif

# ---------- 源文件（按目录扫描） ----------
#
# Meson 官方不支持 glob，理由是"新增文件时构建系统感知不到"。
# 我们的工作流 build.sh 每次都会 `meson setup --reconfigure`，
# 此时会重新执行下面的 run_command，新增/删除 .c 自动生效。
# 若直接手动 `ninja -C build`，新增文件后请运行 `./build.sh`
# 或 `meson setup --reconfigure build`。
inc = include_directories('include', 'src', 'third_party/yyjson')

scan = run_command('sh', '-c',
  'find src -type f -name "*.c" | LC_ALL=C sort',
  check: true,
)
sources = scan.stdout().strip().split('\n')

# ---------- yyjson（vendored）静态库 ----------
# 单独开一个 static_library 以便给它放宽告警（vendored 源码不保证跟我们的 -Wshadow 等兼容）
yyjson_lib = static_library('yyjson',
  'third_party/yyjson/yyjson.c',
  include_directories: include_directories('third_party/yyjson'),
  c_args: [
    '-w',                 # 屏蔽所有告警，vendored code 不归我们管
    '-O2',                # 即便整体 debug，也让 JSON parse 保持快
  ],
)

# ---------- 可执行 ----------
executable('pproxy', sources,
  include_directories: inc,
  dependencies: deps,
  link_with: yyjson_lib,
  install: true,
)

# ---------- 测试：无锁环 ----------
test_ring = executable('test_ring',
  [
    'tests/test_ring.c',
    'src/core/ring.c',
  ],
  include_directories: inc,
  dependencies: deps,
)
test('ring', test_ring)

# ring 多生产者基准：同源码链两次 ring.c，仅 PP_RING_USE_CPU_BACKOFF 不同
test_ring_bench = executable('test_ring_bench',
  [
    'tests/test_ring_bench.c',
    'src/core/ring.c',
  ],
  include_directories: inc,
  dependencies: deps,
  c_args: ['-DPP_RING_USE_CPU_BACKOFF=1'],
)
test_ring_bench_nobackoff = executable('test_ring_bench_nobackoff',
  [
    'tests/test_ring_bench.c',
    'src/core/ring.c',
  ],
  include_directories: inc,
  dependencies: deps,
  c_args: ['-DPP_RING_USE_CPU_BACKOFF=0'],
)
# 仅生成可执行文件；与负载相关，不加入默认 meson test。见 doc/ring.md

# ---------- 测试：tunnel 本机回环（同进程 server↔client） ----------
# 只链接 tunnel 和 core 的少量 .o，不依赖 main / module / left-I/O，无需 root。
test_tunnel_loopback = executable('test_tunnel_loopback',
  [
    'tests/test_tunnel_loopback.c',
    'src/tunnel/tcp.c',
    'src/tunnel/udp.c',
    'src/tunnel/icmp.c',
    'src/tunnel/registry.c',
    'src/io/ks_sock.c',
    'src/io/raw_sock.c',
    'src/io/tun.c',
    'src/io/pcap.c',
    'src/io/xsk.c',
    'src/core/endpoint.c',
    'src/core/error.c',
    'src/core/log.c',
    'src/core/packet.c',
    'src/core/time.c',
  ],
  include_directories: inc,
  dependencies: deps,
)
test('tunnel_loopback', test_tunnel_loopback)

# ---------- 测试：config 热重载 ----------
# 不需要 main / module / I/O / root；构造最小 runtime 验证 pp_config_reload。
test_config_reload = executable('test_config_reload',
  [
    'tests/test_config_reload.c',
    'src/config/config.c',
    'src/core/dpi.c',
    'src/core/session.c',
    'src/core/flow.c',
    'src/core/endpoint.c',
    'src/core/error.c',
    'src/core/log.c',
    'src/core/time.c',
  ],
  include_directories: inc,
  dependencies: deps,
  link_with: yyjson_lib,
)
test('config_reload', test_config_reload)

# ---------- 测试：mgmt HTTP exporter ----------
# 拉起 mgmt 模块监听一个 127.0.0.1:19091，然后自己当 HTTP 客户端拉 /metrics / / /404。
# 不触及 TUN / 其它模块。
test_mgmt_http = executable('test_mgmt_http',
  [
    'tests/test_mgmt_http.c',
    'src/modules/mgmt/mgmt.c',
    'src/core/drop.c',
    'src/config/config.c',
    'src/core/module.c',
    'src/core/thread.c',
    'src/core/dpi.c',
    'src/core/session.c',
    'src/core/flow.c',
    'src/core/endpoint.c',
    'src/core/error.c',
    'src/core/log.c',
    'src/core/time.c',
  ],
  include_directories: inc,
  dependencies: deps,
  link_with: yyjson_lib,
)
test('mgmt_http', test_mgmt_http)

# ---------- 测试：AF_PACKET 左手 I/O ----------
# veth + 对端发以太 IPv4/UDP → rx_burst 校验 meta。需要 CAP_NET_RAW + iproute2。
test_af_packet_io = executable('test_af_packet_io',
  [
    'tests/test_af_packet_io.c',
    'src/io/raw_sock.c',
    'src/io/ks_sock.c',
    'src/core/log.c',
    'src/core/packet.c',
    'src/core/time.c',
  ],
  include_directories: inc,
  dependencies: deps,
)
test('af_packet_io', test_af_packet_io)

# ---------- 测试：pcap 左手 I/O（仅 -Dpcap=true） ----------
# 在 lo 上 open -> tx_burst(IP 帧) -> rx_burst(BPF 过滤) -> 校验 meta。
# 需要 CAP_NET_RAW；没有时测试自己 exit 77 skip。
if get_option('pcap')
  test_pcap_io = executable('test_pcap_io',
    [
      'tests/test_pcap_io.c',
      'src/io/pcap.c',
      'src/core/log.c',
      'src/core/packet.c',
      'src/core/time.c',
    ],
    include_directories: inc,
    dependencies: deps,
  )
  test('pcap_io', test_pcap_io)
endif

# ---------- 测试：AF_XDP 左手 I/O（仅 -Dxdp=true） ----------
# veth pair + XSK open + tx_burst + 对端 AF_PACKET 验证收到。
# 需要 CAP_NET_ADMIN + CAP_BPF + /sbin/ip；不满足时 exit 77 skip。
if get_option('xdp')
  test_xsk_io = executable('test_xsk_io',
    [
      'tests/test_xsk_io.c',
      'src/io/xsk.c',
      'src/core/log.c',
      'src/core/packet.c',
      'src/core/time.c',
    ],
    include_directories: inc,
    dependencies: deps,
  )
  test('xsk_io', test_xsk_io)
endif
