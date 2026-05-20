# netmap (vendored headers)

Header-only userspace API copied from the upstream
[luigirizzo/netmap](https://github.com/luigirizzo/netmap) project.

| field   | value                                             |
|---------|---------------------------------------------------|
| upstream| https://github.com/luigirizzo/netmap              |
| commit  | `10986ec1479b54552333d4cef913bef3dd159727` (master, 2026-04-29) |
| api     | `NETMAP_API = 14`, classic `nm_open()` (header-only, no `-lnetmap`) |
| files   | `net/netmap.h`, `net/netmap_user.h`, `net/netmap_legacy.h` |
| license | BSD-2-Clause-FreeBSD (see `LICENSE`)              |

We vendor only the userspace headers; the netmap kernel module is *not*
shipped. Runtime still requires `/dev/netmap` (kernel module loaded), exactly
like AF_XDP needs `CAP_NET_ADMIN + CAP_BPF`.

> **Why master, not the v13.0 tag?**
> The last upstream tag (v13.0, 2019) does not build on Linux 6.x kernels
> because `struct timeval` / `do_gettimeofday()` were removed; master
> contains the `ktime_get_real_ts64` shim in `LINUX/bsd_glue.h` and bumps
> `NETMAP_API` from 13 → 14. The `tests/clab/deploy.sh` installer pins the
> kernel module to the **same commit hash** so userspace `nr_version` and
> kernel `NETMAP_API` always match (otherwise `NIOCREGIF` returns `EINVAL`).

These headers are pulled in only when the project is built with
`-Dnetmap=true` (i.e. `./build.sh --netmap`); meson then adds this directory
to the include path. They are otherwise inert.

To refresh, keep the commit in `tests/clab/deploy.sh`
(`pproxy_install_netmap`'s `NM_SHA`) and the URL below in lock-step:

```bash
SHA=10986ec1479b54552333d4cef913bef3dd159727
curl -fsSL -o net/netmap.h        https://raw.githubusercontent.com/luigirizzo/netmap/$SHA/sys/net/netmap.h
curl -fsSL -o net/netmap_user.h   https://raw.githubusercontent.com/luigirizzo/netmap/$SHA/sys/net/netmap_user.h
curl -fsSL -o net/netmap_legacy.h https://raw.githubusercontent.com/luigirizzo/netmap/$SHA/sys/net/netmap_legacy.h
curl -fsSL -o LICENSE             https://raw.githubusercontent.com/luigirizzo/netmap/$SHA/LICENSE
```
